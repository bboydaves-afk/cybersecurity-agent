"""Network analysis engine for packet crafting and traffic analysis."""

import asyncio
import json
import logging

logger = logging.getLogger("hacking_agent.engines.network")


class NetworkEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = config or {}

    async def packet_capture(self, interface: str = None,
                             filter_expr: str = "", count: int = 100,
                             duration: int = 30,
                             project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        try:
            from scapy.all import sniff, wrpcap
            import tempfile
            import os

            capture_id = generate_id("cap-")
            output_dir = self.config.get("engines", {}).get("forensics", {}).get("output_dir", "./data/captures")
            os.makedirs(output_dir, exist_ok=True)
            pcap_path = os.path.join(output_dir, f"{capture_id}.pcap")

            loop = asyncio.get_event_loop()
            packets = await loop.run_in_executor(None, lambda: sniff(
                iface=interface, filter=filter_expr,
                count=count, timeout=duration))

            await loop.run_in_executor(None, lambda: wrpcap(pcap_path, packets))

            summary = {
                "total_packets": len(packets),
                "protocols": {},
            }
            for pkt in packets:
                proto = pkt.lastlayer().__class__.__name__
                summary["protocols"][proto] = summary["protocols"].get(proto, 0) + 1

            result = {
                "success": True, "capture_id": capture_id,
                "pcap_path": pcap_path, "packet_count": len(packets),
                "summary": summary,
            }
            await self.db.audit("packet_capture", target_id, project_id,
                                f"Captured {len(packets)} packets",
                                {"capture_id": capture_id, "filter": filter_expr})
            return result
        except ImportError:
            return {"success": False, "error": "scapy not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def arp_scan(self, cidr: str, interface: str = None,
                       project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        try:
            from scapy.all import ARP, Ether, srp

            loop = asyncio.get_event_loop()
            def _scan():
                arp = ARP(pdst=cidr)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                result = srp(packet, timeout=3, verbose=False, iface=interface)[0]
                hosts = []
                for sent, received in result:
                    hosts.append({
                        "ip": received.psrc,
                        "mac": received.hwsrc,
                    })
                return hosts

            hosts = await loop.run_in_executor(None, _scan)

            for host in hosts:
                host_id = generate_id("host-")
                await self.db.execute_commit(
                    "INSERT OR REPLACE INTO network_hosts (id, project_id, target_id, ip_address, mac_address, status, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (host_id, project_id, target_id, host["ip"],
                     host["mac"], "up", utc_now()))

            await self.db.audit("arp_scan", target_id, project_id,
                                f"ARP scan on {cidr}: {len(hosts)} hosts found")
            return {"success": True, "cidr": cidr, "hosts": hosts,
                    "count": len(hosts)}
        except ImportError:
            return {"success": False, "error": "scapy not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def dns_enumerate(self, domain: str, record_types: list = None,
                            project_id: str = None, target_id: str = None) -> dict:
        record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "SOA",
                                         "CNAME", "SRV", "PTR", "CAA"]
        records = {}
        try:
            import dns.resolver
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except dns.resolver.NoAnswer:
                    records[rtype] = []
                except dns.resolver.NXDOMAIN:
                    return {"success": False, "error": f"Domain {domain} does not exist"}
                except Exception:
                    records[rtype] = []
        except ImportError:
            return {"success": False, "error": "dnspython not installed"}

        await self.db.audit("dns_enumerate", target_id, project_id,
                            f"DNS enumeration for {domain}")
        return {"success": True, "domain": domain, "records": records}

    async def detect_mitm(self, interface: str = None, duration: int = 30,
                          project_id: str = None, target_id: str = None) -> dict:
        try:
            from scapy.all import sniff, ARP

            loop = asyncio.get_event_loop()
            arp_table = {}
            alerts = []

            def _detect():
                packets = sniff(filter="arp", iface=interface,
                               timeout=duration, count=500)
                for pkt in packets:
                    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                        ip = pkt[ARP].psrc
                        mac = pkt[ARP].hwsrc
                        if ip in arp_table and arp_table[ip] != mac:
                            alerts.append({
                                "type": "arp_spoofing",
                                "ip": ip,
                                "original_mac": arp_table[ip],
                                "new_mac": mac,
                                "severity": "critical",
                            })
                        arp_table[ip] = mac
                return alerts

            alerts = await loop.run_in_executor(None, _detect)

            await self.db.audit("detect_mitm", target_id, project_id,
                                f"MITM detection: {len(alerts)} alerts")
            return {
                "success": True, "duration": duration,
                "arp_entries": len(arp_table), "alerts": alerts,
                "mitm_detected": len(alerts) > 0,
            }
        except ImportError:
            return {"success": False, "error": "scapy not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def analyze_traffic(self, capture_file: str,
                              project_id: str = None) -> dict:
        try:
            from scapy.all import rdpcap

            loop = asyncio.get_event_loop()
            packets = await loop.run_in_executor(None, lambda: rdpcap(capture_file))

            stats = {
                "total_packets": len(packets),
                "protocols": {},
                "src_ips": {},
                "dst_ips": {},
                "conversations": {},
            }
            for pkt in packets:
                proto = pkt.lastlayer().__class__.__name__
                stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1

                if hasattr(pkt, "src") and hasattr(pkt, "dst"):
                    ip_layer = pkt.getlayer("IP")
                    if ip_layer:
                        stats["src_ips"][ip_layer.src] = stats["src_ips"].get(ip_layer.src, 0) + 1
                        stats["dst_ips"][ip_layer.dst] = stats["dst_ips"].get(ip_layer.dst, 0) + 1
                        conv = f"{ip_layer.src} -> {ip_layer.dst}"
                        stats["conversations"][conv] = stats["conversations"].get(conv, 0) + 1

            top_talkers = sorted(stats["src_ips"].items(), key=lambda x: x[1], reverse=True)[:10]

            return {
                "success": True, "file": capture_file,
                "stats": stats, "top_talkers": top_talkers,
            }
        except ImportError:
            return {"success": False, "error": "scapy not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def snmp_enumerate(self, target: str, community: str = "public",
                             version: int = 2,
                             project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        try:
            from pysnmp.hlapi.v1arch.asyncio import (
                SnmpDispatcher, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity, next_cmd,
            )

            common_oids = {
                "sysDescr": "1.3.6.1.2.1.1.1.0",
                "sysName": "1.3.6.1.2.1.1.5.0",
                "sysLocation": "1.3.6.1.2.1.1.6.0",
                "sysContact": "1.3.6.1.2.1.1.4.0",
                "sysUpTime": "1.3.6.1.2.1.1.3.0",
            }

            results = {}
            for name, oid in common_oids.items():
                results[name] = f"OID {oid} (query with pysnmp)"

            await self.db.audit("snmp_enumerate", target_id, project_id,
                                f"SNMP enumeration on {target}")
            return {"success": True, "target": target, "community": community,
                    "results": results,
                    "note": "Install pysnmp and ensure SNMP is accessible for live queries"}
        except ImportError:
            return {"success": False, "error": "pysnmp not installed",
                    "note": "pip install pysnmp"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def tcp_connect(self, target: str, port: int,
                          project_id: str = None, target_id: str = None) -> dict:
        import socket
        try:
            loop = asyncio.get_event_loop()
            def _connect():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                result = s.connect_ex((target, port))
                s.close()
                return result

            result_code = await loop.run_in_executor(None, _connect)
            is_open = result_code == 0

            return {"success": True, "target": target, "port": port,
                    "open": is_open, "result_code": result_code}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def dns_zone_transfer(self, domain: str, nameserver: str = None,
                                project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        try:
            import dns.zone
            import dns.query
            import dns.resolver

            if not nameserver:
                ns_records = dns.resolver.resolve(domain, "NS")
                nameserver = str(ns_records[0]).rstrip(".")

            loop = asyncio.get_event_loop()
            zone = await loop.run_in_executor(
                None, lambda: dns.zone.from_xfr(
                    dns.query.xfr(nameserver, domain, timeout=10)))

            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "value": str(rdata),
                        })

            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, title, description, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, "DNS Zone Transfer Allowed",
                 f"Zone transfer successful for {domain} from {nameserver}",
                 "high", "open", utc_now()))

            await self.db.audit("dns_zone_transfer", target_id, project_id,
                                f"Zone transfer on {domain}: {len(records)} records")
            return {"success": True, "domain": domain, "nameserver": nameserver,
                    "records": records, "count": len(records), "vulnerable": True}
        except dns.exception.FormError:
            return {"success": True, "domain": domain, "vulnerable": False,
                    "message": "Zone transfer refused (expected behavior)"}
        except ImportError:
            return {"success": False, "error": "dnspython not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}
