"""Reconnaissance engine for network scanning and enumeration."""

import asyncio
import json
import logging
import socket
import time

logger = logging.getLogger("hacking_agent.engines.recon")


class ReconEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = (config or {}).get("engines", {}).get("recon", {})

    async def port_scan(self, target: str, ports: str = "1-1000",
                        scan_type: str = "syn", project_id: str = None,
                        target_id: str = None) -> dict:
        from platforms.nmap_client import NmapClient
        from core.database import generate_id, utc_now

        scan_id = generate_id("scan-")
        started = utc_now()
        start_time = time.time()

        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, parameters, started_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "port_scan", "running",
             json.dumps({"target": target, "ports": ports, "scan_type": scan_type}), started))

        nmap = NmapClient(self.config)
        args_map = {"syn": "-sS", "connect": "-sT", "udp": "-sU",
                     "ack": "-sA", "stealth": "-sS"}
        result = await nmap.scan(target, ports, arguments=args_map.get(scan_type, ""))

        duration = time.time() - start_time
        status = "completed" if result.get("success") else "failed"
        finding_count = sum(
            len(p) for h in result.get("hosts", [])
            for p in h.get("protocols", {}).values())

        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, finding_count=?, completed_at=?, duration_seconds=? WHERE id=?",
            (status, json.dumps(result), finding_count, utc_now(), duration, scan_id))

        for host_data in result.get("hosts", []):
            host_id = generate_id("host-")
            ports_json = json.dumps([
                p for proto_ports in host_data.get("protocols", {}).values()
                for p in proto_ports])
            await self.db.execute_commit(
                "INSERT OR REPLACE INTO network_hosts (id, project_id, target_id, ip_address, hostname, status, last_seen, ports) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (host_id, project_id, target_id, host_data.get("host", ""),
                 host_data.get("hostname", ""), host_data.get("state", "up"),
                 utc_now(), ports_json))

        await self.db.audit("port_scan", target_id, project_id,
                            f"Port scan on {target} ({ports})",
                            {"scan_id": scan_id, "finding_count": finding_count})

        return {"scan_id": scan_id, "status": status,
                "duration": round(duration, 2), **result}

    async def service_enumerate(self, target: str, ports: str = None,
                                project_id: str = None, target_id: str = None) -> dict:
        from platforms.nmap_client import NmapClient
        from core.database import generate_id, utc_now

        scan_id = generate_id("scan-")
        start_time = time.time()
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "service_enum", "running", utc_now()))

        nmap = NmapClient(self.config)
        result = await nmap.service_scan(target, ports)

        duration = time.time() - start_time
        status = "completed" if result.get("success") else "failed"
        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, completed_at=?, duration_seconds=? WHERE id=?",
            (status, json.dumps(result), utc_now(), duration, scan_id))
        await self.db.audit("service_enumerate", target_id, project_id,
                            f"Service enumeration on {target}")
        return {"scan_id": scan_id, "status": status,
                "duration": round(duration, 2), **result}

    async def os_fingerprint(self, target: str, project_id: str = None,
                             target_id: str = None) -> dict:
        from platforms.nmap_client import NmapClient
        from core.database import generate_id, utc_now

        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "os_fingerprint", "running", utc_now()))

        nmap = NmapClient(self.config)
        result = await nmap.os_detect(target)

        status = "completed" if result.get("success") else "failed"
        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, completed_at=? WHERE id=?",
            (status, json.dumps(result), utc_now(), scan_id))
        await self.db.audit("os_fingerprint", target_id, project_id,
                            f"OS fingerprint on {target}")
        return {"scan_id": scan_id, **result}

    async def subdomain_enumerate(self, domain: str, method: str = "dns",
                                  project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "subdomain_enum", "running", utc_now()))

        subdomains = set()

        if method in ("dns", "all"):
            try:
                import dns.resolver
                wordlist = ["www", "mail", "ftp", "admin", "blog", "dev", "staging",
                            "test", "api", "app", "cdn", "docs", "git", "jenkins",
                            "jira", "lab", "login", "m", "monitor", "ns1", "ns2",
                            "portal", "remote", "smtp", "ssh", "vpn", "webmail"]
                for sub in wordlist:
                    try:
                        fqdn = f"{sub}.{domain}"
                        answers = dns.resolver.resolve(fqdn, "A")
                        for rdata in answers:
                            subdomains.add(fqdn)
                    except Exception:
                        pass
            except ImportError:
                pass

        if method in ("crtsh", "all"):
            try:
                from platforms.crtsh_client import CRTShClient
                crtsh = CRTShClient()
                await crtsh.connect()
                result = await crtsh.get_subdomains(domain)
                await crtsh.disconnect()
                subdomains.update(result.get("subdomains", []))
            except Exception as e:
                logger.warning("crt.sh lookup failed: %s", e)

        result = {"success": True, "domain": domain, "method": method,
                  "subdomains": sorted(subdomains), "count": len(subdomains)}

        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, finding_count=?, completed_at=? WHERE id=?",
            ("completed", json.dumps(result), len(subdomains), utc_now(), scan_id))
        await self.db.audit("subdomain_enumerate", target_id, project_id,
                            f"Subdomain enumeration for {domain}: {len(subdomains)} found")
        return {"scan_id": scan_id, **result}

    async def dns_recon(self, domain: str, project_id: str = None,
                        target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

        try:
            import dns.resolver
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except Exception:
                    records[rtype] = []
        except ImportError:
            return {"success": False, "error": "dnspython not installed"}

        result = {"success": True, "domain": domain, "records": records}
        await self.db.audit("dns_recon", target_id, project_id,
                            f"DNS recon for {domain}")
        return result

    async def whois_lookup(self, target: str, project_id: str = None,
                           target_id: str = None) -> dict:
        try:
            import whois
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, lambda: whois.whois(target))
            result = {
                "success": True,
                "domain": target,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "org": w.org,
                "emails": w.emails,
                "country": w.country,
            }
        except Exception as e:
            result = {"success": False, "error": str(e)}

        await self.db.audit("whois_lookup", target_id, project_id,
                            f"WHOIS lookup for {target}")
        return result

    async def traceroute(self, target: str, project_id: str = None,
                         target_id: str = None) -> dict:
        from platforms.nmap_client import NmapClient
        nmap = NmapClient(self.config)
        result = await nmap.scan(target, arguments="--traceroute -Pn")
        await self.db.audit("traceroute", target_id, project_id,
                            f"Traceroute to {target}")
        return result

    async def banner_grab(self, target: str, port: int,
                          project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        try:
            loop = asyncio.get_event_loop()
            def _grab():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target, port))
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(4096).decode("utf-8", errors="replace")
                s.close()
                return banner
            banner = await loop.run_in_executor(None, _grab)
            result = {"success": True, "target": target, "port": port, "banner": banner}
        except Exception as e:
            result = {"success": False, "error": str(e)}

        await self.db.audit("banner_grab", target_id, project_id,
                            f"Banner grab on {target}:{port}")
        return result

    async def network_sweep(self, cidr: str, project_id: str = None,
                            target_id: str = None) -> dict:
        from platforms.nmap_client import NmapClient
        from core.database import generate_id, utc_now

        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "network_sweep", "running", utc_now()))

        nmap = NmapClient(self.config)
        result = await nmap.scan(cidr, arguments="-sn")

        live_hosts = [h for h in result.get("hosts", []) if h.get("state") == "up"]
        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, finding_count=?, completed_at=? WHERE id=?",
            ("completed", json.dumps(result), len(live_hosts), utc_now(), scan_id))
        await self.db.audit("network_sweep", target_id, project_id,
                            f"Network sweep on {cidr}: {len(live_hosts)} hosts found")
        return {"scan_id": scan_id, "live_hosts": live_hosts,
                "count": len(live_hosts), **result}

    async def reverse_dns(self, ip: str, project_id: str = None,
                          target_id: str = None) -> dict:
        try:
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(
                None, lambda: socket.gethostbyaddr(ip))
            result = {"success": True, "ip": ip, "hostname": hostname[0],
                      "aliases": hostname[1]}
        except Exception as e:
            result = {"success": False, "ip": ip, "error": str(e)}
        await self.db.audit("reverse_dns", target_id, project_id,
                            f"Reverse DNS for {ip}")
        return result
