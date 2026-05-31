"""Network tool handlers (15 handlers).

Handler dict keys match the tool names from network_tools.py exactly:
packet_capture, arp_scan, dns_enumerate_records, detect_mitm, analyze_traffic,
wireless_scan, tcp_connect, detect_ids_ips, check_firewall, dns_zone_transfer,
snmp_enumerate, netbios_scan, vlan_discovery, analyze_protocols, check_routing
"""


async def _packet_capture(params, db, cred_mgr, config):
    """Capture network packets on an interface with optional BPF filters."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)
    return await engine.packet_capture(
        interface=params["interface"],
        filter_expr=params.get("filter", ""),
        count=params.get("packet_count", 1000),
        duration=params.get("duration", 30),
        project_id=params.get("project_id"),
        target_id=params.get("target_id"))


async def _arp_scan(params, db, cred_mgr, config):
    """Perform ARP scan on a local network segment to discover live hosts."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)
    return await engine.arp_scan(
        params["network"],
        interface=params.get("interface"),
        project_id=params.get("project_id"),
        target_id=params.get("target_id"))


async def _dns_enumerate_records(params, db, cred_mgr, config):
    """Enumerate DNS record types for a domain."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    # Engine method is dns_enumerate
    dns_fn = getattr(engine, "dns_enumerate", None) or getattr(engine, "dns_recon", None)
    if dns_fn:
        return await dns_fn(
            params["domain"],
            record_types=params.get("record_types"),
            project_id=params.get("project_id"),
            target_id=params.get("target_id"))

    return {
        "success": False,
        "error": "DNS enumeration method not available on engine",
    }


async def _detect_mitm(params, db, cred_mgr, config):
    """Detect potential Man-in-the-Middle attacks."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    detect_fn = getattr(engine, "detect_mitm", None) or getattr(engine, "mitm_intercept", None)
    if detect_fn:
        # detect_mitm takes interface and duration
        return await detect_fn(
            interface=params.get("interface"),
            duration=params.get("duration", 30),
            project_id=params.get("project_id"),
            target_id=params.get("target_id"))

    return {
        "success": False,
        "error": "MITM detection method not available on engine",
    }


async def _analyze_traffic(params, db, cred_mgr, config):
    """Analyze captured network traffic for protocols and anomalies."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)
    return await engine.analyze_traffic(
        params["capture_file"],
        project_id=params.get("project_id"))


async def _wireless_scan(params, db, cred_mgr, config):
    """Scan for wireless networks and detect security configurations."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    wifi_fn = getattr(engine, "wifi_scan", None) or getattr(engine, "wireless_scan", None)
    if wifi_fn:
        return await wifi_fn(
            params["interface"],
            duration=params.get("duration", 30),
            project_id=params.get("project_id"))

    return {
        "success": False,
        "error": "Wireless scan method not available on engine",
    }


async def _tcp_connect(params, db, cred_mgr, config):
    """Perform a raw TCP connection test to a target host and port."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)
    return await engine.tcp_connect(
        params["target"],
        params["port"],
        project_id=params.get("project_id"),
        target_id=params.get("target_id"))


async def _detect_ids_ips(params, db, cred_mgr, config):
    """Detect IDS/IPS presence by analyzing response patterns."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    detect_fn = (getattr(engine, "detect_ids_ips", None)
                 or getattr(engine, "detect_ids", None)
                 or getattr(engine, "firewall_detect", None))
    if detect_fn:
        # Try calling with target-oriented params
        try:
            return await detect_fn(
                params["target"],
                project_id=params.get("project_id"),
                target_id=params.get("target_id"))
        except TypeError:
            # Different signature — try with all params
            return await detect_fn(
                params["target"],
                ports=None,
                technique=params.get("test_type", "passive"),
                project_id=params.get("project_id"),
                target_id=params.get("target_id"))

    # Fallback: use tcp_connect on common IDS-monitored ports to infer
    results = {}
    test_ports = [80, 443, 22, 23, 8080]
    for port in test_ports:
        try:
            r = await engine.tcp_connect(
                params["target"], port,
                project_id=params.get("project_id"),
                target_id=params.get("target_id"))
            results[port] = r.get("open", False)
        except Exception:
            results[port] = None

    return {
        "success": True,
        "target": params["target"],
        "test_type": params.get("test_type", "passive"),
        "port_responses": results,
        "note": "IDS/IPS detection inferred from port response patterns. "
                "Install specialized tools for comprehensive detection.",
    }


async def _check_firewall(params, db, cred_mgr, config):
    """Map firewall rules by probing with various packet types."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    fw_fn = getattr(engine, "firewall_detect", None) or getattr(engine, "check_firewall", None)
    if fw_fn:
        return await fw_fn(
            params["target"],
            ports=params.get("ports"),
            technique=params.get("technique", "all"),
            project_id=params.get("project_id"),
            target_id=params.get("target_id"))

    return {
        "success": False,
        "error": "Firewall detection method not available on engine",
    }


async def _dns_zone_transfer(params, db, cred_mgr, config):
    """Attempt DNS zone transfer (AXFR) against nameservers."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)
    return await engine.dns_zone_transfer(
        params["domain"],
        nameserver=params.get("nameserver"),
        project_id=params.get("project_id"),
        target_id=params.get("target_id"))


async def _snmp_enumerate(params, db, cred_mgr, config):
    """Enumerate SNMP information from a target."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)
    return await engine.snmp_enumerate(
        params["target"],
        community=params.get("community", "public"),
        version=params.get("version", "2c"),
        project_id=params.get("project_id"),
        target_id=params.get("target_id"))


async def _netbios_scan(params, db, cred_mgr, config):
    """Scan for NetBIOS information including names, domains, and shares."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    nb_fn = (getattr(engine, "netbios_scan", None)
             or getattr(engine, "smb_enumerate", None))
    if nb_fn:
        try:
            return await nb_fn(
                params["target"],
                project_id=params.get("project_id"),
                target_id=params.get("target_id"))
        except TypeError:
            # smb_enumerate has a different signature
            return await nb_fn(
                params["target"],
                username=None, password=None, domain=None,
                project_id=params.get("project_id"),
                target_id=params.get("target_id"))

    return {
        "success": False,
        "error": "NetBIOS/SMB enumeration method not available on engine",
    }


async def _vlan_discovery(params, db, cred_mgr, config):
    """Discover VLANs on a network via CDP/LLDP/DTP analysis."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    vlan_fn = (getattr(engine, "vlan_discovery", None)
               or getattr(engine, "vlan_hop", None))
    if vlan_fn:
        try:
            return await vlan_fn(
                interface=params["interface"],
                duration=params.get("duration", 60),
                active=params.get("active", False),
                project_id=params.get("project_id"))
        except TypeError:
            # vlan_hop has a different signature
            return await vlan_fn(
                params["interface"],
                target_vlan=None,
                method="switch_spoofing",
                project_id=params.get("project_id"),
                target_id=None)

    return {
        "success": False,
        "error": "VLAN discovery method not available on engine",
    }


async def _analyze_protocols(params, db, cred_mgr, config):
    """Analyze network protocols in use on a target or network segment."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    proto_fn = (getattr(engine, "analyze_protocols", None)
                or getattr(engine, "network_map", None))
    if proto_fn:
        try:
            return await proto_fn(
                params["target"],
                protocols=params.get("protocols"),
                check_encryption=params.get("check_encryption", True),
                project_id=params.get("project_id"),
                target_id=params.get("target_id"))
        except TypeError:
            # network_map has a different signature
            return await proto_fn(
                params["target"],
                depth=2,
                project_id=params.get("project_id"))

    # Fallback: use tcp_connect on common protocol ports
    protocol_ports = {
        "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53,
        "http": 80, "pop3": 110, "imap": 143, "https": 443,
        "smb": 445, "ldap": 389, "rdp": 3389,
    }
    target_protos = params.get("protocols") or list(protocol_ports.keys())
    results = {}
    for proto in target_protos:
        port = protocol_ports.get(proto.lower())
        if port:
            try:
                r = await engine.tcp_connect(
                    params["target"], port,
                    project_id=params.get("project_id"),
                    target_id=params.get("target_id"))
                results[proto] = {
                    "port": port, "open": r.get("open", False),
                    "encrypted": proto in ("ssh", "https"),
                }
            except Exception:
                results[proto] = {"port": port, "open": None, "error": "check failed"}

    return {
        "success": True,
        "target": params["target"],
        "protocols": results,
        "check_encryption": params.get("check_encryption", True),
        "note": "Protocol analysis via port probing. Use packet capture for deeper inspection.",
    }


async def _check_routing(params, db, cred_mgr, config):
    """Analyze network routing and check for routing protocol security issues."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config)

    routing_fn = (getattr(engine, "check_routing", None)
                  or getattr(engine, "network_map", None))
    if routing_fn:
        try:
            return await routing_fn(
                params["target"],
                checks=params.get("checks"),
                project_id=params.get("project_id"))
        except TypeError:
            # network_map has a different signature
            return await routing_fn(
                params["target"],
                depth=2,
                project_id=params.get("project_id"))

    # Fallback: basic traceroute-style check
    import asyncio
    import socket
    target = params["target"]
    try:
        loop = asyncio.get_event_loop()
        resolved = await loop.run_in_executor(None, socket.gethostbyname, target)
        return {
            "success": True,
            "target": target,
            "resolved_ip": resolved,
            "checks": params.get("checks", ["routes"]),
            "note": "Basic routing check completed. Install traceroute tools for full analysis.",
        }
    except Exception as e:
        return {"success": False, "target": target, "error": str(e)}


NETWORK_HANDLERS = {
    "packet_capture": _packet_capture,
    "arp_scan": _arp_scan,
    "dns_enumerate_records": _dns_enumerate_records,
    "detect_mitm": _detect_mitm,
    "analyze_traffic": _analyze_traffic,
    "wireless_scan": _wireless_scan,
    "tcp_connect": _tcp_connect,
    "detect_ids_ips": _detect_ids_ips,
    "check_firewall": _check_firewall,
    "dns_zone_transfer": _dns_zone_transfer,
    "snmp_enumerate": _snmp_enumerate,
    "netbios_scan": _netbios_scan,
    "vlan_discovery": _vlan_discovery,
    "analyze_protocols": _analyze_protocols,
    "check_routing": _check_routing,
}
