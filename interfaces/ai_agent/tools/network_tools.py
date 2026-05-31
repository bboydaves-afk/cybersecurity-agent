"""Network analysis tool definitions (15 tools)."""

NETWORK_TOOLS = (
    {
        "name": "packet_capture",
        "description": "Capture network packets on an interface with optional BPF filters for protocol analysis and traffic inspection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to capture on (e.g. 'eth0', 'wlan0')"},
                "filter": {"type": "string", "description": "BPF filter expression (e.g. 'tcp port 80', 'host 192.168.1.1')"},
                "duration": {"type": "integer", "description": "Capture duration in seconds", "default": 30},
                "packet_count": {"type": "integer", "description": "Maximum number of packets to capture", "default": 1000},
                "output_format": {"type": "string", "enum": ["summary", "detail", "pcap"], "default": "summary"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["interface"],
        },
    },
    {
        "name": "arp_scan",
        "description": "Perform an ARP scan on a local network segment to discover live hosts and their MAC addresses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "network": {"type": "string", "description": "Network range in CIDR notation (e.g. '192.168.1.0/24')"},
                "interface": {"type": "string", "description": "Network interface to use"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["network"],
        },
    },
    {
        "name": "dns_enumerate_records",
        "description": "Enumerate all DNS record types for a domain including A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, and PTR records.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain to enumerate"},
                "record_types": {"type": "array", "items": {"type": "string"}, "description": "Specific record types to query (e.g. ['A', 'MX', 'TXT'])"},
                "nameserver": {"type": "string", "description": "Custom DNS nameserver to query"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "detect_mitm",
        "description": "Detect potential Man-in-the-Middle (MITM) attacks by checking ARP tables, certificate chains, and DNS responses for anomalies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname to check"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Specific checks: 'arp_poisoning', 'ssl_intercept', 'dns_spoofing', 'all'"},
                "interface": {"type": "string", "description": "Network interface to monitor"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "analyze_traffic",
        "description": "Analyze captured network traffic for protocols, conversations, anomalies, and potential security issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_file": {"type": "string", "description": "Path to PCAP capture file"},
                "analysis_type": {"type": "string", "enum": ["protocols", "conversations", "anomalies", "credentials", "dns", "http", "all"], "default": "all"},
                "filter": {"type": "string", "description": "Display filter to apply during analysis"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["capture_file"],
        },
    },
    {
        "name": "wireless_scan",
        "description": "Scan for wireless networks, detect security configurations, and identify rogue access points.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Wireless interface in monitor mode"},
                "duration": {"type": "integer", "description": "Scan duration in seconds", "default": 30},
                "channel": {"type": "integer", "description": "Specific channel to scan (scans all if omitted)"},
                "ssid_filter": {"type": "string", "description": "Filter by SSID name or pattern"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["interface"],
        },
    },
    {
        "name": "tcp_connect",
        "description": "Perform a raw TCP connection test to a target host and port, useful for testing connectivity and grabbing banners.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "Target port number"},
                "timeout": {"type": "integer", "description": "Connection timeout in seconds", "default": 5},
                "send_data": {"type": "string", "description": "Data to send after connection (e.g. 'HEAD / HTTP/1.0\\r\\n\\r\\n')"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target", "port"],
        },
    },
    {
        "name": "detect_ids_ips",
        "description": "Detect the presence of Intrusion Detection/Prevention Systems by analyzing response patterns and timing anomalies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "test_type": {"type": "string", "enum": ["passive", "active", "evasion"], "default": "passive"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_firewall",
        "description": "Map firewall rules and identify allowed/blocked ports by probing with various packet types (SYN, ACK, FIN, NULL).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "description": "Port range to check (e.g. '1-1000', '80,443,8080')"},
                "technique": {"type": "string", "enum": ["syn", "ack", "fin", "null", "xmas", "all"], "default": "all"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "dns_zone_transfer",
        "description": "Attempt DNS zone transfer (AXFR) against nameservers to retrieve full zone data for a domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "nameserver": {"type": "string", "description": "Specific nameserver to attempt transfer from (auto-detects if omitted)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "snmp_enumerate",
        "description": "Enumerate SNMP information from a target using community strings to gather system info, interfaces, routing, and processes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "community": {"type": "string", "description": "SNMP community string", "default": "public"},
                "version": {"type": "string", "enum": ["1", "2c", "3"], "default": "2c"},
                "oid": {"type": "string", "description": "Specific OID to query"},
                "walk": {"type": "boolean", "description": "Perform SNMP walk instead of get", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "netbios_scan",
        "description": "Scan for NetBIOS information including computer names, domains, MAC addresses, and shared resources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, or CIDR range"},
                "enumerate": {"type": "array", "items": {"type": "string"}, "description": "What to enumerate: 'names', 'shares', 'users', 'domains', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "vlan_discovery",
        "description": "Discover VLANs on a network by analyzing CDP/LLDP frames, DTP negotiation, and 802.1Q tagging.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to use"},
                "duration": {"type": "integer", "description": "Listen duration in seconds", "default": 60},
                "active": {"type": "boolean", "description": "Whether to send active probes (DTP, CDP)", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["interface"],
        },
    },
    {
        "name": "analyze_protocols",
        "description": "Analyze network protocols in use on a target or network segment, identifying insecure protocols and misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, or CIDR range"},
                "protocols": {"type": "array", "items": {"type": "string"}, "description": "Specific protocols to analyze (e.g. 'smb', 'ldap', 'telnet', 'ftp')"},
                "check_encryption": {"type": "boolean", "description": "Check for unencrypted protocol usage", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_routing",
        "description": "Analyze network routing, identify multi-homed hosts, and check for routing protocol security issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or network range"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Checks to run: 'routes', 'gateways', 'multihomed', 'protocols', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target"],
        },
    },
)
