"""Reconnaissance tool definitions (20 tools)."""

RECON_TOOLS = (
    {
        "name": "port_scan",
        "description": "Scan a target for open ports using nmap. Supports SYN, connect, UDP, and ACK scan types.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "description": "Port range (e.g. '1-1000', '80,443,8080')", "default": "1-1000"},
                "scan_type": {"type": "string", "enum": ["syn", "connect", "udp", "ack", "stealth"], "default": "syn"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "service_enumerate",
        "description": "Enumerate services and versions on open ports using nmap -sV.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "description": "Specific ports to enumerate"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "os_fingerprint",
        "description": "Detect the operating system of a target using nmap OS detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "subdomain_enumerate",
        "description": "Discover subdomains for a domain using DNS brute-force and certificate transparency logs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "method": {"type": "string", "enum": ["dns", "crtsh", "all"], "default": "all"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "dns_recon",
        "description": "Perform DNS reconnaissance gathering A, AAAA, MX, NS, TXT, SOA, CNAME, SRV records.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "whois_lookup",
        "description": "Query WHOIS for domain or IP registration information.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to look up"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "traceroute",
        "description": "Trace the network path to a target host.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "banner_grab",
        "description": "Grab the service banner from an open port.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "Port number"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target", "port"],
        },
    },
    {
        "name": "network_sweep",
        "description": "Discover live hosts on a CIDR network range using ping sweep.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cidr": {"type": "string", "description": "CIDR range (e.g. '192.168.1.0/24')"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["cidr"],
        },
    },
    {
        "name": "reverse_dns",
        "description": "Perform reverse DNS lookup on an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "certificate_transparency",
        "description": "Search certificate transparency logs for domain certificates and subdomains.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "shodan_search",
        "description": "Search Shodan for exposed services matching a query.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search query"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "shodan_host_info",
        "description": "Get detailed Shodan information for a specific IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "wayback_urls",
        "description": "Retrieve historical URLs from the Wayback Machine for a domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "google_dork",
        "description": "Generate Google dork queries for reconnaissance on a target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "dork_type": {"type": "string", "enum": ["files", "login", "admin", "config", "database", "all"], "default": "all"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "email_harvest",
        "description": "Harvest email addresses associated with a domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "tech_detect",
        "description": "Detect web technologies, frameworks, CMS, and server software.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "asn_lookup",
        "description": "Get ASN and netblock information for an IP or domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or domain"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "screenshot_web",
        "description": "Capture a screenshot of a web target (returns URL info if screenshot tool not available).",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "full_recon",
        "description": "Run an automated full reconnaissance workflow: port scan, service enum, OS fingerprint, and subdomain discovery.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, or domain"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target"],
        },
    },
)
