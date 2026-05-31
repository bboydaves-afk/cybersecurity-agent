"""Threat intelligence tool definitions (8 tools)."""

THREAT_INTEL_TOOLS = (
    {
        "name": "map_to_mitre",
        "description": "Map security findings, techniques, or attack patterns to the MITRE ATT&CK framework tactics and techniques.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding ID to map to MITRE ATT&CK"},
                "technique_description": {"type": "string", "description": "Free-text description of the attack technique to map"},
                "platform": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
                "include_mitigations": {"type": "boolean", "description": "Include recommended mitigations for each technique", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": [],
        },
    },
    {
        "name": "enrich_ioc",
        "description": "Enrich an Indicator of Compromise (IOC) with threat intelligence data from multiple sources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "IOC value (IP, domain, hash, URL, email)"},
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "url", "email"], "description": "Type of the indicator"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Intelligence sources: 'virustotal', 'shodan', 'abuseipdb', 'threatfox', 'otx', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["indicator", "indicator_type"],
        },
    },
    {
        "name": "query_threat_feed",
        "description": "Query threat intelligence feeds for recent indicators, campaigns, and threat actor activity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "feed": {"type": "string", "enum": ["otx", "threatfox", "abuse_ch", "emerging_threats", "custom"], "description": "Threat feed to query"},
                "query": {"type": "string", "description": "Search query or filter"},
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url", "all"], "default": "all"},
                "time_range": {"type": "string", "description": "Time range (e.g. 'last_24h', 'last_7d', 'last_30d')", "default": "last_7d"},
                "limit": {"type": "integer", "description": "Maximum results", "default": 50},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["feed"],
        },
    },
    {
        "name": "check_indicator",
        "description": "Check a single indicator against known threat intelligence databases and blocklists for reputation and classification.",
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "Indicator to check (IP, domain, hash, URL)"},
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url", "auto"], "default": "auto"},
                "check_blocklists": {"type": "boolean", "description": "Check against public blocklists", "default": True},
                "check_reputation": {"type": "boolean", "description": "Check reputation scores", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "build_attack_chain",
        "description": "Build a visual attack chain or kill chain from a sequence of findings showing the full attack path from initial access to objective.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_ids": {"type": "array", "items": {"type": "string"}, "description": "Ordered list of finding IDs that form the attack chain"},
                "chain_type": {"type": "string", "enum": ["kill_chain", "mitre_attack", "diamond_model"], "default": "kill_chain"},
                "include_timeline": {"type": "boolean", "description": "Include timestamps in the attack chain", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["finding_ids", "project_id"],
        },
    },
    {
        "name": "track_campaign",
        "description": "Track and correlate indicators across a project to identify threat campaigns, shared infrastructure, and actor attribution.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "indicators": {"type": "array", "items": {"type": "string"}, "description": "Indicators to correlate for campaign tracking"},
                "correlation_type": {"type": "string", "enum": ["infrastructure", "ttps", "temporal", "all"], "default": "all"},
                "known_campaigns": {"type": "boolean", "description": "Check against known campaign databases", "default": True},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "search_threat_intel",
        "description": "Search threat intelligence databases for information about threat actors, campaigns, malware families, and vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (threat actor name, malware family, campaign name, technique)"},
                "search_type": {"type": "string", "enum": ["threat_actor", "malware", "campaign", "technique", "vulnerability", "all"], "default": "all"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Intelligence sources to search"},
                "limit": {"type": "integer", "description": "Maximum results", "default": 20},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_attack_surface",
        "description": "Map the external attack surface for a target organization including domains, IPs, exposed services, leaked credentials, and cloud assets.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Primary domain to map attack surface for"},
                "include_subdomains": {"type": "boolean", "description": "Include subdomain enumeration", "default": True},
                "include_cloud": {"type": "boolean", "description": "Check for cloud asset exposure", "default": True},
                "include_leaks": {"type": "boolean", "description": "Check for credential leaks and data exposure", "default": True},
                "include_social": {"type": "boolean", "description": "Include social media and OSINT discovery", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["domain"],
        },
    },
)
