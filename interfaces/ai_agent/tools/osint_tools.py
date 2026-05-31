"""OSINT tool definitions (12 tools)."""

OSINT_TOOLS = (
    {
        "name": "gather_domain_intel",
        "description": "Gather comprehensive intelligence about a domain including WHOIS, DNS records, subdomains, and historical data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name to investigate"},
                "depth": {"type": "string", "description": "Investigation depth (basic, standard, deep)", "default": "standard"},
                "include_subdomains": {"type": "boolean", "description": "Include subdomain enumeration", "default": True},
                "include_historical": {"type": "boolean", "description": "Include historical DNS/WHOIS data", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "search_breach_data",
        "description": "Search for compromised credentials and data breaches associated with email addresses or domains using HIBP and other sources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Email address or domain to search"},
                "query_type": {"type": "string", "description": "Query type (email, domain)", "default": "email"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Breach databases to search (hibp, dehashed, custom)"},
                "include_pastes": {"type": "boolean", "description": "Include paste site searches", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["query", "project_id"],
        },
    },
    {
        "name": "harvest_emails_osint",
        "description": "Harvest email addresses associated with a domain from public sources including search engines, websites, and social media.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to harvest emails for"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Sources to search (google, bing, hunter, clearbit)"},
                "max_results": {"type": "integer", "description": "Maximum number of emails to return", "default": 100},
                "verify": {"type": "boolean", "description": "Verify email address validity", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "social_media_recon",
        "description": "Conduct reconnaissance on social media platforms to gather information about individuals or organizations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target username, name, or organization"},
                "platforms": {"type": "array", "items": {"type": "string"}, "description": "Platforms to search (linkedin, twitter, facebook, instagram, github)"},
                "search_type": {"type": "string", "description": "Search type (username, name, organization)", "default": "username"},
                "collect_posts": {"type": "boolean", "description": "Collect recent posts and activity", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target", "platforms", "project_id"],
        },
    },
    {
        "name": "document_metadata",
        "description": "Extract and analyze metadata from documents found on target websites including author names, software versions, and internal paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to search for documents"},
                "file_types": {"type": "array", "items": {"type": "string"}, "description": "File types to search for (pdf, docx, xlsx, pptx)", "default": ["pdf", "docx"]},
                "max_files": {"type": "integer", "description": "Maximum number of files to download and analyze", "default": 50},
                "extract_fields": {"type": "array", "items": {"type": "string"}, "description": "Metadata fields to extract"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "google_dorking",
        "description": "Perform advanced Google dorking to find sensitive information, exposed files, and security misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
                "dork_categories": {"type": "array", "items": {"type": "string"}, "description": "Dork categories (files, directories, vulnerabilities, credentials, errors)"},
                "custom_dorks": {"type": "array", "items": {"type": "string"}, "description": "Custom Google dork queries"},
                "max_results": {"type": "integer", "description": "Maximum results per dork", "default": 100},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "github_recon",
        "description": "Search GitHub for sensitive information related to a target including leaked credentials, API keys, and internal code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Organization name, domain, or specific search terms"},
                "search_type": {"type": "string", "description": "Search type (code, commits, issues, repositories)", "default": "all"},
                "patterns": {"type": "array", "items": {"type": "string"}, "description": "Patterns to search for (api_key, password, secret)"},
                "max_results": {"type": "integer", "description": "Maximum results to return", "default": 100},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target", "project_id"],
        },
    },
    {
        "name": "dns_intelligence",
        "description": "Gather DNS intelligence including passive DNS history, DNS records, and related domains/IPs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Domain or IP address to investigate"},
                "query_type": {"type": "string", "description": "Query type (domain, ip)", "default": "domain"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "DNS intelligence sources to use"},
                "include_passive": {"type": "boolean", "description": "Include passive DNS history", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["query", "project_id", "target_id"],
        },
    },
    {
        "name": "wayback_analysis",
        "description": "Analyze historical website content using the Wayback Machine to find old vulnerabilities, exposed files, and changed content.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to analyze"},
                "start_date": {"type": "string", "description": "Start date for historical analysis (YYYY-MM-DD)"},
                "end_date": {"type": "string", "description": "End date for historical analysis (YYYY-MM-DD)"},
                "search_for": {"type": "array", "items": {"type": "string"}, "description": "Patterns to search for in historical content"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url", "project_id", "target_id"],
        },
    },
    {
        "name": "search_pastebin",
        "description": "Search paste sites (Pastebin, etc.) for leaked information related to a target including credentials, source code, and internal data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search terms (domain, email, organization name)"},
                "sites": {"type": "array", "items": {"type": "string"}, "description": "Paste sites to search (pastebin, ghostbin, slexy)"},
                "max_results": {"type": "integer", "description": "Maximum results to return", "default": 50},
                "date_range": {"type": "string", "description": "Date range for results (1d, 7d, 30d, all)", "default": "30d"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["query", "project_id"],
        },
    },
    {
        "name": "ip_reputation",
        "description": "Check IP address reputation across multiple threat intelligence sources and blacklists.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "IP address to check"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Reputation sources (abuseipdb, virustotal, shodan, talos)"},
                "include_geolocation": {"type": "boolean", "description": "Include geolocation data", "default": True},
                "include_asn": {"type": "boolean", "description": "Include ASN information", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["ip_address", "project_id"],
        },
    },
    {
        "name": "generate_osint_report",
        "description": "Generate a comprehensive OSINT report summarizing all gathered intelligence for a target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID (optional, for specific target)"},
                "format": {"type": "string", "description": "Report format (html, pdf, json, markdown)", "default": "html"},
                "include_raw_data": {"type": "boolean", "description": "Include raw data sources", "default": False},
                "sections": {"type": "array", "items": {"type": "string"}, "description": "Report sections to include (all by default)"},
            },
            "required": ["project_id"],
        },
    },
)
