"""Email security tool definitions (10 tools)."""

EMAIL_SECURITY_TOOLS = (
    {
        "name": "check_spf",
        "description": "Check SPF (Sender Policy Framework) records for a domain to validate email sending authorization and detect misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check SPF records"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "check_dkim",
        "description": "Check DKIM (DomainKeys Identified Mail) records and signatures for a domain to validate email authentication.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check DKIM records"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "selector": {"type": "string", "description": "DKIM selector (optional, will try common selectors if not provided)"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "check_dmarc",
        "description": "Check DMARC (Domain-based Message Authentication, Reporting & Conformance) policy for a domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check DMARC policy"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "analyze_email_headers",
        "description": "Analyze email headers to detect spoofing, phishing indicators, mail routing, and authentication results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "headers": {"type": "string", "description": "Raw email headers to analyze"},
                "project_id": {"type": "string", "description": "Project ID"},
                "check_authentication": {"type": "boolean", "description": "Check SPF/DKIM/DMARC authentication (default: true)"},
            },
            "required": ["headers", "project_id"],
        },
    },
    {
        "name": "check_mail_server",
        "description": "Check mail server security configuration, TLS support, open relay, and common misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check mail servers"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "check_relay": {"type": "boolean", "description": "Check for open relay (default: true)"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "check_email_spoofing",
        "description": "Test if a domain is vulnerable to email spoofing by analyzing SPF, DKIM, and DMARC configurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to test for spoofing vulnerability"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "test_smtp_auth",
        "description": "Test SMTP authentication methods, TLS encryption, and potential vulnerabilities in mail server authentication.",
        "input_schema": {
            "type": "object",
            "properties": {
                "mail_server": {"type": "string", "description": "Mail server hostname or IP"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "port": {"type": "integer", "description": "SMTP port (default: 25)"},
            },
            "required": ["mail_server", "project_id", "target_id"],
        },
    },
    {
        "name": "check_email_security_posture",
        "description": "Perform comprehensive email security assessment including SPF, DKIM, DMARC, TLS, and spoofing vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to assess"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "check_bimi",
        "description": "Check BIMI (Brand Indicators for Message Identification) records and VMC (Verified Mark Certificate) for a domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check BIMI records"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "generate_email_report",
        "description": "Generate comprehensive email security assessment report with findings, vulnerabilities, and remediation recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID (optional)"},
                "format": {"type": "string", "description": "Report format: html, json, or markdown (default: html)"},
            },
            "required": ["project_id"],
        },
    },
)
