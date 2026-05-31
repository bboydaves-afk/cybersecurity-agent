"""Report and finding management tool definitions (8 tools)."""

REPORT_TOOLS = (
    {
        "name": "create_finding",
        "description": "Create a new security finding with severity, description, evidence, affected assets, and remediation guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Finding title (concise and descriptive)"},
                "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"], "description": "Finding severity level"},
                "description": {"type": "string", "description": "Detailed description of the vulnerability or finding"},
                "evidence": {"type": "string", "description": "Evidence supporting the finding (command output, screenshot references, HTTP requests/responses)"},
                "affected_asset": {"type": "string", "description": "Affected target, IP, URL, or system component"},
                "cve_ids": {"type": "array", "items": {"type": "string"}, "description": "Related CVE identifiers"},
                "cvss_score": {"type": "number", "description": "CVSS v3.1 base score"},
                "cvss_vector": {"type": "string", "description": "CVSS v3.1 vector string"},
                "remediation": {"type": "string", "description": "Recommended remediation steps"},
                "references": {"type": "array", "items": {"type": "string"}, "description": "Reference URLs for additional information"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["title", "severity", "description", "project_id"],
        },
    },
    {
        "name": "update_finding",
        "description": "Update an existing security finding's status, severity, description, or remediation details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding ID to update"},
                "status": {"type": "string", "enum": ["open", "confirmed", "false_positive", "remediated", "accepted", "in_progress"], "description": "Updated status"},
                "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"], "description": "Updated severity"},
                "description": {"type": "string", "description": "Updated description"},
                "evidence": {"type": "string", "description": "Additional evidence"},
                "remediation": {"type": "string", "description": "Updated remediation guidance"},
                "notes": {"type": "string", "description": "Additional notes or comments"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "generate_report",
        "description": "Generate a penetration test or security assessment report with executive summary, findings, and technical details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "report_type": {"type": "string", "enum": ["pentest", "vulnerability_assessment", "web_app", "network", "cloud", "compliance", "executive"], "default": "pentest"},
                "format": {"type": "string", "enum": ["html", "pdf", "docx", "json", "markdown"], "default": "html"},
                "include_sections": {"type": "array", "items": {"type": "string"}, "description": "Sections to include: 'executive_summary', 'scope', 'methodology', 'findings', 'risk_matrix', 'remediation', 'appendix', 'all'"},
                "classification": {"type": "string", "enum": ["public", "internal", "confidential", "restricted"], "default": "confidential"},
                "client_name": {"type": "string", "description": "Client or organization name for the report"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "export_findings",
        "description": "Export security findings in various formats for external tools, ticketing systems, or documentation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "format": {"type": "string", "enum": ["csv", "json", "xml", "sarif", "jira", "markdown"], "default": "csv"},
                "severity_filter": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical", "all"], "default": "all"},
                "status_filter": {"type": "string", "enum": ["open", "confirmed", "remediated", "all"], "default": "all"},
                "fields": {"type": "array", "items": {"type": "string"}, "description": "Fields to include in export"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "calculate_risk_score",
        "description": "Calculate an overall risk score for a project or target based on findings severity, exploitability, and business impact.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Specific target ID (calculates for project if omitted)"},
                "methodology": {"type": "string", "enum": ["cvss", "dread", "owasp_risk", "custom"], "default": "cvss"},
                "business_context": {"type": "object", "description": "Business context factors: data_sensitivity, internet_facing, user_count, regulatory"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "suggest_remediation",
        "description": "Generate AI-powered remediation suggestions for a finding or set of findings with step-by-step guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding ID to generate remediation for"},
                "project_id": {"type": "string", "description": "Project ID (generates for all open findings if finding_id omitted)"},
                "detail_level": {"type": "string", "enum": ["brief", "standard", "detailed"], "default": "standard"},
                "include_code": {"type": "boolean", "description": "Include code samples and configuration snippets", "default": True},
                "target_audience": {"type": "string", "enum": ["developer", "sysadmin", "management"], "default": "developer"},
            },
            "required": [],
        },
    },
    {
        "name": "get_executive_summary",
        "description": "Generate an executive summary of the security assessment with key metrics, top risks, and strategic recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "include_charts": {"type": "boolean", "description": "Include visual charts and graphs data", "default": True},
                "comparison_project": {"type": "string", "description": "Previous project ID for trend comparison"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "get_finding_statistics",
        "description": "Get statistical breakdown of findings by severity, status, category, target, and timeline for a project.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "group_by": {"type": "string", "enum": ["severity", "status", "category", "target", "cwe", "owasp"], "default": "severity"},
                "time_range": {"type": "string", "description": "Time range filter (e.g. 'last_24h', 'last_7d', 'all')", "default": "all"},
            },
            "required": ["project_id"],
        },
    },
)
