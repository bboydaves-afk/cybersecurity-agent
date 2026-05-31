"""Compliance checking tool definitions (10 tools)."""

COMPLIANCE_TOOLS = (
    {
        "name": "check_cis_benchmark",
        "description": "Check a system or cloud environment against CIS Benchmarks for secure configuration baselines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target system IP, hostname, or cloud account ID"},
                "benchmark": {"type": "string", "description": "CIS Benchmark to check (e.g. 'cis_ubuntu_22.04', 'cis_windows_server_2022', 'cis_aws_foundations')"},
                "level": {"type": "integer", "enum": [1, 2], "description": "CIS profile level (1=basic, 2=advanced)", "default": 1},
                "sections": {"type": "array", "items": {"type": "string"}, "description": "Specific benchmark sections to check (checks all if omitted)"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target", "benchmark"],
        },
    },
    {
        "name": "check_nist_controls",
        "description": "Evaluate security controls against the NIST Cybersecurity Framework (CSF) or NIST 800-53 control families.",
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["csf", "800-53", "800-171"], "default": "csf"},
                "control_families": {"type": "array", "items": {"type": "string"}, "description": "Control families to evaluate (e.g. 'AC', 'AU', 'IA', 'SC')"},
                "target": {"type": "string", "description": "Target system or environment to evaluate"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["framework"],
        },
    },
    {
        "name": "check_pci_dss",
        "description": "Evaluate systems against PCI DSS requirements for cardholder data environments.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target system, network, or application to evaluate"},
                "requirements": {"type": "array", "items": {"type": "string"}, "description": "Specific PCI DSS requirements (e.g. 'req_1', 'req_2', 'req_6', 'req_8')"},
                "saq_type": {"type": "string", "enum": ["A", "A-EP", "B", "B-IP", "C", "C-VT", "D", "P2PE"], "description": "Self-Assessment Questionnaire type"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_iso27001",
        "description": "Evaluate security controls against ISO 27001 Annex A controls and ISO 27002 implementation guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domains": {"type": "array", "items": {"type": "string"}, "description": "ISO 27001 domains: 'A5_policies', 'A6_organization', 'A7_hr', 'A8_asset_mgmt', 'A9_access_control', 'A10_crypto', 'A11_physical', 'A12_operations', 'A13_comms', 'A14_acquisition', 'A15_supplier', 'A16_incident', 'A17_continuity', 'A18_compliance'"},
                "target": {"type": "string", "description": "Target system or environment"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": [],
        },
    },
    {
        "name": "check_owasp_compliance",
        "description": "Check web application security against OWASP Top 10, ASVS (Application Security Verification Standard), or MASVS (Mobile).",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target web application URL"},
                "standard": {"type": "string", "enum": ["top10_2021", "asvs_4.0", "masvs", "api_top10"], "default": "top10_2021"},
                "level": {"type": "integer", "enum": [1, 2, 3], "description": "ASVS verification level", "default": 1},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_hipaa",
        "description": "Evaluate systems handling protected health information (PHI) against HIPAA Security Rule requirements.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target system or environment"},
                "safeguards": {"type": "array", "items": {"type": "string"}, "description": "Safeguard categories: 'administrative', 'physical', 'technical', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "generate_compliance_report",
        "description": "Generate a detailed compliance report with findings, gaps, remediation recommendations, and an overall compliance score.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "framework": {"type": "string", "enum": ["cis", "nist", "pci_dss", "iso27001", "owasp", "hipaa", "all"], "description": "Compliance framework for the report"},
                "format": {"type": "string", "enum": ["html", "pdf", "json", "csv"], "default": "html"},
                "include_evidence": {"type": "boolean", "description": "Include evidence screenshots and command outputs", "default": True},
                "include_remediation": {"type": "boolean", "description": "Include detailed remediation guidance", "default": True},
            },
            "required": ["project_id", "framework"],
        },
    },
    {
        "name": "map_findings_to_framework",
        "description": "Map security findings from a project to specific compliance framework controls and requirements.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID with existing findings"},
                "framework": {"type": "string", "enum": ["cis", "nist_csf", "nist_800-53", "pci_dss", "iso27001", "owasp", "hipaa", "mitre_attack"], "description": "Target compliance framework to map to"},
                "severity_filter": {"type": "string", "enum": ["low", "medium", "high", "critical", "all"], "default": "all"},
            },
            "required": ["project_id", "framework"],
        },
    },
    {
        "name": "get_compliance_summary",
        "description": "Get an aggregated compliance summary for a project across all evaluated frameworks with pass/fail/partial counts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "frameworks": {"type": "array", "items": {"type": "string"}, "description": "Frameworks to include in summary (includes all if omitted)"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "remediation_priority",
        "description": "Prioritize compliance gaps and findings by impact, effort, and risk to produce a ranked remediation roadmap.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "framework": {"type": "string", "enum": ["cis", "nist", "pci_dss", "iso27001", "owasp", "hipaa", "all"], "default": "all"},
                "strategy": {"type": "string", "enum": ["risk_first", "quick_wins", "compliance_first", "effort_based"], "default": "risk_first"},
                "max_items": {"type": "integer", "description": "Maximum number of items in the remediation plan", "default": 20},
            },
            "required": ["project_id"],
        },
    },
)
