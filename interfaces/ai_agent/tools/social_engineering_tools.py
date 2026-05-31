"""Social engineering tool definitions (10 tools)."""

SOCIAL_ENGINEERING_TOOLS = (
    {
        "name": "create_phishing_campaign",
        "description": "Create a phishing awareness campaign for security training and assessment purposes (authorized use only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "campaign_name": {"type": "string", "description": "Campaign name"},
                "project_id": {"type": "string", "description": "Project ID"},
                "template_id": {"type": "string", "description": "Phishing template ID"},
                "target_emails": {"type": "array", "items": {"type": "string"}, "description": "Target email addresses"},
                "landing_page_url": {"type": "string", "description": "Landing page URL (optional)"},
                "tracking_enabled": {"type": "boolean", "description": "Enable email open/click tracking (default: true)"},
            },
            "required": ["campaign_name", "project_id", "template_id", "target_emails"],
        },
    },
    {
        "name": "list_phishing_campaigns",
        "description": "List all phishing campaigns with status, statistics, and results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID (optional, shows all if not provided)"},
                "status": {"type": "string", "description": "Filter by status: draft, active, completed (optional)"},
            },
            "required": [],
        },
    },
    {
        "name": "get_campaign_results",
        "description": "Get detailed results for a phishing campaign including open rates, click rates, and credential submission.",
        "input_schema": {
            "type": "object",
            "properties": {
                "campaign_id": {"type": "string", "description": "Campaign ID"},
            },
            "required": ["campaign_id"],
        },
    },
    {
        "name": "generate_phishing_template",
        "description": "Generate a phishing email template based on common attack vectors and social engineering techniques.",
        "input_schema": {
            "type": "object",
            "properties": {
                "template_type": {"type": "string", "description": "Template type: password_reset, invoice, shipping, it_alert, payroll, etc."},
                "target_company": {"type": "string", "description": "Target company name for personalization"},
                "pretext": {"type": "string", "description": "Social engineering pretext/scenario"},
                "urgency_level": {"type": "string", "description": "Urgency level: low, medium, high (default: medium)"},
            },
            "required": ["template_type"],
        },
    },
    {
        "name": "analyze_phishing_email",
        "description": "Analyze a phishing email for social engineering techniques, red flags, and effectiveness rating.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_content": {"type": "string", "description": "Email content or headers to analyze"},
                "include_recommendations": {"type": "boolean", "description": "Include improvement recommendations (default: true)"},
            },
            "required": ["email_content"],
        },
    },
    {
        "name": "check_typosquatting",
        "description": "Check for typosquatting domains that could be used for phishing attacks against a target domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain to check"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "check_registered": {"type": "boolean", "description": "Check if typosquat domains are registered (default: true)"},
            },
            "required": ["domain", "project_id", "target_id"],
        },
    },
    {
        "name": "create_landing_page",
        "description": "Create a phishing landing page for security awareness training (authorized use only).",
        "input_schema": {
            "type": "object",
            "properties": {
                "page_type": {"type": "string", "description": "Page type: login, credential_harvester, info_collection, awareness"},
                "template": {"type": "string", "description": "Template to clone (microsoft, google, dropbox, generic)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "redirect_url": {"type": "string", "description": "URL to redirect after interaction (optional)"},
            },
            "required": ["page_type", "template", "project_id"],
        },
    },
    {
        "name": "generate_pretext",
        "description": "Generate social engineering pretexts and scenarios for authorized security assessments.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scenario_type": {"type": "string", "description": "Scenario type: tech_support, vendor, executive, hr, it_department"},
                "target_role": {"type": "string", "description": "Target employee role (optional)"},
                "objective": {"type": "string", "description": "Social engineering objective"},
            },
            "required": ["scenario_type", "objective"],
        },
    },
    {
        "name": "assess_security_awareness",
        "description": "Assess organization security awareness based on phishing campaign results and user behavior.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "campaign_ids": {"type": "array", "items": {"type": "string"}, "description": "Campaign IDs to include in assessment"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "generate_training_recommendations",
        "description": "Generate security awareness training recommendations based on phishing campaign results and user susceptibility.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "assessment_id": {"type": "string", "description": "Security awareness assessment ID"},
                "format": {"type": "string", "description": "Report format: html, json, or markdown (default: html)"},
            },
            "required": ["project_id"],
        },
    },
)
