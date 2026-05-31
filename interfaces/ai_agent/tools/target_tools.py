"""Target management tool definitions (5 tools)."""

TARGET_TOOLS = (
    {
        "name": "add_target",
        "description": "Add a new target to a project with type classification, scope designation, and optional metadata.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Target name or identifier"},
                "target_type": {"type": "string", "enum": ["ip", "hostname", "domain", "url", "cidr", "cloud_account"], "description": "Type of target"},
                "value": {"type": "string", "description": "Target value (IP address, hostname, domain, URL, CIDR range, or account ID)"},
                "in_scope": {"type": "boolean", "description": "Whether the target is in-scope for testing", "default": True},
                "os": {"type": "string", "description": "Known operating system (e.g. 'linux', 'windows', 'unknown')"},
                "notes": {"type": "string", "description": "Additional notes about the target"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization (e.g. 'production', 'web', 'database')"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["name", "target_type", "value", "project_id"],
        },
    },
    {
        "name": "list_targets",
        "description": "List all targets in a project with optional filters for scope, type, and tags.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "scope_filter": {"type": "string", "enum": ["in_scope", "out_of_scope", "all"], "default": "all"},
                "type_filter": {"type": "string", "enum": ["ip", "hostname", "domain", "url", "cidr", "cloud_account", "all"], "default": "all"},
                "tag_filter": {"type": "string", "description": "Filter by tag"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "update_scope",
        "description": "Update the scope designation of a target (in-scope or out-of-scope) to control which targets are eligible for active testing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target ID to update"},
                "in_scope": {"type": "boolean", "description": "New scope status (true=in-scope, false=out-of-scope)"},
                "reason": {"type": "string", "description": "Reason for the scope change"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target_id", "in_scope"],
        },
    },
    {
        "name": "get_target_info",
        "description": "Get detailed information about a target including scan results, findings, services, and historical activity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target ID"},
                "include_findings": {"type": "boolean", "description": "Include associated findings", "default": True},
                "include_services": {"type": "boolean", "description": "Include discovered services", "default": True},
                "include_history": {"type": "boolean", "description": "Include scan and activity history", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target_id"],
        },
    },
    {
        "name": "remove_target",
        "description": "Remove a target from a project. This does not delete associated findings but unlinks the target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_id": {"type": "string", "description": "Target ID to remove"},
                "archive_data": {"type": "boolean", "description": "Archive associated scan data before removal", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target_id", "project_id"],
        },
    },
)
