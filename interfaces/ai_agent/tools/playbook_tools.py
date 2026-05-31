"""Playbook automation tool definitions (7 tools)."""

PLAYBOOK_TOOLS = (
    {
        "name": "load_playbook",
        "description": "Load a playbook from a YAML file. Playbooks contain automated sequences of security testing actions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "playbook_path": {"type": "string", "description": "Path to the playbook YAML file"},
                "validate": {"type": "boolean", "description": "Validate playbook structure before loading", "default": True},
                "project_id": {"type": "string", "description": "Project ID to associate with the playbook"},
            },
            "required": ["playbook_path", "project_id"],
        },
    },
    {
        "name": "list_playbooks",
        "description": "List all available playbooks. Shows both built-in and custom playbooks with their descriptions and capabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Filter by playbook category (e.g., pentest, webapp, network, cloud)"},
                "include_details": {"type": "boolean", "description": "Include detailed playbook information", "default": False},
            },
            "required": [],
        },
    },
    {
        "name": "execute_playbook",
        "description": "Execute a playbook against a target. Runs all steps in the playbook automation sequence and returns results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "playbook_name": {"type": "string", "description": "Name of the playbook to execute"},
                "target_id": {"type": "string", "description": "Target ID to execute playbook against"},
                "project_id": {"type": "string", "description": "Project ID"},
                "parameters": {"type": "object", "description": "Playbook-specific parameters as key-value pairs"},
                "dry_run": {"type": "boolean", "description": "Perform a dry run without executing dangerous actions", "default": False},
                "stop_on_error": {"type": "boolean", "description": "Stop execution if any step fails", "default": False},
            },
            "required": ["playbook_name", "target_id", "project_id"],
        },
    },
    {
        "name": "get_execution_status",
        "description": "Get the current status of a running or completed playbook execution. Shows progress, results, and any errors.",
        "input_schema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string", "description": "Execution ID to check status for"},
                "include_step_details": {"type": "boolean", "description": "Include detailed status for each step", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["execution_id", "project_id"],
        },
    },
    {
        "name": "list_executions",
        "description": "List all playbook executions for a project. Filter by status, playbook, or target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "status": {"type": "string", "description": "Filter by execution status (running, completed, failed, cancelled)"},
                "playbook_name": {"type": "string", "description": "Filter by playbook name"},
                "target_id": {"type": "string", "description": "Filter by target ID"},
                "limit": {"type": "integer", "description": "Maximum number of executions to return", "default": 50},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "cancel_execution",
        "description": "Cancel a running playbook execution. Stops all pending steps and cleans up resources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string", "description": "Execution ID to cancel"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["execution_id", "project_id"],
        },
    },
    {
        "name": "validate_playbook",
        "description": "Validate a playbook YAML file for syntax errors, missing dependencies, and configuration issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "playbook_path": {"type": "string", "description": "Path to the playbook YAML file to validate"},
                "strict": {"type": "boolean", "description": "Enable strict validation with warnings as errors", "default": False},
            },
            "required": ["playbook_path"],
        },
    },
)
