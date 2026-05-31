"""Evidence collection tool definitions (8 tools)."""

EVIDENCE_TOOLS = (
    {
        "name": "collect_evidence",
        "description": "Collect and store digital evidence with cryptographic hash for integrity verification and chain of custody.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evidence_type": {"type": "string", "description": "Evidence type: screenshot, log_file, network_capture, file, command_output"},
                "source_path": {"type": "string", "description": "Source file path or data location"},
                "project_id": {"type": "string", "description": "Project ID"},
                "description": {"type": "string", "description": "Evidence description"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Evidence tags for categorization"},
            },
            "required": ["evidence_type", "source_path", "project_id", "description"],
        },
    },
    {
        "name": "list_evidence",
        "description": "List all collected evidence for a project with metadata and integrity status.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "evidence_type": {"type": "string", "description": "Filter by evidence type (optional)"},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by tags (optional)"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "get_evidence",
        "description": "Get detailed information about a specific piece of evidence including metadata and chain of custody.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string", "description": "Evidence ID"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["evidence_id", "project_id"],
        },
    },
    {
        "name": "verify_evidence_integrity",
        "description": "Verify the integrity of collected evidence by comparing cryptographic hashes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string", "description": "Evidence ID to verify"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["evidence_id", "project_id"],
        },
    },
    {
        "name": "create_custody_entry",
        "description": "Create a chain of custody entry documenting evidence handling, access, or transfer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string", "description": "Evidence ID"},
                "project_id": {"type": "string", "description": "Project ID"},
                "action": {"type": "string", "description": "Custody action: collected, accessed, transferred, analyzed"},
                "notes": {"type": "string", "description": "Custody notes"},
            },
            "required": ["evidence_id", "project_id", "action"],
        },
    },
    {
        "name": "get_custody_chain",
        "description": "Get complete chain of custody history for a piece of evidence.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string", "description": "Evidence ID"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["evidence_id", "project_id"],
        },
    },
    {
        "name": "export_evidence_package",
        "description": "Export evidence package with all files, metadata, hashes, and chain of custody documentation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "Specific evidence IDs (optional, exports all if not provided)"},
                "output_path": {"type": "string", "description": "Output directory path"},
                "format": {"type": "string", "description": "Package format: zip or tar (default: zip)"},
            },
            "required": ["project_id", "output_path"],
        },
    },
    {
        "name": "generate_evidence_report",
        "description": "Generate evidence collection report with inventory, integrity verification, and chain of custody.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "format": {"type": "string", "description": "Report format: html, json, or markdown (default: html)"},
                "include_custody": {"type": "boolean", "description": "Include full chain of custody (default: true)"},
            },
            "required": ["project_id"],
        },
    },
)
