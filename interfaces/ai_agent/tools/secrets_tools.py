"""Secrets scanning tool definitions (10 tools)."""

SECRETS_TOOLS = (
    {
        "name": "scan_directory_secrets",
        "description": "Scan a directory recursively for exposed secrets, API keys, credentials, and sensitive data using pattern matching and entropy analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory_path": {"type": "string", "description": "Directory path to scan for secrets"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "max_depth": {"type": "integer", "description": "Maximum directory depth to scan (default: unlimited)"},
                "exclude_patterns": {"type": "array", "items": {"type": "string"}, "description": "File/directory patterns to exclude (e.g., node_modules, .git)"},
            },
            "required": ["directory_path", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_git_secrets",
        "description": "Scan Git repository history for exposed secrets, credentials, and sensitive data in commits, including deleted files and branches.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to Git repository"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "scan_all_branches": {"type": "boolean", "description": "Scan all branches (default: false)"},
                "max_commits": {"type": "integer", "description": "Maximum number of commits to scan (default: 1000)"},
            },
            "required": ["repo_path", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_file_secrets",
        "description": "Scan a specific file for exposed secrets, API keys, passwords, tokens, and other sensitive data using pattern matching.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "File path to scan"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["file_path", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_env_files",
        "description": "Scan for and analyze environment files (.env, .env.local, config files) for exposed secrets and misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory_path": {"type": "string", "description": "Directory to search for environment files"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["directory_path", "project_id", "target_id"],
        },
    },
    {
        "name": "check_cloud_secrets",
        "description": "Check for exposed cloud provider secrets (AWS keys, Azure credentials, GCP service accounts) in files and environment.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_path": {"type": "string", "description": "Path to scan for cloud secrets"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "cloud_providers": {"type": "array", "items": {"type": "string"}, "description": "Cloud providers to check (aws, azure, gcp)"},
            },
            "required": ["scan_path", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_config_files",
        "description": "Scan configuration files (YAML, JSON, XML, INI, TOML) for exposed secrets, credentials, and sensitive data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "directory_path": {"type": "string", "description": "Directory containing config files"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "config_types": {"type": "array", "items": {"type": "string"}, "description": "Config file types to scan (yaml, json, xml, ini, toml)"},
            },
            "required": ["directory_path", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_docker_secrets",
        "description": "Scan Docker images, Dockerfiles, and docker-compose files for exposed secrets and misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "Path to Docker files or image name"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "scan_type": {"type": "string", "description": "Type of scan: dockerfile, image, or compose"},
            },
            "required": ["target_path", "project_id", "target_id"],
        },
    },
    {
        "name": "get_secret_patterns",
        "description": "Get list of secret patterns being used for detection, including regex patterns and entropy thresholds.",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Pattern category (api_keys, passwords, tokens, cloud, database, etc.)"},
            },
            "required": [],
        },
    },
    {
        "name": "validate_secret_findings",
        "description": "Validate detected secrets by checking if they are active/valid through API calls or other verification methods.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_ids": {"type": "array", "items": {"type": "string"}, "description": "List of finding IDs to validate"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["finding_ids", "project_id"],
        },
    },
    {
        "name": "generate_secrets_report",
        "description": "Generate a comprehensive report of all secrets scanning findings with severity, recommendations, and remediation steps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID (optional, for specific target)"},
                "format": {"type": "string", "description": "Report format: html, json, or markdown (default: html)"},
                "include_validated": {"type": "boolean", "description": "Include validation results (default: true)"},
            },
            "required": ["project_id"],
        },
    },
)
