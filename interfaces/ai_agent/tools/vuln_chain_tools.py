"""Vulnerability chaining tool definitions (8 tools)."""

VULN_CHAIN_TOOLS = (
    {
        "name": "analyze_attack_paths",
        "description": "Analyze potential attack paths from external access to critical assets by chaining vulnerabilities and misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "start_point": {"type": "string", "description": "Attack starting point (external, internal, dmz)"},
                "target_assets": {"type": "array", "items": {"type": "string"}, "description": "Target assets or systems (optional)"},
                "max_depth": {"type": "integer", "description": "Maximum chain depth (default: 5)"},
            },
            "required": ["project_id", "start_point"],
        },
    },
    {
        "name": "find_vuln_chains",
        "description": "Find vulnerability chains that can be exploited sequentially to achieve privilege escalation or lateral movement.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID (optional)"},
                "min_severity": {"type": "string", "description": "Minimum vulnerability severity to include (low, medium, high, critical)"},
                "include_theoretical": {"type": "boolean", "description": "Include theoretical chains (default: false)"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "calculate_chain_risk",
        "description": "Calculate risk score for a vulnerability chain based on exploitability, impact, and likelihood.",
        "input_schema": {
            "type": "object",
            "properties": {
                "chain_id": {"type": "string", "description": "Vulnerability chain ID"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["chain_id", "project_id"],
        },
    },
    {
        "name": "suggest_pivot_paths",
        "description": "Suggest pivot paths and lateral movement opportunities based on discovered vulnerabilities and network topology.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "current_position": {"type": "string", "description": "Current compromised system or network position"},
                "target_network": {"type": "string", "description": "Target network or subnet (optional)"},
            },
            "required": ["project_id", "current_position"],
        },
    },
    {
        "name": "map_attack_surface",
        "description": "Map the complete attack surface by analyzing all entry points, vulnerabilities, and potential exploitation paths.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "scope": {"type": "string", "description": "Scope: external, internal, or full (default: full)"},
                "include_network_map": {"type": "boolean", "description": "Include network topology visualization (default: true)"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "simulate_attack",
        "description": "Simulate an attack scenario using a vulnerability chain to validate exploitability and impact.",
        "input_schema": {
            "type": "object",
            "properties": {
                "chain_id": {"type": "string", "description": "Vulnerability chain ID to simulate"},
                "project_id": {"type": "string", "description": "Project ID"},
                "dry_run": {"type": "boolean", "description": "Perform dry run without actual exploitation (default: true)"},
            },
            "required": ["chain_id", "project_id"],
        },
    },
    {
        "name": "prioritize_remediation",
        "description": "Prioritize vulnerability remediation based on chain analysis, breaking high-risk attack paths first.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "strategy": {"type": "string", "description": "Prioritization strategy: risk_based, impact_based, or effort_based (default: risk_based)"},
                "max_recommendations": {"type": "integer", "description": "Maximum number of recommendations (default: 20)"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "generate_chain_report",
        "description": "Generate a comprehensive vulnerability chaining report with attack paths, risk analysis, and remediation priorities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "format": {"type": "string", "description": "Report format: html, json, or markdown (default: html)"},
                "include_diagrams": {"type": "boolean", "description": "Include attack path diagrams (default: true)"},
            },
            "required": ["project_id"],
        },
    },
)
