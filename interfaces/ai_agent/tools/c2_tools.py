"""C2 (Command and Control) tool definitions (8 tools)."""

C2_TOOLS = (
    {
        "name": "connect_metasploit",
        "description": "Connect to Metasploit Framework RPC server for exploit and post-exploitation operations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Metasploit RPC host (default: localhost)"},
                "port": {"type": "integer", "description": "Metasploit RPC port (default: 55553)"},
                "username": {"type": "string", "description": "RPC username"},
                "password": {"type": "string", "description": "RPC password"},
            },
            "required": ["username", "password"],
        },
    },
    {
        "name": "list_metasploit_modules",
        "description": "List available Metasploit modules (exploits, payloads, auxiliary, post) with descriptions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "module_type": {"type": "string", "description": "Module type: exploit, payload, auxiliary, post, encoder, nop"},
                "search_term": {"type": "string", "description": "Search term to filter modules (optional)"},
            },
            "required": [],
        },
    },
    {
        "name": "create_metasploit_listener",
        "description": "Create a Metasploit listener/handler for receiving reverse shells or meterpreter sessions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Payload type (e.g., windows/meterpreter/reverse_tcp)"},
                "lhost": {"type": "string", "description": "Listening host IP"},
                "lport": {"type": "integer", "description": "Listening port"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["payload", "lhost", "lport", "project_id"],
        },
    },
    {
        "name": "list_c2_sessions",
        "description": "List all active C2 sessions (Metasploit, Sliver, or other frameworks) with connection details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "description": "C2 framework: metasploit, sliver, or all (default: all)"},
                "project_id": {"type": "string", "description": "Project ID (optional)"},
            },
            "required": [],
        },
    },
    {
        "name": "c2_session_command",
        "description": "Execute a command in an active C2 session and retrieve output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "C2 session ID"},
                "command": {"type": "string", "description": "Command to execute"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["session_id", "command", "project_id"],
        },
    },
    {
        "name": "generate_stager",
        "description": "Generate a payload stager for initial access (shellcode, executable, script, or other formats).",
        "input_schema": {
            "type": "object",
            "properties": {
                "payload_type": {"type": "string", "description": "Payload type (meterpreter, shell, beacon, etc.)"},
                "format": {"type": "string", "description": "Output format: exe, dll, ps1, vbs, hta, raw, etc."},
                "lhost": {"type": "string", "description": "Callback host IP"},
                "lport": {"type": "integer", "description": "Callback port"},
                "project_id": {"type": "string", "description": "Project ID"},
                "encoder": {"type": "string", "description": "Encoder to use (optional)"},
            },
            "required": ["payload_type", "format", "lhost", "lport", "project_id"],
        },
    },
    {
        "name": "connect_sliver",
        "description": "Connect to Sliver C2 server for advanced post-exploitation and red team operations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Sliver server host"},
                "port": {"type": "integer", "description": "Sliver server port (default: 31337)"},
                "config_path": {"type": "string", "description": "Path to Sliver operator config file"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "get_c2_status",
        "description": "Get status of all C2 frameworks including active sessions, listeners, and connection health.",
        "input_schema": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "description": "Specific framework to check (optional)"},
            },
            "required": [],
        },
    },
)
