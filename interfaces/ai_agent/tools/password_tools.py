"""Password auditing tool definitions (10 tools)."""

PASSWORD_TOOLS = (
    {
        "name": "identify_hash",
        "description": "Identify the hash type and algorithm from a given hash string (e.g. MD5, SHA-256, bcrypt, NTLM).",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_value": {"type": "string", "description": "Hash string to identify"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["hash_value"],
        },
    },
    {
        "name": "crack_hash",
        "description": "Attempt to crack a password hash using dictionary, rule-based, or brute-force attacks with hashcat or john.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_value": {"type": "string", "description": "Hash to crack (single hash or file path)"},
                "hash_type": {"type": "string", "description": "Hash algorithm (e.g. 'md5', 'sha256', 'ntlm', 'bcrypt', 'auto')", "default": "auto"},
                "attack_mode": {"type": "string", "enum": ["dictionary", "rules", "brute_force", "combinator", "mask"], "default": "dictionary"},
                "wordlist": {"type": "string", "description": "Wordlist to use (e.g. 'rockyou', 'custom')", "default": "rockyou"},
                "rules": {"type": "string", "description": "Rule file for rule-based attack"},
                "mask": {"type": "string", "description": "Mask pattern for brute-force (e.g. '?u?l?l?l?d?d?d?d')"},
                "max_time": {"type": "integer", "description": "Maximum time in seconds to attempt cracking", "default": 300},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["hash_value"],
        },
    },
    {
        "name": "password_spray",
        "description": "Perform a password spray attack against a service using a list of usernames and a small set of common passwords.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target service URL or IP"},
                "service": {"type": "string", "enum": ["ssh", "rdp", "smb", "ftp", "http_basic", "http_form", "ldap", "smtp", "imap"], "description": "Target service type"},
                "usernames": {"type": "array", "items": {"type": "string"}, "description": "List of usernames to try"},
                "passwords": {"type": "array", "items": {"type": "string"}, "description": "List of passwords to spray (keep small to avoid lockout)"},
                "delay": {"type": "integer", "description": "Delay between attempts in seconds to avoid lockout", "default": 5},
                "port": {"type": "integer", "description": "Target port (uses service default if omitted)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target", "service", "usernames", "passwords"],
        },
    },
    {
        "name": "validate_credential",
        "description": "Validate a single credential pair against a target service to confirm access.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target service URL or IP"},
                "service": {"type": "string", "enum": ["ssh", "rdp", "smb", "ftp", "http_basic", "http_form", "ldap", "mysql", "mssql", "postgresql"], "description": "Target service type"},
                "username": {"type": "string", "description": "Username to validate"},
                "password": {"type": "string", "description": "Password to validate"},
                "port": {"type": "integer", "description": "Target port (uses service default if omitted)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target", "service", "username", "password"],
        },
    },
    {
        "name": "brute_force",
        "description": "Perform a brute-force attack against a service with configurable character sets, length ranges, and throttling.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target service URL or IP"},
                "service": {"type": "string", "enum": ["ssh", "rdp", "smb", "ftp", "http_basic", "http_form"], "description": "Target service type"},
                "username": {"type": "string", "description": "Username to brute-force"},
                "charset": {"type": "string", "description": "Character set to use (e.g. 'lowercase', 'alphanumeric', 'all')", "default": "alphanumeric"},
                "min_length": {"type": "integer", "description": "Minimum password length to try", "default": 1},
                "max_length": {"type": "integer", "description": "Maximum password length to try", "default": 8},
                "threads": {"type": "integer", "description": "Number of concurrent threads", "default": 4},
                "max_time": {"type": "integer", "description": "Maximum time in seconds", "default": 600},
                "port": {"type": "integer", "description": "Target port"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target", "service", "username"],
        },
    },
    {
        "name": "generate_wordlist",
        "description": "Generate a custom wordlist based on target-specific keywords, patterns, and mutation rules.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keywords": {"type": "array", "items": {"type": "string"}, "description": "Seed keywords (e.g. company name, city, mascot)"},
                "mutations": {"type": "array", "items": {"type": "string"}, "description": "Mutation rules to apply: 'leet', 'capitalize', 'append_numbers', 'append_years', 'append_special', 'reverse'"},
                "min_length": {"type": "integer", "description": "Minimum word length", "default": 6},
                "max_length": {"type": "integer", "description": "Maximum word length", "default": 16},
                "max_words": {"type": "integer", "description": "Maximum number of words to generate", "default": 10000},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["keywords"],
        },
    },
    {
        "name": "check_password_policy",
        "description": "Check the password policy enforced by a target service or domain (complexity, length, lockout, history).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain controller, service, or URL"},
                "service": {"type": "string", "enum": ["ldap", "smb", "http", "kerberos"], "description": "Service to query for policy"},
                "port": {"type": "integer", "description": "Target port"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["target", "service"],
        },
    },
    {
        "name": "analyze_password_strength",
        "description": "Analyze the strength of a password or list of passwords against common attack vectors and entropy calculations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "Password to analyze (or 'file:path' for a file of passwords)"},
                "check_breaches": {"type": "boolean", "description": "Check against known breached password lists", "default": True},
                "check_patterns": {"type": "boolean", "description": "Check for common patterns (keyboard walks, dates, sequences)", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["password"],
        },
    },
    {
        "name": "extract_hashes",
        "description": "Extract password hashes from a compromised system (SAM, shadow, LSA secrets, cached credentials).",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Active session ID on the target"},
                "source": {"type": "string", "enum": ["sam", "shadow", "lsa", "cached", "ntds", "kerberos", "browser", "auto"], "default": "auto"},
                "platform": {"type": "string", "enum": ["linux", "windows"], "description": "Target OS platform"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["session_id", "platform"],
        },
    },
    {
        "name": "check_credential_reuse",
        "description": "Check if compromised credentials are reused across other services and targets in the engagement scope.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {"type": "string", "description": "Username to check"},
                "password": {"type": "string", "description": "Password or hash to check"},
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of targets to check against"},
                "services": {"type": "array", "items": {"type": "string"}, "description": "Service types to check (e.g. 'ssh', 'rdp', 'smb')"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["username", "password"],
        },
    },
)
