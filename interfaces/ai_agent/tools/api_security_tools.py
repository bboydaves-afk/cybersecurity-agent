"""API security testing tool definitions (14 tools)."""

API_SECURITY_TOOLS = (
    {
        "name": "discover_api_endpoints",
        "description": "Discover API endpoints through documentation scraping, directory bruteforcing, and traffic analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "methods": {"type": "array", "items": {"type": "string"}, "description": "Discovery methods (swagger, openapi, wadl, bruteforce)"},
                "wordlist": {"type": "string", "description": "Wordlist for endpoint bruteforcing"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "project_id", "target_id"],
        },
    },
    {
        "name": "test_api_authentication",
        "description": "Test API authentication mechanisms for weaknesses including broken authentication, weak tokens, and insecure transmission.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "auth_type": {"type": "string", "description": "Authentication type (jwt, oauth, api_key, basic, bearer)"},
                "credentials": {"type": "object", "description": "Test credentials"},
                "tests": {"type": "array", "items": {"type": "string"}, "description": "Specific authentication tests to run"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "auth_type", "project_id", "target_id"],
        },
    },
    {
        "name": "test_api_authorization",
        "description": "Test API authorization and access control including IDOR, privilege escalation, and broken object level authorization.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoints": {"type": "array", "items": {"type": "string"}, "description": "Endpoints to test"},
                "user_roles": {"type": "array", "items": {"type": "object"}, "description": "User roles with credentials for testing"},
                "tests": {"type": "array", "items": {"type": "string"}, "description": "Authorization tests (idor, bola, privilege_escalation)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoints", "project_id", "target_id"],
        },
    },
    {
        "name": "test_api_rate_limiting",
        "description": "Test API rate limiting and throttling mechanisms to identify lack of or insufficient rate limits.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoint": {"type": "string", "description": "Endpoint to test"},
                "request_count": {"type": "integer", "description": "Number of requests to send", "default": 100},
                "concurrent": {"type": "boolean", "description": "Send requests concurrently", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoint", "project_id", "target_id"],
        },
    },
    {
        "name": "test_api_injection",
        "description": "Test API endpoints for injection vulnerabilities including SQL injection, NoSQL injection, command injection, and LDAP injection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoints": {"type": "array", "items": {"type": "string"}, "description": "Endpoints to test"},
                "injection_types": {"type": "array", "items": {"type": "string"}, "description": "Injection types to test (sql, nosql, command, ldap, xpath)"},
                "parameters": {"type": "array", "items": {"type": "string"}, "description": "Specific parameters to test"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoints", "project_id", "target_id"],
        },
    },
    {
        "name": "test_mass_assignment",
        "description": "Test for mass assignment vulnerabilities where APIs allow modification of object properties that should be restricted.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoint": {"type": "string", "description": "Endpoint to test"},
                "http_method": {"type": "string", "description": "HTTP method (POST, PUT, PATCH)", "default": "POST"},
                "test_parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test for mass assignment"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoint", "project_id", "target_id"],
        },
    },
    {
        "name": "analyze_jwt",
        "description": "Analyze JWT tokens for security issues including weak algorithms, missing validation, and sensitive data exposure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT token to analyze"},
                "tests": {"type": "array", "items": {"type": "string"}, "description": "Tests to perform (algorithm, signature, claims, expiration)"},
                "crack_secret": {"type": "boolean", "description": "Attempt to crack weak secrets", "default": False},
                "wordlist": {"type": "string", "description": "Wordlist for secret cracking"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["token", "project_id"],
        },
    },
    {
        "name": "test_graphql",
        "description": "Test GraphQL API security including introspection, depth limits, field suggestions, and injection vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "GraphQL endpoint URL"},
                "tests": {"type": "array", "items": {"type": "string"}, "description": "Tests to perform (introspection, depth, injection, dos)"},
                "auth_headers": {"type": "object", "description": "Authentication headers"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["endpoint", "project_id", "target_id"],
        },
    },
    {
        "name": "fuzz_api_parameters",
        "description": "Fuzz API parameters with malformed, unexpected, and malicious inputs to identify parsing errors and vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoint": {"type": "string", "description": "Endpoint to fuzz"},
                "parameters": {"type": "array", "items": {"type": "string"}, "description": "Parameters to fuzz"},
                "fuzzing_strategy": {"type": "string", "description": "Fuzzing strategy (type, boundary, format, malicious)", "default": "all"},
                "max_requests": {"type": "integer", "description": "Maximum number of fuzzing requests", "default": 1000},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoint", "parameters", "project_id", "target_id"],
        },
    },
    {
        "name": "test_cors_api",
        "description": "Test API CORS (Cross-Origin Resource Sharing) configuration for security misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoints": {"type": "array", "items": {"type": "string"}, "description": "Endpoints to test"},
                "test_origins": {"type": "array", "items": {"type": "string"}, "description": "Origins to test with"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "project_id", "target_id"],
        },
    },
    {
        "name": "test_http_methods",
        "description": "Test API endpoints for dangerous or unnecessary HTTP methods that may expose vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoints": {"type": "array", "items": {"type": "string"}, "description": "Endpoints to test"},
                "methods": {"type": "array", "items": {"type": "string"}, "description": "Methods to test (OPTIONS, TRACE, PUT, DELETE, PATCH)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoints", "project_id", "target_id"],
        },
    },
    {
        "name": "test_input_validation",
        "description": "Test API input validation including type validation, length limits, format validation, and encoding issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "endpoint": {"type": "string", "description": "Endpoint to test"},
                "parameters": {"type": "array", "items": {"type": "object"}, "description": "Parameters with expected types and constraints"},
                "validation_tests": {"type": "array", "items": {"type": "string"}, "description": "Validation tests (type, length, format, encoding)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "endpoint", "parameters", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_api_security",
        "description": "Perform a comprehensive API security scan covering OWASP API Top 10 and other common vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "Base URL of the API"},
                "api_spec": {"type": "string", "description": "Path to API specification (OpenAPI/Swagger) if available"},
                "auth_config": {"type": "object", "description": "Authentication configuration"},
                "scan_depth": {"type": "string", "description": "Scan depth (quick, standard, deep)", "default": "standard"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["base_url", "project_id", "target_id"],
        },
    },
    {
        "name": "generate_api_report",
        "description": "Generate a comprehensive API security assessment report with findings, risk ratings, and remediation recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
                "format": {"type": "string", "description": "Report format (html, pdf, json, markdown)", "default": "html"},
                "include_details": {"type": "boolean", "description": "Include detailed technical findings", "default": True},
                "executive_summary": {"type": "boolean", "description": "Include executive summary", "default": True},
            },
            "required": ["project_id", "target_id"],
        },
    },
)
