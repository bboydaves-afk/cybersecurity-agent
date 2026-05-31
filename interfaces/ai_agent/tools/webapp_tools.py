"""Web application security testing tool definitions (20 tools)."""

WEBAPP_TOOLS = (
    {
        "name": "directory_fuzz",
        "description": "Fuzz for hidden directories and files on a web server using a wordlist-based approach.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to fuzz (e.g. 'https://target.com')"},
                "wordlist": {"type": "string", "description": "Wordlist to use (e.g. 'common', 'large', 'api')", "default": "common"},
                "extensions": {"type": "string", "description": "File extensions to append (e.g. 'php,html,txt')"},
                "threads": {"type": "integer", "description": "Number of concurrent threads", "default": 10},
                "status_codes": {"type": "string", "description": "HTTP status codes to match (e.g. '200,301,403')", "default": "200,301,302,403"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_xss",
        "description": "Test for Cross-Site Scripting (XSS) vulnerabilities including reflected, stored, and DOM-based XSS.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with parameters to test"},
                "parameter": {"type": "string", "description": "Specific parameter to test (tests all if omitted)"},
                "xss_type": {"type": "string", "enum": ["reflected", "stored", "dom", "all"], "default": "all"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_sqli",
        "description": "Test for SQL Injection vulnerabilities including error-based, blind, time-based, and UNION-based injection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with parameters to test"},
                "parameter": {"type": "string", "description": "Specific parameter to test (tests all if omitted)"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                "sqli_type": {"type": "string", "enum": ["error", "blind", "time", "union", "all"], "default": "all"},
                "dbms": {"type": "string", "enum": ["mysql", "postgresql", "mssql", "oracle", "sqlite", "auto"], "default": "auto"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "analyze_headers",
        "description": "Analyze HTTP response headers for security misconfigurations and missing security headers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to analyze"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_ssl_tls",
        "description": "Test SSL/TLS configuration for weak ciphers, expired certificates, protocol vulnerabilities (POODLE, BEAST, Heartbleed).",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname"},
                "port": {"type": "integer", "description": "Port number", "default": 443},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "test_cors",
        "description": "Test for Cross-Origin Resource Sharing (CORS) misconfigurations that could allow unauthorized cross-origin access.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to test"},
                "origin": {"type": "string", "description": "Custom origin header to test with"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "audit_cookies",
        "description": "Audit cookies for security attributes: Secure, HttpOnly, SameSite, path, expiration, and sensitive data exposure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to fetch cookies from"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "fuzz_api",
        "description": "Fuzz REST API endpoints with malformed inputs, boundary values, and injection payloads.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "API base URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "GET"},
                "headers": {"type": "object", "description": "Custom HTTP headers as key-value pairs"},
                "body_template": {"type": "string", "description": "JSON body template with FUZZ markers"},
                "wordlist": {"type": "string", "description": "Fuzzing wordlist type (e.g. 'injection', 'boundary', 'format')", "default": "injection"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "crawl_site",
        "description": "Crawl a website to discover pages, forms, parameters, JavaScript files, and API endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Starting URL to crawl"},
                "depth": {"type": "integer", "description": "Maximum crawl depth", "default": 3},
                "max_pages": {"type": "integer", "description": "Maximum number of pages to crawl", "default": 100},
                "scope": {"type": "string", "enum": ["strict", "subdomain", "domain"], "default": "strict"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_technologies",
        "description": "Identify web technologies, frameworks, JavaScript libraries, server software, and CMS versions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to analyze"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_csrf",
        "description": "Test for Cross-Site Request Forgery (CSRF) vulnerabilities by checking token implementation and validation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with form or state-changing endpoint"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "POST"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_open_redirect",
        "description": "Test for open redirect vulnerabilities by injecting external URLs into redirect parameters.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with redirect parameters"},
                "parameter": {"type": "string", "description": "Specific parameter to test (e.g. 'redirect', 'url', 'next')"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_csp",
        "description": "Analyze Content Security Policy (CSP) headers for weaknesses, bypasses, and misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to check CSP"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_xxe",
        "description": "Test for XML External Entity (XXE) injection vulnerabilities in XML-accepting endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL that accepts XML input"},
                "method": {"type": "string", "enum": ["POST", "PUT"], "default": "POST"},
                "content_type": {"type": "string", "description": "Content-Type header value", "default": "application/xml"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_ssrf",
        "description": "Test for Server-Side Request Forgery (SSRF) vulnerabilities by injecting internal URLs and cloud metadata endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with server-side URL parameter"},
                "parameter": {"type": "string", "description": "Parameter that accepts URLs"},
                "targets": {"type": "array", "items": {"type": "string"}, "description": "Custom internal targets to test (e.g. '169.254.169.254', 'localhost:8080')"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_idor",
        "description": "Test for Insecure Direct Object Reference (IDOR) vulnerabilities by enumerating and accessing object IDs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with object reference (e.g. '/api/users/123')"},
                "parameter": {"type": "string", "description": "Parameter containing the object ID"},
                "auth_token": {"type": "string", "description": "Authentication token for the low-privilege user"},
                "id_range": {"type": "string", "description": "Range of IDs to test (e.g. '1-100')"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_file_upload",
        "description": "Test file upload functionality for bypasses, unrestricted file types, path traversal, and code execution.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "File upload endpoint URL"},
                "field_name": {"type": "string", "description": "Form field name for file upload", "default": "file"},
                "test_types": {"type": "array", "items": {"type": "string"}, "description": "Test types: 'extension_bypass', 'content_type', 'path_traversal', 'size_limit', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_authentication",
        "description": "Test authentication mechanisms for weaknesses: brute-force protections, session management, password policy, MFA bypass.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Login or authentication endpoint URL"},
                "username_field": {"type": "string", "description": "Username form field name", "default": "username"},
                "password_field": {"type": "string", "description": "Password form field name", "default": "password"},
                "test_types": {"type": "array", "items": {"type": "string"}, "description": "Tests to run: 'lockout', 'session', 'enumeration', 'password_policy', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_rate_limiting",
        "description": "Test rate limiting and throttling on API endpoints to detect missing or weak rate controls.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target endpoint URL to test"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                "requests_count": {"type": "integer", "description": "Number of requests to send", "default": 50},
                "delay_ms": {"type": "integer", "description": "Delay between requests in milliseconds", "default": 0},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "full_web_scan",
        "description": "Run a comprehensive web application security scan combining crawling, header analysis, and active vulnerability tests.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target web application base URL"},
                "scan_depth": {"type": "integer", "description": "Crawl and scan depth", "default": 3},
                "skip_tests": {"type": "array", "items": {"type": "string"}, "description": "Test types to skip (e.g. 'xss', 'sqli')"},
                "auth_cookie": {"type": "string", "description": "Session cookie for authenticated scanning"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["url"],
        },
    },
)
