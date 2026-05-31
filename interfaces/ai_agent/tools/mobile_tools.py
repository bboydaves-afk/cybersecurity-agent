"""Mobile security testing tool definitions (10 tools)."""

MOBILE_TOOLS = (
    {
        "name": "analyze_apk",
        "description": "Analyze Android APK file for security vulnerabilities, permissions, and potential malicious behavior.",
        "input_schema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Path to APK file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "deep_scan": {"type": "boolean", "description": "Perform deep static analysis (default: true)"},
            },
            "required": ["apk_path", "project_id"],
        },
    },
    {
        "name": "analyze_ipa",
        "description": "Analyze iOS IPA file for security vulnerabilities, entitlements, and configuration issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ipa_path": {"type": "string", "description": "Path to IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "deep_scan": {"type": "boolean", "description": "Perform deep static analysis (default: true)"},
            },
            "required": ["ipa_path", "project_id"],
        },
    },
    {
        "name": "check_app_permissions",
        "description": "Check mobile app permissions and identify excessive or dangerous permission requests.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to APK or IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "platform": {"type": "string", "description": "Platform: android or ios"},
            },
            "required": ["app_path", "project_id", "platform"],
        },
    },
    {
        "name": "check_ssl_pinning",
        "description": "Check if mobile app implements SSL/TLS certificate pinning and test bypass techniques.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to APK or IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "platform": {"type": "string", "description": "Platform: android or ios"},
            },
            "required": ["app_path", "project_id", "platform"],
        },
    },
    {
        "name": "check_data_storage",
        "description": "Check mobile app for insecure data storage (local files, databases, shared preferences, keychain).",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to APK or IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "platform": {"type": "string", "description": "Platform: android or ios"},
            },
            "required": ["app_path", "project_id", "platform"],
        },
    },
    {
        "name": "decompile_apk",
        "description": "Decompile Android APK to Java/Smali source code for manual code review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Path to APK file"},
                "output_path": {"type": "string", "description": "Output directory for decompiled code"},
                "project_id": {"type": "string", "description": "Project ID"},
                "decompiler": {"type": "string", "description": "Decompiler to use: jadx, apktool, or both (default: jadx)"},
            },
            "required": ["apk_path", "output_path", "project_id"],
        },
    },
    {
        "name": "check_api_calls",
        "description": "Check mobile app for insecure API calls, hardcoded endpoints, and API key exposure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to APK or IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "platform": {"type": "string", "description": "Platform: android or ios"},
            },
            "required": ["app_path", "project_id", "platform"],
        },
    },
    {
        "name": "check_crypto_usage",
        "description": "Check mobile app for weak cryptography, hardcoded keys, and insecure random number generation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to APK or IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "platform": {"type": "string", "description": "Platform: android or ios"},
            },
            "required": ["app_path", "project_id", "platform"],
        },
    },
    {
        "name": "owasp_mobile_check",
        "description": "Perform OWASP Mobile Top 10 security assessment on mobile application.",
        "input_schema": {
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to APK or IPA file"},
                "project_id": {"type": "string", "description": "Project ID"},
                "platform": {"type": "string", "description": "Platform: android or ios"},
            },
            "required": ["app_path", "project_id", "platform"],
        },
    },
    {
        "name": "generate_mobile_report",
        "description": "Generate comprehensive mobile security assessment report with OWASP Mobile findings and remediation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "app_path": {"type": "string", "description": "Path to analyzed APK or IPA file"},
                "format": {"type": "string", "description": "Report format: html, json, or markdown (default: html)"},
            },
            "required": ["project_id", "app_path"],
        },
    },
)
