"""Digital forensics tool definitions (12 tools)."""

FORENSICS_TOOLS = (
    {
        "name": "parse_log",
        "description": "Parse and analyze log files (syslog, auth, Apache, nginx, Windows Event) for security events and anomalies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "log_source": {"type": "string", "description": "Path to log file or log source identifier"},
                "log_type": {"type": "string", "enum": ["syslog", "auth", "apache", "nginx", "windows_event", "firewall", "application", "auto"], "default": "auto"},
                "search_pattern": {"type": "string", "description": "Regex pattern to search for in logs"},
                "time_range": {"type": "string", "description": "Time range filter (e.g. 'last_24h', 'last_7d', '2024-01-01:2024-01-31')"},
                "severity_filter": {"type": "string", "enum": ["info", "warning", "error", "critical", "all"], "default": "all"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["log_source"],
        },
    },
    {
        "name": "carve_files",
        "description": "Carve and recover files from disk images, memory dumps, or raw data using file signature detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "Path to disk image, memory dump, or raw file"},
                "file_types": {"type": "array", "items": {"type": "string"}, "description": "File types to carve: 'images', 'documents', 'archives', 'executables', 'all'"},
                "output_dir": {"type": "string", "description": "Directory to save carved files"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["source"],
        },
    },
    {
        "name": "analyze_memory",
        "description": "Analyze a memory dump for processes, network connections, loaded modules, injected code, and hidden artifacts using Volatility.",
        "input_schema": {
            "type": "object",
            "properties": {
                "memory_dump": {"type": "string", "description": "Path to memory dump file"},
                "profile": {"type": "string", "description": "OS profile (e.g. 'Win10x64', 'LinuxUbuntu2204')", "default": "auto"},
                "plugins": {"type": "array", "items": {"type": "string"}, "description": "Volatility plugins: 'pslist', 'netscan', 'malfind', 'dlllist', 'handles', 'cmdline', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["memory_dump"],
        },
    },
    {
        "name": "build_timeline",
        "description": "Build a forensic timeline from multiple evidence sources (filesystem, logs, registry, browser history, prefetch).",
        "input_schema": {
            "type": "object",
            "properties": {
                "sources": {"type": "array", "items": {"type": "string"}, "description": "Paths to evidence sources (disk images, log files, memory dumps)"},
                "time_range": {"type": "string", "description": "Time range to focus on (e.g. '2024-01-01:2024-01-31')"},
                "event_types": {"type": "array", "items": {"type": "string"}, "description": "Event types: 'file_access', 'process', 'network', 'registry', 'login', 'all'"},
                "output_format": {"type": "string", "enum": ["json", "csv", "timeline"], "default": "timeline"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["sources"],
        },
    },
    {
        "name": "collect_artifacts",
        "description": "Collect forensic artifacts from a live system or disk image including browser data, prefetch, recent files, and user activity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target system IP or disk image path"},
                "artifact_types": {"type": "array", "items": {"type": "string"}, "description": "Artifacts: 'browser', 'prefetch', 'recent_files', 'usb', 'startup', 'scheduled_tasks', 'all'"},
                "collection_method": {"type": "string", "enum": ["live", "image", "remote"], "default": "live"},
                "output_dir": {"type": "string", "description": "Directory to store collected artifacts"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "analyze_malware",
        "description": "Perform static and dynamic analysis of a suspected malware sample including PE analysis, string extraction, and behavior profiling.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the malware sample"},
                "analysis_type": {"type": "string", "enum": ["static", "dynamic", "both"], "default": "static"},
                "sandbox": {"type": "boolean", "description": "Run in sandboxed environment for dynamic analysis", "default": True},
                "check_virustotal": {"type": "boolean", "description": "Submit hash to VirusTotal for detection results", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "extract_strings",
        "description": "Extract readable strings from binary files, executables, or memory dumps with encoding detection and filtering.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to binary file or memory dump"},
                "min_length": {"type": "integer", "description": "Minimum string length to extract", "default": 4},
                "encoding": {"type": "string", "enum": ["ascii", "unicode", "both"], "default": "both"},
                "filter_pattern": {"type": "string", "description": "Regex pattern to filter extracted strings"},
                "categories": {"type": "array", "items": {"type": "string"}, "description": "String categories: 'urls', 'ips', 'emails', 'paths', 'registry', 'crypto', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "check_persistence",
        "description": "Check for persistence mechanisms on a system: startup items, scheduled tasks, services, registry keys, cron jobs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target system IP or disk image path"},
                "platform": {"type": "string", "enum": ["linux", "windows", "macos"], "description": "Target OS platform"},
                "locations": {"type": "array", "items": {"type": "string"}, "description": "Locations to check: 'startup', 'services', 'cron', 'registry', 'wmi', 'logon_scripts', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target", "platform"],
        },
    },
    {
        "name": "analyze_registry",
        "description": "Analyze Windows registry hives for forensic artifacts including user activity, installed software, USB history, and malware indicators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "registry_path": {"type": "string", "description": "Path to registry hive file or 'live' for live system"},
                "hive": {"type": "string", "enum": ["SAM", "SYSTEM", "SOFTWARE", "NTUSER", "SECURITY", "all"], "default": "all"},
                "analysis_type": {"type": "string", "enum": ["user_activity", "software", "network", "usb", "autorun", "all"], "default": "all"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["registry_path"],
        },
    },
    {
        "name": "check_rootkit",
        "description": "Scan a system for rootkit indicators including hidden processes, kernel module anomalies, and system call hooking.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target system IP or disk image path"},
                "platform": {"type": "string", "enum": ["linux", "windows"], "description": "Target OS platform"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Checks: 'hidden_processes', 'kernel_modules', 'syscall_hooks', 'file_hiding', 'network_hooks', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["target", "platform"],
        },
    },
    {
        "name": "network_forensics",
        "description": "Perform network forensics analysis on PCAP files to reconstruct sessions, extract files, and identify C2 traffic patterns.",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_file": {"type": "string", "description": "Path to PCAP capture file"},
                "analysis_type": {"type": "string", "enum": ["sessions", "file_extraction", "c2_detection", "dns_analysis", "http_analysis", "all"], "default": "all"},
                "ioc_list": {"type": "array", "items": {"type": "string"}, "description": "Known IOCs to search for in traffic (IPs, domains, hashes)"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["capture_file"],
        },
    },
    {
        "name": "generate_ioc",
        "description": "Generate Indicators of Compromise (IOCs) from forensic analysis results in STIX, OpenIOC, or YARA format.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_data": {"type": "string", "description": "Source of IOC data (analysis result ID or file path)"},
                "ioc_types": {"type": "array", "items": {"type": "string"}, "description": "IOC types: 'file_hashes', 'ips', 'domains', 'urls', 'registry', 'mutex', 'all'"},
                "output_format": {"type": "string", "enum": ["stix", "openioc", "yara", "csv", "json"], "default": "stix"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"], "default": "medium"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["source_data"],
        },
    },
)
