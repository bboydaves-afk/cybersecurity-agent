"""Wireless security tool definitions (10 tools)."""

WIRELESS_TOOLS = (
    {
        "name": "scan_wireless_networks",
        "description": "Scan for wireless networks in range and collect information about SSIDs, BSSIDs, channels, encryption, and signal strength.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Wireless interface to use for scanning"},
                "scan_duration": {"type": "integer", "description": "Scan duration in seconds", "default": 30},
                "channels": {"type": "array", "items": {"type": "integer"}, "description": "Specific channels to scan (all by default)"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["interface", "project_id"],
        },
    },
    {
        "name": "analyze_wifi_encryption",
        "description": "Analyze WiFi network encryption methods and identify weak or vulnerable configurations like WEP, WPA, or weak WPA2 setups.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bssid": {"type": "string", "description": "BSSID of the network to analyze"},
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "capture_duration": {"type": "integer", "description": "Duration to capture packets in seconds", "default": 60},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["bssid", "interface", "project_id", "target_id"],
        },
    },
    {
        "name": "detect_rogue_aps",
        "description": "Detect rogue access points and evil twin attacks by comparing discovered networks against known legitimate networks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "known_networks": {"type": "array", "items": {"type": "object"}, "description": "List of known legitimate networks with BSSIDs and SSIDs"},
                "scan_duration": {"type": "integer", "description": "Scan duration in seconds", "default": 60},
                "alert_on_detection": {"type": "boolean", "description": "Send alerts when rogue APs detected", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["interface", "project_id"],
        },
    },
    {
        "name": "check_wps",
        "description": "Check if WPS (WiFi Protected Setup) is enabled and test for WPS vulnerabilities like PIN brute force attacks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bssid": {"type": "string", "description": "BSSID of the network to check"},
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "test_pixie_dust": {"type": "boolean", "description": "Test for Pixie Dust vulnerability", "default": True},
                "test_pin_bruteforce": {"type": "boolean", "description": "Test PIN brute force (time-consuming)", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["bssid", "interface", "project_id", "target_id"],
        },
    },
    {
        "name": "deauth_detection",
        "description": "Monitor for deauthentication attacks and detect potential WiFi jamming or DoS attempts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Wireless interface to use for monitoring"},
                "bssid": {"type": "string", "description": "Specific BSSID to monitor (optional)"},
                "monitor_duration": {"type": "integer", "description": "Monitoring duration in seconds", "default": 300},
                "threshold": {"type": "integer", "description": "Deauth packet threshold to trigger alert", "default": 10},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["interface", "project_id"],
        },
    },
    {
        "name": "capture_handshake",
        "description": "Capture WPA/WPA2 4-way handshake for offline password cracking. Optionally send deauth packets to force handshake.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bssid": {"type": "string", "description": "BSSID of the target network"},
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "channel": {"type": "integer", "description": "WiFi channel of the target network"},
                "deauth": {"type": "boolean", "description": "Send deauth packets to force handshake", "default": False},
                "timeout": {"type": "integer", "description": "Capture timeout in seconds", "default": 300},
                "output_file": {"type": "string", "description": "Output file path for captured handshake"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["bssid", "interface", "channel", "project_id", "target_id"],
        },
    },
    {
        "name": "analyze_wifi_security",
        "description": "Perform comprehensive WiFi security analysis including encryption strength, authentication methods, and common vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bssid": {"type": "string", "description": "BSSID of the network to analyze"},
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Specific security checks to perform"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["bssid", "interface", "project_id", "target_id"],
        },
    },
    {
        "name": "get_connected_clients",
        "description": "Identify and enumerate clients connected to a wireless network including MAC addresses and device fingerprints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bssid": {"type": "string", "description": "BSSID of the network"},
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "channel": {"type": "integer", "description": "WiFi channel"},
                "monitor_duration": {"type": "integer", "description": "Duration to monitor for clients in seconds", "default": 60},
                "fingerprint": {"type": "boolean", "description": "Attempt to fingerprint client devices", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["bssid", "interface", "channel", "project_id", "target_id"],
        },
    },
    {
        "name": "check_wifi_isolation",
        "description": "Test if client isolation is properly configured on the wireless network by attempting peer-to-peer communication.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bssid": {"type": "string", "description": "BSSID of the network to test"},
                "interface": {"type": "string", "description": "Wireless interface to use"},
                "test_method": {"type": "string", "description": "Test method (ping, arp, broadcast)", "default": "all"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["bssid", "interface", "project_id", "target_id"],
        },
    },
    {
        "name": "generate_wireless_report",
        "description": "Generate a comprehensive wireless security assessment report with findings and recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID (optional, for single network report)"},
                "format": {"type": "string", "description": "Report format (html, pdf, json, markdown)", "default": "html"},
                "include_pcaps": {"type": "boolean", "description": "Include packet capture summaries", "default": False},
            },
            "required": ["project_id"],
        },
    },
)
