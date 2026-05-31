"""Notification tool definitions (8 tools)."""

NOTIFICATION_TOOLS = (
    {
        "name": "configure_notification_channel",
        "description": "Configure a notification channel (Slack, email, webhook, Discord, Teams) for receiving alerts and reports.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel_type": {"type": "string", "description": "Channel type: slack, email, webhook, discord, or teams"},
                "channel_name": {"type": "string", "description": "Friendly name for the channel"},
                "config": {"type": "object", "description": "Channel-specific configuration (webhook_url, email, etc.)"},
                "enabled": {"type": "boolean", "description": "Enable channel immediately (default: true)"},
            },
            "required": ["channel_type", "channel_name", "config"],
        },
    },
    {
        "name": "list_notification_channels",
        "description": "List all configured notification channels with their status and configuration details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel_type": {"type": "string", "description": "Filter by channel type (optional)"},
                "enabled_only": {"type": "boolean", "description": "Show only enabled channels (default: false)"},
            },
            "required": [],
        },
    },
    {
        "name": "remove_notification_channel",
        "description": "Remove a configured notification channel.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel_id": {"type": "string", "description": "Channel ID to remove"},
            },
            "required": ["channel_id"],
        },
    },
    {
        "name": "send_notification",
        "description": "Send a custom notification message to a specific channel or all channels.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Notification message"},
                "channel_id": {"type": "string", "description": "Specific channel ID (optional, sends to all if not provided)"},
                "severity": {"type": "string", "description": "Severity level: info, warning, critical (default: info)"},
                "title": {"type": "string", "description": "Notification title (optional)"},
            },
            "required": ["message"],
        },
    },
    {
        "name": "notify_all_channels",
        "description": "Send a notification to all enabled notification channels.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Notification message"},
                "severity": {"type": "string", "description": "Severity level: info, warning, critical (default: info)"},
                "title": {"type": "string", "description": "Notification title (optional)"},
            },
            "required": ["message"],
        },
    },
    {
        "name": "notify_finding",
        "description": "Send a notification about a new security finding with severity and details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding ID"},
                "project_id": {"type": "string", "description": "Project ID"},
                "channel_ids": {"type": "array", "items": {"type": "string"}, "description": "Specific channel IDs (optional, sends to all if not provided)"},
            },
            "required": ["finding_id", "project_id"],
        },
    },
    {
        "name": "notify_scan_complete",
        "description": "Send a notification when a scan or assessment completes with summary results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "scan_type": {"type": "string", "description": "Type of scan completed"},
                "summary": {"type": "object", "description": "Scan summary statistics"},
                "channel_ids": {"type": "array", "items": {"type": "string"}, "description": "Specific channel IDs (optional)"},
            },
            "required": ["project_id", "scan_type"],
        },
    },
    {
        "name": "get_notification_history",
        "description": "Get history of sent notifications with delivery status and timestamps.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel_id": {"type": "string", "description": "Filter by channel ID (optional)"},
                "limit": {"type": "integer", "description": "Maximum number of notifications to return (default: 50)"},
                "severity": {"type": "string", "description": "Filter by severity level (optional)"},
            },
            "required": [],
        },
    },
)
