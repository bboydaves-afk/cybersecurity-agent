"""Automation and scheduling tool definitions (10 tools)."""

AUTOMATION_TOOLS = (
    {
        "name": "start_scheduler",
        "description": "Start the automation scheduler service to enable scheduled scans and automated tasks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "config": {"type": "object", "description": "Scheduler configuration options"},
            },
            "required": [],
        },
    },
    {
        "name": "stop_scheduler",
        "description": "Stop the automation scheduler service and cancel all pending scheduled jobs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "force": {"type": "boolean", "description": "Force stop even if jobs are running", "default": False},
            },
            "required": [],
        },
    },
    {
        "name": "schedule_scan",
        "description": "Schedule a security scan to run at a specific time or on a recurring schedule.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_type": {"type": "string", "description": "Type of scan to schedule (nmap, vuln, webapp, cloud, etc.)"},
                "target_id": {"type": "string", "description": "Target ID to scan"},
                "project_id": {"type": "string", "description": "Project ID"},
                "schedule": {"type": "object", "description": "Schedule configuration (cron, interval, or datetime)"},
                "scan_parameters": {"type": "object", "description": "Parameters for the scan"},
                "name": {"type": "string", "description": "Name for the scheduled job"},
                "enabled": {"type": "boolean", "description": "Enable the schedule immediately", "default": True},
            },
            "required": ["scan_type", "target_id", "project_id", "schedule"],
        },
    },
    {
        "name": "list_scheduled_jobs",
        "description": "List all scheduled jobs with their status, next run time, and configuration.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Filter by project ID"},
                "status": {"type": "string", "description": "Filter by status (active, paused, completed, failed)"},
                "job_type": {"type": "string", "description": "Filter by job type"},
            },
            "required": [],
        },
    },
    {
        "name": "remove_scheduled_job",
        "description": "Remove a scheduled job from the scheduler permanently.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID to remove"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["job_id", "project_id"],
        },
    },
    {
        "name": "pause_scheduled_job",
        "description": "Pause a scheduled job temporarily without removing it. The job can be resumed later.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID to pause"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["job_id", "project_id"],
        },
    },
    {
        "name": "resume_scheduled_job",
        "description": "Resume a previously paused scheduled job.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID to resume"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["job_id", "project_id"],
        },
    },
    {
        "name": "run_job_now",
        "description": "Trigger an immediate execution of a scheduled job without waiting for its next scheduled run.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID to run immediately"},
                "project_id": {"type": "string", "description": "Project ID"},
                "override_parameters": {"type": "object", "description": "Override job parameters for this execution"},
            },
            "required": ["job_id", "project_id"],
        },
    },
    {
        "name": "get_job_history",
        "description": "Get execution history for a scheduled job including past runs, results, and errors.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID to get history for"},
                "project_id": {"type": "string", "description": "Project ID"},
                "limit": {"type": "integer", "description": "Maximum number of history entries to return", "default": 50},
                "include_details": {"type": "boolean", "description": "Include detailed execution results", "default": False},
            },
            "required": ["job_id", "project_id"],
        },
    },
    {
        "name": "get_scheduler_status",
        "description": "Get the current status of the scheduler including running jobs, queue size, and health metrics.",
        "input_schema": {
            "type": "object",
            "properties": {
                "include_jobs": {"type": "boolean", "description": "Include list of currently running jobs", "default": True},
            },
            "required": [],
        },
    },
)
