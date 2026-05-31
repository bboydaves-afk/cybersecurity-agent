"""Automation and scheduling engine for recurring security tasks."""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime


class AutomationEngine:
    """Automation and scheduling engine for recurring security tasks."""

    def __init__(self, db, config: dict = None):
        """Initialize the automation engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("automation", {})
        self.scheduler = None
        self.jobs = {}  # In-memory job storage: {job_id: {definition}}
        self._running = False

    async def start_scheduler(self) -> Dict[str, Any]:
        """Initialize and start APScheduler with default jobs.

        Returns:
            Dict with success status and scheduler info
        """
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            from apscheduler.triggers.cron import CronTrigger
            from apscheduler.triggers.interval import IntervalTrigger
            from core.database import utc_now

            if self.scheduler and self._running:
                return {
                    "success": False,
                    "error": "Scheduler is already running"
                }

            self.scheduler = AsyncIOScheduler(timezone="UTC")
            self.scheduler.start()
            self._running = True

            # Register default jobs if configured
            default_jobs = self.config.get("default_jobs", [])
            for job_config in default_jobs:
                await self.schedule_scan(
                    scan_type=job_config["scan_type"],
                    target=job_config["target"],
                    schedule=job_config["schedule"],
                    params=job_config.get("params", {}),
                    project_id=job_config.get("project_id")
                )

            await self.db.audit(
                action="start_scheduler",
                details={"job_count": len(self.jobs)},
                timestamp=utc_now()
            )

            return {
                "success": True,
                "message": "Scheduler started successfully",
                "job_count": len(self.jobs),
                "running": self._running
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to start scheduler: {str(e)}"
            }

    async def stop_scheduler(self) -> Dict[str, Any]:
        """Shut down the scheduler gracefully.

        Returns:
            Dict with success status
        """
        try:
            from core.database import utc_now

            if not self.scheduler or not self._running:
                return {
                    "success": False,
                    "error": "Scheduler is not running"
                }

            job_count = len(self.jobs)
            self.scheduler.shutdown(wait=True)
            self._running = False
            self.jobs.clear()

            await self.db.audit(
                action="stop_scheduler",
                details={"stopped_jobs": job_count},
                timestamp=utc_now()
            )

            return {
                "success": True,
                "message": "Scheduler stopped successfully",
                "stopped_jobs": job_count
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to stop scheduler: {str(e)}"
            }

    async def schedule_scan(
        self,
        scan_type: str,
        target: str,
        schedule: Dict[str, Any],
        params: Dict[str, Any] = None,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Schedule a recurring scan.

        Args:
            scan_type: Type of scan (port_scan, vuln_scan, web_scan, compliance_check, cloud_audit)
            target: Target IP, hostname, or URL
            schedule: Schedule config with 'type' (cron/interval) and parameters
            params: Scan-specific parameters
            project_id: Project ID for the scan

        Returns:
            Dict with success status and job info
        """
        try:
            from apscheduler.triggers.cron import CronTrigger
            from apscheduler.triggers.interval import IntervalTrigger
            from core.database import generate_id, utc_now

            if not self.scheduler or not self._running:
                return {
                    "success": False,
                    "error": "Scheduler is not running. Call start_scheduler() first."
                }

            valid_scan_types = ["port_scan", "vuln_scan", "web_scan", "compliance_check", "cloud_audit"]
            if scan_type not in valid_scan_types:
                return {
                    "success": False,
                    "error": f"Invalid scan_type. Must be one of: {valid_scan_types}"
                }

            job_id = generate_id("job")
            params = params or {}

            # Create trigger based on schedule type
            schedule_type = schedule.get("type", "interval")
            if schedule_type == "cron":
                trigger = CronTrigger(
                    minute=schedule.get("minute", "0"),
                    hour=schedule.get("hour", "*"),
                    day=schedule.get("day", "*"),
                    month=schedule.get("month", "*"),
                    day_of_week=schedule.get("day_of_week", "*"),
                    timezone="UTC"
                )
            elif schedule_type == "interval":
                trigger = IntervalTrigger(
                    weeks=schedule.get("weeks", 0),
                    days=schedule.get("days", 0),
                    hours=schedule.get("hours", 0),
                    minutes=schedule.get("minutes", 30),
                    timezone="UTC"
                )
            else:
                return {
                    "success": False,
                    "error": f"Invalid schedule type: {schedule_type}. Must be 'cron' or 'interval'."
                }

            # Add job to scheduler
            self.scheduler.add_job(
                self.execute_scheduled_scan,
                trigger=trigger,
                id=job_id,
                kwargs={
                    "scan_type": scan_type,
                    "target": target,
                    "params": params,
                    "project_id": project_id
                },
                replace_existing=True
            )

            # Store job info
            self.jobs[job_id] = {
                "job_id": job_id,
                "scan_type": scan_type,
                "target": target,
                "schedule": schedule,
                "params": params,
                "project_id": project_id,
                "created_at": utc_now(),
                "paused": False
            }

            await self.db.audit(
                action="schedule_scan",
                details={
                    "job_id": job_id,
                    "scan_type": scan_type,
                    "target": target,
                    "schedule": schedule
                },
                project_id=project_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "job_id": job_id,
                "scan_type": scan_type,
                "target": target,
                "next_run": self.scheduler.get_job(job_id).next_run_time.isoformat() if self.scheduler.get_job(job_id) else None
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to schedule scan: {str(e)}"
            }

    async def list_scheduled_jobs(self) -> Dict[str, Any]:
        """List all scheduled jobs with next run time.

        Returns:
            Dict with success status and job list
        """
        try:
            if not self.scheduler or not self._running:
                return {
                    "success": False,
                    "error": "Scheduler is not running"
                }

            jobs_list = []
            for job_id, job_info in self.jobs.items():
                apscheduler_job = self.scheduler.get_job(job_id)
                jobs_list.append({
                    **job_info,
                    "next_run": apscheduler_job.next_run_time.isoformat() if apscheduler_job and apscheduler_job.next_run_time else None
                })

            return {
                "success": True,
                "jobs": jobs_list,
                "total": len(jobs_list)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to list jobs: {str(e)}"
            }

    async def remove_scheduled_job(self, job_id: str) -> Dict[str, Any]:
        """Remove a scheduled job.

        Args:
            job_id: Job ID to remove

        Returns:
            Dict with success status
        """
        try:
            from core.database import utc_now

            if not self.scheduler or not self._running:
                return {
                    "success": False,
                    "error": "Scheduler is not running"
                }

            if job_id not in self.jobs:
                return {
                    "success": False,
                    "error": f"Job {job_id} not found"
                }

            job_info = self.jobs[job_id]
            self.scheduler.remove_job(job_id)
            del self.jobs[job_id]

            await self.db.audit(
                action="remove_scheduled_job",
                details={"job_id": job_id, "job_info": job_info},
                project_id=job_info.get("project_id"),
                timestamp=utc_now()
            )

            return {
                "success": True,
                "message": f"Job {job_id} removed successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to remove job: {str(e)}"
            }

    async def pause_job(self, job_id: str) -> Dict[str, Any]:
        """Pause a scheduled job.

        Args:
            job_id: Job ID to pause

        Returns:
            Dict with success status
        """
        try:
            from core.database import utc_now

            if not self.scheduler or not self._running:
                return {
                    "success": False,
                    "error": "Scheduler is not running"
                }

            if job_id not in self.jobs:
                return {
                    "success": False,
                    "error": f"Job {job_id} not found"
                }

            self.scheduler.pause_job(job_id)
            self.jobs[job_id]["paused"] = True

            await self.db.audit(
                action="pause_job",
                details={"job_id": job_id},
                project_id=self.jobs[job_id].get("project_id"),
                timestamp=utc_now()
            )

            return {
                "success": True,
                "message": f"Job {job_id} paused successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to pause job: {str(e)}"
            }

    async def resume_job(self, job_id: str) -> Dict[str, Any]:
        """Resume a paused job.

        Args:
            job_id: Job ID to resume

        Returns:
            Dict with success status
        """
        try:
            from core.database import utc_now

            if not self.scheduler or not self._running:
                return {
                    "success": False,
                    "error": "Scheduler is not running"
                }

            if job_id not in self.jobs:
                return {
                    "success": False,
                    "error": f"Job {job_id} not found"
                }

            self.scheduler.resume_job(job_id)
            self.jobs[job_id]["paused"] = False

            await self.db.audit(
                action="resume_job",
                details={"job_id": job_id},
                project_id=self.jobs[job_id].get("project_id"),
                timestamp=utc_now()
            )

            return {
                "success": True,
                "message": f"Job {job_id} resumed successfully",
                "next_run": self.scheduler.get_job(job_id).next_run_time.isoformat() if self.scheduler.get_job(job_id) else None
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to resume job: {str(e)}"
            }

    async def run_job_now(self, job_id: str) -> Dict[str, Any]:
        """Trigger immediate execution of a scheduled job.

        Args:
            job_id: Job ID to run

        Returns:
            Dict with success status and execution result
        """
        try:
            from core.database import utc_now

            if job_id not in self.jobs:
                return {
                    "success": False,
                    "error": f"Job {job_id} not found"
                }

            job_info = self.jobs[job_id]

            await self.db.audit(
                action="run_job_now",
                details={"job_id": job_id},
                project_id=job_info.get("project_id"),
                timestamp=utc_now()
            )

            # Execute the scan
            result = await self.execute_scheduled_scan(
                scan_type=job_info["scan_type"],
                target=job_info["target"],
                params=job_info["params"],
                project_id=job_info["project_id"]
            )

            return {
                "success": True,
                "message": f"Job {job_id} executed successfully",
                "execution_result": result
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to run job: {str(e)}"
            }

    async def get_job_history(self, job_id: str, limit: int = 20) -> Dict[str, Any]:
        """Get execution history for a job from audit_log.

        Args:
            job_id: Job ID to get history for
            limit: Maximum number of history entries to return

        Returns:
            Dict with success status and execution history
        """
        try:
            if job_id not in self.jobs:
                return {
                    "success": False,
                    "error": f"Job {job_id} not found"
                }

            # Query audit log for executions
            query = """
                SELECT timestamp, action, details, status
                FROM audit_log
                WHERE details LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            """

            rows = await self.db.execute_query(
                query,
                (f'%{job_id}%', limit)
            )

            history = []
            for row in rows:
                history.append({
                    "timestamp": row[0],
                    "action": row[1],
                    "details": row[2],
                    "status": row[3]
                })

            return {
                "success": True,
                "job_id": job_id,
                "history": history,
                "count": len(history)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get job history: {str(e)}"
            }

    async def execute_scheduled_scan(
        self,
        scan_type: str,
        target: str,
        params: Dict[str, Any],
        project_id: str = None
    ) -> Dict[str, Any]:
        """Internal method called by scheduler to run scans.

        Args:
            scan_type: Type of scan to execute
            target: Target for the scan
            params: Scan parameters
            project_id: Project ID

        Returns:
            Dict with execution result
        """
        try:
            from core.database import utc_now

            start_time = utc_now()
            result = {"success": False, "error": "Unknown scan type"}

            # Execute the appropriate scan based on type
            if scan_type == "port_scan":
                from engines.recon_engine import ReconEngine
                engine = ReconEngine(self.db, self.config)
                result = await engine.port_scan(
                    target=target,
                    ports=params.get("ports", "1-1000"),
                    scan_type=params.get("scan_type", "syn"),
                    project_id=project_id
                )

            elif scan_type == "vuln_scan":
                from engines.vulnerability_engine import VulnerabilityEngine
                engine = VulnerabilityEngine(self.db, self.config)
                result = await engine.vulnerability_scan(
                    target=target,
                    scan_type=params.get("scan_type", "basic"),
                    project_id=project_id
                )

            elif scan_type == "web_scan":
                from engines.webapp_engine import WebAppEngine
                engine = WebAppEngine(self.db, self.config)
                result = await engine.scan_headers(
                    url=target,
                    project_id=project_id
                )

            elif scan_type == "compliance_check":
                from engines.compliance_engine import ComplianceEngine
                engine = ComplianceEngine(self.db, self.config)
                result = await engine.run_compliance_check(
                    target=target,
                    framework=params.get("framework", "cis"),
                    project_id=project_id
                )

            elif scan_type == "cloud_audit":
                from engines.cloud_security_engine import CloudSecurityEngine
                engine = CloudSecurityEngine(self.db, self.config)
                provider = params.get("provider", "aws")
                if provider == "aws":
                    result = await engine.audit_aws_security(project_id=project_id)
                elif provider == "azure":
                    result = await engine.audit_azure_security(project_id=project_id)
                elif provider == "gcp":
                    result = await engine.audit_gcp_security(project_id=project_id)

            end_time = utc_now()

            await self.db.audit(
                action="execute_scheduled_scan",
                details={
                    "scan_type": scan_type,
                    "target": target,
                    "params": params,
                    "result": result,
                    "duration": (end_time - start_time).total_seconds() if isinstance(end_time, datetime) and isinstance(start_time, datetime) else 0
                },
                project_id=project_id,
                timestamp=end_time
            )

            return result

        except Exception as e:
            from core.database import utc_now

            await self.db.audit(
                action="execute_scheduled_scan",
                details={
                    "scan_type": scan_type,
                    "target": target,
                    "error": str(e)
                },
                project_id=project_id,
                timestamp=utc_now()
            )

            return {
                "success": False,
                "error": f"Failed to execute scheduled scan: {str(e)}"
            }

    async def get_scheduler_status(self) -> Dict[str, Any]:
        """Return scheduler state and statistics.

        Returns:
            Dict with scheduler status
        """
        try:
            if not self.scheduler or not self._running:
                return {
                    "success": True,
                    "running": False,
                    "job_count": 0,
                    "jobs": []
                }

            next_executions = []
            for job_id in self.jobs.keys():
                apscheduler_job = self.scheduler.get_job(job_id)
                if apscheduler_job and apscheduler_job.next_run_time:
                    next_executions.append({
                        "job_id": job_id,
                        "scan_type": self.jobs[job_id]["scan_type"],
                        "target": self.jobs[job_id]["target"],
                        "next_run": apscheduler_job.next_run_time.isoformat(),
                        "paused": self.jobs[job_id].get("paused", False)
                    })

            # Sort by next run time
            next_executions.sort(key=lambda x: x["next_run"])

            return {
                "success": True,
                "running": self._running,
                "job_count": len(self.jobs),
                "paused_jobs": sum(1 for j in self.jobs.values() if j.get("paused", False)),
                "next_executions": next_executions[:10]  # Show next 10 executions
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get scheduler status: {str(e)}"
            }
