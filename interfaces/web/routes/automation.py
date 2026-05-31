"""Automation and Scheduling API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api", tags=["automation"])

class ScheduleScanRequest(BaseModel):
    scan_type: str
    project_id: str
    schedule: str
    parameters: Optional[Dict[str, Any]] = None

class RemoveJobRequest(BaseModel):
    job_id: str

@router.get("/automation/jobs")
async def list_jobs(request: Request):
    """List all scheduled jobs."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, app_state.get("config", {}))
    jobs = await engine.list_jobs()
    return {"jobs": jobs}

@router.post("/automation/schedule-scan")
async def schedule_scan(request: Request, body: ScheduleScanRequest):
    """Schedule a scan."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    result = await engine.schedule_scan(
        body.scan_type,
        body.project_id,
        body.schedule,
        body.parameters
    )
    return result

@router.get("/automation/status")
async def get_scheduler_status(request: Request):
    """Get scheduler status."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, app_state.get("config", {}))
    status = await engine.get_scheduler_status()
    return status

@router.post("/automation/remove-job")
async def remove_job(request: Request, body: RemoveJobRequest):
    """Remove a scheduled job."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    result = await engine.remove_job(body.job_id)
    return result
