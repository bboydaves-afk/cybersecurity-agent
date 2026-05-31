"""Forensics API routes."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/forensics", tags=["forensics"])


@router.get("/artifacts")
async def list_artifacts():
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}
    scans = await db.fetch_all(
        "SELECT id, scan_type, status, started_at FROM scans WHERE scan_type IN ('log_analysis','memory_analysis','file_carving') ORDER BY started_at DESC LIMIT 50"
    )
    return {"artifacts": scans}


@router.get("/timeline/{project_id}")
async def get_timeline(project_id: str):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config or {})
    result = await engine.build_timeline(project_id=project_id)
    return result


@router.post("/parse-log")
async def parse_log(request: Request):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    body = await request.json()
    log_path = body.get("log_path")
    log_type = body.get("log_type", "auto")
    if not log_path:
        return {"error": "log_path required"}
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config or {})
    result = await engine.parse_log(log_path=log_path, log_type=log_type)
    return result


@router.post("/ioc")
async def generate_ioc(request: Request):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    body = await request.json()
    project_id = body.get("project_id")
    if not project_id:
        return {"error": "project_id required"}
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config or {})
    result = await engine.generate_ioc(project_id=project_id)
    return result
