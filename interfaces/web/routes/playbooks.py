"""Playbooks API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api", tags=["playbooks"])

class ExecutePlaybookRequest(BaseModel):
    playbook_name: str
    project_id: str
    parameters: Optional[Dict[str, Any]] = None

@router.get("/playbooks/list")
async def list_playbooks(request: Request):
    """List all available playbooks."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, app_state.get("config", {}))
    playbooks = await engine.list_playbooks()
    return {"playbooks": playbooks}

@router.post("/playbooks/execute")
async def execute_playbook(request: Request, body: ExecutePlaybookRequest):
    """Execute a playbook."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    result = await engine.execute_playbook(
        body.playbook_name,
        body.project_id,
        body.parameters
    )
    return result

@router.get("/playbooks/execution/{execution_id}")
async def get_execution_status(request: Request, execution_id: str):
    """Get playbook execution status."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, app_state.get("config", {}))
    status = await engine.get_execution_status(execution_id)
    return status

@router.get("/playbooks/executions")
async def list_executions(request: Request, project_id: Optional[str] = None):
    """List playbook executions."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, app_state.get("config", {}))
    executions = await engine.list_executions(project_id)
    return {"executions": executions}
