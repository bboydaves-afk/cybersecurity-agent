"""Targets and projects API routes."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["targets"])


class TargetCreate(BaseModel):
    project_id: str
    target_type: str = "host"
    value: str
    in_scope: bool = True
    notes: Optional[str] = ""


class ProjectCreate(BaseModel):
    name: str
    client: str = ""
    project_type: str = "pentest"
    scope_description: str = ""
    rules_of_engagement: str = ""


@router.get("/targets")
async def list_targets(request: Request, project_id: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    if project_id:
        targets = await db.fetch_all(
            "SELECT * FROM targets WHERE project_id=? ORDER BY created_at DESC", (project_id,))
    else:
        targets = await db.fetch_all("SELECT * FROM targets ORDER BY created_at DESC")
    return {"targets": targets}


@router.post("/targets")
async def create_target(request: Request, body: TargetCreate):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from core.database import generate_id, utc_now
    tid = generate_id("tgt-")
    await db.execute_commit(
        "INSERT INTO targets (id, project_id, target_type, value, in_scope, notes, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (tid, body.project_id, body.target_type, body.value, int(body.in_scope), body.notes, utc_now()))
    return {"id": tid, "message": "Target created"}


@router.get("/targets/{target_id}")
async def get_target(request: Request, target_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    target = await db.fetch_one("SELECT * FROM targets WHERE id=?", (target_id,))
    if not target:
        return {"error": "Target not found"}
    return {"target": target}


@router.get("/projects")
async def list_projects(request: Request):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    projects = await db.fetch_all("SELECT * FROM projects ORDER BY created_at DESC")
    return {"projects": projects}


@router.post("/projects")
async def create_project(request: Request, body: ProjectCreate):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from core.database import generate_id, utc_now
    pid = generate_id("proj-")
    await db.execute_commit(
        "INSERT INTO projects (id, name, client, project_type, scope_description, "
        "rules_of_engagement, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (pid, body.name, body.client, body.project_type, body.scope_description,
         body.rules_of_engagement, "active", utc_now()))
    return {"id": pid, "message": "Project created"}


@router.get("/projects/{project_id}")
async def get_project(request: Request, project_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    project = await db.fetch_one("SELECT * FROM projects WHERE id=?", (project_id,))
    if not project:
        return {"error": "Project not found"}

    targets = await db.fetch_all(
        "SELECT * FROM targets WHERE project_id=?", (project_id,))
    findings_count = await db.fetch_one(
        "SELECT COUNT(*) as cnt FROM findings WHERE project_id=?", (project_id,))

    return {
        "project": project,
        "targets": targets,
        "finding_count": findings_count["cnt"] if findings_count else 0,
    }
