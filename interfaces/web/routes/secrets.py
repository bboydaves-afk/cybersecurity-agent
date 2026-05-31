"""Secrets Scanning API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["secrets"])

class ScanDirectoryRequest(BaseModel):
    directory: str
    project_id: str
    recursive: Optional[bool] = True

class ScanGitRequest(BaseModel):
    repository: str
    project_id: str
    depth: Optional[int] = 100

class ScanFileRequest(BaseModel):
    file_path: str
    project_id: str

@router.post("/secrets/scan-directory")
async def scan_directory(request: Request, body: ScanDirectoryRequest):
    """Scan directory for secrets."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    result = await engine.scan_directory(
        body.directory,
        body.project_id,
        body.recursive
    )
    return result

@router.post("/secrets/scan-git")
async def scan_git(request: Request, body: ScanGitRequest):
    """Scan Git repository for secrets."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    result = await engine.scan_git_repo(
        body.repository,
        body.project_id,
        body.depth
    )
    return result

@router.post("/secrets/scan-file")
async def scan_file(request: Request, body: ScanFileRequest):
    """Scan file for secrets."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    result = await engine.scan_file(
        body.file_path,
        body.project_id
    )
    return result

@router.get("/secrets/patterns")
async def get_patterns(request: Request):
    """Get list of secret patterns."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, app_state.get("config", {}))
    patterns = await engine.get_patterns()
    return {"patterns": patterns}
