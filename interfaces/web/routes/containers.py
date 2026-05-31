"""Container Security API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["containers"])

class ScanImageRequest(BaseModel):
    image_name: str
    project_id: str
    registry: Optional[str] = None

class CheckDockerRequest(BaseModel):
    project_id: str
    host: Optional[str] = None

class ListContainersRequest(BaseModel):
    project_id: str
    host: Optional[str] = None

class ContainerAssessmentRequest(BaseModel):
    project_id: str
    host: Optional[str] = None

@router.post("/containers/scan-image")
async def scan_image(request: Request, body: ScanImageRequest):
    """Scan container image for vulnerabilities."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    result = await engine.scan_image(
        body.image_name,
        body.project_id,
        body.registry
    )
    return result

@router.post("/containers/check-docker")
async def check_docker(request: Request, body: CheckDockerRequest):
    """Check Docker daemon security configuration."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    result = await engine.check_docker_security(
        body.project_id,
        body.host
    )
    return result

@router.post("/containers/list")
async def list_containers(request: Request, body: ListContainersRequest):
    """List running containers."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    result = await engine.list_containers(
        body.project_id,
        body.host
    )
    return result

@router.post("/containers/assessment")
async def container_assessment(request: Request, body: ContainerAssessmentRequest):
    """Perform comprehensive container security assessment."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    result = await engine.run_assessment(
        body.project_id,
        body.host
    )
    return result
