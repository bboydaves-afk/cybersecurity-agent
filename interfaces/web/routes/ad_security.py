"""Active Directory Security API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["ad_security"])

class EnumerateDomainRequest(BaseModel):
    domain_controller: str
    project_id: str
    username: Optional[str] = None
    password: Optional[str] = None

class EnumerateUsersRequest(BaseModel):
    domain_controller: str
    project_id: str
    username: Optional[str] = None
    password: Optional[str] = None

class ADAssessmentRequest(BaseModel):
    domain_controller: str
    project_id: str
    username: Optional[str] = None
    password: Optional[str] = None

@router.post("/ad/enumerate-domain")
async def enumerate_domain(request: Request, body: EnumerateDomainRequest):
    """Enumerate Active Directory domain information."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.ad_security_engine import ADSecurityEngine
    engine = ADSecurityEngine(db, config)
    result = await engine.enumerate_domain(
        body.domain_controller,
        body.project_id,
        body.username,
        body.password
    )
    return result

@router.post("/ad/enumerate-users")
async def enumerate_users(request: Request, body: EnumerateUsersRequest):
    """Enumerate Active Directory users."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.ad_security_engine import ADSecurityEngine
    engine = ADSecurityEngine(db, config)
    result = await engine.enumerate_users(
        body.domain_controller,
        body.project_id,
        body.username,
        body.password
    )
    return result

@router.post("/ad/assessment")
async def ad_assessment(request: Request, body: ADAssessmentRequest):
    """Perform comprehensive AD security assessment."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.ad_security_engine import ADSecurityEngine
    engine = ADSecurityEngine(db, config)
    result = await engine.run_assessment(
        body.domain_controller,
        body.project_id,
        body.username,
        body.password
    )
    return result
