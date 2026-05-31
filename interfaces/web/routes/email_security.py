"""Email Security API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["email_security"])

class CheckSPFRequest(BaseModel):
    domain: str
    project_id: str

class CheckDKIMRequest(BaseModel):
    domain: str
    project_id: str
    selector: Optional[str] = "default"

class CheckDMARCRequest(BaseModel):
    domain: str
    project_id: str

class EmailPostureRequest(BaseModel):
    domain: str
    project_id: str

@router.post("/email-security/check-spf")
async def check_spf(request: Request, body: CheckSPFRequest):
    """Check SPF record configuration."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    result = await engine.check_spf(
        body.domain,
        body.project_id
    )
    return result

@router.post("/email-security/check-dkim")
async def check_dkim(request: Request, body: CheckDKIMRequest):
    """Check DKIM record configuration."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    result = await engine.check_dkim(
        body.domain,
        body.project_id,
        body.selector
    )
    return result

@router.post("/email-security/check-dmarc")
async def check_dmarc(request: Request, body: CheckDMARCRequest):
    """Check DMARC record configuration."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    result = await engine.check_dmarc(
        body.domain,
        body.project_id
    )
    return result

@router.post("/email-security/posture")
async def email_posture(request: Request, body: EmailPostureRequest):
    """Assess overall email security posture."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    result = await engine.assess_posture(
        body.domain,
        body.project_id
    )
    return result
