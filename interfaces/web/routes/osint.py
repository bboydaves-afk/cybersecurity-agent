"""OSINT API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["osint"])

class DomainIntelRequest(BaseModel):
    domain: str
    project_id: str

class SearchBreachRequest(BaseModel):
    email: str
    project_id: str

class HarvestEmailsRequest(BaseModel):
    domain: str
    project_id: str
    sources: Optional[list] = None

class GithubReconRequest(BaseModel):
    target: str
    project_id: str
    search_type: Optional[str] = "user"

@router.post("/osint/domain-intel")
async def domain_intel(request: Request, body: DomainIntelRequest):
    """Gather intelligence on a domain."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    result = await engine.gather_domain_intel(
        body.domain,
        body.project_id
    )
    return result

@router.post("/osint/search-breach")
async def search_breach(request: Request, body: SearchBreachRequest):
    """Search for email in data breaches."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    result = await engine.search_breaches(
        body.email,
        body.project_id
    )
    return result

@router.post("/osint/harvest-emails")
async def harvest_emails(request: Request, body: HarvestEmailsRequest):
    """Harvest email addresses from domain."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    result = await engine.harvest_emails(
        body.domain,
        body.project_id,
        body.sources
    )
    return result

@router.post("/osint/github-recon")
async def github_recon(request: Request, body: GithubReconRequest):
    """Perform GitHub reconnaissance."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    result = await engine.github_recon(
        body.target,
        body.project_id,
        body.search_type
    )
    return result
