"""API Security Testing API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict

router = APIRouter(prefix="/api", tags=["api_security"])

class DiscoverEndpointsRequest(BaseModel):
    base_url: str
    project_id: str
    openapi_url: Optional[str] = None

class ScanAPIRequest(BaseModel):
    base_url: str
    project_id: str
    endpoints: Optional[list] = None
    auth_token: Optional[str] = None

class AnalyzeJWTRequest(BaseModel):
    token: str
    project_id: str

@router.post("/api-security/discover-endpoints")
async def discover_endpoints(request: Request, body: DiscoverEndpointsRequest):
    """Discover API endpoints."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    result = await engine.discover_endpoints(
        body.base_url,
        body.project_id,
        body.openapi_url
    )
    return result

@router.post("/api-security/scan")
async def scan_api(request: Request, body: ScanAPIRequest):
    """Scan API for security vulnerabilities."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    result = await engine.scan_api(
        body.base_url,
        body.project_id,
        body.endpoints,
        body.auth_token
    )
    return result

@router.post("/api-security/analyze-jwt")
async def analyze_jwt(request: Request, body: AnalyzeJWTRequest):
    """Analyze JWT token for security issues."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    result = await engine.analyze_jwt(body.token, body.project_id)
    return result
