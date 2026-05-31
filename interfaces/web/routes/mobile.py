"""Mobile Security API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["mobile"])

class AnalyzeAPKRequest(BaseModel):
    apk_path: str
    project_id: str

class AnalyzeIPARequest(BaseModel):
    ipa_path: str
    project_id: str

class OWASPCheckRequest(BaseModel):
    app_path: str
    project_id: str
    platform: str

class MobileReportRequest(BaseModel):
    project_id: str
    app_id: str

@router.post("/mobile/analyze-apk")
async def analyze_apk(request: Request, body: AnalyzeAPKRequest):
    """Analyze Android APK file."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    result = await engine.analyze_apk(
        body.apk_path,
        body.project_id
    )
    return result

@router.post("/mobile/analyze-ipa")
async def analyze_ipa(request: Request, body: AnalyzeIPARequest):
    """Analyze iOS IPA file."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    result = await engine.analyze_ipa(
        body.ipa_path,
        body.project_id
    )
    return result

@router.post("/mobile/owasp-check")
async def owasp_check(request: Request, body: OWASPCheckRequest):
    """Check against OWASP Mobile Top 10."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    result = await engine.owasp_mobile_check(
        body.app_path,
        body.project_id,
        body.platform
    )
    return result

@router.post("/mobile/report")
async def mobile_report(request: Request, body: MobileReportRequest):
    """Generate mobile security assessment report."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    result = await engine.generate_report(
        body.project_id,
        body.app_id
    )
    return result
