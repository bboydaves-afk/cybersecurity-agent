"""Evidence Collection API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api", tags=["evidence"])

class CollectEvidenceRequest(BaseModel):
    project_id: str
    evidence_type: str
    source: str
    metadata: Optional[Dict[str, Any]] = None

class VerifyIntegrityRequest(BaseModel):
    evidence_id: str

class ExportPackageRequest(BaseModel):
    project_id: str
    format: Optional[str] = "zip"
    include_reports: Optional[bool] = True

@router.post("/evidence/collect")
async def collect_evidence(request: Request, body: CollectEvidenceRequest):
    """Collect evidence."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    result = await engine.collect_evidence(
        body.project_id,
        body.evidence_type,
        body.source,
        body.metadata
    )
    return result

@router.get("/evidence/list")
async def list_evidence(request: Request, project_id: Optional[str] = None):
    """List collected evidence."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, app_state.get("config", {}))
    evidence = await engine.list_evidence(project_id)
    return {"evidence": evidence}

@router.post("/evidence/verify-integrity")
async def verify_integrity(request: Request, body: VerifyIntegrityRequest):
    """Verify evidence integrity."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    result = await engine.verify_integrity(body.evidence_id)
    return result

@router.post("/evidence/export")
async def export_package(request: Request, body: ExportPackageRequest):
    """Export evidence package."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    result = await engine.export_package(
        body.project_id,
        body.format,
        body.include_reports
    )
    return result
