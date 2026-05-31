"""Cloud security API routes."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/cloud", tags=["cloud_security"])


class CloudAuditRequest(BaseModel):
    provider: str = "aws"
    audit_type: str = "full"
    region: Optional[str] = None
    project_id: Optional[str] = None


class S3AuditRequest(BaseModel):
    bucket_name: Optional[str] = None
    project_id: Optional[str] = None


class IamAuditRequest(BaseModel):
    provider: str = "aws"
    project_id: Optional[str] = None


@router.get("/audits")
async def list_audits(request: Request, provider: str = None, project_id: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    query = "SELECT * FROM cloud_audits WHERE 1=1"
    params = []
    if provider:
        query += " AND provider=?"
        params.append(provider)
    if project_id:
        query += " AND project_id=?"
        params.append(project_id)
    query += " ORDER BY created_at DESC LIMIT 50"

    audits = await db.fetch_all(query, tuple(params))
    return {"audits": audits}


@router.get("/audits/{audit_id}")
async def get_audit(request: Request, audit_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    audit = await db.fetch_one("SELECT * FROM cloud_audits WHERE id=?", (audit_id,))
    if not audit:
        return {"error": "Audit not found"}
    return {"audit": audit}


@router.post("/audit")
async def run_cloud_audit(request: Request, body: CloudAuditRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.cloud_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    result = await engine.run_audit(
        provider=body.provider, audit_type=body.audit_type,
        region=body.region, project_id=body.project_id)
    return result


@router.post("/audit/s3")
async def audit_s3(request: Request, body: S3AuditRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.cloud_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    result = await engine.audit_s3_buckets(
        bucket_name=body.bucket_name, project_id=body.project_id)
    return result


@router.post("/audit/iam")
async def audit_iam(request: Request, body: IamAuditRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.cloud_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    result = await engine.audit_iam(provider=body.provider, project_id=body.project_id)
    return result
