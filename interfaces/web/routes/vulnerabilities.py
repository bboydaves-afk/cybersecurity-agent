"""Vulnerability findings API routes."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None
    remediation: Optional[str] = None
    assigned_to: Optional[str] = None


class VulnScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    project_id: Optional[str] = None
    target_id: Optional[str] = None


class CveSearchRequest(BaseModel):
    query: str
    limit: int = 20


@router.get("/findings")
async def list_findings(request: Request, project_id: str = None,
                        severity: str = None, status: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if project_id:
        query += " AND project_id=?"
        params.append(project_id)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    if status:
        query += " AND status=?"
        params.append(status)
    query += (" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
              "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC")

    findings = await db.fetch_all(query, tuple(params))
    return {"findings": findings}


@router.get("/findings/{finding_id}")
async def get_finding(request: Request, finding_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    finding = await db.fetch_one("SELECT * FROM findings WHERE id=?", (finding_id,))
    if not finding:
        return {"error": "Finding not found"}
    return {"finding": finding}


@router.patch("/findings/{finding_id}")
async def update_finding(request: Request, finding_id: str, body: FindingUpdate):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    updates = []
    params = []
    if body.status is not None:
        updates.append("status=?")
        params.append(body.status)
    if body.severity is not None:
        updates.append("severity=?")
        params.append(body.severity)
    if body.notes is not None:
        updates.append("notes=?")
        params.append(body.notes)
    if body.remediation is not None:
        updates.append("remediation=?")
        params.append(body.remediation)
    if body.assigned_to is not None:
        updates.append("assigned_to=?")
        params.append(body.assigned_to)

    if not updates:
        return {"error": "No fields to update"}

    params.append(finding_id)
    await db.execute_commit(
        f"UPDATE findings SET {', '.join(updates)} WHERE id=?", tuple(params))
    return {"message": "Finding updated", "id": finding_id}


@router.post("/vulnscan")
async def run_vuln_scan(request: Request, body: VulnScanRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(db, config)
    result = await engine.vulnerability_scan(
        body.target, scan_type=body.scan_type,
        project_id=body.project_id, target_id=body.target_id)
    return result


@router.post("/cve/search")
async def search_cve(request: Request, body: CveSearchRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(db, config)
    result = await engine.search_cve(body.query, limit=body.limit)
    return result
