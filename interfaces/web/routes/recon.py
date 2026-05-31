"""Reconnaissance API routes."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["recon"])


class PortScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    scan_type: str = "syn"
    project_id: Optional[str] = None
    target_id: Optional[str] = None


class DnsReconRequest(BaseModel):
    domain: str
    record_types: list[str] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class SubdomainRequest(BaseModel):
    domain: str
    method: str = "all"


@router.get("/scans")
async def list_scans(request: Request, project_id: str = None, scan_type: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    query = "SELECT * FROM scans WHERE 1=1"
    params = []
    if project_id:
        query += " AND project_id=?"
        params.append(project_id)
    if scan_type:
        query += " AND scan_type=?"
        params.append(scan_type)
    query += " ORDER BY started_at DESC LIMIT 100"

    scans = await db.fetch_all(query, tuple(params))
    return {"scans": scans}


@router.get("/scans/{scan_id}")
async def get_scan(request: Request, scan_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    scan = await db.fetch_one("SELECT * FROM scans WHERE id=?", (scan_id,))
    if not scan:
        return {"error": "Scan not found"}
    return {"scan": scan}


@router.post("/scans/port-scan")
async def run_port_scan(request: Request, body: PortScanRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    result = await engine.port_scan(
        body.target, body.ports, body.scan_type, body.project_id, body.target_id)
    return result


@router.post("/scans/dns")
async def run_dns_recon(request: Request, body: DnsReconRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    result = await engine.dns_recon(body.domain, body.record_types)
    return result


@router.post("/scans/subdomains")
async def run_subdomain_enum(request: Request, body: SubdomainRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    result = await engine.subdomain_enumerate(body.domain, body.method)
    return result
