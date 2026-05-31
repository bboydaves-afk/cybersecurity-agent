"""Compliance API routes."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


class ComplianceCheckRequest(BaseModel):
    target: str
    framework: str = "cis"
    profile: str = "level1"
    project_id: Optional[str] = None
    target_id: Optional[str] = None


class ComplianceCompareRequest(BaseModel):
    result_id_a: str
    result_id_b: str


@router.get("/results")
async def list_compliance_results(request: Request, project_id: str = None,
                                   framework: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    query = "SELECT * FROM compliance_results WHERE 1=1"
    params = []
    if project_id:
        query += " AND project_id=?"
        params.append(project_id)
    if framework:
        query += " AND framework=?"
        params.append(framework)
    query += " ORDER BY created_at DESC LIMIT 50"

    results = await db.fetch_all(query, tuple(params))
    return {"results": results}


@router.get("/results/{result_id}")
async def get_compliance_result(request: Request, result_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    result = await db.fetch_one("SELECT * FROM compliance_results WHERE id=?", (result_id,))
    if not result:
        return {"error": "Result not found"}
    return {"result": result}


@router.post("/check")
async def run_compliance_check(request: Request, body: ComplianceCheckRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    result = await engine.run_check(
        target=body.target, framework=body.framework,
        profile=body.profile, project_id=body.project_id,
        target_id=body.target_id)
    return result


@router.get("/frameworks")
async def list_frameworks(request: Request):
    frameworks = [
        {"id": "cis", "name": "CIS Benchmarks", "description": "Center for Internet Security benchmarks",
         "profiles": ["level1", "level2"]},
        {"id": "nist", "name": "NIST 800-53", "description": "NIST Security and Privacy Controls",
         "profiles": ["low", "moderate", "high"]},
        {"id": "pci-dss", "name": "PCI DSS", "description": "Payment Card Industry Data Security Standard",
         "profiles": ["saq-a", "saq-d", "full"]},
        {"id": "iso27001", "name": "ISO 27001", "description": "Information Security Management",
         "profiles": ["annex-a"]},
        {"id": "hipaa", "name": "HIPAA", "description": "Health Insurance Portability and Accountability",
         "profiles": ["technical", "administrative", "physical"]},
        {"id": "soc2", "name": "SOC 2", "description": "Service Organization Control Type 2",
         "profiles": ["type1", "type2"]},
    ]
    return {"frameworks": frameworks}


@router.post("/compare")
async def compare_results(request: Request, body: ComplianceCompareRequest):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    result_a = await db.fetch_one("SELECT * FROM compliance_results WHERE id=?", (body.result_id_a,))
    result_b = await db.fetch_one("SELECT * FROM compliance_results WHERE id=?", (body.result_id_b,))

    if not result_a or not result_b:
        return {"error": "One or both results not found"}

    return {
        "comparison": {
            "result_a": result_a,
            "result_b": result_b,
        }
    }
