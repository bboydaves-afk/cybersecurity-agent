"""Vulnerability Chains API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter(prefix="/api", tags=["vuln_chains"])

class FindChainsRequest(BaseModel):
    project_id: str
    target_host: Optional[str] = None
    min_severity: Optional[str] = "medium"

class AnalyzePathsRequest(BaseModel):
    project_id: str
    start_host: str
    target_host: str

class PrioritizeRemediationRequest(BaseModel):
    project_id: str
    max_results: Optional[int] = 10

@router.post("/vuln-chains/find")
async def find_chains(request: Request, body: FindChainsRequest):
    """Find vulnerability chains."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    result = await engine.find_chains(
        body.project_id,
        body.target_host,
        body.min_severity
    )
    return result

@router.post("/vuln-chains/analyze-paths")
async def analyze_paths(request: Request, body: AnalyzePathsRequest):
    """Analyze attack paths."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    result = await engine.analyze_attack_paths(
        body.project_id,
        body.start_host,
        body.target_host
    )
    return result

@router.post("/vuln-chains/prioritize")
async def prioritize_remediation(request: Request, body: PrioritizeRemediationRequest):
    """Prioritize remediation based on chain analysis."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    result = await engine.prioritize_remediation(
        body.project_id,
        body.max_results
    )
    return result
