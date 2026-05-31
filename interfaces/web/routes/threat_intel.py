"""Threat intelligence API routes."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/threat-intel", tags=["threat_intel"])


@router.get("/indicators")
async def list_indicators():
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}
    indicators = await db.fetch_all(
        "SELECT id, indicator_type, value, source, tags, first_seen FROM threat_intel ORDER BY first_seen DESC LIMIT 100"
    )
    return {"indicators": indicators}


@router.get("/attack-chains/{project_id}")
async def list_attack_chains(project_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}
    chains = await db.fetch_all(
        "SELECT id, name, tactics, created_at FROM attack_chains WHERE project_id = ? ORDER BY created_at DESC",
        (project_id,)
    )
    return {"attack_chains": chains}


@router.post("/enrich")
async def enrich_indicator(request: Request):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    body = await request.json()
    value = body.get("value")
    indicator_type = body.get("type", "ip")
    if not value:
        return {"error": "value required"}
    from engines.threat_intel_engine import ThreatIntelEngine
    cred_mgr = app_state.get("cred_mgr")
    engine = ThreatIntelEngine(db, config or {})
    result = await engine.enrich_ioc(indicator_type=indicator_type, value=value)
    return result


@router.post("/mitre-map")
async def mitre_map(request: Request):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    body = await request.json()
    project_id = body.get("project_id")
    if not project_id:
        return {"error": "project_id required"}
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config or {})
    result = await engine.map_to_mitre(project_id=project_id)
    return result
