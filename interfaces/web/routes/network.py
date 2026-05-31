"""Network analysis API routes."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/network", tags=["network"])


@router.get("/captures")
async def list_captures():
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}
    scans = await db.fetch_all(
        "SELECT id, scan_type, status, started_at FROM scans WHERE scan_type IN ('packet_capture','arp_scan','snmp_enum') ORDER BY started_at DESC LIMIT 50"
    )
    return {"captures": scans}


@router.get("/hosts")
async def list_hosts():
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}
    hosts = await db.fetch_all(
        "SELECT id, ip_address, hostname, os_fingerprint, open_ports, status FROM network_hosts ORDER BY discovered_at DESC LIMIT 100"
    )
    return {"hosts": hosts}


@router.post("/arp-scan")
async def run_arp_scan(request: Request):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    body = await request.json()
    network = body.get("network", "192.168.1.0/24")
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config or {})
    result = await engine.arp_scan(network=network)
    return result


@router.post("/dns-enum")
async def run_dns_enum(request: Request):
    from ..app import app_state
    db, config = app_state.get("db"), app_state.get("config")
    if not db:
        return {"error": "Database not initialized"}
    body = await request.json()
    domain = body.get("domain")
    if not domain:
        return {"error": "domain required"}
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(db, config or {})
    result = await engine.dns_enumerate(domain=domain)
    return result
