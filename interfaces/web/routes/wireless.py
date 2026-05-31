"""Wireless Security API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["wireless"])

class ScanNetworksRequest(BaseModel):
    interface: str
    project_id: str
    duration: Optional[int] = 30

class AnalyzeEncryptionRequest(BaseModel):
    ssid: str
    bssid: str
    project_id: str

class DetectRogueAPsRequest(BaseModel):
    interface: str
    project_id: str
    known_bssids: Optional[list] = None

class WirelessAssessmentRequest(BaseModel):
    interface: str
    project_id: str
    duration: Optional[int] = 60

@router.post("/wireless/scan-networks")
async def scan_networks(request: Request, body: ScanNetworksRequest):
    """Scan for wireless networks."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    result = await engine.scan_networks(
        body.interface,
        body.project_id,
        body.duration
    )
    return result

@router.post("/wireless/analyze-encryption")
async def analyze_encryption(request: Request, body: AnalyzeEncryptionRequest):
    """Analyze wireless encryption strength."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    result = await engine.analyze_encryption(
        body.ssid,
        body.bssid,
        body.project_id
    )
    return result

@router.post("/wireless/detect-rogue-aps")
async def detect_rogue_aps(request: Request, body: DetectRogueAPsRequest):
    """Detect rogue access points."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    result = await engine.detect_rogue_aps(
        body.interface,
        body.project_id,
        body.known_bssids
    )
    return result

@router.post("/wireless/assessment")
async def wireless_assessment(request: Request, body: WirelessAssessmentRequest):
    """Perform comprehensive wireless security assessment."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    result = await engine.run_assessment(
        body.interface,
        body.project_id,
        body.duration
    )
    return result
