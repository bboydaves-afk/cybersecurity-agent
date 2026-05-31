"""Command and Control (C2) API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api", tags=["c2"])

class ConnectMetasploitRequest(BaseModel):
    host: str
    port: Optional[int] = 55553
    username: Optional[str] = "msf"
    password: Optional[str] = None

class CreateListenerRequest(BaseModel):
    listener_type: str
    host: str
    port: int
    options: Optional[Dict[str, Any]] = None

@router.post("/c2/connect-metasploit")
async def connect_metasploit(request: Request, body: ConnectMetasploitRequest):
    """Connect to Metasploit RPC server."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    result = await engine.connect_metasploit(
        body.host,
        body.port,
        body.username,
        body.password
    )
    return result

@router.get("/c2/sessions")
async def list_sessions(request: Request):
    """List active sessions."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.c2_engine import C2Engine
    engine = C2Engine(db, app_state.get("config", {}))
    sessions = await engine.list_sessions()
    return {"sessions": sessions}

@router.post("/c2/create-listener")
async def create_listener(request: Request, body: CreateListenerRequest):
    """Create a listener."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    result = await engine.create_listener(
        body.listener_type,
        body.host,
        body.port,
        body.options
    )
    return result

@router.get("/c2/status")
async def get_status(request: Request):
    """Get C2 framework status."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.c2_engine import C2Engine
    engine = C2Engine(db, app_state.get("config", {}))
    status = await engine.get_status()
    return status
