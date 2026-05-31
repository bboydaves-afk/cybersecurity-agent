"""Notifications API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

router = APIRouter(prefix="/api", tags=["notifications"])

class ConfigureChannelRequest(BaseModel):
    channel_type: str
    channel_name: str
    config: Dict[str, Any]

class SendNotificationRequest(BaseModel):
    channel_name: str
    message: str
    severity: Optional[str] = "info"
    metadata: Optional[Dict[str, Any]] = None

@router.get("/notifications/channels")
async def list_channels(request: Request):
    """List all notification channels."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, app_state.get("config", {}))
    channels = await engine.list_channels()
    return {"channels": channels}

@router.post("/notifications/configure-channel")
async def configure_channel(request: Request, body: ConfigureChannelRequest):
    """Configure a notification channel."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    result = await engine.configure_channel(
        body.channel_type,
        body.channel_name,
        body.config
    )
    return result

@router.post("/notifications/send")
async def send_notification(request: Request, body: SendNotificationRequest):
    """Send a notification."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    result = await engine.send_notification(
        body.channel_name,
        body.message,
        body.severity,
        body.metadata
    )
    return result
