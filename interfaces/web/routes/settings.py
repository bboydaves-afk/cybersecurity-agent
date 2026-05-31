"""Settings and authentication API routes."""

from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api", tags=["settings"])


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class SettingsUpdateRequest(BaseModel):
    key: str
    value: str


@router.post("/auth/login")
async def login(request: Request, body: LoginRequest):
    from ..auth import (
        verify_password, create_access_token,
        DEFAULT_USERNAME, DEFAULT_PASSWORD_HASH,
    )

    if body.username != DEFAULT_USERNAME:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, DEFAULT_PASSWORD_HASH):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": body.username, "role": "admin"})
    return {"access_token": token, "token_type": "bearer", "username": body.username}


@router.post("/auth/verify")
async def verify_auth(request: Request):
    from ..auth import verify_token
    payload = verify_token(request)
    return {"valid": True, "username": payload.get("sub"), "role": payload.get("role")}


@router.get("/settings")
async def get_settings(request: Request):
    from ..app import app_state
    config = app_state.get("config", {})

    safe_config = {
        "ai_agent": {
            "model": config.get("ai_agent", {}).get("model", "claude-sonnet-4-5-20250929"),
            "max_tokens": config.get("ai_agent", {}).get("max_tokens", 8192),
        },
        "database": {
            "path": config.get("database", {}).get("path", "./data/hacking_agent.db"),
        },
        "web": {
            "host": config.get("web", {}).get("host", "127.0.0.1"),
            "port": config.get("web", {}).get("port", 8084),
        },
        "safety": {
            "require_project": config.get("safety", {}).get("require_project", True),
            "require_scope": config.get("safety", {}).get("require_scope", True),
            "max_scan_rate": config.get("safety", {}).get("max_scan_rate", 100),
        },
        "logging": {
            "level": config.get("logging", {}).get("level", "INFO"),
        },
    }
    return {"settings": safe_config}


@router.get("/settings/tools")
async def get_tool_settings(request: Request):
    from interfaces.ai_agent.tools import TOOLS
    from interfaces.ai_agent.safety import DANGEROUS_TOOLS, BLOCKED_TOOLS

    tool_list = []
    for tool in TOOLS:
        name = tool["name"]
        tool_list.append({
            "name": name,
            "description": tool.get("description", ""),
            "dangerous": name in DANGEROUS_TOOLS,
            "blocked": name in BLOCKED_TOOLS,
        })
    return {
        "tools": tool_list,
        "total": len(tool_list),
        "dangerous_count": len(DANGEROUS_TOOLS),
        "blocked_count": len(BLOCKED_TOOLS),
    }


@router.get("/audit-log")
async def get_audit_log(request: Request, limit: int = 100, offset: int = 0):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    logs = await db.fetch_all(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset))
    total = await db.fetch_one("SELECT COUNT(*) as cnt FROM audit_log")
    return {"logs": logs, "total": total["cnt"] if total else 0}
