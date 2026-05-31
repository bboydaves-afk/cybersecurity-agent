"""Tool API endpoints for fleet orchestrator integration.

Exposes TOOLS and TOOL_HANDLERS from the AI agent interface over HTTP,
allowing the fleet orchestrator to discover and execute tools remotely.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import verify_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tool-api"])


class ToolExecuteRequest(BaseModel):
    tool_name: str
    params: dict[str, Any] = {}


@router.get("/api/tools")
async def list_tools(_user=Depends(verify_token)):
    """List all available AI tools."""
    from interfaces.ai_agent.tools import TOOLS

    return {"tools": list(TOOLS), "count": len(TOOLS)}


@router.post("/api/tools/execute")
async def execute_tool(req: ToolExecuteRequest, _user=Depends(verify_token)):
    """Execute an AI tool by name."""
    from interfaces.ai_agent.handlers import TOOL_HANDLERS
    from ..app import app_state

    handler = TOOL_HANDLERS.get(req.tool_name)
    if handler is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {req.tool_name}")

    db = app_state.get("db")
    cred_mgr = app_state.get("cred_mgr")
    config = app_state.get("config", {})

    try:
        result = await handler(req.params, db, cred_mgr, config)
        if result is None:
            return {"status": "ok"}
        if not isinstance(result, dict):
            return {"result": result}
        return result
    except Exception as exc:
        logger.exception("Tool execution error (%s): %s", req.tool_name, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/api/tools/search")
async def search_tools(q: str = "", _user=Depends(verify_token)):
    """Search tools by name or description."""
    from interfaces.ai_agent.tools import TOOLS

    if not q:
        return {"tools": list(TOOLS), "count": len(TOOLS), "query": q}

    q_lower = q.lower()
    matches = [
        t for t in TOOLS
        if q_lower in t.get("name", "").lower()
        or q_lower in t.get("description", "").lower()
    ]
    return {"tools": matches, "count": len(matches), "query": q}
