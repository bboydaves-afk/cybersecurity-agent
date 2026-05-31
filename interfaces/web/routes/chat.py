"""AI Chat API routes."""

import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger("hacking_agent.web.chat")

router = APIRouter(prefix="/api/chat", tags=["chat"])

_agent_sessions: dict = {}


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = "default"


class ChatResetRequest(BaseModel):
    session_id: Optional[str] = "default"


async def _get_or_create_agent(session_id: str, app_state: dict):
    if session_id in _agent_sessions:
        return _agent_sessions[session_id]

    from interfaces.ai_agent.agent import CyberSecurityAIAgent

    db = app_state.get("db")
    cred_mgr = app_state.get("cred_mgr")
    config = app_state.get("config", {})

    agent = CyberSecurityAIAgent(
        db=db, cred_mgr=cred_mgr, config=config)
    _agent_sessions[session_id] = agent
    return agent


@router.post("")
async def chat(request: Request, body: ChatRequest):
    from ..app import app_state

    try:
        agent = await _get_or_create_agent(body.session_id, app_state)
        response = await agent.chat(body.message)
        return {"response": response, "session_id": body.session_id}
    except Exception as e:
        logger.error("Chat error: %s", e, exc_info=True)
        return {"error": str(e)}


@router.post("/stream")
async def chat_stream(request: Request, body: ChatRequest):
    from ..app import app_state

    agent = await _get_or_create_agent(body.session_id, app_state)

    async def event_generator():
        try:
            async for event in agent.chat_stream(body.message):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            logger.error("Stream error: %s", e, exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/reset")
async def reset_chat(request: Request, body: ChatResetRequest):
    session_id = body.session_id
    if session_id in _agent_sessions:
        _agent_sessions[session_id].reset_conversation()
        return {"message": "Chat session reset", "session_id": session_id}
    return {"message": "No active session", "session_id": session_id}


@router.get("/sessions")
async def list_chat_sessions(request: Request):
    sessions = []
    for sid, agent in _agent_sessions.items():
        sessions.append({
            "session_id": sid,
            "message_count": len(agent.messages),
            "model": agent.model,
        })
    return {"sessions": sessions}
