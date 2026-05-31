"""Social Engineering API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

router = APIRouter(prefix="/api", tags=["social_eng"])

class CreateCampaignRequest(BaseModel):
    name: str
    project_id: str
    campaign_type: str
    targets: List[str]
    template: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

class AnalyzePhishingRequest(BaseModel):
    email_content: str
    project_id: str

@router.get("/social-eng/campaigns")
async def list_campaigns(request: Request, project_id: Optional[str] = None):
    """List social engineering campaigns."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.social_eng_engine import SocialEngEngine
    engine = SocialEngEngine(db, app_state.get("config", {}))
    campaigns = await engine.list_campaigns(project_id)
    return {"campaigns": campaigns}

@router.post("/social-eng/create-campaign")
async def create_campaign(request: Request, body: CreateCampaignRequest):
    """Create a social engineering campaign."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.social_eng_engine import SocialEngEngine
    engine = SocialEngEngine(db, config)
    result = await engine.create_campaign(
        body.name,
        body.project_id,
        body.campaign_type,
        body.targets,
        body.template,
        body.parameters
    )
    return result

@router.get("/social-eng/campaign/{campaign_id}/results")
async def get_results(request: Request, campaign_id: str):
    """Get campaign results."""
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    from engines.social_eng_engine import SocialEngEngine
    engine = SocialEngEngine(db, app_state.get("config", {}))
    results = await engine.get_campaign_results(campaign_id)
    return results

@router.post("/social-eng/analyze-phishing")
async def analyze_phishing(request: Request, body: AnalyzePhishingRequest):
    """Analyze phishing email."""
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.social_eng_engine import SocialEngEngine
    engine = SocialEngEngine(db, config)
    result = await engine.analyze_phishing_email(
        body.email_content,
        body.project_id
    )
    return result
