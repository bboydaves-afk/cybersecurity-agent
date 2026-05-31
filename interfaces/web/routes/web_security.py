"""Web application security API routes."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/web", tags=["web_security"])


class HeaderAnalysisRequest(BaseModel):
    url: str


class SslTestRequest(BaseModel):
    hostname: str
    port: int = 443


class DirFuzzRequest(BaseModel):
    url: str
    wordlist: str = "common"
    extensions: list[str] = [".php", ".html", ".js", ".txt"]
    threads: int = 10
    project_id: Optional[str] = None
    target_id: Optional[str] = None


class CrawlRequest(BaseModel):
    url: str
    max_depth: int = 3
    max_pages: int = 100
    project_id: Optional[str] = None
    target_id: Optional[str] = None


@router.get("/endpoints")
async def list_endpoints(request: Request, target_id: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    if target_id:
        endpoints = await db.fetch_all(
            "SELECT * FROM web_endpoints WHERE target_id=? ORDER BY url", (target_id,))
    else:
        endpoints = await db.fetch_all("SELECT * FROM web_endpoints ORDER BY discovered_at DESC LIMIT 200")
    return {"endpoints": endpoints}


@router.get("/scans")
async def list_web_scans(request: Request, project_id: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    query = "SELECT * FROM scans WHERE scan_type LIKE 'web_%'"
    params = []
    if project_id:
        query += " AND project_id=?"
        params.append(project_id)
    query += " ORDER BY started_at DESC LIMIT 50"

    scans = await db.fetch_all(query, tuple(params))
    return {"scans": scans}


@router.post("/headers")
async def analyze_headers(request: Request, body: HeaderAnalysisRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    result = await engine.analyze_headers(body.url)
    return result


@router.post("/ssl")
async def test_ssl(request: Request, body: SslTestRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    result = await engine.test_ssl(body.hostname, body.port)
    return result


@router.post("/dirfuzz")
async def directory_fuzz(request: Request, body: DirFuzzRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    result = await engine.directory_fuzz(
        body.url, wordlist=body.wordlist, extensions=body.extensions,
        threads=body.threads, project_id=body.project_id, target_id=body.target_id)
    return result


@router.post("/crawl")
async def crawl_site(request: Request, body: CrawlRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    result = await engine.crawl(
        body.url, max_depth=body.max_depth, max_pages=body.max_pages,
        project_id=body.project_id, target_id=body.target_id)
    return result
