"""Reports API routes."""

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from pathlib import Path

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportGenerateRequest(BaseModel):
    project_id: str
    format: str = "html"
    title: Optional[str] = None
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_findings: bool = True
    include_remediation: bool = True


@router.get("")
async def list_reports(request: Request, project_id: str = None):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    if project_id:
        reports = await db.fetch_all(
            "SELECT * FROM reports WHERE project_id=? ORDER BY generated_at DESC", (project_id,))
    else:
        reports = await db.fetch_all("SELECT * FROM reports ORDER BY generated_at DESC LIMIT 50")
    return {"reports": reports}


@router.get("/{report_id}")
async def get_report(request: Request, report_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    report = await db.fetch_one("SELECT * FROM reports WHERE id=?", (report_id,))
    if not report:
        return {"error": "Report not found"}
    return {"report": report}


@router.get("/{report_id}/download")
async def download_report(request: Request, report_id: str):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    report = await db.fetch_one("SELECT * FROM reports WHERE id=?", (report_id,))
    if not report:
        return {"error": "Report not found"}

    file_path = report.get("file_path", "")
    if not file_path or not Path(file_path).exists():
        return {"error": "Report file not found"}

    return FileResponse(
        file_path,
        filename=Path(file_path).name,
        media_type="application/octet-stream",
    )


@router.post("/generate")
async def generate_report(request: Request, body: ReportGenerateRequest):
    from ..app import app_state
    db = app_state.get("db")
    config = app_state.get("config", {})
    if not db:
        return {"error": "Database not initialized"}

    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    result = await engine.generate_report(
        body.project_id,
        format=body.format,
        title=body.title,
        include_executive_summary=body.include_executive_summary,
        include_methodology=body.include_methodology,
        include_findings=body.include_findings,
        include_remediation=body.include_remediation,
    )
    return result
