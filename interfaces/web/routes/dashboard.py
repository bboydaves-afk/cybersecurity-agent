"""Dashboard API routes."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_stats(request: Request):
    from ..app import app_state
    db = app_state.get("db")
    if not db:
        return {"error": "Database not initialized"}

    projects = await db.fetch_one("SELECT COUNT(*) as cnt FROM projects WHERE status='active'")
    targets = await db.fetch_one("SELECT COUNT(*) as cnt FROM targets")
    findings = await db.fetch_all(
        "SELECT severity, COUNT(*) as cnt FROM findings WHERE status != 'false_positive' GROUP BY severity")
    scans = await db.fetch_one("SELECT COUNT(*) as cnt FROM scans")
    recent_findings = await db.fetch_all(
        "SELECT id, title, severity, created_at FROM findings ORDER BY created_at DESC LIMIT 10")
    recent_scans = await db.fetch_all(
        "SELECT id, scan_type, status, started_at FROM scans ORDER BY started_at DESC LIMIT 10")

    severity_counts = {r["severity"]: r["cnt"] for r in findings}

    return {
        "active_projects": projects["cnt"] if projects else 0,
        "total_targets": targets["cnt"] if targets else 0,
        "total_scans": scans["cnt"] if scans else 0,
        "findings_by_severity": severity_counts,
        "total_findings": sum(severity_counts.values()),
        "recent_findings": recent_findings,
        "recent_scans": recent_scans,
    }
