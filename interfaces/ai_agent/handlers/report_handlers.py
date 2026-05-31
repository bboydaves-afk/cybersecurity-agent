"""Report tool handlers (8 handlers)."""


async def _create_finding(params, db, cred_mgr, config):
    from core.database import generate_id, utc_now
    finding_id = generate_id("fnd-")
    now = utc_now()
    await db.execute_commit(
        "INSERT INTO findings (id, project_id, target_id, title, description, severity, cvss_score, cvss_vector, cve_id, evidence, remediation, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (finding_id, params.get("project_id"), params.get("target_id"),
         params["title"], params["description"], params["severity"],
         params.get("cvss_score"), params.get("cvss_vector"),
         ",".join(params.get("cve_ids", [])) if params.get("cve_ids") else None,
         params.get("evidence"), params.get("remediation"), "open", now, now))
    await db.audit("create_finding", params.get("target_id"), params.get("project_id"),
                   f"Created finding: {params['title']}")
    return {"success": True, "finding_id": finding_id, "title": params["title"],
            "severity": params["severity"]}


async def _update_finding(params, db, cred_mgr, config):
    from core.database import utc_now
    finding_id = params["finding_id"]
    now = utc_now()
    updates = []
    values = []
    for field in ("status", "severity", "description", "evidence", "remediation", "notes"):
        if field in params:
            updates.append(f"{field} = ?")
            values.append(params[field])
    if not updates:
        return {"success": False, "error": "No fields to update"}
    updates.append("updated_at = ?")
    values.append(now)
    values.append(finding_id)
    await db.execute_commit(
        f"UPDATE findings SET {', '.join(updates)} WHERE id = ?", tuple(values))
    await db.audit("update_finding", None, params.get("project_id"),
                   f"Updated finding {finding_id}: {', '.join(f for f in ('status', 'severity', 'description', 'evidence', 'remediation', 'notes') if f in params)}")
    return {"success": True, "finding_id": finding_id, "updated_fields": [f for f in ("status", "severity", "description", "evidence", "remediation", "notes") if f in params]}


async def _generate_report(params, db, cred_mgr, config):
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    return await engine.generate_report(
        params["project_id"], params.get("report_type", "pentest"),
        params.get("format", "html"),
        params.get("classification"), params.get("include_sections"))


async def _export_findings(params, db, cred_mgr, config):
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    return await engine.export_findings(
        params["project_id"], params.get("format", "csv"),
        params.get("severity_filter"), params.get("status_filter"))


async def _calculate_risk_score(params, db, cred_mgr, config):
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    return await engine.risk_matrix(
        params["project_id"], params.get("methodology", "cvss"))


async def _suggest_remediation(params, db, cred_mgr, config):
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    return await engine.remediation_plan(
        params.get("project_id"), params.get("detail_level", "standard"),
        params.get("include_code", True))


async def _get_executive_summary(params, db, cred_mgr, config):
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    return await engine.executive_summary(
        params["project_id"], params.get("comparison_project"))


async def _get_finding_statistics(params, db, cred_mgr, config):
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(db, config)
    project_id = params["project_id"]
    group_by = params.get("group_by", "severity")
    time_range = params.get("time_range", "all")
    rows = await db.fetch_all(
        "SELECT severity, status, COUNT(*) as count FROM findings WHERE project_id = ? GROUP BY severity, status",
        (project_id,))
    by_severity = {}
    by_status = {}
    total = 0
    for row in rows:
        sev = row["severity"]
        stat = row["status"]
        cnt = row["count"]
        total += cnt
        by_severity[sev] = by_severity.get(sev, 0) + cnt
        by_status[stat] = by_status.get(stat, 0) + cnt
    return {
        "success": True,
        "project_id": project_id,
        "total_findings": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "group_by": group_by,
        "time_range": time_range,
    }


REPORT_HANDLERS = {
    "create_finding": _create_finding,
    "update_finding": _update_finding,
    "generate_report": _generate_report,
    "export_findings": _export_findings,
    "calculate_risk_score": _calculate_risk_score,
    "suggest_remediation": _suggest_remediation,
    "get_executive_summary": _get_executive_summary,
    "get_finding_statistics": _get_finding_statistics,
}
