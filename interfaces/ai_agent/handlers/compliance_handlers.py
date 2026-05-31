"""Compliance checking tool handlers (10 handlers)."""


async def _check_cis_benchmark(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.cis_benchmark(
        params["target"], params.get("benchmark"),
        params.get("level", 1),
        params.get("project_id"), params.get("target_id"))


async def _check_nist_controls(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.nist_check(
        params.get("target"), params.get("framework", "csf"),
        params.get("control_families"),
        params.get("project_id"), params.get("target_id"))


async def _check_pci_dss(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.pci_dss_check(
        params["target"], params.get("requirements"),
        params.get("project_id"), params.get("target_id"))


async def _check_iso27001(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.compliance_scan(
        params.get("target", ""), "iso27001",
        params.get("domains"),
        params.get("project_id"), params.get("target_id"))


async def _check_owasp_compliance(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.compliance_scan(
        params["url"], "owasp",
        params.get("standard", "top10_2021"),
        params.get("project_id"), params.get("target_id"))


async def _check_hipaa(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.hipaa_check(
        params["target"], params.get("safeguards"),
        params.get("project_id"), params.get("target_id"))


async def _generate_compliance_report(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    return await engine.compliance_report(
        params["project_id"], params["framework"],
        params.get("format", "html"),
        params.get("include_evidence", True))


async def _map_findings_to_framework(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    method = getattr(engine, 'gap_analysis', None)
    if method:
        return await method(
            params["project_id"], params["framework"],
            params.get("severity_filter", "all"), None)
    return {
        "success": True,
        "tool": "map_findings_to_framework",
        "params": params,
        "note": "Map security findings to specific compliance framework controls and requirements",
    }


async def _get_compliance_summary(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    method = getattr(engine, 'compliance_report', None)
    if method:
        return await method(
            params["project_id"], params.get("frameworks", ["all"])[0] if params.get("frameworks") else "all",
            "json", False)
    return {
        "success": True,
        "tool": "get_compliance_summary",
        "params": params,
        "note": "Get aggregated compliance summary across all evaluated frameworks with pass/fail/partial counts",
    }


async def _remediation_priority(params, db, cred_mgr, config):
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(db, config)
    method = getattr(engine, 'gap_analysis', None)
    if method:
        return await method(
            params["project_id"], params.get("framework", "all"),
            params.get("strategy", "risk_first"),
            params.get("max_items", 20))
    return {
        "success": True,
        "tool": "remediation_priority",
        "params": params,
        "note": "Prioritize compliance gaps by impact, effort, and risk to produce a ranked remediation roadmap",
    }


COMPLIANCE_HANDLERS = {
    "check_cis_benchmark": _check_cis_benchmark,
    "check_nist_controls": _check_nist_controls,
    "check_pci_dss": _check_pci_dss,
    "check_iso27001": _check_iso27001,
    "check_owasp_compliance": _check_owasp_compliance,
    "check_hipaa": _check_hipaa,
    "generate_compliance_report": _generate_compliance_report,
    "map_findings_to_framework": _map_findings_to_framework,
    "get_compliance_summary": _get_compliance_summary,
    "remediation_priority": _remediation_priority,
}
