"""Evidence collection handlers (8 handlers)."""


async def _collect_evidence(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.collect_evidence(
        params["evidence_type"],
        params["source"],
        params.get("description"),
        params.get("metadata", {}),
        params.get("project_id"),
        params.get("target_id")
    )


async def _list_evidence(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.list_evidence(
        params.get("project_id"),
        params.get("target_id"),
        params.get("evidence_type")
    )


async def _get_evidence(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.get_evidence(
        params["evidence_id"]
    )


async def _verify_evidence_integrity(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.verify_evidence_integrity(
        params["evidence_id"]
    )


async def _create_custody_entry(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.create_custody_entry(
        params["evidence_id"],
        params["action"],
        params.get("notes")
    )


async def _get_custody_chain(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.get_custody_chain(
        params["evidence_id"]
    )


async def _export_evidence_package(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.export_evidence_package(
        params.get("project_id"),
        params.get("target_id"),
        params.get("output_path"),
        params.get("include_metadata", True)
    )


async def _generate_evidence_report(params, db, cred_mgr, config):
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(db, config)
    return await engine.generate_evidence_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


EVIDENCE_HANDLERS = {
    "collect_evidence": _collect_evidence,
    "list_evidence": _list_evidence,
    "get_evidence": _get_evidence,
    "verify_evidence_integrity": _verify_evidence_integrity,
    "create_custody_entry": _create_custody_entry,
    "get_custody_chain": _get_custody_chain,
    "export_evidence_package": _export_evidence_package,
    "generate_evidence_report": _generate_evidence_report,
}
