"""OSINT handlers (12 handlers)."""


async def _gather_domain_intel(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.gather_domain_intel(
        params["domain"],
        params.get("deep", False),
        params.get("project_id"),
        params.get("target_id")
    )


async def _search_breach_data(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.search_breach_data(
        params["email_or_domain"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _harvest_emails_osint(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.harvest_emails_osint(
        params["domain"],
        params.get("sources", []),
        params.get("limit", 100),
        params.get("project_id"),
        params.get("target_id")
    )


async def _social_media_recon(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.social_media_recon(
        params["username"],
        params.get("platforms", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _document_metadata(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.document_metadata(
        params["domain"],
        params.get("file_types", ["pdf", "doc", "docx", "xls", "xlsx"]),
        params.get("limit", 50),
        params.get("project_id"),
        params.get("target_id")
    )


async def _google_dorking(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.google_dorking(
        params["domain"],
        params.get("dork_type"),
        params.get("custom_dork"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _github_recon(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.github_recon(
        params["org_or_user"],
        params.get("search_code", True),
        params.get("search_commits", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _dns_intelligence(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.dns_intelligence(
        params["domain"],
        params.get("historical", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _wayback_analysis(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.wayback_analysis(
        params["url"],
        params.get("years", 5),
        params.get("project_id"),
        params.get("target_id")
    )


async def _search_pastebin(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.search_pastebin(
        params["search_term"],
        params.get("sources", ["pastebin", "github_gist", "gitlab_snippets"]),
        params.get("project_id"),
        params.get("target_id")
    )


async def _ip_reputation(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.ip_reputation(
        params["ip"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _generate_osint_report(params, db, cred_mgr, config):
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(db, config)
    return await engine.generate_osint_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


OSINT_HANDLERS = {
    "gather_domain_intel": _gather_domain_intel,
    "search_breach_data": _search_breach_data,
    "harvest_emails_osint": _harvest_emails_osint,
    "social_media_recon": _social_media_recon,
    "document_metadata": _document_metadata,
    "google_dorking": _google_dorking,
    "github_recon": _github_recon,
    "dns_intelligence": _dns_intelligence,
    "wayback_analysis": _wayback_analysis,
    "search_pastebin": _search_pastebin,
    "ip_reputation": _ip_reputation,
    "generate_osint_report": _generate_osint_report,
}
