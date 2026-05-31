"""Threat intelligence tool handlers (8 handlers)."""


async def _map_to_mitre(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.mitre_attack_map(
        params.get("project_id"), params.get("finding_id"),
        params.get("include_mitigations", True))


async def _enrich_ioc(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.ioc_lookup(
        params["indicator"], params["indicator_type"],
        params.get("sources"), params.get("project_id"))


async def _query_threat_feed(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.threat_feed(
        params["feed"], params.get("indicator_type", "all"),
        params.get("time_range", "last_7d"), params.get("limit", 50))


async def _check_indicator(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.ioc_lookup(
        params["indicator"], params.get("indicator_type", "auto"),
        None, params.get("project_id"))


async def _build_attack_chain(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.mitre_attack_map(
        params["project_id"], params["finding_ids"],
        params.get("include_timeline", True))


async def _track_campaign(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.apt_profile(
        params.get("indicators", []),
        params.get("known_campaigns", True),
        params.get("correlation_type", "all"))


async def _search_threat_intel(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    search_type = params.get("search_type", "all")
    if search_type == "malware":
        return await engine.malware_intel(
            params["query"], "summary", params.get("project_id"))
    elif search_type == "threat_actor":
        return await engine.apt_profile(
            params["query"], True, True)
    else:
        return await engine.malware_intel(
            params["query"], "summary", params.get("project_id"))


async def _get_attack_surface(params, db, cred_mgr, config):
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(db, config)
    return await engine.attack_surface_map(
        params["domain"], params.get("include_subdomains", True),
        params.get("include_cloud", True),
        params.get("project_id"), None)


THREAT_INTEL_HANDLERS = {
    "map_to_mitre": _map_to_mitre,
    "enrich_ioc": _enrich_ioc,
    "query_threat_feed": _query_threat_feed,
    "check_indicator": _check_indicator,
    "build_attack_chain": _build_attack_chain,
    "track_campaign": _track_campaign,
    "search_threat_intel": _search_threat_intel,
    "get_attack_surface": _get_attack_surface,
}
