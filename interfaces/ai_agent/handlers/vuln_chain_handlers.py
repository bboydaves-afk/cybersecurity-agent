"""Vulnerability chaining handlers (8 handlers)."""


async def _analyze_attack_paths(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.analyze_attack_paths(
        params["start_point"],
        params["end_goal"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _find_vuln_chains(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.find_vuln_chains(
        params.get("project_id"),
        params.get("target_id"),
        params.get("min_severity", "medium"),
        params.get("max_chain_length", 5)
    )


async def _calculate_chain_risk(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.calculate_chain_risk(
        params["chain"],
        params.get("project_id")
    )


async def _suggest_pivot_paths(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.suggest_pivot_paths(
        params["current_position"],
        params.get("target_position"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _map_attack_surface(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.map_attack_surface(
        params.get("project_id"),
        params.get("target_id"),
        params.get("include_external", True),
        params.get("include_internal", True)
    )


async def _simulate_attack(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.simulate_attack(
        params["attack_path"],
        params.get("dry_run", True),
        params.get("project_id")
    )


async def _prioritize_remediation(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.prioritize_remediation(
        params.get("project_id"),
        params.get("target_id"),
        params.get("max_recommendations", 10)
    )


async def _generate_chain_report(params, db, cred_mgr, config):
    from engines.vuln_chain_engine import VulnChainEngine
    engine = VulnChainEngine(db, config)
    return await engine.generate_chain_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


VULN_CHAIN_HANDLERS = {
    "analyze_attack_paths": _analyze_attack_paths,
    "find_vuln_chains": _find_vuln_chains,
    "calculate_chain_risk": _calculate_chain_risk,
    "suggest_pivot_paths": _suggest_pivot_paths,
    "map_attack_surface": _map_attack_surface,
    "simulate_attack": _simulate_attack,
    "prioritize_remediation": _prioritize_remediation,
    "generate_chain_report": _generate_chain_report,
}
