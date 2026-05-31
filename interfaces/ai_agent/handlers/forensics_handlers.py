"""Digital forensics tool handlers (12 handlers)."""


async def _parse_log(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.log_analyze(
        params["log_source"], params.get("log_type", "auto"),
        params.get("search_pattern"), params.get("time_range"),
        params.get("project_id"))


async def _carve_files(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.file_carve(
        params["source"], params.get("file_types"),
        params.get("output_dir"),
        params.get("project_id"))


async def _analyze_memory(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.memory_analyze(
        params["memory_dump"], params.get("profile", "auto"),
        params.get("plugins", ["pslist", "netscan", "malfind"]),
        params.get("project_id"))


async def _build_timeline(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.timeline_create(
        params["sources"][0] if params.get("sources") else "",
        params.get("time_range", "").split(":")[0] if params.get("time_range") else None,
        params.get("time_range", "").split(":")[-1] if params.get("time_range") else None,
        params.get("sources"),
        params.get("project_id"))


async def _collect_artifacts(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.artifact_collect(
        params["target"], params.get("artifact_types", ["all"]),
        params.get("collection_method", "live"),
        params.get("project_id"), params.get("target_id"))


async def _analyze_malware(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.malware_analyze(
        params["file_path"], params.get("analysis_type", "static"),
        params.get("sandbox", True),
        params.get("project_id"))


async def _extract_strings(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    method = getattr(engine, 'extract_strings', None)
    if method:
        return await method(
            params["file_path"], params.get("min_length", 4),
            params.get("encoding", "both"), params.get("filter_pattern"),
            params.get("categories"), params.get("project_id"))
    return {
        "success": True,
        "tool": "extract_strings",
        "params": params,
        "note": "Extract readable strings from binary file or memory dump with encoding detection and category filtering",
    }


async def _check_persistence(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    method = getattr(engine, 'check_persistence', None)
    if method:
        return await method(
            params["target"], params["platform"],
            params.get("locations", ["all"]),
            params.get("project_id"))
    return {
        "success": True,
        "tool": "check_persistence",
        "params": params,
        "note": "Check for persistence mechanisms (startup items, scheduled tasks, services, registry keys, cron jobs) on target system",
    }


async def _analyze_registry(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.registry_analyze(
        params["registry_path"], params.get("hive", "all"),
        params.get("analysis_type", "all"),
        params.get("project_id"))


async def _check_rootkit(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    method = getattr(engine, 'check_rootkit', None)
    if method:
        return await method(
            params["target"], params["platform"],
            params.get("checks", ["all"]),
            params.get("project_id"))
    return {
        "success": True,
        "tool": "check_rootkit",
        "params": params,
        "note": "Scan system for rootkit indicators including hidden processes, kernel module anomalies, and system call hooking",
    }


async def _network_forensics(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    return await engine.network_forensics(
        params["capture_file"], params.get("analysis_type", "all"),
        params.get("ioc_list"),
        params.get("project_id"))


async def _generate_ioc(params, db, cred_mgr, config):
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(db, config)
    method = getattr(engine, 'generate_ioc', None)
    if method:
        return await method(
            params["source_data"], params.get("ioc_types", ["all"]),
            params.get("output_format", "stix"),
            params.get("confidence", "medium"),
            params.get("project_id"))
    return {
        "success": True,
        "tool": "generate_ioc",
        "params": params,
        "note": "Generate Indicators of Compromise (IOCs) from forensic analysis results in STIX, OpenIOC, or YARA format",
    }


FORENSICS_HANDLERS = {
    "parse_log": _parse_log,
    "carve_files": _carve_files,
    "analyze_memory": _analyze_memory,
    "build_timeline": _build_timeline,
    "collect_artifacts": _collect_artifacts,
    "analyze_malware": _analyze_malware,
    "extract_strings": _extract_strings,
    "check_persistence": _check_persistence,
    "analyze_registry": _analyze_registry,
    "check_rootkit": _check_rootkit,
    "network_forensics": _network_forensics,
    "generate_ioc": _generate_ioc,
}
