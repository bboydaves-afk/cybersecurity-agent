"""Secrets scanning handlers (10 handlers)."""


async def _scan_directory_secrets(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.scan_directory_secrets(
        params["directory"],
        params.get("recursive", True),
        params.get("exclude_patterns", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_git_secrets(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.scan_git_secrets(
        params["repo_path"],
        params.get("scan_history", True),
        params.get("branch"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_file_secrets(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.scan_file_secrets(
        params["file_path"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_env_files(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.scan_env_files(
        params["directory"],
        params.get("recursive", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_cloud_secrets(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.check_cloud_secrets(
        params["cloud_provider"],
        params.get("resource_type"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_config_files(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.scan_config_files(
        params["directory"],
        params.get("config_types", [".yml", ".yaml", ".json", ".xml", ".ini", ".conf"]),
        params.get("recursive", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_docker_secrets(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.scan_docker_secrets(
        params.get("image"),
        params.get("container_id"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _get_secret_patterns(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.get_secret_patterns(
        params.get("category")
    )


async def _validate_secret_findings(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.validate_secret_findings(
        params["findings"],
        params.get("project_id")
    )


async def _generate_secrets_report(params, db, cred_mgr, config):
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(db, config)
    return await engine.generate_secrets_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


SECRETS_HANDLERS = {
    "scan_directory_secrets": _scan_directory_secrets,
    "scan_git_secrets": _scan_git_secrets,
    "scan_file_secrets": _scan_file_secrets,
    "scan_env_files": _scan_env_files,
    "check_cloud_secrets": _check_cloud_secrets,
    "scan_config_files": _scan_config_files,
    "scan_docker_secrets": _scan_docker_secrets,
    "get_secret_patterns": _get_secret_patterns,
    "validate_secret_findings": _validate_secret_findings,
    "generate_secrets_report": _generate_secrets_report,
}
