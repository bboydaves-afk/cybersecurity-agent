"""Mobile security handlers (10 handlers)."""


async def _analyze_apk(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.analyze_apk(
        params["apk_path"],
        params.get("deep_analysis", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _analyze_ipa(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.analyze_ipa(
        params["ipa_path"],
        params.get("deep_analysis", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_app_permissions(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.check_app_permissions(
        params["app_path"],
        params["platform"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_ssl_pinning(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.check_ssl_pinning(
        params["app_path"],
        params["platform"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_data_storage(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.check_data_storage(
        params["app_path"],
        params["platform"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _decompile_apk(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.decompile_apk(
        params["apk_path"],
        params.get("output_dir"),
        params.get("project_id")
    )


async def _check_api_calls(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.check_api_calls(
        params["app_path"],
        params["platform"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_crypto_usage(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.check_crypto_usage(
        params["app_path"],
        params["platform"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _owasp_mobile_check(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.owasp_mobile_check(
        params["app_path"],
        params["platform"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _generate_mobile_report(params, db, cred_mgr, config):
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(db, config)
    return await engine.generate_mobile_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


MOBILE_HANDLERS = {
    "analyze_apk": _analyze_apk,
    "analyze_ipa": _analyze_ipa,
    "check_app_permissions": _check_app_permissions,
    "check_ssl_pinning": _check_ssl_pinning,
    "check_data_storage": _check_data_storage,
    "decompile_apk": _decompile_apk,
    "check_api_calls": _check_api_calls,
    "check_crypto_usage": _check_crypto_usage,
    "owasp_mobile_check": _owasp_mobile_check,
    "generate_mobile_report": _generate_mobile_report,
}
