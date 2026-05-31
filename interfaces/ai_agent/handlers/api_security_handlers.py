"""API security handlers (14 handlers)."""


async def _discover_api_endpoints(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.discover_api_endpoints(
        params["base_url"],
        params.get("wordlist"),
        params.get("methods", ["GET", "POST", "PUT", "DELETE", "PATCH"]),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_api_authentication(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_api_authentication(
        params["url"],
        params.get("auth_type"),
        params.get("credentials", {}),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_api_authorization(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_api_authorization(
        params["url"],
        params["auth_token"],
        params.get("test_cases", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_rate_limiting(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_rate_limiting(
        params["url"],
        params.get("requests_count", 100),
        params.get("interval", 1),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_api_injection(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_api_injection(
        params["url"],
        params.get("method", "GET"),
        params.get("parameters", {}),
        params.get("injection_types", ["sql", "nosql", "xss", "xxe"]),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_mass_assignment(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_mass_assignment(
        params["url"],
        params["method"],
        params.get("base_payload", {}),
        params.get("test_fields", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _analyze_jwt(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.analyze_jwt(
        params["token"],
        params.get("check_vulnerabilities", True),
        params.get("project_id")
    )


async def _test_graphql(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_graphql(
        params["url"],
        params.get("introspection", True),
        params.get("depth_limit_test", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _fuzz_api_parameters(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.fuzz_api_parameters(
        params["url"],
        params["method"],
        params["parameter"],
        params.get("payloads", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_cors_api(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_cors_api(
        params["url"],
        params.get("origins", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_http_methods(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_http_methods(
        params["url"],
        params.get("methods", ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_input_validation(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.test_input_validation(
        params["url"],
        params["method"],
        params["parameters"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_api_security(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.scan_api_security(
        params["base_url"],
        params.get("auth_token"),
        params.get("tests", []),
        params.get("project_id"),
        params.get("target_id")
    )


async def _generate_api_report(params, db, cred_mgr, config):
    from engines.api_security_engine import APISecurityEngine
    engine = APISecurityEngine(db, config)
    return await engine.generate_api_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


API_SECURITY_HANDLERS = {
    "discover_api_endpoints": _discover_api_endpoints,
    "test_api_authentication": _test_api_authentication,
    "test_api_authorization": _test_api_authorization,
    "test_api_rate_limiting": _test_rate_limiting,
    "test_api_injection": _test_api_injection,
    "test_mass_assignment": _test_mass_assignment,
    "analyze_jwt": _analyze_jwt,
    "test_graphql": _test_graphql,
    "fuzz_api_parameters": _fuzz_api_parameters,
    "test_cors_api": _test_cors_api,
    "test_http_methods": _test_http_methods,
    "test_input_validation": _test_input_validation,
    "scan_api_security": _scan_api_security,
    "generate_api_report": _generate_api_report,
}
