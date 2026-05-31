"""Web application tool handlers (20 handlers)."""


async def _directory_fuzz(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.directory_fuzz(
        params["url"], params.get("wordlist", "common"),
        params.get("extensions"), params.get("threads", 10),
        params.get("project_id"), params.get("target_id"))


async def _test_xss(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_xss(
        params["url"], params.get("parameter"),
        params.get("method", "GET"), params.get("payloads"),
        params.get("project_id"), params.get("target_id"))


async def _test_sqli(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_sqli(
        params["url"], params.get("parameter"),
        params.get("method", "GET"), params.get("dbms"),
        params.get("project_id"), params.get("target_id"))


async def _analyze_headers(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.analyze_headers(
        params["url"], params.get("project_id"), params.get("target_id"))


async def _test_ssl_tls(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_ssl_tls(
        params["target"], params.get("port", 443),
        params.get("project_id"), params.get("target_id"))


async def _test_cors(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_cors(
        params["url"], params.get("origins"),
        params.get("project_id"), params.get("target_id"))


async def _audit_cookies(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.audit_cookies(
        params["url"], params.get("project_id"), params.get("target_id"))


async def _fuzz_api(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.fuzz_api(
        params["url"], params.get("method", "GET"),
        params.get("parameters"), params.get("headers"),
        params.get("auth_token"), params.get("project_id"),
        params.get("target_id"))


async def _crawl_site(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.crawl_site(
        params["url"], params.get("max_depth", 3),
        params.get("max_pages", 100),
        params.get("project_id"), params.get("target_id"))


async def _check_technologies(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.check_technologies(
        params["url"], params.get("project_id"), params.get("target_id"))


async def _test_csrf(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_csrf(
        params["url"], params.get("method", "POST"),
        params.get("form_data"), params.get("cookies"),
        params.get("project_id"), params.get("target_id"))


async def _test_open_redirect(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_open_redirect(
        params["url"], params.get("parameter"),
        params.get("project_id"), params.get("target_id"))


async def _check_csp(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.check_csp(
        params["url"], params.get("project_id"), params.get("target_id"))


async def _test_xxe(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_xxe(
        params["url"], params.get("parameter"),
        params.get("method", "POST"),
        params.get("project_id"), params.get("target_id"))


async def _test_ssrf(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_ssrf(
        params["url"], params.get("parameter"),
        params.get("callback_url"),
        params.get("project_id"), params.get("target_id"))


async def _test_idor(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_idor(
        params["url"], params.get("parameter"),
        params.get("auth_tokens"), params.get("id_range"),
        params.get("project_id"), params.get("target_id"))


async def _test_file_upload(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_file_upload(
        params["url"], params.get("field_name", "file"),
        params.get("project_id"), params.get("target_id"))


async def _test_authentication(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_authentication(
        params["url"], params.get("login_url"),
        params.get("username_field", "username"),
        params.get("password_field", "password"),
        params.get("project_id"), params.get("target_id"))


async def _test_rate_limiting(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.test_rate_limiting(
        params["url"], params.get("method", "GET"),
        params.get("requests_count", 100),
        params.get("project_id"), params.get("target_id"))


async def _full_web_scan(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    url = params["url"]
    pid = params.get("project_id")
    tid = params.get("target_id")
    results = {}
    results["headers"] = await engine.analyze_headers(url, pid, tid)
    results["technologies"] = await engine.check_technologies(url, pid, tid)
    results["ssl_tls"] = await engine.test_ssl_tls(url, 443, pid, tid)
    results["cors"] = await engine.test_cors(url, None, pid, tid)
    results["cookies"] = await engine.audit_cookies(url, pid, tid)
    results["csp"] = await engine.check_csp(url, pid, tid)
    results["directories"] = await engine.directory_fuzz(url, "common", None, 10, pid, tid)
    results["xss"] = await engine.test_xss(url, None, "GET", None, pid, tid)
    results["sqli"] = await engine.test_sqli(url, None, "GET", None, pid, tid)
    return {"success": True, "url": url, "results": results}


WEBAPP_HANDLERS = {
    "directory_fuzz": _directory_fuzz,
    "test_xss": _test_xss,
    "test_sqli": _test_sqli,
    "analyze_headers": _analyze_headers,
    "test_ssl_tls": _test_ssl_tls,
    "test_cors": _test_cors,
    "audit_cookies": _audit_cookies,
    "fuzz_api": _fuzz_api,
    "crawl_site": _crawl_site,
    "check_technologies": _check_technologies,
    "test_csrf": _test_csrf,
    "test_open_redirect": _test_open_redirect,
    "check_csp": _check_csp,
    "test_xxe": _test_xxe,
    "test_ssrf": _test_ssrf,
    "test_idor": _test_idor,
    "test_file_upload": _test_file_upload,
    "test_authentication": _test_authentication,
    "test_rate_limiting": _test_rate_limiting,
    "full_web_scan": _full_web_scan,
}
