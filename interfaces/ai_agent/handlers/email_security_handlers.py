"""Email security handlers (10 handlers)."""


async def _check_spf(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_spf(
        params["domain"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_dkim(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_dkim(
        params["domain"],
        params.get("selector"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_dmarc(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_dmarc(
        params["domain"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _analyze_email_headers(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.analyze_email_headers(
        params["headers"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_mail_server(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_mail_server(
        params["domain"],
        params.get("check_tls", True),
        params.get("check_vulnerabilities", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_email_spoofing(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_email_spoofing(
        params["domain"],
        params.get("test_sender"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _test_smtp_auth(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.test_smtp_auth(
        params["host"],
        params.get("port", 25),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_email_security_posture(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_email_security_posture(
        params["domain"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_bimi(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.check_bimi(
        params["domain"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _generate_email_report(params, db, cred_mgr, config):
    from engines.email_security_engine import EmailSecurityEngine
    engine = EmailSecurityEngine(db, config)
    return await engine.generate_email_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


EMAIL_SECURITY_HANDLERS = {
    "check_spf": _check_spf,
    "check_dkim": _check_dkim,
    "check_dmarc": _check_dmarc,
    "analyze_email_headers": _analyze_email_headers,
    "check_mail_server": _check_mail_server,
    "check_email_spoofing": _check_email_spoofing,
    "test_smtp_auth": _test_smtp_auth,
    "check_email_security_posture": _check_email_security_posture,
    "check_bimi": _check_bimi,
    "generate_email_report": _generate_email_report,
}
