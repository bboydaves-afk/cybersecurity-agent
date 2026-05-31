"""Active Directory handlers (12 handlers)."""


async def _enumerate_domain(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.enumerate_domain(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _enumerate_ad_users(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.enumerate_ad_users(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("filter"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _enumerate_ad_groups(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.enumerate_ad_groups(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("privileged_only", False),
        params.get("project_id"),
        params.get("target_id")
    )


async def _enumerate_ad_computers(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.enumerate_ad_computers(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_ad_password_policy(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.check_ad_password_policy(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_kerberoastable(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.check_kerberoastable(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_asrep_roastable(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.check_asrep_roastable(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_delegation(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.check_delegation(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _enumerate_gpos(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.enumerate_gpos(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_trusts(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.check_trusts(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _enumerate_shares(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.enumerate_shares(
        params["target"],
        params.get("username"),
        params.get("password"),
        params.get("domain"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _ad_security_assessment(params, db, cred_mgr, config):
    from engines.ad_engine import ADEngine
    engine = ADEngine(db, config)
    return await engine.ad_security_assessment(
        params["domain"],
        params.get("dc_ip"),
        params.get("username"),
        params.get("password"),
        params.get("project_id"),
        params.get("target_id")
    )


AD_HANDLERS = {
    "enumerate_domain": _enumerate_domain,
    "enumerate_ad_users": _enumerate_ad_users,
    "enumerate_ad_groups": _enumerate_ad_groups,
    "enumerate_ad_computers": _enumerate_ad_computers,
    "check_ad_password_policy": _check_ad_password_policy,
    "check_kerberoastable": _check_kerberoastable,
    "check_asrep_roastable": _check_asrep_roastable,
    "check_delegation": _check_delegation,
    "enumerate_gpos": _enumerate_gpos,
    "check_trusts": _check_trusts,
    "enumerate_shares": _enumerate_shares,
    "ad_security_assessment": _ad_security_assessment,
}
