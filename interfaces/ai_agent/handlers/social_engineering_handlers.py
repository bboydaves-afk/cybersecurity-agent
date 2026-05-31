"""Social engineering handlers (10 handlers)."""


async def _create_phishing_campaign(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.create_phishing_campaign(
        params["name"],
        params["template"],
        params["targets"],
        params.get("sender_email"),
        params.get("landing_page"),
        params.get("project_id")
    )


async def _list_phishing_campaigns(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.list_phishing_campaigns(
        params.get("project_id"),
        params.get("status")
    )


async def _get_campaign_results(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.get_campaign_results(
        params["campaign_id"]
    )


async def _generate_phishing_template(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.generate_phishing_template(
        params["template_type"],
        params.get("target_company"),
        params.get("personalization", {}),
        params.get("project_id")
    )


async def _analyze_phishing_email(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.analyze_phishing_email(
        params["email_content"],
        params.get("headers"),
        params.get("project_id")
    )


async def _check_typosquatting(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.check_typosquatting(
        params["domain"],
        params.get("variations", 100),
        params.get("check_registered", True),
        params.get("project_id"),
        params.get("target_id")
    )


async def _create_landing_page(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.create_landing_page(
        params["page_type"],
        params.get("clone_url"),
        params.get("capture_credentials", True),
        params.get("redirect_url"),
        params.get("project_id")
    )


async def _generate_pretext(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.generate_pretext(
        params["scenario_type"],
        params.get("target_info", {}),
        params.get("objective"),
        params.get("project_id")
    )


async def _assess_security_awareness(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.assess_security_awareness(
        params["campaign_results"],
        params.get("project_id")
    )


async def _generate_training_recommendations(params, db, cred_mgr, config):
    from engines.social_engineering_engine import SocialEngineeringEngine
    engine = SocialEngineeringEngine(db, config)
    return await engine.generate_training_recommendations(
        params["assessment_results"],
        params.get("project_id")
    )


SOCIAL_ENGINEERING_HANDLERS = {
    "create_phishing_campaign": _create_phishing_campaign,
    "list_phishing_campaigns": _list_phishing_campaigns,
    "get_campaign_results": _get_campaign_results,
    "generate_phishing_template": _generate_phishing_template,
    "analyze_phishing_email": _analyze_phishing_email,
    "check_typosquatting": _check_typosquatting,
    "create_landing_page": _create_landing_page,
    "generate_pretext": _generate_pretext,
    "assess_security_awareness": _assess_security_awareness,
    "generate_training_recommendations": _generate_training_recommendations,
}
