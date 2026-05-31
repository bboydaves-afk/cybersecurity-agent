"""Automation handlers (10 handlers)."""


async def _start_scheduler(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.start_scheduler()


async def _stop_scheduler(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.stop_scheduler()


async def _schedule_scan(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.schedule_scan(
        params["scan_type"],
        params["schedule"],
        params.get("scan_params", {}),
        params.get("project_id"),
        params.get("target_id")
    )


async def _list_scheduled_jobs(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.list_scheduled_jobs(
        params.get("project_id")
    )


async def _remove_scheduled_job(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.remove_scheduled_job(
        params["job_id"]
    )


async def _pause_scheduled_job(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.pause_scheduled_job(
        params["job_id"]
    )


async def _resume_scheduled_job(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.resume_scheduled_job(
        params["job_id"]
    )


async def _run_job_now(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.run_job_now(
        params["job_id"]
    )


async def _get_job_history(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.get_job_history(
        params["job_id"],
        params.get("limit", 50)
    )


async def _get_scheduler_status(params, db, cred_mgr, config):
    from engines.automation_engine import AutomationEngine
    engine = AutomationEngine(db, config)
    return await engine.get_scheduler_status()


AUTOMATION_HANDLERS = {
    "start_scheduler": _start_scheduler,
    "stop_scheduler": _stop_scheduler,
    "schedule_scan": _schedule_scan,
    "list_scheduled_jobs": _list_scheduled_jobs,
    "remove_scheduled_job": _remove_scheduled_job,
    "pause_scheduled_job": _pause_scheduled_job,
    "resume_scheduled_job": _resume_scheduled_job,
    "run_job_now": _run_job_now,
    "get_job_history": _get_job_history,
    "get_scheduler_status": _get_scheduler_status,
}
