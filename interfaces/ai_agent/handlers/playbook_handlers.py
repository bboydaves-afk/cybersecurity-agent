"""Playbook handlers (7 handlers)."""


async def _load_playbook(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.load_playbook(
        params["playbook_name"]
    )


async def _list_playbooks(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.list_playbooks()


async def _execute_playbook(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.execute_playbook(
        params["playbook_name"],
        params.get("variables", {}),
        params.get("project_id"),
        params.get("target_id")
    )


async def _get_execution_status(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.get_execution_status(
        params["execution_id"]
    )


async def _list_executions(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.list_executions(
        params.get("project_id"),
        params.get("limit", 50)
    )


async def _cancel_execution(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.cancel_execution(
        params["execution_id"]
    )


async def _validate_playbook(params, db, cred_mgr, config):
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db, config)
    return await engine.validate_playbook(
        params["playbook_name"]
    )


PLAYBOOK_HANDLERS = {
    "load_playbook": _load_playbook,
    "list_playbooks": _list_playbooks,
    "execute_playbook": _execute_playbook,
    "get_execution_status": _get_execution_status,
    "list_executions": _list_executions,
    "cancel_execution": _cancel_execution,
    "validate_playbook": _validate_playbook,
}
