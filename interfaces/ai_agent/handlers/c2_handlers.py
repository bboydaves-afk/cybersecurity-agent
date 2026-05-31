"""C2 (Command and Control) handlers (8 handlers)."""


async def _connect_metasploit(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.connect_metasploit(
        params.get("host", "127.0.0.1"),
        params.get("port", 55553),
        params.get("username", "msf"),
        params.get("password", "msf")
    )


async def _list_metasploit_modules(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.list_metasploit_modules(
        params.get("module_type"),
        params.get("search_term")
    )


async def _create_metasploit_listener(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.create_metasploit_listener(
        params["payload"],
        params.get("lhost"),
        params.get("lport"),
        params.get("options", {}),
        params.get("project_id")
    )


async def _list_c2_sessions(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.list_c2_sessions(
        params.get("c2_type", "metasploit"),
        params.get("project_id")
    )


async def _c2_session_command(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.c2_session_command(
        params["session_id"],
        params["command"],
        params.get("c2_type", "metasploit"),
        params.get("project_id")
    )


async def _generate_stager(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.generate_stager(
        params["payload_type"],
        params["lhost"],
        params["lport"],
        params.get("format", "exe"),
        params.get("encoder"),
        params.get("iterations", 1),
        params.get("project_id")
    )


async def _connect_sliver(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.connect_sliver(
        params.get("host", "127.0.0.1"),
        params.get("port", 31337),
        params.get("config_path")
    )


async def _get_c2_status(params, db, cred_mgr, config):
    from engines.c2_engine import C2Engine
    engine = C2Engine(db, config)
    return await engine.get_c2_status(
        params.get("c2_type")
    )


C2_HANDLERS = {
    "connect_metasploit": _connect_metasploit,
    "list_metasploit_modules": _list_metasploit_modules,
    "create_metasploit_listener": _create_metasploit_listener,
    "list_c2_sessions": _list_c2_sessions,
    "c2_session_command": _c2_session_command,
    "generate_stager": _generate_stager,
    "connect_sliver": _connect_sliver,
    "get_c2_status": _get_c2_status,
}
