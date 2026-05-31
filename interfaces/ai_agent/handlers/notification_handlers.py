"""Notification handlers (8 handlers)."""


async def _configure_notification_channel(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.configure_notification_channel(
        params["channel_type"],
        params["name"],
        params["config"],
        params.get("enabled", True)
    )


async def _list_notification_channels(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.list_notification_channels(
        params.get("enabled_only", False)
    )


async def _remove_notification_channel(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.remove_notification_channel(
        params["channel_id"]
    )


async def _send_notification(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.send_notification(
        params["channel_id"],
        params["message"],
        params.get("title"),
        params.get("severity", "info")
    )


async def _notify_all_channels(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.notify_all_channels(
        params["message"],
        params.get("title"),
        params.get("severity", "info")
    )


async def _notify_finding(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.notify_finding(
        params["finding_id"],
        params.get("channels", [])
    )


async def _notify_scan_complete(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.notify_scan_complete(
        params["scan_type"],
        params["target"],
        params.get("findings_count", 0),
        params.get("critical_count", 0),
        params.get("channels", [])
    )


async def _get_notification_history(params, db, cred_mgr, config):
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(db, config)
    return await engine.get_notification_history(
        params.get("channel_id"),
        params.get("limit", 50)
    )


NOTIFICATION_HANDLERS = {
    "configure_notification_channel": _configure_notification_channel,
    "list_notification_channels": _list_notification_channels,
    "remove_notification_channel": _remove_notification_channel,
    "send_notification": _send_notification,
    "notify_all_channels": _notify_all_channels,
    "notify_finding": _notify_finding,
    "notify_scan_complete": _notify_scan_complete,
    "get_notification_history": _get_notification_history,
}
