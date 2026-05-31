"""Wireless security handlers (10 handlers)."""


async def _scan_wireless_networks(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.scan_wireless_networks(
        params.get("interface"),
        params.get("duration", 30),
        params.get("project_id"),
        params.get("target_id")
    )


async def _analyze_wifi_encryption(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.analyze_wifi_encryption(
        params["bssid"],
        params.get("interface"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _detect_rogue_aps(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.detect_rogue_aps(
        params["known_networks"],
        params.get("interface"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_wps(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.check_wps(
        params["bssid"],
        params.get("interface"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _deauth_detection(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.deauth_detection(
        params.get("interface"),
        params.get("duration", 60),
        params.get("project_id"),
        params.get("target_id")
    )


async def _capture_handshake(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.capture_handshake(
        params["bssid"],
        params["channel"],
        params.get("interface"),
        params.get("timeout", 300),
        params.get("project_id"),
        params.get("target_id")
    )


async def _analyze_wifi_security(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.analyze_wifi_security(
        params["bssid"],
        params.get("interface"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _get_connected_clients(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.get_connected_clients(
        params["bssid"],
        params.get("interface"),
        params.get("duration", 60),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_wifi_isolation(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.check_wifi_isolation(
        params["bssid"],
        params.get("interface"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _generate_wireless_report(params, db, cred_mgr, config):
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(db, config)
    return await engine.generate_wireless_report(
        params.get("project_id"),
        params.get("target_id"),
        params.get("format", "html")
    )


WIRELESS_HANDLERS = {
    "scan_wireless_networks": _scan_wireless_networks,
    "analyze_wifi_encryption": _analyze_wifi_encryption,
    "detect_rogue_aps": _detect_rogue_aps,
    "check_wps": _check_wps,
    "deauth_detection": _deauth_detection,
    "capture_handshake": _capture_handshake,
    "analyze_wifi_security": _analyze_wifi_security,
    "get_connected_clients": _get_connected_clients,
    "check_wifi_isolation": _check_wifi_isolation,
    "generate_wireless_report": _generate_wireless_report,
}
