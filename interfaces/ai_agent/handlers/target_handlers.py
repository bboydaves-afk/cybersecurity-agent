"""Target management handlers (5 handlers)."""

import json


async def _add_target(params, db, cred_mgr, config):
    from core.database import generate_id, utc_now
    target_id = generate_id("tgt-")
    await db.execute_commit(
        "INSERT INTO targets (id, project_id, target_type, value, hostname, ip_address, in_scope, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target_id, params["project_id"], params.get("target_type", "host"),
         params["value"], params.get("hostname"), params.get("ip_address"),
         1 if params.get("in_scope", True) else 0,
         params.get("notes"), utc_now()))
    await db.audit("add_target", target_id, params["project_id"],
                    f"Target added: {params['value']}")
    return {"success": True, "target_id": target_id, "value": params["value"]}


async def _list_targets(params, db, cred_mgr, config):
    project_id = params.get("project_id")
    if project_id:
        targets = await db.fetch_all(
            "SELECT * FROM targets WHERE project_id=?", (project_id,))
    else:
        targets = await db.fetch_all("SELECT * FROM targets")
    return {"success": True, "targets": targets, "count": len(targets)}


async def _update_scope(params, db, cred_mgr, config):
    from core.database import utc_now
    in_scope = 1 if params.get("in_scope", True) else 0
    await db.execute_commit(
        "UPDATE targets SET in_scope=? WHERE id=?",
        (in_scope, params["target_id"]))
    await db.audit("update_scope", params["target_id"],
                    description=f"Scope updated: in_scope={in_scope}")
    return {"success": True, "target_id": params["target_id"], "in_scope": bool(in_scope)}


async def _get_target_info(params, db, cred_mgr, config):
    target = await db.fetch_one(
        "SELECT * FROM targets WHERE id=?", (params["target_id"],))
    if not target:
        return {"error": f"Target {params['target_id']} not found"}
    findings = await db.fetch_all(
        "SELECT id, title, severity, status FROM findings WHERE target_id=?",
        (params["target_id"],))
    scans = await db.fetch_all(
        "SELECT id, scan_type, status, started_at FROM scans WHERE target_id=?",
        (params["target_id"],))
    hosts = await db.fetch_all(
        "SELECT * FROM network_hosts WHERE target_id=?",
        (params["target_id"],))
    return {"success": True, "target": target, "findings": findings,
            "scans": scans, "hosts": hosts}


async def _remove_target(params, db, cred_mgr, config):
    from core.database import utc_now
    await db.execute_commit(
        "DELETE FROM targets WHERE id=?", (params["target_id"],))
    await db.audit("remove_target", params["target_id"],
                    description=f"Target removed: {params['target_id']}")
    return {"success": True, "target_id": params["target_id"]}


TARGET_HANDLERS = {
    "add_target": _add_target,
    "list_targets": _list_targets,
    "update_scope": _update_scope,
    "get_target_info": _get_target_info,
    "remove_target": _remove_target,
}
