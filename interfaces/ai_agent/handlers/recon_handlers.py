"""Recon tool handlers (20 handlers)."""

async def _port_scan(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.port_scan(
        params["target"], params.get("ports", "1-1000"),
        params.get("scan_type", "syn"),
        params.get("project_id"), params.get("target_id"))

async def _service_enumerate(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.service_enumerate(
        params["target"], params.get("ports"),
        params.get("project_id"), params.get("target_id"))

async def _os_fingerprint(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.os_fingerprint(
        params["target"], params.get("project_id"), params.get("target_id"))

async def _subdomain_enumerate(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.subdomain_enumerate(
        params["domain"], params.get("method", "all"),
        params.get("project_id"), params.get("target_id"))

async def _dns_recon(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.dns_recon(
        params["domain"], params.get("project_id"), params.get("target_id"))

async def _whois_lookup(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.whois_lookup(
        params["target"], params.get("project_id"), params.get("target_id"))

async def _traceroute(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.traceroute(
        params["target"], params.get("project_id"), params.get("target_id"))

async def _banner_grab(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.banner_grab(
        params["target"], params["port"],
        params.get("project_id"), params.get("target_id"))

async def _network_sweep(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.network_sweep(
        params["cidr"], params.get("project_id"), params.get("target_id"))

async def _reverse_dns(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    return await engine.reverse_dns(
        params["ip"], params.get("project_id"), params.get("target_id"))

async def _certificate_transparency(params, db, cred_mgr, config):
    from platforms.crtsh_client import CRTShClient
    client = CRTShClient()
    await client.connect()
    result = await client.get_subdomains(params["domain"])
    await client.disconnect()
    return result

async def _shodan_search(params, db, cred_mgr, config):
    from platforms.shodan_client import ShodanClient
    client = ShodanClient(config.get("platforms", {}).get("shodan", {}))
    await client.connect()
    result = await client.search_query(params["query"])
    await client.disconnect()
    return result

async def _shodan_host_info(params, db, cred_mgr, config):
    from platforms.shodan_client import ShodanClient
    client = ShodanClient(config.get("platforms", {}).get("shodan", {}))
    await client.connect()
    result = await client.get_host_info(params["ip"])
    await client.disconnect()
    return result

async def _wayback_urls(params, db, cred_mgr, config):
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://web.archive.org/cdx/search/cdx",
                params={"url": f"*.{params['domain']}/*", "output": "json",
                        "fl": "original", "collapse": "urlkey", "limit": "200"})
            urls = [row[0] for row in resp.json()[1:]] if resp.status_code == 200 else []
            return {"success": True, "domain": params["domain"],
                    "urls": urls, "count": len(urls)}
    except Exception as e:
        return {"success": False, "error": str(e)}

async def _google_dork(params, db, cred_mgr, config):
    domain = params["domain"]
    dork_type = params.get("dork_type", "all")
    dorks = {
        "files": [f'site:{domain} filetype:pdf', f'site:{domain} filetype:doc', f'site:{domain} filetype:xls', f'site:{domain} filetype:sql', f'site:{domain} filetype:log'],
        "login": [f'site:{domain} inurl:login', f'site:{domain} inurl:signin', f'site:{domain} intitle:"login"', f'site:{domain} inurl:auth'],
        "admin": [f'site:{domain} inurl:admin', f'site:{domain} inurl:dashboard', f'site:{domain} inurl:cpanel', f'site:{domain} intitle:"admin panel"'],
        "config": [f'site:{domain} filetype:env', f'site:{domain} filetype:yml', f'site:{domain} filetype:conf', f'site:{domain} inurl:.git'],
        "database": [f'site:{domain} filetype:sql', f'site:{domain} inurl:phpmyadmin', f'site:{domain} intitle:"index of" "database"'],
    }
    if dork_type == "all":
        result_dorks = {k: v for k, v in dorks.items()}
    else:
        result_dorks = {dork_type: dorks.get(dork_type, [])}
    return {"success": True, "domain": domain, "dorks": result_dorks,
            "note": "Copy these queries into Google to find exposed resources"}

async def _email_harvest(params, db, cred_mgr, config):
    domain = params["domain"]
    emails = set()
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            for url in [f"https://{domain}", f"https://www.{domain}"]:
                try:
                    resp = await client.get(url)
                    import re
                    found = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), resp.text)
                    emails.update(found)
                except Exception:
                    pass
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "domain": domain, "emails": sorted(emails), "count": len(emails)}

async def _tech_detect(params, db, cred_mgr, config):
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(db, config)
    return await engine.check_technologies(
        params["url"], params.get("project_id"), params.get("target_id"))

async def _asn_lookup(params, db, cred_mgr, config):
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"https://api.bgpview.io/search?query_term={params['target']}")
            if resp.status_code == 200:
                return {"success": True, **resp.json().get("data", {})}
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

async def _screenshot_web(params, db, cred_mgr, config):
    return {"success": True, "url": params["url"],
            "note": "Screenshot capture requires a headless browser (Playwright/Selenium). Use 'crawl_site' or 'analyze_headers' for non-visual recon."}

async def _full_recon(params, db, cred_mgr, config):
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(db, config)
    target = params["target"]
    pid = params.get("project_id")
    tid = params.get("target_id")
    results = {}
    results["port_scan"] = await engine.port_scan(target, "1-1000", "syn", pid, tid)
    results["service_enum"] = await engine.service_enumerate(target, None, pid, tid)
    if "." in target and not target.replace(".", "").isdigit():
        results["dns_recon"] = await engine.dns_recon(target, pid, tid)
        results["subdomain_enum"] = await engine.subdomain_enumerate(target, "all", pid, tid)
    return {"success": True, "target": target, "results": results}


RECON_HANDLERS = {
    "port_scan": _port_scan,
    "service_enumerate": _service_enumerate,
    "os_fingerprint": _os_fingerprint,
    "subdomain_enumerate": _subdomain_enumerate,
    "dns_recon": _dns_recon,
    "whois_lookup": _whois_lookup,
    "traceroute": _traceroute,
    "banner_grab": _banner_grab,
    "network_sweep": _network_sweep,
    "reverse_dns": _reverse_dns,
    "certificate_transparency": _certificate_transparency,
    "shodan_search": _shodan_search,
    "shodan_host_info": _shodan_host_info,
    "wayback_urls": _wayback_urls,
    "google_dork": _google_dork,
    "email_harvest": _email_harvest,
    "tech_detect": _tech_detect,
    "asn_lookup": _asn_lookup,
    "screenshot_web": _screenshot_web,
    "full_recon": _full_recon,
}
