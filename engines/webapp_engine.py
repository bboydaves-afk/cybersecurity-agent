"""Web application security testing engine."""

import asyncio
import json
import logging
import ssl
import time
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("hacking_agent.engines.webapp")


class WebAppEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = (config or {}).get("engines", {}).get("webapp", {})
        self._user_agent = self.config.get("user_agent", "CyberSecurityAgent/1.0")
        self._timeout = self.config.get("request_timeout", 30)

    async def _get_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._timeout, follow_redirects=True, verify=False,
            headers={"User-Agent": self._user_agent})

    async def directory_fuzz(self, url: str, wordlist: str = "common",
                             extensions: list = None,
                             project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        scan_id = generate_id("scan-")
        start_time = time.time()
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "dir_fuzz", "running", utc_now()))

        common_dirs = [
            "admin", "login", "dashboard", "api", "wp-admin", "wp-login.php",
            "robots.txt", "sitemap.xml", ".git", ".env", "backup", "config",
            "test", "uploads", "images", "css", "js", "assets", "static",
            "include", "includes", "lib", "vendor", "node_modules", "phpmyadmin",
            "server-status", "server-info", ".htaccess", ".htpasswd", "web.config",
            "crossdomain.xml", "phpinfo.php", "info.php", "debug", "console",
            "swagger", "api-docs", "graphql", "health", "metrics", "status",
        ]
        exts = extensions or ["", ".php", ".html", ".txt", ".bak", ".old"]

        found = []
        async with await self._get_client() as client:
            base = url.rstrip("/")
            for directory in common_dirs:
                for ext in exts:
                    test_url = f"{base}/{directory}{ext}"
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code not in (404, 403, 500):
                            found.append({
                                "url": test_url,
                                "status_code": resp.status_code,
                                "content_length": len(resp.content),
                                "content_type": resp.headers.get("content-type", ""),
                            })
                    except Exception:
                        pass

        duration = time.time() - start_time
        result = {"success": True, "found": found, "count": len(found),
                  "duration": round(duration, 2)}
        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, finding_count=?, completed_at=?, duration_seconds=? WHERE id=?",
            ("completed", json.dumps(result), len(found), utc_now(), duration, scan_id))

        for endpoint in found:
            ep_id = generate_id("web-")
            await self.db.execute_commit(
                "INSERT INTO web_endpoints (id, target_id, url, status_code, content_type, content_length, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ep_id, target_id, endpoint["url"], endpoint["status_code"],
                 endpoint.get("content_type"), endpoint.get("content_length"), utc_now()))

        await self.db.audit("directory_fuzz", target_id, project_id,
                            f"Dir fuzz on {url}: {len(found)} found")
        return {"scan_id": scan_id, **result}

    async def analyze_headers(self, url: str, project_id: str = None,
                              target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        security_headers = {
            "Strict-Transport-Security": {"required": True, "severity": "high"},
            "Content-Security-Policy": {"required": True, "severity": "high"},
            "X-Content-Type-Options": {"required": True, "severity": "medium"},
            "X-Frame-Options": {"required": True, "severity": "medium"},
            "X-XSS-Protection": {"required": False, "severity": "low"},
            "Referrer-Policy": {"required": True, "severity": "low"},
            "Permissions-Policy": {"required": False, "severity": "low"},
            "Cross-Origin-Opener-Policy": {"required": False, "severity": "low"},
            "Cross-Origin-Resource-Policy": {"required": False, "severity": "low"},
        }
        info_headers = ["Server", "X-Powered-By", "X-AspNet-Version",
                        "X-AspNetMvc-Version", "X-Generator"]

        async with await self._get_client() as client:
            try:
                resp = await client.get(url)
                headers = dict(resp.headers)
            except Exception as e:
                return {"success": False, "error": str(e)}

        findings = []
        present = {}
        missing = []

        for header, meta in security_headers.items():
            val = headers.get(header.lower()) or headers.get(header)
            if val:
                present[header] = val
            elif meta["required"]:
                missing.append(header)
                findings.append({
                    "title": f"Missing Security Header: {header}",
                    "severity": meta["severity"],
                    "description": f"The {header} header is not set",
                })

        disclosed = {}
        for h in info_headers:
            val = headers.get(h.lower()) or headers.get(h)
            if val:
                disclosed[h] = val
                findings.append({
                    "title": f"Server Information Disclosure: {h}",
                    "severity": "info",
                    "description": f"{h}: {val}",
                })

        for finding in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, title, description, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, finding["title"],
                 finding["description"], finding["severity"], "open", utc_now()))

        grade = "A" if not missing else "B" if len(missing) <= 2 else "C" if len(missing) <= 4 else "F"
        result = {
            "success": True, "url": url, "grade": grade,
            "present_headers": present, "missing_headers": missing,
            "information_disclosure": disclosed, "findings": findings,
        }
        await self.db.audit("analyze_headers", target_id, project_id,
                            f"Header analysis on {url}: grade {grade}")
        return result

    async def test_ssl(self, hostname: str, port: int = 443,
                       project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "ssl_scan", "running", utc_now()))

        findings = []
        cert_info = {}
        try:
            loop = asyncio.get_event_loop()
            def _check_ssl():
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    __import__("socket").socket(), server_hostname=hostname
                ) as s:
                    s.settimeout(10)
                    s.connect((hostname, port))
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    version = s.version()
                    return cert, cipher, version

            cert, cipher, version = await loop.run_in_executor(None, _check_ssl)

            import datetime
            cert_info = {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "serial_number": cert.get("serialNumber"),
                "san": [e[1] for e in cert.get("subjectAltName", [])],
            }
            cipher_info = {"name": cipher[0], "version": cipher[1],
                           "bits": cipher[2]}

            if version in ("TLSv1", "TLSv1.1"):
                findings.append({
                    "title": f"Outdated TLS Version: {version}",
                    "severity": "high",
                    "description": f"Server supports {version} which is deprecated",
                })

            weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
            for weak in weak_ciphers:
                if weak in cipher[0].upper():
                    findings.append({
                        "title": f"Weak Cipher Suite: {cipher[0]}",
                        "severity": "high",
                        "description": f"Server uses weak cipher {cipher[0]}",
                    })

            result = {
                "success": True, "hostname": hostname, "port": port,
                "tls_version": version, "cipher": cipher_info,
                "certificate": cert_info, "findings": findings,
                "grade": "A" if not findings else "B" if len(findings) == 1 else "F",
            }
        except Exception as e:
            result = {"success": False, "error": str(e)}

        await self.db.execute_commit(
            "UPDATE scans SET status=?, results=?, completed_at=? WHERE id=?",
            ("completed" if result.get("success") else "failed",
             json.dumps(result, default=str), utc_now(), scan_id))

        for finding in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, scan_id, title, description, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, scan_id, finding["title"],
                 finding["description"], finding["severity"], "open", utc_now()))

        await self.db.audit("test_ssl", target_id, project_id,
                            f"SSL/TLS test on {hostname}:{port}")
        return {"scan_id": scan_id, **result}

    async def test_cors(self, url: str, project_id: str = None,
                        target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        findings = []
        test_origins = [
            "https://evil.com",
            "null",
            url.replace(urlparse(url).netloc, "attacker.com"),
        ]

        async with await self._get_client() as client:
            for origin in test_origins:
                try:
                    resp = await client.get(url, headers={"Origin": origin})
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if acao == "*":
                        findings.append({
                            "title": "CORS Wildcard Origin",
                            "severity": "medium",
                            "description": "Access-Control-Allow-Origin is set to *",
                            "origin_tested": origin,
                        })
                    elif acao == origin and origin != url:
                        sev = "high" if acac.lower() == "true" else "medium"
                        findings.append({
                            "title": "CORS Reflects Arbitrary Origin",
                            "severity": sev,
                            "description": f"Server reflects origin {origin} with credentials={acac}",
                            "origin_tested": origin,
                        })
                except Exception:
                    pass

        for finding in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, title, description, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, finding["title"],
                 finding["description"], finding["severity"], "open", utc_now()))

        result = {"success": True, "url": url, "findings": findings,
                  "vulnerable": len(findings) > 0}
        await self.db.audit("test_cors", target_id, project_id,
                            f"CORS test on {url}: {'vulnerable' if findings else 'ok'}")
        return result

    async def audit_cookies(self, url: str, project_id: str = None,
                            target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        findings = []

        async with await self._get_client() as client:
            try:
                resp = await client.get(url)
                cookies = resp.headers.get_list("set-cookie")

                for cookie_str in cookies:
                    parts = cookie_str.split(";")
                    name_val = parts[0].strip()
                    name = name_val.split("=")[0] if "=" in name_val else name_val
                    flags = [p.strip().lower() for p in parts[1:]]

                    issues = []
                    if not any("secure" in f for f in flags):
                        issues.append("Missing Secure flag")
                    if not any("httponly" in f for f in flags):
                        issues.append("Missing HttpOnly flag")
                    if not any("samesite" in f for f in flags):
                        issues.append("Missing SameSite attribute")

                    if issues:
                        findings.append({
                            "cookie": name,
                            "issues": issues,
                            "severity": "medium" if "Secure" in str(issues) else "low",
                        })
            except Exception as e:
                return {"success": False, "error": str(e)}

        result = {"success": True, "url": url, "cookie_findings": findings}
        await self.db.audit("audit_cookies", target_id, project_id,
                            f"Cookie audit on {url}: {len(findings)} issues")
        return result

    async def crawl_site(self, url: str, max_depth: int = 3,
                         project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        visited = set()
        to_visit = [(url, 0)]
        endpoints = []
        base_domain = urlparse(url).netloc

        async with await self._get_client() as client:
            while to_visit and len(visited) < 200:
                current_url, depth = to_visit.pop(0)
                if current_url in visited or depth > max_depth:
                    continue
                visited.add(current_url)

                try:
                    resp = await client.get(current_url)
                    endpoints.append({
                        "url": current_url,
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "content_length": len(resp.content),
                    })

                    if "text/html" in resp.headers.get("content-type", ""):
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(resp.text, "html.parser")
                        for tag in soup.find_all(["a", "form", "script", "link"]):
                            href = tag.get("href") or tag.get("src") or tag.get("action")
                            if href:
                                full = urljoin(current_url, href)
                                if urlparse(full).netloc == base_domain and full not in visited:
                                    to_visit.append((full, depth + 1))
                except Exception:
                    pass

        for ep in endpoints:
            ep_id = generate_id("web-")
            await self.db.execute_commit(
                "INSERT INTO web_endpoints (id, target_id, url, status_code, content_type, content_length, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ep_id, target_id, ep["url"], ep["status_code"],
                 ep.get("content_type"), ep.get("content_length"), utc_now()))

        result = {"success": True, "url": url, "pages_crawled": len(endpoints),
                  "endpoints": endpoints}
        await self.db.audit("crawl_site", target_id, project_id,
                            f"Crawled {url}: {len(endpoints)} pages")
        return result

    async def check_technologies(self, url: str, project_id: str = None,
                                 target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        techs = []
        async with await self._get_client() as client:
            try:
                resp = await client.get(url)
                headers = dict(resp.headers)
                body = resp.text[:50000]

                server = headers.get("server", "")
                if server:
                    techs.append({"name": "Server", "value": server, "category": "web_server"})
                powered = headers.get("x-powered-by", "")
                if powered:
                    techs.append({"name": "X-Powered-By", "value": powered, "category": "framework"})

                tech_signatures = [
                    ("WordPress", ["wp-content", "wp-includes"], "cms"),
                    ("Drupal", ["Drupal.settings", "drupal.js"], "cms"),
                    ("Joomla", ["joomla", "/administrator/"], "cms"),
                    ("React", ["react", "_reactRootContainer"], "js_framework"),
                    ("Angular", ["ng-version", "ng-app"], "js_framework"),
                    ("Vue.js", ["vue.js", "__vue__"], "js_framework"),
                    ("jQuery", ["jquery"], "js_library"),
                    ("Bootstrap", ["bootstrap.min"], "css_framework"),
                    ("Laravel", ["laravel_session"], "framework"),
                    ("Django", ["csrfmiddlewaretoken", "django"], "framework"),
                    ("ASP.NET", ["__VIEWSTATE", "asp.net"], "framework"),
                    ("PHP", [".php", "PHPSESSID"], "language"),
                ]
                for name, sigs, cat in tech_signatures:
                    if any(s.lower() in body.lower() or s.lower() in str(headers).lower() for s in sigs):
                        techs.append({"name": name, "category": cat})

            except Exception as e:
                return {"success": False, "error": str(e)}

        result = {"success": True, "url": url, "technologies": techs,
                  "count": len(techs)}
        await self.db.audit("check_technologies", target_id, project_id,
                            f"Tech detection on {url}: {len(techs)} found")
        return result

    async def test_xss(self, url: str, parameter: str = None,
                       project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        findings = []
        payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
        ]

        async with await self._get_client() as client:
            for payload in payloads:
                try:
                    if parameter:
                        test_url = f"{url}?{parameter}={payload}"
                    else:
                        parsed = urlparse(url)
                        test_url = f"{url}{'&' if parsed.query else '?'}test={payload}"

                    resp = await client.get(test_url)
                    if payload in resp.text:
                        findings.append({
                            "title": "Reflected XSS",
                            "severity": "high",
                            "payload": payload,
                            "parameter": parameter or "test",
                            "evidence": f"Payload reflected in response",
                        })
                except Exception:
                    pass

        for finding in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, title, description, severity, owasp_category, evidence, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, finding["title"],
                 f"XSS via payload: {finding['payload']}",
                 finding["severity"], "A03", json.dumps(finding), "open", utc_now()))

        result = {"success": True, "url": url, "findings": findings,
                  "vulnerable": len(findings) > 0}
        await self.db.audit("test_xss", target_id, project_id,
                            f"XSS test on {url}: {'vulnerable' if findings else 'clean'}")
        return result

    async def test_sqli(self, url: str, parameter: str = None,
                        project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        findings = []
        payloads = [
            ("'", ["sql", "syntax", "mysql", "postgresql", "oracle", "sqlite", "error"]),
            ("' OR '1'='1", ["true", "admin", "success"]),
            ("1 AND 1=1", []),
            ("1' AND '1'='1", []),
            ("1; DROP TABLE--", ["sql", "syntax", "error"]),
        ]

        error_patterns = [
            "you have an error in your sql syntax",
            "warning: mysql", "unclosed quotation mark",
            "postgresql", "ora-", "sqlite3",
            "microsoft sql", "syntax error", "unterminated string",
        ]

        async with await self._get_client() as client:
            for payload, _ in payloads:
                try:
                    if parameter:
                        test_url = f"{url}?{parameter}={payload}"
                    else:
                        parsed = urlparse(url)
                        test_url = f"{url}{'&' if parsed.query else '?'}id={payload}"

                    resp = await client.get(test_url)
                    body_lower = resp.text.lower()

                    for pattern in error_patterns:
                        if pattern in body_lower:
                            findings.append({
                                "title": "SQL Injection (Error-Based)",
                                "severity": "critical",
                                "payload": payload,
                                "parameter": parameter or "id",
                                "evidence": f"SQL error pattern detected: {pattern}",
                            })
                            break
                except Exception:
                    pass

        for finding in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, title, description, severity, owasp_category, evidence, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, finding["title"],
                 f"SQLi via: {finding['payload']}", finding["severity"],
                 "A03", json.dumps(finding), "open", utc_now()))

        result = {"success": True, "url": url, "findings": findings,
                  "vulnerable": len(findings) > 0}
        await self.db.audit("test_sqli", target_id, project_id,
                            f"SQLi test on {url}: {'vulnerable' if findings else 'clean'}")
        return result

    async def check_csp(self, url: str, project_id: str = None,
                        target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        async with await self._get_client() as client:
            try:
                resp = await client.get(url)
                csp = resp.headers.get("content-security-policy", "")
            except Exception as e:
                return {"success": False, "error": str(e)}

        findings = []
        if not csp:
            findings.append({"title": "Missing CSP Header", "severity": "medium"})
        else:
            if "'unsafe-inline'" in csp:
                findings.append({"title": "CSP allows unsafe-inline", "severity": "medium"})
            if "'unsafe-eval'" in csp:
                findings.append({"title": "CSP allows unsafe-eval", "severity": "medium"})
            if "default-src" not in csp:
                findings.append({"title": "CSP missing default-src", "severity": "low"})

        result = {"success": True, "url": url, "csp": csp,
                  "findings": findings, "grade": "A" if not findings else "C"}
        await self.db.audit("check_csp", target_id, project_id,
                            f"CSP check on {url}")
        return result
