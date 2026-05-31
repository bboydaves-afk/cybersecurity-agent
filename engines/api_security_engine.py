"""API security testing engine for REST and GraphQL APIs."""

from typing import Optional, Dict, Any, List
import asyncio


class APISecurityEngine:
    """API security testing engine for REST and GraphQL APIs."""

    def __init__(self, db, config: dict = None):
        """Initialize API Security Engine."""
        self.db = db
        self.config = (config or {}).get("engines", {}).get("api_security_engine", {})

    async def discover_endpoints(
        self,
        base_url: str,
        spec_url: str = None,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Discover API endpoints from OpenAPI/Swagger spec."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            endpoints = []
            spec_data = None

            # Common spec paths to try
            spec_paths = [
                spec_url,
                "/swagger.json",
                "/openapi.json",
                "/api-docs",
                "/v2/api-docs",
                "/v3/api-docs",
                "/swagger/v1/swagger.json",
                "/api/swagger.json",
                "/docs/swagger.json",
            ] if spec_url else [
                "/swagger.json",
                "/openapi.json",
                "/api-docs",
                "/v2/api-docs",
                "/v3/api-docs",
                "/swagger/v1/swagger.json",
                "/api/swagger.json",
                "/docs/swagger.json",
            ]

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                # Try to find spec
                for path in spec_paths:
                    if not path:
                        continue

                    url = f"{base_url.rstrip('/')}{path}" if not path.startswith("http") else path
                    try:
                        response = await client.get(url)
                        if response.status_code == 200:
                            spec_data = response.json()
                            break
                    except Exception:
                        continue

                # Check for GraphQL endpoint
                graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql"]
                graphql_found = False
                for path in graphql_paths:
                    url = f"{base_url.rstrip('/')}{path}"
                    try:
                        response = await client.post(
                            url,
                            json={"query": "{__typename}"},
                        )
                        if response.status_code in [200, 400]:
                            endpoints.append({
                                "path": path,
                                "method": "POST",
                                "type": "graphql",
                            })
                            graphql_found = True
                            break
                    except Exception:
                        continue

            # Parse OpenAPI/Swagger spec
            if spec_data:
                if "paths" in spec_data:
                    for path, methods in spec_data["paths"].items():
                        for method, details in methods.items():
                            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                                endpoint = {
                                    "path": path,
                                    "method": method.upper(),
                                    "type": "rest",
                                    "summary": details.get("summary", ""),
                                    "parameters": details.get("parameters", []),
                                    "security": details.get("security", []),
                                }
                                endpoints.append(endpoint)

            # Create finding
            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    f"API Endpoints Discovered: {base_url}",
                    "Info",
                    "API Security",
                    f"Discovered {len(endpoints)} API endpoints",
                    f"Endpoints: {str(endpoints[:50])}. GraphQL: {graphql_found}. Spec found: {spec_data is not None}",
                    "Review API endpoint security and implement proper authentication/authorization",
                    utc_now(),
                ),
            )

            await self.db.audit(
                action="api_discover_endpoints",
                details={"base_url": base_url, "endpoint_count": len(endpoints)},
                project_id=project_id,
            )

            return {
                "success": True,
                "endpoint_count": len(endpoints),
                "endpoints": endpoints,
                "graphql_found": graphql_found,
                "spec_found": spec_data is not None,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_authentication(
        self,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        api_key: str = None,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test API endpoints for authentication issues."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            unprotected = []
            weak_auth = []

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for endpoint in endpoints[:50]:  # Limit to 50 endpoints
                    path = endpoint.get("path", "")
                    method = endpoint.get("method", "GET")
                    url = f"{base_url.rstrip('/')}{path}"

                    # Test without auth
                    try:
                        response = await client.request(method, url)
                        if response.status_code == 200:
                            unprotected.append({
                                "path": path,
                                "method": method,
                                "status": response.status_code,
                            })
                    except Exception:
                        pass

                    # Test with invalid token
                    try:
                        headers = {"Authorization": "Bearer invalid_token_12345"}
                        response = await client.request(method, url, headers=headers)
                        if response.status_code == 200:
                            weak_auth.append({
                                "path": path,
                                "method": method,
                                "issue": "accepts invalid token",
                            })
                    except Exception:
                        pass

            # Create findings
            findings = []

            if unprotected:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Unprotected API Endpoints",
                        "Critical",
                        "API Security",
                        f"Found {len(unprotected)} API endpoints without authentication",
                        f"Unprotected endpoints: {str(unprotected)}",
                        "Implement authentication for all API endpoints",
                        utc_now(),
                    ),
                )
                findings.append(finding_id)

            if weak_auth:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Weak API Authentication",
                        "High",
                        "API Security",
                        f"Found {len(weak_auth)} API endpoints with weak authentication",
                        f"Weak auth endpoints: {str(weak_auth)}",
                        "Properly validate authentication tokens and reject invalid tokens",
                        utc_now(),
                    ),
                )
                findings.append(finding_id)

            await self.db.audit(
                action="api_test_authentication",
                details={"base_url": base_url, "unprotected": len(unprotected)},
                project_id=project_id,
            )

            return {
                "success": True,
                "unprotected_endpoints": unprotected,
                "weak_auth_endpoints": weak_auth,
                "findings": findings,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_authorization(
        self,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        tokens: Dict[str, str],
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test API endpoints for authorization issues (BOLA/IDOR)."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            bola_issues = []
            idor_issues = []

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for endpoint in endpoints[:30]:  # Limit testing
                    path = endpoint.get("path", "")
                    method = endpoint.get("method", "GET")

                    # Test BOLA by accessing resource with different user tokens
                    if "{id}" in path or "{userId}" in path:
                        test_ids = ["1", "2", "123", "999"]
                        for test_id in test_ids:
                            test_path = path.replace("{id}", test_id).replace("{userId}", test_id)
                            url = f"{base_url.rstrip('/')}{test_path}"

                            # Try with different tokens
                            for token_name, token_value in tokens.items():
                                try:
                                    headers = {"Authorization": f"Bearer {token_value}"}
                                    response = await client.request(method, url, headers=headers)
                                    if response.status_code == 200:
                                        bola_issues.append({
                                            "path": test_path,
                                            "method": method,
                                            "token_used": token_name,
                                            "accessed_id": test_id,
                                        })
                                except Exception:
                                    pass

            # Create finding
            if bola_issues:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "BOLA/IDOR Vulnerability Detected",
                        "Critical",
                        "API Security",
                        f"Found {len(bola_issues)} potential BOLA/IDOR issues",
                        f"Issues: {str(bola_issues)}",
                        "Implement proper authorization checks to verify user can access requested resources",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_authorization",
                details={"base_url": base_url, "bola_issues": len(bola_issues)},
                project_id=project_id,
            )

            return {
                "success": True,
                "bola_issues": bola_issues,
                "idor_issues": idor_issues,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_rate_limiting(
        self,
        base_url: str,
        endpoint: str,
        method: str = "GET",
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test API endpoint for rate limiting."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            rate_limited = False
            requests_sent = 0
            rate_limit_threshold = 0

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                # Send rapid requests
                for i in range(100):
                    try:
                        response = await client.request(method, url)
                        requests_sent += 1

                        if response.status_code == 429:
                            rate_limited = True
                            rate_limit_threshold = i + 1
                            break

                    except Exception:
                        break

            # Create finding if no rate limiting
            if not rate_limited and requests_sent >= 50:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Missing API Rate Limiting",
                        "High",
                        "API Security",
                        f"Endpoint {endpoint} lacks rate limiting",
                        f"Sent {requests_sent} requests without receiving 429 Too Many Requests",
                        "Implement rate limiting to prevent API abuse and DoS attacks",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_rate_limiting",
                details={"endpoint": endpoint, "rate_limited": rate_limited, "requests": requests_sent},
                project_id=project_id,
            )

            return {
                "success": True,
                "rate_limited": rate_limited,
                "requests_sent": requests_sent,
                "threshold": rate_limit_threshold if rate_limited else None,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_injection(
        self,
        base_url: str,
        endpoint: str,
        method: str,
        parameters: List[str],
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test API parameters for injection vulnerabilities."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            vulnerable = []

            # Injection payloads
            sql_payloads = ["' OR '1'='1", "1' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
            nosql_payloads = ["{'$gt': ''}", "[$ne]=1", "{$where: '1==1'}"]
            cmd_payloads = ["; ls", "| whoami", "& dir", "`id`"]
            ssrf_payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080"]

            all_payloads = {
                "sqli": sql_payloads,
                "nosqli": nosql_payloads,
                "cmdi": cmd_payloads,
                "ssrf": ssrf_payloads,
            }

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for param in parameters:
                    for injection_type, payloads in all_payloads.items():
                        for payload in payloads:
                            try:
                                if method == "GET":
                                    test_url = f"{url}?{param}={payload}"
                                    response = await client.get(test_url)
                                else:
                                    data = {param: payload}
                                    response = await client.request(method, url, json=data)

                                # Check for error messages indicating injection
                                error_indicators = [
                                    "sql", "mysql", "postgresql", "oracle", "syntax error",
                                    "mongodb", "uncaught exception", "stack trace",
                                    "root:", "uid=", "gid=", "internal server error",
                                ]

                                body = response.text.lower()
                                if any(indicator in body for indicator in error_indicators):
                                    vulnerable.append({
                                        "parameter": param,
                                        "injection_type": injection_type,
                                        "payload": payload,
                                        "status": response.status_code,
                                    })
                                    break  # Don't test more payloads for this param

                            except Exception:
                                pass

            # Create finding if vulnerabilities found
            if vulnerable:
                finding_id = generate_id()
                severity = "Critical"

                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        f"API Injection Vulnerabilities: {endpoint}",
                        severity,
                        "API Security",
                        f"Found {len(vulnerable)} potential injection vulnerabilities",
                        f"Vulnerable parameters: {str(vulnerable)}",
                        "Implement input validation, parameterized queries, and proper escaping",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_injection",
                details={"endpoint": endpoint, "vulnerable_count": len(vulnerable)},
                project_id=project_id,
            )

            return {
                "success": True,
                "vulnerable_parameters": vulnerable,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_mass_assignment(
        self,
        base_url: str,
        endpoint: str,
        method: str,
        known_fields: List[str],
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test for mass assignment vulnerabilities."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            vulnerable = False
            accepted_fields = []

            # Test fields that could indicate mass assignment
            test_fields = ["role", "admin", "is_admin", "privilege", "isAdmin", "user_role", "permissions", "is_superuser"]

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for field in test_fields:
                    try:
                        # Build payload with known fields + test field
                        payload = {f: "test" for f in known_fields}
                        payload[field] = "admin"

                        response = await client.request(method, url, json=payload)

                        # If request succeeds, might indicate mass assignment
                        if response.status_code in [200, 201]:
                            accepted_fields.append(field)
                            vulnerable = True

                    except Exception:
                        pass

            # Create finding if vulnerable
            if vulnerable:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        f"Mass Assignment Vulnerability: {endpoint}",
                        "High",
                        "API Security",
                        f"Endpoint accepts potentially dangerous fields",
                        f"Accepted fields: {', '.join(accepted_fields)}",
                        "Implement explicit field whitelisting and reject unknown fields",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_mass_assignment",
                details={"endpoint": endpoint, "vulnerable": vulnerable},
                project_id=project_id,
            )

            return {
                "success": True,
                "vulnerable": vulnerable,
                "accepted_fields": accepted_fields,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def analyze_jwt(
        self,
        token: str,
        project_id: str = None,
    ) -> Dict[str, Any]:
        """Analyze JWT token for security issues."""
        import base64
        import json
        from core.database import generate_id, utc_now
        from datetime import datetime

        try:
            # Split token
            parts = token.split(".")
            if len(parts) != 3:
                return {"success": False, "error": "Invalid JWT format"}

            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

            issues = []
            severity = "Low"

            # Check algorithm
            alg = header.get("alg", "").lower()
            if alg == "none":
                issues.append("Algorithm set to 'none' - no signature verification")
                severity = "Critical"
            elif alg in ["hs256", "hs384", "hs512"] and header.get("typ") == "JWT":
                issues.append("Using symmetric algorithm (HMAC) - ensure secret is strong")
                severity = "Medium" if severity == "Low" else severity

            # Check expiry
            if "exp" in payload:
                exp_timestamp = payload["exp"]
                exp_date = datetime.fromtimestamp(exp_timestamp)
                if exp_date < datetime.now():
                    issues.append(f"Token expired on {exp_date}")
                    severity = "Medium" if severity == "Low" else severity
            else:
                issues.append("No expiration time (exp) claim")
                severity = "High" if severity not in ["Critical"] else severity

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "api_key", "apikey", "private_key"]
            found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
            if found_sensitive:
                issues.append(f"Potentially sensitive data in payload: {', '.join(found_sensitive)}")
                severity = "High" if severity not in ["Critical"] else severity

            # Create finding if issues found
            if issues:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        None,
                        "JWT Security Issues",
                        severity,
                        "API Security",
                        f"Found {len(issues)} JWT security issues",
                        f"Header: {header}. Payload: {payload}. Issues: {'; '.join(issues)}",
                        "Use strong algorithms (RS256), include exp claim, avoid sensitive data in payload",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_analyze_jwt",
                details={"issues": len(issues), "severity": severity},
                project_id=project_id,
            )

            return {
                "success": True,
                "header": header,
                "payload": payload,
                "issues": issues,
                "severity": severity,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_graphql(
        self,
        url: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test GraphQL API for security issues."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            issues = []
            introspection_enabled = False
            types_found = []

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                # Test introspection
                introspection_query = """
                {
                  __schema {
                    types {
                      name
                      kind
                    }
                  }
                }
                """

                try:
                    response = await client.post(url, json={"query": introspection_query})
                    if response.status_code == 200:
                        data = response.json()
                        if "data" in data and "__schema" in data["data"]:
                            introspection_enabled = True
                            types_found = [t["name"] for t in data["data"]["__schema"]["types"][:20]]
                            issues.append("GraphQL introspection is enabled")
                except Exception:
                    pass

                # Test query depth
                deep_query = """
                {
                  user {
                    posts {
                      comments {
                        user {
                          posts {
                            comments {
                              user {
                                id
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
                """

                try:
                    response = await client.post(url, json={"query": deep_query})
                    if response.status_code == 200:
                        issues.append("No query depth limiting detected")
                except Exception:
                    pass

                # Test batching
                batch_query = [
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                ]

                try:
                    response = await client.post(url, json=batch_query)
                    if response.status_code == 200:
                        issues.append("Query batching is allowed - potential for DoS")
                except Exception:
                    pass

            # Create finding
            if issues:
                finding_id = generate_id()
                severity = "High" if introspection_enabled else "Medium"

                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "GraphQL Security Issues",
                        severity,
                        "API Security",
                        f"Found {len(issues)} GraphQL security issues",
                        f"Issues: {'; '.join(issues)}. Types found: {len(types_found)}",
                        "Disable introspection in production, implement query depth limiting, and restrict batching",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_graphql",
                details={"url": url, "issues": len(issues), "introspection": introspection_enabled},
                project_id=project_id,
            )

            return {
                "success": True,
                "introspection_enabled": introspection_enabled,
                "types_found": types_found,
                "issues": issues,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def fuzz_parameters(
        self,
        base_url: str,
        endpoint: str,
        method: str,
        parameters: List[str],
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Fuzz API parameters with boundary values and special characters."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            errors = []

            # Fuzzing payloads
            payloads = [
                "",  # Empty
                " ",  # Space
                "null",
                "None",
                "undefined",
                "-1",  # Negative
                "99999999999999999999",  # Large number
                "0.0",
                "true",
                "false",
                "[]",
                "{}",
                "A" * 10000,  # Long string
                "\x00",  # Null byte
                "../../../etc/passwd",  # Path traversal
                "<script>alert(1)</script>",  # XSS
                "${7*7}",  # Template injection
                "{{7*7}}",
            ]

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for param in parameters[:10]:  # Limit parameters
                    for payload in payloads:
                        try:
                            if method == "GET":
                                test_url = f"{url}?{param}={payload}"
                                response = await client.get(test_url)
                            else:
                                data = {param: payload}
                                response = await client.request(method, url, json=data)

                            # Check for errors
                            if response.status_code >= 500:
                                errors.append({
                                    "parameter": param,
                                    "payload": payload[:100],
                                    "status": response.status_code,
                                    "error": "Server error",
                                })

                        except Exception as e:
                            errors.append({
                                "parameter": param,
                                "payload": payload[:100],
                                "error": str(e)[:200],
                            })

            # Create finding if errors found
            if errors:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        f"API Parameter Fuzzing Issues: {endpoint}",
                        "Medium",
                        "API Security",
                        f"Found {len(errors)} parameter handling errors",
                        f"Errors: {str(errors[:20])}",
                        "Implement robust input validation and error handling",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_fuzz_parameters",
                details={"endpoint": endpoint, "errors": len(errors)},
                project_id=project_id,
            )

            return {
                "success": True,
                "errors": errors,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_cors_api(
        self,
        base_url: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test CORS configuration on API."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = base_url
            issues = []

            evil_origins = [
                "https://evil.com",
                "http://attacker.com",
                "null",
            ]

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for origin in evil_origins:
                    try:
                        headers = {"Origin": origin}
                        response = await client.options(url, headers=headers)

                        acao = response.headers.get("Access-Control-Allow-Origin", "")
                        acac = response.headers.get("Access-Control-Allow-Credentials", "")

                        if acao == "*":
                            issues.append("CORS allows all origins (Access-Control-Allow-Origin: *)")
                        elif acao == origin:
                            issues.append(f"CORS reflects origin: {origin}")

                        if acac == "true" and (acao == "*" or acao == origin):
                            issues.append("CORS allows credentials with permissive origin")

                    except Exception:
                        pass

            # Create finding if issues found
            if issues:
                finding_id = generate_id()
                severity = "High" if any("credentials" in i for i in issues) else "Medium"

                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Insecure CORS Configuration",
                        severity,
                        "API Security",
                        f"Found {len(issues)} CORS security issues",
                        f"Issues: {'; '.join(issues)}",
                        "Restrict CORS to specific trusted origins and avoid wildcard with credentials",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_cors",
                details={"base_url": base_url, "issues": len(issues)},
                project_id=project_id,
            )

            return {
                "success": True,
                "issues": issues,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_http_methods(
        self,
        base_url: str,
        endpoint: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test all HTTP methods on an endpoint."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            allowed_methods = []
            unexpected_methods = []

            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"]

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for method in methods:
                    try:
                        response = await client.request(method, url)

                        if response.status_code not in [404, 405]:
                            allowed_methods.append({
                                "method": method,
                                "status": response.status_code,
                            })

                            # TRACE is dangerous
                            if method == "TRACE" and response.status_code == 200:
                                unexpected_methods.append(method)

                    except Exception:
                        pass

            # Create finding if unexpected methods
            if unexpected_methods:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        f"Unexpected HTTP Methods Allowed: {endpoint}",
                        "Medium",
                        "API Security",
                        f"Endpoint allows unexpected HTTP methods",
                        f"Allowed methods: {str(allowed_methods)}. Unexpected: {', '.join(unexpected_methods)}",
                        "Disable unnecessary HTTP methods and only allow required methods",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_http_methods",
                details={"endpoint": endpoint, "allowed_methods": len(allowed_methods)},
                project_id=project_id,
            )

            return {
                "success": True,
                "allowed_methods": allowed_methods,
                "unexpected_methods": unexpected_methods,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_input_validation(
        self,
        base_url: str,
        endpoint: str,
        method: str,
        parameters: List[str],
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Test for missing input validation."""
        import httpx
        from core.database import generate_id, utc_now

        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            validation_issues = []

            # Test payloads
            test_cases = [
                {"type": "empty", "value": ""},
                {"type": "wrong_type_string", "value": "abc"},
                {"type": "wrong_type_array", "value": []},
                {"type": "negative", "value": -999},
                {"type": "zero", "value": 0},
                {"type": "special_chars", "value": "!@#$%^&*()"},
                {"type": "oversized", "value": "A" * 100000},
            ]

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for param in parameters[:5]:  # Limit
                    for test_case in test_cases:
                        try:
                            if method == "GET":
                                test_url = f"{url}?{param}={test_case['value']}"
                                response = await client.get(test_url)
                            else:
                                data = {param: test_case["value"]}
                                response = await client.request(method, url, json=data)

                            # If request succeeds with bad input, validation might be missing
                            if response.status_code in [200, 201]:
                                validation_issues.append({
                                    "parameter": param,
                                    "test_type": test_case["type"],
                                    "accepted_value": str(test_case["value"])[:100],
                                })

                        except Exception:
                            pass

            # Create finding
            if validation_issues:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        f"Missing Input Validation: {endpoint}",
                        "Medium",
                        "API Security",
                        f"Found {len(validation_issues)} input validation issues",
                        f"Issues: {str(validation_issues[:20])}",
                        "Implement strict input validation for all parameters",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="api_test_input_validation",
                details={"endpoint": endpoint, "issues": len(validation_issues)},
                project_id=project_id,
            )

            return {
                "success": True,
                "validation_issues": validation_issues,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_api_security(
        self,
        base_url: str,
        spec_url: str = None,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Run comprehensive API security scan."""
        from core.database import generate_id, utc_now

        try:
            results = {
                "base_url": base_url,
                "timestamp": utc_now(),
            }

            # Discover endpoints
            discovery_result = await self.discover_endpoints(base_url, spec_url, project_id, target_id)
            results["discovery"] = discovery_result

            if discovery_result.get("success") and discovery_result.get("endpoints"):
                endpoints = discovery_result["endpoints"][:20]  # Limit to 20

                # Test authentication
                results["authentication"] = await self.test_authentication(
                    base_url, endpoints, project_id=project_id, target_id=target_id
                )

                # Test rate limiting on first endpoint
                if endpoints:
                    first_endpoint = endpoints[0]
                    results["rate_limiting"] = await self.test_rate_limiting(
                        base_url,
                        first_endpoint.get("path", "/"),
                        first_endpoint.get("method", "GET"),
                        project_id,
                        target_id,
                    )

                # Test CORS
                results["cors"] = await self.test_cors_api(base_url, project_id, target_id)

                # Test GraphQL if found
                if discovery_result.get("graphql_found"):
                    results["graphql"] = await self.test_graphql(
                        f"{base_url.rstrip('/')}/graphql", project_id, target_id
                    )

            # Calculate risk score
            critical_count = 0
            high_count = 0

            # Count findings
            for check_name, check_result in results.items():
                if isinstance(check_result, dict):
                    findings = check_result.get("findings", [])
                    critical_count += len([f for f in findings if "Critical" in str(f)])
                    high_count += len([f for f in findings if "High" in str(f)])

            risk_score = (critical_count * 10) + (high_count * 5)

            # Create summary finding
            finding_id = generate_id()
            severity = "Critical" if critical_count > 0 else "High" if high_count > 0 else "Medium"

            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    f"API Security Scan: {base_url}",
                    severity,
                    "API Security",
                    f"Comprehensive API scan found {critical_count} critical and {high_count} high severity issues",
                    f"Risk Score: {risk_score}/100. Results: {str(results)}",
                    "Address all identified API security issues following recommendations",
                    utc_now(),
                ),
            )

            await self.db.audit(
                action="api_scan_security",
                details={
                    "base_url": base_url,
                    "risk_score": risk_score,
                    "critical": critical_count,
                    "high": high_count,
                },
                project_id=project_id,
            )

            return {
                "success": True,
                "risk_score": risk_score,
                "critical_issues": critical_count,
                "high_issues": high_count,
                "results": results,
                "summary_finding_id": finding_id,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_api_report(
        self,
        project_id: str,
    ) -> Dict[str, Any]:
        """Generate API security assessment report."""
        from core.database import utc_now

        try:
            # Get all API security findings for the project
            rows = await self.db.execute_query(
                """SELECT * FROM findings
                   WHERE project_id = ? AND category = 'API Security'
                   ORDER BY created_at DESC""",
                (project_id,),
            )

            findings = []
            for row in rows:
                findings.append({
                    "id": row[0],
                    "title": row[3],
                    "severity": row[4],
                    "description": row[6],
                    "evidence": row[7],
                    "remediation": row[8],
                })

            # Count by severity
            severity_counts = {
                "Critical": len([f for f in findings if f["severity"] == "Critical"]),
                "High": len([f for f in findings if f["severity"] == "High"]),
                "Medium": len([f for f in findings if f["severity"] == "Medium"]),
                "Low": len([f for f in findings if f["severity"] == "Low"]),
                "Info": len([f for f in findings if f["severity"] == "Info"]),
            }

            report = {
                "title": "API Security Assessment Report",
                "project_id": project_id,
                "generated_at": utc_now(),
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "findings": findings,
            }

            await self.db.audit(
                action="api_generate_report",
                details={"project_id": project_id, "findings": len(findings)},
                project_id=project_id,
            )

            return {
                "success": True,
                "report": report,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
