"""Email security assessment engine."""

import asyncio
from typing import Optional, Dict, Any, List


class EmailSecurityEngine:
    """Engine for email security assessments including SPF, DKIM, DMARC, and mail server testing."""

    def __init__(self, db, config: dict = None):
        """Initialize the email security engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("email_security", {})

    async def check_spf(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Check SPF record for a domain.

        Args:
            domain: Domain to check
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and SPF details
        """
        from core.database import generate_id, utc_now
        import dns.resolver

        try:
            # Query SPF record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                spf_records = [str(rdata).strip('"') for rdata in answers if str(rdata).startswith('v=spf1')]
            except Exception as e:
                await self.db.audit(
                    action="check_spf",
                    resource_type="domain",
                    resource_id=domain,
                    details={"domain": domain, "error": str(e), "result": "no_record"},
                    project_id=project_id
                )
                return {
                    "success": True,
                    "domain": domain,
                    "spf_exists": False,
                    "grade": "none",
                    "issues": ["No SPF record found"],
                    "recommendation": "Implement SPF record with strict policy (-all)"
                }

            if not spf_records:
                return {
                    "success": True,
                    "domain": domain,
                    "spf_exists": False,
                    "grade": "none",
                    "issues": ["No SPF record found"]
                }

            spf_record = spf_records[0]
            mechanisms = spf_record.split()

            # Analyze SPF policy
            issues = []
            grade = "neutral"
            policy = None

            for mechanism in mechanisms:
                if mechanism in ['all', '+all']:
                    issues.append("Dangerous: SPF allows all senders (+all)")
                    grade = "fail"
                    policy = "+all"
                elif mechanism == '?all':
                    issues.append("Weak: SPF uses neutral policy (?all)")
                    grade = "weak"
                    policy = "?all"
                elif mechanism == '~all':
                    issues.append("Moderate: SPF uses soft fail (~all)")
                    grade = "moderate"
                    policy = "~all"
                elif mechanism == '-all':
                    grade = "strict"
                    policy = "-all"

            # Check for too many DNS lookups
            lookup_count = sum(1 for m in mechanisms if m.startswith(('include:', 'a:', 'mx:', 'ptr:', 'exists:')))
            if lookup_count > 10:
                issues.append(f"SPF has {lookup_count} DNS lookups (max 10 recommended)")

            result = {
                "success": True,
                "domain": domain,
                "spf_exists": True,
                "spf_record": spf_record,
                "policy": policy,
                "mechanisms": mechanisms,
                "grade": grade,
                "issues": issues,
                "lookup_count": lookup_count
            }

            await self.db.audit(
                action="check_spf",
                resource_type="domain",
                resource_id=domain,
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    async def check_dkim(self, domain: str, selector: str = None, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Check DKIM record for a domain.

        Args:
            domain: Domain to check
            selector: DKIM selector (if known)
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and DKIM details
        """
        from core.database import generate_id, utc_now
        import dns.resolver

        try:
            # Common selectors to try
            selectors = [selector] if selector else [
                'google', 'default', 'selector1', 'selector2',
                'k1', 's1', 'dkim', 'mail', 'smtp'
            ]

            found_records = []

            for sel in selectors:
                if sel is None:
                    continue

                dkim_domain = f"{sel}._domainkey.{domain}"
                try:
                    answers = dns.resolver.resolve(dkim_domain, 'TXT')
                    for rdata in answers:
                        record = str(rdata).strip('"').replace('" "', '')
                        if 'v=DKIM1' in record or 'p=' in record:
                            # Parse DKIM record
                            parts = {}
                            for part in record.split(';'):
                                part = part.strip()
                                if '=' in part:
                                    key, value = part.split('=', 1)
                                    parts[key.strip()] = value.strip()

                            # Check key length
                            issues = []
                            key_data = parts.get('p', '')
                            if len(key_data) < 200:
                                issues.append("DKIM key appears short (may be < 1024 bits)")

                            # Check algorithm
                            algo = parts.get('k', 'rsa')
                            if algo != 'rsa':
                                issues.append(f"Non-standard key algorithm: {algo}")

                            found_records.append({
                                'selector': sel,
                                'domain': dkim_domain,
                                'record': record,
                                'parts': parts,
                                'algorithm': algo,
                                'issues': issues
                            })
                except:
                    continue

            result = {
                "success": True,
                "domain": domain,
                "dkim_exists": len(found_records) > 0,
                "records": found_records,
                "selectors_tested": [s for s in selectors if s],
                "recommendation": "Implement DKIM signing with at least 2048-bit RSA keys" if not found_records else None
            }

            await self.db.audit(
                action="check_dkim",
                resource_type="domain",
                resource_id=domain,
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    async def check_dmarc(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Check DMARC record for a domain.

        Args:
            domain: Domain to check
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and DMARC details
        """
        from core.database import generate_id, utc_now
        import dns.resolver

        try:
            dmarc_domain = f"_dmarc.{domain}"

            try:
                answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                dmarc_records = [str(rdata).strip('"').replace('" "', '') for rdata in answers if 'v=DMARC1' in str(rdata)]
            except Exception as e:
                await self.db.audit(
                    action="check_dmarc",
                    resource_type="domain",
                    resource_id=domain,
                    details={"domain": domain, "error": str(e), "result": "no_record"},
                    project_id=project_id
                )
                return {
                    "success": True,
                    "domain": domain,
                    "dmarc_exists": False,
                    "grade": "none",
                    "issues": ["No DMARC record found"],
                    "recommendation": "Implement DMARC with p=quarantine or p=reject"
                }

            if not dmarc_records:
                return {
                    "success": True,
                    "domain": domain,
                    "dmarc_exists": False,
                    "grade": "none",
                    "issues": ["No DMARC record found"]
                }

            dmarc_record = dmarc_records[0]

            # Parse DMARC record
            parts = {}
            for part in dmarc_record.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    parts[key.strip()] = value.strip()

            policy = parts.get('p', 'none')
            subdomain_policy = parts.get('sp', policy)
            pct = int(parts.get('pct', '100'))
            rua = parts.get('rua', '')
            ruf = parts.get('ruf', '')

            # Grade the DMARC policy
            issues = []
            grade = "strict"

            if policy == 'none':
                issues.append("DMARC policy is set to 'none' (monitoring only)")
                grade = "weak"
            elif policy == 'quarantine':
                grade = "moderate"
            elif policy == 'reject':
                grade = "strict"

            if pct < 100:
                issues.append(f"DMARC policy only applies to {pct}% of messages")

            if not rua:
                issues.append("No aggregate reporting address (rua) configured")

            result = {
                "success": True,
                "domain": domain,
                "dmarc_exists": True,
                "dmarc_record": dmarc_record,
                "policy": policy,
                "subdomain_policy": subdomain_policy,
                "percentage": pct,
                "aggregate_reports": rua,
                "forensic_reports": ruf,
                "grade": grade,
                "issues": issues,
                "parts": parts
            }

            await self.db.audit(
                action="check_dmarc",
                resource_type="domain",
                resource_id=domain,
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    async def analyze_email_headers(self, headers_text: str, project_id: str = None) -> Dict[str, Any]:
        """Analyze raw email headers for security issues.

        Args:
            headers_text: Raw email headers
            project_id: Project ID

        Returns:
            Dict with success status and analysis results
        """
        from core.database import generate_id, utc_now
        import email
        from email.parser import Parser

        try:
            parser = Parser()
            headers = parser.parsestr(headers_text)

            # Extract key headers
            from_header = headers.get('From', '')
            reply_to = headers.get('Reply-To', '')
            return_path = headers.get('Return-Path', '')
            received = headers.get_all('Received', [])

            # SPF/DKIM/DMARC results
            auth_results = headers.get('Authentication-Results', '')

            # Trace route
            received_chain = []
            for rec in received:
                received_chain.append(rec.strip())

            # Check for mismatches
            issues = []

            if reply_to and reply_to != from_header:
                issues.append(f"Reply-To mismatch: From={from_header}, Reply-To={reply_to}")

            if return_path and return_path != from_header:
                issues.append(f"Return-Path mismatch: From={from_header}, Return-Path={return_path}")

            # Parse authentication results
            spf_result = None
            dkim_result = None
            dmarc_result = None

            if auth_results:
                if 'spf=pass' in auth_results.lower():
                    spf_result = 'pass'
                elif 'spf=fail' in auth_results.lower():
                    spf_result = 'fail'
                    issues.append("SPF check failed")

                if 'dkim=pass' in auth_results.lower():
                    dkim_result = 'pass'
                elif 'dkim=fail' in auth_results.lower():
                    dkim_result = 'fail'
                    issues.append("DKIM check failed")

                if 'dmarc=pass' in auth_results.lower():
                    dmarc_result = 'pass'
                elif 'dmarc=fail' in auth_results.lower():
                    dmarc_result = 'fail'
                    issues.append("DMARC check failed")

            # Check for suspicious X-headers
            suspicious_headers = []
            for key in headers.keys():
                if key.startswith('X-') and key not in ['X-Mailer', 'X-Originating-IP', 'X-Microsoft-Antispam']:
                    suspicious_headers.append(f"{key}: {headers[key]}")

            result = {
                "success": True,
                "from": from_header,
                "reply_to": reply_to,
                "return_path": return_path,
                "received_chain": received_chain,
                "hops": len(received_chain),
                "authentication_results": {
                    "spf": spf_result,
                    "dkim": dkim_result,
                    "dmarc": dmarc_result
                },
                "suspicious_headers": suspicious_headers,
                "issues": issues
            }

            await self.db.audit(
                action="analyze_email_headers",
                resource_type="email",
                resource_id=generate_id(),
                details={"issues_found": len(issues)},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def check_mail_server(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Check mail server configuration.

        Args:
            domain: Domain to check
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and mail server details
        """
        from core.database import generate_id, utc_now
        import dns.resolver

        try:
            # Get MX records
            try:
                mx_records = []
                answers = dns.resolver.resolve(domain, 'MX')
                for rdata in answers:
                    mx_records.append({
                        'priority': rdata.preference,
                        'host': str(rdata.exchange).rstrip('.')
                    })
                mx_records.sort(key=lambda x: x['priority'])
            except Exception as e:
                return {
                    "success": True,
                    "domain": domain,
                    "mx_records": [],
                    "issues": [f"No MX records found: {str(e)}"]
                }

            if not mx_records:
                return {
                    "success": True,
                    "domain": domain,
                    "mx_records": [],
                    "issues": ["No MX records configured"]
                }

            # Test SMTP on primary MX
            primary_mx = mx_records[0]['host']
            smtp_results = []
            issues = []

            for port in [25, 587]:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(primary_mx, port),
                        timeout=5
                    )

                    # Read banner
                    banner = await asyncio.wait_for(reader.readline(), timeout=3)
                    banner = banner.decode().strip()

                    # Send EHLO
                    writer.write(b'EHLO test.com\r\n')
                    await writer.drain()

                    response = b''
                    while True:
                        line = await asyncio.wait_for(reader.readline(), timeout=3)
                        response += line
                        if not line.startswith(b'250-'):
                            break

                    capabilities = response.decode().strip().split('\r\n')

                    starttls_support = any('STARTTLS' in cap for cap in capabilities)

                    # Test VRFY command
                    writer.write(b'VRFY test@test.com\r\n')
                    await writer.drain()
                    vrfy_response = await asyncio.wait_for(reader.readline(), timeout=3)
                    vrfy_enabled = not vrfy_response.startswith(b'252')

                    if vrfy_enabled:
                        issues.append(f"VRFY command enabled on port {port} (user enumeration risk)")

                    # Close connection
                    writer.write(b'QUIT\r\n')
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()

                    smtp_results.append({
                        'port': port,
                        'open': True,
                        'banner': banner,
                        'starttls': starttls_support,
                        'vrfy_enabled': vrfy_enabled
                    })

                    if not starttls_support:
                        issues.append(f"STARTTLS not supported on port {port}")

                except asyncio.TimeoutError:
                    smtp_results.append({'port': port, 'open': False, 'error': 'timeout'})
                except Exception as e:
                    smtp_results.append({'port': port, 'open': False, 'error': str(e)})

            result = {
                "success": True,
                "domain": domain,
                "mx_records": mx_records,
                "primary_mx": primary_mx,
                "smtp_tests": smtp_results,
                "issues": issues
            }

            await self.db.audit(
                action="check_mail_server",
                resource_type="domain",
                resource_id=domain,
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    async def check_email_spoofing(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Test if domain is spoofable.

        Args:
            domain: Domain to check
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and spoofing assessment
        """
        from core.database import generate_id, utc_now

        try:
            # Check SPF, DMARC
            spf_result = await self.check_spf(domain, project_id, target_id)
            dmarc_result = await self.check_dmarc(domain, project_id, target_id)

            has_spf = spf_result.get('spf_exists', False)
            spf_grade = spf_result.get('grade', 'none')
            has_dmarc = dmarc_result.get('dmarc_exists', False)
            dmarc_policy = dmarc_result.get('policy', 'none')

            # Assess spoofing risk
            if not has_spf and not has_dmarc:
                risk_level = "critical"
                assessment = "Domain is highly spoofable - no SPF or DMARC protection"
            elif has_spf and spf_grade in ['fail', 'weak'] and (not has_dmarc or dmarc_policy == 'none'):
                risk_level = "high"
                assessment = "Domain has weak email authentication - spoofing is feasible"
            elif has_spf and spf_grade in ['moderate', 'strict'] and dmarc_policy in ['none', 'quarantine']:
                risk_level = "medium"
                assessment = "Domain has moderate protection - spoofing is difficult but possible"
            elif has_spf and spf_grade == 'strict' and dmarc_policy == 'reject':
                risk_level = "low"
                assessment = "Domain is well protected against spoofing"
            else:
                risk_level = "medium"
                assessment = "Domain has partial email authentication"

            result = {
                "success": True,
                "domain": domain,
                "spoofing_risk": risk_level,
                "assessment": assessment,
                "spf_status": {
                    "exists": has_spf,
                    "grade": spf_grade
                },
                "dmarc_status": {
                    "exists": has_dmarc,
                    "policy": dmarc_policy
                },
                "recommendations": []
            }

            if not has_spf:
                result["recommendations"].append("Implement SPF record with -all policy")
            elif spf_grade in ['fail', 'weak']:
                result["recommendations"].append("Strengthen SPF policy to use -all")

            if not has_dmarc:
                result["recommendations"].append("Implement DMARC with p=quarantine or p=reject")
            elif dmarc_policy == 'none':
                result["recommendations"].append("Change DMARC policy from p=none to p=quarantine or p=reject")

            await self.db.audit(
                action="check_email_spoofing",
                resource_type="domain",
                resource_id=domain,
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    async def test_smtp_auth(self, host: str, port: int = 587, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Test SMTP authentication mechanisms.

        Args:
            host: SMTP server hostname
            port: SMTP server port
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and auth mechanisms
        """
        from core.database import generate_id, utc_now

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )

            # Read banner
            banner = await asyncio.wait_for(reader.readline(), timeout=3)
            banner = banner.decode().strip()

            # Send EHLO
            writer.write(b'EHLO test.com\r\n')
            await writer.drain()

            response = b''
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=3)
                response += line
                if not line.startswith(b'250-'):
                    break

            capabilities = response.decode().strip().split('\r\n')

            # Parse AUTH methods
            auth_methods = []
            for cap in capabilities:
                if 'AUTH' in cap:
                    parts = cap.split()
                    if len(parts) > 1:
                        auth_methods.extend(parts[1:])

            # Check for weak auth
            issues = []
            if 'PLAIN' in auth_methods:
                issues.append("PLAIN authentication supported (credentials sent in base64)")
            if 'LOGIN' in auth_methods:
                issues.append("LOGIN authentication supported (legacy method)")

            # Close connection
            writer.write(b'QUIT\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            result = {
                "success": True,
                "host": host,
                "port": port,
                "banner": banner,
                "auth_methods": list(set(auth_methods)),
                "issues": issues,
                "secure_methods": [m for m in auth_methods if m in ['CRAM-MD5', 'DIGEST-MD5', 'GSSAPI', 'XOAUTH2']]
            }

            await self.db.audit(
                action="test_smtp_auth",
                resource_type="smtp_server",
                resource_id=f"{host}:{port}",
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "host": host,
                "port": port
            }

    async def check_email_security_posture(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Perform full email security assessment.

        Args:
            domain: Domain to assess
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and comprehensive assessment
        """
        from core.database import generate_id, utc_now

        try:
            # Run all checks
            spf_result = await self.check_spf(domain, project_id, target_id)
            dkim_result = await self.check_dkim(domain, project_id=project_id, target_id=target_id)
            dmarc_result = await self.check_dmarc(domain, project_id, target_id)
            mail_server_result = await self.check_mail_server(domain, project_id, target_id)
            spoofing_result = await self.check_email_spoofing(domain, project_id, target_id)

            # Calculate overall grade
            grades = {
                'A': 4,
                'B': 3,
                'C': 2,
                'D': 1,
                'F': 0
            }

            score = 0
            max_score = 0

            # SPF (25%)
            spf_grade_map = {'strict': 'A', 'moderate': 'B', 'weak': 'D', 'none': 'F'}
            spf_letter = spf_grade_map.get(spf_result.get('grade', 'none'), 'F')
            score += grades.get(spf_letter, 0)
            max_score += 4

            # DKIM (25%)
            dkim_letter = 'A' if dkim_result.get('dkim_exists') else 'F'
            score += grades.get(dkim_letter, 0)
            max_score += 4

            # DMARC (30%)
            dmarc_grade_map = {'strict': 'A', 'moderate': 'B', 'weak': 'D', 'none': 'F'}
            dmarc_letter = dmarc_grade_map.get(dmarc_result.get('grade', 'none'), 'F')
            score += grades.get(dmarc_letter, 0)
            max_score += 4

            # Mail server security (20%)
            mx_issues = len(mail_server_result.get('issues', []))
            if mx_issues == 0:
                mx_letter = 'A'
            elif mx_issues <= 2:
                mx_letter = 'B'
            else:
                mx_letter = 'D'
            score += grades.get(mx_letter, 0)
            max_score += 4

            # Calculate final grade
            percentage = (score / max_score * 100) if max_score > 0 else 0
            if percentage >= 90:
                overall_grade = 'A'
            elif percentage >= 80:
                overall_grade = 'B'
            elif percentage >= 70:
                overall_grade = 'C'
            elif percentage >= 60:
                overall_grade = 'D'
            else:
                overall_grade = 'F'

            result = {
                "success": True,
                "domain": domain,
                "overall_grade": overall_grade,
                "score_percentage": round(percentage, 1),
                "component_grades": {
                    "spf": spf_letter,
                    "dkim": dkim_letter,
                    "dmarc": dmarc_letter,
                    "mail_server": mx_letter
                },
                "spf": spf_result,
                "dkim": dkim_result,
                "dmarc": dmarc_result,
                "mail_server": mail_server_result,
                "spoofing_assessment": spoofing_result,
                "summary": self._generate_summary(overall_grade, spoofing_result)
            }

            await self.db.audit(
                action="check_email_security_posture",
                resource_type="domain",
                resource_id=domain,
                details={"overall_grade": overall_grade, "score": percentage},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    def _generate_summary(self, grade: str, spoofing_result: Dict) -> str:
        """Generate assessment summary."""
        if grade == 'A':
            return f"Excellent email security posture. {spoofing_result.get('assessment', '')}"
        elif grade == 'B':
            return f"Good email security with minor improvements needed. {spoofing_result.get('assessment', '')}"
        elif grade == 'C':
            return f"Moderate email security - significant improvements recommended. {spoofing_result.get('assessment', '')}"
        else:
            return f"Poor email security posture - immediate action required. {spoofing_result.get('assessment', '')}"

    async def check_bimi(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Check for BIMI (Brand Indicators for Message Identification) record.

        Args:
            domain: Domain to check
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and BIMI details
        """
        from core.database import generate_id, utc_now
        import dns.resolver

        try:
            bimi_domain = f"default._bimi.{domain}"

            try:
                answers = dns.resolver.resolve(bimi_domain, 'TXT')
                bimi_records = [str(rdata).strip('"').replace('" "', '') for rdata in answers if 'v=BIMI1' in str(rdata)]
            except Exception as e:
                return {
                    "success": True,
                    "domain": domain,
                    "bimi_exists": False,
                    "note": "BIMI record not found (optional feature)"
                }

            if not bimi_records:
                return {
                    "success": True,
                    "domain": domain,
                    "bimi_exists": False
                }

            bimi_record = bimi_records[0]

            # Parse BIMI record
            parts = {}
            for part in bimi_record.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    parts[key.strip()] = value.strip()

            logo_url = parts.get('l', '')
            authority_url = parts.get('a', '')

            result = {
                "success": True,
                "domain": domain,
                "bimi_exists": True,
                "bimi_record": bimi_record,
                "logo_url": logo_url,
                "authority_url": authority_url,
                "parts": parts
            }

            await self.db.audit(
                action="check_bimi",
                resource_type="domain",
                resource_id=domain,
                details=result,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    async def generate_email_report(self, project_id: str) -> Dict[str, Any]:
        """Generate email security assessment report for a project.

        Args:
            project_id: Project ID

        Returns:
            Dict with success status and report data
        """
        from core.database import generate_id, utc_now

        try:
            # Query audit log for email security checks
            query = """
                SELECT action, resource_id, details, timestamp
                FROM audit_log
                WHERE project_id = ?
                AND action IN ('check_spf', 'check_dkim', 'check_dmarc', 'check_email_security_posture')
                ORDER BY timestamp DESC
            """

            rows = await self.db.execute_query(query, (project_id,))

            domains_assessed = {}

            for row in rows:
                action, resource_id, details_json, timestamp = row
                domain = resource_id

                if domain not in domains_assessed:
                    domains_assessed[domain] = {
                        'domain': domain,
                        'checks': [],
                        'last_assessed': timestamp
                    }

                domains_assessed[domain]['checks'].append({
                    'action': action,
                    'timestamp': timestamp,
                    'details': details_json
                })

            result = {
                "success": True,
                "project_id": project_id,
                "domains_assessed": len(domains_assessed),
                "domains": list(domains_assessed.values()),
                "generated_at": utc_now()
            }

            await self.db.audit(
                action="generate_email_report",
                resource_type="project",
                resource_id=project_id,
                details={"domains_count": len(domains_assessed)},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "project_id": project_id
            }
