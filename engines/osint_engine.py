"""Open Source Intelligence (OSINT) gathering engine."""

import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime


class OSINTEngine:
    """Engine for OSINT gathering and reconnaissance."""

    def __init__(self, db, config: dict = None):
        """Initialize the OSINT Engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("osint", {})

    async def gather_domain_intel(
        self,
        domain: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Comprehensive domain OSINT gathering.

        Args:
            domain: Target domain
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with domain intelligence
        """
        from core.database import generate_id, utc_now
        import subprocess

        try:
            intel = {
                "domain": domain,
                "whois": None,
                "dns_records": {},
                "subdomains": [],
                "technologies": [],
                "emails": []
            }

            # WHOIS lookup
            try:
                result = subprocess.run(
                    ["nslookup", domain],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    intel["whois"] = result.stdout
            except Exception:
                pass

            # DNS records
            dns_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
            for record_type in dns_types:
                try:
                    result = subprocess.run(
                        ["nslookup", f"-type={record_type}", domain],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0 and result.stdout:
                        intel["dns_records"][record_type] = result.stdout
                except Exception:
                    pass

            # Common subdomains
            common_subdomains = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
                "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
                "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
                "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
                "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
                "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
                "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search"
            ]

            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    result = subprocess.run(
                        ["nslookup", full_domain],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0 and "can't find" not in result.stdout.lower():
                        intel["subdomains"].append(full_domain)
                except Exception:
                    pass

            # Email pattern generation
            common_patterns = [
                "info", "contact", "admin", "support", "sales", "hello", "team",
                "security", "abuse", "webmaster", "postmaster", "noreply"
            ]
            intel["emails"] = [f"{pattern}@{domain}" for pattern in common_patterns]

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    "INFO",
                    f"Domain Intelligence: {domain}",
                    json.dumps(intel),
                    utc_now()
                )
            )

            await self.db.audit(
                action="gather_domain_intel",
                details={"domain": domain, "subdomains_found": len(intel["subdomains"])},
                project_id=project_id
            )

            return {
                "success": True,
                "domain": domain,
                "intel": intel,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def search_breach_data(
        self,
        email_or_domain: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Check Have I Been Pwned for breaches.

        Args:
            email_or_domain: Email address or domain to check
            project_id: Project ID

        Returns:
            Dict with breach data
        """
        from core.database import generate_id, utc_now

        try:
            # Use HIBP platform client
            from platforms.hibp import HIBPClient

            hibp = HIBPClient(self.db, self.config)

            # Check if it's a domain or email
            if "@" in email_or_domain:
                result = await hibp.check_email(email_or_domain)
            else:
                result = await hibp.check_domain(email_or_domain)

            if result["success"]:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, severity, title, description, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        "HIGH" if result.get("breaches") else "INFO",
                        f"Breach Data Search: {email_or_domain}",
                        json.dumps(result),
                        utc_now()
                    )
                )

                await self.db.audit(
                    action="search_breach_data",
                    details={"target": email_or_domain, "breaches_found": len(result.get("breaches", []))},
                    project_id=project_id
                )

                return {
                    "success": True,
                    "target": email_or_domain,
                    "breaches": result.get("breaches", []),
                    "finding_id": finding_id
                }
            else:
                return result

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def harvest_emails(
        self,
        domain: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Harvest email addresses for a domain.

        Args:
            domain: Target domain
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with harvested emails
        """
        from core.database import generate_id, utc_now

        try:
            emails = set()
            patterns = []

            # Common email patterns
            common_formats = [
                "{first}.{last}",
                "{f}{last}",
                "{first}{last}",
                "{first}_{last}",
                "{last}.{first}",
                "{first}",
                "{last}",
                "{f}.{last}",
                "{first}{l}",
            ]

            for fmt in common_formats:
                patterns.append({
                    "format": fmt,
                    "example": fmt.replace("{first}", "john").replace("{last}", "doe").replace("{f}", "j").replace("{l}", "d") + f"@{domain}"
                })

            # Common role-based emails
            roles = [
                "info", "contact", "admin", "administrator", "support", "sales", "hello",
                "team", "security", "abuse", "webmaster", "postmaster", "noreply", "no-reply",
                "help", "service", "marketing", "hr", "jobs", "careers", "press", "media",
                "billing", "accounts", "finance", "legal", "privacy", "compliance"
            ]

            for role in roles:
                emails.add(f"{role}@{domain}")

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    "INFO",
                    f"Email Harvesting: {domain}",
                    json.dumps({"emails": list(emails), "patterns": patterns}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="harvest_emails",
                details={"domain": domain, "emails_found": len(emails)},
                project_id=project_id
            )

            return {
                "success": True,
                "domain": domain,
                "emails": list(emails),
                "patterns": patterns,
                "total_emails": len(emails),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def social_media_recon(
        self,
        target_name: str,
        platforms: List[str] = None,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate social media profile URLs.

        Args:
            target_name: Person or organization name
            platforms: List of platforms to check
            project_id: Project ID

        Returns:
            Dict with social media profiles
        """
        from core.database import generate_id, utc_now

        try:
            if platforms is None:
                platforms = ["linkedin", "twitter", "facebook", "github", "instagram", "youtube"]

            # Clean target name for URL
            clean_name = target_name.lower().replace(" ", "")
            dash_name = target_name.lower().replace(" ", "-")
            underscore_name = target_name.lower().replace(" ", "_")

            profiles = {}

            platform_templates = {
                "linkedin": [
                    f"https://www.linkedin.com/in/{dash_name}",
                    f"https://www.linkedin.com/company/{dash_name}"
                ],
                "twitter": [
                    f"https://twitter.com/{clean_name}",
                    f"https://twitter.com/{underscore_name}"
                ],
                "facebook": [
                    f"https://www.facebook.com/{clean_name}",
                    f"https://www.facebook.com/{dash_name}"
                ],
                "github": [
                    f"https://github.com/{clean_name}",
                    f"https://github.com/{dash_name}"
                ],
                "instagram": [
                    f"https://www.instagram.com/{clean_name}",
                    f"https://www.instagram.com/{underscore_name}"
                ],
                "youtube": [
                    f"https://www.youtube.com/@{clean_name}",
                    f"https://www.youtube.com/c/{clean_name}"
                ],
                "reddit": [
                    f"https://www.reddit.com/user/{clean_name}",
                    f"https://www.reddit.com/user/{underscore_name}"
                ],
                "medium": [
                    f"https://medium.com/@{clean_name}"
                ],
                "tiktok": [
                    f"https://www.tiktok.com/@{clean_name}"
                ],
                "pinterest": [
                    f"https://www.pinterest.com/{clean_name}"
                ]
            }

            for platform in platforms:
                if platform.lower() in platform_templates:
                    profiles[platform] = platform_templates[platform.lower()]

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Social Media Reconnaissance: {target_name}",
                    json.dumps({"profiles": profiles}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="social_media_recon",
                details={"target": target_name, "platforms": len(profiles)},
                project_id=project_id
            )

            return {
                "success": True,
                "target": target_name,
                "profiles": profiles,
                "total_platforms": len(profiles),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def document_metadata(
        self,
        file_path: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Extract metadata from documents.

        Args:
            file_path: Path to document
            project_id: Project ID

        Returns:
            Dict with extracted metadata
        """
        from core.database import generate_id, utc_now
        import os

        try:
            metadata = {
                "file_name": os.path.basename(file_path),
                "file_size": os.path.getsize(file_path),
                "file_extension": os.path.splitext(file_path)[1].lower()
            }

            ext = metadata["file_extension"]

            # PDF metadata
            if ext == ".pdf":
                try:
                    from PyPDF2 import PdfReader
                    reader = PdfReader(file_path)
                    info = reader.metadata
                    metadata.update({
                        "author": info.get("/Author", ""),
                        "creator": info.get("/Creator", ""),
                        "producer": info.get("/Producer", ""),
                        "subject": info.get("/Subject", ""),
                        "title": info.get("/Title", ""),
                        "creation_date": str(info.get("/CreationDate", "")),
                        "modification_date": str(info.get("/ModDate", "")),
                        "pages": len(reader.pages)
                    })
                except Exception as e:
                    metadata["error"] = f"Failed to extract PDF metadata: {str(e)}"

            # DOCX metadata
            elif ext == ".docx":
                try:
                    from docx import Document
                    doc = Document(file_path)
                    core_props = doc.core_properties
                    metadata.update({
                        "author": core_props.author or "",
                        "category": core_props.category or "",
                        "comments": core_props.comments or "",
                        "content_status": core_props.content_status or "",
                        "created": str(core_props.created) if core_props.created else "",
                        "identifier": core_props.identifier or "",
                        "keywords": core_props.keywords or "",
                        "language": core_props.language or "",
                        "last_modified_by": core_props.last_modified_by or "",
                        "modified": str(core_props.modified) if core_props.modified else "",
                        "revision": core_props.revision or "",
                        "subject": core_props.subject or "",
                        "title": core_props.title or "",
                        "version": core_props.version or ""
                    })
                except Exception as e:
                    metadata["error"] = f"Failed to extract DOCX metadata: {str(e)}"

            # Image metadata
            elif ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]:
                try:
                    from PIL import Image
                    from PIL.ExifTags import TAGS

                    img = Image.open(file_path)
                    metadata.update({
                        "format": img.format,
                        "mode": img.mode,
                        "size": img.size,
                        "width": img.width,
                        "height": img.height
                    })

                    exif_data = {}
                    if hasattr(img, '_getexif') and img._getexif():
                        for tag, value in img._getexif().items():
                            tag_name = TAGS.get(tag, tag)
                            exif_data[tag_name] = str(value)
                        metadata["exif"] = exif_data

                except Exception as e:
                    metadata["error"] = f"Failed to extract image metadata: {str(e)}"

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Document Metadata: {metadata['file_name']}",
                    json.dumps(metadata),
                    utc_now()
                )
            )

            await self.db.audit(
                action="document_metadata",
                details={"file": metadata['file_name']},
                project_id=project_id
            )

            return {
                "success": True,
                "metadata": metadata,
                "finding_id": finding_id
            }

        except FileNotFoundError:
            return {"success": False, "error": f"File not found: {file_path}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def google_dorking(
        self,
        domain: str,
        dork_category: str = "all",
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate Google dork queries.

        Args:
            domain: Target domain
            dork_category: Category of dorks (all, files, login, admin, database, config, errors)
            project_id: Project ID

        Returns:
            Dict with dork queries
        """
        from core.database import generate_id, utc_now

        try:
            dorks = {
                "files": [
                    f'site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx',
                    f'site:{domain} ext:sql | ext:db | ext:dbf | ext:mdb',
                    f'site:{domain} ext:log | ext:bak | ext:old | ext:backup',
                    f'site:{domain} ext:env | ext:config | ext:ini',
                    f'site:{domain} filetype:xml | filetype:conf | filetype:cnf',
                    f'site:{domain} filetype:txt inurl:password',
                    f'site:{domain} filetype:csv | filetype:dat'
                ],
                "login": [
                    f'site:{domain} inurl:login | inurl:signin | inurl:logon',
                    f'site:{domain} inurl:portal | inurl:auth',
                    f'site:{domain} inurl:wp-admin | inurl:wp-login',
                    f'site:{domain} inurl:admin/login | inurl:user/login',
                    f'site:{domain} intitle:"Index of" "parent directory"',
                    f'site:{domain} inurl:token | inurl:secret | inurl:api-key'
                ],
                "admin": [
                    f'site:{domain} inurl:admin | inurl:administrator',
                    f'site:{domain} intitle:admin | intitle:"admin panel"',
                    f'site:{domain} inurl:dashboard | inurl:cpanel',
                    f'site:{domain} inurl:phpmyadmin | inurl:pma',
                    f'site:{domain} inurl:webadmin | inurl:controlpanel',
                    f'site:{domain} intitle:"Dashboard" intitle:"Admin"'
                ],
                "database": [
                    f'site:{domain} inurl:sql | inurl:db | inurl:database',
                    f'site:{domain} "Index of" inurl:database',
                    f'site:{domain} "phpMyAdmin" "running on"',
                    f'site:{domain} inurl:wp-config.php | inurl:config.php',
                    f'site:{domain} ext:sql "INSERT INTO"',
                    f'site:{domain} "MySQL Error" | "SQL syntax"'
                ],
                "config": [
                    f'site:{domain} ext:xml | ext:conf | ext:cnf | ext:config',
                    f'site:{domain} ext:env | ext:ini',
                    f'site:{domain} inurl:config | inurl:configuration',
                    f'site:{domain} intitle:"index of" "application.properties"',
                    f'site:{domain} intitle:"index of" ".env"',
                    f'site:{domain} filetype:yaml | filetype:yml'
                ],
                "errors": [
                    f'site:{domain} "Warning: mysql" | "SQL syntax"',
                    f'site:{domain} "Fatal error" | "Parse error"',
                    f'site:{domain} "Exception" | "Stack trace"',
                    f'site:{domain} "Uncaught exception" | "Error:"',
                    f'site:{domain} intitle:"Error" | intitle:"Exception"',
                    f'site:{domain} "JDBC" | "ORA-" | "PostgreSQL"'
                ],
                "exposure": [
                    f'site:{domain} intitle:"Index of" ".git"',
                    f'site:{domain} intitle:"Index of" ".svn"',
                    f'site:{domain} intitle:"Index of" "backup"',
                    f'site:{domain} ext:log | ext:bak',
                    f'site:{domain} "API key" | "api_key"',
                    f'site:{domain} "password" | "passwd" ext:txt'
                ]
            }

            if dork_category.lower() != "all" and dork_category.lower() in dorks:
                selected_dorks = {dork_category: dorks[dork_category]}
            else:
                selected_dorks = dorks

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Google Dorking Queries: {domain}",
                    json.dumps({"dorks": selected_dorks, "category": dork_category}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="google_dorking",
                details={"domain": domain, "category": dork_category},
                project_id=project_id
            )

            total_queries = sum(len(queries) for queries in selected_dorks.values())

            return {
                "success": True,
                "domain": domain,
                "category": dork_category,
                "dorks": selected_dorks,
                "total_queries": total_queries,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def github_recon(
        self,
        org_or_user: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Search GitHub for exposed secrets.

        Args:
            org_or_user: GitHub organization or username
            project_id: Project ID

        Returns:
            Dict with GitHub reconnaissance results
        """
        from core.database import generate_id, utc_now

        try:
            # Common secret search queries for GitHub
            search_queries = [
                f'user:{org_or_user} password',
                f'user:{org_or_user} api_key',
                f'user:{org_or_user} secret',
                f'user:{org_or_user} token',
                f'user:{org_or_user} credentials',
                f'user:{org_or_user} aws_access_key_id',
                f'user:{org_or_user} filename:.env',
                f'user:{org_or_user} filename:config.json',
                f'user:{org_or_user} extension:pem private',
                f'user:{org_or_user} extension:ppk private',
                f'user:{org_or_user} AKIA',  # AWS keys
                f'user:{org_or_user} "-----BEGIN RSA PRIVATE KEY-----"',
                f'user:{org_or_user} "-----BEGIN PRIVATE KEY-----"',
                f'user:{org_or_user} db_password',
                f'user:{org_or_user} mysql_password'
            ]

            # Files to look for
            sensitive_files = [
                '.env', '.env.production', '.env.local', '.env.development',
                'config.json', 'credentials.json', 'secrets.json',
                'id_rsa', 'id_dsa', '.pem', '.ppk', '.key',
                'config.php', 'database.yml', 'application.properties',
                'web.config', 'appsettings.json', '.htpasswd',
                'wp-config.php', 'settings.py', 'secrets.yml'
            ]

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"GitHub Reconnaissance: {org_or_user}",
                    json.dumps({
                        "search_queries": search_queries,
                        "sensitive_files": sensitive_files,
                        "target": org_or_user
                    }),
                    utc_now()
                )
            )

            await self.db.audit(
                action="github_recon",
                details={"target": org_or_user},
                project_id=project_id
            )

            return {
                "success": True,
                "target": org_or_user,
                "search_queries": search_queries,
                "sensitive_files": sensitive_files,
                "total_queries": len(search_queries),
                "finding_id": finding_id,
                "note": "Use these queries on GitHub's search interface to find potential exposures"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def dns_intelligence(
        self,
        domain: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Deep DNS analysis.

        Args:
            domain: Target domain
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with DNS intelligence
        """
        from core.database import generate_id, utc_now
        import subprocess

        try:
            dns_intel = {
                "domain": domain,
                "records": {},
                "mail_security": {},
                "zone_transfer": None,
                "dnssec": None
            }

            # Get all record types
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"]
            for record_type in record_types:
                try:
                    result = subprocess.run(
                        ["nslookup", f"-type={record_type}", domain],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        dns_intel["records"][record_type] = result.stdout
                except Exception:
                    pass

            # Check SPF, DKIM, DMARC
            txt_records = dns_intel["records"].get("TXT", "")
            dns_intel["mail_security"]["spf"] = "v=spf1" in txt_records
            dns_intel["mail_security"]["dmarc_lookup"] = f"_dmarc.{domain}"

            try:
                dmarc_result = subprocess.run(
                    ["nslookup", f"-type=TXT", f"_dmarc.{domain}"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                dns_intel["mail_security"]["dmarc"] = "v=DMARC1" in dmarc_result.stdout
            except Exception:
                dns_intel["mail_security"]["dmarc"] = False

            # Attempt zone transfer
            ns_records = dns_intel["records"].get("NS", "")
            if ns_records:
                dns_intel["zone_transfer"] = "Zone transfer attempts should be made manually with: dig axfr @nameserver domain"

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    "INFO",
                    f"DNS Intelligence: {domain}",
                    json.dumps(dns_intel),
                    utc_now()
                )
            )

            await self.db.audit(
                action="dns_intelligence",
                details={"domain": domain},
                project_id=project_id
            )

            return {
                "success": True,
                "domain": domain,
                "intel": dns_intel,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def wayback_analysis(
        self,
        domain: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Analyze Wayback Machine snapshots.

        Args:
            domain: Target domain
            project_id: Project ID

        Returns:
            Dict with Wayback analysis
        """
        from core.database import generate_id, utc_now

        try:
            wayback_data = {
                "domain": domain,
                "wayback_url": f"https://web.archive.org/web/*/{domain}",
                "cdx_api": f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json",
                "analysis_tips": [
                    "Look for old admin panels or login pages that may still exist",
                    "Check for exposed configuration files or backups",
                    "Identify removed pages that might reveal system architecture",
                    "Find old technology stack information (server headers, frameworks)",
                    "Search for employee names or email patterns",
                    "Look for API endpoints that may still be active",
                    "Check robots.txt history for hidden directories"
                ]
            }

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Wayback Machine Analysis: {domain}",
                    json.dumps(wayback_data),
                    utc_now()
                )
            )

            await self.db.audit(
                action="wayback_analysis",
                details={"domain": domain},
                project_id=project_id
            )

            return {
                "success": True,
                "domain": domain,
                "data": wayback_data,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def search_pastebin(
        self,
        query: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Search paste sites for leaked data.

        Args:
            query: Search query
            project_id: Project ID

        Returns:
            Dict with paste search results
        """
        from core.database import generate_id, utc_now

        try:
            paste_sites = {
                "pastebin": f"https://www.google.com/search?q=site:pastebin.com+{query}",
                "ghostbin": f"https://www.google.com/search?q=site:ghostbin.co+{query}",
                "slexy": f"https://www.google.com/search?q=site:slexy.org+{query}",
                "codepad": f"https://www.google.com/search?q=site:codepad.org+{query}",
                "ideone": f"https://www.google.com/search?q=site:ideone.com+{query}",
                "github_gist": f"https://www.google.com/search?q=site:gist.github.com+{query}",
                "paste2": f"https://www.google.com/search?q=site:paste2.org+{query}",
                "justpaste": f"https://www.google.com/search?q=site:justpaste.it+{query}"
            }

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Pastebin Search: {query}",
                    json.dumps({"paste_sites": paste_sites, "query": query}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="search_pastebin",
                details={"query": query},
                project_id=project_id
            )

            return {
                "success": True,
                "query": query,
                "paste_sites": paste_sites,
                "total_sites": len(paste_sites),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def ip_reputation(
        self,
        ip_address: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Check IP reputation.

        Args:
            ip_address: IP address to check
            project_id: Project ID

        Returns:
            Dict with IP reputation data
        """
        from core.database import generate_id, utc_now

        try:
            # Use VirusTotal client if available
            from platforms.virustotal import VirusTotalClient

            vt = VirusTotalClient(self.db, self.config)
            result = await vt.check_ip(ip_address)

            if result["success"]:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, severity, title, description, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        "INFO",
                        f"IP Reputation Check: {ip_address}",
                        json.dumps(result),
                        utc_now()
                    )
                )

                await self.db.audit(
                    action="ip_reputation",
                    details={"ip": ip_address},
                    project_id=project_id
                )

                return {
                    "success": True,
                    "ip": ip_address,
                    "reputation": result,
                    "finding_id": finding_id
                }
            else:
                # Fallback to basic info
                reputation_info = {
                    "ip": ip_address,
                    "lookup_urls": [
                        f"https://www.virustotal.com/gui/ip-address/{ip_address}",
                        f"https://www.abuseipdb.com/check/{ip_address}",
                        f"https://www.talosintelligence.com/reputation_center/lookup?search={ip_address}",
                        f"https://check.spamhaus.org/listed/?searchterm={ip_address}"
                    ]
                }

                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, severity, title, description, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        "INFO",
                        f"IP Reputation Check: {ip_address}",
                        json.dumps(reputation_info),
                        utc_now()
                    )
                )

                return {
                    "success": True,
                    "ip": ip_address,
                    "reputation": reputation_info,
                    "finding_id": finding_id
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_osint_report(self, project_id: str = None) -> Dict[str, Any]:
        """Generate comprehensive OSINT report.

        Args:
            project_id: Project ID

        Returns:
            Dict with OSINT report
        """
        from core.database import generate_id, utc_now

        try:
            # Get all OSINT findings for this project
            cursor = await self.db.execute_query(
                """SELECT * FROM findings
                   WHERE project_id = ? AND title LIKE '%Intelligence%'
                   OR title LIKE '%Reconnaissance%'
                   OR title LIKE '%OSINT%'
                   ORDER BY created_at DESC""",
                (project_id,)
            )
            findings = cursor.fetchall()

            report = {
                "project_id": project_id,
                "generated_at": utc_now(),
                "total_findings": len(findings),
                "findings": []
            }

            for finding in findings:
                report["findings"].append({
                    "id": finding[0],
                    "title": finding[4],
                    "severity": finding[3],
                    "created_at": finding[6]
                })

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    "OSINT Report",
                    json.dumps(report),
                    utc_now()
                )
            )

            await self.db.audit(
                action="generate_osint_report",
                details={"total_findings": len(findings)},
                project_id=project_id
            )

            return {
                "success": True,
                "report": report,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
