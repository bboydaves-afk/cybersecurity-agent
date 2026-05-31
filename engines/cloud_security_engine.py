"""Cloud security auditing engine for AWS, Azure, and GCP."""

import json
import logging

logger = logging.getLogger("hacking_agent.engines.cloud_security")


class CloudSecurityEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = config or {}
        self._cloud_config = self.config.get("cloud", {})

    async def audit_aws(self, profile: str = "default",
                        project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        from knowledge.loader import get_cloud_misconfigs
        misconfigs_kb = get_cloud_misconfigs()
        aws_checks = misconfigs_kb.get("aws", [])

        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "cloud_audit", "running", utc_now()))

        findings = []
        try:
            import boto3
            session = boto3.Session(profile_name=profile)

            # S3 public bucket check
            s3 = session.client("s3")
            try:
                buckets = s3.list_buckets().get("Buckets", [])
                for bucket in buckets:
                    try:
                        acl = s3.get_bucket_acl(Bucket=bucket["Name"])
                        for grant in acl.get("Grants", []):
                            grantee = grant.get("Grantee", {})
                            if grantee.get("URI", "").endswith("AllUsers"):
                                findings.append({
                                    "check_id": "AWS-S3-001",
                                    "title": f"Public S3 Bucket: {bucket['Name']}",
                                    "severity": "critical",
                                    "resource": bucket["Name"],
                                })
                    except Exception:
                        pass
            except Exception as e:
                logger.warning("S3 check failed: %s", e)

            # IAM checks
            iam = session.client("iam")
            try:
                users = iam.list_users().get("Users", [])
                for user in users:
                    mfa = iam.list_mfa_devices(UserName=user["UserName"])
                    if not mfa.get("MFADevices"):
                        findings.append({
                            "check_id": "AWS-IAM-003",
                            "title": f"No MFA: {user['UserName']}",
                            "severity": "high",
                            "resource": user["UserName"],
                        })
                    keys = iam.list_access_keys(UserName=user["UserName"])
                    for key in keys.get("AccessKeyMetadata", []):
                        from datetime import datetime, timezone
                        age = (datetime.now(timezone.utc) - key["CreateDate"].replace(tzinfo=timezone.utc)).days
                        if age > 90:
                            findings.append({
                                "check_id": "AWS-KMS-001",
                                "title": f"Old Access Key: {user['UserName']} ({age} days)",
                                "severity": "medium",
                                "resource": key["AccessKeyId"],
                            })
            except Exception as e:
                logger.warning("IAM check failed: %s", e)

            # Security groups
            ec2 = session.client("ec2")
            try:
                sgs = ec2.describe_security_groups().get("SecurityGroups", [])
                for sg in sgs:
                    for rule in sg.get("IpPermissions", []):
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                port = rule.get("FromPort", "all")
                                findings.append({
                                    "check_id": "AWS-EC2-001",
                                    "title": f"SG {sg['GroupId']} allows 0.0.0.0/0 on port {port}",
                                    "severity": "high",
                                    "resource": sg["GroupId"],
                                })
            except Exception as e:
                logger.warning("EC2 check failed: %s", e)

        except ImportError:
            return {"success": False, "error": "boto3 not installed"}
        except Exception as e:
            await self.db.execute_commit(
                "UPDATE scans SET status='failed', completed_at=? WHERE id=?",
                (utc_now(), scan_id))
            return {"success": False, "error": str(e)}

        for f in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, scan_id, title, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, scan_id, f["title"], f["severity"], "open", utc_now()))

        await self.db.execute_commit(
            "UPDATE scans SET status='completed', results=?, finding_count=?, completed_at=? WHERE id=?",
            (json.dumps(findings, default=str), len(findings), utc_now(), scan_id))

        await self.db.audit("audit_aws", target_id, project_id,
                            f"AWS audit: {len(findings)} findings")
        return {"success": True, "scan_id": scan_id, "provider": "aws",
                "findings": findings, "finding_count": len(findings)}

    async def audit_azure(self, subscription_id: str = None,
                          project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        from knowledge.loader import get_cloud_misconfigs

        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "cloud_audit", "running", utc_now()))

        findings = []
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.network import NetworkManagementClient

            credential = DefaultAzureCredential()
            sub_id = subscription_id or self._cloud_config.get("azure", {}).get("subscription_id", "")

            # Storage checks
            try:
                storage = StorageManagementClient(credential, sub_id)
                for account in storage.storage_accounts.list():
                    if account.allow_blob_public_access:
                        findings.append({
                            "check_id": "AZ-STOR-001",
                            "title": f"Public blob access: {account.name}",
                            "severity": "critical",
                            "resource": account.name,
                        })
            except Exception as e:
                logger.warning("Azure storage check failed: %s", e)

            # NSG checks
            try:
                network = NetworkManagementClient(credential, sub_id)
                for nsg in network.network_security_groups.list_all():
                    for rule in (nsg.security_rules or []):
                        if rule.source_address_prefix == "*" and rule.access == "Allow" and rule.direction == "Inbound":
                            findings.append({
                                "check_id": "AZ-NSG-001",
                                "title": f"NSG {nsg.name}: allows any inbound ({rule.name})",
                                "severity": "high",
                                "resource": nsg.name,
                            })
            except Exception as e:
                logger.warning("Azure NSG check failed: %s", e)

        except ImportError:
            return {"success": False, "error": "azure SDK not installed"}
        except Exception as e:
            await self.db.execute_commit(
                "UPDATE scans SET status='failed', completed_at=? WHERE id=?",
                (utc_now(), scan_id))
            return {"success": False, "error": str(e)}

        for f in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, scan_id, title, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, scan_id, f["title"], f["severity"], "open", utc_now()))

        await self.db.execute_commit(
            "UPDATE scans SET status='completed', results=?, finding_count=?, completed_at=? WHERE id=?",
            (json.dumps(findings, default=str), len(findings), utc_now(), scan_id))

        await self.db.audit("audit_azure", target_id, project_id,
                            f"Azure audit: {len(findings)} findings")
        return {"success": True, "scan_id": scan_id, "provider": "azure",
                "findings": findings, "finding_count": len(findings)}

    async def audit_gcp(self, gcp_project_id: str = None,
                        project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        scan_id = generate_id("scan-")
        await self.db.execute_commit(
            "INSERT INTO scans (id, project_id, target_id, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, project_id, target_id, "cloud_audit", "running", utc_now()))

        findings = []
        try:
            from google.cloud import storage as gcs

            client = gcs.Client(project=gcp_project_id)
            for bucket in client.list_buckets():
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                        findings.append({
                            "check_id": "GCP-GCS-001",
                            "title": f"Public GCS bucket: {bucket.name}",
                            "severity": "critical",
                            "resource": bucket.name,
                        })

        except ImportError:
            return {"success": False, "error": "google-cloud-storage not installed"}
        except Exception as e:
            await self.db.execute_commit(
                "UPDATE scans SET status='failed', completed_at=? WHERE id=?",
                (utc_now(), scan_id))
            return {"success": False, "error": str(e)}

        for f in findings:
            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, scan_id, title, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id, scan_id, f["title"], f["severity"], "open", utc_now()))

        await self.db.execute_commit(
            "UPDATE scans SET status='completed', results=?, finding_count=?, completed_at=? WHERE id=?",
            (json.dumps(findings, default=str), len(findings), utc_now(), scan_id))

        await self.db.audit("audit_gcp", target_id, project_id,
                            f"GCP audit: {len(findings)} findings")
        return {"success": True, "scan_id": scan_id, "provider": "gcp",
                "findings": findings, "finding_count": len(findings)}

    async def check_iam_permissions(self, provider: str, identity: str = None,
                                    project_id: str = None, target_id: str = None) -> dict:
        await self.db.audit("check_iam_permissions", target_id, project_id,
                            f"IAM review for {provider}")
        checks = {
            "aws": ["Wildcard (*) permissions", "Inline policies", "Unused roles", "Cross-account access", "Root account usage"],
            "azure": ["Owner/Contributor at subscription", "Custom roles with write", "Guest accounts", "Service principal secrets"],
            "gcp": ["Primitive roles (Owner/Editor)", "Service account keys", "Domain-wide delegation", "Public access bindings"],
        }
        return {
            "success": True, "provider": provider,
            "checks_to_perform": checks.get(provider, []),
            "note": f"Run the audit_{provider} tool for automated checks",
        }

    async def check_storage_exposure(self, provider: str,
                                     project_id: str = None, target_id: str = None) -> dict:
        if provider == "aws":
            return await self.audit_aws(project_id=project_id, target_id=target_id)
        elif provider == "azure":
            return await self.audit_azure(project_id=project_id, target_id=target_id)
        elif provider == "gcp":
            return await self.audit_gcp(project_id=project_id, target_id=target_id)
        return {"success": False, "error": f"Unknown provider: {provider}"}

    async def get_cloud_summary(self, project_id: str) -> dict:
        scans = await self.db.fetch_all(
            "SELECT * FROM scans WHERE project_id=? AND scan_type='cloud_audit' ORDER BY started_at DESC",
            (project_id,))
        findings = await self.db.fetch_all(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE project_id=? AND scan_id IN (SELECT id FROM scans WHERE scan_type='cloud_audit') GROUP BY severity",
            (project_id,))

        severity_counts = {r["severity"]: r["cnt"] for r in findings}
        return {
            "success": True, "project_id": project_id,
            "total_audits": len(scans),
            "findings_by_severity": severity_counts,
            "total_findings": sum(severity_counts.values()),
        }
