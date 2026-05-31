"""Secrets scanning and detection engine."""

import json
import re
import os
from typing import Dict, List, Any, Optional
from pathlib import Path


class SecretsEngine:
    """Engine for scanning and detecting secrets in files and repositories."""

    # Secret detection patterns
    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "description": "AWS Access Key ID",
            "severity": "CRITICAL"
        },
        "aws_secret_key": {
            "pattern": r"aws_secret_access_key[\s]*[:=][\s]*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "description": "AWS Secret Access Key",
            "severity": "CRITICAL"
        },
        "azure_key": {
            "pattern": r"[a-zA-Z0-9+/]{86}==",
            "description": "Azure Storage Account Key",
            "severity": "CRITICAL"
        },
        "gcp_key": {
            "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
            "description": "Google Cloud Platform API Key",
            "severity": "CRITICAL"
        },
        "github_token": {
            "pattern": r"gh[ps]_[A-Za-z0-9_]{36}",
            "description": "GitHub Personal Access Token",
            "severity": "CRITICAL"
        },
        "github_oauth": {
            "pattern": r"gho_[A-Za-z0-9_]{36}",
            "description": "GitHub OAuth Access Token",
            "severity": "CRITICAL"
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
            "description": "JSON Web Token (JWT)",
            "severity": "HIGH"
        },
        "private_key_rsa": {
            "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
            "description": "RSA Private Key",
            "severity": "CRITICAL"
        },
        "private_key_ec": {
            "pattern": r"-----BEGIN EC PRIVATE KEY-----",
            "description": "EC Private Key",
            "severity": "CRITICAL"
        },
        "private_key_dsa": {
            "pattern": r"-----BEGIN DSA PRIVATE KEY-----",
            "description": "DSA Private Key",
            "severity": "CRITICAL"
        },
        "private_key_openssh": {
            "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "description": "OpenSSH Private Key",
            "severity": "CRITICAL"
        },
        "private_key_generic": {
            "pattern": r"-----BEGIN PRIVATE KEY-----",
            "description": "Generic Private Key",
            "severity": "CRITICAL"
        },
        "generic_password": {
            "pattern": r"(password|passwd|pwd|secret|token|api_key|apikey|auth)[\s]*[:=][\s]*['\"]([^\s'\"]{8,})['\"]",
            "description": "Generic Password/Secret",
            "severity": "HIGH"
        },
        "connection_string_mongodb": {
            "pattern": r"mongodb(\+srv)?://[^\s]+",
            "description": "MongoDB Connection String",
            "severity": "CRITICAL"
        },
        "connection_string_mysql": {
            "pattern": r"mysql://[^\s]+",
            "description": "MySQL Connection String",
            "severity": "CRITICAL"
        },
        "connection_string_postgresql": {
            "pattern": r"postgresql://[^\s]+",
            "description": "PostgreSQL Connection String",
            "severity": "CRITICAL"
        },
        "connection_string_redis": {
            "pattern": r"redis://[^\s]+",
            "description": "Redis Connection String",
            "severity": "HIGH"
        },
        "connection_string_amqp": {
            "pattern": r"amqp://[^\s]+",
            "description": "AMQP Connection String",
            "severity": "HIGH"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "description": "Slack Token",
            "severity": "HIGH"
        },
        "slack_webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "description": "Slack Webhook URL",
            "severity": "HIGH"
        },
        "stripe_key": {
            "pattern": r"sk_live_[0-9a-zA-Z]{24}",
            "description": "Stripe Live Secret Key",
            "severity": "CRITICAL"
        },
        "twilio_key": {
            "pattern": r"SK[0-9a-fA-F]{32}",
            "description": "Twilio API Key",
            "severity": "HIGH"
        },
        "mailgun_key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "description": "Mailgun API Key",
            "severity": "HIGH"
        },
        "sendgrid_key": {
            "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
            "description": "SendGrid API Key",
            "severity": "HIGH"
        },
        "heroku_key": {
            "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "description": "Heroku API Key",
            "severity": "HIGH"
        },
        "facebook_token": {
            "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
            "description": "Facebook Access Token",
            "severity": "HIGH"
        },
        "twitter_token": {
            "pattern": r"[1-9][0-9]+-[0-9a-zA-Z]{40}",
            "description": "Twitter Access Token",
            "severity": "HIGH"
        },
        "npm_token": {
            "pattern": r"npm_[A-Za-z0-9]{36}",
            "description": "NPM Access Token",
            "severity": "HIGH"
        },
        "docker_auth": {
            "pattern": r"\"auth\":\s*\"[A-Za-z0-9+/=]+\"",
            "description": "Docker Auth Token",
            "severity": "HIGH"
        }
    }

    def __init__(self, db, config: dict = None):
        """Initialize the Secrets Engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("secrets", {})
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        self.compiled_patterns = {}
        for name, info in self.SECRET_PATTERNS.items():
            self.compiled_patterns[name] = {
                "regex": re.compile(info["pattern"], re.IGNORECASE),
                "description": info["description"],
                "severity": info["severity"]
            }

    async def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Scan files in a directory for secrets.

        Args:
            path: Directory path to scan
            recursive: Whether to scan recursively
            project_id: Project ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now

        try:
            if not os.path.isdir(path):
                return {"success": False, "error": f"Not a directory: {path}"}

            all_secrets = []
            files_scanned = 0

            # File extensions to skip
            skip_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
                             '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll', '.so',
                             '.dylib', '.bin', '.dat', '.mp3', '.mp4', '.avi'}

            # Directories to skip
            skip_dirs = {'node_modules', '.git', '.svn', 'venv', '__pycache__',
                        'dist', 'build', 'target', '.idea', '.vscode'}

            path_obj = Path(path)

            if recursive:
                files_to_scan = [f for f in path_obj.rglob('*') if f.is_file()]
            else:
                files_to_scan = [f for f in path_obj.glob('*') if f.is_file()]

            for file_path in files_to_scan:
                # Skip if in ignored directory
                if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                    continue

                # Skip binary files
                if file_path.suffix.lower() in skip_extensions:
                    continue

                # Skip large files (>10MB)
                if file_path.stat().st_size > 10 * 1024 * 1024:
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    file_secrets = self._scan_content(str(file_path), content)
                    all_secrets.extend(file_secrets)
                    files_scanned += 1

                except Exception:
                    continue  # Skip files that can't be read

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if all_secrets else "INFO",
                    f"Directory Secrets Scan: {path}",
                    json.dumps({
                        "secrets": all_secrets,
                        "files_scanned": files_scanned,
                        "total_secrets": len(all_secrets)
                    }),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_directory",
                details={"path": path, "secrets_found": len(all_secrets), "files_scanned": files_scanned},
                project_id=project_id
            )

            return {
                "success": True,
                "path": path,
                "secrets": all_secrets,
                "total_secrets": len(all_secrets),
                "files_scanned": files_scanned,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_git_repo(
        self,
        repo_path: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Scan git repository history for secrets.

        Args:
            repo_path: Path to git repository
            project_id: Project ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now
        import subprocess

        try:
            if not os.path.isdir(os.path.join(repo_path, '.git')):
                return {"success": False, "error": "Not a git repository"}

            all_secrets = []

            # Get list of all commits
            result = subprocess.run(
                ["git", "log", "--all", "--pretty=format:%H"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                return {"success": False, "error": f"Git log failed: {result.stderr}"}

            commits = result.stdout.strip().split('\n')[:100]  # Limit to last 100 commits

            for commit in commits:
                # Get commit diff
                diff_result = subprocess.run(
                    ["git", "show", commit],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if diff_result.returncode == 0:
                    secrets = self._scan_content(f"commit:{commit}", diff_result.stdout)
                    for secret in secrets:
                        secret["commit"] = commit
                    all_secrets.extend(secrets)

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if all_secrets else "INFO",
                    f"Git Repository Secrets Scan: {repo_path}",
                    json.dumps({
                        "secrets": all_secrets,
                        "commits_scanned": len(commits),
                        "total_secrets": len(all_secrets)
                    }),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_git_repo",
                details={"repo": repo_path, "secrets_found": len(all_secrets)},
                project_id=project_id
            )

            return {
                "success": True,
                "repo_path": repo_path,
                "secrets": all_secrets,
                "total_secrets": len(all_secrets),
                "commits_scanned": len(commits),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_file(
        self,
        file_path: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to file
            project_id: Project ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            secrets = self._scan_content(file_path, content)

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if secrets else "INFO",
                    f"File Secrets Scan: {file_path}",
                    json.dumps({"secrets": secrets, "file": file_path}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_file",
                details={"file": file_path, "secrets_found": len(secrets)},
                project_id=project_id
            )

            return {
                "success": True,
                "file": file_path,
                "secrets": secrets,
                "total_secrets": len(secrets),
                "finding_id": finding_id
            }

        except FileNotFoundError:
            return {"success": False, "error": f"File not found: {file_path}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _scan_content(self, source: str, content: str) -> List[Dict[str, Any]]:
        """Scan content for secrets.

        Args:
            source: Source identifier (file path or commit)
            content: Content to scan

        Returns:
            List of found secrets
        """
        secrets = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_info in self.compiled_patterns.items():
                matches = pattern_info["regex"].finditer(line)
                for match in matches:
                    secret_value = match.group(0)

                    # Calculate entropy for generic patterns
                    entropy = self._calculate_entropy(secret_value)

                    secrets.append({
                        "type": pattern_name,
                        "description": pattern_info["description"],
                        "severity": pattern_info["severity"],
                        "source": source,
                        "line": line_num,
                        "value": secret_value[:50] + "..." if len(secret_value) > 50 else secret_value,
                        "entropy": round(entropy, 2),
                        "context": line.strip()[:200]
                    })

        return secrets

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            string: String to analyze

        Returns:
            Entropy value
        """
        import math

        if not string:
            return 0.0

        entropy = 0
        for char in set(string):
            prob = string.count(char) / len(string)
            entropy -= prob * math.log2(prob)

        return entropy

    async def scan_env_files(
        self,
        path: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Find and analyze .env files for secrets.

        Args:
            path: Directory path to search
            project_id: Project ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now

        try:
            env_patterns = ['.env', '.env.local', '.env.production', '.env.development',
                          '.env.staging', '.env.test', '.env.backup', '.env.old']

            all_secrets = []
            files_found = []

            path_obj = Path(path)

            for env_pattern in env_patterns:
                for env_file in path_obj.rglob(env_pattern):
                    if env_file.is_file():
                        files_found.append(str(env_file))

                        try:
                            with open(env_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            secrets = self._scan_content(str(env_file), content)
                            all_secrets.extend(secrets)
                        except Exception:
                            continue

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if all_secrets else "INFO",
                    f"Environment Files Scan: {path}",
                    json.dumps({
                        "secrets": all_secrets,
                        "files_found": files_found,
                        "total_secrets": len(all_secrets)
                    }),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_env_files",
                details={"path": path, "files_found": len(files_found), "secrets_found": len(all_secrets)},
                project_id=project_id
            )

            return {
                "success": True,
                "path": path,
                "files_found": files_found,
                "secrets": all_secrets,
                "total_secrets": len(all_secrets),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_cloud_secrets(
        self,
        provider: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Check cloud secret management configuration.

        Args:
            provider: Cloud provider (aws, azure, gcp)
            project_id: Project ID

        Returns:
            Dict with cloud secrets analysis
        """
        from core.database import generate_id, utc_now

        try:
            recommendations = {
                "aws": {
                    "service": "AWS Secrets Manager",
                    "checks": [
                        "Verify automatic rotation is enabled",
                        "Check KMS encryption keys are used",
                        "Review IAM policies for least privilege access",
                        "Enable CloudTrail logging for secret access",
                        "Check for secrets older than 90 days without rotation",
                        "Verify cross-account access policies"
                    ],
                    "cli_commands": [
                        "aws secretsmanager list-secrets",
                        "aws secretsmanager describe-secret --secret-id <secret-name>",
                        "aws secretsmanager get-resource-policy --secret-id <secret-name>"
                    ]
                },
                "azure": {
                    "service": "Azure Key Vault",
                    "checks": [
                        "Enable soft-delete and purge protection",
                        "Configure access policies with least privilege",
                        "Enable diagnostic logging",
                        "Set up automatic key rotation",
                        "Review network access rules (firewall)",
                        "Check for expired secrets and certificates"
                    ],
                    "cli_commands": [
                        "az keyvault list",
                        "az keyvault secret list --vault-name <vault-name>",
                        "az keyvault secret show --vault-name <vault-name> --name <secret-name>"
                    ]
                },
                "gcp": {
                    "service": "Google Secret Manager",
                    "checks": [
                        "Enable automatic replication",
                        "Configure IAM permissions with least privilege",
                        "Enable audit logging",
                        "Set up secret version rotation",
                        "Review secret access patterns",
                        "Check for secrets without expiration"
                    ],
                    "cli_commands": [
                        "gcloud secrets list",
                        "gcloud secrets describe <secret-name>",
                        "gcloud secrets versions list <secret-name>"
                    ]
                }
            }

            if provider.lower() not in recommendations:
                return {"success": False, "error": f"Unsupported provider: {provider}"}

            provider_info = recommendations[provider.lower()]

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Cloud Secrets Check: {provider.upper()}",
                    json.dumps(provider_info),
                    utc_now()
                )
            )

            await self.db.audit(
                action="check_cloud_secrets",
                details={"provider": provider},
                project_id=project_id
            )

            return {
                "success": True,
                "provider": provider,
                "service": provider_info["service"],
                "checks": provider_info["checks"],
                "cli_commands": provider_info["cli_commands"],
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_config_files(
        self,
        path: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Scan configuration files for embedded credentials.

        Args:
            path: Directory path to scan
            project_id: Project ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now

        try:
            config_extensions = {'.yaml', '.yml', '.json', '.xml', '.ini',
                               '.toml', '.conf', '.config', '.properties'}

            all_secrets = []
            files_scanned = 0

            path_obj = Path(path)

            for file_path in path_obj.rglob('*'):
                if file_path.is_file() and file_path.suffix.lower() in config_extensions:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        secrets = self._scan_content(str(file_path), content)
                        all_secrets.extend(secrets)
                        files_scanned += 1
                    except Exception:
                        continue

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if all_secrets else "INFO",
                    f"Configuration Files Scan: {path}",
                    json.dumps({
                        "secrets": all_secrets,
                        "files_scanned": files_scanned,
                        "total_secrets": len(all_secrets)
                    }),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_config_files",
                details={"path": path, "files_scanned": files_scanned, "secrets_found": len(all_secrets)},
                project_id=project_id
            )

            return {
                "success": True,
                "path": path,
                "secrets": all_secrets,
                "total_secrets": len(all_secrets),
                "files_scanned": files_scanned,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_docker_secrets(
        self,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Check Dockerfiles and docker-compose for hardcoded secrets.

        Args:
            project_id: Project ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now

        try:
            docker_files = []
            all_secrets = []

            # Find Dockerfiles and docker-compose files in current directory
            for root, dirs, files in os.walk('.'):
                for file in files:
                    if file in ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'] or file.endswith('.dockerfile'):
                        file_path = os.path.join(root, file)
                        docker_files.append(file_path)

                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            secrets = self._scan_content(file_path, content)

                            # Additional Docker-specific checks
                            lines = content.split('\n')
                            for line_num, line in enumerate(lines, 1):
                                # Check for ENV with hardcoded values
                                if line.strip().startswith('ENV') and '=' in line:
                                    if any(keyword in line.upper() for keyword in ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'API']):
                                        secrets.append({
                                            "type": "docker_env_secret",
                                            "description": "Hardcoded secret in ENV instruction",
                                            "severity": "HIGH",
                                            "source": file_path,
                                            "line": line_num,
                                            "context": line.strip()
                                        })

                                # Check for ARG with default values
                                if line.strip().startswith('ARG') and '=' in line:
                                    if any(keyword in line.upper() for keyword in ['PASSWORD', 'SECRET', 'TOKEN', 'KEY']):
                                        secrets.append({
                                            "type": "docker_arg_secret",
                                            "description": "Hardcoded secret in ARG instruction",
                                            "severity": "MEDIUM",
                                            "source": file_path,
                                            "line": line_num,
                                            "context": line.strip()
                                        })

                            all_secrets.extend(secrets)
                        except Exception:
                            continue

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if all_secrets else "INFO",
                    "Docker Secrets Scan",
                    json.dumps({
                        "secrets": all_secrets,
                        "files_scanned": docker_files,
                        "total_secrets": len(all_secrets)
                    }),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_docker_secrets",
                details={"files_scanned": len(docker_files), "secrets_found": len(all_secrets)},
                project_id=project_id
            )

            return {
                "success": True,
                "docker_files": docker_files,
                "secrets": all_secrets,
                "total_secrets": len(all_secrets),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_secret_patterns(self) -> Dict[str, Any]:
        """Return the regex patterns used for detection.

        Returns:
            Dict with all secret patterns
        """
        patterns_info = {}
        for name, info in self.SECRET_PATTERNS.items():
            patterns_info[name] = {
                "pattern": info["pattern"],
                "description": info["description"],
                "severity": info["severity"]
            }

        return {
            "success": True,
            "patterns": patterns_info,
            "total_patterns": len(patterns_info)
        }

    async def validate_findings(
        self,
        finding_ids: List[str],
        project_id: str = None
    ) -> Dict[str, Any]:
        """Help validate if detected secrets are real.

        Args:
            finding_ids: List of finding IDs to validate
            project_id: Project ID

        Returns:
            Dict with validation results
        """
        from core.database import utc_now

        try:
            validations = []

            # Known test values that are false positives
            test_values = [
                "AKIAIOSFODNN7EXAMPLE",  # AWS example
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS example
                "example", "test", "sample", "demo", "fake", "dummy",
                "your_", "my_", "insert_", "replace_", "change_"
            ]

            for finding_id in finding_ids:
                cursor = await self.db.execute_query(
                    "SELECT description FROM findings WHERE id = ?",
                    (finding_id,)
                )
                result = cursor.fetchone()

                if result:
                    finding_data = json.loads(result[0])
                    secrets = finding_data.get("secrets", [])

                    for secret in secrets:
                        value = secret.get("value", "")
                        entropy = secret.get("entropy", 0)

                        is_likely_real = True
                        reason = "Appears to be a real secret"

                        # Check if it's a test value
                        if any(test in value.lower() for test in test_values):
                            is_likely_real = False
                            reason = "Contains test/example keywords"

                        # Check entropy for high-entropy patterns
                        elif secret.get("type") in ["aws_access_key", "github_token"] and entropy < 3.0:
                            is_likely_real = False
                            reason = "Low entropy suggests fake/test value"

                        validations.append({
                            "finding_id": finding_id,
                            "type": secret.get("type"),
                            "value_preview": value[:20] + "...",
                            "is_likely_real": is_likely_real,
                            "reason": reason,
                            "entropy": entropy
                        })

            await self.db.audit(
                action="validate_findings",
                details={"findings_checked": len(finding_ids)},
                project_id=project_id
            )

            return {
                "success": True,
                "validations": validations,
                "total_validated": len(validations)
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate_secrets_report(
        self,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate report of all found secrets with remediation guidance.

        Args:
            project_id: Project ID

        Returns:
            Dict with secrets report
        """
        from core.database import generate_id, utc_now

        try:
            # Get all secret findings for this project
            cursor = await self.db.execute_query(
                """SELECT * FROM findings
                   WHERE project_id = ? AND (title LIKE '%Secrets%' OR severity = 'CRITICAL')
                   ORDER BY created_at DESC""",
                (project_id,)
            )
            findings = cursor.fetchall()

            total_secrets = 0
            by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            by_type = {}

            for finding in findings:
                try:
                    finding_data = json.loads(finding[5])  # description column
                    secrets = finding_data.get("secrets", [])
                    total_secrets += len(secrets)

                    for secret in secrets:
                        severity = secret.get("severity", "UNKNOWN")
                        secret_type = secret.get("type", "unknown")

                        if severity in by_severity:
                            by_severity[severity] += 1

                        by_type[secret_type] = by_type.get(secret_type, 0) + 1
                except Exception:
                    continue

            remediation_guidance = {
                "immediate_actions": [
                    "Rotate all exposed credentials immediately",
                    "Remove secrets from version control history (git filter-branch or BFG)",
                    "Move secrets to secure secret management systems",
                    "Enable monitoring for compromised credentials"
                ],
                "preventive_measures": [
                    "Use environment variables for secrets",
                    "Implement pre-commit hooks (e.g., git-secrets, detect-secrets)",
                    "Use cloud provider secret managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)",
                    "Add .env files to .gitignore",
                    "Implement secret scanning in CI/CD pipelines",
                    "Use encrypted secret management (HashiCorp Vault, Doppler)",
                    "Enable branch protection rules requiring code review"
                ],
                "tools": [
                    "git-secrets - Prevents committing secrets",
                    "truffleHog - Git history scanner",
                    "detect-secrets - Baseline secret scanner",
                    "GitGuardian - Real-time secret detection",
                    "gitleaks - SAST tool for detecting secrets"
                ]
            }

            report = {
                "project_id": project_id,
                "generated_at": utc_now(),
                "summary": {
                    "total_secrets": total_secrets,
                    "total_findings": len(findings),
                    "by_severity": by_severity,
                    "by_type": by_type
                },
                "remediation": remediation_guidance
            }

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "CRITICAL" if total_secrets > 0 else "INFO",
                    "Secrets Scanning Report",
                    json.dumps(report),
                    utc_now()
                )
            )

            await self.db.audit(
                action="generate_secrets_report",
                details={"total_secrets": total_secrets},
                project_id=project_id
            )

            return {
                "success": True,
                "report": report,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
