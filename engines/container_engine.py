"""Container and Kubernetes security assessment engine."""

import json
import subprocess
from typing import Dict, List, Any, Optional


class ContainerEngine:
    """Engine for Docker and Kubernetes security assessment."""

    def __init__(self, db, config: dict = None):
        """Initialize the Container Engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("container", {})

    async def scan_docker_image(
        self,
        image_name: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Analyze Docker image for security issues.

        Args:
            image_name: Name or ID of Docker image
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with scan results
        """
        from core.database import generate_id, utc_now

        try:
            # Run docker inspect
            result = subprocess.run(
                ["docker", "inspect", image_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to inspect image: {result.stderr}"
                }

            inspect_data = json.loads(result.stdout)
            if not inspect_data:
                return {"success": False, "error": "No data returned from inspect"}

            image_data = inspect_data[0]
            config = image_data.get("Config", {})

            issues = []

            # Check for root user
            user = config.get("User", "")
            if not user or user == "root" or user == "0":
                issues.append({
                    "severity": "HIGH",
                    "issue": "Running as root user",
                    "description": "Container runs as root, increasing attack surface"
                })

            # Check exposed ports
            exposed_ports = config.get("ExposedPorts", {})
            sensitive_ports = ["22", "23", "3389", "5900"]
            for port in exposed_ports:
                port_num = port.split("/")[0]
                if port_num in sensitive_ports:
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"Sensitive port exposed: {port}",
                        "description": "Exposing management/remote access ports"
                    })

            # Check environment variables for secrets
            env_vars = config.get("Env", [])
            secret_patterns = ["PASSWORD", "SECRET", "TOKEN", "KEY", "API"]
            for env in env_vars:
                if any(pattern in env.upper() for pattern in secret_patterns):
                    issues.append({
                        "severity": "HIGH",
                        "issue": "Potential secret in environment variable",
                        "description": f"Environment variable may contain secrets: {env.split('=')[0]}"
                    })

            # Check image layers for size
            layers = image_data.get("RootFS", {}).get("Layers", [])
            if len(layers) > 50:
                issues.append({
                    "severity": "LOW",
                    "issue": f"Large number of layers ({len(layers)})",
                    "description": "Too many layers may indicate inefficient build process"
                })

            # Check for health check
            if not config.get("Healthcheck"):
                issues.append({
                    "severity": "LOW",
                    "issue": "No health check defined",
                    "description": "Container lacks health check configuration"
                })

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
                    f"Docker Image Scan: {image_name}",
                    json.dumps({"issues": issues, "image_data": image_data}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_docker_image",
                details={"image": image_name, "issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "image": image_name,
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Docker inspect timed out"}
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Failed to parse docker output: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_docker_config(self, project_id: str = None) -> Dict[str, Any]:
        """Audit Docker daemon configuration.

        Args:
            project_id: Project ID

        Returns:
            Dict with configuration audit results
        """
        from core.database import generate_id, utc_now

        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to get docker info: {result.stderr}"
                }

            info = json.loads(result.stdout)
            issues = []

            # Check if running as root
            security_options = info.get("SecurityOptions", [])
            if "name=userns" not in str(security_options):
                issues.append({
                    "severity": "HIGH",
                    "issue": "User namespace remapping not enabled",
                    "description": "Docker daemon should use userns-remap for additional isolation"
                })

            # Check live restore
            if not info.get("LiveRestoreEnabled", False):
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Live restore not enabled",
                    "description": "Containers will stop when daemon stops"
                })

            # Check logging driver
            logging_driver = info.get("LoggingDriver", "")
            if logging_driver == "none":
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Logging disabled",
                    "description": "Container logs are not being captured"
                })

            # Check storage driver
            storage_driver = info.get("Driver", "")
            if storage_driver not in ["overlay2", "zfs", "btrfs"]:
                issues.append({
                    "severity": "LOW",
                    "issue": f"Suboptimal storage driver: {storage_driver}",
                    "description": "Consider using overlay2 for better performance"
                })

            # Check for experimental features
            if info.get("ExperimentalBuild", False):
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Experimental features enabled",
                    "description": "Experimental features may have security issues"
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
                    "Docker Daemon Configuration Audit",
                    json.dumps({"issues": issues, "config": info}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="check_docker_config",
                details={"issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "issues": issues,
                "total_issues": len(issues),
                "docker_info": info,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_containers(self, project_id: str = None) -> Dict[str, Any]:
        """List running containers with security-relevant information.

        Args:
            project_id: Project ID

        Returns:
            Dict with container list
        """
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to list containers: {result.stderr}"
                }

            containers = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    containers.append(json.loads(line))

            # Get detailed info for each container
            detailed_containers = []
            for container in containers:
                container_id = container.get("ID")
                inspect_result = subprocess.run(
                    ["docker", "inspect", container_id],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if inspect_result.returncode == 0:
                    inspect_data = json.loads(inspect_result.stdout)[0]
                    host_config = inspect_data.get("HostConfig", {})

                    detailed_containers.append({
                        "id": container_id,
                        "name": container.get("Names"),
                        "image": container.get("Image"),
                        "status": container.get("Status"),
                        "privileged": host_config.get("Privileged", False),
                        "capabilities": host_config.get("CapAdd", []),
                        "network_mode": host_config.get("NetworkMode", ""),
                        "pid_mode": host_config.get("PidMode", ""),
                        "ipc_mode": host_config.get("IpcMode", ""),
                        "volumes": len(inspect_data.get("Mounts", [])),
                        "user": inspect_data.get("Config", {}).get("User", "root")
                    })

            await self.db.audit(
                action="list_containers",
                details={"container_count": len(detailed_containers)},
                project_id=project_id
            )

            return {
                "success": True,
                "containers": detailed_containers,
                "total_containers": len(detailed_containers)
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_container_escape(
        self,
        container_id: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check for container escape vectors.

        Args:
            container_id: Container ID
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with escape vector analysis
        """
        from core.database import generate_id, utc_now

        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to inspect container: {result.stderr}"
                }

            inspect_data = json.loads(result.stdout)[0]
            host_config = inspect_data.get("HostConfig", {})

            escape_vectors = []

            # Check privileged mode
            if host_config.get("Privileged", False):
                escape_vectors.append({
                    "severity": "CRITICAL",
                    "vector": "Privileged Mode",
                    "description": "Container running in privileged mode has full host access"
                })

            # Check for dangerous mounts
            mounts = inspect_data.get("Mounts", [])
            dangerous_paths = ["/var/run/docker.sock", "/proc", "/sys", "/dev", "/"]
            for mount in mounts:
                source = mount.get("Source", "")
                if any(source.startswith(path) for path in dangerous_paths):
                    escape_vectors.append({
                        "severity": "CRITICAL",
                        "vector": f"Dangerous Mount: {source}",
                        "description": f"Mounting {source} allows container escape"
                    })

            # Check capabilities
            cap_add = host_config.get("CapAdd", [])
            dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"]
            for cap in cap_add:
                if cap in dangerous_caps:
                    escape_vectors.append({
                        "severity": "CRITICAL",
                        "vector": f"Dangerous Capability: {cap}",
                        "description": f"Capability {cap} can be used for container escape"
                    })

            # Check PID namespace
            if host_config.get("PidMode") == "host":
                escape_vectors.append({
                    "severity": "HIGH",
                    "vector": "Host PID Namespace",
                    "description": "Container shares host PID namespace"
                })

            # Check network namespace
            if host_config.get("NetworkMode") == "host":
                escape_vectors.append({
                    "severity": "HIGH",
                    "vector": "Host Network Namespace",
                    "description": "Container shares host network namespace"
                })

            # Check IPC namespace
            if host_config.get("IpcMode") == "host":
                escape_vectors.append({
                    "severity": "HIGH",
                    "vector": "Host IPC Namespace",
                    "description": "Container shares host IPC namespace"
                })

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    "CRITICAL" if escape_vectors else "INFO",
                    f"Container Escape Vector Analysis: {container_id}",
                    json.dumps({"escape_vectors": escape_vectors}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="check_container_escape",
                details={"container_id": container_id, "vectors_found": len(escape_vectors)},
                project_id=project_id
            )

            return {
                "success": True,
                "container_id": container_id,
                "escape_vectors": escape_vectors,
                "total_vectors": len(escape_vectors),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_dockerfile(
        self,
        dockerfile_path: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Static analysis of Dockerfile for security issues.

        Args:
            dockerfile_path: Path to Dockerfile
            project_id: Project ID

        Returns:
            Dict with analysis results
        """
        from core.database import generate_id, utc_now
        import re

        try:
            with open(dockerfile_path, "r") as f:
                content = f.read()

            issues = []
            lines = content.split("\n")

            # Check for running as root
            user_instructions = [line for line in lines if line.strip().startswith("USER")]
            if not user_instructions or "USER root" in content:
                issues.append({
                    "severity": "HIGH",
                    "issue": "Running as root user",
                    "description": "Dockerfile does not set a non-root USER"
                })

            # Check for secrets in COPY/ADD
            secret_patterns = ["password", "secret", "token", "key", ".env", "credentials"]
            for i, line in enumerate(lines, 1):
                if line.strip().startswith(("COPY", "ADD")):
                    if any(pattern in line.lower() for pattern in secret_patterns):
                        issues.append({
                            "severity": "HIGH",
                            "issue": f"Potential secret in COPY/ADD (line {i})",
                            "description": f"Line may copy sensitive files: {line.strip()}"
                        })

            # Check for ADD from URLs
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("ADD") and ("http://" in line or "https://" in line):
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"ADD from URL (line {i})",
                        "description": "ADD from URLs can introduce security risks, use COPY instead"
                    })

            # Check for latest tag
            from_instructions = [line for line in lines if line.strip().startswith("FROM")]
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("FROM") and ":latest" in line:
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"Using :latest tag (line {i})",
                        "description": "Pin specific versions instead of :latest"
                    })

            # Check for HEALTHCHECK
            if not any(line.strip().startswith("HEALTHCHECK") for line in lines):
                issues.append({
                    "severity": "LOW",
                    "issue": "No HEALTHCHECK instruction",
                    "description": "Dockerfile lacks health check configuration"
                })

            # Check for exposed sensitive ports
            sensitive_ports = ["22", "23", "3389", "5900"]
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("EXPOSE"):
                    ports = re.findall(r'\d+', line)
                    for port in ports:
                        if port in sensitive_ports:
                            issues.append({
                                "severity": "MEDIUM",
                                "issue": f"Sensitive port exposed (line {i})",
                                "description": f"Port {port} is a management/remote access port"
                            })

            # Check for hardcoded secrets in ENV
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("ENV"):
                    secret_keywords = ["PASSWORD", "SECRET", "TOKEN", "KEY", "API"]
                    if any(keyword in line.upper() for keyword in secret_keywords):
                        if "=" in line:
                            issues.append({
                                "severity": "HIGH",
                                "issue": f"Hardcoded secret in ENV (line {i})",
                                "description": f"Environment variable may contain hardcoded secret: {line.strip()}"
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
                    f"Dockerfile Security Scan: {dockerfile_path}",
                    json.dumps({"issues": issues, "file": dockerfile_path}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_dockerfile",
                details={"file": dockerfile_path, "issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "file": dockerfile_path,
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except FileNotFoundError:
            return {"success": False, "error": f"Dockerfile not found: {dockerfile_path}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def audit_kubernetes_rbac(
        self,
        kubeconfig: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Audit Kubernetes RBAC configuration.

        Args:
            kubeconfig: Path to kubeconfig file
            project_id: Project ID

        Returns:
            Dict with RBAC audit results
        """
        from core.database import generate_id, utc_now

        try:
            env = {"KUBECONFIG": kubeconfig}
            issues = []

            # Check for cluster-admin bindings
            result = subprocess.run(
                ["kubectl", "get", "clusterrolebindings", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode == 0:
                bindings = json.loads(result.stdout)
                for binding in bindings.get("items", []):
                    role_ref = binding.get("roleRef", {})
                    if role_ref.get("name") == "cluster-admin":
                        subjects = binding.get("subjects", [])
                        for subject in subjects:
                            issues.append({
                                "severity": "HIGH",
                                "issue": f"cluster-admin binding to {subject.get('kind')}: {subject.get('name')}",
                                "description": "Excessive permissions granted via cluster-admin role"
                            })

            # Check for wildcard permissions
            result = subprocess.run(
                ["kubectl", "get", "clusterroles", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode == 0:
                roles = json.loads(result.stdout)
                for role in roles.get("items", []):
                    role_name = role.get("metadata", {}).get("name")
                    rules = role.get("rules", [])
                    for rule in rules:
                        resources = rule.get("resources", [])
                        verbs = rule.get("verbs", [])
                        if "*" in resources or "*" in verbs:
                            issues.append({
                                "severity": "HIGH",
                                "issue": f"Wildcard permissions in role: {role_name}",
                                "description": f"Role has wildcard (*) in resources or verbs"
                            })

            # Check default service account usage
            result = subprocess.run(
                ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode == 0:
                pods = json.loads(result.stdout)
                default_sa_count = 0
                for pod in pods.get("items", []):
                    sa = pod.get("spec", {}).get("serviceAccountName", "")
                    if sa == "default":
                        default_sa_count += 1

                if default_sa_count > 0:
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"{default_sa_count} pods using default service account",
                        "description": "Pods should use dedicated service accounts"
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
                    "Kubernetes RBAC Audit",
                    json.dumps({"issues": issues}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="audit_kubernetes_rbac",
                details={"issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_pod_security(
        self,
        kubeconfig: str,
        namespace: str = "default",
        project_id: str = None
    ) -> Dict[str, Any]:
        """Check Kubernetes pod security configuration.

        Args:
            kubeconfig: Path to kubeconfig file
            namespace: Kubernetes namespace
            project_id: Project ID

        Returns:
            Dict with pod security analysis
        """
        from core.database import generate_id, utc_now

        try:
            env = {"KUBECONFIG": kubeconfig}
            issues = []

            result = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to get pods: {result.stderr}"
                }

            pods = json.loads(result.stdout)

            for pod in pods.get("items", []):
                pod_name = pod.get("metadata", {}).get("name")
                spec = pod.get("spec", {})

                # Check for privileged containers
                for container in spec.get("containers", []):
                    security_context = container.get("securityContext", {})
                    if security_context.get("privileged", False):
                        issues.append({
                            "severity": "CRITICAL",
                            "issue": f"Privileged container in pod {pod_name}",
                            "description": f"Container {container.get('name')} runs in privileged mode"
                        })

                    # Check for running as root
                    if not security_context.get("runAsNonRoot", False):
                        issues.append({
                            "severity": "HIGH",
                            "issue": f"Container may run as root in pod {pod_name}",
                            "description": f"Container {container.get('name')} lacks runAsNonRoot"
                        })

                    # Check for capabilities
                    caps = security_context.get("capabilities", {}).get("add", [])
                    dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
                    for cap in caps:
                        if cap in dangerous_caps:
                            issues.append({
                                "severity": "HIGH",
                                "issue": f"Dangerous capability in pod {pod_name}",
                                "description": f"Container {container.get('name')} has {cap}"
                            })

                # Check host network/PID/IPC
                if spec.get("hostNetwork", False):
                    issues.append({
                        "severity": "HIGH",
                        "issue": f"Host network in pod {pod_name}",
                        "description": "Pod uses host network namespace"
                    })

                if spec.get("hostPID", False):
                    issues.append({
                        "severity": "HIGH",
                        "issue": f"Host PID in pod {pod_name}",
                        "description": "Pod uses host PID namespace"
                    })

                if spec.get("hostIPC", False):
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"Host IPC in pod {pod_name}",
                        "description": "Pod uses host IPC namespace"
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
                    f"Pod Security Check: {namespace}",
                    json.dumps({"issues": issues, "namespace": namespace}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="check_pod_security",
                details={"namespace": namespace, "issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "namespace": namespace,
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_k8s_secrets(
        self,
        kubeconfig: str,
        namespace: str = "default",
        project_id: str = None
    ) -> Dict[str, Any]:
        """Scan Kubernetes secrets for security issues.

        Args:
            kubeconfig: Path to kubeconfig file
            namespace: Kubernetes namespace
            project_id: Project ID

        Returns:
            Dict with secrets analysis
        """
        from core.database import generate_id, utc_now
        import base64

        try:
            env = {"KUBECONFIG": kubeconfig}
            issues = []

            result = subprocess.run(
                ["kubectl", "get", "secrets", "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to get secrets: {result.stderr}"
                }

            secrets_data = json.loads(result.stdout)
            secrets = []

            for secret in secrets_data.get("items", []):
                secret_name = secret.get("metadata", {}).get("name")
                secret_type = secret.get("type")
                data = secret.get("data", {})

                # Check for default service account tokens
                if secret_type == "kubernetes.io/service-account-token" and "default" in secret_name:
                    issues.append({
                        "severity": "LOW",
                        "issue": f"Default service account token: {secret_name}",
                        "description": "Consider using dedicated service accounts"
                    })

                secrets.append({
                    "name": secret_name,
                    "type": secret_type,
                    "key_count": len(data.keys()),
                    "keys": list(data.keys())
                })

            # Check for automountServiceAccountToken
            result = subprocess.run(
                ["kubectl", "get", "pods", "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode == 0:
                pods = json.loads(result.stdout)
                auto_mount_count = 0
                for pod in pods.get("items", []):
                    if pod.get("spec", {}).get("automountServiceAccountToken", True):
                        auto_mount_count += 1

                if auto_mount_count > 0:
                    issues.append({
                        "severity": "MEDIUM",
                        "issue": f"{auto_mount_count} pods with auto-mounted tokens",
                        "description": "Consider disabling automountServiceAccountToken when not needed"
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
                    f"Kubernetes Secrets Scan: {namespace}",
                    json.dumps({"issues": issues, "secrets": secrets}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_k8s_secrets",
                details={"namespace": namespace, "secret_count": len(secrets)},
                project_id=project_id
            )

            return {
                "success": True,
                "namespace": namespace,
                "secrets": secrets,
                "issues": issues,
                "total_secrets": len(secrets),
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_network_policies(
        self,
        kubeconfig: str,
        namespace: str = "default",
        project_id: str = None
    ) -> Dict[str, Any]:
        """Check Kubernetes network policies.

        Args:
            kubeconfig: Path to kubeconfig file
            namespace: Kubernetes namespace
            project_id: Project ID

        Returns:
            Dict with network policy analysis
        """
        from core.database import generate_id, utc_now

        try:
            env = {"KUBECONFIG": kubeconfig}
            issues = []

            result = subprocess.run(
                ["kubectl", "get", "networkpolicies", "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to get network policies: {result.stderr}"
                }

            policies_data = json.loads(result.stdout)
            policies = policies_data.get("items", [])

            if not policies:
                issues.append({
                    "severity": "HIGH",
                    "issue": f"No network policies in namespace {namespace}",
                    "description": "Namespace lacks network segmentation controls"
                })
            else:
                for policy in policies:
                    policy_name = policy.get("metadata", {}).get("name")
                    spec = policy.get("spec", {})

                    # Check for overly permissive ingress
                    ingress = spec.get("ingress", [])
                    for rule in ingress:
                        if not rule.get("from"):
                            issues.append({
                                "severity": "MEDIUM",
                                "issue": f"Permissive ingress in policy {policy_name}",
                                "description": "Ingress rule allows traffic from all sources"
                            })

                    # Check for overly permissive egress
                    egress = spec.get("egress", [])
                    for rule in egress:
                        if not rule.get("to"):
                            issues.append({
                                "severity": "MEDIUM",
                                "issue": f"Permissive egress in policy {policy_name}",
                                "description": "Egress rule allows traffic to all destinations"
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
                    f"Network Policy Check: {namespace}",
                    json.dumps({"issues": issues, "policy_count": len(policies)}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="check_network_policies",
                details={"namespace": namespace, "policies_found": len(policies)},
                project_id=project_id
            )

            return {
                "success": True,
                "namespace": namespace,
                "policies": len(policies),
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def scan_container_registry(
        self,
        registry_url: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Scan container registry for security issues.

        Args:
            registry_url: Container registry URL
            project_id: Project ID

        Returns:
            Dict with registry scan results
        """
        from core.database import generate_id, utc_now
        import httpx

        try:
            issues = []

            # Check for anonymous access
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    response = await client.get(f"{registry_url}/v2/_catalog")
                    if response.status_code == 200:
                        issues.append({
                            "severity": "CRITICAL",
                            "issue": "Anonymous access enabled",
                            "description": "Registry allows unauthenticated catalog access"
                        })

                        catalog = response.json()
                        repositories = catalog.get("repositories", [])

                        # Check each repository for tags
                        for repo in repositories[:10]:  # Limit to first 10 repos
                            tags_response = await client.get(f"{registry_url}/v2/{repo}/tags/list")
                            if tags_response.status_code == 200:
                                tags_data = tags_response.json()
                                tags = tags_data.get("tags", [])

                                if "latest" in tags:
                                    issues.append({
                                        "severity": "LOW",
                                        "issue": f"'latest' tag in use: {repo}",
                                        "description": "Repository uses mutable 'latest' tag"
                                    })

                                # Check for old/untagged images
                                if len(tags) > 20:
                                    issues.append({
                                        "severity": "LOW",
                                        "issue": f"Many tags in repository: {repo} ({len(tags)} tags)",
                                        "description": "Consider cleaning up old images"
                                    })

                except httpx.HTTPError:
                    pass  # Registry requires authentication (good)

            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, severity, title, description, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    "INFO",
                    f"Container Registry Scan: {registry_url}",
                    json.dumps({"issues": issues, "registry": registry_url}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="scan_container_registry",
                details={"registry": registry_url, "issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "registry": registry_url,
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_runtime_security(
        self,
        container_id: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check container runtime security configuration.

        Args:
            container_id: Container ID
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with runtime security analysis
        """
        from core.database import generate_id, utc_now

        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to inspect container: {result.stderr}"
                }

            inspect_data = json.loads(result.stdout)[0]
            host_config = inspect_data.get("HostConfig", {})

            issues = []

            # Check capabilities
            cap_drop = host_config.get("CapDrop", [])
            if "ALL" not in cap_drop:
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Capabilities not dropped",
                    "description": "Container should drop all capabilities and add back only needed ones"
                })

            # Check seccomp profile
            security_opt = host_config.get("SecurityOpt", [])
            has_seccomp = any("seccomp" in opt for opt in security_opt)
            if not has_seccomp or "seccomp=unconfined" in str(security_opt):
                issues.append({
                    "severity": "HIGH",
                    "issue": "No seccomp profile or unconfined",
                    "description": "Container lacks syscall filtering"
                })

            # Check read-only root filesystem
            if not host_config.get("ReadonlyRootfs", False):
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "Root filesystem not read-only",
                    "description": "Container should use read-only root filesystem"
                })

            # Check resource limits
            memory = host_config.get("Memory", 0)
            if memory == 0:
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "No memory limit set",
                    "description": "Container lacks memory resource limit"
                })

            cpu_quota = host_config.get("CpuQuota", 0)
            if cpu_quota == 0:
                issues.append({
                    "severity": "LOW",
                    "issue": "No CPU limit set",
                    "description": "Container lacks CPU resource limit"
                })

            # Check for no-new-privileges
            has_no_new_privs = any("no-new-privileges" in opt for opt in security_opt)
            if not has_no_new_privs:
                issues.append({
                    "severity": "MEDIUM",
                    "issue": "no-new-privileges not set",
                    "description": "Container can gain additional privileges"
                })

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
                    f"Runtime Security Check: {container_id}",
                    json.dumps({"issues": issues}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="check_runtime_security",
                details={"container_id": container_id, "issues_found": len(issues)},
                project_id=project_id
            )

            return {
                "success": True,
                "container_id": container_id,
                "issues": issues,
                "total_issues": len(issues),
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def container_security_assessment(
        self,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Run comprehensive container security assessment.

        Args:
            project_id: Project ID

        Returns:
            Dict with complete assessment results
        """
        from core.database import generate_id, utc_now

        try:
            results = {
                "docker_config": None,
                "containers": [],
                "overall_issues": []
            }

            # Check Docker configuration
            config_result = await self.check_docker_config(project_id=project_id)
            if config_result["success"]:
                results["docker_config"] = config_result
                results["overall_issues"].extend(config_result.get("issues", []))

            # List and check all containers
            list_result = await self.list_containers(project_id=project_id)
            if list_result["success"]:
                for container in list_result.get("containers", []):
                    container_id = container["id"]

                    # Check escape vectors
                    escape_result = await self.check_container_escape(
                        container_id=container_id,
                        project_id=project_id
                    )

                    # Check runtime security
                    runtime_result = await self.check_runtime_security(
                        container_id=container_id,
                        project_id=project_id
                    )

                    results["containers"].append({
                        "id": container_id,
                        "name": container["name"],
                        "escape_vectors": escape_result.get("escape_vectors", []),
                        "runtime_issues": runtime_result.get("issues", [])
                    })

                    results["overall_issues"].extend(escape_result.get("escape_vectors", []))
                    results["overall_issues"].extend(runtime_result.get("issues", []))

            # Generate summary
            critical = len([i for i in results["overall_issues"] if i.get("severity") == "CRITICAL"])
            high = len([i for i in results["overall_issues"] if i.get("severity") == "HIGH"])
            medium = len([i for i in results["overall_issues"] if i.get("severity") == "MEDIUM"])
            low = len([i for i in results["overall_issues"] if i.get("severity") == "LOW"])

            summary = {
                "total_issues": len(results["overall_issues"]),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "containers_checked": len(results["containers"])
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
                    "Container Security Assessment",
                    json.dumps({"summary": summary, "results": results}),
                    utc_now()
                )
            )

            await self.db.audit(
                action="container_security_assessment",
                details={"summary": summary},
                project_id=project_id
            )

            return {
                "success": True,
                "summary": summary,
                "results": results,
                "finding_id": finding_id
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
