"""Container and Kubernetes security tool definitions (12 tools)."""

CONTAINER_TOOLS = (
    {
        "name": "scan_docker_image",
        "description": "Scan a Docker image for vulnerabilities, misconfigurations, and security issues using multiple scanners.",
        "input_schema": {
            "type": "object",
            "properties": {
                "image": {"type": "string", "description": "Docker image name and tag (e.g., nginx:latest)"},
                "scanner": {"type": "string", "description": "Scanner to use (trivy, clair, grype, all)", "default": "trivy"},
                "severity_threshold": {"type": "string", "description": "Minimum severity to report (low, medium, high, critical)", "default": "medium"},
                "include_unfixed": {"type": "boolean", "description": "Include vulnerabilities without fixes", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["image", "project_id"],
        },
    },
    {
        "name": "check_docker_config",
        "description": "Check Docker daemon and host configuration for security best practices and CIS Docker Benchmark compliance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Docker host to check (default: local)"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Specific checks to perform (all by default)"},
                "benchmark": {"type": "string", "description": "Security benchmark to use (cis, custom)", "default": "cis"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "list_containers",
        "description": "List running containers with security-relevant information including privileged status, network mode, and volume mounts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Docker host (default: local)"},
                "all": {"type": "boolean", "description": "Include stopped containers", "default": False},
                "filter": {"type": "object", "description": "Filter criteria (e.g., privileged, network mode)"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["project_id"],
        },
    },
    {
        "name": "check_container_escape",
        "description": "Check for container escape vulnerabilities and misconfigurations that could allow breakout to the host.",
        "input_schema": {
            "type": "object",
            "properties": {
                "container_id": {"type": "string", "description": "Container ID to check"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Escape vectors to check (privileged, capabilities, mounts, cgroups)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["container_id", "project_id", "target_id"],
        },
    },
    {
        "name": "scan_dockerfile",
        "description": "Scan a Dockerfile for security issues and best practice violations before building the image.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dockerfile_path": {"type": "string", "description": "Path to the Dockerfile"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Checks to perform (secrets, base_image, user, commands)"},
                "strict": {"type": "boolean", "description": "Fail on warnings", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["dockerfile_path", "project_id"],
        },
    },
    {
        "name": "audit_kubernetes_rbac",
        "description": "Audit Kubernetes RBAC (Role-Based Access Control) configurations for over-permissive roles and privilege escalation risks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kubeconfig": {"type": "string", "description": "Path to kubeconfig file"},
                "namespace": {"type": "string", "description": "Specific namespace to audit (all by default)"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "RBAC checks (cluster_admin, wildcard_permissions, privilege_escalation)"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["project_id", "target_id"],
        },
    },
    {
        "name": "check_pod_security",
        "description": "Check Kubernetes pod security configurations including security contexts, capabilities, and pod security standards compliance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kubeconfig": {"type": "string", "description": "Path to kubeconfig file"},
                "namespace": {"type": "string", "description": "Namespace to check (all by default)"},
                "pod_name": {"type": "string", "description": "Specific pod to check (optional)"},
                "security_standard": {"type": "string", "description": "Pod security standard (baseline, restricted)", "default": "baseline"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["project_id", "target_id"],
        },
    },
    {
        "name": "scan_k8s_secrets",
        "description": "Scan Kubernetes secrets for security issues including unencrypted secrets, exposed credentials, and improper storage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kubeconfig": {"type": "string", "description": "Path to kubeconfig file"},
                "namespace": {"type": "string", "description": "Namespace to scan (all by default)"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Secret checks (encryption, exposure, rotation)"},
                "decode_secrets": {"type": "boolean", "description": "Decode and analyze secret contents", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["project_id", "target_id"],
        },
    },
    {
        "name": "check_network_policies",
        "description": "Check Kubernetes network policies and identify pods without network segmentation or overly permissive rules.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kubeconfig": {"type": "string", "description": "Path to kubeconfig file"},
                "namespace": {"type": "string", "description": "Namespace to check (all by default)"},
                "visualize": {"type": "boolean", "description": "Generate network policy visualization", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["project_id", "target_id"],
        },
    },
    {
        "name": "scan_container_registry",
        "description": "Scan a container registry for vulnerable images, misconfigurations, and security issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "registry_url": {"type": "string", "description": "Container registry URL"},
                "credentials": {"type": "object", "description": "Registry authentication credentials"},
                "repository": {"type": "string", "description": "Specific repository to scan (all by default)"},
                "severity_threshold": {"type": "string", "description": "Minimum severity to report", "default": "medium"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["registry_url", "project_id", "target_id"],
        },
    },
    {
        "name": "check_runtime_security",
        "description": "Monitor container runtime security including process activity, file access, and network connections for anomalies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "container_id": {"type": "string", "description": "Container ID to monitor"},
                "duration": {"type": "integer", "description": "Monitoring duration in seconds", "default": 300},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Runtime checks (processes, files, network, syscalls)"},
                "baseline": {"type": "string", "description": "Path to baseline profile for comparison"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["container_id", "project_id", "target_id"],
        },
    },
    {
        "name": "container_security_assessment",
        "description": "Perform a comprehensive container and Kubernetes security assessment covering images, runtime, and orchestration.",
        "input_schema": {
            "type": "object",
            "properties": {
                "scope": {"type": "string", "description": "Assessment scope (docker, kubernetes, both)", "default": "both"},
                "kubeconfig": {"type": "string", "description": "Path to kubeconfig file (for Kubernetes)"},
                "docker_host": {"type": "string", "description": "Docker host (for Docker)"},
                "depth": {"type": "string", "description": "Assessment depth (quick, standard, deep)", "default": "standard"},
                "project_id": {"type": "string", "description": "Project ID"},
                "target_id": {"type": "string", "description": "Target ID"},
            },
            "required": ["project_id", "target_id"],
        },
    },
)
