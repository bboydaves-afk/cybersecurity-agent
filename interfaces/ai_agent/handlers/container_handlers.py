"""Container security handlers (12 handlers)."""


async def _scan_docker_image(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.scan_docker_image(
        params["image"],
        params.get("scanner", "trivy"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_docker_config(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.check_docker_config(
        params.get("host"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _list_containers(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.list_containers(
        params.get("host"),
        params.get("all", False),
        params.get("project_id")
    )


async def _check_container_escape(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.check_container_escape(
        params["container_id"],
        params.get("host"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_dockerfile(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.scan_dockerfile(
        params["dockerfile_path"],
        params.get("project_id"),
        params.get("target_id")
    )


async def _audit_kubernetes_rbac(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.audit_kubernetes_rbac(
        params.get("kubeconfig"),
        params.get("namespace"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_pod_security(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.check_pod_security(
        params.get("kubeconfig"),
        params.get("namespace"),
        params.get("pod_name"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_k8s_secrets(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.scan_k8s_secrets(
        params.get("kubeconfig"),
        params.get("namespace"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_network_policies(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.check_network_policies(
        params.get("kubeconfig"),
        params.get("namespace"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _scan_container_registry(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.scan_container_registry(
        params["registry_url"],
        params.get("credentials", {}),
        params.get("project_id"),
        params.get("target_id")
    )


async def _check_runtime_security(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.check_runtime_security(
        params.get("host"),
        params.get("container_id"),
        params.get("project_id"),
        params.get("target_id")
    )


async def _container_security_assessment(params, db, cred_mgr, config):
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(db, config)
    return await engine.container_security_assessment(
        params.get("host"),
        params.get("kubeconfig"),
        params.get("project_id"),
        params.get("target_id")
    )


CONTAINER_HANDLERS = {
    "scan_docker_image": _scan_docker_image,
    "check_docker_config": _check_docker_config,
    "list_containers": _list_containers,
    "check_container_escape": _check_container_escape,
    "scan_dockerfile": _scan_dockerfile,
    "audit_kubernetes_rbac": _audit_kubernetes_rbac,
    "check_pod_security": _check_pod_security,
    "scan_k8s_secrets": _scan_k8s_secrets,
    "check_network_policies": _check_network_policies,
    "scan_container_registry": _scan_container_registry,
    "check_runtime_security": _check_runtime_security,
    "container_security_assessment": _container_security_assessment,
}
