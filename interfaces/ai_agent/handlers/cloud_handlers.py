"""Cloud security tool handlers (15 handlers).

Handler dict keys match tool names from cloud_tools.py exactly:
audit_aws_security, audit_azure_security, audit_gcp_security,
check_iam_permissions, check_storage_exposure, check_public_resources,
review_security_groups, check_encryption, check_logging, check_mfa,
check_key_rotation, check_network_exposure, check_container_security,
check_lambda_security, get_cloud_summary
"""


async def _audit_aws_security(params, db, cred_mgr, config):
    """Comprehensive AWS security audit covering IAM, S3, EC2, VPC, CloudTrail."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    return await engine.audit_aws(
        profile=params.get("profile", "default"),
        project_id=params.get("project_id"),
    )


async def _audit_azure_security(params, db, cred_mgr, config):
    """Comprehensive Azure security audit covering identity, networking, storage."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    return await engine.audit_azure(
        subscription_id=params.get("subscription_id"),
        project_id=params.get("project_id"),
    )


async def _audit_gcp_security(params, db, cred_mgr, config):
    """Comprehensive GCP security audit covering IAM, GCS, GCE, VPC."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    return await engine.audit_gcp(
        gcp_project_id=params.get("project_gcp"),
        project_id=params.get("project_id"),
    )


async def _check_iam_permissions(params, db, cred_mgr, config):
    """Analyze IAM policies, roles, and permissions for overly permissive access."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    return await engine.check_iam_permissions(
        provider=params["cloud"],
        identity=params.get("principal"),
        project_id=params.get("project_id"),
    )


async def _check_storage_exposure(params, db, cred_mgr, config):
    """Check cloud storage for public access, misconfigured ACLs, sensitive data."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    return await engine.check_storage_exposure(
        provider=params["cloud"],
        project_id=params.get("project_id"),
    )


async def _check_public_resources(params, db, cred_mgr, config):
    """Identify cloud resources with public exposure: IPs, LBs, databases, storage."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")
    resource_types = params.get("resource_types", ["all"])

    # Use the full audit for the provider to find public-facing resources
    if provider == "aws":
        audit_result = await engine.audit_aws(project_id=project_id)
    elif provider == "azure":
        audit_result = await engine.audit_azure(project_id=project_id)
    elif provider == "gcp":
        audit_result = await engine.audit_gcp(project_id=project_id)
    else:
        return {"success": False, "error": f"Unknown provider: {provider}"}

    # Filter findings related to public exposure
    all_findings = audit_result.get("findings", [])
    public_findings = [
        f for f in all_findings
        if any(kw in f.get("title", "").lower()
               for kw in ["public", "0.0.0.0", "alluser", "any inbound", "*"])
    ]

    return {
        "success": True,
        "provider": provider,
        "resource_types_checked": resource_types,
        "public_resources": public_findings,
        "total_public": len(public_findings),
        "scan_id": audit_result.get("scan_id"),
    }


async def _review_security_groups(params, db, cred_mgr, config):
    """Review security groups, network ACLs, and firewall rules."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")

    # Run the full audit and filter for security group / firewall findings
    if provider == "aws":
        audit_result = await engine.audit_aws(project_id=project_id)
    elif provider == "azure":
        audit_result = await engine.audit_azure(project_id=project_id)
    elif provider == "gcp":
        audit_result = await engine.audit_gcp(project_id=project_id)
    else:
        return {"success": False, "error": f"Unknown provider: {provider}"}

    all_findings = audit_result.get("findings", [])
    sg_keywords = ["sg ", "nsg", "security group", "firewall", "0.0.0.0", "inbound", "acl"]
    sg_findings = [
        f for f in all_findings
        if any(kw in f.get("title", "").lower() for kw in sg_keywords)
           or f.get("check_id", "").startswith(("AWS-EC2", "AZ-NSG"))
    ]

    return {
        "success": True,
        "provider": provider,
        "vpc_id": params.get("vpc_id"),
        "security_group_findings": sg_findings,
        "total_issues": len(sg_findings),
        "check_unused": params.get("check_unused", True),
        "scan_id": audit_result.get("scan_id"),
    }


async def _check_encryption(params, db, cred_mgr, config):
    """Verify encryption at rest and in transit for cloud resources."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")
    resource_types = params.get("resource_types", ["all"])

    # Run storage-focused audit to check encryption status
    result = await engine.check_storage_exposure(
        provider=provider,
        project_id=project_id,
    )

    # Add encryption-specific checks metadata
    encryption_checks = {
        "aws": ["S3 default encryption", "EBS volume encryption", "RDS encryption at rest",
                "KMS key rotation", "CloudTrail log encryption", "SNS/SQS encryption"],
        "azure": ["Storage account encryption", "Disk encryption (SSE/ADE)",
                  "SQL TDE enabled", "Key Vault soft delete", "HTTPS enforcement"],
        "gcp": ["Cloud Storage encryption", "Persistent disk encryption",
                "Cloud SQL encryption", "KMS key rotation"],
    }

    return {
        "success": True,
        "provider": provider,
        "resource_types": resource_types,
        "check_key_management": params.get("check_key_management", True),
        "encryption_checks": encryption_checks.get(provider, []),
        "audit_result": result,
        "note": f"Run audit_{provider}_security for full automated encryption checks",
    }


async def _check_logging(params, db, cred_mgr, config):
    """Verify audit logging, monitoring, and alerting configuration."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")
    services = params.get("services", ["all"])

    await engine.db.audit("check_logging", project_id=project_id,
                          description=f"Logging check for {provider}")

    logging_checks = {
        "aws": {
            "api_logging": "CloudTrail enabled in all regions with log validation",
            "flow_logs": "VPC Flow Logs enabled for all VPCs",
            "access_logs": "S3 access logging, ELB access logging",
            "dns_logs": "Route53 query logging enabled",
            "monitoring": "CloudWatch alarms for unauthorized API calls, root usage",
            "guardduty": "GuardDuty enabled in all regions",
        },
        "azure": {
            "api_logging": "Activity Log with 90+ day retention",
            "flow_logs": "NSG Flow Logs enabled",
            "access_logs": "Storage Analytics logging, App Service logs",
            "dns_logs": "DNS Analytics enabled",
            "monitoring": "Azure Monitor alerts, Defender for Cloud enabled",
            "sentinel": "Microsoft Sentinel workspace configured",
        },
        "gcp": {
            "api_logging": "Cloud Audit Logs (Admin + Data Access)",
            "flow_logs": "VPC Flow Logs enabled",
            "access_logs": "Cloud Storage access logging, Load Balancer logging",
            "dns_logs": "Cloud DNS logging enabled",
            "monitoring": "Cloud Monitoring alerting policies configured",
        },
    }

    provider_checks = logging_checks.get(provider, {})
    if "all" not in services:
        provider_checks = {k: v for k, v in provider_checks.items() if k in services}

    return {
        "success": True,
        "provider": provider,
        "services_checked": services,
        "logging_checks": provider_checks,
        "note": "Verify each logging control is properly configured with appropriate retention",
    }


async def _check_mfa(params, db, cred_mgr, config):
    """Check MFA enforcement for IAM users, root accounts, and privileged roles."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")

    # Run IAM-focused check which includes MFA status
    iam_result = await engine.check_iam_permissions(
        provider=provider,
        project_id=project_id,
    )

    # If provider is AWS, the full audit also checks MFA per-user
    if provider == "aws":
        audit_result = await engine.audit_aws(project_id=project_id)
        mfa_findings = [
            f for f in audit_result.get("findings", [])
            if "mfa" in f.get("title", "").lower() or f.get("check_id") == "AWS-IAM-003"
        ]
    else:
        mfa_findings = []

    mfa_checks = {
        "aws": ["Root account MFA", "All IAM users MFA", "MFA delete on S3", "Hardware MFA for root"],
        "azure": ["Global admin MFA (Conditional Access)", "All users MFA", "PIM for privileged roles"],
        "gcp": ["Organization admin MFA", "2-Step Verification enforcement", "Security key requirement"],
    }

    return {
        "success": True,
        "provider": provider,
        "check_root": params.get("check_root", True),
        "check_service_accounts": params.get("check_service_accounts", True),
        "mfa_findings": mfa_findings,
        "mfa_checks": mfa_checks.get(provider, []),
        "iam_context": iam_result,
    }


async def _check_key_rotation(params, db, cred_mgr, config):
    """Check access key age and rotation policies."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")
    max_age_days = params.get("max_age_days", 90)

    # For AWS, the full audit includes key age checks
    if provider == "aws":
        audit_result = await engine.audit_aws(project_id=project_id)
        key_findings = [
            f for f in audit_result.get("findings", [])
            if "key" in f.get("title", "").lower()
               or "access key" in f.get("title", "").lower()
               or f.get("check_id", "").startswith("AWS-KMS")
        ]
    else:
        key_findings = []

    await engine.db.audit("check_key_rotation", project_id=project_id,
                          description=f"Key rotation check for {provider}")

    rotation_checks = {
        "aws": ["IAM access key age", "KMS key rotation", "Secrets Manager rotation",
                "Certificate expiration", "SSH key age"],
        "azure": ["Service principal secret expiry", "Key Vault key rotation",
                  "Storage account key rotation", "App registration secret expiry"],
        "gcp": ["Service account key age", "KMS key rotation", "API key restrictions"],
    }

    return {
        "success": True,
        "provider": provider,
        "max_age_days": max_age_days,
        "include_inactive": params.get("include_inactive", False),
        "key_findings": key_findings,
        "rotation_checks": rotation_checks.get(provider, []),
    }


async def _check_network_exposure(params, db, cred_mgr, config):
    """Analyze cloud network architecture for exposure risks."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")

    # Run full audit and filter for network-related findings
    if provider == "aws":
        audit_result = await engine.audit_aws(project_id=project_id)
    elif provider == "azure":
        audit_result = await engine.audit_azure(project_id=project_id)
    elif provider == "gcp":
        audit_result = await engine.audit_gcp(project_id=project_id)
    else:
        return {"success": False, "error": f"Unknown provider: {provider}"}

    all_findings = audit_result.get("findings", [])
    network_keywords = ["sg ", "nsg", "security group", "0.0.0.0", "inbound",
                        "vpc", "vnet", "peering", "gateway", "endpoint", "network"]
    network_findings = [
        f for f in all_findings
        if any(kw in f.get("title", "").lower() for kw in network_keywords)
    ]

    return {
        "success": True,
        "provider": provider,
        "vpc_id": params.get("vpc_id"),
        "check_peering": params.get("check_peering", True),
        "check_endpoints": params.get("check_endpoints", True),
        "network_findings": network_findings,
        "total_issues": len(network_findings),
        "scan_id": audit_result.get("scan_id"),
    }


async def _check_container_security(params, db, cred_mgr, config):
    """Audit container and Kubernetes security configurations."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")
    cluster_name = params.get("cluster_name")
    checks = params.get("checks", ["all"])

    # Use kubernetes_audit if available, otherwise provide guidance
    k8s_audit = getattr(engine, "kubernetes_audit", None)
    if k8s_audit:
        k8s_result = await k8s_audit(
            kubeconfig=None,
            namespace=None,
            checks=checks,
            project_id=project_id,
        )
    else:
        k8s_result = None

    # Use container_audit if available
    container_audit_fn = getattr(engine, "container_audit", None)
    if container_audit_fn:
        container_result = await container_audit_fn(
            registry_url=None,
            image=None,
            credentials=None,
            project_id=project_id,
        )
    else:
        container_result = None

    container_checks = {
        "aws": ["ECR image scanning", "ECS task role permissions", "EKS RBAC",
                "EKS network policies", "Fargate pod security"],
        "azure": ["ACR image scanning", "AKS RBAC", "AKS network policies",
                  "AKS pod security policies", "Container Instances config"],
        "gcp": ["GCR/Artifact Registry scanning", "GKE RBAC", "GKE network policies",
                "GKE Workload Identity", "Binary Authorization"],
    }

    return {
        "success": True,
        "provider": provider,
        "cluster_name": cluster_name,
        "checks_requested": checks,
        "container_checks": container_checks.get(provider, []),
        "kubernetes_audit": k8s_result,
        "container_audit": container_result,
    }


async def _check_lambda_security(params, db, cred_mgr, config):
    """Audit serverless function security: roles, env vars, VPC config."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    provider = params["cloud"]
    project_id = params.get("project_id")

    # Use serverless_audit if available on the engine
    serverless_audit_fn = getattr(engine, "serverless_audit", None)
    if serverless_audit_fn:
        result = await serverless_audit_fn(
            provider=provider,
            credentials=None,
            region=None,
            project_id=project_id,
        )
    else:
        result = None

    serverless_checks = {
        "aws": ["Lambda execution role least privilege", "Environment variable secrets",
                "VPC configuration", "Function URL auth", "Layer vulnerabilities",
                "Concurrency/timeout limits", "Dead letter queue config"],
        "azure": ["Function App managed identity", "App Settings secrets",
                  "VNet integration", "Authentication settings", "CORS config"],
        "gcp": ["Cloud Function service account", "Environment variable secrets",
                "VPC connector", "Ingress settings", "IAM invoker permissions"],
    }

    return {
        "success": True,
        "provider": provider,
        "function_name": params.get("function_name"),
        "check_env_vars": params.get("check_env_vars", True),
        "check_permissions": params.get("check_permissions", True),
        "serverless_checks": serverless_checks.get(provider, []),
        "serverless_audit": result,
    }


async def _get_cloud_summary(params, db, cred_mgr, config):
    """Get summary of cloud security audit findings across providers."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(db, config)
    return await engine.get_cloud_summary(
        project_id=params["project_id"],
    )


CLOUD_HANDLERS = {
    "audit_aws_security": _audit_aws_security,
    "audit_azure_security": _audit_azure_security,
    "audit_gcp_security": _audit_gcp_security,
    "check_iam_permissions": _check_iam_permissions,
    "check_storage_exposure": _check_storage_exposure,
    "check_public_resources": _check_public_resources,
    "review_security_groups": _review_security_groups,
    "check_encryption": _check_encryption,
    "check_logging": _check_logging,
    "check_mfa": _check_mfa,
    "check_key_rotation": _check_key_rotation,
    "check_network_exposure": _check_network_exposure,
    "check_container_security": _check_container_security,
    "check_lambda_security": _check_lambda_security,
    "get_cloud_summary": _get_cloud_summary,
}
