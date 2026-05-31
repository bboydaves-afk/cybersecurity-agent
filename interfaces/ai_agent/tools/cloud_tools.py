"""Cloud security auditing tool definitions (15 tools)."""

CLOUD_TOOLS = (
    {
        "name": "audit_aws_security",
        "description": "Run a comprehensive AWS security audit covering IAM, S3, EC2, VPC, CloudTrail, and security group configurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "profile": {"type": "string", "description": "AWS CLI profile name or 'default'"},
                "region": {"type": "string", "description": "AWS region to audit (e.g. 'us-east-1')"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Specific checks: 'iam', 's3', 'ec2', 'vpc', 'cloudtrail', 'rds', 'lambda', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["profile"],
        },
    },
    {
        "name": "audit_azure_security",
        "description": "Run a comprehensive Azure security audit covering identity, networking, storage, compute, and logging configurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "subscription_id": {"type": "string", "description": "Azure subscription ID"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Specific checks: 'identity', 'network', 'storage', 'compute', 'logging', 'keyvault', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["subscription_id"],
        },
    },
    {
        "name": "audit_gcp_security",
        "description": "Run a comprehensive GCP security audit covering IAM, GCS, GCE, VPC, and logging configurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_gcp": {"type": "string", "description": "GCP project ID"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Specific checks: 'iam', 'storage', 'compute', 'network', 'logging', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["project_gcp"],
        },
    },
    {
        "name": "check_iam_permissions",
        "description": "Analyze IAM policies, roles, and permissions for overly permissive access, privilege escalation paths, and policy violations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "principal": {"type": "string", "description": "IAM user, role, or service principal ARN/ID to analyze"},
                "check_escalation": {"type": "boolean", "description": "Check for privilege escalation paths", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud", "principal"],
        },
    },
    {
        "name": "check_storage_exposure",
        "description": "Check cloud storage buckets and blobs for public access, misconfigured ACLs, and sensitive data exposure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "bucket_name": {"type": "string", "description": "Specific bucket or container name (checks all if omitted)"},
                "check_contents": {"type": "boolean", "description": "Check for sensitive file patterns in bucket contents", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_public_resources",
        "description": "Identify cloud resources with public exposure: public IPs, load balancers, databases, and storage endpoints.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "resource_types": {"type": "array", "items": {"type": "string"}, "description": "Resource types to check: 'compute', 'database', 'storage', 'api', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "review_security_groups",
        "description": "Review security groups, network ACLs, and firewall rules for overly permissive inbound/outbound rules.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "vpc_id": {"type": "string", "description": "Specific VPC or VNet ID to review"},
                "check_unused": {"type": "boolean", "description": "Check for unused security groups", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_encryption",
        "description": "Verify encryption at rest and in transit for cloud resources including storage, databases, and messaging services.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "resource_types": {"type": "array", "items": {"type": "string"}, "description": "Resource types: 'storage', 'database', 'compute', 'messaging', 'all'"},
                "check_key_management": {"type": "boolean", "description": "Check KMS key configurations and rotation", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_logging",
        "description": "Verify that audit logging, monitoring, and alerting are properly configured for cloud resources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "services": {"type": "array", "items": {"type": "string"}, "description": "Services to check: 'api_logging', 'flow_logs', 'access_logs', 'dns_logs', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_mfa",
        "description": "Check MFA enforcement status for IAM users, root accounts, and privileged roles across cloud accounts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "check_root": {"type": "boolean", "description": "Check root/global admin MFA status", "default": True},
                "check_service_accounts": {"type": "boolean", "description": "Check service account MFA requirements", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_key_rotation",
        "description": "Check access key age and rotation policies for IAM users and service accounts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "max_age_days": {"type": "integer", "description": "Maximum acceptable key age in days", "default": 90},
                "include_inactive": {"type": "boolean", "description": "Include inactive keys in results", "default": False},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_network_exposure",
        "description": "Analyze cloud network architecture for exposure risks including peering, transit gateways, and internet gateways.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "vpc_id": {"type": "string", "description": "Specific VPC or VNet to analyze"},
                "check_peering": {"type": "boolean", "description": "Check VPC peering configurations", "default": True},
                "check_endpoints": {"type": "boolean", "description": "Check VPC endpoints and private links", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_container_security",
        "description": "Audit container and Kubernetes security configurations including image scanning, RBAC, network policies, and pod security.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "cluster_name": {"type": "string", "description": "Kubernetes cluster name or ID"},
                "checks": {"type": "array", "items": {"type": "string"}, "description": "Checks: 'images', 'rbac', 'network_policies', 'pod_security', 'secrets', 'all'"},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "check_lambda_security",
        "description": "Audit serverless function security: execution roles, environment variables, VPC config, timeout settings, and code vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "description": "Cloud provider"},
                "function_name": {"type": "string", "description": "Specific function name (checks all if omitted)"},
                "check_env_vars": {"type": "boolean", "description": "Check environment variables for secrets", "default": True},
                "check_permissions": {"type": "boolean", "description": "Check execution role permissions", "default": True},
                "project_id": {"type": "string", "description": "Project ID"},
            },
            "required": ["cloud"],
        },
    },
    {
        "name": "get_cloud_summary",
        "description": "Get a summary of cloud security audit findings including severity distribution, top risks, and compliance posture.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string", "description": "Project ID"},
                "cloud": {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "default": "all"},
            },
            "required": ["project_id"],
        },
    },
)
