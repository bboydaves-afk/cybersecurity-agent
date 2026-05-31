"""Safety classification and scope validation for CyberSecurity Agent."""

import logging
import re
from enum import Enum

logger = logging.getLogger("hacking_agent.safety")


class SafetyLevel(str, Enum):
    SAFE = "safe"
    WARNING = "warning"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


BLOCKED_PATTERNS = [
    re.compile(r"rm\s+-rf\s+/\s*$"),
    re.compile(r"mkfs\."),
    re.compile(r"dd\s+if=.*of=/dev/"),
    re.compile(r":()\{\s*:\|:&\s*\};:"),
    re.compile(r"chmod\s+-R\s+777\s+/"),
    re.compile(r">\s*/dev/sd[a-z]"),
]

DANGEROUS_TOOLS: set[str] = {
    # Exploit tools (ALL)
    "generate_payload", "execute_exploit", "start_listener",
    "interact_session", "close_session", "privilege_escalation_check",
    "lateral_movement", "establish_persistence",
    "extract_data", "run_post_module", "searchsploit",
    # Password tools (except identify and analyze)
    "crack_hash", "password_spray", "brute_force",
    "validate_credential", "generate_wordlist",
    "extract_hashes", "check_credential_reuse",
    # Active web tests
    "test_xss", "test_sqli", "test_csrf", "test_xxe", "test_ssrf",
    "test_idor", "test_open_redirect", "test_file_upload",
    "test_authentication", "test_rate_limiting",
    "directory_fuzz", "fuzz_api", "full_web_scan",
    # Active network tools
    "packet_capture", "arp_scan", "wireless_scan",
    "dns_zone_transfer", "snmp_enumerate", "netbios_scan",
    # Active recon (potentially noisy)
    "port_scan", "service_enumerate", "os_fingerprint",
    "vulnerability_scan", "network_sweep", "full_recon",
    "banner_grab",
    # Target mutations
    "add_target", "remove_target", "update_scope",
    # Finding mutations
    "create_finding", "update_finding",
    # Report deletion
    "delete_report",
    # Forensics (sensitive)
    "carve_files", "analyze_malware", "collect_artifacts",
    # Cloud audit (read-only but touches production)
    "audit_aws_security", "audit_azure_security", "audit_gcp_security",
    # --- NEW: Active Directory ---
    "enumerate_domain", "enumerate_ad_users", "enumerate_ad_groups",
    "enumerate_ad_computers", "check_kerberoastable", "check_asrep_roastable",
    "check_delegation", "enumerate_gpos", "check_trusts", "enumerate_shares",
    "ad_security_assessment",
    # --- NEW: API Security (active tests) ---
    "test_api_authentication", "test_api_authorization", "test_api_rate_limiting",
    "test_api_injection", "test_mass_assignment", "fuzz_api_parameters",
    "test_graphql", "test_http_methods", "test_input_validation",
    "scan_api_security",
    # --- NEW: Wireless (active scanning) ---
    "scan_wireless_networks", "check_wps", "deauth_detection",
    "capture_handshake", "check_wifi_isolation", "analyze_wifi_security",
    # --- NEW: Container (touches infrastructure) ---
    "check_container_escape", "audit_kubernetes_rbac", "check_pod_security",
    "scan_k8s_secrets", "container_security_assessment",
    # --- NEW: OSINT (data gathering) ---
    "harvest_emails_osint", "github_recon", "search_pastebin",
    # --- NEW: Secrets (sensitive data access) ---
    "scan_directory_secrets", "scan_git_secrets", "scan_file_secrets",
    "scan_env_files", "scan_config_files", "scan_docker_secrets",
    # --- NEW: Email Security (active testing) ---
    "check_mail_server", "test_smtp_auth", "check_email_spoofing",
    # --- NEW: Social Engineering (ALL) ---
    "create_phishing_campaign", "generate_phishing_template",
    "create_landing_page", "generate_pretext",
    # --- NEW: C2 (ALL) ---
    "connect_metasploit", "create_metasploit_listener", "list_c2_sessions",
    "c2_session_command", "generate_stager", "connect_sliver",
    # --- NEW: Mobile (decompilation/analysis) ---
    "decompile_apk", "check_data_storage",
    # --- NEW: Automation (scheduler control) ---
    "start_scheduler", "stop_scheduler", "schedule_scan",
    "remove_scheduled_job", "run_job_now",
    # --- NEW: Playbook execution ---
    "execute_playbook", "cancel_execution",
    # --- NEW: Evidence (data handling) ---
    "collect_evidence", "export_evidence_package",
    # --- NEW: Vulnerability chaining ---
    "simulate_attack",
    # --- NEW: Notifications (external comms) ---
    "send_notification", "notify_all_channels",
}

WARNING_TOOLS: set[str] = {
    "check_default_creds", "check_breach_data",
    "scan_virustotal", "crawl_site",
    # --- NEW ---
    "check_ad_password_policy", "discover_api_endpoints",
    "analyze_jwt", "test_cors_api", "detect_rogue_aps",
    "scan_docker_image", "check_docker_config", "list_containers",
    "search_breach_data", "social_media_recon", "document_metadata",
    "ip_reputation", "check_spf", "check_dkim", "check_dmarc",
    "analyze_email_headers", "analyze_phishing_email", "check_typosquatting",
    "analyze_apk", "analyze_ipa", "check_ssl_pinning",
    "check_app_permissions", "check_crypto_usage",
    "find_vuln_chains", "analyze_attack_paths",
    "notify_finding", "notify_scan_complete",
    "configure_notification_channel",
}


def check_safety(tool_name: str, params: dict | None = None) -> SafetyLevel:
    if params:
        for key, value in params.items():
            if isinstance(value, str):
                for pattern in BLOCKED_PATTERNS:
                    if pattern.search(value):
                        return SafetyLevel.BLOCKED

    if tool_name in DANGEROUS_TOOLS:
        return SafetyLevel.DANGEROUS

    if tool_name in WARNING_TOOLS:
        return SafetyLevel.WARNING

    return SafetyLevel.SAFE


def get_safety_message(level: SafetyLevel, tool_name: str,
                       params: dict | None = None) -> str:
    if level == SafetyLevel.BLOCKED:
        return f"BLOCKED: Tool '{tool_name}' contains a blocked command pattern. This operation is not permitted."
    elif level == SafetyLevel.DANGEROUS:
        return f"WARNING: Tool '{tool_name}' is classified as dangerous. Ensure you have proper authorization and the target is in-scope."
    elif level == SafetyLevel.WARNING:
        return f"CAUTION: Tool '{tool_name}' may have security implications. Proceed with awareness."
    return ""


async def check_scope(db, target_id: str) -> bool:
    if not target_id:
        return True
    target = await db.fetch_one(
        "SELECT in_scope FROM targets WHERE id=?", (target_id,))
    if not target:
        return False
    return bool(target.get("in_scope", 0))
