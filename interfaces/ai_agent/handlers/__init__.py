"""Aggregates all handler dicts into TOOL_HANDLERS."""

from .recon_handlers import RECON_HANDLERS
from .webapp_handlers import WEBAPP_HANDLERS
from .vulnerability_handlers import VULNERABILITY_HANDLERS
from .exploit_handlers import EXPLOIT_HANDLERS
from .network_handlers import NETWORK_HANDLERS
from .password_handlers import PASSWORD_HANDLERS
from .cloud_handlers import CLOUD_HANDLERS
from .forensics_handlers import FORENSICS_HANDLERS
from .compliance_handlers import COMPLIANCE_HANDLERS
from .report_handlers import REPORT_HANDLERS
from .threat_intel_handlers import THREAT_INTEL_HANDLERS
from .target_handlers import TARGET_HANDLERS
from .playbook_handlers import PLAYBOOK_HANDLERS
from .ad_handlers import AD_HANDLERS
from .api_security_handlers import API_SECURITY_HANDLERS
from .automation_handlers import AUTOMATION_HANDLERS
from .wireless_handlers import WIRELESS_HANDLERS
from .container_handlers import CONTAINER_HANDLERS
from .osint_handlers import OSINT_HANDLERS
from .secrets_handlers import SECRETS_HANDLERS
from .email_security_handlers import EMAIL_SECURITY_HANDLERS
from .notification_handlers import NOTIFICATION_HANDLERS
from .social_engineering_handlers import SOCIAL_ENGINEERING_HANDLERS
from .vuln_chain_handlers import VULN_CHAIN_HANDLERS
from .evidence_handlers import EVIDENCE_HANDLERS
from .c2_handlers import C2_HANDLERS
from .mobile_handlers import MOBILE_HANDLERS

TOOL_HANDLERS = {
    **RECON_HANDLERS,
    **WEBAPP_HANDLERS,
    **VULNERABILITY_HANDLERS,
    **EXPLOIT_HANDLERS,
    **NETWORK_HANDLERS,
    **PASSWORD_HANDLERS,
    **CLOUD_HANDLERS,
    **FORENSICS_HANDLERS,
    **COMPLIANCE_HANDLERS,
    **REPORT_HANDLERS,
    **THREAT_INTEL_HANDLERS,
    **TARGET_HANDLERS,
    **PLAYBOOK_HANDLERS,
    **AD_HANDLERS,
    **API_SECURITY_HANDLERS,
    **AUTOMATION_HANDLERS,
    **WIRELESS_HANDLERS,
    **CONTAINER_HANDLERS,
    **OSINT_HANDLERS,
    **SECRETS_HANDLERS,
    **EMAIL_SECURITY_HANDLERS,
    **NOTIFICATION_HANDLERS,
    **SOCIAL_ENGINEERING_HANDLERS,
    **VULN_CHAIN_HANDLERS,
    **EVIDENCE_HANDLERS,
    **C2_HANDLERS,
    **MOBILE_HANDLERS,
}
