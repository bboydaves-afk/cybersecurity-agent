"""Aggregates all tool definitions into a single TOOLS tuple."""

from .recon_tools import RECON_TOOLS
from .webapp_tools import WEBAPP_TOOLS
from .vulnerability_tools import VULNERABILITY_TOOLS
from .exploit_tools import EXPLOIT_TOOLS
from .network_tools import NETWORK_TOOLS
from .password_tools import PASSWORD_TOOLS
from .cloud_tools import CLOUD_TOOLS
from .forensics_tools import FORENSICS_TOOLS
from .compliance_tools import COMPLIANCE_TOOLS
from .report_tools import REPORT_TOOLS
from .threat_intel_tools import THREAT_INTEL_TOOLS
from .target_tools import TARGET_TOOLS
from .playbook_tools import PLAYBOOK_TOOLS
from .ad_tools import AD_TOOLS
from .api_security_tools import API_SECURITY_TOOLS
from .automation_tools import AUTOMATION_TOOLS
from .wireless_tools import WIRELESS_TOOLS
from .container_tools import CONTAINER_TOOLS
from .osint_tools import OSINT_TOOLS
from .secrets_tools import SECRETS_TOOLS
from .email_security_tools import EMAIL_SECURITY_TOOLS
from .notification_tools import NOTIFICATION_TOOLS
from .social_engineering_tools import SOCIAL_ENGINEERING_TOOLS
from .vuln_chain_tools import VULN_CHAIN_TOOLS
from .evidence_tools import EVIDENCE_TOOLS
from .c2_tools import C2_TOOLS
from .mobile_tools import MOBILE_TOOLS

TOOLS = (
    RECON_TOOLS + WEBAPP_TOOLS + VULNERABILITY_TOOLS + EXPLOIT_TOOLS +
    NETWORK_TOOLS + PASSWORD_TOOLS + CLOUD_TOOLS + FORENSICS_TOOLS +
    COMPLIANCE_TOOLS + REPORT_TOOLS + THREAT_INTEL_TOOLS + TARGET_TOOLS +
    PLAYBOOK_TOOLS + AD_TOOLS + API_SECURITY_TOOLS + AUTOMATION_TOOLS +
    WIRELESS_TOOLS + CONTAINER_TOOLS + OSINT_TOOLS + SECRETS_TOOLS +
    EMAIL_SECURITY_TOOLS + NOTIFICATION_TOOLS + SOCIAL_ENGINEERING_TOOLS +
    VULN_CHAIN_TOOLS + EVIDENCE_TOOLS + C2_TOOLS + MOBILE_TOOLS
)
