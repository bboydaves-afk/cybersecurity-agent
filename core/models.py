"""Data models for CyberSecurity Agent."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


def generate_id(prefix: str = "") -> str:
    short = uuid.uuid4().hex[:12]
    return f"{prefix}{short}" if prefix else short


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Enums ---

class ProjectType(str, Enum):
    PENTEST = "pentest"
    RED_TEAM = "red_team"
    BUG_BOUNTY = "bug_bounty"
    CTF = "ctf"
    AUDIT = "audit"
    ASSESSMENT = "assessment"


class ProjectStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class TargetType(str, Enum):
    HOST = "host"
    NETWORK = "network"
    WEB_APP = "web_app"
    API = "api"
    CLOUD = "cloud"
    DOMAIN = "domain"
    WIRELESS = "wireless"


class ScanType(str, Enum):
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    VULN_SCAN = "vuln_scan"
    WEB_SCAN = "web_scan"
    DIR_FUZZ = "dir_fuzz"
    DNS_ENUM = "dns_enum"
    SUBDOMAIN_ENUM = "subdomain_enum"
    SSL_SCAN = "ssl_scan"
    CLOUD_AUDIT = "cloud_audit"
    COMPLIANCE_CHECK = "compliance_check"
    ARP_SCAN = "arp_scan"
    OS_FINGERPRINT = "os_fingerprint"
    BANNER_GRAB = "banner_grab"
    NETWORK_SWEEP = "network_sweep"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"


class ExploitType(str, Enum):
    REMOTE_CODE_EXEC = "remote_code_exec"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfil"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    COMMAND_INJECTION = "command_injection"
    SQLI = "sqli"
    XSS = "xss"
    OTHER = "other"


class SessionType(str, Enum):
    SHELL = "shell"
    METERPRETER = "meterpreter"
    SSH = "ssh"
    RDP = "rdp"
    VNC = "vnc"
    WEB_SHELL = "web_shell"
    OTHER = "other"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"
    LOST = "lost"
    BACKGROUNDED = "backgrounded"


class ComplianceFramework(str, Enum):
    CIS = "cis"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    OWASP = "owasp"
    HIPAA = "hipaa"


class ReportType(str, Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAIL = "technical_detail"
    COMPLIANCE = "compliance"
    VULNERABILITY_SUMMARY = "vulnerability_summary"
    FULL_PENTEST = "full_pentest"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"


class CredentialType(str, Enum):
    PASSWORD = "password"
    HASH = "hash"
    TOKEN = "token"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    COOKIE = "cookie"
    CERTIFICATE = "certificate"
    OTHER = "other"


class ChatRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


# --- Models ---

class Project(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("proj-"))
    name: str
    client: Optional[str] = None
    project_type: ProjectType = ProjectType.PENTEST
    status: ProjectStatus = ProjectStatus.ACTIVE
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    scope_notes: Optional[str] = None
    rules_of_engagement: Optional[str] = None
    created_at: str = Field(default_factory=utc_now)
    metadata: Optional[dict] = None


class Target(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("tgt-"))
    project_id: str
    target_type: TargetType = TargetType.HOST
    value: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    in_scope: bool = True
    os_guess: Optional[str] = None
    notes: Optional[str] = None
    created_at: str = Field(default_factory=utc_now)


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("scan-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    scan_type: ScanType
    status: ScanStatus = ScanStatus.PENDING
    parameters: Optional[dict] = None
    results: Optional[dict] = None
    finding_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("find-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Severity = Severity.INFO
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    evidence: Optional[dict] = None
    remediation: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN
    mitre_technique: Optional[str] = None
    created_at: str = Field(default_factory=utc_now)
    updated_at: Optional[str] = None


class NetworkHost(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("host-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: str = "up"
    last_seen: Optional[str] = None
    ports: Optional[list] = None
    services: Optional[list] = None


class WebEndpoint(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("web-"))
    target_id: Optional[str] = None
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    headers: Optional[dict] = None
    parameters: Optional[dict] = None
    technologies: Optional[list] = None
    notes: Optional[str] = None
    discovered_at: str = Field(default_factory=utc_now)


class CredentialFound(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("cred-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    finding_id: Optional[str] = None
    credential_type: CredentialType = CredentialType.PASSWORD
    username: Optional[str] = None
    value: str
    source: Optional[str] = None
    cracked: bool = False
    plaintext: Optional[str] = None
    created_at: str = Field(default_factory=utc_now)


class Exploit(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("exp-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    finding_id: Optional[str] = None
    exploit_type: ExploitType = ExploitType.OTHER
    technique: Optional[str] = None
    payload: Optional[str] = None
    result: Optional[str] = None
    success: bool = False
    access_level: Optional[str] = None
    session_id: Optional[str] = None
    executed_at: str = Field(default_factory=utc_now)
    notes: Optional[str] = None


class Session(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("sess-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    exploit_id: Optional[str] = None
    session_type: SessionType = SessionType.SHELL
    status: SessionStatus = SessionStatus.ACTIVE
    access_level: Optional[str] = None
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    opened_at: str = Field(default_factory=utc_now)
    closed_at: Optional[str] = None


class ComplianceResult(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("comp-"))
    project_id: Optional[str] = None
    target_id: Optional[str] = None
    framework: ComplianceFramework
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    not_applicable: int = 0
    score: Optional[float] = None
    details: Optional[dict] = None
    checked_at: str = Field(default_factory=utc_now)


class Report(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("rpt-"))
    project_id: Optional[str] = None
    title: str
    report_type: ReportType = ReportType.FULL_PENTEST
    format: str = "html"
    file_path: Optional[str] = None
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    generated_at: str = Field(default_factory=utc_now)


class ThreatIntel(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("ioc-"))
    indicator_type: IndicatorType
    indicator_value: str
    source: Optional[str] = None
    reputation: Optional[str] = None
    tags: Optional[list] = None
    raw_data: Optional[dict] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    created_at: str = Field(default_factory=utc_now)


class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("chain-"))
    project_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_tactics: Optional[list] = None
    steps: Optional[list] = None
    impact: Optional[str] = None
    created_at: str = Field(default_factory=utc_now)


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: generate_id("aud-"))
    timestamp: str = Field(default_factory=utc_now)
    actor: str = "agent"
    action_type: str
    target_id: Optional[str] = None
    project_id: Optional[str] = None
    description: Optional[str] = None
    details: Optional[dict] = None
    result: Optional[str] = None


class ChatMessage(BaseModel):
    role: ChatRole
    content: str
    timestamp: str = Field(default_factory=utc_now)
