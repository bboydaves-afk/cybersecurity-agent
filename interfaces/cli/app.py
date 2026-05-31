"""CyberSecurity Agent CLI interface."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("hacking_agent.cli")
console = Console()

app = typer.Typer(
    name="hacking",
    help="CyberSecurity AI Agent - Penetration Testing & Security Assessment",
    no_args_is_help=True,
)


class AppState:
    """Lazy-loading application state."""

    def __init__(self):
        self._db = None
        self._cred_mgr = None
        self._config = None

    @property
    def config(self) -> dict:
        if self._config is None:
            import yaml
            import os
            config_path = os.environ.get("_HACKING_CONFIG_PATH", "config.yaml")
            if Path(config_path).exists():
                with open(config_path, encoding="utf-8") as f:
                    self._config = yaml.safe_load(f) or {}
            else:
                self._config = {}
        return self._config

    @property
    def db(self):
        if self._db is None:
            from core.database import Database
            db_path = self.config.get("database", {}).get("path", "./data/hacking_agent.db")
            self._db = Database(db_path)
            asyncio.get_event_loop().run_until_complete(self._db.connect())
        return self._db

    @property
    def cred_mgr(self):
        if self._cred_mgr is None:
            from core.credentials import CredentialManager
            self._cred_mgr = CredentialManager(self.db)
        return self._cred_mgr


state = AppState()


def run_async(coro):
    """Run an async function synchronously."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def print_result(data: dict, title: str = "Result"):
    """Pretty-print a result dict."""
    if "error" in data:
        console.print(f"[red]Error:[/red] {data['error']}")
        return
    console.print(Panel(json.dumps(data, indent=2, default=str), title=title, border_style="green"))


# ─── Project Commands ───

project_app = typer.Typer(help="Manage pentest projects")
app.add_typer(project_app, name="project")


@project_app.command("list")
def project_list():
    """List all projects."""
    rows = run_async(state.db.fetch_all("SELECT id, name, client, project_type, status, created_at FROM projects ORDER BY created_at DESC"))
    table = Table(title="Projects", border_style="dim")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Client", style="dim")
    table.add_column("Type", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Created", style="dim")
    for r in rows:
        table.add_row(r["id"], r["name"], r.get("client", "-"), r["project_type"], r["status"], r.get("created_at", ""))
    console.print(table)


@project_app.command("create")
def project_create(
    name: str = typer.Option(..., help="Project name"),
    client: str = typer.Option("", help="Client name"),
    project_type: str = typer.Option("pentest", help="Type: pentest|red_team|bug_bounty|ctf|audit"),
):
    """Create a new project."""
    from core.models import generate_id, utc_now
    pid = generate_id("proj")
    run_async(state.db.execute_commit(
        "INSERT INTO projects (id, name, client, project_type, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)",
        (pid, name, client, project_type, utc_now())
    ))
    console.print(f"[green]Created project:[/green] {pid} — {name}")


# ─── Target Commands ───

target_app = typer.Typer(help="Manage targets and scope")
app.add_typer(target_app, name="target")


@target_app.command("add")
def target_add(
    value: str = typer.Option(..., help="Target value (IP, domain, URL)"),
    target_type: str = typer.Option("host", help="Type: host|domain|url|network|cloud|api|wireless"),
    project_id: str = typer.Option(..., help="Project ID"),
    in_scope: bool = typer.Option(True, help="Is target in scope"),
):
    """Add a target to a project."""
    from core.models import generate_id, utc_now
    tid = generate_id("tgt")
    run_async(state.db.execute_commit(
        "INSERT INTO targets (id, project_id, target_type, value, in_scope, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (tid, project_id, target_type, value, in_scope, utc_now())
    ))
    console.print(f"[green]Added target:[/green] {tid} — {value} ({'in scope' if in_scope else 'out of scope'})")


@target_app.command("list")
def target_list(project_id: Optional[str] = typer.Option(None, help="Filter by project ID")):
    """List targets."""
    if project_id:
        rows = run_async(state.db.fetch_all("SELECT id, value, target_type, in_scope FROM targets WHERE project_id = ?", (project_id,)))
    else:
        rows = run_async(state.db.fetch_all("SELECT id, value, target_type, in_scope FROM targets ORDER BY created_at DESC"))
    table = Table(title="Targets", border_style="dim")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("In Scope", style="white")
    for r in rows:
        scope_str = "[green]Yes[/green]" if r["in_scope"] else "[red]No[/red]"
        table.add_row(r["id"], r["value"], r["target_type"], scope_str)
    console.print(table)


@target_app.command("scope")
def target_scope(target_id: str = typer.Argument(..., help="Target ID"), in_scope: bool = typer.Option(True, help="Set scope")):
    """Toggle target scope."""
    run_async(state.db.execute_commit("UPDATE targets SET in_scope = ? WHERE id = ?", (in_scope, target_id)))
    console.print(f"[green]Updated scope:[/green] {target_id} → {'in scope' if in_scope else 'out of scope'}")


# ─── Recon Commands ───

recon_app = typer.Typer(help="Reconnaissance and scanning")
app.add_typer(recon_app, name="recon")


@recon_app.command("scan")
def recon_scan(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    ports: str = typer.Option("1-1000", help="Port range"),
    scan_type: str = typer.Option("syn", help="Scan type: syn|connect|udp"),
):
    """Run a port scan."""
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(state.db, state.config)
    result = run_async(engine.port_scan(target=target, ports=ports, scan_type=scan_type))
    print_result(result, f"Port Scan: {target}")


@recon_app.command("enumerate")
def recon_enumerate(target: str = typer.Argument(..., help="Target IP or hostname")):
    """Enumerate services on target."""
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(state.db, state.config)
    result = run_async(engine.service_enumerate(target=target))
    print_result(result, f"Service Enumeration: {target}")


@recon_app.command("subdomains")
def recon_subdomains(domain: str = typer.Argument(..., help="Domain to enumerate")):
    """Enumerate subdomains."""
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(state.db, state.config)
    result = run_async(engine.subdomain_enumerate(domain=domain))
    print_result(result, f"Subdomain Enumeration: {domain}")


@recon_app.command("whois")
def recon_whois(target: str = typer.Argument(..., help="Domain or IP")):
    """WHOIS lookup."""
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(state.db, state.config)
    result = run_async(engine.whois_lookup(target=target))
    print_result(result, f"WHOIS: {target}")


@recon_app.command("dns")
def recon_dns(domain: str = typer.Argument(..., help="Domain to query")):
    """DNS reconnaissance."""
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(state.db, state.config)
    result = run_async(engine.dns_recon(domain=domain))
    print_result(result, f"DNS Recon: {domain}")


@recon_app.command("sweep")
def recon_sweep(network: str = typer.Argument(..., help="Network CIDR")):
    """Network host sweep."""
    from engines.recon_engine import ReconEngine
    engine = ReconEngine(state.db, state.config)
    result = run_async(engine.network_sweep(network=network))
    print_result(result, f"Network Sweep: {network}")


# ─── Web Security Commands ───

web_app = typer.Typer(help="Web application security testing")
app.add_typer(web_app, name="web")


@web_app.command("headers")
def web_headers(url: str = typer.Argument(..., help="Target URL")):
    """Analyze HTTP security headers."""
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(state.db, state.config)
    result = run_async(engine.analyze_headers(url=url))
    print_result(result, f"Header Analysis: {url}")


@web_app.command("ssl")
def web_ssl(hostname: str = typer.Argument(..., help="Hostname"), port: int = typer.Option(443)):
    """Test SSL/TLS configuration."""
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(state.db, state.config)
    result = run_async(engine.test_ssl(hostname=hostname, port=port))
    print_result(result, f"SSL/TLS Test: {hostname}:{port}")


@web_app.command("fuzz")
def web_fuzz(url: str = typer.Argument(..., help="Base URL"), wordlist: str = typer.Option("common", help="Wordlist name")):
    """Directory fuzzing."""
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(state.db, state.config)
    result = run_async(engine.directory_fuzz(url=url, wordlist=wordlist))
    print_result(result, f"Directory Fuzz: {url}")


@web_app.command("cors")
def web_cors(url: str = typer.Argument(..., help="Target URL")):
    """Test CORS configuration."""
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(state.db, state.config)
    result = run_async(engine.test_cors(url=url))
    print_result(result, f"CORS Test: {url}")


@web_app.command("crawl")
def web_crawl(url: str = typer.Argument(..., help="Target URL"), depth: int = typer.Option(2)):
    """Crawl website."""
    from engines.webapp_engine import WebAppEngine
    engine = WebAppEngine(state.db, state.config)
    result = run_async(engine.crawl_site(url=url, max_depth=depth))
    print_result(result, f"Web Crawl: {url}")


# ─── Vulnerability Commands ───

vuln_app = typer.Typer(help="Vulnerability assessment")
app.add_typer(vuln_app, name="vuln")


@vuln_app.command("search")
def vuln_search(query: str = typer.Argument(..., help="CVE ID or keyword")):
    """Search for CVEs."""
    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(state.db, state.config)
    result = run_async(engine.search_cve(query=query))
    print_result(result, f"CVE Search: {query}")


@vuln_app.command("details")
def vuln_details(cve_id: str = typer.Argument(..., help="CVE ID (e.g., CVE-2021-44228)")):
    """Get CVE details."""
    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(state.db, state.config)
    result = run_async(engine.get_cve_details(cve_id=cve_id))
    print_result(result, f"CVE Details: {cve_id}")


@vuln_app.command("scan")
def vuln_scan(target: str = typer.Argument(..., help="Target to scan")):
    """Run vulnerability scan."""
    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(state.db, state.config)
    result = run_async(engine.vulnerability_scan(target=target))
    print_result(result, f"Vulnerability Scan: {target}")


@vuln_app.command("stats")
def vuln_stats(project_id: Optional[str] = typer.Option(None)):
    """Show vulnerability statistics."""
    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(state.db, state.config)
    result = run_async(engine.get_vuln_stats(project_id=project_id))
    print_result(result, "Vulnerability Statistics")


# ─── Exploit Commands ───

exploit_app = typer.Typer(help="Exploitation tools")
app.add_typer(exploit_app, name="exploit")


@exploit_app.command("search")
def exploit_search(query: str = typer.Argument(..., help="Search query or CVE")):
    """Search for exploits."""
    from engines.vulnerability_engine import VulnerabilityEngine
    engine = VulnerabilityEngine(state.db, state.config)
    result = run_async(engine.search_exploits(query=query))
    print_result(result, f"Exploit Search: {query}")


@exploit_app.command("sessions")
def exploit_sessions():
    """List active sessions."""
    from engines.exploit_engine import ExploitEngine
    engine = ExploitEngine(state.db, state.config)
    result = run_async(engine.list_sessions())
    print_result(result, "Active Sessions")


@exploit_app.command("payloads")
def exploit_payloads(payload_type: str = typer.Argument("reverse_shell", help="Payload type")):
    """Generate payload."""
    from engines.exploit_engine import ExploitEngine
    engine = ExploitEngine(state.db, state.config)
    result = run_async(engine.generate_payload(payload_type=payload_type))
    print_result(result, f"Payload: {payload_type}")


# ─── Network Commands ───

network_app = typer.Typer(help="Network analysis tools")
app.add_typer(network_app, name="network")


@network_app.command("arp")
def network_arp(network: str = typer.Argument("192.168.1.0/24", help="Network CIDR")):
    """ARP scan a network."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(state.db, state.config)
    result = run_async(engine.arp_scan(network=network))
    print_result(result, f"ARP Scan: {network}")


@network_app.command("dns")
def network_dns(domain: str = typer.Argument(..., help="Domain to enumerate")):
    """DNS enumeration."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(state.db, state.config)
    result = run_async(engine.dns_enumerate(domain=domain))
    print_result(result, f"DNS Enumeration: {domain}")


@network_app.command("snmp")
def network_snmp(target: str = typer.Argument(..., help="Target IP"), community: str = typer.Option("public")):
    """SNMP enumeration."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(state.db, state.config)
    result = run_async(engine.snmp_enumerate(target=target, community=community))
    print_result(result, f"SNMP Enumeration: {target}")


@network_app.command("capture")
def network_capture(interface: str = typer.Argument("eth0"), count: int = typer.Option(100), filter_expr: str = typer.Option("", help="BPF filter")):
    """Capture network packets."""
    from engines.network_engine import NetworkEngine
    engine = NetworkEngine(state.db, state.config)
    result = run_async(engine.packet_capture(interface=interface, count=count, filter_expr=filter_expr))
    print_result(result, f"Packet Capture: {interface}")


# ─── Password Commands ───

password_app = typer.Typer(help="Password and credential tools")
app.add_typer(password_app, name="password")


@password_app.command("identify")
def password_identify(hash_value: str = typer.Argument(..., help="Hash to identify")):
    """Identify hash type."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(state.db, state.config)
    result = run_async(engine.identify_hash(hash_value=hash_value))
    print_result(result, "Hash Identification")


@password_app.command("crack")
def password_crack(hash_value: str = typer.Argument(..., help="Hash to crack"), hash_type: str = typer.Option("auto")):
    """Generate cracking commands for a hash."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(state.db, state.config)
    result = run_async(engine.crack_hash(hash_value=hash_value, hash_type=hash_type))
    print_result(result, "Crack Hash")


@password_app.command("strength")
def password_strength(password: str = typer.Argument(..., help="Password to analyze")):
    """Analyze password strength."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(state.db, state.config)
    result = run_async(engine.analyze_password_strength(password=password))
    print_result(result, "Password Strength")


@password_app.command("policy")
def password_policy():
    """Show recommended password policies."""
    from engines.password_engine import PasswordEngine
    engine = PasswordEngine(state.db, state.config)
    result = run_async(engine.check_password_policy())
    print_result(result, "Password Policy")


# ─── Cloud Security Commands ───

cloud_app = typer.Typer(help="Cloud security auditing")
app.add_typer(cloud_app, name="cloud")


@cloud_app.command("audit-aws")
def cloud_audit_aws():
    """Audit AWS security configuration."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(state.db, state.config)
    result = run_async(engine.audit_aws())
    print_result(result, "AWS Security Audit")


@cloud_app.command("audit-azure")
def cloud_audit_azure():
    """Audit Azure security configuration."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(state.db, state.config)
    result = run_async(engine.audit_azure())
    print_result(result, "Azure Security Audit")


@cloud_app.command("audit-gcp")
def cloud_audit_gcp():
    """Audit GCP security configuration."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(state.db, state.config)
    result = run_async(engine.audit_gcp())
    print_result(result, "GCP Security Audit")


@cloud_app.command("iam")
def cloud_iam(provider: str = typer.Argument("aws", help="Provider: aws|azure|gcp")):
    """Check IAM permissions."""
    from engines.cloud_security_engine import CloudSecurityEngine
    engine = CloudSecurityEngine(state.db, state.config)
    result = run_async(engine.check_iam_permissions(provider=provider))
    print_result(result, f"IAM Check: {provider}")


# ─── Forensics Commands ───

forensics_app = typer.Typer(help="Digital forensics tools")
app.add_typer(forensics_app, name="forensics")


@forensics_app.command("analyze")
def forensics_analyze(log_path: str = typer.Argument(..., help="Log file path"), log_type: str = typer.Option("auto")):
    """Analyze log files."""
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(state.db, state.config)
    result = run_async(engine.parse_log(log_path=log_path, log_type=log_type))
    print_result(result, f"Log Analysis: {log_path}")


@forensics_app.command("timeline")
def forensics_timeline(project_id: str = typer.Argument(..., help="Project ID")):
    """Build forensic timeline."""
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(state.db, state.config)
    result = run_async(engine.build_timeline(project_id=project_id))
    print_result(result, "Forensic Timeline")


@forensics_app.command("strings")
def forensics_strings(file_path: str = typer.Argument(..., help="File to analyze"), min_length: int = typer.Option(4)):
    """Extract strings from binary."""
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(state.db, state.config)
    result = run_async(engine.extract_strings(file_path=file_path, min_length=min_length))
    print_result(result, f"String Extraction: {file_path}")


@forensics_app.command("malware")
def forensics_malware(file_path: str = typer.Argument(..., help="File to analyze")):
    """Analyze potential malware."""
    from engines.forensics_engine import ForensicsEngine
    engine = ForensicsEngine(state.db, state.config)
    result = run_async(engine.analyze_malware(file_path=file_path))
    print_result(result, f"Malware Analysis: {file_path}")


# ─── Compliance Commands ───

compliance_app = typer.Typer(help="Compliance checking")
app.add_typer(compliance_app, name="compliance")


@compliance_app.command("check")
def compliance_check(
    framework: str = typer.Argument("cis", help="Framework: cis|nist|pci_dss|iso27001|hipaa|owasp"),
    target: str = typer.Option("", help="Target to check"),
    project_id: str = typer.Option("", help="Project ID"),
):
    """Run compliance check."""
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(state.db, state.config)
    method_map = {
        "cis": engine.check_cis,
        "nist": engine.check_nist,
        "pci_dss": engine.check_pci_dss,
    }
    method = method_map.get(framework)
    if method:
        result = run_async(method(target=target, project_id=project_id))
    else:
        result = {"error": f"Unknown framework: {framework}. Use cis, nist, or pci_dss"}
    print_result(result, f"Compliance Check: {framework}")


@compliance_app.command("report")
def compliance_report(project_id: str = typer.Argument(...)):
    """Generate compliance report."""
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(state.db, state.config)
    result = run_async(engine.generate_compliance_report(project_id=project_id))
    print_result(result, "Compliance Report")


@compliance_app.command("summary")
def compliance_summary(project_id: str = typer.Argument(...)):
    """Get compliance summary."""
    from engines.compliance_engine import ComplianceEngine
    engine = ComplianceEngine(state.db, state.config)
    result = run_async(engine.get_compliance_summary(project_id=project_id))
    print_result(result, "Compliance Summary")


# ─── Report Commands ───

report_app = typer.Typer(help="Report generation")
app.add_typer(report_app, name="report")


@report_app.command("generate")
def report_generate(
    project_id: str = typer.Argument(..., help="Project ID"),
    format: str = typer.Option("html", help="Format: html|json|markdown"),
    title: str = typer.Option("Penetration Test Report"),
):
    """Generate a pentest report."""
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(state.db, state.config)
    result = run_async(engine.generate_report(project_id=project_id, format=format, title=title))
    print_result(result, f"Report Generated ({format})")


@report_app.command("findings")
def report_findings(project_id: str = typer.Argument(...), format: str = typer.Option("json")):
    """Export findings."""
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(state.db, state.config)
    result = run_async(engine.export_findings(project_id=project_id, format=format))
    print_result(result, "Findings Export")


@report_app.command("risk")
def report_risk(project_id: str = typer.Argument(...)):
    """Calculate risk score."""
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(state.db, state.config)
    result = run_async(engine.calculate_risk_score(project_id=project_id))
    print_result(result, "Risk Score")


@report_app.command("executive")
def report_executive(project_id: str = typer.Argument(...)):
    """Get executive summary."""
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(state.db, state.config)
    result = run_async(engine.get_executive_summary(project_id=project_id))
    print_result(result, "Executive Summary")


@report_app.command("remediation")
def report_remediation(finding_id: str = typer.Argument(...)):
    """Get remediation suggestions for a finding."""
    from engines.reporting_engine import ReportingEngine
    engine = ReportingEngine(state.db, state.config)
    result = run_async(engine.suggest_remediation(finding_id=finding_id))
    print_result(result, "Remediation Suggestions")


# ─── Threat Intelligence Commands ───

intel_app = typer.Typer(help="Threat intelligence")
app.add_typer(intel_app, name="intel")


@intel_app.command("mitre")
def intel_mitre(project_id: str = typer.Argument(...)):
    """Map findings to MITRE ATT&CK."""
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(state.db, state.config)
    result = run_async(engine.map_to_mitre(project_id=project_id))
    print_result(result, "MITRE ATT&CK Mapping")


@intel_app.command("enrich")
def intel_enrich(value: str = typer.Argument(..., help="Indicator value"), indicator_type: str = typer.Option("ip")):
    """Enrich an IOC."""
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(state.db, state.config)
    result = run_async(engine.enrich_ioc(indicator_type=indicator_type, value=value))
    print_result(result, f"IOC Enrichment: {value}")


@intel_app.command("search")
def intel_search(query: str = typer.Argument(...)):
    """Search threat intelligence database."""
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(state.db, state.config)
    result = run_async(engine.search_threat_intel(query=query))
    print_result(result, f"Threat Intel Search: {query}")


@intel_app.command("attack-chain")
def intel_attack_chain(project_id: str = typer.Argument(...)):
    """Build attack chain for project."""
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(state.db, state.config)
    result = run_async(engine.build_attack_chain(project_id=project_id))
    print_result(result, "Attack Chain")


@intel_app.command("surface")
def intel_surface(project_id: str = typer.Argument(...)):
    """Get attack surface summary."""
    from engines.threat_intel_engine import ThreatIntelEngine
    engine = ThreatIntelEngine(state.db, state.config)
    result = run_async(engine.get_attack_surface(project_id=project_id))
    print_result(result, "Attack Surface")


# ─── Playbook Commands ───

playbook_app = typer.Typer(help="Manage and run playbooks")
app.add_typer(playbook_app, name="playbook")


@playbook_app.command("run")
def playbook_run(
    playbook_name: str = typer.Argument(..., help="Playbook name or path"),
    project_id: str = typer.Option(..., help="Project ID"),
):
    """Run a security playbook."""
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(state.db, state.config)
    result = run_async(engine.run_playbook(playbook_name=playbook_name, project_id=project_id))
    print_result(result, f"Playbook Run: {playbook_name}")


@playbook_app.command("list")
def playbook_list():
    """List available playbooks."""
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(state.db, state.config)
    result = run_async(engine.list_playbooks())
    print_result(result, "Available Playbooks")


@playbook_app.command("status")
def playbook_status(execution_id: str = typer.Argument(..., help="Execution ID")):
    """Get playbook execution status."""
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(state.db, state.config)
    result = run_async(engine.get_playbook_status(execution_id=execution_id))
    print_result(result, f"Playbook Status: {execution_id}")


@playbook_app.command("validate")
def playbook_validate(playbook_path: str = typer.Argument(..., help="Playbook file path")):
    """Validate playbook syntax."""
    from engines.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(state.db, state.config)
    result = run_async(engine.validate_playbook(playbook_path=playbook_path))
    print_result(result, f"Playbook Validation: {playbook_path}")


# ─── Active Directory Commands ───

ad_app = typer.Typer(help="Active Directory security testing")
app.add_typer(ad_app, name="ad")


@ad_app.command("enumerate")
def ad_enumerate(
    target: str = typer.Argument(..., help="Domain controller IP/hostname"),
    domain: str = typer.Option("", help="Domain name"),
):
    """Enumerate Active Directory."""
    from engines.ad_engine import ADEngine
    engine = ADEngine(state.db, state.config)
    result = run_async(engine.enumerate_ad(target=target, domain=domain))
    print_result(result, f"AD Enumeration: {target}")


@ad_app.command("users")
def ad_users(target: str = typer.Argument(..., help="Domain controller")):
    """Enumerate AD users."""
    from engines.ad_engine import ADEngine
    engine = ADEngine(state.db, state.config)
    result = run_async(engine.enumerate_users(target=target))
    print_result(result, f"AD Users: {target}")


@ad_app.command("groups")
def ad_groups(target: str = typer.Argument(..., help="Domain controller")):
    """Enumerate AD groups."""
    from engines.ad_engine import ADEngine
    engine = ADEngine(state.db, state.config)
    result = run_async(engine.enumerate_groups(target=target))
    print_result(result, f"AD Groups: {target}")


@ad_app.command("kerberoast")
def ad_kerberoast(target: str = typer.Argument(..., help="Domain controller")):
    """Perform Kerberoasting attack."""
    from engines.ad_engine import ADEngine
    engine = ADEngine(state.db, state.config)
    result = run_async(engine.kerberoast(target=target))
    print_result(result, f"Kerberoasting: {target}")


@ad_app.command("assess")
def ad_assess(target: str = typer.Argument(..., help="Domain controller")):
    """Assess AD security posture."""
    from engines.ad_engine import ADEngine
    engine = ADEngine(state.db, state.config)
    result = run_async(engine.assess_security(target=target))
    print_result(result, f"AD Security Assessment: {target}")


# ─── API Security Commands ───

apisec_app = typer.Typer(help="API security testing")
app.add_typer(apisec_app, name="apisec")


@apisec_app.command("discover")
def apisec_discover(url: str = typer.Argument(..., help="Base URL")):
    """Discover API endpoints."""
    from engines.apisec_engine import APISecEngine
    engine = APISecEngine(state.db, state.config)
    result = run_async(engine.discover_endpoints(url=url))
    print_result(result, f"API Discovery: {url}")


@apisec_app.command("scan")
def apisec_scan(url: str = typer.Argument(..., help="API URL"), spec_path: str = typer.Option("", help="OpenAPI spec path")):
    """Scan API for vulnerabilities."""
    from engines.apisec_engine import APISecEngine
    engine = APISecEngine(state.db, state.config)
    result = run_async(engine.scan_api(url=url, spec_path=spec_path))
    print_result(result, f"API Scan: {url}")


@apisec_app.command("jwt")
def apisec_jwt(token: str = typer.Argument(..., help="JWT token")):
    """Analyze JWT token."""
    from engines.apisec_engine import APISecEngine
    engine = APISecEngine(state.db, state.config)
    result = run_async(engine.analyze_jwt(token=token))
    print_result(result, "JWT Analysis")


@apisec_app.command("fuzz")
def apisec_fuzz(url: str = typer.Argument(..., help="API endpoint"), method: str = typer.Option("GET")):
    """Fuzz API endpoint."""
    from engines.apisec_engine import APISecEngine
    engine = APISecEngine(state.db, state.config)
    result = run_async(engine.fuzz_endpoint(url=url, method=method))
    print_result(result, f"API Fuzzing: {url}")


# ─── Schedule Commands ───

schedule_app = typer.Typer(help="Manage scheduled tasks")
app.add_typer(schedule_app, name="schedule")


@schedule_app.command("add")
def schedule_add(
    task_name: str = typer.Argument(..., help="Task name"),
    task_type: str = typer.Option(..., help="Task type: scan|playbook|report"),
    schedule: str = typer.Option(..., help="Cron expression"),
):
    """Add a scheduled task."""
    from engines.scheduler_engine import SchedulerEngine
    engine = SchedulerEngine(state.db, state.config)
    result = run_async(engine.add_task(task_name=task_name, task_type=task_type, schedule=schedule))
    print_result(result, f"Scheduled Task Added: {task_name}")


@schedule_app.command("list")
def schedule_list():
    """List scheduled tasks."""
    from engines.scheduler_engine import SchedulerEngine
    engine = SchedulerEngine(state.db, state.config)
    result = run_async(engine.list_tasks())
    print_result(result, "Scheduled Tasks")


@schedule_app.command("remove")
def schedule_remove(task_id: str = typer.Argument(..., help="Task ID")):
    """Remove a scheduled task."""
    from engines.scheduler_engine import SchedulerEngine
    engine = SchedulerEngine(state.db, state.config)
    result = run_async(engine.remove_task(task_id=task_id))
    print_result(result, f"Removed Task: {task_id}")


@schedule_app.command("status")
def schedule_status():
    """Show scheduler status."""
    from engines.scheduler_engine import SchedulerEngine
    engine = SchedulerEngine(state.db, state.config)
    result = run_async(engine.get_status())
    print_result(result, "Scheduler Status")


# ─── Wireless Commands ───

wireless_app = typer.Typer(help="Wireless network security testing")
app.add_typer(wireless_app, name="wireless")


@wireless_app.command("scan")
def wireless_scan(interface: str = typer.Argument("wlan0", help="Wireless interface")):
    """Scan for wireless networks."""
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(state.db, state.config)
    result = run_async(engine.scan_networks(interface=interface))
    print_result(result, f"Wireless Scan: {interface}")


@wireless_app.command("analyze")
def wireless_analyze(bssid: str = typer.Argument(..., help="BSSID to analyze")):
    """Analyze wireless network."""
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(state.db, state.config)
    result = run_async(engine.analyze_network(bssid=bssid))
    print_result(result, f"Wireless Analysis: {bssid}")


@wireless_app.command("rogue")
def wireless_rogue(interface: str = typer.Argument("wlan0", help="Wireless interface")):
    """Detect rogue access points."""
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(state.db, state.config)
    result = run_async(engine.detect_rogue_aps(interface=interface))
    print_result(result, "Rogue AP Detection")


@wireless_app.command("assess")
def wireless_assess(bssid: str = typer.Argument(..., help="BSSID")):
    """Assess wireless security."""
    from engines.wireless_engine import WirelessEngine
    engine = WirelessEngine(state.db, state.config)
    result = run_async(engine.assess_security(bssid=bssid))
    print_result(result, f"Wireless Security Assessment: {bssid}")


# ─── Container Security Commands ───

container_app = typer.Typer(help="Container and Kubernetes security")
app.add_typer(container_app, name="container")


@container_app.command("scan-image")
def container_scan_image(image: str = typer.Argument(..., help="Container image name")):
    """Scan container image for vulnerabilities."""
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(state.db, state.config)
    result = run_async(engine.scan_image(image=image))
    print_result(result, f"Container Image Scan: {image}")


@container_app.command("docker-check")
def container_docker_check():
    """Check Docker security configuration."""
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(state.db, state.config)
    result = run_async(engine.check_docker_security())
    print_result(result, "Docker Security Check")


@container_app.command("k8s-rbac")
def container_k8s_rbac(namespace: str = typer.Option("default")):
    """Audit Kubernetes RBAC."""
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(state.db, state.config)
    result = run_async(engine.audit_k8s_rbac(namespace=namespace))
    print_result(result, f"K8s RBAC Audit: {namespace}")


@container_app.command("assess")
def container_assess(target: str = typer.Argument(..., help="Container/cluster name")):
    """Assess container security posture."""
    from engines.container_engine import ContainerEngine
    engine = ContainerEngine(state.db, state.config)
    result = run_async(engine.assess_security(target=target))
    print_result(result, f"Container Security Assessment: {target}")


# ─── OSINT Commands ───

osint_app = typer.Typer(help="Open-source intelligence gathering")
app.add_typer(osint_app, name="osint")


@osint_app.command("domain")
def osint_domain(domain: str = typer.Argument(..., help="Domain to research")):
    """Gather domain intelligence."""
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(state.db, state.config)
    result = run_async(engine.research_domain(domain=domain))
    print_result(result, f"Domain OSINT: {domain}")


@osint_app.command("breach")
def osint_breach(email: str = typer.Argument(..., help="Email address")):
    """Check for breach exposure."""
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(state.db, state.config)
    result = run_async(engine.check_breaches(email=email))
    print_result(result, f"Breach Check: {email}")


@osint_app.command("emails")
def osint_emails(domain: str = typer.Argument(..., help="Domain")):
    """Harvest email addresses."""
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(state.db, state.config)
    result = run_async(engine.harvest_emails(domain=domain))
    print_result(result, f"Email Harvest: {domain}")


@osint_app.command("github")
def osint_github(user: str = typer.Argument(..., help="GitHub username or org")):
    """Search GitHub for sensitive data."""
    from engines.osint_engine import OSINTEngine
    engine = OSINTEngine(state.db, state.config)
    result = run_async(engine.search_github(user=user))
    print_result(result, f"GitHub OSINT: {user}")


# ─── Secrets Scanning Commands ───

secrets_app = typer.Typer(help="Secrets and credential scanning")
app.add_typer(secrets_app, name="secrets")


@secrets_app.command("scan-dir")
def secrets_scan_dir(path: str = typer.Argument(..., help="Directory path")):
    """Scan directory for secrets."""
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(state.db, state.config)
    result = run_async(engine.scan_directory(path=path))
    print_result(result, f"Directory Scan: {path}")


@secrets_app.command("scan-git")
def secrets_scan_git(repo_path: str = typer.Argument(..., help="Git repository path")):
    """Scan Git history for secrets."""
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(state.db, state.config)
    result = run_async(engine.scan_git_history(repo_path=repo_path))
    print_result(result, f"Git History Scan: {repo_path}")


@secrets_app.command("scan-file")
def secrets_scan_file(file_path: str = typer.Argument(..., help="File path")):
    """Scan file for secrets."""
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(state.db, state.config)
    result = run_async(engine.scan_file(file_path=file_path))
    print_result(result, f"File Scan: {file_path}")


@secrets_app.command("patterns")
def secrets_patterns():
    """List secret detection patterns."""
    from engines.secrets_engine import SecretsEngine
    engine = SecretsEngine(state.db, state.config)
    result = run_async(engine.list_patterns())
    print_result(result, "Secret Patterns")


# ─── Email Security Commands ───

email_app = typer.Typer(help="Email security testing")
app.add_typer(email_app, name="email")


@email_app.command("spf")
def email_spf(domain: str = typer.Argument(..., help="Domain name")):
    """Check SPF records."""
    from engines.email_engine import EmailEngine
    engine = EmailEngine(state.db, state.config)
    result = run_async(engine.check_spf(domain=domain))
    print_result(result, f"SPF Check: {domain}")


@email_app.command("dkim")
def email_dkim(domain: str = typer.Argument(..., help="Domain name"), selector: str = typer.Option("default")):
    """Check DKIM records."""
    from engines.email_engine import EmailEngine
    engine = EmailEngine(state.db, state.config)
    result = run_async(engine.check_dkim(domain=domain, selector=selector))
    print_result(result, f"DKIM Check: {domain}")


@email_app.command("dmarc")
def email_dmarc(domain: str = typer.Argument(..., help="Domain name")):
    """Check DMARC policy."""
    from engines.email_engine import EmailEngine
    engine = EmailEngine(state.db, state.config)
    result = run_async(engine.check_dmarc(domain=domain))
    print_result(result, f"DMARC Check: {domain}")


@email_app.command("posture")
def email_posture(domain: str = typer.Argument(..., help="Domain name")):
    """Assess email security posture."""
    from engines.email_engine import EmailEngine
    engine = EmailEngine(state.db, state.config)
    result = run_async(engine.assess_email_security(domain=domain))
    print_result(result, f"Email Security Posture: {domain}")


# ─── Notification Commands ───

notify_app = typer.Typer(help="Notification management")
app.add_typer(notify_app, name="notify")


@notify_app.command("configure")
def notify_configure(
    channel: str = typer.Argument(..., help="Channel: slack|email|webhook"),
    config_json: str = typer.Option(..., help="JSON config string"),
):
    """Configure notification channel."""
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(state.db, state.config)
    result = run_async(engine.configure_channel(channel=channel, config=json.loads(config_json)))
    print_result(result, f"Notification Config: {channel}")


@notify_app.command("list")
def notify_list():
    """List notification channels."""
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(state.db, state.config)
    result = run_async(engine.list_channels())
    print_result(result, "Notification Channels")


@notify_app.command("send")
def notify_send(channel: str = typer.Argument(..., help="Channel name"), message: str = typer.Option(...)):
    """Send test notification."""
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(state.db, state.config)
    result = run_async(engine.send_notification(channel=channel, message=message))
    print_result(result, f"Notification Sent: {channel}")


@notify_app.command("test")
def notify_test(channel: str = typer.Argument(..., help="Channel name")):
    """Test notification channel."""
    from engines.notification_engine import NotificationEngine
    engine = NotificationEngine(state.db, state.config)
    result = run_async(engine.test_channel(channel=channel))
    print_result(result, f"Channel Test: {channel}")


# ─── Social Engineering Commands ───

social_app = typer.Typer(help="Social engineering campaigns")
app.add_typer(social_app, name="social")


@social_app.command("campaign-create")
def social_campaign_create(
    name: str = typer.Argument(..., help="Campaign name"),
    campaign_type: str = typer.Option("phishing", help="Type: phishing|pretexting|vishing"),
    project_id: str = typer.Option(..., help="Project ID"),
):
    """Create social engineering campaign."""
    from engines.social_engine import SocialEngine
    engine = SocialEngine(state.db, state.config)
    result = run_async(engine.create_campaign(name=name, campaign_type=campaign_type, project_id=project_id))
    print_result(result, f"Campaign Created: {name}")


@social_app.command("campaign-list")
def social_campaign_list(project_id: Optional[str] = typer.Option(None)):
    """List social engineering campaigns."""
    from engines.social_engine import SocialEngine
    engine = SocialEngine(state.db, state.config)
    result = run_async(engine.list_campaigns(project_id=project_id))
    print_result(result, "Social Engineering Campaigns")


@social_app.command("analyze")
def social_analyze(campaign_id: str = typer.Argument(..., help="Campaign ID")):
    """Analyze campaign results."""
    from engines.social_engine import SocialEngine
    engine = SocialEngine(state.db, state.config)
    result = run_async(engine.analyze_campaign(campaign_id=campaign_id))
    print_result(result, f"Campaign Analysis: {campaign_id}")


@social_app.command("typosquat")
def social_typosquat(domain: str = typer.Argument(..., help="Domain to analyze")):
    """Generate typosquatting variants."""
    from engines.social_engine import SocialEngine
    engine = SocialEngine(state.db, state.config)
    result = run_async(engine.generate_typosquats(domain=domain))
    print_result(result, f"Typosquat Analysis: {domain}")


# ─── Attack Chain Commands ───

chain_app = typer.Typer(help="Attack chain analysis")
app.add_typer(chain_app, name="chain")


@chain_app.command("find")
def chain_find(target_id: str = typer.Argument(..., help="Target ID")):
    """Find attack chains to target."""
    from engines.chain_engine import ChainEngine
    engine = ChainEngine(state.db, state.config)
    result = run_async(engine.find_attack_chains(target_id=target_id))
    print_result(result, f"Attack Chains: {target_id}")


@chain_app.command("analyze")
def chain_analyze(chain_id: str = typer.Argument(..., help="Chain ID")):
    """Analyze attack chain feasibility."""
    from engines.chain_engine import ChainEngine
    engine = ChainEngine(state.db, state.config)
    result = run_async(engine.analyze_chain(chain_id=chain_id))
    print_result(result, f"Chain Analysis: {chain_id}")


@chain_app.command("prioritize")
def chain_prioritize(project_id: str = typer.Argument(..., help="Project ID")):
    """Prioritize attack chains by impact."""
    from engines.chain_engine import ChainEngine
    engine = ChainEngine(state.db, state.config)
    result = run_async(engine.prioritize_chains(project_id=project_id))
    print_result(result, "Chain Prioritization")


@chain_app.command("simulate")
def chain_simulate(chain_id: str = typer.Argument(..., help="Chain ID")):
    """Simulate attack chain execution."""
    from engines.chain_engine import ChainEngine
    engine = ChainEngine(state.db, state.config)
    result = run_async(engine.simulate_chain(chain_id=chain_id))
    print_result(result, f"Chain Simulation: {chain_id}")


# ─── Evidence Management Commands ───

evidence_app = typer.Typer(help="Evidence collection and management")
app.add_typer(evidence_app, name="evidence")


@evidence_app.command("collect")
def evidence_collect(
    item_type: str = typer.Argument(..., help="Type: screenshot|log|file|network"),
    source: str = typer.Option(..., help="Source path or description"),
    finding_id: str = typer.Option(..., help="Finding ID"),
):
    """Collect evidence item."""
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(state.db, state.config)
    result = run_async(engine.collect_evidence(item_type=item_type, source=source, finding_id=finding_id))
    print_result(result, f"Evidence Collected: {item_type}")


@evidence_app.command("list")
def evidence_list(finding_id: Optional[str] = typer.Option(None), project_id: Optional[str] = typer.Option(None)):
    """List evidence items."""
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(state.db, state.config)
    result = run_async(engine.list_evidence(finding_id=finding_id, project_id=project_id))
    print_result(result, "Evidence Items")


@evidence_app.command("verify")
def evidence_verify(evidence_id: str = typer.Argument(..., help="Evidence ID")):
    """Verify evidence integrity."""
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(state.db, state.config)
    result = run_async(engine.verify_integrity(evidence_id=evidence_id))
    print_result(result, f"Evidence Verification: {evidence_id}")


@evidence_app.command("export")
def evidence_export(project_id: str = typer.Argument(..., help="Project ID"), output_path: str = typer.Option("./evidence.zip")):
    """Export evidence package."""
    from engines.evidence_engine import EvidenceEngine
    engine = EvidenceEngine(state.db, state.config)
    result = run_async(engine.export_evidence(project_id=project_id, output_path=output_path))
    print_result(result, f"Evidence Export: {output_path}")


# ─── Command & Control Commands ───

c2_app = typer.Typer(help="Command and control management")
app.add_typer(c2_app, name="c2")


@c2_app.command("connect")
def c2_connect(host: str = typer.Argument(..., help="C2 server host"), port: int = typer.Option(4444)):
    """Connect to C2 server."""
    from engines.c2_engine import C2Engine
    engine = C2Engine(state.db, state.config)
    result = run_async(engine.connect_server(host=host, port=port))
    print_result(result, f"C2 Connection: {host}:{port}")


@c2_app.command("sessions")
def c2_sessions():
    """List active C2 sessions."""
    from engines.c2_engine import C2Engine
    engine = C2Engine(state.db, state.config)
    result = run_async(engine.list_sessions())
    print_result(result, "C2 Sessions")


@c2_app.command("listener")
def c2_listener(port: int = typer.Argument(4444, help="Listener port"), listener_type: str = typer.Option("http")):
    """Start C2 listener."""
    from engines.c2_engine import C2Engine
    engine = C2Engine(state.db, state.config)
    result = run_async(engine.start_listener(port=port, listener_type=listener_type))
    print_result(result, f"C2 Listener: {listener_type}:{port}")


@c2_app.command("status")
def c2_status():
    """Show C2 infrastructure status."""
    from engines.c2_engine import C2Engine
    engine = C2Engine(state.db, state.config)
    result = run_async(engine.get_status())
    print_result(result, "C2 Status")


# ─── Mobile Security Commands ───

mobile_app = typer.Typer(help="Mobile application security testing")
app.add_typer(mobile_app, name="mobile")


@mobile_app.command("apk")
def mobile_apk(apk_path: str = typer.Argument(..., help="APK file path")):
    """Analyze Android APK."""
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(state.db, state.config)
    result = run_async(engine.analyze_apk(apk_path=apk_path))
    print_result(result, f"APK Analysis: {apk_path}")


@mobile_app.command("ipa")
def mobile_ipa(ipa_path: str = typer.Argument(..., help="IPA file path")):
    """Analyze iOS IPA."""
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(state.db, state.config)
    result = run_async(engine.analyze_ipa(ipa_path=ipa_path))
    print_result(result, f"IPA Analysis: {ipa_path}")


@mobile_app.command("owasp")
def mobile_owasp(app_path: str = typer.Argument(..., help="App file path"), platform: str = typer.Option("android", help="android|ios")):
    """Run OWASP Mobile Top 10 checks."""
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(state.db, state.config)
    result = run_async(engine.check_owasp_mobile(app_path=app_path, platform=platform))
    print_result(result, f"OWASP Mobile Check: {app_path}")


@mobile_app.command("report")
def mobile_report(analysis_id: str = typer.Argument(..., help="Analysis ID")):
    """Generate mobile security report."""
    from engines.mobile_engine import MobileEngine
    engine = MobileEngine(state.db, state.config)
    result = run_async(engine.generate_report(analysis_id=analysis_id))
    print_result(result, f"Mobile Report: {analysis_id}")


# ─── Status Command ───

@app.command("status")
def status():
    """Show agent status overview."""
    console.print(Panel.fit(
        "[green]CyberSecurity AI Agent[/green]\n"
        f"Database: {state.config.get('database', {}).get('path', './data/hacking_agent.db')}\n"
        f"Web Port: {state.config.get('web', {}).get('port', 8084)}",
        title="Agent Status",
        border_style="green",
    ))

    projects = run_async(state.db.fetch_one("SELECT COUNT(*) as cnt FROM projects WHERE status='active'"))
    targets = run_async(state.db.fetch_one("SELECT COUNT(*) as cnt FROM targets"))
    findings = run_async(state.db.fetch_one("SELECT COUNT(*) as cnt FROM findings"))
    scans = run_async(state.db.fetch_one("SELECT COUNT(*) as cnt FROM scans"))

    table = Table(border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="white", justify="right")
    table.add_row("Active Projects", str(projects["cnt"] if projects else 0))
    table.add_row("Targets", str(targets["cnt"] if targets else 0))
    table.add_row("Findings", str(findings["cnt"] if findings else 0))
    table.add_row("Scans", str(scans["cnt"] if scans else 0))
    console.print(table)
