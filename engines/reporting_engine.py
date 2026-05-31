"""Penetration test reporting engine."""

import json
import logging
import os
from datetime import datetime

logger = logging.getLogger("hacking_agent.engines.reporting")


class ReportingEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = (config or {}).get("engines", {}).get("reporting", {})
        self._output_dir = self.config.get("output_dir", "./data/reports")
        os.makedirs(self._output_dir, exist_ok=True)

    async def create_finding(self, project_id: str, title: str,
                             severity: str, description: str = None,
                             target_id: str = None, cve_id: str = None,
                             cwe_id: str = None, owasp_category: str = None,
                             evidence: dict = None, remediation: str = None,
                             mitre_technique: str = None) -> dict:
        from core.database import generate_id, utc_now
        find_id = generate_id("find-")
        await self.db.execute_commit(
            "INSERT INTO findings (id, project_id, target_id, title, description, severity, cve_id, cwe_id, owasp_category, evidence, remediation, mitre_technique, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (find_id, project_id, target_id, title, description, severity,
             cve_id, cwe_id, owasp_category,
             json.dumps(evidence) if evidence else None,
             remediation, mitre_technique, "open", utc_now()))

        await self.db.audit("create_finding", target_id, project_id,
                            f"Finding created: {title} ({severity})")
        return {"success": True, "finding_id": find_id, "title": title,
                "severity": severity}

    async def update_finding(self, finding_id: str, status: str = None,
                             severity: str = None, remediation: str = None,
                             notes: str = None) -> dict:
        from core.database import utc_now
        updates = []
        params = []
        if status:
            updates.append("status=?")
            params.append(status)
        if severity:
            updates.append("severity=?")
            params.append(severity)
        if remediation:
            updates.append("remediation=?")
            params.append(remediation)
        updates.append("updated_at=?")
        params.append(utc_now())
        params.append(finding_id)

        await self.db.execute_commit(
            f"UPDATE findings SET {', '.join(updates)} WHERE id=?",
            tuple(params))

        await self.db.audit("update_finding",
                            description=f"Finding {finding_id} updated")
        return {"success": True, "finding_id": finding_id}

    async def generate_report(self, project_id: str,
                              report_type: str = "full_pentest",
                              format: str = "html") -> dict:
        from core.database import generate_id, utc_now

        project = await self.db.fetch_one(
            "SELECT * FROM projects WHERE id=?", (project_id,))
        if not project:
            return {"error": f"Project {project_id} not found"}

        findings = await self.db.fetch_all(
            "SELECT * FROM findings WHERE project_id=? AND status != 'false_positive' ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
            (project_id,))

        targets = await self.db.fetch_all(
            "SELECT * FROM targets WHERE project_id=?", (project_id,))

        scans = await self.db.fetch_all(
            "SELECT * FROM scans WHERE project_id=? ORDER BY started_at",
            (project_id,))

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1
        )

        report_id = generate_id("rpt-")
        title = f"{project['name']} - Penetration Test Report"

        if format == "html":
            html = self._generate_html_report(
                project, findings, targets, scans, severity_counts, risk_score, title)
            file_name = f"{report_id}.html"
            file_path = os.path.join(self._output_dir, file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html)
        elif format == "json":
            report_data = {
                "title": title, "project": project,
                "findings": findings, "targets": targets,
                "severity_counts": severity_counts,
                "risk_score": risk_score,
                "generated_at": utc_now(),
            }
            file_name = f"{report_id}.json"
            file_path = os.path.join(self._output_dir, file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)
        elif format == "markdown":
            md = self._generate_markdown_report(
                project, findings, targets, severity_counts, risk_score, title)
            file_name = f"{report_id}.md"
            file_path = os.path.join(self._output_dir, file_name)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(md)
        else:
            file_path = ""

        await self.db.execute_commit(
            "INSERT INTO reports (id, project_id, title, report_type, format, file_path, finding_count, critical_count, high_count, generated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (report_id, project_id, title, report_type, format, file_path,
             len(findings), severity_counts["critical"],
             severity_counts["high"], utc_now()))

        await self.db.audit("generate_report", project_id=project_id,
                            description=f"Report generated: {title} ({format})")
        return {
            "success": True, "report_id": report_id, "title": title,
            "format": format, "file_path": file_path,
            "finding_count": len(findings), "risk_score": risk_score,
            "severity_counts": severity_counts,
        }

    def _generate_html_report(self, project, findings, targets, scans,
                               severity_counts, risk_score, title):
        severity_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#17a2b8", "info": "#6c757d",
        }

        findings_html = ""
        for i, f in enumerate(findings, 1):
            color = severity_colors.get(f.get("severity", "info"), "#6c757d")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 15px; margin: 10px 0; background: #1a1a2e;">
                <h3>{i}. {f.get('title', 'Untitled')}</h3>
                <span class="badge" style="background:{color}; padding:3px 10px; border-radius:3px; color:white;">{f.get('severity', 'info').upper()}</span>
                {f'<span style="color:#888;"> | CVSS: {f["cvss_score"]}</span>' if f.get('cvss_score') else ''}
                {f'<span style="color:#888;"> | {f["cve_id"]}</span>' if f.get('cve_id') else ''}
                <p style="margin-top:10px;">{f.get('description', 'No description')}</p>
                {f'<p><strong>Remediation:</strong> {f["remediation"]}</p>' if f.get('remediation') else ''}
            </div>"""

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #0f0f23; color: #e0e0e0; margin: 40px; }}
h1 {{ color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }}
h2 {{ color: #00ccff; margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
th {{ background: #1a1a3e; color: #00ff88; }}
tr:nth-child(even) {{ background: #1a1a2e; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
.summary-card {{ padding: 20px; border-radius: 8px; text-align: center; }}
.summary-card h3 {{ margin: 0; font-size: 2em; }}
.summary-card p {{ margin: 5px 0 0 0; font-size: 0.9em; text-transform: uppercase; }}
</style></head><body>
<h1>{title}</h1>
<p><strong>Client:</strong> {project.get('client', 'N/A')} |
<strong>Type:</strong> {project.get('project_type', 'pentest')} |
<strong>Date:</strong> {project.get('start_date', 'N/A')} |
<strong>Risk Score:</strong> {risk_score}</p>

<h2>Executive Summary</h2>
<div class="summary-grid">
    <div class="summary-card" style="background:#dc354530;"><h3>{severity_counts['critical']}</h3><p>Critical</p></div>
    <div class="summary-card" style="background:#fd7e1430;"><h3>{severity_counts['high']}</h3><p>High</p></div>
    <div class="summary-card" style="background:#ffc10730;"><h3>{severity_counts['medium']}</h3><p>Medium</p></div>
    <div class="summary-card" style="background:#17a2b830;"><h3>{severity_counts['low']}</h3><p>Low</p></div>
    <div class="summary-card" style="background:#6c757d30;"><h3>{severity_counts['info']}</h3><p>Info</p></div>
</div>

<h2>Scope ({len(targets)} targets)</h2>
<table><tr><th>Target</th><th>Type</th><th>In Scope</th></tr>
{''.join(f"<tr><td>{t.get('value','')}</td><td>{t.get('target_type','')}</td><td>{'Yes' if t.get('in_scope') else 'No'}</td></tr>" for t in targets)}
</table>

<h2>Findings ({len(findings)} total)</h2>
{findings_html}

<h2>Methodology</h2>
<p>Testing was performed following industry-standard methodologies including OWASP Testing Guide, PTES, and NIST SP 800-115.</p>

<hr><p style="color:#666; font-size:0.8em;">Generated by CyberSecurity Agent | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
</body></html>"""

    def _generate_markdown_report(self, project, findings, targets,
                                   severity_counts, risk_score, title):
        md = f"# {title}\n\n"
        md += f"**Client:** {project.get('client', 'N/A')} | "
        md += f"**Type:** {project.get('project_type', 'pentest')} | "
        md += f"**Risk Score:** {risk_score}\n\n"

        md += "## Executive Summary\n\n"
        md += f"| Severity | Count |\n|----------|-------|\n"
        for sev, count in severity_counts.items():
            md += f"| {sev.upper()} | {count} |\n"
        md += f"\n**Total Findings:** {len(findings)}\n\n"

        md += "## Findings\n\n"
        for i, f in enumerate(findings, 1):
            md += f"### {i}. [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}\n\n"
            if f.get("description"):
                md += f"{f['description']}\n\n"
            if f.get("cvss_score"):
                md += f"**CVSS:** {f['cvss_score']}\n\n"
            if f.get("remediation"):
                md += f"**Remediation:** {f['remediation']}\n\n"
            md += "---\n\n"

        return md

    async def calculate_risk_score(self, project_id: str) -> dict:
        findings = await self.db.fetch_all(
            "SELECT severity FROM findings WHERE project_id=? AND status != 'false_positive'",
            (project_id,))

        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        score = sum(weights.get(f["severity"], 0) for f in findings)
        max_possible = len(findings) * 10 if findings else 1

        severity_counts = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if score == 0:
            rating = "Secure"
        elif score <= 20:
            rating = "Low Risk"
        elif score <= 50:
            rating = "Medium Risk"
        elif score <= 100:
            rating = "High Risk"
        else:
            rating = "Critical Risk"

        return {
            "success": True, "project_id": project_id,
            "risk_score": score, "max_possible": max_possible,
            "rating": rating, "finding_count": len(findings),
            "severity_counts": severity_counts,
        }

    async def suggest_remediation(self, finding_id: str) -> dict:
        finding = await self.db.fetch_one(
            "SELECT * FROM findings WHERE id=?", (finding_id,))
        if not finding:
            return {"error": f"Finding {finding_id} not found"}

        from knowledge.loader import get_exploit_categories, get_owasp_top10

        suggestions = []
        if finding.get("owasp_category"):
            owasp = get_owasp_top10()
            for cat in owasp.get("categories", []):
                if cat["id"] == finding["owasp_category"]:
                    suggestions.extend(cat.get("remediation", []))

        title_lower = (finding.get("title") or "").lower()
        if "xss" in title_lower or "cross-site scripting" in title_lower:
            suggestions.extend([
                "Encode output based on context (HTML, JS, URL, CSS)",
                "Implement Content-Security-Policy header",
                "Validate and sanitize all user input",
            ])
        elif "sql" in title_lower and "injection" in title_lower:
            suggestions.extend([
                "Use parameterized queries / prepared statements",
                "Implement input validation and sanitization",
                "Apply least-privilege database permissions",
            ])
        elif "ssl" in title_lower or "tls" in title_lower:
            suggestions.extend([
                "Upgrade to TLS 1.2 or higher",
                "Disable weak cipher suites",
                "Use strong key lengths (RSA 2048+ or ECC 256+)",
            ])

        if not suggestions:
            suggestions = [
                "Review the vulnerability details and apply vendor patches",
                "Implement defense-in-depth controls",
                "Monitor for exploitation attempts",
            ]

        return {
            "success": True, "finding_id": finding_id,
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "suggestions": list(set(suggestions)),
        }

    async def export_findings(self, project_id: str,
                              format: str = "json") -> dict:
        findings = await self.db.fetch_all(
            "SELECT * FROM findings WHERE project_id=? ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
            (project_id,))

        from core.database import generate_id
        export_id = generate_id("export-")

        if format == "json":
            file_path = os.path.join(self._output_dir, f"{export_id}.json")
            with open(file_path, "w") as f:
                json.dump(findings, f, indent=2, default=str)
        elif format == "csv":
            import csv
            file_path = os.path.join(self._output_dir, f"{export_id}.csv")
            if findings:
                with open(file_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=findings[0].keys())
                    writer.writeheader()
                    writer.writerows(findings)
        else:
            return {"error": f"Unsupported format: {format}"}

        return {"success": True, "file_path": file_path,
                "format": format, "finding_count": len(findings)}

    async def get_executive_summary(self, project_id: str) -> dict:
        project = await self.db.fetch_one(
            "SELECT * FROM projects WHERE id=?", (project_id,))
        if not project:
            return {"error": "Project not found"}

        risk = await self.calculate_risk_score(project_id)
        targets = await self.db.fetch_all(
            "SELECT COUNT(*) as cnt FROM targets WHERE project_id=?",
            (project_id,))
        scans = await self.db.fetch_all(
            "SELECT COUNT(*) as cnt FROM scans WHERE project_id=?",
            (project_id,))

        return {
            "success": True,
            "project": project.get("name"),
            "client": project.get("client"),
            "type": project.get("project_type"),
            "target_count": targets[0]["cnt"] if targets else 0,
            "scan_count": scans[0]["cnt"] if scans else 0,
            "risk_assessment": risk,
        }

    async def get_finding_statistics(self, project_id: str) -> dict:
        return await self.calculate_risk_score(project_id)
