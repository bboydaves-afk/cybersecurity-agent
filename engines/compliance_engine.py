"""Security compliance checking engine."""

import json
import logging

logger = logging.getLogger("hacking_agent.engines.compliance")


class ComplianceEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = config or {}

    async def check_cis(self, target_id: str, benchmark: str = "linux",
                        project_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        from knowledge.loader import get_compliance_frameworks

        frameworks = get_compliance_frameworks()
        cis = frameworks.get("frameworks", {}).get("cis", {})
        categories = cis.get("categories", [])

        results = []
        passed = 0
        failed = 0
        for cat in categories:
            for check in cat.get("checks", []):
                status = "requires_manual_review"
                results.append({
                    "control_id": cat["id"],
                    "control_name": cat["name"],
                    "check": check,
                    "status": status,
                })
                if status == "pass":
                    passed += 1
                else:
                    failed += 1

        total = len(results)
        score = (passed / total * 100) if total > 0 else 0

        comp_id = generate_id("comp-")
        await self.db.execute_commit(
            "INSERT INTO compliance_results (id, project_id, target_id, framework, total_controls, passed, failed, score, details, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (comp_id, project_id, target_id, "cis", total, passed, failed,
             score, json.dumps(results), utc_now()))

        await self.db.audit("check_cis", target_id, project_id,
                            f"CIS benchmark ({benchmark}): {passed}/{total} passed")
        return {
            "success": True, "framework": "CIS Controls v8",
            "benchmark": benchmark, "total_controls": total,
            "passed": passed, "failed": failed,
            "score": round(score, 1), "results": results,
        }

    async def check_nist(self, target_id: str, controls: list = None,
                         project_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        from knowledge.loader import get_compliance_frameworks

        frameworks = get_compliance_frameworks()
        nist = frameworks.get("frameworks", {}).get("nist", {})
        families = nist.get("families", [])

        results = []
        for family in families:
            if controls and family["id"] not in controls:
                continue
            for ctrl in family.get("key_controls", []):
                results.append({
                    "family": family["id"],
                    "family_name": family["name"],
                    "control": ctrl,
                    "status": "requires_review",
                })

        total = len(results)
        comp_id = generate_id("comp-")
        await self.db.execute_commit(
            "INSERT INTO compliance_results (id, project_id, target_id, framework, total_controls, details, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (comp_id, project_id, target_id, "nist", total,
             json.dumps(results), utc_now()))

        await self.db.audit("check_nist", target_id, project_id,
                            f"NIST 800-53: {total} controls reviewed")
        return {
            "success": True, "framework": "NIST 800-53 Rev 5",
            "total_controls": total, "results": results,
        }

    async def check_pci_dss(self, target_id: str,
                            project_id: str = None) -> dict:
        from core.database import generate_id, utc_now
        from knowledge.loader import get_compliance_frameworks

        frameworks = get_compliance_frameworks()
        pci = frameworks.get("frameworks", {}).get("pci_dss", {})
        requirements = pci.get("requirements", [])

        results = []
        for req in requirements:
            results.append({
                "requirement_id": req["id"],
                "requirement_name": req["name"],
                "status": "requires_review",
            })

        total = len(results)
        comp_id = generate_id("comp-")
        await self.db.execute_commit(
            "INSERT INTO compliance_results (id, project_id, target_id, framework, total_controls, details, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (comp_id, project_id, target_id, "pci_dss", total,
             json.dumps(results), utc_now()))

        await self.db.audit("check_pci_dss", target_id, project_id,
                            f"PCI-DSS v4.0: {total} requirements")
        return {
            "success": True, "framework": "PCI-DSS v4.0",
            "total_requirements": total, "results": results,
        }

    async def generate_compliance_report(self, project_id: str,
                                         framework: str = None) -> dict:
        from core.database import utc_now

        query = "SELECT * FROM compliance_results WHERE project_id=?"
        params = [project_id]
        if framework:
            query += " AND framework=?"
            params.append(framework)
        query += " ORDER BY checked_at DESC"

        results = await self.db.fetch_all(query, tuple(params))

        summary = {}
        for r in results:
            fw = r["framework"]
            if fw not in summary:
                summary[fw] = {"total": 0, "passed": 0, "failed": 0, "score": 0}
            summary[fw]["total"] += r.get("total_controls", 0)
            summary[fw]["passed"] += r.get("passed", 0)
            summary[fw]["failed"] += r.get("failed", 0)
            if r.get("score"):
                summary[fw]["score"] = r["score"]

        await self.db.audit("generate_compliance_report", project_id=project_id,
                            description=f"Compliance report generated")
        return {"success": True, "project_id": project_id,
                "frameworks": summary, "details": results}

    async def get_compliance_summary(self, project_id: str) -> dict:
        results = await self.db.fetch_all(
            "SELECT framework, total_controls, passed, failed, score, checked_at FROM compliance_results WHERE project_id=? ORDER BY checked_at DESC",
            (project_id,))

        latest = {}
        for r in results:
            fw = r["framework"]
            if fw not in latest:
                latest[fw] = r

        return {"success": True, "project_id": project_id,
                "frameworks": latest}

    async def map_findings_to_framework(self, project_id: str,
                                        framework: str = "owasp") -> dict:
        findings = await self.db.fetch_all(
            "SELECT * FROM findings WHERE project_id=? AND status != 'false_positive'",
            (project_id,))

        mapping = {}
        for f in findings:
            cat = f.get("owasp_category") or f.get("cwe_id") or "Uncategorized"
            if cat not in mapping:
                mapping[cat] = []
            mapping[cat].append({
                "id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
            })

        await self.db.audit("map_findings_to_framework", project_id=project_id,
                            description=f"Findings mapped to {framework}")
        return {"success": True, "framework": framework,
                "mapping": mapping, "total_findings": len(findings)}
