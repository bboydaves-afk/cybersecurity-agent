"""Threat intelligence engine for IOC enrichment and MITRE mapping."""

import json
import logging

logger = logging.getLogger("hacking_agent.engines.threat_intel")


class ThreatIntelEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = config or {}

    async def map_to_mitre(self, finding_id: str = None, technique_id: str = None,
                           project_id: str = None) -> dict:
        from knowledge.loader import get_mitre_attack
        from core.database import utc_now

        mitre = get_mitre_attack()
        tactics = mitre.get("tactics", [])

        if technique_id:
            for tactic in tactics:
                for tech in tactic.get("techniques", []):
                    if tech["id"] == technique_id:
                        return {
                            "success": True, "technique": tech,
                            "tactic": {"id": tactic["id"], "name": tactic["name"]},
                        }
            return {"success": False, "error": f"Technique {technique_id} not found"}

        if finding_id:
            finding = await self.db.fetch_one(
                "SELECT * FROM findings WHERE id=?", (finding_id,))
            if not finding:
                return {"error": f"Finding {finding_id} not found"}

            title_lower = (finding.get("title") or "").lower()
            suggested = []

            keyword_map = {
                "injection": ["T1190", "T1059"],
                "xss": ["T1059.007"],
                "brute force": ["T1110"],
                "credential": ["T1003", "T1110"],
                "privilege escalation": ["T1068", "T1548"],
                "persistence": ["T1053", "T1547"],
                "remote code": ["T1190", "T1203"],
                "phishing": ["T1566"],
                "default credential": ["T1078"],
                "misconfiguration": ["T1190"],
            }

            for keyword, techniques in keyword_map.items():
                if keyword in title_lower:
                    for tid in techniques:
                        for tactic in tactics:
                            for tech in tactic.get("techniques", []):
                                if tech["id"] == tid:
                                    suggested.append({
                                        "technique": tech,
                                        "tactic": tactic["name"],
                                    })

            if finding.get("mitre_technique"):
                await self.db.execute_commit(
                    "UPDATE findings SET mitre_technique=? WHERE id=?",
                    (finding["mitre_technique"], finding_id))

            return {
                "success": True, "finding_id": finding_id,
                "finding_title": finding.get("title"),
                "suggested_techniques": suggested,
            }

        return {"success": False, "error": "Provide finding_id or technique_id"}

    async def enrich_ioc(self, indicator_type: str, indicator_value: str,
                         project_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        enrichment = {"indicator_type": indicator_type,
                      "indicator_value": indicator_value, "sources": {}}

        if indicator_type in ("ip", "domain"):
            try:
                from platforms.virustotal_client import VirusTotalClient
                vt = VirusTotalClient(self.config.get("platforms", {}).get("virustotal", {}))
                await vt.connect()
                if indicator_type == "ip":
                    vt_result = await vt.get_ip_report(indicator_value)
                else:
                    vt_result = await vt.get_domain_report(indicator_value)
                await vt.disconnect()
                enrichment["sources"]["virustotal"] = vt_result
            except Exception as e:
                enrichment["sources"]["virustotal"] = {"error": str(e)}

        if indicator_type == "ip":
            try:
                from platforms.shodan_client import ShodanClient
                shodan = ShodanClient(self.config.get("platforms", {}).get("shodan", {}))
                await shodan.connect()
                shodan_result = await shodan.search_host(indicator_value)
                await shodan.disconnect()
                enrichment["sources"]["shodan"] = shodan_result
            except Exception as e:
                enrichment["sources"]["shodan"] = {"error": str(e)}

        if indicator_type == "domain":
            try:
                from platforms.crtsh_client import CRTShClient
                crtsh = CRTShClient()
                await crtsh.connect()
                ct_result = await crtsh.get_subdomains(indicator_value)
                await crtsh.disconnect()
                enrichment["sources"]["certificate_transparency"] = ct_result
            except Exception as e:
                enrichment["sources"]["crtsh"] = {"error": str(e)}

        intel_id = generate_id("ioc-")
        await self.db.execute_commit(
            "INSERT INTO threat_intel (id, indicator_type, indicator_value, source, raw_data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (intel_id, indicator_type, indicator_value, "enrichment",
             json.dumps(enrichment, default=str), utc_now()))

        await self.db.audit("enrich_ioc", project_id=project_id,
                            description=f"IOC enriched: {indicator_type}={indicator_value}")
        return {"success": True, **enrichment}

    async def check_indicator(self, indicator_type: str, value: str,
                              project_id: str = None) -> dict:
        existing = await self.db.fetch_one(
            "SELECT * FROM threat_intel WHERE indicator_type=? AND indicator_value=?",
            (indicator_type, value))
        if existing:
            return {"success": True, "known": True, "data": existing}

        result = await self.enrich_ioc(indicator_type, value, project_id)
        result["known"] = False
        return result

    async def build_attack_chain(self, project_id: str,
                                 name: str = None) -> dict:
        from core.database import generate_id, utc_now

        findings = await self.db.fetch_all(
            "SELECT * FROM findings WHERE project_id=? AND status IN ('confirmed', 'exploited') ORDER BY created_at",
            (project_id,))

        exploits = await self.db.fetch_all(
            "SELECT * FROM exploits WHERE project_id=? AND success=1 ORDER BY executed_at",
            (project_id,))

        steps = []
        tactics = set()

        for f in findings:
            step = {
                "type": "finding",
                "id": f["id"],
                "title": f["title"],
                "severity": f["severity"],
            }
            if f.get("mitre_technique"):
                step["mitre_technique"] = f["mitre_technique"]
            steps.append(step)

        for e in exploits:
            step = {
                "type": "exploit",
                "id": e["id"],
                "technique": e["technique"],
                "access_level": e.get("access_level"),
            }
            steps.append(step)

        chain_id = generate_id("chain-")
        await self.db.execute_commit(
            "INSERT INTO attack_chains (id, project_id, name, description, mitre_tactics, steps, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (chain_id, project_id, name or f"Attack Chain - {project_id[:8]}",
             f"Auto-generated attack chain with {len(steps)} steps",
             json.dumps(list(tactics)), json.dumps(steps), utc_now()))

        await self.db.audit("build_attack_chain", project_id=project_id,
                            description=f"Attack chain built: {len(steps)} steps")
        return {
            "success": True, "chain_id": chain_id,
            "steps": steps, "step_count": len(steps),
        }

    async def search_threat_intel(self, query: str,
                                  project_id: str = None) -> dict:
        results = await self.db.fetch_all(
            "SELECT * FROM threat_intel WHERE indicator_value LIKE ? OR tags LIKE ? ORDER BY created_at DESC LIMIT 50",
            (f"%{query}%", f"%{query}%"))

        return {"success": True, "query": query,
                "results": results, "count": len(results)}

    async def get_attack_surface(self, project_id: str) -> dict:
        targets = await self.db.fetch_all(
            "SELECT * FROM targets WHERE project_id=? AND in_scope=1",
            (project_id,))
        hosts = await self.db.fetch_all(
            "SELECT * FROM network_hosts WHERE project_id=?",
            (project_id,))
        endpoints = await self.db.fetch_all(
            "SELECT we.* FROM web_endpoints we JOIN targets t ON we.target_id=t.id WHERE t.project_id=?",
            (project_id,))

        open_ports = set()
        for h in hosts:
            if h.get("ports"):
                try:
                    ports = json.loads(h["ports"]) if isinstance(h["ports"], str) else h["ports"]
                    for p in ports:
                        if isinstance(p, dict) and p.get("state") == "open":
                            open_ports.add(p.get("port"))
                except Exception:
                    pass

        return {
            "success": True, "project_id": project_id,
            "targets": len(targets),
            "discovered_hosts": len(hosts),
            "web_endpoints": len(endpoints),
            "unique_open_ports": sorted(open_ports),
            "attack_surface_size": len(hosts) + len(endpoints),
        }
