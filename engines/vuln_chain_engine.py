"""Vulnerability chaining and attack path analysis engine."""

import asyncio
from typing import List, Dict, Any, Optional
from core.database import generate_id, utc_now


class VulnChainEngine:
    """Engine for analyzing vulnerability chains and attack paths."""

    def __init__(self, db, config: dict = None):
        """Initialize the vulnerability chain engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("vuln_chain", {})

        # Common vulnerability chains
        self.chain_patterns = {
            "sqli_to_rce": ["sql_injection", "file_write", "command_injection"],
            "ssrf_to_cloud": ["ssrf", "cloud_metadata_access", "credential_theft"],
            "xss_to_hijack": ["xss", "session_token_exposure", "session_hijacking"],
            "info_to_creds": ["information_disclosure", "credential_exposure", "authentication_bypass"],
            "weak_auth_to_privesc": ["weak_authentication", "privilege_escalation", "admin_access"],
            "lfi_to_rce": ["lfi", "file_upload", "code_execution"],
            "xxe_to_ssrf": ["xxe", "ssrf", "internal_network_access"],
            "cors_to_data_theft": ["cors_misconfiguration", "xss", "data_exfiltration"],
            "deserialization_to_rce": ["insecure_deserialization", "code_execution", "reverse_shell"],
            "path_traversal_to_disclosure": ["path_traversal", "file_read", "credential_disclosure"]
        }

        # CVSS multipliers for chain steps
        self.chain_multipliers = {
            1: 1.0,    # Single finding
            2: 1.5,    # Two-step chain
            3: 2.0,    # Three-step chain
            4: 2.5,    # Four-step chain
            5: 3.0     # Five+ step chain
        }

    async def analyze_attack_paths(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Analyze all findings for a project and identify multi-step attack paths.

        Args:
            project_id: Project ID to analyze
            target_id: Optional target ID to filter by

        Returns:
            Dictionary with attack paths
        """
        try:
            # Get all findings for the project
            findings = await self._get_project_findings(project_id, target_id)

            if not findings:
                return {
                    "success": True,
                    "attack_paths": [],
                    "message": "No findings to analyze"
                }

            # Build attack graph
            attack_graph = await self._build_attack_graph(findings)

            # Find all possible paths from entry points to critical assets
            attack_paths = await self._find_attack_paths(attack_graph, findings)

            # Calculate impact for each path
            for path in attack_paths:
                path["risk_score"] = await self._calculate_path_risk(path)
                path["impact_level"] = self._determine_impact_level(path["risk_score"])

            # Sort by risk score
            attack_paths.sort(key=lambda x: x["risk_score"], reverse=True)

            # Store analysis results
            analysis_id = generate_id()
            await self.db.audit(
                action="analyze_attack_paths",
                resource_type="analysis",
                resource_id=analysis_id,
                details={
                    "project_id": project_id,
                    "target_id": target_id,
                    "paths_found": len(attack_paths),
                    "findings_analyzed": len(findings)
                },
                severity="info"
            )

            return {
                "success": True,
                "analysis_id": analysis_id,
                "attack_paths": attack_paths,
                "total_paths": len(attack_paths),
                "critical_paths": len([p for p in attack_paths if p["impact_level"] == "critical"]),
                "high_paths": len([p for p in attack_paths if p["impact_level"] == "high"]),
                "findings_analyzed": len(findings)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def find_chains(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Identify vulnerability chains where multiple findings combine for greater impact.

        Args:
            project_id: Project ID to analyze
            target_id: Optional target ID to filter by

        Returns:
            Dictionary with identified chains
        """
        try:
            findings = await self._get_project_findings(project_id, target_id)

            if not findings:
                return {
                    "success": True,
                    "chains": [],
                    "message": "No findings to analyze"
                }

            chains = []

            # Check each known chain pattern
            for chain_name, pattern in self.chain_patterns.items():
                matched_chain = await self._match_chain_pattern(findings, pattern, chain_name)
                if matched_chain:
                    chains.append(matched_chain)

            # Look for custom chains using graph traversal
            custom_chains = await self._find_custom_chains(findings)
            chains.extend(custom_chains)

            # Calculate risk for each chain
            for chain in chains:
                chain_id = generate_id()
                chain["chain_id"] = chain_id
                chain["risk_score"] = await self.calculate_chain_risk(chain_id, project_id, chain_data=chain)

            # Sort by risk score
            chains.sort(key=lambda x: x["risk_score"], reverse=True)

            await self.db.audit(
                action="find_chains",
                resource_type="analysis",
                resource_id=project_id,
                details={
                    "project_id": project_id,
                    "target_id": target_id,
                    "chains_found": len(chains)
                },
                severity="info"
            )

            return {
                "success": True,
                "chains": chains,
                "total_chains": len(chains),
                "known_patterns": len([c for c in chains if c.get("pattern_type") == "known"]),
                "custom_patterns": len([c for c in chains if c.get("pattern_type") == "custom"])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def calculate_chain_risk(self, chain_id: str, project_id: str = None, target_id: str = None, chain_data: Dict = None) -> float:
        """Calculate combined risk score for a vulnerability chain.

        Args:
            chain_id: Chain ID
            project_id: Project ID
            target_id: Optional target ID
            chain_data: Optional chain data (if not stored)

        Returns:
            Combined risk score
        """
        try:
            if not chain_data:
                # In a real implementation, we'd retrieve from storage
                return 0.0

            findings = chain_data.get("findings", [])

            if not findings:
                return 0.0

            # Calculate base score as average of individual CVSS scores
            base_scores = [f.get("cvss_score", 5.0) for f in findings]
            avg_base_score = sum(base_scores) / len(base_scores)

            # Apply chain multiplier based on number of steps
            chain_length = len(findings)
            multiplier = self.chain_multipliers.get(chain_length, 3.0)

            # Calculate final score (capped at 10.0)
            final_score = min(avg_base_score * multiplier, 10.0)

            return round(final_score, 1)

        except Exception as e:
            return 0.0

    async def suggest_pivot_paths(self, finding_id: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Given a finding, suggest possible pivot points and next steps.

        Args:
            finding_id: Finding ID to pivot from
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with pivot suggestions
        """
        try:
            # Get the finding details
            finding = await self._get_finding(finding_id, project_id)

            if not finding:
                return {
                    "success": False,
                    "error": "Finding not found"
                }

            # Get all findings for context
            all_findings = await self._get_project_findings(project_id, target_id)

            # Determine finding type/category
            finding_type = finding.get("vulnerability_type", "").lower()

            # Generate pivot suggestions based on finding type
            pivots = []

            # Check known chain patterns that start with this finding type
            for chain_name, pattern in self.chain_patterns.items():
                if finding_type in [p.lower() for p in pattern]:
                    # Get position in pattern
                    pattern_lower = [p.lower() for p in pattern]
                    pos = pattern_lower.index(finding_type)

                    # Suggest next steps in the pattern
                    if pos < len(pattern) - 1:
                        next_steps = pattern[pos + 1:]
                        pivots.append({
                            "chain_pattern": chain_name,
                            "current_step": pattern[pos],
                            "next_steps": next_steps,
                            "description": self._get_chain_description(chain_name),
                            "techniques": self._get_pivot_techniques(finding_type, next_steps[0] if next_steps else None)
                        })

            # Check for related findings that could be chained
            related_findings = [f for f in all_findings if f["id"] != finding_id]
            for related in related_findings:
                if self._can_chain(finding, related):
                    pivots.append({
                        "type": "related_finding",
                        "finding_id": related["id"],
                        "vulnerability": related.get("title", "Unknown"),
                        "chain_potential": "high",
                        "description": f"Combine with {related.get('vulnerability_type', 'finding')} for greater impact"
                    })

            await self.db.audit(
                action="suggest_pivot_paths",
                resource_type="finding",
                resource_id=finding_id,
                details={
                    "project_id": project_id,
                    "pivots_found": len(pivots)
                },
                severity="info"
            )

            return {
                "success": True,
                "finding_id": finding_id,
                "finding_type": finding_type,
                "pivot_suggestions": pivots,
                "total_suggestions": len(pivots)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def map_attack_surface(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Build an attack surface map connecting all targets, findings, and potential paths.

        Args:
            project_id: Project ID
            target_id: Optional target ID to filter by

        Returns:
            Dictionary with attack surface map
        """
        try:
            # Get all findings
            findings = await self._get_project_findings(project_id, target_id)

            # Build attack surface map
            attack_surface = {
                "entry_points": [],
                "internal_pivots": [],
                "high_value_targets": [],
                "lateral_movement": [],
                "privilege_escalation": [],
                "data_access": []
            }

            for finding in findings:
                finding_type = finding.get("vulnerability_type", "").lower()
                severity = finding.get("severity", "").lower()

                # Categorize findings by attack surface role
                if any(x in finding_type for x in ["exposed", "disclosure", "enumeration", "weak_auth"]):
                    attack_surface["entry_points"].append({
                        "id": finding["id"],
                        "type": finding_type,
                        "severity": severity,
                        "target": finding.get("target", "unknown")
                    })

                if any(x in finding_type for x in ["lateral", "pivot", "ssrf", "network"]):
                    attack_surface["lateral_movement"].append({
                        "id": finding["id"],
                        "type": finding_type,
                        "severity": severity
                    })

                if "privilege" in finding_type or "escalation" in finding_type:
                    attack_surface["privilege_escalation"].append({
                        "id": finding["id"],
                        "type": finding_type,
                        "severity": severity
                    })

                if any(x in finding_type for x in ["sql", "file_read", "lfi", "path_traversal", "data"]):
                    attack_surface["data_access"].append({
                        "id": finding["id"],
                        "type": finding_type,
                        "severity": severity
                    })

            # Identify internal pivots (findings that enable lateral movement)
            attack_surface["internal_pivots"] = [
                f for f in findings
                if any(x in f.get("vulnerability_type", "").lower() for x in ["ssrf", "xxe", "deserialization"])
            ]

            # Identify high-value targets
            attack_surface["high_value_targets"] = [
                f for f in findings
                if f.get("severity", "").lower() in ["critical", "high"]
                and any(x in f.get("vulnerability_type", "").lower() for x in ["rce", "sql", "auth"])
            ]

            # Calculate attack surface metrics
            metrics = {
                "total_findings": len(findings),
                "entry_points": len(attack_surface["entry_points"]),
                "lateral_movement_options": len(attack_surface["lateral_movement"]),
                "privilege_escalation_paths": len(attack_surface["privilege_escalation"]),
                "data_access_points": len(attack_surface["data_access"]),
                "high_value_targets": len(attack_surface["high_value_targets"]),
                "attack_surface_score": self._calculate_attack_surface_score(attack_surface)
            }

            await self.db.audit(
                action="map_attack_surface",
                resource_type="analysis",
                resource_id=project_id,
                details={
                    "project_id": project_id,
                    "target_id": target_id,
                    "metrics": metrics
                },
                severity="info"
            )

            return {
                "success": True,
                "attack_surface": attack_surface,
                "metrics": metrics
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def simulate_attack(self, chain_id: str, project_id: str = None, target_id: str = None, chain_data: Dict = None) -> Dict[str, Any]:
        """Simulate an attack chain (dry run) with step-by-step description.

        Args:
            chain_id: Chain ID to simulate
            project_id: Project ID
            target_id: Optional target ID
            chain_data: Optional chain data

        Returns:
            Dictionary with simulation results
        """
        try:
            if not chain_data:
                return {
                    "success": False,
                    "error": "Chain data required for simulation"
                }

            findings = chain_data.get("findings", [])
            chain_name = chain_data.get("name", "Custom Chain")

            # Build simulation steps
            simulation = {
                "chain_id": chain_id,
                "chain_name": chain_name,
                "total_steps": len(findings),
                "steps": []
            }

            for idx, finding in enumerate(findings):
                step = {
                    "step_number": idx + 1,
                    "finding_id": finding.get("id"),
                    "vulnerability": finding.get("vulnerability_type", "Unknown"),
                    "severity": finding.get("severity", "Unknown"),
                    "target": finding.get("target", "Unknown"),
                    "actions": self._get_exploit_actions(finding),
                    "expected_outcome": self._get_expected_outcome(finding),
                    "tools_needed": self._get_required_tools(finding),
                    "detection_risk": self._assess_detection_risk(finding)
                }

                # Add chain context
                if idx == 0:
                    step["role"] = "Initial Access"
                    step["description"] = "Gain initial foothold on the target system"
                elif idx == len(findings) - 1:
                    step["role"] = "Objective Achievement"
                    step["description"] = "Achieve final attack objective"
                else:
                    step["role"] = "Privilege Escalation / Lateral Movement"
                    step["description"] = "Expand access and move towards objective"

                simulation["steps"].append(step)

            # Add overall assessment
            simulation["overall_assessment"] = {
                "feasibility": self._assess_feasibility(findings),
                "time_estimate": self._estimate_attack_time(findings),
                "skill_required": self._assess_skill_required(findings),
                "detection_likelihood": self._assess_overall_detection(findings),
                "business_impact": self._assess_business_impact(findings)
            }

            await self.db.audit(
                action="simulate_attack",
                resource_type="chain",
                resource_id=chain_id,
                details={
                    "project_id": project_id,
                    "chain_name": chain_name,
                    "steps": len(findings)
                },
                severity="info"
            )

            return {
                "success": True,
                "simulation": simulation
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def prioritize_remediation(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Prioritize findings by their role in attack chains.

        Args:
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with prioritized remediation list
        """
        try:
            # Get all findings and chains
            findings = await self._get_project_findings(project_id, target_id)
            chains_result = await self.find_chains(project_id, target_id)
            chains = chains_result.get("chains", [])

            # Calculate priority score for each finding
            prioritized = []

            for finding in findings:
                finding_id = finding.get("id")

                # Count how many chains include this finding
                chain_count = sum(1 for chain in chains if finding_id in [f.get("id") for f in chain.get("findings", [])])

                # Check if finding is a critical enabler (first step in high-risk chains)
                is_enabler = sum(
                    1 for chain in chains
                    if chain.get("findings", [{}])[0].get("id") == finding_id
                    and chain.get("risk_score", 0) >= 7.0
                )

                # Base priority from CVSS
                base_priority = finding.get("cvss_score", 5.0)

                # Chain multiplier
                chain_bonus = chain_count * 1.5
                enabler_bonus = is_enabler * 2.0

                # Calculate final priority score
                priority_score = base_priority + chain_bonus + enabler_bonus

                prioritized.append({
                    "finding_id": finding_id,
                    "title": finding.get("title", "Unknown"),
                    "severity": finding.get("severity", "Unknown"),
                    "base_cvss": base_priority,
                    "chain_involvement": chain_count,
                    "is_critical_enabler": is_enabler > 0,
                    "priority_score": round(priority_score, 1),
                    "priority_level": self._get_priority_level(priority_score),
                    "remediation_impact": f"Breaks {chain_count} attack chain(s)" if chain_count > 0 else "Isolated finding"
                })

            # Sort by priority score
            prioritized.sort(key=lambda x: x["priority_score"], reverse=True)

            await self.db.audit(
                action="prioritize_remediation",
                resource_type="analysis",
                resource_id=project_id,
                details={
                    "project_id": project_id,
                    "findings_prioritized": len(prioritized)
                },
                severity="info"
            )

            return {
                "success": True,
                "prioritized_findings": prioritized,
                "total_findings": len(prioritized),
                "critical_priority": len([f for f in prioritized if f["priority_level"] == "critical"]),
                "high_priority": len([f for f in prioritized if f["priority_level"] == "high"])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def generate_chain_report(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Generate attack chain analysis report.

        Args:
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with report data
        """
        try:
            # Gather all analysis data
            chains_result = await self.find_chains(project_id, target_id)
            paths_result = await self.analyze_attack_paths(project_id, target_id)
            surface_result = await self.map_attack_surface(project_id, target_id)
            remediation_result = await self.prioritize_remediation(project_id, target_id)

            report = {
                "report_id": generate_id(),
                "project_id": project_id,
                "target_id": target_id,
                "generated_at": utc_now(),
                "executive_summary": {
                    "total_chains": chains_result.get("total_chains", 0),
                    "total_attack_paths": paths_result.get("total_paths", 0),
                    "critical_paths": paths_result.get("critical_paths", 0),
                    "attack_surface_score": surface_result.get("metrics", {}).get("attack_surface_score", 0),
                    "high_priority_remediations": remediation_result.get("critical_priority", 0) + remediation_result.get("high_priority", 0)
                },
                "chains": chains_result.get("chains", []),
                "attack_paths": paths_result.get("attack_paths", []),
                "attack_surface": surface_result.get("attack_surface", {}),
                "attack_surface_metrics": surface_result.get("metrics", {}),
                "remediation_priorities": remediation_result.get("prioritized_findings", []),
                "recommendations": self._generate_recommendations(
                    chains_result.get("chains", []),
                    paths_result.get("attack_paths", [])
                )
            }

            await self.db.audit(
                action="generate_chain_report",
                resource_type="report",
                resource_id=report["report_id"],
                details={
                    "project_id": project_id,
                    "target_id": target_id
                },
                severity="info"
            )

            return {
                "success": True,
                "report": report
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    # Helper methods

    async def _get_project_findings(self, project_id: str, target_id: str = None) -> List[Dict]:
        """Get all findings for a project."""
        # In a real implementation, query the findings table
        # For now, return mock data structure
        return []

    async def _get_finding(self, finding_id: str, project_id: str) -> Optional[Dict]:
        """Get a specific finding."""
        return None

    async def _build_attack_graph(self, findings: List[Dict]) -> Dict:
        """Build a graph representation of possible attack paths."""
        graph = {"nodes": [], "edges": []}

        for finding in findings:
            graph["nodes"].append({
                "id": finding["id"],
                "type": finding.get("vulnerability_type"),
                "severity": finding.get("severity")
            })

        # Add edges based on possible transitions
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                if self._can_chain(f1, f2):
                    graph["edges"].append({
                        "from": f1["id"],
                        "to": f2["id"],
                        "weight": 1.0
                    })

        return graph

    async def _find_attack_paths(self, graph: Dict, findings: List[Dict]) -> List[Dict]:
        """Find all possible attack paths through the graph."""
        paths = []

        # Simplified path finding - in production, use proper graph algorithms
        # (Dijkstra, BFS, etc.)

        return paths

    async def _calculate_path_risk(self, path: Dict) -> float:
        """Calculate risk score for an attack path."""
        steps = path.get("steps", [])
        if not steps:
            return 0.0

        # Average CVSS with chain multiplier
        avg_cvss = sum(s.get("cvss", 5.0) for s in steps) / len(steps)
        multiplier = self.chain_multipliers.get(len(steps), 3.0)

        return min(avg_cvss * multiplier, 10.0)

    def _determine_impact_level(self, risk_score: float) -> str:
        """Determine impact level from risk score."""
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"

    async def _match_chain_pattern(self, findings: List[Dict], pattern: List[str], chain_name: str) -> Optional[Dict]:
        """Check if findings match a known chain pattern."""
        matched_findings = []

        for pattern_step in pattern:
            for finding in findings:
                if pattern_step.lower() in finding.get("vulnerability_type", "").lower():
                    matched_findings.append(finding)
                    break

        if len(matched_findings) >= 2:  # At least 2 steps matched
            return {
                "name": chain_name,
                "pattern_type": "known",
                "pattern": pattern,
                "findings": matched_findings,
                "completeness": len(matched_findings) / len(pattern)
            }

        return None

    async def _find_custom_chains(self, findings: List[Dict]) -> List[Dict]:
        """Find custom vulnerability chains using graph analysis."""
        chains = []

        # Build dependency graph and find connected components
        # In production, implement proper graph clustering

        return chains

    def _can_chain(self, finding1: Dict, finding2: Dict) -> bool:
        """Determine if two findings can be chained together."""
        # Check if findings are on same or related targets
        # Check if vulnerability types are compatible for chaining

        type1 = finding1.get("vulnerability_type", "").lower()
        type2 = finding2.get("vulnerability_type", "").lower()

        # Simple heuristic - can be expanded
        chainable_pairs = [
            ("sql", "file"),
            ("ssrf", "cloud"),
            ("xss", "session"),
            ("lfi", "upload"),
            ("auth", "privilege")
        ]

        for pair in chainable_pairs:
            if (pair[0] in type1 and pair[1] in type2) or (pair[0] in type2 and pair[1] in type1):
                return True

        return False

    def _get_chain_description(self, chain_name: str) -> str:
        """Get description for a chain pattern."""
        descriptions = {
            "sqli_to_rce": "SQL injection leading to file write and remote code execution",
            "ssrf_to_cloud": "SSRF vulnerability enabling cloud metadata access and credential theft",
            "xss_to_hijack": "XSS vulnerability leading to session token exposure and hijacking",
            "info_to_creds": "Information disclosure revealing credentials and enabling authentication bypass",
            "weak_auth_to_privesc": "Weak authentication leading to privilege escalation and admin access"
        }
        return descriptions.get(chain_name, "Custom vulnerability chain")

    def _get_pivot_techniques(self, current_type: str, next_type: str) -> List[str]:
        """Get techniques for pivoting from current to next vulnerability."""
        techniques = []

        if "sql" in current_type and next_type:
            techniques.append("Use SQLi to write web shell via INTO OUTFILE")
            techniques.append("Extract database credentials and pivot to other services")

        if "ssrf" in current_type:
            techniques.append("Access cloud metadata endpoint (169.254.169.254)")
            techniques.append("Scan internal network for additional services")

        if "xss" in current_type:
            techniques.append("Steal session cookies via document.cookie")
            techniques.append("Perform actions on behalf of victim user")

        return techniques or ["Manual analysis required"]

    def _calculate_attack_surface_score(self, attack_surface: Dict) -> float:
        """Calculate overall attack surface score."""
        score = 0.0

        score += len(attack_surface["entry_points"]) * 1.0
        score += len(attack_surface["lateral_movement"]) * 1.5
        score += len(attack_surface["privilege_escalation"]) * 2.0
        score += len(attack_surface["high_value_targets"]) * 2.5

        return round(min(score, 10.0), 1)

    def _get_exploit_actions(self, finding: Dict) -> List[str]:
        """Get exploit actions for a finding."""
        vuln_type = finding.get("vulnerability_type", "").lower()

        actions = {
            "sql_injection": ["Identify injection point", "Test for UNION-based injection", "Extract database contents"],
            "xss": ["Inject payload", "Capture session cookies", "Execute malicious JavaScript"],
            "ssrf": ["Identify SSRF endpoint", "Access internal resources", "Scan internal network"],
            "rce": ["Identify command injection point", "Execute reverse shell", "Establish persistence"]
        }

        for key, action_list in actions.items():
            if key in vuln_type:
                return action_list

        return ["Exploit vulnerability", "Escalate privileges"]

    def _get_expected_outcome(self, finding: Dict) -> str:
        """Get expected outcome for exploiting a finding."""
        severity = finding.get("severity", "").lower()
        vuln_type = finding.get("vulnerability_type", "").lower()

        if "rce" in vuln_type or "command" in vuln_type:
            return "Remote code execution achieved"
        elif "sql" in vuln_type:
            return "Database access obtained"
        elif "auth" in vuln_type:
            return "Authentication bypassed"
        elif severity in ["critical", "high"]:
            return "Significant system access gained"
        else:
            return "Information disclosed or limited access"

    def _get_required_tools(self, finding: Dict) -> List[str]:
        """Get tools required for exploiting a finding."""
        vuln_type = finding.get("vulnerability_type", "").lower()

        tools = {
            "sql": ["sqlmap", "Burp Suite", "manual SQL queries"],
            "xss": ["XSS Hunter", "Burp Suite", "BeEF"],
            "ssrf": ["curl", "Burp Suite", "Collaborator"],
            "rce": ["Metasploit", "netcat", "reverse shell payloads"],
            "network": ["nmap", "Wireshark", "tcpdump"]
        }

        for key, tool_list in tools.items():
            if key in vuln_type:
                return tool_list

        return ["Standard pentesting tools"]

    def _assess_detection_risk(self, finding: Dict) -> str:
        """Assess detection risk for exploiting a finding."""
        vuln_type = finding.get("vulnerability_type", "").lower()

        if any(x in vuln_type for x in ["rce", "command", "sql"]):
            return "High - Active exploitation likely to trigger alerts"
        elif any(x in vuln_type for x in ["scan", "brute"]):
            return "Medium - May trigger IDS/IPS signatures"
        else:
            return "Low - Passive reconnaissance or stealthy exploitation"

    def _assess_feasibility(self, findings: List[Dict]) -> str:
        """Assess feasibility of executing the attack chain."""
        if len(findings) <= 2:
            return "High - Short chain with few dependencies"
        elif len(findings) <= 4:
            return "Medium - Multiple steps required"
        else:
            return "Low - Complex chain with many dependencies"

    def _estimate_attack_time(self, findings: List[Dict]) -> str:
        """Estimate time required to execute attack chain."""
        if len(findings) <= 2:
            return "1-4 hours"
        elif len(findings) <= 4:
            return "4-8 hours"
        else:
            return "1-3 days"

    def _assess_skill_required(self, findings: List[Dict]) -> str:
        """Assess skill level required for attack chain."""
        severities = [f.get("severity", "").lower() for f in findings]

        if "critical" in severities:
            return "Advanced - Requires deep technical knowledge"
        elif "high" in severities:
            return "Intermediate - Requires solid technical skills"
        else:
            return "Basic - Can be executed with common tools"

    def _assess_overall_detection(self, findings: List[Dict]) -> str:
        """Assess overall detection likelihood for the chain."""
        return "Medium - Some steps may trigger security monitoring"

    def _assess_business_impact(self, findings: List[Dict]) -> str:
        """Assess business impact of successful attack chain."""
        severities = [f.get("severity", "").lower() for f in findings]

        if "critical" in severities:
            return "Critical - Full system compromise, data breach likely"
        elif "high" in severities:
            return "High - Significant unauthorized access"
        else:
            return "Medium - Limited unauthorized access or information disclosure"

    def _get_priority_level(self, priority_score: float) -> str:
        """Get priority level from score."""
        if priority_score >= 15.0:
            return "critical"
        elif priority_score >= 10.0:
            return "high"
        elif priority_score >= 5.0:
            return "medium"
        else:
            return "low"

    def _generate_recommendations(self, chains: List[Dict], paths: List[Dict]) -> List[str]:
        """Generate security recommendations based on chains and paths."""
        recommendations = []

        if chains:
            recommendations.append("Prioritize remediation of findings that appear in multiple attack chains")

        if paths:
            recommendations.append("Focus on breaking attack paths by addressing initial access vectors")

        recommendations.extend([
            "Implement defense-in-depth strategies to prevent chain exploitation",
            "Deploy monitoring and detection for chain-based attack patterns",
            "Regular security assessments to identify new potential chains"
        ])

        return recommendations
