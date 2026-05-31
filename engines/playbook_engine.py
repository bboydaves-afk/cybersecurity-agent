"""Playbook execution engine for automated security workflows."""

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hacking_agent.engines.playbook")


class PlaybookEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = (config or {}).get("engines", {}).get("playbook", {})
        self._executions = {}
        self._playbooks_dir = Path(__file__).parent.parent / "data" / "playbooks"

    async def load_playbook(self, playbook_name: str) -> dict:
        """Load and parse YAML playbook from data/playbooks/{name}.yaml."""
        try:
            import yaml

            if not playbook_name.endswith(".yaml"):
                playbook_name = f"{playbook_name}.yaml"

            playbook_path = self._playbooks_dir / playbook_name

            if not playbook_path.exists():
                return {
                    "success": False,
                    "error": f"Playbook not found: {playbook_name}",
                    "path": str(playbook_path),
                }

            with open(playbook_path, "r", encoding="utf-8") as f:
                playbook_data = yaml.safe_load(f)

            if not playbook_data:
                return {"success": False, "error": "Empty playbook file"}

            await self.db.audit("load_playbook", description=f"Loaded playbook: {playbook_name}",
                                details={"playbook": playbook_name})

            return {
                "success": True,
                "playbook_name": playbook_name,
                "playbook_path": str(playbook_path),
                "data": playbook_data,
                "name": playbook_data.get("name"),
                "description": playbook_data.get("description"),
                "version": playbook_data.get("version"),
                "phases": len(playbook_data.get("phases", [])),
            }

        except Exception as e:
            logger.error("Failed to load playbook %s: %s", playbook_name, e)
            return {"success": False, "error": str(e)}

    async def list_playbooks(self) -> dict:
        """List available playbooks from data/playbooks/*.yaml."""
        try:
            import yaml

            playbooks = []

            if not self._playbooks_dir.exists():
                return {"success": True, "playbooks": [], "count": 0,
                        "error": f"Playbooks directory not found: {self._playbooks_dir}"}

            for yaml_file in self._playbooks_dir.glob("*.yaml"):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)

                    playbooks.append({
                        "filename": yaml_file.name,
                        "name": data.get("name", yaml_file.stem),
                        "description": data.get("description", ""),
                        "version": data.get("version", "1.0"),
                        "author": data.get("author", ""),
                        "trigger": data.get("trigger", "manual"),
                        "phases": len(data.get("phases", [])),
                        "path": str(yaml_file),
                    })
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", yaml_file.name, e)
                    playbooks.append({
                        "filename": yaml_file.name,
                        "error": str(e),
                    })

            return {
                "success": True,
                "playbooks": playbooks,
                "count": len(playbooks),
                "directory": str(self._playbooks_dir),
            }

        except Exception as e:
            logger.error("Failed to list playbooks: %s", e)
            return {"success": False, "error": str(e)}

    async def execute_playbook(self, playbook_name: str, project_id: str = None,
                               target_id: str = None, variables: dict = None,
                               dry_run: bool = False) -> dict:
        """Execute a playbook step by step."""
        from core.database import generate_id, utc_now

        execution_id = generate_id("exec-")
        started = utc_now()

        load_result = await self.load_playbook(playbook_name)
        if not load_result.get("success"):
            return load_result

        playbook_data = load_result["data"]
        playbook_title = playbook_data.get("name", playbook_name)
        phases = playbook_data.get("phases", [])

        if dry_run:
            plan = await self._build_execution_plan(playbook_data, variables or {})
            await self.db.audit("execute_playbook", target_id, project_id,
                                f"Dry run: {playbook_title}",
                                {"execution_id": execution_id, "dry_run": True})
            return {
                "success": True,
                "execution_id": execution_id,
                "playbook": playbook_title,
                "dry_run": True,
                "plan": plan,
                "total_phases": len(plan["phases"]),
                "total_steps": sum(len(p["steps"]) for p in plan["phases"]),
            }

        execution_state = {
            "id": execution_id,
            "playbook_name": playbook_name,
            "playbook_title": playbook_title,
            "project_id": project_id,
            "target_id": target_id,
            "variables": variables or {},
            "status": "running",
            "started_at": started,
            "completed_at": None,
            "current_phase": 0,
            "current_step": 0,
            "phases_completed": 0,
            "steps_completed": 0,
            "results": [],
            "errors": [],
        }

        self._executions[execution_id] = execution_state

        await self.db.audit("execute_playbook", target_id, project_id,
                            f"Started execution: {playbook_title}",
                            {"execution_id": execution_id, "phases": len(phases)})

        try:
            for phase_idx, phase in enumerate(phases):
                phase_name = phase.get("name", f"Phase {phase_idx + 1}")
                phase_desc = phase.get("description", "")
                requires_approval = phase.get("requires_approval", False)
                condition = phase.get("condition")

                execution_state["current_phase"] = phase_idx

                if condition:
                    if not self._evaluate_condition(condition, execution_state):
                        logger.info("Skipping phase '%s': condition '%s' not met",
                                    phase_name, condition)
                        execution_state["results"].append({
                            "phase": phase_name,
                            "status": "skipped",
                            "reason": f"Condition not met: {condition}",
                        })
                        continue

                if requires_approval:
                    execution_state["results"].append({
                        "phase": phase_name,
                        "status": "pending_approval",
                        "note": "This phase requires manual approval before execution",
                    })
                    logger.warning("Phase '%s' requires approval - skipping in automated run",
                                   phase_name)
                    continue

                phase_result = {
                    "phase": phase_name,
                    "description": phase_desc,
                    "steps": [],
                }

                steps = phase.get("steps", [])
                for step_idx, step in enumerate(steps):
                    execution_state["current_step"] = step_idx

                    action = step.get("action") or step.get("tool")
                    step_desc = step.get("description", "")
                    params = step.get("params", {})
                    step_condition = step.get("condition")
                    requires_confirmation = step.get("requires_confirmation", False)

                    if step_condition:
                        if not self._evaluate_condition(step_condition, execution_state):
                            phase_result["steps"].append({
                                "action": action,
                                "status": "skipped",
                                "reason": f"Condition not met: {step_condition}",
                            })
                            continue

                    if requires_confirmation:
                        phase_result["steps"].append({
                            "action": action,
                            "status": "pending_confirmation",
                            "note": "This step requires manual confirmation",
                        })
                        continue

                    resolved_params = self._resolve_variables(params, execution_state["variables"])

                    step_result = await self._execute_step(action, resolved_params,
                                                            project_id, target_id)

                    phase_result["steps"].append({
                        "action": action,
                        "description": step_desc,
                        "params": resolved_params,
                        "result": step_result,
                        "status": "completed" if step_result.get("success") else "failed",
                    })

                    execution_state["steps_completed"] += 1

                    if not step_result.get("success"):
                        logger.warning("Step '%s' failed: %s", action,
                                       step_result.get("error", "Unknown error"))

                execution_state["results"].append(phase_result)
                execution_state["phases_completed"] += 1

            execution_state["status"] = "completed"
            execution_state["completed_at"] = utc_now()

            await self.db.audit("execute_playbook", target_id, project_id,
                                f"Completed execution: {playbook_title}",
                                {"execution_id": execution_id,
                                 "phases_completed": execution_state["phases_completed"],
                                 "steps_completed": execution_state["steps_completed"]})

            return {
                "success": True,
                "execution_id": execution_id,
                "playbook": playbook_title,
                "status": execution_state["status"],
                "phases_completed": execution_state["phases_completed"],
                "steps_completed": execution_state["steps_completed"],
                "started_at": started,
                "completed_at": execution_state["completed_at"],
                "results": execution_state["results"],
                "errors": execution_state["errors"],
            }

        except Exception as e:
            logger.error("Playbook execution failed: %s", e)
            execution_state["status"] = "failed"
            execution_state["completed_at"] = utc_now()
            execution_state["errors"].append(str(e))

            await self.db.audit("execute_playbook", target_id, project_id,
                                f"Failed execution: {playbook_title}",
                                {"execution_id": execution_id, "error": str(e)})

            return {
                "success": False,
                "execution_id": execution_id,
                "error": str(e),
                "status": "failed",
                "results": execution_state["results"],
            }

    async def get_execution_status(self, execution_id: str) -> dict:
        """Get status of a running/completed playbook execution."""
        if execution_id not in self._executions:
            return {"success": False, "error": f"Execution {execution_id} not found"}

        state = self._executions[execution_id]

        return {
            "success": True,
            "execution_id": execution_id,
            "playbook": state["playbook_title"],
            "status": state["status"],
            "project_id": state["project_id"],
            "target_id": state["target_id"],
            "started_at": state["started_at"],
            "completed_at": state["completed_at"],
            "current_phase": state["current_phase"],
            "current_step": state["current_step"],
            "phases_completed": state["phases_completed"],
            "steps_completed": state["steps_completed"],
            "results_count": len(state["results"]),
            "errors_count": len(state["errors"]),
        }

    async def list_executions(self, project_id: str = None) -> dict:
        """List all playbook executions for a project."""
        executions = []

        for exec_id, state in self._executions.items():
            if project_id and state["project_id"] != project_id:
                continue

            executions.append({
                "execution_id": exec_id,
                "playbook": state["playbook_title"],
                "status": state["status"],
                "project_id": state["project_id"],
                "target_id": state["target_id"],
                "started_at": state["started_at"],
                "completed_at": state["completed_at"],
                "phases_completed": state["phases_completed"],
                "steps_completed": state["steps_completed"],
            })

        executions.sort(key=lambda x: x["started_at"], reverse=True)

        return {
            "success": True,
            "executions": executions,
            "count": len(executions),
            "project_id": project_id,
        }

    async def cancel_execution(self, execution_id: str) -> dict:
        """Cancel a running execution."""
        from core.database import utc_now

        if execution_id not in self._executions:
            return {"success": False, "error": f"Execution {execution_id} not found"}

        state = self._executions[execution_id]

        if state["status"] != "running":
            return {
                "success": False,
                "error": f"Cannot cancel execution with status: {state['status']}",
            }

        state["status"] = "cancelled"
        state["completed_at"] = utc_now()

        await self.db.audit("cancel_execution", state["target_id"], state["project_id"],
                            f"Cancelled execution: {state['playbook_title']}",
                            {"execution_id": execution_id})

        return {
            "success": True,
            "execution_id": execution_id,
            "status": "cancelled",
            "playbook": state["playbook_title"],
            "phases_completed": state["phases_completed"],
            "steps_completed": state["steps_completed"],
        }

    async def validate_playbook(self, playbook_path: str) -> dict:
        """Validate YAML structure without executing."""
        try:
            import yaml

            path = Path(playbook_path)
            if not path.exists():
                return {"success": False, "error": f"File not found: {playbook_path}"}

            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            errors = []
            warnings = []

            if not data:
                errors.append("Playbook file is empty")
                return {"success": False, "errors": errors}

            if "name" not in data:
                warnings.append("Playbook missing 'name' field")

            if "phases" not in data:
                errors.append("Playbook missing required 'phases' field")
            elif not isinstance(data["phases"], list):
                errors.append("'phases' must be a list")
            else:
                for idx, phase in enumerate(data["phases"]):
                    if not isinstance(phase, dict):
                        errors.append(f"Phase {idx} must be a dictionary")
                        continue

                    if "name" not in phase:
                        warnings.append(f"Phase {idx} missing 'name' field")

                    if "steps" not in phase:
                        errors.append(f"Phase {idx} missing required 'steps' field")
                    elif not isinstance(phase["steps"], list):
                        errors.append(f"Phase {idx} 'steps' must be a list")
                    else:
                        for step_idx, step in enumerate(phase["steps"]):
                            if not isinstance(step, dict):
                                errors.append(f"Phase {idx} step {step_idx} must be a dictionary")
                                continue

                            if "action" not in step and "tool" not in step:
                                errors.append(f"Phase {idx} step {step_idx} missing 'action' or 'tool' field")

            phases_count = len(data.get("phases", []))
            total_steps = sum(len(p.get("steps", [])) for p in data.get("phases", []))

            result = {
                "success": len(errors) == 0,
                "playbook_path": playbook_path,
                "name": data.get("name"),
                "description": data.get("description"),
                "version": data.get("version"),
                "phases": phases_count,
                "total_steps": total_steps,
                "errors": errors,
                "warnings": warnings,
            }

            await self.db.audit("validate_playbook", description=f"Validated playbook: {playbook_path}",
                                details={"valid": len(errors) == 0, "errors": len(errors),
                                         "warnings": len(warnings)})

            return result

        except Exception as e:
            logger.error("Playbook validation failed: %s", e)
            return {"success": False, "error": str(e)}

    async def _build_execution_plan(self, playbook_data: dict, variables: dict) -> dict:
        """Build execution plan for dry run."""
        plan = {
            "name": playbook_data.get("name"),
            "description": playbook_data.get("description"),
            "phases": [],
        }

        for phase in playbook_data.get("phases", []):
            phase_plan = {
                "name": phase.get("name"),
                "description": phase.get("description"),
                "requires_approval": phase.get("requires_approval", False),
                "condition": phase.get("condition"),
                "steps": [],
            }

            for step in phase.get("steps", []):
                action = step.get("action") or step.get("tool")
                params = step.get("params", {})
                resolved_params = self._resolve_variables(params, variables)

                phase_plan["steps"].append({
                    "action": action,
                    "description": step.get("description"),
                    "params": resolved_params,
                    "condition": step.get("condition"),
                    "requires_confirmation": step.get("requires_confirmation", False),
                })

            plan["phases"].append(phase_plan)

        return plan

    def _resolve_variables(self, params: dict, variables: dict) -> dict:
        """Resolve {{variable}} placeholders in parameters."""
        if not isinstance(params, dict):
            return params

        resolved = {}
        for key, value in params.items():
            if isinstance(value, str):
                for var_name, var_value in variables.items():
                    placeholder = f"{{{{{var_name}}}}}"
                    if placeholder in value:
                        value = value.replace(placeholder, str(var_value))
                resolved[key] = value
            elif isinstance(value, dict):
                resolved[key] = self._resolve_variables(value, variables)
            else:
                resolved[key] = value

        return resolved

    def _evaluate_condition(self, condition: str, state: dict) -> bool:
        """Evaluate simple condition string."""
        if not condition:
            return True

        variables = state.get("variables", {})

        condition = condition.strip()

        for var_name, var_value in variables.items():
            condition = condition.replace(var_name, f'"{var_value}"')

        try:
            result = eval(condition, {"__builtins__": {}}, {})
            return bool(result)
        except Exception as e:
            logger.warning("Failed to evaluate condition '%s': %s", condition, e)
            return False

    async def _execute_step(self, action: str, params: dict, project_id: str,
                            target_id: str) -> dict:
        """Execute a single playbook step by calling the appropriate engine method."""
        try:
            engine_map = {
                # Recon engine
                "port_scan": ("recon", "port_scan"),
                "service_enumerate": ("recon", "service_enumerate"),
                "os_fingerprint": ("recon", "os_fingerprint"),
                "subdomain_enumerate": ("recon", "subdomain_enumerate"),
                "dns_recon": ("recon", "dns_recon"),
                "whois_lookup": ("recon", "whois_lookup"),
                "banner_grab": ("recon", "banner_grab"),
                "network_sweep": ("recon", "network_sweep"),

                # Vulnerability engine
                "vulnerability_scan": ("vulnerability", "vulnerability_scan"),
                "search_cve": ("vulnerability", "search_cve"),
                "search_exploits": ("vulnerability", "search_exploits"),
                "check_default_creds": ("vulnerability", "check_default_creds"),
                "scan_virustotal": ("vulnerability", "scan_virustotal"),

                # Web app engine
                "analyze_headers": ("webapp", "analyze_headers"),
                "test_ssl": ("webapp", "test_ssl"),
                "directory_fuzz": ("webapp", "directory_fuzz"),
                "test_cors": ("webapp", "test_cors"),
                "crawl_site": ("webapp", "crawl_site"),

                # Exploit engine
                "generate_payload": ("exploit", "generate_payload"),
                "execute_exploit": ("exploit", "execute_exploit"),
                "start_listener": ("exploit", "start_listener"),
                "privilege_escalation_check": ("exploit", "privilege_escalation_check"),
                "extract_data": ("exploit", "extract_data"),
                "lateral_movement": ("exploit", "lateral_movement"),
                "establish_persistence": ("exploit", "establish_persistence"),

                # Reporting engine
                "calculate_risk_score": ("reporting", "calculate_risk_score"),
                "suggest_remediation": ("reporting", "suggest_remediation"),
                "generate_report": ("reporting", "generate_report"),
            }

            if action not in engine_map:
                logger.warning("Unknown action: %s", action)
                return {
                    "success": False,
                    "error": f"Unknown action: {action}",
                    "note": "Action not mapped to any engine method",
                }

            engine_name, method_name = engine_map[action]

            engine = self._get_engine(engine_name)
            if not engine:
                return {
                    "success": False,
                    "error": f"Engine not available: {engine_name}",
                }

            method = getattr(engine, method_name, None)
            if not method:
                return {
                    "success": False,
                    "error": f"Method not found: {engine_name}.{method_name}",
                }

            final_params = {**params, "project_id": project_id, "target_id": target_id}

            result = await method(**final_params)

            return result

        except Exception as e:
            logger.error("Step execution failed for action '%s': %s", action, e)
            return {"success": False, "error": str(e)}

    def _get_engine(self, engine_name: str):
        """Get engine instance by name (lazy import)."""
        try:
            if engine_name == "recon":
                from engines.recon_engine import ReconEngine
                return ReconEngine(self.db, self.config)
            elif engine_name == "vulnerability":
                from engines.vulnerability_engine import VulnerabilityEngine
                return VulnerabilityEngine(self.db, self.config)
            elif engine_name == "webapp":
                from engines.webapp_engine import WebAppEngine
                return WebAppEngine(self.db, self.config)
            elif engine_name == "exploit":
                from engines.exploit_engine import ExploitEngine
                return ExploitEngine(self.db, self.config)
            elif engine_name == "reporting":
                from engines.reporting_engine import ReportingEngine
                return ReportingEngine(self.db, self.config)
            else:
                logger.warning("Unknown engine: %s", engine_name)
                return None
        except Exception as e:
            logger.error("Failed to import engine %s: %s", engine_name, e)
            return None
