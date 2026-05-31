"""Digital forensics engine for log analysis and artifact collection."""

import json
import logging
import os
import re

logger = logging.getLogger("hacking_agent.engines.forensics")


class ForensicsEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = (config or {}).get("engines", {}).get("forensics", {})
        self._output_dir = self.config.get("output_dir", "./data/forensics")
        os.makedirs(self._output_dir, exist_ok=True)

    async def parse_log(self, log_path: str, log_type: str = "auto",
                        project_id: str = None) -> dict:
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return {"success": False, "error": str(e)}

        patterns = {
            "auth": {
                "failed_login": re.compile(r"(Failed password|authentication failure|invalid user)", re.I),
                "successful_login": re.compile(r"(Accepted password|session opened|Accepted publickey)", re.I),
                "sudo": re.compile(r"sudo:", re.I),
            },
            "apache": {
                "error": re.compile(r'\s[45]\d{2}\s'),
                "sqli_attempt": re.compile(r"(union\s+select|or\s+1\s*=\s*1|drop\s+table|--\s*$)", re.I),
                "xss_attempt": re.compile(r"(<script|onerror|onload|javascript:)", re.I),
                "path_traversal": re.compile(r"\.\./"),
            },
            "windows_event": {
                "logon_failure": re.compile(r"(Event ID: 4625|Logon Failure)", re.I),
                "logon_success": re.compile(r"(Event ID: 4624|Successful Logon)", re.I),
                "privilege_use": re.compile(r"(Event ID: 4672|Special privileges)", re.I),
                "account_change": re.compile(r"(Event ID: 4720|Account Created)", re.I),
            },
        }

        if log_type == "auto":
            first_lines = "".join(lines[:20]).lower()
            if "sshd" in first_lines or "pam" in first_lines:
                log_type = "auth"
            elif "apache" in first_lines or "http" in first_lines or "GET /" in first_lines:
                log_type = "apache"
            elif "event id" in first_lines or "windows" in first_lines:
                log_type = "windows_event"
            else:
                log_type = "auth"

        type_patterns = patterns.get(log_type, patterns["auth"])
        matches = {name: [] for name in type_patterns}

        for i, line in enumerate(lines):
            for name, pattern in type_patterns.items():
                if pattern.search(line):
                    matches[name].append({
                        "line_number": i + 1,
                        "content": line.strip()[:200],
                    })

        summary = {name: len(items) for name, items in matches.items()}
        suspicious = sum(summary.values())

        await self.db.audit("parse_log", project_id=project_id,
                            description=f"Log parsed: {log_path} ({log_type}), {suspicious} events")

        return {
            "success": True, "file": log_path, "log_type": log_type,
            "total_lines": len(lines),
            "summary": summary,
            "suspicious_events": suspicious,
            "matches": {k: v[:50] for k, v in matches.items()},
        }

    async def build_timeline(self, project_id: str) -> dict:
        from core.database import utc_now

        events = []

        scans = await self.db.fetch_all(
            "SELECT id, scan_type, started_at, completed_at, status FROM scans WHERE project_id=? ORDER BY started_at",
            (project_id,))
        for scan in scans:
            events.append({
                "timestamp": scan["started_at"],
                "type": "scan",
                "action": scan["scan_type"],
                "status": scan["status"],
                "id": scan["id"],
            })

        findings = await self.db.fetch_all(
            "SELECT id, title, severity, created_at FROM findings WHERE project_id=? ORDER BY created_at",
            (project_id,))
        for f in findings:
            events.append({
                "timestamp": f["created_at"],
                "type": "finding",
                "title": f["title"],
                "severity": f["severity"],
                "id": f["id"],
            })

        exploits = await self.db.fetch_all(
            "SELECT id, technique, success, executed_at FROM exploits WHERE project_id=? ORDER BY executed_at",
            (project_id,))
        for exp in exploits:
            events.append({
                "timestamp": exp["executed_at"],
                "type": "exploit",
                "technique": exp["technique"],
                "success": bool(exp["success"]),
                "id": exp["id"],
            })

        events.sort(key=lambda e: e.get("timestamp", ""))

        await self.db.audit("build_timeline", project_id=project_id,
                            description=f"Timeline built: {len(events)} events")
        return {"success": True, "project_id": project_id,
                "events": events, "total_events": len(events)}

    async def extract_strings(self, file_path: str, min_length: int = 4,
                              project_id: str = None) -> dict:
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
            strings = [s.decode("ascii") for s in ascii_pattern.findall(data)]

            interesting = {
                "urls": [s for s in strings if re.match(r"https?://", s, re.I)],
                "ips": [s for s in strings if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s)],
                "emails": [s for s in strings if re.match(r"[^@]+@[^@]+\.[^@]+", s)],
                "paths": [s for s in strings if re.match(r"[/\\][a-zA-Z]", s)],
                "registry": [s for s in strings if re.match(r"HKEY_|HKLM|HKCU", s, re.I)],
            }

            await self.db.audit("extract_strings", project_id=project_id,
                                description=f"Strings extracted from {file_path}: {len(strings)} total")
            return {
                "success": True, "file": file_path,
                "total_strings": len(strings),
                "interesting": interesting,
                "sample": strings[:100],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_persistence(self, target_os: str = "linux",
                                project_id: str = None, target_id: str = None) -> dict:
        checks = {
            "linux": [
                {"name": "Cron jobs", "command": "crontab -l; ls -la /etc/cron.*; cat /etc/crontab"},
                {"name": "Systemd services", "command": "systemctl list-unit-files --type=service --state=enabled"},
                {"name": "Init scripts", "command": "ls -la /etc/init.d/"},
                {"name": "Shell profiles", "command": "cat ~/.bashrc ~/.bash_profile ~/.profile /etc/profile 2>/dev/null | grep -v '^#'"},
                {"name": "SSH authorized keys", "command": "find / -name authorized_keys 2>/dev/null"},
                {"name": "LD_PRELOAD", "command": "cat /etc/ld.so.preload 2>/dev/null; echo $LD_PRELOAD"},
                {"name": "Kernel modules", "command": "lsmod | head -20"},
                {"name": "SUID binaries (new)", "command": "find / -perm -4000 -newer /etc/passwd 2>/dev/null"},
            ],
            "windows": [
                {"name": "Run keys", "command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"name": "Scheduled tasks", "command": "schtasks /query /fo LIST /v | findstr /i 'TaskName Status'"},
                {"name": "Services", "command": "sc query type= service state= all | findstr /i 'SERVICE_NAME DISPLAY_NAME STATE'"},
                {"name": "Startup folder", "command": "dir /b \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\""},
                {"name": "WMI subscriptions", "command": "wmic /namespace:\\\\root\\subscription PATH __EventConsumer GET /format:list"},
                {"name": "DLL search order", "command": "dir /s /b C:\\Windows\\System32\\*.dll | findstr /i 'missing'"},
            ],
        }

        await self.db.audit("check_persistence", target_id, project_id,
                            f"Persistence check ({target_os})")
        return {
            "success": True, "target_os": target_os,
            "checks": checks.get(target_os, checks["linux"]),
            "note": "Run these commands on the target to check for persistence mechanisms",
        }

    async def collect_artifacts(self, target_id: str, artifact_types: list = None,
                                project_id: str = None) -> dict:
        default_types = ["logs", "configs", "users", "network", "processes", "scheduled_tasks"]
        artifact_types = artifact_types or default_types

        artifact_commands = {
            "logs": {
                "linux": ["cat /var/log/auth.log", "cat /var/log/syslog", "journalctl -n 100"],
                "windows": ["wevtutil qe Security /c:50 /rd:true /f:text"],
            },
            "configs": {
                "linux": ["cat /etc/passwd", "cat /etc/shadow", "cat /etc/hosts", "iptables -L -n"],
                "windows": ["systeminfo", "ipconfig /all", "netsh advfirewall show allprofiles"],
            },
            "users": {
                "linux": ["who", "last -20", "cat /etc/passwd | grep -v nologin"],
                "windows": ["net user", "net localgroup administrators", "query user"],
            },
            "network": {
                "linux": ["netstat -tlnp", "ss -tlnp", "arp -a", "ip route"],
                "windows": ["netstat -ano", "arp -a", "route print", "ipconfig /all"],
            },
            "processes": {
                "linux": ["ps auxf", "top -bn1 | head -20"],
                "windows": ["tasklist /v", "wmic process get name,processid,commandline"],
            },
            "scheduled_tasks": {
                "linux": ["crontab -l", "ls -la /etc/cron.d/"],
                "windows": ["schtasks /query /fo LIST"],
            },
        }

        commands = {}
        for atype in artifact_types:
            if atype in artifact_commands:
                commands[atype] = artifact_commands[atype]

        await self.db.audit("collect_artifacts", target_id, project_id,
                            f"Artifact collection plan for {len(artifact_types)} types")
        return {
            "success": True, "target_id": target_id,
            "artifact_types": artifact_types,
            "commands": commands,
            "note": "Run these commands on the target to collect forensic artifacts",
        }

    async def analyze_malware(self, file_path: str,
                              project_id: str = None) -> dict:
        import hashlib
        import os

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            hashes = {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            }

            file_size = os.path.getsize(file_path)
            entropy = self._calculate_entropy(data)

            ascii_pattern = re.compile(rb"[\x20-\x7e]{6,}")
            strings = [s.decode("ascii") for s in ascii_pattern.findall(data)]

            suspicious_strings = [s for s in strings if any(
                kw in s.lower() for kw in [
                    "cmd.exe", "powershell", "http://", "https://",
                    "socket", "connect", "exec", "system(",
                    "registry", "HKEY_", "CreateProcess",
                ])]

            indicators = {
                "high_entropy": entropy > 7.0,
                "suspicious_strings": len(suspicious_strings) > 0,
                "packed": entropy > 7.5,
            }

            await self.db.audit("analyze_malware", project_id=project_id,
                                description=f"Malware analysis: {file_path}")
            return {
                "success": True, "file": file_path,
                "file_size": file_size, "hashes": hashes,
                "entropy": round(entropy, 2),
                "total_strings": len(strings),
                "suspicious_strings": suspicious_strings[:50],
                "indicators": indicators,
                "recommendation": "Submit hashes to VirusTotal for reputation check",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _calculate_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    async def generate_ioc(self, project_id: str) -> dict:
        from core.database import utc_now

        findings = await self.db.fetch_all(
            "SELECT * FROM findings WHERE project_id=? AND status IN ('open', 'confirmed', 'exploited')",
            (project_id,))
        intel = await self.db.fetch_all(
            "SELECT * FROM threat_intel WHERE id IN (SELECT DISTINCT indicator_value FROM threat_intel)")

        iocs = {"ips": [], "domains": [], "hashes": [], "urls": [], "cves": []}

        for f in findings:
            if f.get("cve_id"):
                iocs["cves"].append(f["cve_id"])

        for i in intel:
            itype = i.get("indicator_type", "")
            val = i.get("indicator_value", "")
            if itype == "ip":
                iocs["ips"].append(val)
            elif itype == "domain":
                iocs["domains"].append(val)
            elif itype in ("hash_md5", "hash_sha1", "hash_sha256"):
                iocs["hashes"].append({"type": itype, "value": val})
            elif itype == "url":
                iocs["urls"].append(val)

        await self.db.audit("generate_ioc", project_id=project_id,
                            description=f"IOC report generated")
        return {"success": True, "project_id": project_id, "iocs": iocs}
