"""Async SQLite database for CyberSecurity Agent."""

import aiosqlite
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("hacking_agent.database")


def generate_id(prefix: str = "") -> str:
    short = uuid.uuid4().hex[:12]
    return f"{prefix}{short}" if prefix else short


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, db_path: str = "./data/hacking_agent.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._create_tables()
        logger.info("Database connected: %s", self.db_path)

    async def close(self):
        if self._db:
            await self._db.close()
            self._db = None
            logger.info("Database closed")

    async def execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        return await self._db.execute(sql, params)

    async def execute_commit(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        cursor = await self._db.execute(sql, params)
        await self._db.commit()
        return cursor

    async def fetch_one(self, sql: str, params: tuple = ()) -> dict | None:
        cursor = await self._db.execute(sql, params)
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        cursor = await self._db.execute(sql, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def audit(self, action_type: str, target_id: str = None,
                    project_id: str = None, description: str = "",
                    details: dict = None, result: str = None):
        await self.execute_commit(
            "INSERT INTO audit_log (id, timestamp, actor, action_type, target_id, project_id, description, details, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (generate_id("aud-"), utc_now(), "agent", action_type, target_id,
             project_id, description, json.dumps(details) if details else None, result))

    async def _create_tables(self):
        statements = [
            # 1. projects
            """CREATE TABLE IF NOT EXISTS projects (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                client          TEXT,
                project_type    TEXT CHECK (project_type IN ('pentest','red_team','bug_bounty','ctf','audit','assessment')),
                status          TEXT DEFAULT 'active' CHECK (status IN ('active','completed','paused','cancelled')),
                start_date      TEXT,
                end_date        TEXT,
                scope_notes     TEXT,
                rules_of_engagement TEXT,
                created_at      TEXT,
                metadata        TEXT
            )""",
            # 2. targets
            """CREATE TABLE IF NOT EXISTS targets (
                id              TEXT PRIMARY KEY,
                project_id      TEXT NOT NULL,
                target_type     TEXT CHECK (target_type IN ('host','network','web_app','api','cloud','domain','wireless')),
                value           TEXT NOT NULL,
                hostname        TEXT,
                ip_address      TEXT,
                in_scope        INTEGER DEFAULT 1,
                os_guess        TEXT,
                notes           TEXT,
                created_at      TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id)",
            # 3. scans
            """CREATE TABLE IF NOT EXISTS scans (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                scan_type       TEXT NOT NULL CHECK (scan_type IN ('port_scan','service_enum','vuln_scan','web_scan','dir_fuzz','dns_enum','subdomain_enum','ssl_scan','cloud_audit','compliance_check','arp_scan','os_fingerprint','banner_grab','network_sweep','api_scan','wireless_scan','container_scan','ad_scan','secrets_scan','email_scan','osint_scan','mobile_scan')),
                status          TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
                parameters      TEXT,
                results         TEXT,
                finding_count   INTEGER DEFAULT 0,
                started_at      TEXT,
                completed_at    TEXT,
                duration_seconds REAL,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id)",
            "CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)",
            # 4. findings
            """CREATE TABLE IF NOT EXISTS findings (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                scan_id         TEXT,
                title           TEXT NOT NULL,
                description     TEXT,
                severity        TEXT CHECK (severity IN ('critical','high','medium','low','info')),
                cvss_score      REAL,
                cvss_vector     TEXT,
                cve_id          TEXT,
                cwe_id          TEXT,
                owasp_category  TEXT,
                evidence        TEXT,
                remediation     TEXT,
                status          TEXT DEFAULT 'open' CHECK (status IN ('open','confirmed','exploited','false_positive','remediated','accepted_risk')),
                mitre_technique TEXT,
                created_at      TEXT,
                updated_at      TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (target_id) REFERENCES targets(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
            "CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id)",
            # 5. network_hosts
            """CREATE TABLE IF NOT EXISTS network_hosts (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                ip_address      TEXT NOT NULL,
                hostname        TEXT,
                mac_address     TEXT,
                os_name         TEXT,
                os_version      TEXT,
                os_accuracy     INTEGER,
                status          TEXT DEFAULT 'up',
                last_seen       TEXT,
                ports           TEXT,
                services        TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_hosts_ip ON network_hosts(ip_address)",
            # 6. web_endpoints
            """CREATE TABLE IF NOT EXISTS web_endpoints (
                id              TEXT PRIMARY KEY,
                target_id       TEXT,
                url             TEXT NOT NULL,
                method          TEXT DEFAULT 'GET',
                status_code     INTEGER,
                content_type    TEXT,
                content_length  INTEGER,
                headers         TEXT,
                parameters      TEXT,
                technologies    TEXT,
                notes           TEXT,
                discovered_at   TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )""",
            # 7. credentials_found
            """CREATE TABLE IF NOT EXISTS credentials_found (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                finding_id      TEXT,
                credential_type TEXT CHECK (credential_type IN ('password','hash','token','api_key','ssh_key','cookie','certificate','other')),
                username        TEXT,
                value           TEXT,
                source          TEXT,
                cracked         INTEGER DEFAULT 0,
                plaintext       TEXT,
                created_at      TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            # 8. exploits
            """CREATE TABLE IF NOT EXISTS exploits (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                finding_id      TEXT,
                exploit_type    TEXT CHECK (exploit_type IN ('remote_code_exec','privilege_escalation','lateral_movement','data_exfil','credential_access','persistence','command_injection','sqli','xss','other')),
                technique       TEXT,
                payload         TEXT,
                result          TEXT,
                success         INTEGER DEFAULT 0,
                access_level    TEXT,
                session_id      TEXT,
                executed_at     TEXT,
                notes           TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            )""",
            # 9. sessions
            """CREATE TABLE IF NOT EXISTS sessions (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                exploit_id      TEXT,
                session_type    TEXT CHECK (session_type IN ('shell','meterpreter','ssh','rdp','vnc','web_shell','other')),
                status          TEXT DEFAULT 'active' CHECK (status IN ('active','closed','lost','backgrounded')),
                access_level    TEXT,
                local_address   TEXT,
                remote_address  TEXT,
                opened_at       TEXT,
                closed_at       TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            # 10. compliance_results
            """CREATE TABLE IF NOT EXISTS compliance_results (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                framework       TEXT CHECK (framework IN ('cis','nist','pci_dss','iso27001','owasp','hipaa')),
                total_controls  INTEGER DEFAULT 0,
                passed          INTEGER DEFAULT 0,
                failed          INTEGER DEFAULT 0,
                not_applicable  INTEGER DEFAULT 0,
                score           REAL,
                details         TEXT,
                checked_at      TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            # 11. reports
            """CREATE TABLE IF NOT EXISTS reports (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                title           TEXT NOT NULL,
                report_type     TEXT CHECK (report_type IN ('executive_summary','technical_detail','compliance','vulnerability_summary','full_pentest')),
                format          TEXT DEFAULT 'html' CHECK (format IN ('html','pdf','json','markdown')),
                file_path       TEXT,
                finding_count   INTEGER DEFAULT 0,
                critical_count  INTEGER DEFAULT 0,
                high_count      INTEGER DEFAULT 0,
                generated_at    TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            # 12. threat_intel
            """CREATE TABLE IF NOT EXISTS threat_intel (
                id              TEXT PRIMARY KEY,
                indicator_type  TEXT CHECK (indicator_type IN ('ip','domain','url','hash_md5','hash_sha1','hash_sha256','email','cve')),
                indicator_value TEXT NOT NULL,
                source          TEXT,
                reputation      TEXT,
                tags            TEXT,
                raw_data        TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                created_at      TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(indicator_type)",
            "CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intel(indicator_value)",
            # 13. attack_chains
            """CREATE TABLE IF NOT EXISTS attack_chains (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                name            TEXT,
                description     TEXT,
                mitre_tactics   TEXT,
                steps           TEXT,
                impact          TEXT,
                created_at      TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            # 14. audit_log
            """CREATE TABLE IF NOT EXISTS audit_log (
                id              TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                actor           TEXT DEFAULT 'agent',
                action_type     TEXT NOT NULL,
                target_id       TEXT,
                project_id      TEXT,
                description     TEXT,
                details         TEXT,
                result          TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id)",
            # 15. chat_history
            """CREATE TABLE IF NOT EXISTS chat_history (
                id              TEXT PRIMARY KEY,
                session_id      TEXT,
                role            TEXT CHECK (role IN ('user','assistant','system')),
                content         TEXT,
                tool_calls      TEXT,
                tokens_used     INTEGER DEFAULT 0,
                timestamp       TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_history(session_id)",
            # 16. playbook_executions
            """CREATE TABLE IF NOT EXISTS playbook_executions (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                playbook_name   TEXT NOT NULL,
                status          TEXT DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','cancelled')),
                variables       TEXT,
                current_phase   TEXT,
                current_step    INTEGER DEFAULT 0,
                total_steps     INTEGER DEFAULT 0,
                results         TEXT,
                started_at      TEXT,
                completed_at    TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_playbook_exec_project ON playbook_executions(project_id)",
            # 17. evidence
            """CREATE TABLE IF NOT EXISTS evidence (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                target_id       TEXT,
                evidence_type   TEXT CHECK (evidence_type IN ('screenshot','packet_capture','log_file','command_output','configuration','credential','exploit_output','document','other')),
                description     TEXT,
                source          TEXT,
                file_path       TEXT,
                file_hash       TEXT,
                file_size       INTEGER,
                collected_at    TEXT,
                collected_by    TEXT DEFAULT 'agent',
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project_id)",
            # 18. custody_chain
            """CREATE TABLE IF NOT EXISTS custody_chain (
                id              TEXT PRIMARY KEY,
                evidence_id     TEXT NOT NULL,
                action          TEXT CHECK (action IN ('collected','transferred','analyzed','presented','archived','exported')),
                handler         TEXT,
                timestamp       TEXT,
                notes           TEXT,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_chain(evidence_id)",
            # 19. scheduled_jobs
            """CREATE TABLE IF NOT EXISTS scheduled_jobs (
                id              TEXT PRIMARY KEY,
                job_name        TEXT NOT NULL,
                scan_type       TEXT,
                target          TEXT,
                schedule_type   TEXT CHECK (schedule_type IN ('cron','interval','once')),
                schedule_config TEXT,
                parameters      TEXT,
                project_id      TEXT,
                enabled         INTEGER DEFAULT 1,
                last_run        TEXT,
                next_run        TEXT,
                created_at      TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_project ON scheduled_jobs(project_id)",
            # 20. notification_channels
            """CREATE TABLE IF NOT EXISTS notification_channels (
                id              TEXT PRIMARY KEY,
                channel_type    TEXT CHECK (channel_type IN ('slack','email','webhook','teams')),
                name            TEXT,
                config          TEXT,
                enabled         INTEGER DEFAULT 1,
                created_at      TEXT
            )""",
            # 21. phishing_campaigns
            """CREATE TABLE IF NOT EXISTS phishing_campaigns (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                name            TEXT NOT NULL,
                template_type   TEXT,
                status          TEXT DEFAULT 'draft' CHECK (status IN ('draft','active','completed','cancelled')),
                targets_count   INTEGER DEFAULT 0,
                emails_sent     INTEGER DEFAULT 0,
                emails_opened   INTEGER DEFAULT 0,
                links_clicked   INTEGER DEFAULT 0,
                creds_submitted INTEGER DEFAULT 0,
                reported        INTEGER DEFAULT 0,
                created_at      TEXT,
                completed_at    TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_phishing_project ON phishing_campaigns(project_id)",
            # 22. secrets_found
            """CREATE TABLE IF NOT EXISTS secrets_found (
                id              TEXT PRIMARY KEY,
                project_id      TEXT,
                secret_type     TEXT,
                file_path       TEXT,
                line_number     INTEGER,
                matched_pattern TEXT,
                value_preview   TEXT,
                entropy         REAL,
                verified        INTEGER DEFAULT 0,
                false_positive  INTEGER DEFAULT 0,
                found_at        TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_secrets_project ON secrets_found(project_id)",
        ]
        for stmt in statements:
            await self._db.execute(stmt)
        await self._db.commit()
        logger.debug("Database tables verified")
