"""SQLite CRM database for lead management and email tracking."""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


DB_PATH = Path(__file__).parent / "data" / "outreach.db"


def get_db() -> sqlite3.Connection:
    """Get database connection with row factory."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize all CRM tables."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT NOT NULL,
            contact_name TEXT DEFAULT '',
            contact_email TEXT DEFAULT '',
            contact_title TEXT DEFAULT '',
            industry TEXT DEFAULT '',
            category TEXT DEFAULT '',
            size TEXT DEFAULT '',
            website TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            priority TEXT DEFAULT 'medium' CHECK(priority IN ('high','medium','low')),
            status TEXT DEFAULT 'new' CHECK(status IN ('new','contacted','replied','meeting','proposal','won','lost','paused')),
            source TEXT DEFAULT 'manual',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            email_type TEXT DEFAULT 'initial' CHECK(email_type IN ('initial','followup_1','followup_2','followup_3','custom','reply')),
            direction TEXT DEFAULT 'outbound' CHECK(direction IN ('outbound','inbound')),
            status TEXT DEFAULT 'draft' CHECK(status IN ('draft','queued','sent','failed','opened','replied','bounced')),
            scheduled_at TEXT,
            sent_at TEXT,
            opened_at TEXT,
            replied_at TEXT,
            message_id TEXT,
            error TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sequences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_id INTEGER NOT NULL,
            sequence_name TEXT DEFAULT 'default',
            current_step INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            paused_reason TEXT,
            started_at TEXT DEFAULT (datetime('now')),
            next_action_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lead_id INTEGER NOT NULL,
            interaction_type TEXT NOT NULL CHECK(interaction_type IN ('email_sent','email_received','call','meeting','note','status_change')),
            summary TEXT DEFAULT '',
            details TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (lead_id) REFERENCES leads(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
        CREATE INDEX IF NOT EXISTS idx_leads_priority ON leads(priority);
        CREATE INDEX IF NOT EXISTS idx_emails_lead ON emails(lead_id);
        CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
        CREATE INDEX IF NOT EXISTS idx_sequences_active ON sequences(is_active);
        CREATE INDEX IF NOT EXISTS idx_sequences_next ON sequences(next_action_at);
    """)
    conn.commit()
    conn.close()


# --- Lead CRUD ---

def add_lead(company: str, contact_email: str = "", contact_name: str = "",
             contact_title: str = "", industry: str = "", category: str = "",
             size: str = "", website: str = "", notes: str = "",
             priority: str = "medium", source: str = "manual") -> int:
    conn = get_db()
    cur = conn.execute("""
        INSERT INTO leads (company, contact_email, contact_name, contact_title,
                          industry, category, size, website, notes, priority, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (company, contact_email, contact_name, contact_title,
          industry, category, size, website, notes, priority, source))
    conn.commit()
    lead_id = cur.lastrowid
    conn.close()
    return lead_id


def get_lead(lead_id: int) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_leads(status: str = None, priority: str = None, category: str = None) -> list:
    conn = get_db()
    query = "SELECT * FROM leads WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if priority:
        query += " AND priority = ?"
        params.append(priority)
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, id"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_lead(lead_id: int, **kwargs):
    conn = get_db()
    allowed = {"company", "contact_name", "contact_email", "contact_title",
               "industry", "category", "size", "website", "notes", "priority", "status"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = datetime.now().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    conn.execute(f"UPDATE leads SET {set_clause} WHERE id = ?",
                 list(updates.values()) + [lead_id])
    conn.commit()
    conn.close()


def delete_lead(lead_id: int):
    conn = get_db()
    conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
    conn.commit()
    conn.close()


# --- Email CRUD ---

def add_email(lead_id: int, subject: str, body: str,
              email_type: str = "initial", direction: str = "outbound",
              status: str = "draft", scheduled_at: str = None,
              message_id: str = None) -> int:
    conn = get_db()
    cur = conn.execute("""
        INSERT INTO emails (lead_id, subject, body, email_type, direction, status, scheduled_at, message_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (lead_id, subject, body, email_type, direction, status, scheduled_at, message_id))
    conn.commit()
    email_id = cur.lastrowid
    conn.close()
    return email_id


def get_emails_for_lead(lead_id: int) -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM emails WHERE lead_id = ? ORDER BY created_at", (lead_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_queued_emails() -> list:
    conn = get_db()
    rows = conn.execute("""
        SELECT e.*, l.contact_email, l.contact_name, l.company
        FROM emails e JOIN leads l ON e.lead_id = l.id
        WHERE e.status = 'queued'
        AND (e.scheduled_at IS NULL OR e.scheduled_at <= datetime('now'))
        ORDER BY e.created_at
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_email(email_id: int, **kwargs):
    conn = get_db()
    allowed = {"status", "sent_at", "opened_at", "replied_at", "message_id", "error"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    conn.execute(f"UPDATE emails SET {set_clause} WHERE id = ?",
                 list(updates.values()) + [email_id])
    conn.commit()
    conn.close()


# --- Sequence ---

def start_sequence(lead_id: int, sequence_name: str = "default") -> int:
    conn = get_db()
    # Deactivate existing sequences for this lead
    conn.execute("UPDATE sequences SET is_active = 0 WHERE lead_id = ? AND is_active = 1", (lead_id,))
    cur = conn.execute("""
        INSERT INTO sequences (lead_id, sequence_name, current_step, is_active)
        VALUES (?, ?, 0, 1)
    """, (lead_id, sequence_name))
    conn.commit()
    seq_id = cur.lastrowid
    conn.close()
    return seq_id


def get_active_sequences() -> list:
    conn = get_db()
    rows = conn.execute("""
        SELECT s.*, l.company, l.contact_email, l.contact_name
        FROM sequences s JOIN leads l ON s.lead_id = l.id
        WHERE s.is_active = 1
        ORDER BY s.next_action_at
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_sequence(seq_id: int, **kwargs):
    conn = get_db()
    allowed = {"current_step", "is_active", "paused_reason", "next_action_at", "completed_at"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    conn.execute(f"UPDATE sequences SET {set_clause} WHERE id = ?",
                 list(updates.values()) + [seq_id])
    conn.commit()
    conn.close()


# --- Interactions ---

def add_interaction(lead_id: int, interaction_type: str, summary: str = "", details: str = ""):
    conn = get_db()
    conn.execute("""
        INSERT INTO interactions (lead_id, interaction_type, summary, details)
        VALUES (?, ?, ?, ?)
    """, (lead_id, interaction_type, summary, details))
    conn.commit()
    conn.close()


def get_interactions(lead_id: int) -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM interactions WHERE lead_id = ? ORDER BY created_at DESC",
                        (lead_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- Settings ---

def set_setting(key: str, value: str):
    conn = get_db()
    conn.execute("""
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')
    """, (key, value, value))
    conn.commit()
    conn.close()


def get_setting(key: str, default: str = "") -> str:
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


# --- Stats ---

def get_pipeline_stats() -> dict:
    conn = get_db()
    stats = {}
    for status in ["new", "contacted", "replied", "meeting", "proposal", "won", "lost", "paused"]:
        row = conn.execute("SELECT COUNT(*) as c FROM leads WHERE status = ?", (status,)).fetchone()
        stats[status] = row["c"]
    row = conn.execute("SELECT COUNT(*) as c FROM leads").fetchone()
    stats["total"] = row["c"]
    row = conn.execute("SELECT COUNT(*) as c FROM emails WHERE status = 'sent'").fetchone()
    stats["emails_sent"] = row["c"]
    row = conn.execute("SELECT COUNT(*) as c FROM emails WHERE status = 'replied'").fetchone()
    stats["replies"] = row["c"]
    conn.close()
    return stats
