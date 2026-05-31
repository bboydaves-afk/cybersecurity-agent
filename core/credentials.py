"""Fernet-encrypted credential manager for CyberSecurity Agent."""

import json
import logging
import os
from cryptography.fernet import Fernet

logger = logging.getLogger("hacking_agent.credentials")


class CredentialManager:
    def __init__(self, db):
        self.db = db
        key = os.environ.get("HACKING_ENCRYPTION_KEY")
        if not key:
            key = Fernet.generate_key().decode()
            logger.warning("No HACKING_ENCRYPTION_KEY set — generated ephemeral key")
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()

    async def store_credential(self, name: str, credential_type: str,
                                value: str, metadata: dict = None) -> str:
        from core.database import generate_id, utc_now
        cred_id = generate_id("cred-")
        encrypted = self.encrypt(value)
        await self.db.execute_commit(
            "INSERT INTO credentials_found (id, credential_type, username, value, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (cred_id, credential_type, name, encrypted, json.dumps(metadata) if metadata else None, utc_now()))
        return cred_id

    async def get_credential(self, cred_id: str) -> dict | None:
        row = await self.db.fetch_one(
            "SELECT * FROM credentials_found WHERE id = ?", (cred_id,))
        if row and row.get("value"):
            try:
                row["value"] = self.decrypt(row["value"])
            except Exception:
                pass
        return row

    async def store_api_key(self, platform: str, api_key: str):
        encrypted = self.encrypt(api_key)
        existing = await self.db.fetch_one(
            "SELECT id FROM credentials_found WHERE source = ? AND credential_type = 'api_key'",
            (f"platform:{platform}",))
        if existing:
            await self.db.execute_commit(
                "UPDATE credentials_found SET value = ? WHERE id = ?",
                (encrypted, existing["id"]))
        else:
            from core.database import generate_id, utc_now
            await self.db.execute_commit(
                "INSERT INTO credentials_found (id, credential_type, username, value, source, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (generate_id("key-"), "api_key", platform, encrypted, f"platform:{platform}", utc_now()))

    async def get_api_key(self, platform: str) -> str | None:
        row = await self.db.fetch_one(
            "SELECT value FROM credentials_found WHERE source = ? AND credential_type = 'api_key'",
            (f"platform:{platform}",))
        if row and row.get("value"):
            try:
                return self.decrypt(row["value"])
            except Exception:
                return None
        return None
