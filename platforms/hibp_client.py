"""HaveIBeenPwned v3 API client."""

import hashlib
import logging
import os

from ._base import BasePlatformClient

logger = logging.getLogger("hacking_agent.platforms.hibp")


class HIBPClient(BasePlatformClient):
    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self._api_key = os.environ.get(
            self.config.get("api_key_env", "HIBP_API_KEY"), "")

    def _build_headers(self) -> dict:
        headers = {
            "User-Agent": "CyberSecurityAgent/1.0",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["hibp-api-key"] = self._api_key
        return headers

    async def check_breach(self, email: str) -> dict:
        result = await self._request(
            "GET", f"/breachedaccount/{email}",
            params={"truncateResponse": "false"})
        if isinstance(result, list):
            return {"success": True, "breaches": result, "breached": True}
        if "error" in result and "404" in str(result.get("error", "")):
            return {"success": True, "breaches": [], "breached": False}
        return result

    async def get_breaches(self) -> dict:
        return await self._request("GET", "/breaches")

    async def get_breach(self, name: str) -> dict:
        return await self._request("GET", f"/breach/{name}")

    async def check_password(self, password: str) -> dict:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}")
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    hash_suffix, count = line.split(":")
                    if hash_suffix.strip() == suffix:
                        return {
                            "success": True,
                            "pwned": True,
                            "count": int(count.strip()),
                        }
            return {"success": True, "pwned": False, "count": 0}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_pastes(self, email: str) -> dict:
        return await self._request("GET", f"/pasteaccount/{email}")
