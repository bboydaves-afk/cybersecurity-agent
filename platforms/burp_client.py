"""Burp Suite Enterprise/Professional API client."""

import logging
import os

from ._base import BasePlatformClient

logger = logging.getLogger("hacking_agent.platforms.burp")


class BurpClient(BasePlatformClient):
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.BASE_URL = self.config.get("api_url", "http://localhost:1337/v0.1")
        self._api_key = os.environ.get(
            self.config.get("api_key_env", "BURP_API_KEY"), "")

    def _build_headers(self) -> dict:
        headers = {"User-Agent": "CyberSecurityAgent/1.0"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def start_scan(self, urls: list[str],
                         scan_config: str = "default") -> dict:
        return await self._request("POST", "/scan", json={
            "urls": urls,
            "scan_configurations": [{"type": "NamedConfiguration", "name": scan_config}],
        })

    async def get_scan_status(self, scan_id: str) -> dict:
        return await self._request("GET", f"/scan/{scan_id}")

    async def get_findings(self, scan_id: str) -> dict:
        result = await self._request("GET", f"/scan/{scan_id}")
        if "issue_events" in result:
            return {"success": True, "findings": result["issue_events"]}
        return result

    async def list_scans(self) -> dict:
        return await self._request("GET", "/scan")

    async def cancel_scan(self, scan_id: str) -> dict:
        return await self._request("DELETE", f"/scan/{scan_id}")
