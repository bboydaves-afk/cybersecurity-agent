"""VirusTotal v3 API client."""

import logging
import os

from ._base import BasePlatformClient

logger = logging.getLogger("hacking_agent.platforms.virustotal")


class VirusTotalClient(BasePlatformClient):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self._api_key = os.environ.get(
            self.config.get("api_key_env", "VIRUSTOTAL_API_KEY"), "")

    def _build_headers(self) -> dict:
        return {
            "x-apikey": self._api_key,
            "User-Agent": "CyberSecurityAgent/1.0",
        }

    async def scan_url(self, url: str) -> dict:
        return await self._request("POST", "/urls", data={"url": url})

    async def get_url_report(self, url_id: str) -> dict:
        return await self._request("GET", f"/urls/{url_id}")

    async def scan_file(self, file_path: str) -> dict:
        import aiofiles
        async with aiofiles.open(file_path, "rb") as f:
            content = await f.read()
        return await self._request("POST", "/files",
                                   files={"file": content})

    async def get_file_report(self, file_hash: str) -> dict:
        return await self._request("GET", f"/files/{file_hash}")

    async def get_domain_report(self, domain: str) -> dict:
        return await self._request("GET", f"/domains/{domain}")

    async def get_ip_report(self, ip: str) -> dict:
        return await self._request("GET", f"/ip_addresses/{ip}")

    async def get_domain_subdomains(self, domain: str) -> dict:
        return await self._request("GET", f"/domains/{domain}/subdomains")

    async def get_domain_dns(self, domain: str) -> dict:
        return await self._request("GET",
                                   f"/domains/{domain}/resolutions")
