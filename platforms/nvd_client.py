"""National Vulnerability Database (NVD) API client."""

import logging
import os

from ._base import BasePlatformClient

logger = logging.getLogger("hacking_agent.platforms.nvd")


class NVDClient(BasePlatformClient):
    BASE_URL = "https://services.nvd.nist.gov/rest/json"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self._api_key = os.environ.get(
            self.config.get("api_key_env", "NVD_API_KEY"), "")

    def _build_headers(self) -> dict:
        headers = {"User-Agent": "CyberSecurityAgent/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    async def search_cve(self, keyword: str, results_per_page: int = 20) -> dict:
        return await self._request("GET", "/cves/2.0", params={
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        })

    async def get_cve(self, cve_id: str) -> dict:
        return await self._request("GET", "/cves/2.0", params={
            "cveId": cve_id,
        })

    async def search_by_cpe(self, cpe_name: str,
                            results_per_page: int = 20) -> dict:
        return await self._request("GET", "/cves/2.0", params={
            "cpeName": cpe_name,
            "resultsPerPage": results_per_page,
        })

    async def get_cve_history(self, cve_id: str) -> dict:
        return await self._request("GET", "/cvehistory/2.0", params={
            "cveId": cve_id,
        })

    async def search_by_cvss(self, severity: str = "CRITICAL") -> dict:
        return await self._request("GET", "/cves/2.0", params={
            "cvssV3Severity": severity,
            "resultsPerPage": 20,
        })
