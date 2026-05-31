"""Shodan API client for internet-wide scanning data."""

import logging
import os

from ._base import BasePlatformClient

logger = logging.getLogger("hacking_agent.platforms.shodan")


class ShodanClient(BasePlatformClient):
    BASE_URL = "https://api.shodan.io"

    def __init__(self, config: dict = None):
        super().__init__(config)
        self._api_key = os.environ.get(
            self.config.get("api_key_env", "SHODAN_API_KEY"), "")

    def _build_headers(self) -> dict:
        return {"User-Agent": "CyberSecurityAgent/1.0"}

    async def search_host(self, ip: str) -> dict:
        return await self._request("GET", f"/shodan/host/{ip}",
                                   params={"key": self._api_key})

    async def search_query(self, query: str, page: int = 1) -> dict:
        return await self._request("GET", "/shodan/host/search",
                                   params={"key": self._api_key, "query": query, "page": page})

    async def get_host_info(self, ip: str, history: bool = False) -> dict:
        params = {"key": self._api_key}
        if history:
            params["history"] = "true"
        return await self._request("GET", f"/shodan/host/{ip}", params=params)

    async def count(self, query: str) -> dict:
        return await self._request("GET", "/shodan/host/count",
                                   params={"key": self._api_key, "query": query})

    async def search_exploits(self, query: str) -> dict:
        return await self._request("GET", "/api-ms/exploits/search",
                                   params={"key": self._api_key, "query": query})

    async def get_ports(self) -> dict:
        return await self._request("GET", "/shodan/ports",
                                   params={"key": self._api_key})

    async def dns_resolve(self, hostnames: list[str]) -> dict:
        return await self._request("GET", "/dns/resolve",
                                   params={"key": self._api_key,
                                           "hostnames": ",".join(hostnames)})

    async def reverse_dns(self, ips: list[str]) -> dict:
        return await self._request("GET", "/dns/reverse",
                                   params={"key": self._api_key,
                                           "ips": ",".join(ips)})
