"""Certificate Transparency Log search via crt.sh."""

import logging

from ._base import BasePlatformClient

logger = logging.getLogger("hacking_agent.platforms.crtsh")


class CRTShClient(BasePlatformClient):
    BASE_URL = "https://crt.sh"

    async def search_certificates(self, domain: str,
                                  wildcard: bool = True) -> dict:
        query = f"%.{domain}" if wildcard else domain
        try:
            result = await self._request("GET", "/", params={
                "q": query, "output": "json"})
            if isinstance(result, list):
                return {"success": True, "certificates": result,
                        "count": len(result)}
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_subdomains(self, domain: str) -> dict:
        result = await self.search_certificates(domain)
        if not result.get("success"):
            return result
        subdomains = set()
        for cert in result.get("certificates", []):
            name = cert.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lower()
                if line and not line.startswith("*"):
                    subdomains.add(line)
        return {
            "success": True,
            "domain": domain,
            "subdomains": sorted(subdomains),
            "count": len(subdomains),
        }

    async def get_certificate(self, cert_id: str) -> dict:
        return await self._request("GET", "/", params={
            "id": cert_id, "output": "json"})
