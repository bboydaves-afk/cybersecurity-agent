"""Base platform client for external security tool integrations."""

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger("hacking_agent.platforms")


class BasePlatformClient(ABC):
    """Abstract base for API-based security platform clients."""

    BASE_URL: str = ""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._client: httpx.AsyncClient | None = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> bool:
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=timeout,
            headers=self._build_headers(),
            follow_redirects=True,
        )
        self._connected = True
        logger.info("%s connected", self.__class__.__name__)
        return True

    async def disconnect(self):
        if self._client:
            await self._client.aclose()
            self._client = None
        self._connected = False
        logger.info("%s disconnected", self.__class__.__name__)

    def _build_headers(self) -> dict:
        return {"User-Agent": "CyberSecurityAgent/1.0"}

    async def _request(self, method: str, url: str, *,
                       max_retries: int = 3, **kwargs) -> dict:
        if not self._connected or not self._client:
            raise RuntimeError(f"{self.__class__.__name__} not connected")

        last_error = None
        for attempt in range(max_retries):
            try:
                response = await self._client.request(method, url, **kwargs)
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    import asyncio
                    logger.warning("Rate limited, waiting %ds (attempt %d/%d)",
                                   retry_after, attempt + 1, max_retries)
                    await asyncio.sleep(retry_after)
                    continue
                response.raise_for_status()
                if response.headers.get("content-type", "").startswith("application/json"):
                    return response.json()
                return {"text": response.text, "status_code": response.status_code}
            except httpx.HTTPStatusError as e:
                last_error = e
                logger.error("HTTP %d from %s: %s", e.response.status_code, url, e)
                break
            except httpx.RequestError as e:
                last_error = e
                logger.error("Request error for %s: %s", url, e)
                if attempt < max_retries - 1:
                    import asyncio
                    await asyncio.sleep(2 ** attempt)
                continue

        return {"error": str(last_error), "success": False}
