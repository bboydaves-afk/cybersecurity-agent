"""Nmap scanner wrapper using python-nmap."""

import asyncio
import logging
from typing import Any

logger = logging.getLogger("hacking_agent.platforms.nmap")


class NmapClient:
    """Wrapper around python-nmap for async port scanning."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._nmap_path = self.config.get("path", "nmap")
        self._default_timing = self.config.get("default_timing", "T3")

    async def scan(self, target: str, ports: str = "1-1000",
                   arguments: str = "", timing: str = None) -> dict:
        try:
            import nmap
            scanner = nmap.PortScanner(nmap_search_path=(self._nmap_path,))
            timing = timing or self._default_timing
            args = f"-{timing} {arguments}".strip()
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: scanner.scan(target, ports, arguments=args))
            hosts = []
            for host in scanner.all_hosts():
                host_data = {
                    "host": host,
                    "hostname": scanner[host].hostname(),
                    "state": scanner[host].state(),
                    "protocols": {},
                }
                for proto in scanner[host].all_protocols():
                    ports_list = []
                    for port in sorted(scanner[host][proto].keys()):
                        port_info = scanner[host][proto][port]
                        ports_list.append({
                            "port": port,
                            "state": port_info.get("state", ""),
                            "service": port_info.get("name", ""),
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "extrainfo": port_info.get("extrainfo", ""),
                        })
                    host_data["protocols"][proto] = ports_list
                hosts.append(host_data)
            return {
                "success": True,
                "command_line": scanner.command_line(),
                "hosts": hosts,
                "scan_stats": scanner.scanstats(),
            }
        except Exception as e:
            logger.error("Nmap scan failed: %s", e)
            return {"success": False, "error": str(e)}

    async def service_scan(self, target: str, ports: str = None) -> dict:
        return await self.scan(target, ports or "1-65535", arguments="-sV")

    async def os_detect(self, target: str) -> dict:
        return await self.scan(target, arguments="-O --osscan-guess")

    async def script_scan(self, target: str, scripts: str = "default",
                          ports: str = None) -> dict:
        return await self.scan(target, ports or "1-1000",
                               arguments=f"--script={scripts}")

    async def vuln_scan(self, target: str, ports: str = None) -> dict:
        return await self.scan(target, ports or "1-1000",
                               arguments="--script=vuln")

    async def quick_scan(self, target: str) -> dict:
        return await self.scan(target, ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
                               timing="T4")
