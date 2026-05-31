"""Metasploit Framework RPC API client."""

import asyncio
import logging
import os

logger = logging.getLogger("hacking_agent.platforms.metasploit")


class MetasploitClient:
    """Client for Metasploit RPC API using pymetasploit3."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._host = self.config.get("rpc_host", "127.0.0.1")
        self._port = self.config.get("rpc_port", 55553)
        self._user = self.config.get("rpc_user", "msf")
        self._password = os.environ.get(
            self.config.get("rpc_password_env", "MSF_RPC_PASSWORD"), "")
        self._client = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> bool:
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            loop = asyncio.get_event_loop()
            self._client = await loop.run_in_executor(
                None, lambda: MsfRpcClient(
                    self._password, server=self._host,
                    port=self._port, username=self._user, ssl=True))
            self._connected = True
            logger.info("Connected to Metasploit RPC at %s:%d", self._host, self._port)
            return True
        except Exception as e:
            logger.error("Metasploit connection failed: %s", e)
            return False

    async def disconnect(self):
        self._client = None
        self._connected = False

    async def search_exploits(self, query: str) -> dict:
        if not self._connected:
            return {"error": "Not connected to Metasploit"}
        try:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None, lambda: self._client.modules.search(query))
            return {"success": True, "modules": results[:50]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_module_info(self, module_type: str, module_name: str) -> dict:
        if not self._connected:
            return {"error": "Not connected to Metasploit"}
        try:
            loop = asyncio.get_event_loop()
            mod = await loop.run_in_executor(
                None, lambda: self._client.modules.use(module_type, module_name))
            return {
                "success": True,
                "name": mod.name,
                "description": mod.description,
                "options": {k: str(v) for k, v in mod.options.items()},
                "required": mod.required,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def execute_module(self, module_type: str, module_name: str,
                             options: dict) -> dict:
        if not self._connected:
            return {"error": "Not connected to Metasploit"}
        try:
            loop = asyncio.get_event_loop()
            mod = await loop.run_in_executor(
                None, lambda: self._client.modules.use(module_type, module_name))
            for key, value in options.items():
                mod[key] = value
            result = await loop.run_in_executor(None, mod.execute)
            return {"success": True, "job_id": result.get("job_id"),
                    "uuid": result.get("uuid")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_sessions(self) -> dict:
        if not self._connected:
            return {"error": "Not connected to Metasploit"}
        try:
            loop = asyncio.get_event_loop()
            sessions = await loop.run_in_executor(
                None, lambda: self._client.sessions.list)
            return {"success": True, "sessions": sessions}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def interact_session(self, session_id: str, command: str) -> dict:
        if not self._connected:
            return {"error": "Not connected to Metasploit"}
        try:
            loop = asyncio.get_event_loop()
            shell = await loop.run_in_executor(
                None, lambda: self._client.sessions.session(session_id))
            await loop.run_in_executor(None, lambda: shell.write(command))
            await asyncio.sleep(2)
            output = await loop.run_in_executor(None, shell.read)
            return {"success": True, "output": output}
        except Exception as e:
            return {"success": False, "error": str(e)}
