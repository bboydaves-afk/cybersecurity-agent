"""Wireless network security assessment engine."""

import asyncio
import platform
import re
from typing import Dict, List, Optional, Any


class WirelessEngine:
    """Wireless network security assessment engine."""

    def __init__(self, db, config: dict = None):
        """Initialize the wireless engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("wireless", {})
        self.system = platform.system()

    async def scan_wireless_networks(
        self,
        interface: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Scan for WiFi networks.

        Args:
            interface: Network interface to scan with (e.g., wlan0, Wi-Fi)
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and discovered networks
        """
        try:
            from core.database import utc_now

            networks = []

            if self.system == "Windows":
                # Use netsh wlan show networks mode=bssid
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "wlan", "show", "networks", "mode=bssid",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    return {
                        "success": False,
                        "error": f"Scan failed: {stderr.decode()}"
                    }

                # Parse Windows output
                output = stdout.decode('utf-8', errors='ignore')
                networks = self._parse_windows_scan(output)

            elif self.system == "Linux":
                # Try nmcli first, fallback to iwlist
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "nmcli", "-t", "-f", "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                        "dev", "wifi", "list",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()

                    if proc.returncode == 0:
                        output = stdout.decode('utf-8', errors='ignore')
                        networks = self._parse_nmcli_scan(output)
                    else:
                        # Fallback to iwlist
                        proc = await asyncio.create_subprocess_exec(
                            "iwlist", interface, "scan",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, stderr = await proc.communicate()

                        if proc.returncode != 0:
                            return {
                                "success": False,
                                "error": f"Scan failed: {stderr.decode()}"
                            }

                        output = stdout.decode('utf-8', errors='ignore')
                        networks = self._parse_iwlist_scan(output)

                except FileNotFoundError:
                    return {
                        "success": False,
                        "error": "nmcli and iwlist not found. Install network-manager or wireless-tools."
                    }
            else:
                return {
                    "success": False,
                    "error": f"Unsupported platform: {self.system}"
                }

            await self.db.audit(
                action="scan_wireless_networks",
                details={
                    "interface": interface,
                    "networks_found": len(networks)
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "networks": networks,
                "count": len(networks),
                "interface": interface,
                "timestamp": utc_now()
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Wireless scan failed: {str(e)}"
            }

    def _parse_windows_scan(self, output: str) -> List[Dict[str, Any]]:
        """Parse Windows netsh scan output."""
        networks = []
        current_network = {}

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('SSID'):
                if current_network and 'ssid' in current_network:
                    networks.append(current_network)
                current_network = {}
                ssid = line.split(':', 1)[1].strip()
                current_network['ssid'] = ssid

            elif 'BSSID' in line:
                bssid = line.split(':', 1)[1].strip()
                current_network['bssid'] = bssid

            elif 'Signal' in line:
                signal = line.split(':', 1)[1].strip()
                current_network['signal'] = signal

            elif 'Channel' in line:
                channel = line.split(':', 1)[1].strip()
                current_network['channel'] = channel

            elif 'Authentication' in line:
                auth = line.split(':', 1)[1].strip()
                current_network['authentication'] = auth

            elif 'Encryption' in line:
                encryption = line.split(':', 1)[1].strip()
                current_network['encryption'] = encryption

        if current_network and 'ssid' in current_network:
            networks.append(current_network)

        return networks

    def _parse_nmcli_scan(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmcli scan output."""
        networks = []

        for line in output.split('\n'):
            if not line.strip():
                continue

            parts = line.split(':')
            if len(parts) >= 8:
                networks.append({
                    'ssid': parts[0],
                    'bssid': parts[1],
                    'mode': parts[2],
                    'channel': parts[3],
                    'frequency': parts[4],
                    'rate': parts[5],
                    'signal': parts[6],
                    'encryption': parts[7]
                })

        return networks

    def _parse_iwlist_scan(self, output: str) -> List[Dict[str, Any]]:
        """Parse iwlist scan output."""
        networks = []
        current_network = {}

        for line in output.split('\n'):
            line = line.strip()

            if 'Address:' in line:
                if current_network:
                    networks.append(current_network)
                current_network = {}
                bssid = line.split('Address:')[1].strip()
                current_network['bssid'] = bssid

            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip().strip('"')
                current_network['ssid'] = ssid

            elif 'Channel:' in line:
                channel = line.split('Channel:')[1].strip()
                current_network['channel'] = channel

            elif 'Quality=' in line:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                if signal_match:
                    current_network['signal'] = signal_match.group(1) + ' dBm'

            elif 'Encryption key:' in line:
                if 'off' in line:
                    current_network['encryption'] = 'Open'
                else:
                    current_network['encryption'] = 'Encrypted'

            elif 'IE: IEEE 802.11i/WPA2' in line:
                current_network['encryption'] = 'WPA2'

            elif 'IE: WPA Version' in line:
                current_network['encryption'] = 'WPA'

        if current_network:
            networks.append(current_network)

        return networks

    async def analyze_encryption(
        self,
        scan_results: Dict[str, Any],
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Analyze encryption of discovered networks.

        Args:
            scan_results: Results from scan_wireless_networks
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with analysis results and findings
        """
        try:
            from core.database import generate_id, utc_now

            if not scan_results.get("success"):
                return {
                    "success": False,
                    "error": "Invalid scan results"
                }

            networks = scan_results.get("networks", [])
            findings = []

            for network in networks:
                ssid = network.get('ssid', 'Hidden')
                bssid = network.get('bssid', 'Unknown')
                encryption = network.get('encryption', '').upper()
                auth = network.get('authentication', '').upper()

                # Check for open networks
                if 'OPEN' in encryption or encryption == '' or 'OFF' in encryption:
                    finding_id = generate_id("finding")
                    finding = {
                        "finding_id": finding_id,
                        "title": f"Open WiFi Network: {ssid}",
                        "severity": "high",
                        "category": "wireless_security",
                        "description": f"Open wireless network detected with no encryption. SSID: {ssid}, BSSID: {bssid}",
                        "recommendation": "Enable WPA2 or WPA3 encryption on the access point.",
                        "affected_asset": f"{ssid} ({bssid})",
                        "project_id": project_id,
                        "target_id": target_id
                    }
                    findings.append(finding)

                # Check for WEP
                elif 'WEP' in encryption or 'WEP' in auth:
                    finding_id = generate_id("finding")
                    finding = {
                        "finding_id": finding_id,
                        "title": f"Weak Encryption (WEP): {ssid}",
                        "severity": "critical",
                        "category": "wireless_security",
                        "description": f"Network using deprecated WEP encryption. SSID: {ssid}, BSSID: {bssid}. WEP can be cracked in minutes.",
                        "recommendation": "Upgrade to WPA2 or WPA3 immediately.",
                        "affected_asset": f"{ssid} ({bssid})",
                        "project_id": project_id,
                        "target_id": target_id
                    }
                    findings.append(finding)

                # Check for WPA (not WPA2/3)
                elif 'WPA' in encryption and 'WPA2' not in encryption and 'WPA3' not in encryption:
                    finding_id = generate_id("finding")
                    finding = {
                        "finding_id": finding_id,
                        "title": f"Weak Encryption (WPA1): {ssid}",
                        "severity": "medium",
                        "category": "wireless_security",
                        "description": f"Network using WPA1 encryption. SSID: {ssid}, BSSID: {bssid}. WPA1 has known vulnerabilities.",
                        "recommendation": "Upgrade to WPA2 or WPA3.",
                        "affected_asset": f"{ssid} ({bssid})",
                        "project_id": project_id,
                        "target_id": target_id
                    }
                    findings.append(finding)

            # Store findings in database
            if findings:
                for finding in findings:
                    await self.db.execute_commit(
                        """INSERT INTO findings
                           (finding_id, title, severity, category, description, recommendation,
                            affected_asset, project_id, target_id, discovered_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            finding["finding_id"], finding["title"], finding["severity"],
                            finding["category"], finding["description"], finding["recommendation"],
                            finding["affected_asset"], project_id, target_id, utc_now()
                        )
                    )

            await self.db.audit(
                action="analyze_encryption",
                details={
                    "networks_analyzed": len(networks),
                    "findings_created": len(findings)
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "networks_analyzed": len(networks),
                "findings": findings,
                "finding_count": len(findings)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Encryption analysis failed: {str(e)}"
            }

    async def detect_rogue_aps(
        self,
        known_ssids: List[str],
        scan_results: Dict[str, Any],
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Detect rogue access points.

        Args:
            known_ssids: List of authorized SSIDs
            scan_results: Results from scan_wireless_networks
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with rogue AP detection results
        """
        try:
            from core.database import generate_id, utc_now

            if not scan_results.get("success"):
                return {
                    "success": False,
                    "error": "Invalid scan results"
                }

            networks = scan_results.get("networks", [])
            rogue_aps = []
            evil_twins = []
            findings = []

            # Build SSID to BSSID mapping for known networks
            known_ssid_set = set(known_ssids)
            ssid_bssid_map = {}

            for network in networks:
                ssid = network.get('ssid', '')
                bssid = network.get('bssid', '')

                if not ssid or ssid == '':
                    continue

                # Check for unknown SSIDs
                if ssid not in known_ssid_set:
                    rogue_aps.append(network)

                # Track SSID to BSSID mapping for evil twin detection
                if ssid in known_ssid_set:
                    if ssid not in ssid_bssid_map:
                        ssid_bssid_map[ssid] = []
                    ssid_bssid_map[ssid].append(bssid)

            # Detect evil twins (same SSID, different BSSID)
            for ssid, bssids in ssid_bssid_map.items():
                if len(bssids) > 1:
                    evil_twins.append({
                        "ssid": ssid,
                        "bssids": bssids,
                        "count": len(bssids)
                    })

            # Create findings for rogue APs
            for ap in rogue_aps:
                finding_id = generate_id("finding")
                finding = {
                    "finding_id": finding_id,
                    "title": f"Rogue Access Point: {ap.get('ssid', 'Hidden')}",
                    "severity": "high",
                    "category": "wireless_security",
                    "description": f"Unauthorized access point detected. SSID: {ap.get('ssid')}, BSSID: {ap.get('bssid')}, Encryption: {ap.get('encryption')}",
                    "recommendation": "Investigate and remove unauthorized access point. Check physical premises for rogue hardware.",
                    "affected_asset": f"{ap.get('ssid')} ({ap.get('bssid')})",
                    "project_id": project_id,
                    "target_id": target_id
                }
                findings.append(finding)

            # Create findings for evil twins
            for twin in evil_twins:
                finding_id = generate_id("finding")
                finding = {
                    "finding_id": finding_id,
                    "title": f"Possible Evil Twin Attack: {twin['ssid']}",
                    "severity": "critical",
                    "category": "wireless_security",
                    "description": f"Multiple access points broadcasting the same SSID detected. SSID: {twin['ssid']}, BSSIDs: {', '.join(twin['bssids'])}. This may indicate an evil twin attack.",
                    "recommendation": "Verify all access points are authorized. Investigate unknown BSSIDs immediately. Consider implementing 802.1X authentication.",
                    "affected_asset": f"{twin['ssid']}",
                    "project_id": project_id,
                    "target_id": target_id
                }
                findings.append(finding)

            # Store findings
            if findings:
                for finding in findings:
                    await self.db.execute_commit(
                        """INSERT INTO findings
                           (finding_id, title, severity, category, description, recommendation,
                            affected_asset, project_id, target_id, discovered_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            finding["finding_id"], finding["title"], finding["severity"],
                            finding["category"], finding["description"], finding["recommendation"],
                            finding["affected_asset"], project_id, target_id, utc_now()
                        )
                    )

            await self.db.audit(
                action="detect_rogue_aps",
                details={
                    "rogue_aps": len(rogue_aps),
                    "evil_twins": len(evil_twins)
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "rogue_aps": rogue_aps,
                "rogue_count": len(rogue_aps),
                "evil_twins": evil_twins,
                "evil_twin_count": len(evil_twins),
                "findings": findings
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Rogue AP detection failed: {str(e)}"
            }

    async def check_wps(
        self,
        target_bssid: str,
        interface: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check if WPS is enabled on target AP.

        Args:
            target_bssid: Target access point BSSID
            interface: Network interface
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with WPS status and attack commands
        """
        try:
            from core.database import generate_id, utc_now

            # WPS checking typically requires specialized tools
            # Provide command templates for authorized testing
            commands = {
                "wash_scan": f"wash -i {interface} -C",
                "reaver_attack": f"reaver -i {interface} -b {target_bssid} -vv",
                "pixie_dust": f"reaver -i {interface} -b {target_bssid} -K -vv",
                "bully_attack": f"bully {interface} -b {target_bssid} -v 3"
            }

            # Create informational finding
            finding_id = generate_id("finding")
            finding = {
                "finding_id": finding_id,
                "title": f"WPS Enabled Check Required: {target_bssid}",
                "severity": "info",
                "category": "wireless_security",
                "description": f"WPS status should be verified for {target_bssid}. If enabled, WPS is vulnerable to brute force attacks.",
                "recommendation": "Disable WPS on the access point. Use commands provided to test WPS security (authorized testing only).",
                "affected_asset": target_bssid,
                "project_id": project_id,
                "target_id": target_id
            }

            await self.db.execute_commit(
                """INSERT INTO findings
                   (finding_id, title, severity, category, description, recommendation,
                    affected_asset, project_id, target_id, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding["finding_id"], finding["title"], finding["severity"],
                    finding["category"], finding["description"], finding["recommendation"],
                    finding["affected_asset"], project_id, target_id, utc_now()
                )
            )

            await self.db.audit(
                action="check_wps",
                details={"target_bssid": target_bssid, "interface": interface},
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "target": target_bssid,
                "interface": interface,
                "commands": commands,
                "warning": "WPS testing commands provided. Use only with explicit authorization.",
                "finding": finding
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"WPS check failed: {str(e)}"
            }

    async def deauth_detection(
        self,
        interface: str,
        duration: int,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Monitor for deauthentication frames.

        Args:
            interface: Network interface in monitor mode
            duration: Monitoring duration in seconds
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with monitoring commands and instructions
        """
        try:
            from core.database import utc_now

            commands = {
                "aircrack_monitor": f"airodump-ng {interface} --write deauth_capture --output-format pcap",
                "wireshark_filter": "wlan.fc.type_subtype == 0x0c",
                "tshark_monitor": f"tshark -i {interface} -f 'wlan type mgt subtype deauth' -a duration:{duration}",
                "tcpdump_monitor": f"tcpdump -i {interface} -s 0 'wlan[0] == 0xc0' -w deauth_{utc_now()}.pcap"
            }

            instructions = [
                "1. Put interface in monitor mode: airmon-ng start <interface>",
                f"2. Run one of the provided monitoring commands for {duration} seconds",
                "3. Analyze captured deauth frames",
                "4. High frequency of deauth frames may indicate an ongoing attack",
                "5. Note source MAC addresses of deauth frames"
            ]

            await self.db.audit(
                action="deauth_detection",
                details={"interface": interface, "duration": duration},
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "interface": interface,
                "duration": duration,
                "commands": commands,
                "instructions": instructions,
                "warning": "Deauth detection requires monitor mode. Use only for authorized network defense."
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Deauth detection setup failed: {str(e)}"
            }

    async def capture_handshake(
        self,
        target_bssid: str,
        interface: str,
        channel: int,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Provide commands for capturing WPA handshakes.

        Args:
            target_bssid: Target access point BSSID
            interface: Network interface in monitor mode
            channel: WiFi channel
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with capture commands (authorized testing only)
        """
        try:
            from core.database import utc_now

            commands = {
                "airodump_capture": f"airodump-ng -c {channel} --bssid {target_bssid} -w handshake {interface}",
                "hcxdumptool": f"hcxdumptool -i {interface} -o handshake.pcapng --enable_status=1 --filterlist=filter.txt --filtermode=2",
                "verify_handshake": "aircrack-ng -w /path/to/wordlist.txt handshake*.cap",
                "convert_hashcat": "hcxpcapngtool -o handshake.hc22000 handshake.pcapng"
            }

            instructions = [
                "AUTHORIZED TESTING ONLY - Ensure you have written permission",
                "1. Put interface in monitor mode: airmon-ng start <interface>",
                f"2. Set channel: iwconfig {interface} channel {channel}",
                "3. Start airodump-ng capture on target BSSID",
                "4. Wait for a client to connect (or reconnect)",
                "5. Look for 'WPA handshake' message in airodump-ng",
                "6. Stop capture and verify handshake with aircrack-ng"
            ]

            await self.db.audit(
                action="capture_handshake",
                details={
                    "target_bssid": target_bssid,
                    "interface": interface,
                    "channel": channel
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "target": target_bssid,
                "interface": interface,
                "channel": channel,
                "commands": commands,
                "instructions": instructions,
                "warning": "AUTHORIZED TESTING ONLY. Capturing handshakes without authorization is illegal."
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Handshake capture setup failed: {str(e)}"
            }

    async def analyze_wifi_security(
        self,
        interface: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Full wireless security assessment.

        Args:
            interface: Network interface
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with comprehensive wireless security analysis
        """
        try:
            from core.database import utc_now

            # Perform scan
            scan_result = await self.scan_wireless_networks(
                interface=interface,
                project_id=project_id,
                target_id=target_id
            )

            if not scan_result.get("success"):
                return scan_result

            # Analyze encryption
            encryption_analysis = await self.analyze_encryption(
                scan_results=scan_result,
                project_id=project_id,
                target_id=target_id
            )

            # Detect rogue APs (using empty known_ssids for demo)
            known_ssids = self.config.get("known_ssids", [])
            rogue_analysis = await self.detect_rogue_aps(
                known_ssids=known_ssids,
                scan_results=scan_result,
                project_id=project_id,
                target_id=target_id
            )

            await self.db.audit(
                action="analyze_wifi_security",
                details={
                    "interface": interface,
                    "networks_found": len(scan_result.get("networks", [])),
                    "findings": encryption_analysis.get("finding_count", 0) +
                               len(rogue_analysis.get("findings", []))
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "interface": interface,
                "scan": scan_result,
                "encryption_analysis": encryption_analysis,
                "rogue_analysis": rogue_analysis,
                "total_findings": encryption_analysis.get("finding_count", 0) +
                                 len(rogue_analysis.get("findings", []))
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"WiFi security analysis failed: {str(e)}"
            }

    async def get_connected_clients(
        self,
        interface: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """List connected wireless clients.

        Args:
            interface: Network interface
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with connected client information
        """
        try:
            from core.database import utc_now

            clients = []

            if self.system == "Windows":
                proc = await asyncio.create_subprocess_exec(
                    "netsh", "wlan", "show", "interfaces",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    return {
                        "success": False,
                        "error": f"Failed to get interface info: {stderr.decode()}"
                    }

                output = stdout.decode('utf-8', errors='ignore')
                client_info = {}

                for line in output.split('\n'):
                    line = line.strip()
                    if 'SSID' in line and 'BSSID' not in line:
                        ssid = line.split(':', 1)[1].strip()
                        client_info['ssid'] = ssid
                    elif 'BSSID' in line:
                        bssid = line.split(':', 1)[1].strip()
                        client_info['bssid'] = bssid
                    elif 'State' in line:
                        state = line.split(':', 1)[1].strip()
                        client_info['state'] = state

                if client_info:
                    clients.append(client_info)

            elif self.system == "Linux":
                # Use iw dev for client info
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "iw", "dev", interface, "station", "dump",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()

                    if proc.returncode == 0:
                        output = stdout.decode('utf-8', errors='ignore')
                        current_client = {}

                        for line in output.split('\n'):
                            line = line.strip()
                            if line.startswith('Station'):
                                if current_client:
                                    clients.append(current_client)
                                mac = line.split()[1]
                                current_client = {'mac': mac}
                            elif 'signal:' in line:
                                signal = line.split(':')[1].strip()
                                current_client['signal'] = signal
                            elif 'tx bitrate:' in line:
                                bitrate = line.split(':')[1].strip()
                                current_client['tx_bitrate'] = bitrate

                        if current_client:
                            clients.append(current_client)

                except FileNotFoundError:
                    return {
                        "success": False,
                        "error": "iw command not found. Install iw package."
                    }

            await self.db.audit(
                action="get_connected_clients",
                details={
                    "interface": interface,
                    "clients_found": len(clients)
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "interface": interface,
                "clients": clients,
                "count": len(clients)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get connected clients: {str(e)}"
            }

    async def check_wifi_isolation(
        self,
        target_network: str,
        interface: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Test client isolation on wireless network.

        Args:
            target_network: Target network CIDR (e.g., 192.168.1.0/24)
            interface: Network interface
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with isolation test results
        """
        try:
            from core.database import utc_now, generate_id

            # Provide ARP scan command for isolation testing
            commands = {
                "arp_scan": f"arp-scan --interface={interface} {target_network}",
                "nmap_ping": f"nmap -sn -e {interface} {target_network}",
                "fping": f"fping -g {target_network}"
            }

            instructions = [
                "1. Connect to the wireless network to test",
                "2. Run ARP scan on the network subnet",
                "3. If other clients are visible, isolation is NOT enabled",
                "4. If only gateway/AP is visible, isolation IS enabled",
                "5. Client isolation prevents peer-to-peer communication"
            ]

            # Create informational finding
            finding_id = generate_id("finding")
            finding = {
                "finding_id": finding_id,
                "title": f"WiFi Client Isolation Test Required: {target_network}",
                "severity": "info",
                "category": "wireless_security",
                "description": f"Client isolation should be verified for network {target_network}. Use provided commands to test.",
                "recommendation": "Enable client isolation (AP isolation) on wireless networks to prevent peer-to-peer attacks.",
                "affected_asset": target_network,
                "project_id": project_id,
                "target_id": target_id
            }

            await self.db.execute_commit(
                """INSERT INTO findings
                   (finding_id, title, severity, category, description, recommendation,
                    affected_asset, project_id, target_id, discovered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding["finding_id"], finding["title"], finding["severity"],
                    finding["category"], finding["description"], finding["recommendation"],
                    finding["affected_asset"], project_id, target_id, utc_now()
                )
            )

            await self.db.audit(
                action="check_wifi_isolation",
                details={
                    "target_network": target_network,
                    "interface": interface
                },
                project_id=project_id,
                target_id=target_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "target_network": target_network,
                "interface": interface,
                "commands": commands,
                "instructions": instructions,
                "finding": finding
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"WiFi isolation check failed: {str(e)}"
            }

    async def generate_wireless_report(
        self,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate wireless security assessment report.

        Args:
            project_id: Project ID

        Returns:
            Dict with report data
        """
        try:
            from core.database import utc_now

            # Query wireless-related findings
            query = """
                SELECT finding_id, title, severity, category, description,
                       recommendation, affected_asset, discovered_at
                FROM findings
                WHERE category = 'wireless_security'
            """

            params = []
            if project_id:
                query += " AND project_id = ?"
                params.append(project_id)

            query += " ORDER BY severity DESC, discovered_at DESC"

            rows = await self.db.execute_query(query, tuple(params))

            findings = []
            for row in rows:
                findings.append({
                    "finding_id": row[0],
                    "title": row[1],
                    "severity": row[2],
                    "category": row[3],
                    "description": row[4],
                    "recommendation": row[5],
                    "affected_asset": row[6],
                    "discovered_at": row[7]
                })

            # Count by severity
            severity_counts = {
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
                "info": sum(1 for f in findings if f["severity"] == "info")
            }

            report = {
                "title": "Wireless Security Assessment Report",
                "generated_at": utc_now(),
                "project_id": project_id,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "findings": findings,
                "summary": {
                    "critical_issues": severity_counts["critical"],
                    "high_issues": severity_counts["high"],
                    "recommendations": [
                        "Disable WPS on all access points",
                        "Use WPA2 or WPA3 encryption only",
                        "Enable client isolation on guest networks",
                        "Implement 802.1X authentication for corporate networks",
                        "Regularly scan for rogue access points",
                        "Monitor for deauthentication attacks"
                    ]
                }
            }

            await self.db.audit(
                action="generate_wireless_report",
                details={
                    "project_id": project_id,
                    "findings_count": len(findings)
                },
                project_id=project_id,
                timestamp=utc_now()
            )

            return {
                "success": True,
                "report": report
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Report generation failed: {str(e)}"
            }
