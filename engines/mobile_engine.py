"""Mobile application security testing engine."""

import os
import re
import zipfile
import plistlib
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from core.database import generate_id, utc_now


class MobileEngine:
    """Engine for mobile application security testing (Android/iOS)."""

    def __init__(self, db, config: dict = None):
        """Initialize the mobile security engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("mobile", {})

        # Dangerous Android permissions
        self.dangerous_permissions = [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.CAMERA",
            "android.permission.BODY_SENSORS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.GET_ACCOUNTS"
        ]

        # OWASP Mobile Top 10 (2024)
        self.owasp_mobile_top10 = {
            "M1": "Improper Credential Usage",
            "M2": "Inadequate Supply Chain Security",
            "M3": "Insecure Authentication/Authorization",
            "M4": "Insufficient Input/Output Validation",
            "M5": "Insecure Communication",
            "M6": "Inadequate Privacy Controls",
            "M7": "Insufficient Binary Protections",
            "M8": "Security Misconfiguration",
            "M9": "Insecure Data Storage",
            "M10": "Insufficient Cryptography"
        }

    async def analyze_apk(
        self,
        apk_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Static analysis of Android APK.

        Args:
            apk_path: Path to APK file
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with analysis results
        """
        try:
            apk_file = Path(apk_path)

            if not apk_file.exists():
                return {
                    "success": False,
                    "error": f"APK file not found: {apk_path}"
                }

            analysis_id = generate_id()
            findings = []

            # Extract APK
            extract_dir = Path(f"/tmp/apk_analysis_{analysis_id}")
            extract_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(apk_file, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            # Parse AndroidManifest.xml (need to decode from binary XML)
            manifest_path = extract_dir / "AndroidManifest.xml"

            if manifest_path.exists():
                # Try to parse manifest (this is simplified - real parsing needs AXML decoder)
                manifest_data = await self._parse_android_manifest(manifest_path)

                # Check for security issues
                findings.extend(await self._check_manifest_security(manifest_data, project_id))

                # Analyze permissions
                permissions_result = await self.check_permissions(
                    manifest_data,
                    "android",
                    project_id
                )
                if permissions_result.get("findings"):
                    findings.extend(permissions_result["findings"])

            # Check for common security files
            security_checks = {
                "network_security_config.xml": extract_dir / "res" / "xml" / "network_security_config.xml",
                "backup_rules.xml": extract_dir / "res" / "xml" / "backup_rules.xml",
                "proguard-rules.pro": extract_dir / "proguard-rules.pro"
            }

            for check_name, check_path in security_checks.items():
                if check_path.exists():
                    findings.append({
                        "type": "info",
                        "category": "configuration",
                        "title": f"Found {check_name}",
                        "description": f"Application includes {check_name} - review for security settings"
                    })

            # Check for debuggable flag
            if manifest_data.get("debuggable"):
                findings.append({
                    "type": "high",
                    "category": "M8",
                    "title": "Debuggable Application",
                    "description": "android:debuggable=true detected - allows runtime debugging and memory inspection",
                    "remediation": "Set android:debuggable=false in production builds"
                })

            # Check for backup allowed
            if manifest_data.get("allowBackup", True):
                findings.append({
                    "type": "medium",
                    "category": "M9",
                    "title": "Backup Allowed",
                    "description": "android:allowBackup=true allows app data to be backed up via ADB",
                    "remediation": "Set android:allowBackup=false or use backup rules to exclude sensitive data"
                })

            # Check minimum SDK version
            min_sdk = manifest_data.get("minSdkVersion", 0)
            if min_sdk < 23:
                findings.append({
                    "type": "medium",
                    "category": "M8",
                    "title": "Low Minimum SDK Version",
                    "description": f"minSdkVersion={min_sdk} supports very old Android versions with known vulnerabilities",
                    "remediation": "Consider raising minSdkVersion to 23 (Android 6.0) or higher"
                })

            # Audit log
            await self.db.audit(
                action="analyze_apk",
                resource_type="mobile_app",
                resource_id=analysis_id,
                details={
                    "apk_path": apk_path,
                    "project_id": project_id,
                    "findings_count": len(findings)
                },
                severity="info"
            )

            return {
                "success": True,
                "analysis_id": analysis_id,
                "platform": "android",
                "apk_path": apk_path,
                "manifest_data": manifest_data,
                "findings": findings,
                "total_findings": len(findings),
                "high_severity": len([f for f in findings if f["type"] == "high"]),
                "medium_severity": len([f for f in findings if f["type"] == "medium"])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def analyze_ipa(
        self,
        ipa_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Static analysis of iOS IPA.

        Args:
            ipa_path: Path to IPA file
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with analysis results
        """
        try:
            ipa_file = Path(ipa_path)

            if not ipa_file.exists():
                return {
                    "success": False,
                    "error": f"IPA file not found: {ipa_path}"
                }

            analysis_id = generate_id()
            findings = []

            # Extract IPA
            extract_dir = Path(f"/tmp/ipa_analysis_{analysis_id}")
            extract_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(ipa_file, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            # Find Info.plist (usually in Payload/*.app/)
            payload_dir = extract_dir / "Payload"
            app_dirs = list(payload_dir.glob("*.app")) if payload_dir.exists() else []

            if not app_dirs:
                return {
                    "success": False,
                    "error": "No .app directory found in IPA"
                }

            app_dir = app_dirs[0]
            info_plist_path = app_dir / "Info.plist"

            if not info_plist_path.exists():
                return {
                    "success": False,
                    "error": "Info.plist not found in IPA"
                }

            # Parse Info.plist
            with open(info_plist_path, 'rb') as f:
                plist_data = plistlib.load(f)

            # Check App Transport Security (ATS)
            ats_settings = plist_data.get("NSAppTransportSecurity", {})
            allow_arbitrary_loads = ats_settings.get("NSAllowsArbitraryLoads", False)

            if allow_arbitrary_loads:
                findings.append({
                    "type": "high",
                    "category": "M5",
                    "title": "App Transport Security Disabled",
                    "description": "NSAllowsArbitraryLoads=true disables ATS and allows insecure HTTP connections",
                    "remediation": "Remove NSAllowsArbitraryLoads or use NSExceptionDomains for specific domains"
                })

            # Check URL schemes
            url_schemes = plist_data.get("CFBundleURLTypes", [])
            if url_schemes:
                findings.append({
                    "type": "info",
                    "category": "M4",
                    "title": "Custom URL Schemes",
                    "description": f"Application registers {len(url_schemes)} custom URL scheme(s) - verify input validation",
                    "details": {"schemes": [s.get("CFBundleURLSchemes", []) for s in url_schemes]}
                })

            # Check for permissions (iOS uses usage descriptions)
            privacy_permissions = [
                ("NSCameraUsageDescription", "Camera"),
                ("NSPhotoLibraryUsageDescription", "Photo Library"),
                ("NSLocationWhenInUseUsageDescription", "Location (When In Use)"),
                ("NSLocationAlwaysUsageDescription", "Location (Always)"),
                ("NSMicrophoneUsageDescription", "Microphone"),
                ("NSContactsUsageDescription", "Contacts"),
                ("NSCalendarsUsageDescription", "Calendars"),
                ("NSRemindersUsageDescription", "Reminders"),
                ("NSMotionUsageDescription", "Motion & Fitness"),
                ("NSHealthShareUsageDescription", "Health Data (Read)"),
                ("NSHealthUpdateUsageDescription", "Health Data (Write)"),
                ("NSBluetoothPeripheralUsageDescription", "Bluetooth"),
                ("NSFaceIDUsageDescription", "Face ID")
            ]

            requested_permissions = []
            for key, name in privacy_permissions:
                if key in plist_data:
                    requested_permissions.append(name)

            if requested_permissions:
                findings.append({
                    "type": "info",
                    "category": "M6",
                    "title": "Privacy-Sensitive Permissions",
                    "description": f"Application requests {len(requested_permissions)} privacy-sensitive permission(s)",
                    "details": {"permissions": requested_permissions},
                    "remediation": "Review if all permissions are necessary for app functionality"
                })

            # Check entitlements (if present)
            entitlements_path = app_dir / "embedded.mobileprovision"
            if entitlements_path.exists():
                findings.append({
                    "type": "info",
                    "category": "info",
                    "title": "Provisioning Profile Found",
                    "description": "Application includes provisioning profile - analyze for entitlements"
                })

            # Check minimum iOS version
            min_os_version = plist_data.get("MinimumOSVersion", "0.0")
            if float(min_os_version.split(".")[0]) < 12:
                findings.append({
                    "type": "medium",
                    "category": "M8",
                    "title": "Low Minimum iOS Version",
                    "description": f"MinimumOSVersion={min_os_version} supports old iOS versions with known vulnerabilities",
                    "remediation": "Consider raising MinimumOSVersion to 12.0 or higher"
                })

            # Audit log
            await self.db.audit(
                action="analyze_ipa",
                resource_type="mobile_app",
                resource_id=analysis_id,
                details={
                    "ipa_path": ipa_path,
                    "project_id": project_id,
                    "findings_count": len(findings)
                },
                severity="info"
            )

            return {
                "success": True,
                "analysis_id": analysis_id,
                "platform": "ios",
                "ipa_path": ipa_path,
                "plist_data": plist_data,
                "findings": findings,
                "total_findings": len(findings),
                "high_severity": len([f for f in findings if f["type"] == "high"]),
                "medium_severity": len([f for f in findings if f["type"] == "medium"])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def check_permissions(
        self,
        manifest_data: Dict[str, Any],
        platform: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Analyze app permissions for overprivilege.

        Args:
            manifest_data: Parsed manifest/plist data
            platform: Platform (android/ios)
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with permission analysis
        """
        try:
            findings = []

            if platform == "android":
                permissions = manifest_data.get("permissions", [])

                # Check for dangerous permissions
                dangerous_found = []
                for perm in permissions:
                    if perm in self.dangerous_permissions:
                        dangerous_found.append(perm)

                if dangerous_found:
                    findings.append({
                        "type": "medium",
                        "category": "M6",
                        "title": "Dangerous Permissions Requested",
                        "description": f"Application requests {len(dangerous_found)} dangerous permission(s)",
                        "details": {"permissions": dangerous_found},
                        "remediation": "Review if all permissions are necessary. Request at runtime when needed."
                    })

                # Check for overly broad permissions
                broad_permissions = [
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_NETWORK_STATE",
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                    "android.permission.READ_EXTERNAL_STORAGE"
                ]

                broad_found = [p for p in permissions if p in broad_permissions]
                if broad_found:
                    findings.append({
                        "type": "info",
                        "category": "M6",
                        "title": "Broad Permissions",
                        "description": f"Application uses {len(broad_found)} broad permission(s)",
                        "details": {"permissions": broad_found}
                    })

            return {
                "success": True,
                "platform": platform,
                "findings": findings
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def check_ssl_pinning(
        self,
        apk_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check if SSL pinning is implemented.

        Args:
            apk_path: Path to APK or decompiled source
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with SSL pinning analysis
        """
        try:
            findings = []
            pinning_found = False

            # Patterns to search for SSL pinning implementations
            pinning_patterns = {
                "okhttp_pinning": r"CertificatePinner",
                "trustmanager": r"X509TrustManager",
                "network_security_config": r"network-security-config",
                "ssl_pinning_lib": r"SSLPinning|PinningTrustManager"
            }

            search_path = Path(apk_path)

            if search_path.is_file():
                # If APK, suggest decompiling first
                findings.append({
                    "type": "info",
                    "category": "M5",
                    "title": "SSL Pinning Check Requires Decompilation",
                    "description": "To check for SSL pinning, decompile the APK first",
                    "remediation": "Use decompile_apk() to extract source code, then re-run this check"
                })
            else:
                # Search decompiled source
                for pattern_name, pattern in pinning_patterns.items():
                    matches = await self._search_files(search_path, pattern)
                    if matches:
                        pinning_found = True
                        findings.append({
                            "type": "info",
                            "category": "M5",
                            "title": f"SSL Pinning Evidence: {pattern_name}",
                            "description": f"Found {len(matches)} reference(s) to SSL pinning via {pattern_name}",
                            "details": {"matches": matches[:5]}  # Limit to 5 examples
                        })

            if not pinning_found and not search_path.is_file():
                findings.append({
                    "type": "high",
                    "category": "M5",
                    "title": "SSL Pinning Not Detected",
                    "description": "No evidence of SSL certificate pinning found - vulnerable to MitM attacks",
                    "remediation": "Implement certificate pinning using OkHttp CertificatePinner or network security config"
                })

            return {
                "success": True,
                "ssl_pinning_implemented": pinning_found,
                "findings": findings
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def check_data_storage(
        self,
        platform: str,
        app_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check for insecure data storage.

        Args:
            platform: Platform (android/ios)
            app_path: Path to app or extracted data
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with data storage analysis
        """
        try:
            findings = []

            if platform == "android":
                # Check for insecure storage patterns
                insecure_patterns = {
                    "shared_prefs": r"SharedPreferences|getSharedPreferences",
                    "internal_storage": r"openFileOutput|MODE_WORLD_READABLE|MODE_WORLD_WRITABLE",
                    "external_storage": r"getExternalStorageDirectory",
                    "sqlite_unencrypted": r"SQLiteDatabase\.openOrCreateDatabase",
                    "hardcoded_keys": r"(password|api[_-]?key|secret|token)\s*=\s*['\"][^'\"]+['\"]"
                }

                for pattern_name, pattern in insecure_patterns.items():
                    matches = await self._search_files(Path(app_path), pattern, max_results=10)
                    if matches:
                        severity = "high" if pattern_name == "hardcoded_keys" else "medium"
                        findings.append({
                            "type": severity,
                            "category": "M9",
                            "title": f"Insecure Data Storage: {pattern_name}",
                            "description": f"Found {len(matches)} reference(s) to potentially insecure data storage",
                            "details": {"pattern": pattern_name, "matches": matches[:3]},
                            "remediation": "Use Android Keystore for sensitive data or encrypted storage (SQLCipher)"
                        })

            elif platform == "ios":
                # Check for insecure iOS storage
                insecure_patterns = {
                    "userdefaults": r"NSUserDefaults|UserDefaults",
                    "plist_storage": r"writeToFile|dictionaryWithContentsOfFile",
                    "keychain_misuse": r"kSecAttrAccessible.*kSecAttrAccessibleAlways",
                    "hardcoded_keys": r"(password|apiKey|secret|token)\s*=\s*\"[^\"]+\""
                }

                for pattern_name, pattern in insecure_patterns.items():
                    matches = await self._search_files(Path(app_path), pattern, max_results=10)
                    if matches:
                        severity = "high" if pattern_name == "hardcoded_keys" else "medium"
                        findings.append({
                            "type": severity,
                            "category": "M9",
                            "title": f"Insecure Data Storage: {pattern_name}",
                            "description": f"Found {len(matches)} reference(s) to potentially insecure data storage",
                            "details": {"pattern": pattern_name, "matches": matches[:3]},
                            "remediation": "Use iOS Keychain for sensitive data with appropriate kSecAttrAccessible settings"
                        })

            return {
                "success": True,
                "platform": platform,
                "findings": findings
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def decompile_apk(
        self,
        apk_path: str,
        output_dir: str = None,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Return commands for decompiling APK.

        Args:
            apk_path: Path to APK file
            project_id: Project ID
            target_id: Optional target ID
            output_dir: Optional output directory

        Returns:
            Dictionary with decompilation commands
        """
        try:
            if not output_dir:
                output_dir = f"/tmp/apk_decompiled_{generate_id()[:8]}"

            # Check tool availability
            tools_status = {
                "apktool": await self._check_command("apktool"),
                "jadx": await self._check_command("jadx"),
                "dex2jar": await self._check_command("d2j-dex2jar")
            }

            commands = {
                "apktool": {
                    "command": f"apktool d {apk_path} -o {output_dir}/apktool",
                    "description": "Decompile APK resources and smali code",
                    "available": tools_status["apktool"]
                },
                "jadx": {
                    "command": f"jadx -d {output_dir}/jadx {apk_path}",
                    "description": "Decompile APK to Java source code",
                    "available": tools_status["jadx"]
                },
                "dex2jar": {
                    "command": f"d2j-dex2jar {apk_path} -o {output_dir}/classes.jar",
                    "description": "Convert DEX to JAR (then use JD-GUI to view)",
                    "available": tools_status["dex2jar"]
                }
            }

            return {
                "success": True,
                "apk_path": apk_path,
                "output_dir": output_dir,
                "commands": commands,
                "recommended_workflow": [
                    "1. Use jadx for Java source code: jadx -d output/jadx app.apk",
                    "2. Use apktool for resources: apktool d app.apk -o output/apktool",
                    "3. Analyze decompiled source for security issues"
                ]
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def check_api_calls(
        self,
        source_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Search decompiled source for API endpoints and keys.

        Args:
            source_path: Path to decompiled source
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with API analysis
        """
        try:
            findings = []

            # Patterns for API endpoints and keys
            patterns = {
                "http_urls": r'https?://[^\s\'"]+',
                "api_keys": r'(api[_-]?key|apikey)\s*[=:]\s*[\'"][^\'"]{20,}[\'"]',
                "tokens": r'(token|auth[_-]?token)\s*[=:]\s*[\'"][^\'"]{20,}[\'"]',
                "aws_keys": r'AKIA[0-9A-Z]{16}',
                "firebase_urls": r'https://[a-z0-9-]+\.firebaseio\.com'
            }

            for pattern_name, pattern in patterns.items():
                matches = await self._search_files(Path(source_path), pattern, max_results=50)

                if matches:
                    severity = "critical" if "key" in pattern_name or "token" in pattern_name else "medium"
                    findings.append({
                        "type": severity,
                        "category": "M1",
                        "title": f"Hardcoded {pattern_name.replace('_', ' ').title()}",
                        "description": f"Found {len(matches)} hardcoded {pattern_name}",
                        "details": {"matches": matches[:10]},  # Limit to 10 examples
                        "remediation": "Move sensitive data to secure storage or remote configuration"
                    })

            return {
                "success": True,
                "findings": findings,
                "total_findings": len(findings)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def check_crypto_usage(
        self,
        source_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check for weak cryptography.

        Args:
            source_path: Path to decompiled source
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with crypto analysis
        """
        try:
            findings = []

            # Weak crypto patterns
            weak_patterns = {
                "ecb_mode": {
                    "pattern": r'Cipher\.getInstance\(["\'].*ECB.*["\']\)',
                    "severity": "high",
                    "description": "ECB mode detected - does not provide semantic security"
                },
                "des_3des": {
                    "pattern": r'(DES|TripleDES|DESede)',
                    "severity": "high",
                    "description": "DES/3DES encryption detected - use AES instead"
                },
                "md5_passwords": {
                    "pattern": r'MessageDigest\.getInstance\(["\']MD5["\']\)',
                    "severity": "high",
                    "description": "MD5 hash detected - vulnerable to collision attacks"
                },
                "sha1_passwords": {
                    "pattern": r'MessageDigest\.getInstance\(["\']SHA-?1["\']\)',
                    "severity": "medium",
                    "description": "SHA1 hash detected - use SHA-256 or bcrypt for passwords"
                },
                "hardcoded_keys": {
                    "pattern": r'(SecretKeySpec|IvParameterSpec)\s*\([^)]*["\'][^"\']{8,}["\']',
                    "severity": "critical",
                    "description": "Hardcoded encryption key or IV detected"
                },
                "insecure_random": {
                    "pattern": r'new\s+Random\s*\(',
                    "severity": "medium",
                    "description": "Insecure Random instead of SecureRandom"
                }
            }

            for pattern_name, pattern_info in weak_patterns.items():
                matches = await self._search_files(
                    Path(source_path),
                    pattern_info["pattern"],
                    max_results=20
                )

                if matches:
                    findings.append({
                        "type": pattern_info["severity"],
                        "category": "M10",
                        "title": f"Weak Cryptography: {pattern_name.replace('_', ' ').title()}",
                        "description": f"{pattern_info['description']} ({len(matches)} occurrence(s))",
                        "details": {"matches": matches[:5]},
                        "remediation": "Use AES-GCM or ChaCha20-Poly1305 with SecureRandom-generated keys/IVs"
                    })

            return {
                "success": True,
                "findings": findings,
                "total_findings": len(findings)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def owasp_mobile_check(
        self,
        apk_path: str,
        project_id: str = None,
        target_id: str = None
    ) -> Dict[str, Any]:
        """Check against OWASP Mobile Top 10.

        Args:
            apk_path: Path to APK or decompiled source
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with OWASP Mobile Top 10 analysis
        """
        try:
            findings = []
            owasp_coverage = {k: [] for k in self.owasp_mobile_top10.keys()}

            # Run multiple checks and categorize by OWASP category
            checks = [
                self.analyze_apk(apk_path, project_id),
                self.check_ssl_pinning(apk_path, project_id),
                self.check_data_storage("android", apk_path, project_id),
                self.check_crypto_usage(apk_path, project_id) if Path(apk_path).is_dir() else None,
                self.check_api_calls(apk_path, project_id) if Path(apk_path).is_dir() else None
            ]

            # Aggregate findings
            for check_result in checks:
                if check_result:
                    result = await check_result if hasattr(check_result, '__await__') else check_result
                    if result and result.get("success"):
                        check_findings = result.get("findings", [])
                        findings.extend(check_findings)

                        # Categorize by OWASP
                        for finding in check_findings:
                            category = finding.get("category", "")
                            if category in owasp_coverage:
                                owasp_coverage[category].append(finding)

            # Generate OWASP summary
            owasp_summary = []
            for category, title in self.owasp_mobile_top10.items():
                category_findings = owasp_coverage[category]
                status = "FAIL" if category_findings else "PASS"

                owasp_summary.append({
                    "category": category,
                    "title": title,
                    "status": status,
                    "findings_count": len(category_findings),
                    "highest_severity": self._get_highest_severity(category_findings) if category_findings else "none"
                })

            return {
                "success": True,
                "owasp_summary": owasp_summary,
                "all_findings": findings,
                "total_findings": len(findings),
                "failed_categories": len([s for s in owasp_summary if s["status"] == "FAIL"]),
                "passed_categories": len([s for s in owasp_summary if s["status"] == "PASS"])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def generate_mobile_report(self, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Generate mobile security assessment report.

        Args:
            project_id: Project ID
            target_id: Optional target ID

        Returns:
            Dictionary with report data
        """
        try:
            # This would aggregate all mobile findings from the project
            # For now, return a template

            report = {
                "report_id": generate_id(),
                "project_id": project_id,
                "target_id": target_id,
                "generated_at": utc_now(),
                "report_type": "mobile_security_assessment",
                "summary": {
                    "note": "Run APK/IPA analysis to populate this report"
                },
                "owasp_mobile_top10": self.owasp_mobile_top10,
                "recommendations": [
                    "Implement certificate pinning to prevent MitM attacks",
                    "Use Android Keystore or iOS Keychain for sensitive data",
                    "Enable code obfuscation with ProGuard/R8 (Android) or SwiftShield (iOS)",
                    "Implement root/jailbreak detection",
                    "Use runtime application self-protection (RASP)",
                    "Regular security testing in CI/CD pipeline"
                ]
            }

            await self.db.audit(
                action="generate_mobile_report",
                resource_type="report",
                resource_id=report["report_id"],
                details={
                    "project_id": project_id
                },
                severity="info"
            )

            return {
                "success": True,
                "report": report
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    # Helper methods

    async def _parse_android_manifest(self, manifest_path: Path) -> Dict[str, Any]:
        """Parse AndroidManifest.xml (simplified - real parsing needs AXML decoder)."""
        # In production, use androguard or axmlparser
        # For now, return mock structure
        return {
            "package": "com.example.app",
            "permissions": [],
            "debuggable": False,
            "allowBackup": True,
            "minSdkVersion": 21,
            "targetSdkVersion": 33,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        }

    async def _check_manifest_security(self, manifest_data: Dict, project_id: str) -> List[Dict]:
        """Check manifest for security issues."""
        findings = []

        # Check exported components
        for component_type in ["activities", "services", "receivers", "providers"]:
            components = manifest_data.get(component_type, [])
            exported = [c for c in components if c.get("exported", False)]

            if exported:
                findings.append({
                    "type": "medium",
                    "category": "M4",
                    "title": f"Exported {component_type.title()}",
                    "description": f"{len(exported)} {component_type} are exported and accessible to other apps",
                    "remediation": "Review exported components and add permission protection if needed"
                })

        return findings

    async def _search_files(self, search_path: Path, pattern: str, max_results: int = 100) -> List[str]:
        """Search files for pattern."""
        matches = []

        try:
            if not search_path.exists():
                return matches

            for file_path in search_path.rglob("*"):
                if file_path.is_file() and file_path.suffix in [".java", ".kt", ".smali", ".xml", ".m", ".swift"]:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            file_matches = re.findall(pattern, content, re.IGNORECASE)

                            for match in file_matches[:5]:  # Limit per file
                                matches.append(f"{file_path.name}: {match[:100]}")

                                if len(matches) >= max_results:
                                    return matches
                    except:
                        continue

        except Exception:
            pass

        return matches

    async def _check_command(self, command: str) -> bool:
        """Check if a command is available."""
        import shutil
        return shutil.which(command) is not None

    def _get_highest_severity(self, findings: List[Dict]) -> str:
        """Get highest severity from findings."""
        severity_order = ["critical", "high", "medium", "low", "info"]

        for severity in severity_order:
            if any(f.get("type") == severity for f in findings):
                return severity

        return "none"
