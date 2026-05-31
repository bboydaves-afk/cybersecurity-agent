"""Active Directory and LDAP security assessment engine."""

from typing import Optional, Dict, Any, List
import asyncio


class ADEngine:
    """Active Directory and LDAP security assessment engine."""

    def __init__(self, db, config: dict = None):
        """Initialize AD Engine."""
        self.db = db
        self.config = (config or {}).get("engines", {}).get("ad_engine", {})

    async def enumerate_domain(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate domain information via LDAP."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            # Build server and connection
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"

            # Attempt connection
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )

            if not conn.bind():
                return {
                    "success": False,
                    "error": f"LDAP bind failed: {conn.result}",
                }

            # Get domain info
            domain_info = {
                "domain_controller": domain_controller,
                "domain": domain,
                "naming_contexts": server.info.naming_contexts if server.info else [],
                "domain_functional_level": None,
                "forest_functional_level": None,
                "schema_version": None,
            }

            # Get root DSE info
            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for domain functional level
            conn.search(
                base_dn,
                "(objectClass=domain)",
                attributes=["msDS-Behavior-Version", "lockoutThreshold", "minPwdLength", "pwdHistoryLength", "pwdProperties", "maxPwdAge", "minPwdAge"],
            )

            if conn.entries:
                entry = conn.entries[0]
                domain_info["domain_functional_level"] = (
                    str(entry["msDS-Behavior-Version"].value)
                    if "msDS-Behavior-Version" in entry
                    else "Unknown"
                )

                # Password policy
                password_policy = {
                    "lockout_threshold": str(entry["lockoutThreshold"].value) if "lockoutThreshold" in entry else "Not set",
                    "min_password_length": str(entry["minPwdLength"].value) if "minPwdLength" in entry else "Not set",
                    "password_history": str(entry["pwdHistoryLength"].value) if "pwdHistoryLength" in entry else "Not set",
                    "password_complexity": "Enabled" if (entry["pwdProperties"].value & 1) else "Disabled" if "pwdProperties" in entry else "Unknown",
                    "max_password_age_days": str(abs(int(entry["maxPwdAge"].value)) // (10000000 * 60 * 60 * 24)) if "maxPwdAge" in entry and entry["maxPwdAge"].value else "Never",
                }
                domain_info["password_policy"] = password_policy

            conn.unbind()

            # Store finding
            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    f"AD Domain Enumeration: {domain}",
                    "Info",
                    "Active Directory",
                    f"Successfully enumerated domain {domain}",
                    str(domain_info),
                    "Review domain configuration for security issues",
                    utc_now(),
                ),
            )

            await self.db.audit(
                action="ad_enumerate_domain",
                details={"domain": domain, "dc": domain_controller},
                project_id=project_id,
            )

            return {
                "success": True,
                "domain_info": domain_info,
                "finding_id": finding_id,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def enumerate_users(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        search_filter: str = "(objectClass=user)",
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate AD users with security analysis."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for users
            conn.search(
                base_dn,
                search_filter,
                attributes=[
                    "sAMAccountName",
                    "mail",
                    "memberOf",
                    "lastLogon",
                    "userAccountControl",
                    "adminCount",
                    "servicePrincipalName",
                    "displayName",
                    "description",
                ],
            )

            users = []
            privileged_users = []
            disabled_users = []
            password_never_expires = []
            inactive_users = []

            for entry in conn.entries:
                user_data = {
                    "username": str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "",
                    "email": str(entry["mail"].value) if "mail" in entry else "",
                    "display_name": str(entry["displayName"].value) if "displayName" in entry else "",
                    "description": str(entry["description"].value) if "description" in entry else "",
                    "groups": [str(g) for g in entry["memberOf"].values] if "memberOf" in entry else [],
                    "admin_count": int(entry["adminCount"].value) if "adminCount" in entry and entry["adminCount"].value else 0,
                    "spn": [str(s) for s in entry["servicePrincipalName"].values] if "servicePrincipalName" in entry else [],
                }

                # Check userAccountControl flags
                uac = int(entry["userAccountControl"].value) if "userAccountControl" in entry else 0
                user_data["disabled"] = bool(uac & 0x0002)
                user_data["password_never_expires"] = bool(uac & 0x10000)
                user_data["locked"] = bool(uac & 0x0010)

                users.append(user_data)

                # Categorize users
                if user_data["admin_count"] > 0:
                    privileged_users.append(user_data["username"])
                if user_data["disabled"]:
                    disabled_users.append(user_data["username"])
                if user_data["password_never_expires"]:
                    password_never_expires.append(user_data["username"])

            conn.unbind()

            # Create findings for security issues
            findings = []

            if privileged_users:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Privileged AD Users Identified",
                        "Medium",
                        "Active Directory",
                        f"Found {len(privileged_users)} privileged users in domain {domain}",
                        f"Privileged users: {', '.join(privileged_users)}",
                        "Review privileged user accounts and ensure least privilege principle",
                        utc_now(),
                    ),
                )
                findings.append(finding_id)

            if password_never_expires:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Users with Password Never Expires",
                        "High",
                        "Active Directory",
                        f"Found {len(password_never_expires)} users with password never expires flag",
                        f"Users: {', '.join(password_never_expires[:20])}",
                        "Disable 'Password Never Expires' flag and enforce password rotation policy",
                        utc_now(),
                    ),
                )
                findings.append(finding_id)

            await self.db.audit(
                action="ad_enumerate_users",
                details={"domain": domain, "user_count": len(users)},
                project_id=project_id,
            )

            return {
                "success": True,
                "user_count": len(users),
                "users": users[:100],  # Limit response size
                "privileged_users": privileged_users,
                "disabled_users": disabled_users,
                "password_never_expires": password_never_expires,
                "findings": findings,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def enumerate_groups(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate AD groups with focus on privileged groups."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for groups
            conn.search(
                base_dn,
                "(objectClass=group)",
                attributes=["cn", "description", "member", "groupType", "adminCount"],
            )

            groups = []
            privileged_groups = [
                "Domain Admins",
                "Enterprise Admins",
                "Schema Admins",
                "Administrators",
                "Account Operators",
                "Backup Operators",
                "Server Operators",
                "Print Operators",
                "DnsAdmins",
            ]
            found_privileged = {}

            for entry in conn.entries:
                group_name = str(entry["cn"].value) if "cn" in entry else ""
                members = [str(m) for m in entry["member"].values] if "member" in entry else []

                group_data = {
                    "name": group_name,
                    "description": str(entry["description"].value) if "description" in entry else "",
                    "member_count": len(members),
                    "members": members[:10],  # Limit members in response
                    "admin_count": int(entry["adminCount"].value) if "adminCount" in entry and entry["adminCount"].value else 0,
                }

                groups.append(group_data)

                # Check if privileged group
                if group_name in privileged_groups:
                    found_privileged[group_name] = {
                        "member_count": len(members),
                        "members": members,
                    }

            conn.unbind()

            # Create finding for privileged groups
            if found_privileged:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Privileged AD Groups Enumerated",
                        "Info",
                        "Active Directory",
                        f"Enumerated {len(found_privileged)} privileged groups in domain {domain}",
                        str(found_privileged),
                        "Review membership of privileged groups regularly",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_enumerate_groups",
                details={"domain": domain, "group_count": len(groups)},
                project_id=project_id,
            )

            return {
                "success": True,
                "group_count": len(groups),
                "groups": groups[:50],  # Limit response size
                "privileged_groups": found_privileged,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def enumerate_computers(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate computer objects and identify outdated systems."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for computers
            conn.search(
                base_dn,
                "(objectClass=computer)",
                attributes=["cn", "operatingSystem", "operatingSystemVersion", "lastLogon", "dNSHostName"],
            )

            computers = []
            outdated_os = []
            unsupported_os = [
                "Windows XP",
                "Windows Vista",
                "Windows 7",
                "Windows 8",
                "Windows Server 2003",
                "Windows Server 2008",
                "Windows Server 2012",
            ]

            for entry in conn.entries:
                os_name = str(entry["operatingSystem"].value) if "operatingSystem" in entry else "Unknown"
                computer_data = {
                    "name": str(entry["cn"].value) if "cn" in entry else "",
                    "dns_name": str(entry["dNSHostName"].value) if "dNSHostName" in entry else "",
                    "operating_system": os_name,
                    "os_version": str(entry["operatingSystemVersion"].value) if "operatingSystemVersion" in entry else "",
                }

                computers.append(computer_data)

                # Check for unsupported OS
                if any(unsupported in os_name for unsupported in unsupported_os):
                    outdated_os.append(computer_data)

            conn.unbind()

            # Create finding for outdated systems
            if outdated_os:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Unsupported Operating Systems Detected",
                        "Critical",
                        "Active Directory",
                        f"Found {len(outdated_os)} computers running unsupported operating systems",
                        f"Outdated systems: {str(outdated_os[:20])}",
                        "Upgrade or decommission systems running unsupported operating systems",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_enumerate_computers",
                details={"domain": domain, "computer_count": len(computers)},
                project_id=project_id,
            )

            return {
                "success": True,
                "computer_count": len(computers),
                "computers": computers[:50],  # Limit response size
                "outdated_os": outdated_os,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_password_policy(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Check domain password policy for weak settings."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Get password policy
            conn.search(
                base_dn,
                "(objectClass=domain)",
                attributes=[
                    "minPwdLength",
                    "pwdHistoryLength",
                    "pwdProperties",
                    "maxPwdAge",
                    "minPwdAge",
                    "lockoutThreshold",
                    "lockoutDuration",
                ],
            )

            if not conn.entries:
                return {"success": False, "error": "Failed to retrieve password policy"}

            entry = conn.entries[0]

            # Parse policy
            min_length = int(entry["minPwdLength"].value) if "minPwdLength" in entry else 0
            history = int(entry["pwdHistoryLength"].value) if "pwdHistoryLength" in entry else 0
            pwd_props = int(entry["pwdProperties"].value) if "pwdProperties" in entry else 0
            complexity = bool(pwd_props & 1)
            max_age = int(entry["maxPwdAge"].value) if "maxPwdAge" in entry and entry["maxPwdAge"].value else 0
            max_age_days = abs(max_age) // (10000000 * 60 * 60 * 24) if max_age else 0
            lockout_threshold = int(entry["lockoutThreshold"].value) if "lockoutThreshold" in entry else 0

            policy = {
                "min_password_length": min_length,
                "password_history": history,
                "complexity_enabled": complexity,
                "max_password_age_days": max_age_days if max_age_days > 0 else "Never",
                "lockout_threshold": lockout_threshold if lockout_threshold > 0 else "Not set",
            }

            conn.unbind()

            # Assess weaknesses
            weaknesses = []
            severity = "Low"

            if min_length < 12:
                weaknesses.append(f"Minimum password length ({min_length}) is below recommended 12 characters")
                severity = "High"

            if not complexity:
                weaknesses.append("Password complexity is not enabled")
                severity = "High"

            if max_age_days == 0 or max_age_days > 90:
                weaknesses.append(f"Maximum password age ({max_age_days}) exceeds 90 days or is not set")
                severity = "Medium" if severity == "Low" else severity

            if lockout_threshold == 0 or lockout_threshold > 5:
                weaknesses.append(f"Account lockout threshold ({lockout_threshold}) is too high or not set")
                severity = "Medium" if severity == "Low" else severity

            if history < 12:
                weaknesses.append(f"Password history ({history}) is below recommended 12 passwords")

            # Create finding if weaknesses found
            if weaknesses:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Weak Domain Password Policy",
                        severity,
                        "Active Directory",
                        f"Domain {domain} has weak password policy settings",
                        f"Weaknesses: {'; '.join(weaknesses)}. Policy: {str(policy)}",
                        "Strengthen password policy: min 12 chars, complexity enabled, max age 90 days, lockout threshold 5 attempts, history 12 passwords",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_check_password_policy",
                details={"domain": domain, "weaknesses": len(weaknesses)},
                project_id=project_id,
            )

            return {
                "success": True,
                "policy": policy,
                "weaknesses": weaknesses,
                "severity": severity,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_kerberoastable(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Find kerberoastable accounts (accounts with SPNs)."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for users with SPNs
            conn.search(
                base_dn,
                "(&(objectClass=user)(servicePrincipalName=*))",
                attributes=["sAMAccountName", "servicePrincipalName", "memberOf", "adminCount"],
            )

            kerberoastable = []
            for entry in conn.entries:
                account = {
                    "username": str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "",
                    "spns": [str(s) for s in entry["servicePrincipalName"].values] if "servicePrincipalName" in entry else [],
                    "privileged": int(entry["adminCount"].value) > 0 if "adminCount" in entry and entry["adminCount"].value else False,
                }
                kerberoastable.append(account)

            conn.unbind()

            # Create finding if kerberoastable accounts found
            if kerberoastable:
                finding_id = generate_id()
                severity = "Critical" if any(a["privileged"] for a in kerberoastable) else "High"

                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Kerberoastable Accounts Detected",
                        severity,
                        "Active Directory",
                        f"Found {len(kerberoastable)} accounts with SPNs that can be kerberoasted",
                        f"Accounts: {str(kerberoastable)}",
                        "Use managed service accounts (MSA/gMSA) or ensure service accounts have strong passwords (25+ chars)",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_check_kerberoastable",
                details={"domain": domain, "count": len(kerberoastable)},
                project_id=project_id,
            )

            return {
                "success": True,
                "kerberoastable_count": len(kerberoastable),
                "accounts": kerberoastable,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_asrep_roastable(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Find AS-REP roastable accounts (no Kerberos preauth required)."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for users with DONT_REQ_PREAUTH flag (0x400000)
            conn.search(
                base_dn,
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName", "userAccountControl", "adminCount"],
            )

            asrep_roastable = []
            for entry in conn.entries:
                account = {
                    "username": str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "",
                    "privileged": int(entry["adminCount"].value) > 0 if "adminCount" in entry and entry["adminCount"].value else False,
                }
                asrep_roastable.append(account)

            conn.unbind()

            # Create finding if AS-REP roastable accounts found
            if asrep_roastable:
                finding_id = generate_id()
                severity = "Critical" if any(a["privileged"] for a in asrep_roastable) else "High"

                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "AS-REP Roastable Accounts Detected",
                        severity,
                        "Active Directory",
                        f"Found {len(asrep_roastable)} accounts without Kerberos preauth requirement",
                        f"Accounts: {str(asrep_roastable)}",
                        "Enable Kerberos preauthentication for all accounts (uncheck 'Do not require Kerberos preauthentication')",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_check_asrep_roastable",
                details={"domain": domain, "count": len(asrep_roastable)},
                project_id=project_id,
            )

            return {
                "success": True,
                "asrep_roastable_count": len(asrep_roastable),
                "accounts": asrep_roastable,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_delegation(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Find unconstrained and constrained delegation configurations."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for unconstrained delegation (TRUSTED_FOR_DELEGATION flag 0x80000)
            conn.search(
                base_dn,
                "(&(objectClass=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                attributes=["sAMAccountName", "objectClass", "userAccountControl"],
            )

            unconstrained = []
            for entry in conn.entries:
                obj_class = str(entry["objectClass"].values[-1]) if "objectClass" in entry else ""
                unconstrained.append({
                    "name": str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "",
                    "type": obj_class,
                })

            # Search for constrained delegation
            conn.search(
                base_dn,
                "(&(objectClass=*)(msDS-AllowedToDelegateTo=*))",
                attributes=["sAMAccountName", "objectClass", "msDS-AllowedToDelegateTo"],
            )

            constrained = []
            for entry in conn.entries:
                obj_class = str(entry["objectClass"].values[-1]) if "objectClass" in entry else ""
                constrained.append({
                    "name": str(entry["sAMAccountName"].value) if "sAMAccountName" in entry else "",
                    "type": obj_class,
                    "allowed_to": [str(s) for s in entry["msDS-AllowedToDelegateTo"].values] if "msDS-AllowedToDelegateTo" in entry else [],
                })

            conn.unbind()

            # Create findings
            findings = []

            if unconstrained:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Unconstrained Delegation Detected",
                        "Critical",
                        "Active Directory",
                        f"Found {len(unconstrained)} objects with unconstrained delegation",
                        f"Objects: {str(unconstrained)}",
                        "Disable unconstrained delegation and use constrained delegation or resource-based constrained delegation instead",
                        utc_now(),
                    ),
                )
                findings.append(finding_id)

            if constrained:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Constrained Delegation Detected",
                        "Medium",
                        "Active Directory",
                        f"Found {len(constrained)} objects with constrained delegation",
                        f"Objects: {str(constrained)}",
                        "Review constrained delegation configurations and ensure they follow least privilege principle",
                        utc_now(),
                    ),
                )
                findings.append(finding_id)

            await self.db.audit(
                action="ad_check_delegation",
                details={"domain": domain, "unconstrained": len(unconstrained), "constrained": len(constrained)},
                project_id=project_id,
            )

            return {
                "success": True,
                "unconstrained_delegation": unconstrained,
                "constrained_delegation": constrained,
                "findings": findings,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def enumerate_gpos(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate Group Policy Objects."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for GPOs
            conn.search(
                f"CN=Policies,CN=System,{base_dn}",
                "(objectClass=groupPolicyContainer)",
                attributes=["displayName", "gPCFileSysPath", "versionNumber", "flags"],
            )

            gpos = []
            for entry in conn.entries:
                gpo = {
                    "name": str(entry["displayName"].value) if "displayName" in entry else "",
                    "path": str(entry["gPCFileSysPath"].value) if "gPCFileSysPath" in entry else "",
                    "version": str(entry["versionNumber"].value) if "versionNumber" in entry else "",
                }
                gpos.append(gpo)

            conn.unbind()

            # Create finding
            finding_id = generate_id()
            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    "Group Policy Objects Enumerated",
                    "Info",
                    "Active Directory",
                    f"Found {len(gpos)} Group Policy Objects in domain {domain}",
                    str(gpos),
                    "Review GPO configurations for security misconfigurations",
                    utc_now(),
                ),
            )

            await self.db.audit(
                action="ad_enumerate_gpos",
                details={"domain": domain, "gpo_count": len(gpos)},
                project_id=project_id,
            )

            return {
                "success": True,
                "gpo_count": len(gpos),
                "gpos": gpos,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def check_trusts(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate domain trusts."""
        from ldap3 import Server, Connection, ALL, NTLM
        from core.database import generate_id, utc_now

        try:
            server = Server(domain_controller, get_info=ALL)
            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if not conn.bind():
                return {"success": False, "error": f"LDAP bind failed: {conn.result}"}

            base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

            # Search for trusts
            conn.search(
                f"CN=System,{base_dn}",
                "(objectClass=trustedDomain)",
                attributes=["trustPartner", "trustDirection", "trustType", "trustAttributes"],
            )

            trusts = []
            for entry in conn.entries:
                direction_map = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
                trust_direction = int(entry["trustDirection"].value) if "trustDirection" in entry else 0

                trust = {
                    "partner": str(entry["trustPartner"].value) if "trustPartner" in entry else "",
                    "direction": direction_map.get(trust_direction, "Unknown"),
                    "type": str(entry["trustType"].value) if "trustType" in entry else "",
                }
                trusts.append(trust)

            conn.unbind()

            # Create finding if trusts found
            if trusts:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Domain Trusts Detected",
                        "Medium",
                        "Active Directory",
                        f"Found {len(trusts)} domain trust relationships",
                        str(trusts),
                        "Review trust relationships and ensure they are necessary and properly secured",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_check_trusts",
                details={"domain": domain, "trust_count": len(trusts)},
                project_id=project_id,
            )

            return {
                "success": True,
                "trust_count": len(trusts),
                "trusts": trusts,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def enumerate_shares(
        self,
        targets: List[str],
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Enumerate SMB shares across targets."""
        from core.database import generate_id, utc_now

        try:
            # Use smbclient command for share enumeration
            import subprocess

            all_shares = {}
            accessible_shares = []

            for target in targets:
                try:
                    # Run smbclient to list shares
                    cmd = ["smbclient", "-L", target, "-U", f"{username}%{password}", "-N"]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )

                    if result.returncode == 0:
                        shares = []
                        for line in result.stdout.split("\n"):
                            if "Disk" in line or "IPC" in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    share_name = parts[0]
                                    shares.append(share_name)

                                    # Check if share is accessible
                                    if share_name not in ["IPC$", "ADMIN$", "C$"]:
                                        accessible_shares.append({
                                            "target": target,
                                            "share": share_name,
                                        })

                        all_shares[target] = shares

                except subprocess.TimeoutExpired:
                    all_shares[target] = ["timeout"]
                except Exception as e:
                    all_shares[target] = [f"error: {str(e)}"]

            # Create finding if accessible shares found
            if accessible_shares:
                finding_id = generate_id()
                await self.db.execute_commit(
                    """INSERT INTO findings
                       (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        project_id,
                        target_id,
                        "Accessible SMB Shares Found",
                        "Medium",
                        "Active Directory",
                        f"Found {len(accessible_shares)} accessible SMB shares",
                        str(accessible_shares),
                        "Review share permissions and ensure principle of least privilege",
                        utc_now(),
                    ),
                )

            await self.db.audit(
                action="ad_enumerate_shares",
                details={"target_count": len(targets), "accessible_shares": len(accessible_shares)},
                project_id=project_id,
            )

            return {
                "success": True,
                "all_shares": all_shares,
                "accessible_shares": accessible_shares,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def ad_security_assessment(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        project_id: str = None,
        target_id: str = None,
    ) -> Dict[str, Any]:
        """Run comprehensive AD security assessment."""
        from core.database import generate_id, utc_now

        try:
            results = {
                "domain": domain,
                "domain_controller": domain_controller,
                "timestamp": utc_now(),
            }

            # Run all checks
            results["password_policy"] = await self.check_password_policy(
                domain_controller, domain, username, password, project_id, target_id
            )

            results["kerberoastable"] = await self.check_kerberoastable(
                domain_controller, domain, username, password, project_id, target_id
            )

            results["asrep_roastable"] = await self.check_asrep_roastable(
                domain_controller, domain, username, password, project_id, target_id
            )

            results["delegation"] = await self.check_delegation(
                domain_controller, domain, username, password, project_id, target_id
            )

            results["trusts"] = await self.check_trusts(
                domain_controller, domain, username, password, project_id, target_id
            )

            # Calculate risk score
            risk_score = 0
            critical_issues = 0
            high_issues = 0

            for check_name, check_result in results.items():
                if isinstance(check_result, dict) and check_result.get("success"):
                    if check_result.get("severity") == "Critical":
                        critical_issues += 1
                        risk_score += 10
                    elif check_result.get("severity") == "High":
                        high_issues += 1
                        risk_score += 5

            # Create summary finding
            finding_id = generate_id()
            severity = "Critical" if critical_issues > 0 else "High" if high_issues > 0 else "Medium"

            await self.db.execute_commit(
                """INSERT INTO findings
                   (id, project_id, target_id, title, severity, category, description, evidence, remediation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    project_id,
                    target_id,
                    f"Active Directory Security Assessment: {domain}",
                    severity,
                    "Active Directory",
                    f"Comprehensive AD assessment found {critical_issues} critical and {high_issues} high severity issues",
                    f"Risk Score: {risk_score}/100. Results: {str(results)}",
                    "Address all identified security issues following recommendations in individual findings",
                    utc_now(),
                ),
            )

            await self.db.audit(
                action="ad_security_assessment",
                details={
                    "domain": domain,
                    "risk_score": risk_score,
                    "critical_issues": critical_issues,
                    "high_issues": high_issues,
                },
                project_id=project_id,
            )

            return {
                "success": True,
                "risk_score": risk_score,
                "critical_issues": critical_issues,
                "high_issues": high_issues,
                "results": results,
                "summary_finding_id": finding_id,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
