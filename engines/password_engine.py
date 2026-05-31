"""Password auditing engine for hash cracking and credential testing."""

import asyncio
import hashlib
import json
import logging
import re

logger = logging.getLogger("hacking_agent.engines.password")


class PasswordEngine:
    def __init__(self, db, config: dict = None):
        self.db = db
        self.config = (config or {}).get("engines", {}).get("password", {})

    async def identify_hash(self, hash_value: str) -> dict:
        hash_value = hash_value.strip()
        results = []

        patterns = [
            (r"^\$2[aby]?\$\d{2}\$.{53}$", "bcrypt", "strong"),
            (r"^\$6\$.{8,}\$.{86}$", "SHA-512 (crypt)", "moderate"),
            (r"^\$5\$.{8,}\$.{43}$", "SHA-256 (crypt)", "weak"),
            (r"^\$1\$.{8}\$.{22}$", "MD5 (crypt)", "weak"),
            (r"^\$argon2(i|d|id)\$", "Argon2", "excellent"),
            (r"^\$scrypt\$", "scrypt", "strong"),
            (r"^[a-f0-9]{32}$", "MD5 / NTLM", "weak"),
            (r"^[a-f0-9]{40}$", "SHA-1", "weak"),
            (r"^[a-f0-9]{64}$", "SHA-256", "weak"),
            (r"^[a-f0-9]{128}$", "SHA-512", "moderate"),
            (r"^[a-f0-9]{32}:[a-f0-9]{32}$", "NetNTLMv1", "weak"),
            (r"^[A-Za-z0-9+/]{27}=$", "LM Hash", "very_weak"),
        ]

        for pattern, name, strength in patterns:
            if re.match(pattern, hash_value, re.IGNORECASE):
                results.append({"type": name, "strength": strength})

        if not results:
            try:
                import hashid as hid
                h = hid.HashID()
                for match in h.identifyHash(hash_value):
                    results.append({"type": match.name, "strength": "unknown"})
                    if len(results) >= 5:
                        break
            except ImportError:
                pass

        if not results:
            length = len(hash_value)
            results.append({
                "type": f"Unknown (length={length})",
                "strength": "unknown",
            })

        await self.db.audit("identify_hash", description=f"Hash identified: {results[0]['type'] if results else 'unknown'}")
        return {"success": True, "hash": hash_value[:20] + "...",
                "possible_types": results}

    async def crack_hash(self, hash_value: str, hash_type: str = "auto",
                         wordlist: str = "rockyou.txt",
                         project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        wordlist_dir = self.config.get("wordlist_dir", "./data/wordlists")
        hashcat_path = self.config.get("hashcat_path", "hashcat")
        john_path = self.config.get("john_path", "john")

        hashcat_modes = {
            "md5": "0", "sha1": "100", "sha256": "1400", "sha512": "1800",
            "ntlm": "1000", "bcrypt": "3200", "mysql": "300",
            "md5crypt": "500", "sha512crypt": "1800",
        }
        mode = hashcat_modes.get(hash_type.lower(), "0")

        commands = {
            "hashcat": f"{hashcat_path} -m {mode} -a 0 '{hash_value}' {wordlist_dir}/{wordlist} --force",
            "john": f"echo '{hash_value}' > /tmp/hash.txt && {john_path} --wordlist={wordlist_dir}/{wordlist} /tmp/hash.txt",
        }

        await self.db.audit("crack_hash", target_id, project_id,
                            f"Hash crack attempt ({hash_type})")

        return {
            "success": True,
            "hash_type": hash_type,
            "wordlist": wordlist,
            "commands": commands,
            "note": "Run the hashcat or john command to crack the hash. Results will depend on wordlist quality and hash complexity.",
            "estimated_time": "varies by hash type and wordlist size",
        }

    async def password_spray(self, target: str, usernames: list,
                             password: str, protocol: str = "ssh",
                             project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        results = []
        for username in usernames:
            cred_result = await self.validate_credential(
                target, username, password, protocol, project_id, target_id)
            results.append({
                "username": username,
                "valid": cred_result.get("valid", False),
            })

        valid_count = sum(1 for r in results if r["valid"])
        await self.db.audit("password_spray", target_id, project_id,
                            f"Password spray on {target} ({protocol}): {valid_count}/{len(usernames)} valid",
                            {"target": target, "protocol": protocol})

        return {
            "success": True, "target": target, "protocol": protocol,
            "password_tested": password, "results": results,
            "valid_count": valid_count, "total_tested": len(usernames),
        }

    async def validate_credential(self, target: str, username: str,
                                  password: str, protocol: str = "ssh",
                                  project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        valid = False
        error = None

        if protocol == "ssh":
            try:
                import asyncssh
                try:
                    async with asyncssh.connect(
                        target, username=username, password=password,
                        known_hosts=None, connect_timeout=10
                    ) as conn:
                        valid = True
                except (asyncssh.PermissionDenied, asyncssh.DisconnectError):
                    valid = False
                except Exception as e:
                    error = str(e)
            except ImportError:
                return {"success": False, "error": "asyncssh not installed"}
        elif protocol in ("http", "https"):
            import httpx
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    resp = await client.post(
                        target,
                        data={"username": username, "password": password},
                        timeout=10)
                    valid = resp.status_code in (200, 302)
            except Exception as e:
                error = str(e)
        else:
            return {"success": False, "error": f"Unsupported protocol: {protocol}"}

        if valid:
            cred_mgr_import = "from core.credentials import CredentialManager"
            cred_id = generate_id("cred-")
            await self.db.execute_commit(
                "INSERT INTO credentials_found (id, project_id, target_id, credential_type, username, value, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (cred_id, project_id, target_id, "password", username,
                 f"[ENCRYPTED]", f"validate:{protocol}://{target}", utc_now()))

            find_id = generate_id("find-")
            await self.db.execute_commit(
                "INSERT INTO findings (id, project_id, target_id, title, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (find_id, project_id, target_id,
                 f"Valid Credential Found: {username}@{target} ({protocol})",
                 "high", "confirmed", utc_now()))

        await self.db.audit("validate_credential", target_id, project_id,
                            f"Credential test: {username}@{target} ({protocol}) = {'valid' if valid else 'invalid'}")

        return {"success": True, "target": target, "username": username,
                "protocol": protocol, "valid": valid, "error": error}

    async def brute_force(self, target: str, username: str,
                          wordlist: str = "rockyou.txt", protocol: str = "ssh",
                          max_attempts: int = 100,
                          project_id: str = None, target_id: str = None) -> dict:
        from core.database import generate_id, utc_now

        wordlist_path = f"{self.config.get('wordlist_dir', './data/wordlists')}/{wordlist}"

        commands = {
            "hydra_ssh": f"hydra -l {username} -P {wordlist_path} {target} ssh -t 4 -f",
            "hydra_http": f"hydra -l {username} -P {wordlist_path} {target} http-post-form '/login:user=^USER^&pass=^PASS^:Invalid' -t 4 -f",
            "hydra_ftp": f"hydra -l {username} -P {wordlist_path} {target} ftp -t 4 -f",
            "hydra_rdp": f"hydra -l {username} -P {wordlist_path} {target} rdp -t 4 -f",
        }

        await self.db.audit("brute_force", target_id, project_id,
                            f"Brute force setup: {username}@{target} ({protocol})")

        return {
            "success": True,
            "target": target,
            "username": username,
            "protocol": protocol,
            "suggested_command": commands.get(f"hydra_{protocol}", commands["hydra_ssh"]),
            "wordlist": wordlist_path,
            "note": "Run the suggested hydra command. Ensure you have authorization.",
        }

    async def generate_wordlist(self, base_words: list, rules: str = "standard",
                                project_id: str = None) -> dict:
        import os
        from core.database import generate_id

        mutations = []
        for word in base_words:
            mutations.append(word)
            mutations.append(word.capitalize())
            mutations.append(word.upper())
            mutations.append(word.lower())
            for year in range(2020, 2027):
                mutations.append(f"{word}{year}")
                mutations.append(f"{word.capitalize()}{year}")
                mutations.append(f"{word}{year}!")
                mutations.append(f"{word.capitalize()}{year}!")
                mutations.append(f"{word.capitalize()}{year}#")
            for num in ["1", "12", "123", "1234", "!", "@", "#", "$"]:
                mutations.append(f"{word}{num}")
                mutations.append(f"{word.capitalize()}{num}")
            mutations.append(f"{word}@")
            mutations.append(f"@{word}")
            mutations.append(word.replace("a", "@").replace("e", "3").replace("o", "0"))

        unique = sorted(set(mutations))

        output_dir = self.config.get("wordlist_dir", "./data/wordlists")
        os.makedirs(output_dir, exist_ok=True)
        wl_id = generate_id("wl-")
        path = os.path.join(output_dir, f"custom_{wl_id}.txt")
        with open(path, "w") as f:
            f.write("\n".join(unique))

        await self.db.audit("generate_wordlist", project_id=project_id,
                            description=f"Custom wordlist generated: {len(unique)} entries")

        return {"success": True, "path": path, "word_count": len(unique),
                "base_words": base_words}

    async def analyze_password_strength(self, password: str) -> dict:
        score = 0
        feedback = []

        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Too short (minimum 8 characters)")
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add numbers")
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Add special characters")

        common_patterns = ["password", "123456", "qwerty", "admin", "letmein",
                          "welcome", "monkey", "dragon", "master"]
        if password.lower() in common_patterns:
            score = 0
            feedback.append("Extremely common password — easily crackable")

        if score >= 6:
            strength = "strong"
        elif score >= 4:
            strength = "moderate"
        elif score >= 2:
            strength = "weak"
        else:
            strength = "very_weak"

        return {"success": True, "score": score, "max_score": 7,
                "strength": strength, "feedback": feedback}

    async def check_password_policy(self, target_id: str = None,
                                    project_id: str = None) -> dict:
        from knowledge.loader import get_password_policies
        policies = get_password_policies()
        rules = policies.get("password_strength_rules", {})

        return {
            "success": True,
            "recommended_policy": rules,
            "common_patterns": policies.get("common_patterns", []),
            "note": "Compare target's password policy against these recommendations",
        }
