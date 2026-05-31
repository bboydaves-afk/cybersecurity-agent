"""CyberSecurity AI Agent — Claude tool-use orchestrator."""

import json
import logging
import os

import anthropic

from .safety import SafetyLevel, check_safety, get_safety_message, check_scope
from .tools import TOOLS
from .handlers import TOOL_HANDLERS

logger = logging.getLogger("hacking_agent.agent")

SYSTEM_PROMPT = """You are an expert cybersecurity professional and penetration tester AI assistant.
You assist with authorized security assessments, penetration tests, bug bounty programs, CTF challenges, and defensive security operations.

CRITICAL SAFETY RULES:
1. ALWAYS verify the target is in-scope before any active scanning or exploitation
2. NEVER perform destructive operations without explicit user confirmation
3. ALL exploitation requires an active project with defined scope and rules of engagement
4. Discovered credentials are automatically encrypted at rest
5. Log ALL actions to the audit trail for compliance
6. Follow the principle of least privilege and minimal footprint

Your capabilities include:
- Reconnaissance: port scanning, service enumeration, OS fingerprinting, subdomain discovery, OSINT
- Web Application Security: OWASP Top 10 testing, directory fuzzing, header/SSL analysis
- API Security: REST/GraphQL testing, authentication/authorization bypass, JWT analysis, rate limiting, fuzzing
- Vulnerability Assessment: CVE lookup, exploit search, CVSS scoring, vulnerability scanning
- Vulnerability Chaining: multi-step attack path analysis, automated chain detection, impact prioritization
- Exploitation: authorized payload generation, Metasploit integration, post-exploitation
- Active Directory: LDAP enumeration, Kerberoasting, AS-REP roasting, delegation attacks, GPO analysis, trust mapping
- Network Analysis: packet capture, ARP scanning, DNS enumeration, traffic analysis
- Wireless Security: WiFi scanning, encryption analysis, rogue AP detection, WPS testing, handshake capture
- Password Auditing: hash identification/cracking, password spraying, credential testing
- Cloud Security: AWS/Azure/GCP misconfiguration auditing, IAM analysis
- Container Security: Docker image scanning, Kubernetes RBAC audit, pod security, container escape detection
- OSINT: email harvesting, social media recon, document metadata, GitHub secrets, domain intelligence
- Secrets Scanning: git repo scanning, config file analysis, environment variable audit, pattern detection
- Email Security: SPF/DKIM/DMARC validation, spoofing tests, SMTP analysis, header forensics
- Digital Forensics: log analysis, file carving, timeline reconstruction, malware analysis
- Evidence Collection: chain of custody, integrity hashing, evidence packaging, court-ready documentation
- Social Engineering: phishing simulations, awareness assessment, typosquatting, pretext generation
- Mobile Security: APK/IPA analysis, permission auditing, SSL pinning, OWASP Mobile Top 10
- C2 Integration: Metasploit RPC, Sliver framework, listener management, session interaction
- Compliance: CIS/NIST/PCI-DSS/ISO27001/HIPAA benchmarking
- Reporting: professional pentest report generation, finding documentation, remediation guidance
- Threat Intelligence: MITRE ATT&CK mapping, IOC enrichment, attack chain analysis
- Automation: scheduled scans, playbook execution, recurring assessments, job management
- Notifications: Slack/Teams/email/webhook alerts for findings, scan completions, and events

Methodology:
1. Define scope and rules of engagement (create project + add targets)
2. Passive reconnaissance first (WHOIS, DNS, certificate transparency)
3. Active scanning with minimal footprint (port scan, service enum)
4. Vulnerability identification and validation
5. Exploitation only when explicitly authorized
6. Document everything with evidence
7. Generate professional reports with remediation guidance

Use severity indicators: [CRITICAL] [HIGH] [MEDIUM] [LOW] [INFO]
Always recommend remediation for findings."""


class CyberSecurityAIAgent:
    def __init__(self, api_key: str = None, model: str = None,
                 max_tokens: int = 8192, db=None, cred_mgr=None, config: dict = None):
        self.client = anthropic.AsyncAnthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.model = model or config.get("ai_agent", {}).get("model", "claude-sonnet-4-5-20250929")
        self.max_tokens = max_tokens
        self.db = db
        self.cred_mgr = cred_mgr
        self.config = config or {}
        self.messages: list[dict] = []
        self.tools = [dict(t) for t in TOOLS]

    async def chat(self, user_message: str) -> str:
        self.messages.append({"role": "user", "content": user_message})

        while True:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                tools=self.tools,
                messages=self.messages,
            )

            assistant_content = response.content
            self.messages.append({"role": "assistant", "content": assistant_content})

            tool_use_blocks = [b for b in assistant_content if b.type == "tool_use"]
            if not tool_use_blocks:
                text_parts = [b.text for b in assistant_content if hasattr(b, "text")]
                return "\n".join(text_parts)

            tool_results = []
            for block in tool_use_blocks:
                tool_name = block.name
                tool_input = block.input
                tool_use_id = block.id

                safety = check_safety(tool_name, tool_input)

                if safety == SafetyLevel.BLOCKED:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps({"error": get_safety_message(safety, tool_name, tool_input)}),
                        "is_error": True,
                    })
                    continue

                if safety == SafetyLevel.DANGEROUS:
                    logger.warning("DANGEROUS tool: %s with params %s", tool_name, tool_input)

                target_id = tool_input.get("target_id") if isinstance(tool_input, dict) else None
                if target_id and self.db:
                    in_scope = await check_scope(self.db, target_id)
                    if not in_scope:
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": json.dumps({"error": "Target is OUT OF SCOPE. Operation blocked."}),
                            "is_error": True,
                        })
                        continue

                result = await self._execute_tool(tool_name, tool_input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": json.dumps(result, default=str),
                })

            self.messages.append({"role": "user", "content": tool_results})

    async def chat_stream(self, user_message: str):
        self.messages.append({"role": "user", "content": user_message})

        while True:
            tool_use_blocks = []
            current_text = ""

            async with self.client.messages.stream(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT,
                tools=self.tools,
                messages=self.messages,
            ) as stream:
                async for event in stream:
                    if event.type == "content_block_start":
                        if hasattr(event.content_block, "text"):
                            pass
                        elif event.content_block.type == "tool_use":
                            yield {"type": "tool_start", "tool": event.content_block.name}
                    elif event.type == "content_block_delta":
                        if hasattr(event.delta, "text"):
                            current_text += event.delta.text
                            yield {"type": "text_delta", "text": event.delta.text}

                response = await stream.get_final_message()

            assistant_content = response.content
            self.messages.append({"role": "assistant", "content": assistant_content})

            tool_use_blocks = [b for b in assistant_content if b.type == "tool_use"]
            if not tool_use_blocks:
                yield {"type": "done"}
                return

            tool_results = []
            for block in tool_use_blocks:
                tool_name = block.name
                tool_input = block.input
                tool_use_id = block.id

                safety = check_safety(tool_name, tool_input)

                if safety == SafetyLevel.BLOCKED:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps({"error": get_safety_message(safety, tool_name)}),
                        "is_error": True,
                    })
                    yield {"type": "tool_result", "tool": tool_name, "error": True}
                    continue

                yield {"type": "tool_executing", "tool": tool_name}
                result = await self._execute_tool(tool_name, tool_input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": json.dumps(result, default=str),
                })
                yield {"type": "tool_result", "tool": tool_name,
                       "result_preview": str(result)[:200]}

            self.messages.append({"role": "user", "content": tool_results})

    async def _execute_tool(self, tool_name: str, params: dict) -> dict:
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            result = await handler(params, self.db, self.cred_mgr, self.config)
            return result
        except Exception as e:
            logger.error("Tool %s failed: %s", tool_name, e, exc_info=True)
            return {"error": f"Tool execution failed: {str(e)}"}

    def reset_conversation(self):
        self.messages.clear()
