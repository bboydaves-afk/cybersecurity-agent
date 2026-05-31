"""Interactive chat session for CyberSecurity Agent."""

import asyncio
import logging
import os

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

logger = logging.getLogger("hacking_agent.chat")
console = Console()


class ChatSession:
    def __init__(self, config: dict = None, voice: bool = False):
        self.config = config or {}
        self.voice = voice
        self.agent = None

    async def start(self):
        from core.database import Database
        from core.credentials import CredentialManager
        from .agent import CyberSecurityAIAgent

        db_path = self.config.get("database", {}).get("path", "./data/hacking_agent.db")
        db = Database(db_path)
        await db.connect()
        cred_mgr = CredentialManager(db)

        api_key = os.environ.get("ANTHROPIC_API_KEY") or self.config.get("ai_agent", {}).get("api_key", "")

        self.agent = CyberSecurityAIAgent(
            api_key=api_key, db=db, cred_mgr=cred_mgr, config=self.config)

        console.print(Panel(
            "[bold green]CyberSecurity AI Agent[/bold green]\n"
            "[dim]AI-Powered Penetration Testing & Security Assessment[/dim]\n\n"
            f"[cyan]Tools:[/cyan] {len(self.agent.tools)} available\n"
            f"[cyan]Model:[/cyan] {self.agent.model}\n\n"
            "[dim]Commands: 'exit' to quit, 'reset' to clear history[/dim]",
            title="[bold]Welcome[/bold]",
            border_style="green",
        ))

        try:
            while True:
                try:
                    user_input = console.input("\n[bold cyan]You>[/bold cyan] ").strip()
                except (EOFError, KeyboardInterrupt):
                    break

                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit", "q"):
                    break
                if user_input.lower() == "reset":
                    self.agent.reset_conversation()
                    console.print("[yellow]Conversation reset.[/yellow]")
                    continue

                console.print()
                try:
                    response = ""
                    async for event in self.agent.chat_stream(user_input):
                        if event["type"] == "text_delta":
                            console.print(event["text"], end="")
                            response += event["text"]
                        elif event["type"] == "tool_start":
                            console.print(f"\n[dim]> Using tool: {event['tool']}...[/dim]")
                        elif event["type"] == "tool_executing":
                            console.print(f"[dim]> Executing: {event['tool']}...[/dim]")
                        elif event["type"] == "tool_result":
                            if event.get("error"):
                                console.print(f"[red]> Tool error: {event['tool']}[/red]")
                            else:
                                console.print(f"[green]> {event['tool']} completed[/green]")
                        elif event["type"] == "done":
                            console.print()
                except Exception as e:
                    console.print(f"\n[red]Error: {e}[/red]")
                    logger.error("Chat error: %s", e, exc_info=True)

        finally:
            await db.close()
            console.print("\n[dim]Session ended.[/dim]")
