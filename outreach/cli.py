"""CLI interface for the Outreach CRM."""

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box
from datetime import datetime, timedelta

from outreach import database as db
from outreach import email_client
from outreach import sequences
from outreach import auto_reply
from outreach import scanner
from outreach.load_leads import load_charlotte_leads

console = Console()
app = typer.Typer(help="Cybersecurity Outreach CRM", no_args_is_help=True)


# --- Configure ---

@app.command()
def configure():
    """Configure email credentials and sender info."""
    db.init_db()
    console.print("\n[bold green]Outreach CRM Configuration[/bold green]\n")

    email_addr = Prompt.ask("Outlook/M365 email address", default=db.get_setting("email_address"))
    password = Prompt.ask("Email password (or app password)", password=True)
    display_name = Prompt.ask("Your display name", default=db.get_setting("display_name"))
    company = Prompt.ask("Your company name", default=db.get_setting("company_name"))
    phone = Prompt.ask("Your phone number", default=db.get_setting("phone"))

    db.set_setting("email_address", email_addr)
    db.set_setting("email_password", password)
    db.set_setting("display_name", display_name)
    db.set_setting("company_name", company)
    db.set_setting("phone", phone)

    console.print("\n[green]Configuration saved![/green]")
    console.print(f"  Email: {email_addr}")
    console.print(f"  Name:  {display_name}")
    console.print(f"  Company: {company}")

    # Test connection
    if Confirm.ask("\nTest email connection?"):
        try:
            import smtplib
            with smtplib.SMTP("smtp.office365.com", 587, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(email_addr, password)
            console.print("[green]SMTP connection successful![/green]")
        except Exception as e:
            console.print(f"[red]SMTP failed: {e}[/red]")
            console.print("[yellow]Tip: You may need to enable SMTP AUTH in M365 admin[/yellow]")
            console.print("[yellow]Or generate an App Password if using MFA[/yellow]")


# --- Dashboard ---

@app.command()
def dashboard():
    """Show pipeline dashboard."""
    db.init_db()
    stats = db.get_pipeline_stats()

    console.print()
    console.print(Panel("[bold]Outreach CRM Dashboard[/bold]", style="green"))

    # Pipeline
    table = Table(title="Pipeline", box=box.ROUNDED)
    table.add_column("Stage", style="bold")
    table.add_column("Count", justify="right")

    stages = [
        ("New", stats["new"], "cyan"),
        ("Contacted", stats["contacted"], "blue"),
        ("Replied", stats["replied"], "green"),
        ("Meeting", stats["meeting"], "yellow"),
        ("Proposal", stats["proposal"], "magenta"),
        ("Won", stats["won"], "bold green"),
        ("Lost", stats["lost"], "red"),
        ("Paused", stats["paused"], "dim"),
    ]

    for name, count, color in stages:
        bar = "#" * min(count, 30)
        table.add_row(f"[{color}]{name}[/{color}]", f"[{color}]{count}[/{color}]  {bar}")

    console.print(table)

    # Stats
    console.print(f"\n  Total leads: [bold]{stats['total']}[/bold]")
    console.print(f"  Emails sent: [bold]{stats['emails_sent']}[/bold]")
    console.print(f"  Replies:     [bold green]{stats['replies']}[/bold green]")
    if stats["emails_sent"] > 0:
        rate = (stats["replies"] / stats["emails_sent"]) * 100
        console.print(f"  Reply rate:  [bold]{rate:.1f}%[/bold]")

    # Active sequences
    active_seqs = db.get_active_sequences()
    if active_seqs:
        console.print(f"\n  Active sequences: [bold]{len(active_seqs)}[/bold]")
        for seq in active_seqs[:5]:
            next_at = seq.get("next_action_at", "?")
            console.print(f"    - {seq['company']} (step {seq['current_step']}, next: {next_at})")

    console.print()


# --- Leads ---

@app.command()
def leads(
    status: str = typer.Option(None, help="Filter by status"),
    category: str = typer.Option(None, help="Filter by category"),
    priority: str = typer.Option(None, help="Filter by priority"),
):
    """List all leads."""
    db.init_db()
    all_leads = db.list_leads(status=status, priority=priority, category=category)

    table = Table(title=f"Leads ({len(all_leads)})", box=box.ROUNDED)
    table.add_column("ID", style="dim", width=4)
    table.add_column("Company", style="bold", max_width=28)
    table.add_column("Contact", max_width=22)
    table.add_column("Category", max_width=12)
    table.add_column("Priority", width=8)
    table.add_column("Status", width=10)
    table.add_column("Email", max_width=28)

    priority_colors = {"high": "red", "medium": "yellow", "low": "dim"}
    status_colors = {"new": "cyan", "contacted": "blue", "replied": "green",
                     "meeting": "yellow", "proposal": "magenta", "won": "bold green",
                     "lost": "red", "paused": "dim"}

    for lead in all_leads:
        pc = priority_colors.get(lead["priority"], "white")
        sc = status_colors.get(lead["status"], "white")
        table.add_row(
            str(lead["id"]),
            lead["company"],
            lead["contact_name"] or "-",
            lead["category"] or "-",
            f"[{pc}]{lead['priority']}[/{pc}]",
            f"[{sc}]{lead['status']}[/{sc}]",
            lead["contact_email"] or "[dim]none[/dim]",
        )

    console.print(table)


@app.command()
def add_lead(
    company: str = typer.Argument(..., help="Company name"),
    email: str = typer.Option("", help="Contact email"),
    name: str = typer.Option("", help="Contact name"),
    title: str = typer.Option("", help="Contact title"),
    industry: str = typer.Option("", help="Industry"),
    category: str = typer.Option("", help="Category (msp, healthcare, fintech, etc.)"),
    priority: str = typer.Option("medium", help="Priority (high/medium/low)"),
    website: str = typer.Option("", help="Website"),
):
    """Add a new lead."""
    db.init_db()
    lead_id = db.add_lead(
        company=company, contact_email=email, contact_name=name,
        contact_title=title, industry=industry, category=category,
        priority=priority, website=website
    )
    console.print(f"[green]Lead #{lead_id} created: {company}[/green]")


@app.command()
def lead_detail(lead_id: int = typer.Argument(..., help="Lead ID")):
    """Show detailed lead info with email history."""
    lead = db.get_lead(lead_id)
    if not lead:
        console.print(f"[red]Lead {lead_id} not found[/red]")
        return

    console.print(Panel(f"[bold]{lead['company']}[/bold]", style="green"))
    console.print(f"  Contact:  {lead['contact_name']} ({lead['contact_title']})")
    console.print(f"  Email:    {lead['contact_email']}")
    console.print(f"  Industry: {lead['industry']}")
    console.print(f"  Category: {lead['category']}")
    console.print(f"  Size:     {lead['size']}")
    console.print(f"  Website:  {lead['website']}")
    console.print(f"  Priority: {lead['priority']}")
    console.print(f"  Status:   {lead['status']}")
    console.print(f"  Notes:    {lead['notes']}")

    # Email history
    emails = db.get_emails_for_lead(lead_id)
    if emails:
        console.print(f"\n[bold]Email History ({len(emails)}):[/bold]")
        for em in emails:
            direction = ">>" if em["direction"] == "outbound" else "<<"
            color = "green" if em["status"] == "sent" else "yellow" if em["status"] == "queued" else "red" if em["status"] == "failed" else "cyan"
            console.print(f"  {direction} [{color}]{em['status']}[/{color}] {em['email_type']}: {em['subject']} ({em.get('sent_at') or em['created_at']})")

    # Interactions
    interactions = db.get_interactions(lead_id)
    if interactions:
        console.print(f"\n[bold]Activity Log ({len(interactions)}):[/bold]")
        for i in interactions[:10]:
            console.print(f"  [{i['created_at']}] {i['interaction_type']}: {i['summary']}")


@app.command()
def update(
    lead_id: int = typer.Argument(..., help="Lead ID"),
    status: str = typer.Option(None, help="New status"),
    email: str = typer.Option(None, help="Contact email"),
    name: str = typer.Option(None, help="Contact name"),
    priority: str = typer.Option(None, help="Priority"),
    notes: str = typer.Option(None, help="Notes"),
):
    """Update a lead."""
    kwargs = {}
    if status:
        kwargs["status"] = status
    if email:
        kwargs["contact_email"] = email
    if name:
        kwargs["contact_name"] = name
    if priority:
        kwargs["priority"] = priority
    if notes:
        kwargs["notes"] = notes

    if not kwargs:
        console.print("[yellow]Nothing to update. Use --status, --email, --name, etc.[/yellow]")
        return

    db.update_lead(lead_id, **kwargs)
    console.print(f"[green]Lead #{lead_id} updated[/green]")


# --- Email Commands ---

@app.command()
def send(lead_id: int = typer.Argument(..., help="Lead ID to email")):
    """Queue the personalized email for a lead and start follow-up sequence."""
    lead = db.get_lead(lead_id)
    if not lead:
        console.print(f"[red]Lead {lead_id} not found[/red]")
        return
    if not lead["contact_email"]:
        console.print(f"[red]No email address for {lead['company']}. Update with: outreach update {lead_id} --email ADDRESS[/red]")
        return

    # Check for existing personalized email in templates
    from outreach.load_leads import get_email_for_lead
    subject, body = get_email_for_lead(lead)

    if not subject:
        subject = Prompt.ask("Email subject")
        body = Prompt.ask("Email body (or 'edit' to open editor)")

    console.print(f"\n[bold]To:[/bold] {lead['contact_email']}")
    console.print(f"[bold]Subject:[/bold] {subject}")
    console.print(f"\n{body[:300]}...")

    if Confirm.ask("\nQueue this email for sending?"):
        email_id = email_client.send_to_lead(lead_id, subject, body, "initial", queue=True)
        console.print(f"[green]Email #{email_id} queued[/green]")

        # Start follow-up sequence
        seq_name = "msp_partnership" if lead.get("category") == "msp" else "default"
        if Confirm.ask(f"Start auto follow-up sequence ({seq_name})?"):
            seq_id = db.start_sequence(lead_id, seq_name)
            next_action = datetime.now() + timedelta(days=3)
            db.update_sequence(seq_id, current_step=1,
                             next_action_at=next_action.isoformat())
            console.print(f"[green]Sequence started. Follow-up 1 in 3 days.[/green]")


@app.command()
def send_all():
    """Send all queued emails now."""
    queued = db.get_queued_emails()
    if not queued:
        console.print("[yellow]No emails in queue[/yellow]")
        return

    console.print(f"\n[bold]Ready to send {len(queued)} emails:[/bold]")
    for em in queued:
        console.print(f"  -> {em['company']} ({em['contact_email']}): {em['subject']}")

    if Confirm.ask(f"\nSend all {len(queued)} emails now?"):
        stats = email_client.send_queued_emails()
        console.print(f"\n[green]Sent: {stats['sent']}[/green]")
        if stats["failed"]:
            console.print(f"[red]Failed: {stats['failed']}[/red]")
            for err in stats["errors"]:
                console.print(f"  [red]{err}[/red]")


@app.command()
def check():
    """Check inbox for replies from leads."""
    console.print("[cyan]Checking inbox for replies...[/cyan]")
    replies = email_client.check_replies()

    if replies:
        console.print(f"\n[bold green]Found {len(replies)} new replies![/bold green]\n")
        for r in replies:
            console.print(Panel(
                f"[bold]{r['company']}[/bold] ({r['from']})\n"
                f"Subject: {r['subject']}\n"
                f"Date: {r['date']}\n\n"
                f"{r['body_preview']}...",
                title="New Reply",
                style="green"
            ))
    else:
        console.print("[dim]No new replies found[/dim]")


@app.command()
def process():
    """Process follow-up sequences, check replies, and auto-generate responses."""
    console.print("[cyan]Processing outreach pipeline...[/cyan]\n")

    # Step 1: Check for replies and process with AI auto-reply
    mode = db.get_setting("auto_reply_mode", "review")
    ar_results = auto_reply.process_all_new_replies(mode=mode)

    if ar_results["new_replies"] > 0:
        console.print(f"[green]New replies: {ar_results['new_replies']}[/green]")
        for detail in ar_results["details"]:
            console.print(f"  - {detail['company']}: {detail['category']} -> {detail['action']}")
        if ar_results["drafted"] > 0:
            console.print(f"[yellow]  {ar_results['drafted']} draft replies need review: outreach drafts[/yellow]")
    else:
        console.print("[dim]No new replies[/dim]")

    # Step 2: Process follow-up sequences
    console.print()
    results = sequences.process_sequences()
    console.print(f"Follow-ups queued: {results['sent']}")
    console.print(f"Sequences completed: {results['completed']}")

    # Step 3: Send queued emails
    queued = db.get_queued_emails()
    if queued:
        console.print(f"\n[bold]{len(queued)} emails ready to send[/bold]")
        if Confirm.ask("Send now?"):
            stats = email_client.send_queued_emails()
            console.print(f"[green]Sent: {stats['sent']}[/green]")


# --- Bulk Operations ---

@app.command()
def load():
    """Load Charlotte, NC leads into the CRM."""
    db.init_db()
    count = load_charlotte_leads()
    console.print(f"[green]Loaded {count} leads into the CRM[/green]")
    console.print("Run [bold]outreach leads[/bold] to see them")


@app.command()
def campaign(
    category: str = typer.Argument(..., help="Category to email (msp, healthcare, fintech, all)"),
):
    """Queue personalized emails for all leads in a category and start sequences."""
    filter_cat = None if category == "all" else category
    all_leads = db.list_leads(status="new", category=filter_cat)

    if not all_leads:
        console.print(f"[yellow]No 'new' leads found in category: {category}[/yellow]")
        return

    from outreach.load_leads import get_email_for_lead
    ready = []
    for lead in all_leads:
        if lead["contact_email"]:
            subject, body = get_email_for_lead(lead)
            if subject:
                ready.append((lead, subject, body))

    console.print(f"\n[bold]Campaign: {category}[/bold]")
    console.print(f"  Leads with email + template: {len(ready)}")
    console.print(f"  Leads without email: {len(all_leads) - len(ready)}")

    if not ready:
        console.print("[yellow]No leads have both an email address and a template ready.[/yellow]")
        console.print("[yellow]Add emails with: outreach update <ID> --email ADDRESS[/yellow]")
        return

    for lead, subject, _ in ready:
        console.print(f"  -> {lead['company']} ({lead['contact_email']}): {subject}")

    if Confirm.ask(f"\nQueue {len(ready)} emails and start follow-up sequences?"):
        for lead, subject, body in ready:
            email_id = email_client.send_to_lead(lead["id"], subject, body, "initial", queue=True)
            seq_name = "msp_partnership" if lead.get("category") == "msp" else "default"
            seq_id = db.start_sequence(lead["id"], seq_name)
            next_action = datetime.now() + timedelta(days=3)
            db.update_sequence(seq_id, current_step=1,
                             next_action_at=next_action.isoformat())

        console.print(f"\n[green]Queued {len(ready)} emails with auto follow-up sequences[/green]")
        console.print("Run [bold]outreach send-all[/bold] to send them")


# --- Auto-Reply ---

@app.command()
def auto(
    mode: str = typer.Option("review", help="Mode: 'review' (draft for approval) or 'auto' (send immediately)"),
):
    """Check inbox and AI-generate replies to new messages."""
    db.init_db()
    console.print(f"\n[cyan]Checking inbox and processing replies (mode: {mode})...[/cyan]\n")

    results = auto_reply.process_all_new_replies(mode=mode)

    if results["new_replies"] == 0:
        console.print("[dim]No new replies found[/dim]")
        return

    console.print(f"[bold]Processed {results['new_replies']} new replies:[/bold]\n")

    for detail in results["details"]:
        cat = detail["category"]
        cat_colors = {
            "interested": "green", "meeting_request": "bold green",
            "question": "cyan", "referral": "yellow",
            "objection": "red", "not_interested": "dim red",
            "out_of_office": "dim", "unrelated": "dim",
        }
        color = cat_colors.get(cat, "white")
        action = detail["action"]
        console.print(f"  [{color}]{cat:18s}[/{color}] {detail['company']}")
        console.print(f"                     {detail['summary']}")
        console.print(f"                     Action: {action}\n")

    console.print(f"  Auto-replied: {results['auto_replied']}")
    console.print(f"  Drafts to review: {results['drafted']}")
    console.print(f"  Declined/lost: {results['declined']}")
    console.print(f"  Out of office: {results['ooo']}")

    if results["drafted"] > 0:
        console.print(f"\n[yellow]Run [bold]outreach drafts[/bold] to review and approve AI-drafted replies[/yellow]")

    if results["auto_replied"] > 0:
        console.print(f"\n[green]Run [bold]outreach send-all[/bold] to send queued auto-replies[/green]")


@app.command()
def drafts():
    """Review AI-drafted replies waiting for approval."""
    db.init_db()
    pending = auto_reply.get_draft_replies()

    if not pending:
        console.print("[dim]No draft replies waiting for review[/dim]")
        return

    console.print(f"\n[bold]Draft Replies ({len(pending)}):[/bold]\n")

    for draft in pending:
        console.print(Panel(
            f"[bold]To:[/bold] {draft['contact_name']} at {draft['company']} ({draft['contact_email']})\n"
            f"[bold]Subject:[/bold] {draft['subject']}\n\n"
            f"{draft['body']}",
            title=f"Draft #{draft['id']}",
            style="cyan"
        ))

        action = Prompt.ask(
            "Action",
            choices=["approve", "edit", "discard", "skip"],
            default="approve"
        )

        if action == "approve":
            auto_reply.approve_draft(draft["id"])
            console.print(f"[green]Draft #{draft['id']} approved and queued[/green]\n")
        elif action == "edit":
            console.print("[yellow]Type your edited reply (end with a blank line):[/yellow]")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            new_body = "\n".join(lines)
            if new_body.strip():
                auto_reply.edit_and_approve(draft["id"], new_body)
                console.print(f"[green]Draft #{draft['id']} edited and queued[/green]\n")
            else:
                console.print("[yellow]Empty edit -- skipped[/yellow]\n")
        elif action == "discard":
            auto_reply.discard_draft(draft["id"])
            console.print(f"[red]Draft #{draft['id']} discarded[/red]\n")
        else:
            console.print("[dim]Skipped[/dim]\n")

    queued = db.get_queued_emails()
    if queued:
        console.print(f"\n[bold]{len(queued)} emails queued.[/bold] Run [bold]outreach send-all[/bold] to send.")


@app.command()
def sendgrid(
    api_key: str = typer.Option(None, help="SendGrid API key"),
    test: bool = typer.Option(False, help="Send a test email"),
):
    """Configure SendGrid for email sending."""
    db.init_db()

    if api_key:
        db.set_setting("sendgrid_api_key", api_key)
        console.print("[green]SendGrid API key saved[/green]")

    current_key = db.get_setting("sendgrid_api_key")
    if current_key:
        console.print(f"  API key: {current_key[:12]}...{current_key[-4:]}")
    else:
        console.print("[yellow]No SendGrid API key configured[/yellow]")
        console.print("  Set with: outreach sendgrid --api-key SG.xxx")
        return

    if test:
        sender = db.get_setting("email_address")
        console.print(f"\n[cyan]Sending test email via SendGrid from {sender}...[/cyan]")
        success, result = email_client.send_email(
            to_email=sender,
            subject="Voltsys AI - SendGrid Test",
            body="This is a test email sent via SendGrid.\n\nIf you see this with the Voltsys AI signature and logo, everything is working correctly.",
        )
        if success:
            console.print(f"[green]Test email sent! Check {sender}[/green]")
        else:
            console.print(f"[red]Failed: {result}[/red]")


@app.command()
def auto_settings(
    mode: str = typer.Option(None, help="Default mode: 'review' or 'auto'"),
    show: bool = typer.Option(False, help="Show current settings"),
):
    """Configure auto-reply settings."""
    db.init_db()

    if show or not mode:
        current_mode = db.get_setting("auto_reply_mode", "review")
        console.print(f"\n[bold]Auto-Reply Settings:[/bold]")
        console.print(f"  Mode: [cyan]{current_mode}[/cyan]")
        console.print(f"\n  [dim]review[/dim] = AI drafts replies for your approval before sending")
        console.print(f"  [dim]auto[/dim]   = AI sends replies immediately for positive responses")
        console.print(f"          (objections and declines always go to review)\n")
        return

    if mode in ("review", "auto"):
        db.set_setting("auto_reply_mode", mode)
        console.print(f"[green]Auto-reply mode set to: {mode}[/green]")
    else:
        console.print("[red]Invalid mode. Use 'review' or 'auto'[/red]")


# --- Security Scanner ---

@app.command()
def scan(
    url: str = typer.Argument(..., help="Website URL or domain to scan"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all header details"),
):
    """Scan a website for missing security headers and SSL issues."""
    console.print(f"\n[cyan]Scanning {url}...[/cyan]\n")
    result = scanner.scan_website(url)

    if not result.reachable:
        console.print(f"[red]Unreachable: {result.error}[/red]")
        return

    # Grade with color
    grade_colors = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    gc = grade_colors.get(result.grade, "white")

    console.print(Panel(
        f"  Grade: [{gc}]{result.grade}[/{gc}]  (Score: {result.score}/100)\n"
        f"  URL: {result.final_url}\n"
        f"  Status: {result.status_code} | Response: {result.response_time_ms}ms",
        title=f"Security Scan: {scanner._normalize_domain(url)}",
        style="cyan"
    ))

    # Headers table
    table = Table(title="Security Headers", box=box.ROUNDED)
    table.add_column("Header", style="bold", min_width=32)
    table.add_column("Status", width=10)
    table.add_column("Value", max_width=40)

    for header, (weight, severity, desc) in scanner.SECURITY_HEADERS.items():
        if header in result.headers_present:
            val = result.headers_present[header]
            table.add_row(header, "[green]Present[/green]", val[:40] if verbose else "")
        else:
            sev_color = {"high": "bold red", "medium": "red", "low": "yellow"}.get(severity, "red")
            table.add_row(header, f"[{sev_color}]MISSING[/{sev_color}]", f"[dim]{desc}[/dim]")

    console.print(table)

    # Server info
    if result.server_info:
        info_parts = [f"{k}: {v}" for k, v in result.server_info.items()]
        console.print(f"\n  [yellow]Info Disclosure:[/yellow] {' | '.join(info_parts)}")

    # SSL
    if result.ssl_valid:
        console.print(f"  [green]SSL:[/green] Valid ({result.ssl_issuer}, expires {result.ssl_expiry}, {result.ssl_days_remaining}d remaining)")
    else:
        console.print(f"  [red]SSL:[/red] {result.ssl_issuer or 'Not configured / Invalid'}")

    # Cookies
    if result.cookie_issues:
        console.print(f"\n  [yellow]Cookie Issues:[/yellow]")
        for issue in result.cookie_issues:
            console.print(f"    - {issue}")

    console.print()


@app.command()
def scan_bulk_cmd(
    file: str = typer.Argument(..., help="File with URLs, one per line"),
    output: str = typer.Option(None, "--output", "-o", help="Save results to CSV"),
    delay: float = typer.Option(1.5, help="Delay between requests in seconds"),
    import_leads: bool = typer.Option(False, "--import", help="Import D/F graded sites as CRM leads"),
    industry: str = typer.Option("", "--industry", "-i", help="Industry for imported leads"),
    category: str = typer.Option("", "--category", "-c", help="Category for imported leads"),
):
    """Scan multiple websites from a URL list file."""
    db.init_db()
    from pathlib import Path
    filepath = Path(file)
    if not filepath.exists():
        console.print(f"[red]File not found: {file}[/red]")
        return

    urls = [line.strip() for line in filepath.read_text().splitlines() if line.strip() and not line.startswith("#")]
    if not urls:
        console.print("[yellow]No URLs found in file[/yellow]")
        return

    console.print(f"\n[cyan]Scanning {len(urls)} websites...[/cyan]\n")

    def progress(current, total, url):
        console.print(f"  [{current}/{total}] {url}...")

    results = scanner.scan_bulk(urls, delay=delay, progress_callback=progress)

    # Summary table
    table = Table(title=f"Scan Results ({len(results)} sites)", box=box.ROUNDED)
    table.add_column("Website", style="bold", max_width=30)
    table.add_column("Grade", width=6, justify="center")
    table.add_column("Score", width=6, justify="right")
    table.add_column("Missing", width=8, justify="right")
    table.add_column("Server", max_width=25)
    table.add_column("SSL", width=8)

    grade_colors = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}

    for r in sorted(results, key=lambda x: x.score):
        gc = grade_colors.get(r.grade, "white")
        domain = scanner._normalize_domain(r.url)
        server = " | ".join(r.server_info.values())[:25] if r.server_info else "-"
        ssl_status = "[green]Valid[/green]" if r.ssl_valid else "[red]No[/red]"
        if not r.reachable:
            table.add_row(domain, "[dim]?[/dim]", "-", "-", "-", f"[red]{r.error[:20]}[/red]")
        else:
            table.add_row(domain, f"[{gc}]{r.grade}[/{gc}]", str(r.score),
                         str(len(r.headers_missing)), server, ssl_status)

    console.print(table)

    # Grade distribution
    grades = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for r in results:
        if r.reachable:
            grades[r.grade] += 1
    unreachable = sum(1 for r in results if not r.reachable)

    console.print(f"\n  Grade Distribution: A:{grades['A']} B:{grades['B']} C:{grades['C']} D:{grades['D']} F:{grades['F']} Unreachable:{unreachable}")
    console.print(f"  Potential leads (D/F): [bold]{grades['D'] + grades['F']}[/bold]")

    if import_leads:
        stats = scanner.import_from_scan(results, industry=industry, category=category)
        console.print(f"\n  [green]Imported: {stats['imported']}[/green]")
        console.print(f"  Skipped (good security): {stats['skipped_good']}")
        console.print(f"  Skipped (duplicate): {stats['skipped_duplicate']}")

    if output:
        csv_data = scanner.export_results_csv(results)
        Path(output).write_text(csv_data)
        console.print(f"\n[green]Results saved to {output}[/green]")

    console.print()


@app.command()
def discover(
    location: str = typer.Argument(..., help="Location (e.g., 'Charlotte NC')"),
    industry: str = typer.Option("", "--industry", "-i", help="Industry filter"),
    max_results: int = typer.Option(20, "--max", "-m", help="Max results to discover"),
    import_leads: bool = typer.Option(False, "--import", help="Import discovered leads to CRM"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would be imported"),
):
    """Discover local businesses via Google search, scan their security, and import as leads."""
    db.init_db()
    industry_str = f" ({industry})" if industry else ""
    console.print(f"\n[cyan]Discovering businesses in {location}{industry_str}...[/cyan]\n")

    def progress(current, total, url):
        console.print(f"  Scanning [{current}/{total}] {url}...")

    try:
        stats = scanner.scan_and_import(
            location=location,
            industry=industry,
            max_results=max_results,
            dry_run=dry_run if not import_leads else False,
            progress_callback=progress,
        )
    except ImportError as e:
        console.print(f"[red]{e}[/red]")
        return

    # Results table
    if stats["results"]:
        table = Table(title="Discovered Businesses", box=box.ROUNDED)
        table.add_column("Company", style="bold", max_width=30)
        table.add_column("Website", max_width=25)
        table.add_column("Grade", width=6, justify="center")
        table.add_column("Score", width=6, justify="right")
        table.add_column("Missing", width=8, justify="right")
        table.add_column("Action", width=18)

        grade_colors = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
        action_colors = {
            "imported": "green", "would_import": "cyan",
            "skipped_good": "dim", "skipped_duplicate": "yellow",
        }

        for r in sorted(stats["results"], key=lambda x: x["score"]):
            gc = grade_colors.get(r["grade"], "white")
            ac = action_colors.get(r["action"], "white")
            table.add_row(
                r["company"][:30], r["website"][:25],
                f"[{gc}]{r['grade']}[/{gc}]", str(r["score"]),
                str(r["missing"]), f"[{ac}]{r['action']}[/{ac}]",
            )

        console.print(table)

    console.print(f"\n  Discovered: {stats['discovered']}")
    console.print(f"  Scanned: {stats['scanned']}")
    console.print(f"  {'Imported' if import_leads else 'Would import'}: [bold]{stats['imported']}[/bold]")
    console.print(f"  Skipped (good security): {stats['skipped_good']}")
    console.print(f"  Skipped (duplicate): {stats['skipped_duplicate']}")

    if dry_run and stats["imported"] > 0:
        console.print(f"\n[yellow]Dry run -- no leads were imported. Re-run with --import to add them.[/yellow]")

    console.print()


@app.command()
def scan_leads(
    category: str = typer.Option(None, help="Only scan leads in this category"),
    update: bool = typer.Option(True, "--update/--no-update", help="Update lead notes with scan results"),
):
    """Scan all existing leads' websites for security issues."""
    db.init_db()
    leads = db.list_leads(category=category)
    leads_with_site = [l for l in leads if l.get("website")]

    if not leads_with_site:
        console.print("[yellow]No leads with websites to scan[/yellow]")
        return

    console.print(f"\n[cyan]Scanning {len(leads_with_site)} lead websites...[/cyan]\n")

    def progress(current, total, url):
        console.print(f"  [{current}/{total}] {url}...")

    if update:
        stats = scanner.scan_existing_leads(category=category, progress_callback=progress)
        console.print(f"\n  Scanned: {stats['scanned']}")
        console.print(f"  Updated: [green]{stats['updated']}[/green]")
        console.print(f"  Unreachable: [yellow]{stats['unreachable']}[/yellow]")
    else:
        urls = [l["website"] for l in leads_with_site]
        results = scanner.scan_bulk(urls, delay=1.5, progress_callback=progress)

        table = Table(title="Lead Security Scan", box=box.ROUNDED)
        table.add_column("Company", style="bold", max_width=28)
        table.add_column("Website", max_width=25)
        table.add_column("Grade", width=6, justify="center")
        table.add_column("Score", width=6, justify="right")
        table.add_column("Missing Headers", width=8, justify="right")

        grade_colors = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}

        domain_to_lead = {}
        for l in leads_with_site:
            domain_to_lead[scanner._normalize_domain(l["website"])] = l

        for r in sorted(results, key=lambda x: x.score):
            gc = grade_colors.get(r.grade, "white")
            domain = scanner._normalize_domain(r.url)
            lead = domain_to_lead.get(domain, {})
            company = lead.get("company", domain)
            if r.reachable:
                table.add_row(company[:28], domain[:25], f"[{gc}]{r.grade}[/{gc}]",
                             str(r.score), str(len(r.headers_missing)))
            else:
                table.add_row(company[:28], domain[:25], "[dim]?[/dim]", "-", f"[red]Unreachable[/red]")

        console.print(table)

    console.print()


@app.command()
def outreach_scan_leads(
    source: str = typer.Option("security_scan", help="Lead source to target"),
):
    """Find contact emails for scan-discovered leads, generate personalized emails, and queue them."""
    db.init_db()

    # Step 1: Scrape emails
    console.print("\n[cyan]Step 1: Scraping contact emails from lead websites...[/cyan]\n")

    def email_progress(current, total, url):
        console.print(f"  [{current}/{total}] {url}...")

    email_stats = scanner.scrape_emails_for_leads(source=source, progress_callback=email_progress)
    console.print(f"\n  Emails found: [green]{email_stats['found']}[/green]")
    console.print(f"  Not found: [yellow]{email_stats['not_found']}[/yellow]")

    # Step 2: Generate outreach emails
    console.print(f"\n[cyan]Step 2: Generating personalized outreach emails...[/cyan]\n")
    gen_stats = scanner.generate_and_queue_scan_emails(source=source)
    console.print(f"  Emails generated: [green]{gen_stats['queued']}[/green]")
    console.print(f"  Skipped (no scan data): {gen_stats['skipped_no_scan']}")
    console.print(f"  Skipped (already has email): {gen_stats['skipped_has_email']}")

    # Step 3: Show leads ready to send
    leads = db.list_leads(status="new")
    ready = []
    for l in leads:
        if l.get("source") == source and l.get("contact_email"):
            emails = db.get_emails_for_lead(l["id"])
            drafts = [e for e in emails if e["status"] == "draft" and e["direction"] == "outbound"]
            if drafts:
                ready.append((l, drafts[0]))

    if ready:
        console.print(f"\n[bold]{len(ready)} emails ready to review and send:[/bold]\n")
        table = Table(box=box.ROUNDED)
        table.add_column("ID", width=4)
        table.add_column("Company", style="bold", max_width=30)
        table.add_column("Email", max_width=30)
        table.add_column("Subject", max_width=40)

        for lead, email in ready:
            table.add_row(str(lead["id"]), lead["company"][:30],
                         lead["contact_email"], email["subject"][:40])

        console.print(table)
        console.print(f"\n  To review: [bold]outreach drafts[/bold]")
        console.print(f"  To queue all: run the command below")
        console.print(f"  To send: [bold]outreach send-all[/bold]\n")

        if Confirm.ask(f"Queue all {len(ready)} draft emails for sending now?"):
            conn = db.get_db()
            for lead, email in ready:
                conn.execute("UPDATE emails SET status = 'queued' WHERE id = ?", (email["id"],))
            conn.commit()
            conn.close()
            console.print(f"[green]{len(ready)} emails queued! Run 'outreach send-all' to send.[/green]\n")
    else:
        console.print("\n[yellow]No emails ready to send. Leads may need contact emails added manually.[/yellow]\n")


def main():
    app()


if __name__ == "__main__":
    main()
