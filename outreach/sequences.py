"""Automated follow-up email sequences."""

from datetime import datetime, timedelta
from . import database as db
from . import email_client


# Follow-up sequence definitions (step -> days delay, email type, subject template, body template)
SEQUENCES = {
    "default": [
        {
            "step": 0,
            "delay_days": 0,
            "email_type": "initial",
            "subject": None,  # Uses the personalized email
            "body": None,
        },
        {
            "step": 1,
            "delay_days": 3,
            "email_type": "followup_1",
            "subject_prefix": "Re: ",
            "body": """Hi {contact_name},

Just following up on my note from a few days ago. I know cybersecurity assessments aren't usually the most urgent item on the list -- until they are.

I'd be happy to share a quick overview of the most common vulnerabilities I find in {industry} organizations -- no sales pitch, just useful context your team can act on immediately.

Would 10 minutes work this week?

Best,
{sender_name}""",
        },
        {
            "step": 2,
            "delay_days": 7,
            "email_type": "followup_2",
            "subject_prefix": "Re: ",
            "body": """Hi {contact_name},

I put together a brief checklist of the top 10 security gaps I see most often in {industry} organizations during assessments. Thought it might be useful for your team regardless of whether we work together.

Would you like me to send it over?

Best,
{sender_name}""",
        },
        {
            "step": 3,
            "delay_days": 14,
            "email_type": "followup_3",
            "subject_prefix": "Re: ",
            "body": """Hi {contact_name},

I want to be respectful of your time, so this will be my last note. If cybersecurity assessments aren't a priority right now, I completely understand.

If it ever does come up -- whether it's a compliance audit, an insurance requirement, or just wanting to know where you stand -- I'm here in Charlotte and happy to help.

Wishing {company} continued success.

Best,
{sender_name}
{sender_company}
{sender_phone}""",
        },
    ],
    "msp_partnership": [
        {
            "step": 0,
            "delay_days": 0,
            "email_type": "initial",
            "subject": None,
            "body": None,
        },
        {
            "step": 1,
            "delay_days": 3,
            "email_type": "followup_1",
            "subject_prefix": "Re: ",
            "body": """Hi {contact_name},

Following up on my partnership note. I know you're busy keeping clients running, so I'll keep this short.

The pitch is simple: your regulated clients need annual pentests. I deliver them under your brand. You add revenue without adding headcount.

I've got availability this month for a pilot engagement if you'd like to see the quality of work before committing to anything.

Quick call?

Best,
{sender_name}""",
        },
        {
            "step": 2,
            "delay_days": 7,
            "email_type": "followup_2",
            "subject_prefix": "Re: ",
            "body": """Hi {contact_name},

One more thought -- I ran the numbers on what a typical pentest partnership looks like for an MSP:

- Average pentest engagement: $5,000
- Wholesale rate to you: $3,000
- Your margin: $2,000 per engagement
- If 20 of your clients need an annual pentest: $40,000/year in new revenue

No hiring, no training, no new tools. Just a referral or white-label arrangement.

Worth 15 minutes to discuss?

Best,
{sender_name}""",
        },
        {
            "step": 3,
            "delay_days": 14,
            "email_type": "followup_3",
            "subject_prefix": "Re: ",
            "body": """Hi {contact_name},

Last note from me. If the timing isn't right for a pentest partnership, I completely understand.

If any of your clients ever ask about penetration testing, vulnerability assessments, or compliance audits -- feel free to send them my way. I'm always happy to help, with or without a formal partnership.

Best,
{sender_name}
{sender_company}
{sender_phone}""",
        },
    ],
}


def format_body(template: str, lead: dict) -> str:
    """Fill in template variables."""
    sender_name = db.get_setting("display_name", "[YOUR NAME]")
    sender_company = db.get_setting("company_name", "[YOUR COMPANY]")
    sender_phone = db.get_setting("phone", "[YOUR PHONE]")

    contact_name = lead.get("contact_name", "").split()[0] if lead.get("contact_name") else "there"

    return template.format(
        contact_name=contact_name,
        company=lead.get("company", ""),
        industry=lead.get("industry", "your industry"),
        sender_name=sender_name,
        sender_company=sender_company,
        sender_phone=sender_phone,
    )


def process_sequences():
    """Check active sequences and send due follow-ups."""
    active = db.get_active_sequences()
    results = {"sent": 0, "completed": 0, "errors": []}

    for seq in active:
        # Skip if no next action time or not due yet
        if seq["next_action_at"]:
            next_time = datetime.fromisoformat(seq["next_action_at"])
            if next_time > datetime.now():
                continue

        lead = db.get_lead(seq["lead_id"])
        if not lead or not lead["contact_email"]:
            continue

        # Check if lead already replied (stop sequence)
        if lead["status"] == "replied":
            db.update_sequence(seq["id"], is_active=0, paused_reason="Lead replied")
            continue

        sequence_def = SEQUENCES.get(seq["sequence_name"], SEQUENCES["default"])
        current_step = seq["current_step"]

        # Find the next step to execute
        next_step = None
        for step_def in sequence_def:
            if step_def["step"] == current_step:
                next_step = step_def
                break

        if not next_step:
            # Sequence complete
            db.update_sequence(seq["id"], is_active=0,
                             completed_at=datetime.now().isoformat())
            results["completed"] += 1
            continue

        # Skip step 0 (initial email already sent manually)
        if next_step["step"] == 0:
            next_next = current_step + 1
            if next_next < len(sequence_def):
                delay = sequence_def[next_next]["delay_days"]
                next_action = datetime.now() + timedelta(days=delay)
                db.update_sequence(seq["id"], current_step=next_next,
                                 next_action_at=next_action.isoformat())
            continue

        # Get the original email subject for Re: prefix
        original_emails = db.get_emails_for_lead(seq["lead_id"])
        original_subject = ""
        for em in original_emails:
            if em["email_type"] == "initial" and em["direction"] == "outbound":
                original_subject = em["subject"]
                break

        subject = next_step.get("subject_prefix", "") + original_subject
        body = format_body(next_step["body"], lead)

        # Queue the follow-up
        email_id = db.add_email(
            lead_id=seq["lead_id"],
            subject=subject,
            body=body,
            email_type=next_step["email_type"],
            direction="outbound",
            status="queued"
        )

        # Advance sequence
        next_step_num = current_step + 1
        if next_step_num < len(sequence_def):
            delay = sequence_def[next_step_num]["delay_days"] - next_step["delay_days"]
            next_action = datetime.now() + timedelta(days=max(delay, 1))
            db.update_sequence(seq["id"], current_step=next_step_num,
                             next_action_at=next_action.isoformat())
        else:
            db.update_sequence(seq["id"], is_active=0,
                             completed_at=datetime.now().isoformat())
            results["completed"] += 1

        results["sent"] += 1

    return results
