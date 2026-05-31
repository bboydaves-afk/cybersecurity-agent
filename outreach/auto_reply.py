"""AI-powered auto-reply engine using Claude to analyze and respond to lead emails."""

import os
import json
from datetime import datetime
from typing import Optional

try:
    import anthropic
except ImportError:
    anthropic = None

from . import database as db
from . import email_client


# Reply classification categories
REPLY_CATEGORIES = {
    "interested": "Lead expressed interest in services or wants to learn more",
    "meeting_request": "Lead wants to schedule a call or meeting",
    "question": "Lead asked a question about services, pricing, process, etc.",
    "objection": "Lead raised a concern or objection but didn't say no",
    "not_interested": "Lead explicitly declined or asked to stop emails",
    "out_of_office": "Automated out-of-office or vacation reply",
    "referral": "Lead referred you to someone else at their company",
    "unrelated": "Reply doesn't relate to the outreach (spam, newsletter, etc.)",
}

# System prompt for the AI reply engine
SYSTEM_PROMPT = """You are an AI assistant helping David Lopez, a cybersecurity penetration testing consultant at Voltsys AI in Charlotte, NC. Your job is to analyze incoming email replies from business leads and draft professional, natural responses.

About Voltsys AI:
- Cybersecurity assessment firm in Charlotte, NC
- Services: penetration testing (external, internal, web app, cloud, wireless), vulnerability assessments, compliance audits
- Industries: MSPs (white-label partnerships), healthcare (HIPAA), fintech (PCI-DSS, SOC 2, SEC/FINRA), legal, manufacturing
- Differentiator: AI-assisted testing platform delivers enterprise-quality assessments faster and more affordably
- For MSPs: white-label co-branded reports, wholesale pricing, never contacts their clients directly
- Pricing: typically $3,000-$8,000 per engagement depending on scope

Response guidelines:
- Write as David Lopez in first person -- casual professional tone, friendly but not salesy
- Keep responses concise (3-8 sentences typically)
- Always move toward scheduling a meeting or call as the next step
- If they ask about pricing, give ranges and suggest a scoping call for an exact quote
- If they express interest, suggest specific times (e.g., "Would Tuesday or Wednesday afternoon work?")
- If they ask a technical question, answer it knowledgeably but briefly, then pivot to a call
- If they raise an objection, acknowledge it genuinely and address it
- If they say "not interested" or "unsubscribe", be gracious -- never argue or push back
- If it's a referral, thank them and ask for the best way to reach the referred person
- If it's out of office, note the return date and plan to follow up after
- Never be pushy, desperate, or use aggressive sales language
- Sign off as David Lopez, Voltsys AI, 305-244-2536
"""


def get_client() -> Optional[object]:
    """Get an Anthropic client."""
    if not anthropic:
        return None
    api_key = os.environ.get("ANTHROPIC_API_KEY") or db.get_setting("anthropic_api_key")
    if not api_key:
        return None
    return anthropic.Anthropic(api_key=api_key)


def classify_reply(reply_body: str, lead: dict, conversation_history: list) -> dict:
    """Use Claude to classify a reply and generate a response.

    Returns dict with:
        category: str (one of REPLY_CATEGORIES keys)
        confidence: float (0-1)
        summary: str (brief summary of what the lead said)
        suggested_reply: str (AI-generated response)
        should_auto_send: bool (safe to auto-send, or needs human review)
        next_action: str (recommended next step)
    """
    client = get_client()
    if not client:
        return {
            "category": "unknown",
            "confidence": 0,
            "summary": "Could not classify -- ANTHROPIC_API_KEY not set",
            "suggested_reply": "",
            "should_auto_send": False,
            "next_action": "Set ANTHROPIC_API_KEY environment variable",
        }

    # Build conversation context
    history_text = ""
    for em in conversation_history:
        direction = "YOU SENT" if em["direction"] == "outbound" else "THEY REPLIED"
        history_text += f"\n--- {direction} ({em.get('sent_at') or em['created_at']}) ---\n"
        history_text += f"Subject: {em['subject']}\n"
        history_text += f"{em['body'][:2000]}\n"

    prompt = f"""Analyze this email reply from a business lead and generate an appropriate response.

LEAD INFO:
- Company: {lead.get('company', 'Unknown')}
- Contact: {lead.get('contact_name', 'Unknown')}
- Title: {lead.get('contact_title', 'Unknown')}
- Industry: {lead.get('industry', 'Unknown')}
- Category: {lead.get('category', 'Unknown')}
- Size: {lead.get('size', 'Unknown')}
- Notes: {lead.get('notes', '')}

CONVERSATION HISTORY:
{history_text}

NEW REPLY TO ANALYZE:
{reply_body}

Respond with a JSON object (no markdown, just raw JSON):
{{
    "category": "<one of: interested, meeting_request, question, objection, not_interested, out_of_office, referral, unrelated>",
    "confidence": <0.0 to 1.0>,
    "summary": "<1-2 sentence summary of what the lead said>",
    "suggested_reply": "<your drafted reply as David Lopez>",
    "should_auto_send": <true if safe to auto-send (interested, meeting, question, referral), false if needs review (objection, not_interested, unrelated)>,
    "next_action": "<recommended next step for the CRM>"
}}"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        # Parse JSON from response
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)

        # Safety: never auto-send for negative or ambiguous replies
        if result.get("category") in ("not_interested", "objection", "unrelated"):
            result["should_auto_send"] = False

        return result

    except json.JSONDecodeError:
        return {
            "category": "unknown",
            "confidence": 0,
            "summary": "Could not parse AI response",
            "suggested_reply": text if 'text' in dir() else "",
            "should_auto_send": False,
            "next_action": "Review manually",
        }
    except Exception as e:
        return {
            "category": "error",
            "confidence": 0,
            "summary": f"AI classification error: {str(e)}",
            "suggested_reply": "",
            "should_auto_send": False,
            "next_action": "Review manually",
        }


def process_reply(lead_id: int, reply_body: str, reply_subject: str,
                  mode: str = "review") -> dict:
    """Process a reply from a lead: classify it, generate response, optionally send.

    Args:
        lead_id: The lead who replied
        reply_body: The reply email body
        reply_subject: The reply subject line
        mode: "auto" to send immediately, "review" to queue as draft

    Returns:
        dict with classification results and action taken
    """
    lead = db.get_lead(lead_id)
    if not lead:
        return {"error": f"Lead {lead_id} not found"}

    # Get conversation history
    conversation = db.get_emails_for_lead(lead_id)

    # Classify and generate reply
    result = classify_reply(reply_body, lead, conversation)

    # Handle based on category
    action_taken = "none"

    if result["category"] == "not_interested":
        # Mark lead as lost, don't send anything
        db.update_lead(lead_id, status="lost")
        db.add_interaction(lead_id, "note",
                          f"Lead declined: {result['summary']}",
                          f"Category: {result['category']}")
        action_taken = "marked_lost"

    elif result["category"] == "out_of_office":
        # Log it, don't reply to auto-responders
        db.add_interaction(lead_id, "note",
                          f"Out of office: {result['summary']}",
                          result.get("next_action", ""))
        action_taken = "logged_ooo"

    elif result["category"] == "unrelated":
        # Log and skip
        db.add_interaction(lead_id, "note",
                          f"Unrelated reply: {result['summary']}")
        action_taken = "logged_unrelated"

    elif result.get("suggested_reply"):
        # Determine subject (keep Re: thread)
        re_subject = reply_subject
        if not re_subject.startswith("Re:"):
            re_subject = f"Re: {re_subject}"

        if mode == "auto" and result.get("should_auto_send"):
            # Send immediately
            email_id = db.add_email(
                lead_id=lead_id,
                subject=re_subject,
                body=result["suggested_reply"],
                email_type="custom",
                direction="outbound",
                status="queued",
            )
            action_taken = "queued_auto_reply"

            # Update lead status based on category
            if result["category"] in ("interested", "meeting_request"):
                db.update_lead(lead_id, status="meeting")
            elif result["category"] == "referral":
                db.add_interaction(lead_id, "note",
                                  f"Referral: {result['summary']}")
        else:
            # Save as draft for review
            email_id = db.add_email(
                lead_id=lead_id,
                subject=re_subject,
                body=result["suggested_reply"],
                email_type="custom",
                direction="outbound",
                status="draft",
            )
            action_taken = "drafted_for_review"

        db.add_interaction(lead_id, "note",
                          f"AI auto-reply ({result['category']}): {result['summary']}",
                          f"Confidence: {result.get('confidence', 0):.0%}")

    result["action_taken"] = action_taken
    return result


def process_all_new_replies(mode: str = "review") -> dict:
    """Check inbox for new replies and process them all with AI.

    Args:
        mode: "auto" to send replies immediately, "review" to save as drafts

    Returns:
        dict with counts and details
    """
    # First check inbox for new replies
    new_replies = email_client.check_replies()

    results = {
        "new_replies": len(new_replies),
        "auto_replied": 0,
        "drafted": 0,
        "declined": 0,
        "ooo": 0,
        "errors": 0,
        "details": [],
    }

    for reply in new_replies:
        lead_id = reply["lead_id"]
        lead = db.get_lead(lead_id)

        # Get the full reply body from the most recent inbound email
        emails = db.get_emails_for_lead(lead_id)
        reply_body = ""
        reply_subject = reply.get("subject", "")
        for em in reversed(emails):
            if em["direction"] == "inbound":
                reply_body = em["body"]
                reply_subject = em["subject"]
                break

        if not reply_body:
            reply_body = reply.get("body_preview", "")

        # Process with AI
        result = process_reply(lead_id, reply_body, reply_subject, mode=mode)

        detail = {
            "company": reply["company"],
            "category": result.get("category", "unknown"),
            "summary": result.get("summary", ""),
            "action": result.get("action_taken", "none"),
        }
        results["details"].append(detail)

        if result.get("action_taken") == "queued_auto_reply":
            results["auto_replied"] += 1
        elif result.get("action_taken") == "drafted_for_review":
            results["drafted"] += 1
        elif result.get("action_taken") == "marked_lost":
            results["declined"] += 1
        elif result.get("action_taken") == "logged_ooo":
            results["ooo"] += 1
        elif result.get("category") == "error":
            results["errors"] += 1

    return results


def get_draft_replies() -> list:
    """Get all draft auto-replies waiting for review."""
    conn = db.get_db()
    rows = conn.execute("""
        SELECT e.*, l.company, l.contact_name, l.contact_email
        FROM emails e JOIN leads l ON e.lead_id = l.id
        WHERE e.status = 'draft' AND e.direction = 'outbound' AND e.email_type = 'custom'
        ORDER BY e.created_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def approve_draft(email_id: int) -> bool:
    """Approve a draft reply and queue it for sending."""
    db.update_email(email_id, status="queued")
    return True


def edit_and_approve(email_id: int, new_body: str) -> bool:
    """Edit a draft reply body and queue it for sending."""
    conn = db.get_db()
    conn.execute("UPDATE emails SET body = ?, status = 'queued' WHERE id = ?",
                 (new_body, email_id))
    conn.commit()
    conn.close()
    return True


def discard_draft(email_id: int) -> bool:
    """Discard a draft reply."""
    conn = db.get_db()
    conn.execute("DELETE FROM emails WHERE id = ? AND status = 'draft'", (email_id,))
    conn.commit()
    conn.close()
    return True
