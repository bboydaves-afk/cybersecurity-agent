"""M365 email client using Microsoft Graph API (read) and SendGrid (send)."""

import json
import base64
import msal
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from . import database as db

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import (
        Mail, Attachment, FileContent, FileName, FileType,
        Disposition, ContentId, From, To, Subject, Content,
        MimeType, Header,
    )
    HAS_SENDGRID = True
except ImportError:
    HAS_SENDGRID = False

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGO_PATH = Path(__file__).parent / "data" / "voltsys_logo.png"
LOGO_B64_PATH = Path(__file__).parent / "data" / "logo_b64.txt"


def _get_logo_b64() -> str:
    """Get the Voltsys AI logo as base64 string."""
    if LOGO_B64_PATH.exists():
        return LOGO_B64_PATH.read_text().strip()
    return ""


def _build_signature_html() -> str:
    """Build the branded Voltsys AI email signature with logo."""
    sender_name = db.get_setting("display_name", "David Lopez")
    sender_company = db.get_setting("company_name", "Voltsys AI")
    sender_phone = db.get_setting("phone", "")
    sender_email = db.get_setting("email_address", "")

    logo_html = ""
    logo_b64 = _get_logo_b64()
    if logo_b64:
        logo_html = (
            f'<img src="cid:voltsys_logo" alt="Voltsys AI" '
            f'width="200" height="53" style="display:block; margin-bottom:12px;" />'
        )

    return f'''
<br/>
<table cellpadding="0" cellspacing="0" border="0" style="font-family: Segoe UI, Arial, sans-serif; font-size: 13px; color: #333;">
  <tr>
    <td style="padding-right: 16px; border-right: 3px solid #6c2fff; vertical-align: top;">
      {logo_html}
    </td>
    <td style="padding-left: 16px; vertical-align: top;">
      <div style="font-size: 15px; font-weight: 700; color: #1a1a2e; margin-bottom: 2px;">{sender_name}</div>
      <div style="font-size: 12px; color: #6c2fff; font-weight: 600; margin-bottom: 8px;">Cybersecurity Consultant</div>
      <div style="font-size: 12px; color: #555; line-height: 1.7;">
        <span style="color: #6c2fff; font-weight: 600;">{sender_company}</span><br/>
        <a href="mailto:{sender_email}" style="color: #555; text-decoration: none;">{sender_email}</a><br/>
        {f'<span>{sender_phone}</span><br/>' if sender_phone else ''}
        <span style="color: #888;">Charlotte, NC</span>
      </div>
      <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid #e0d4ff; font-size: 11px; color: #999;">
        Penetration Testing &bull; Vulnerability Assessments &bull; Compliance Audits
      </div>
    </td>
  </tr>
</table>'''


def get_graph_token() -> str:
    """Get an access token for Microsoft Graph API using client credentials."""
    tenant_id = db.get_setting("azure_tenant_id")
    client_id = db.get_setting("azure_client_id")
    client_secret = db.get_setting("azure_client_secret")

    if not all([tenant_id, client_id, client_secret]):
        raise ValueError(
            "Azure app not configured. Need tenant_id, client_id, client_secret."
        )

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )

    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

    if "access_token" in result:
        return result["access_token"]
    else:
        error = result.get("error_description", result.get("error", "Unknown error"))
        raise ValueError(f"Failed to get Graph token: {error}")


def _graph_headers(token: str) -> dict:
    """Standard headers for Graph API calls."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _build_html_content(body: str) -> str:
    """Build full HTML email content with signature."""
    html_body = body.replace("\n\n", "</p><p>").replace("\n", "<br>")
    signature_html = _build_signature_html()
    return (
        f'<html><body style="font-family: Segoe UI, Arial, sans-serif; '
        f'font-size: 14px; color: #333; line-height: 1.6;">'
        f'<p>{html_body}</p>'
        f'{signature_html}'
        f'</body></html>'
    )


def _send_via_sendgrid(to_email: str, subject: str, html_content: str,
                       email_id: int = None, in_reply_to: str = None) -> tuple:
    """Send email via SendGrid API. Returns (success, message_id_or_error)."""
    if not HAS_SENDGRID:
        return False, "SendGrid package not installed"

    api_key = db.get_setting("sendgrid_api_key")
    if not api_key:
        return False, "SendGrid API key not configured"

    sender_address = db.get_setting("email_address")
    display_name = db.get_setting("display_name", "")

    message = Mail(
        from_email=From(sender_address, display_name),
        to_emails=To(to_email),
        subject=subject,
        html_content=Content(MimeType.html, html_content),
    )

    # Attach logo as inline CID image
    logo_b64 = _get_logo_b64()
    if logo_b64:
        attachment = Attachment(
            FileContent(logo_b64),
            FileName("voltsys_logo.png"),
            FileType("image/png"),
            Disposition("inline"),
            ContentId("voltsys_logo"),
        )
        message.attachment = attachment

    # Add threading headers for replies
    if in_reply_to:
        message.header = Header("In-Reply-To", in_reply_to)
        message.header = Header("References", in_reply_to)

    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)

        if response.status_code in (200, 201, 202):
            msg_id = f"<sg-{datetime.now().strftime('%Y%m%d%H%M%S')}-{email_id or 0}@voltsys.ai>"

            if email_id:
                db.update_email(email_id, status="sent",
                               sent_at=datetime.now().isoformat(),
                               message_id=msg_id)
            return True, msg_id
        else:
            error = f"SendGrid error {response.status_code}: {response.body.decode()[:200]}"
            if email_id:
                db.update_email(email_id, status="failed", error=error)
            return False, error

    except Exception as e:
        error = f"SendGrid error: {str(e)}"
        if email_id:
            db.update_email(email_id, status="failed", error=error)
        return False, error


def _send_via_graph(to_email: str, subject: str, html_content: str,
                    email_id: int = None, in_reply_to: str = None) -> tuple:
    """Send email via Microsoft Graph API. Returns (success, message_id_or_error)."""
    sender_address = db.get_setting("email_address")
    display_name = db.get_setting("display_name", "")

    try:
        token = get_graph_token()
    except ValueError as e:
        error = str(e)
        if email_id:
            db.update_email(email_id, status="failed", error=error)
        return False, error

    message = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_content,
            },
            "toRecipients": [
                {"emailAddress": {"address": to_email}}
            ],
            "from": {
                "emailAddress": {
                    "address": sender_address,
                    "name": display_name,
                }
            },
        },
        "saveToSentItems": "true",
    }

    logo_b64 = _get_logo_b64()
    if logo_b64:
        message["message"]["attachments"] = [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": "voltsys_logo.png",
                "contentId": "voltsys_logo",
                "isInline": True,
                "contentType": "image/png",
                "contentBytes": logo_b64,
            }
        ]

    if in_reply_to:
        message["message"]["internetMessageHeaders"] = [
            {"name": "In-Reply-To", "value": in_reply_to},
            {"name": "References", "value": in_reply_to},
        ]

    try:
        url = f"{GRAPH_BASE}/users/{sender_address}/sendMail"
        resp = requests.post(url, headers=_graph_headers(token), json=message, timeout=30)

        if resp.status_code == 202:
            msg_id = f"<graph-{datetime.now().strftime('%Y%m%d%H%M%S')}-{email_id or 0}@voltsys.ai>"

            if email_id:
                db.update_email(email_id, status="sent",
                               sent_at=datetime.now().isoformat(),
                               message_id=msg_id)
            return True, msg_id
        else:
            error_body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            error_msg = error_body.get("error", {}).get("message", resp.text[:200])
            error = f"Graph API error {resp.status_code}: {error_msg}"

            if email_id:
                db.update_email(email_id, status="failed", error=error)
            return False, error

    except Exception as e:
        error = str(e)
        if email_id:
            db.update_email(email_id, status="failed", error=error)
        return False, error


def send_email(to_email: str, subject: str, body: str,
               email_id: int = None, in_reply_to: str = None) -> tuple:
    """Send email using SendGrid (primary) or Graph API (fallback).

    Returns (success, message_id_or_error).
    """
    html_content = _build_html_content(body)

    # Try SendGrid first (better deliverability for new tenants)
    sendgrid_key = db.get_setting("sendgrid_api_key")
    if sendgrid_key and HAS_SENDGRID:
        return _send_via_sendgrid(to_email, subject, html_content, email_id, in_reply_to)

    # Fall back to Graph API
    return _send_via_graph(to_email, subject, html_content, email_id, in_reply_to)


def send_queued_emails() -> dict:
    """Send all queued emails that are due. Returns stats."""
    queued = db.get_queued_emails()
    stats = {"sent": 0, "failed": 0, "errors": []}

    for em in queued:
        if not em["contact_email"]:
            db.update_email(em["id"], status="failed", error="No contact email")
            stats["failed"] += 1
            continue

        # Find the most recent message_id for threading (replies)
        reply_to_id = None
        if em["email_type"] in ("custom", "followup_1", "followup_2", "followup_3"):
            lead_emails = db.get_emails_for_lead(em["lead_id"])
            for prev in reversed(lead_emails):
                if prev.get("message_id") and prev["id"] != em["id"]:
                    reply_to_id = prev["message_id"]
                    break

        success, result = send_email(
            to_email=em["contact_email"],
            subject=em["subject"],
            body=em["body"],
            email_id=em["id"],
            in_reply_to=reply_to_id,
        )

        if success:
            stats["sent"] += 1
            db.update_lead(em["lead_id"], status="contacted")
            db.add_interaction(em["lead_id"], "email_sent",
                             f"Sent: {em['subject']}", f"To: {em['contact_email']}")
        else:
            stats["failed"] += 1
            stats["errors"].append(f"{em['company']}: {result}")

    return stats


def check_replies() -> list:
    """Check inbox for replies from leads using Microsoft Graph API."""
    sender_address = db.get_setting("email_address")
    replies = []

    try:
        token = get_graph_token()
    except ValueError as e:
        print(f"Graph auth error: {e}")
        return replies

    try:
        # Get all lead emails for matching
        leads = db.list_leads()
        lead_emails = {}
        for lead in leads:
            if lead["contact_email"]:
                lead_emails[lead["contact_email"].lower()] = lead

        # Search for recent messages in inbox (last 7 days)
        since_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z")
        url = (
            f"{GRAPH_BASE}/users/{sender_address}/mailFolders/inbox/messages"
            f"?$filter=receivedDateTime ge {since_date}"
            f"&$select=id,subject,from,receivedDateTime,body,internetMessageId,internetMessageHeaders"
            f"&$top=50"
            f"&$orderby=receivedDateTime desc"
        )

        resp = requests.get(url, headers=_graph_headers(token), timeout=30)

        if resp.status_code != 200:
            print(f"Graph API error {resp.status_code}: {resp.text[:200]}")
            return replies

        messages = resp.json().get("value", [])

        for msg in messages:
            from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "").lower()

            if from_addr not in lead_emails:
                continue

            lead = lead_emails[from_addr]
            msg_message_id = msg.get("internetMessageId", "")

            # Check if we already recorded this
            existing = db.get_emails_for_lead(lead["id"])
            already_tracked = any(
                e.get("message_id") == msg_message_id and e["direction"] == "inbound"
                for e in existing
            )

            if already_tracked or not msg_message_id:
                continue

            # Extract plain text body
            body_content = msg.get("body", {}).get("content", "")
            content_type = msg.get("body", {}).get("contentType", "text")

            if content_type.lower() == "html":
                # Strip HTML tags for plain text version
                import re
                body = re.sub(r'<style[^>]*>.*?</style>', '', body_content, flags=re.DOTALL)
                body = re.sub(r'<[^>]+>', '', body)
                body = re.sub(r'\s+', ' ', body).strip()
            else:
                body = body_content

            # Record the reply
            db.add_email(
                lead_id=lead["id"],
                subject=msg.get("subject", ""),
                body=body[:5000],
                email_type="reply",
                direction="inbound",
                status="replied",
                message_id=msg_message_id,
            )

            db.update_lead(lead["id"], status="replied")
            db.add_interaction(
                lead["id"], "email_received",
                f"Reply from {lead['company']}",
                body[:500],
            )

            # Pause any active sequence
            for seq in db.get_active_sequences():
                if seq["lead_id"] == lead["id"]:
                    db.update_sequence(
                        seq["id"],
                        is_active=0,
                        paused_reason="Lead replied",
                    )

            replies.append({
                "lead_id": lead["id"],
                "company": lead["company"],
                "from": from_addr,
                "subject": msg.get("subject", ""),
                "body_preview": body[:200],
                "date": msg.get("receivedDateTime", ""),
            })

    except Exception as e:
        print(f"Error checking replies: {e}")

    return replies


def send_to_lead(lead_id: int, subject: str, body: str,
                 email_type: str = "initial", queue: bool = True) -> int:
    """Create and optionally queue an email for a lead."""
    lead = db.get_lead(lead_id)
    if not lead:
        raise ValueError(f"Lead {lead_id} not found")
    if not lead["contact_email"]:
        raise ValueError(f"No email address for {lead['company']}")

    status = "queued" if queue else "draft"
    email_id = db.add_email(lead_id, subject, body, email_type, "outbound", status)
    return email_id
