"""Notification and alerting engine for security events."""

import asyncio
from typing import Optional, Dict, Any, List


class NotificationEngine:
    """Engine for sending notifications and alerts about security events."""

    def __init__(self, db, config: dict = None):
        """Initialize the notification engine.

        Args:
            db: Database instance
            config: Configuration dictionary
        """
        self.db = db
        self.config = (config or {}).get("engines", {}).get("notification", {})
        self.channels = {}  # In-memory channel storage
        self.notification_history = []  # In-memory notification history

    async def configure_channel(self, channel_type: str, config_data: Dict[str, Any], project_id: str = None) -> Dict[str, Any]:
        """Configure a notification channel.

        Args:
            channel_type: Type of channel (slack, email, webhook, teams)
            config_data: Channel configuration
            project_id: Project ID

        Returns:
            Dict with success status and channel details
        """
        from core.database import generate_id, utc_now

        try:
            channel_id = generate_id()

            # Validate channel type and configuration
            valid_types = ['slack', 'email', 'webhook', 'teams']
            if channel_type not in valid_types:
                return {
                    "success": False,
                    "error": f"Invalid channel type. Must be one of: {', '.join(valid_types)}"
                }

            # Validate required fields based on channel type
            required_fields = {
                'slack': ['webhook_url'],
                'email': ['smtp_host', 'smtp_port', 'from_addr', 'to_addrs'],
                'webhook': ['url', 'method'],
                'teams': ['webhook_url']
            }

            missing_fields = []
            for field in required_fields.get(channel_type, []):
                if field not in config_data:
                    missing_fields.append(field)

            if missing_fields:
                return {
                    "success": False,
                    "error": f"Missing required fields: {', '.join(missing_fields)}"
                }

            # Store channel configuration
            channel = {
                "channel_id": channel_id,
                "channel_type": channel_type,
                "config": config_data,
                "project_id": project_id,
                "created_at": utc_now(),
                "enabled": True
            }

            self.channels[channel_id] = channel

            await self.db.audit(
                action="configure_channel",
                resource_type="notification_channel",
                resource_id=channel_id,
                details={"channel_type": channel_type, "project_id": project_id},
                project_id=project_id
            )

            return {
                "success": True,
                "channel_id": channel_id,
                "channel_type": channel_type,
                "message": f"{channel_type.capitalize()} notification channel configured successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def list_channels(self) -> Dict[str, Any]:
        """List all configured notification channels.

        Returns:
            Dict with success status and channels list
        """
        try:
            channels_list = []
            for channel_id, channel in self.channels.items():
                # Don't expose sensitive config data
                channels_list.append({
                    "channel_id": channel_id,
                    "channel_type": channel["channel_type"],
                    "project_id": channel.get("project_id"),
                    "created_at": channel["created_at"],
                    "enabled": channel["enabled"]
                })

            return {
                "success": True,
                "channels": channels_list,
                "count": len(channels_list)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def remove_channel(self, channel_id: str) -> Dict[str, Any]:
        """Remove a notification channel.

        Args:
            channel_id: Channel ID to remove

        Returns:
            Dict with success status
        """
        from core.database import generate_id, utc_now

        try:
            if channel_id not in self.channels:
                return {
                    "success": False,
                    "error": "Channel not found"
                }

            channel = self.channels[channel_id]
            project_id = channel.get("project_id")

            del self.channels[channel_id]

            await self.db.audit(
                action="remove_channel",
                resource_type="notification_channel",
                resource_id=channel_id,
                details={"channel_type": channel["channel_type"]},
                project_id=project_id
            )

            return {
                "success": True,
                "message": "Channel removed successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def send_notification(
        self,
        channel_id: str,
        subject: str,
        message: str,
        severity: str = "info",
        data: Dict[str, Any] = None,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Send a notification through a specific channel.

        Args:
            channel_id: Channel ID to send through
            subject: Notification subject
            message: Notification message
            severity: Severity level (info, warning, critical)
            data: Additional data
            project_id: Project ID

        Returns:
            Dict with success status
        """
        from core.database import generate_id, utc_now

        try:
            if channel_id not in self.channels:
                return {
                    "success": False,
                    "error": "Channel not found"
                }

            channel = self.channels[channel_id]

            if not channel["enabled"]:
                return {
                    "success": False,
                    "error": "Channel is disabled"
                }

            channel_type = channel["channel_type"]
            config = channel["config"]

            # Send based on channel type
            if channel_type == "slack":
                result = await self._send_slack(config, subject, message, severity, data)
            elif channel_type == "email":
                result = await self._send_email(config, subject, message, severity, data)
            elif channel_type == "webhook":
                result = await self._send_webhook(config, subject, message, severity, data)
            elif channel_type == "teams":
                result = await self._send_teams(config, subject, message, severity, data)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported channel type: {channel_type}"
                }

            # Log notification
            notification_record = {
                "channel_id": channel_id,
                "channel_type": channel_type,
                "subject": subject,
                "message": message,
                "severity": severity,
                "sent_at": utc_now(),
                "result": result
            }
            self.notification_history.append(notification_record)

            await self.db.audit(
                action="send_notification",
                resource_type="notification",
                resource_id=generate_id(),
                details={
                    "channel_id": channel_id,
                    "channel_type": channel_type,
                    "subject": subject,
                    "severity": severity,
                    "success": result.get("success", False)
                },
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _send_slack(self, config: Dict, subject: str, message: str, severity: str, data: Dict = None) -> Dict[str, Any]:
        """Send Slack notification."""
        import httpx

        try:
            webhook_url = config["webhook_url"]

            # Map severity to color
            color_map = {
                "info": "#36a64f",
                "warning": "#ff9800",
                "critical": "#f44336"
            }

            payload = {
                "attachments": [
                    {
                        "color": color_map.get(severity, "#36a64f"),
                        "title": subject,
                        "text": message,
                        "fields": [],
                        "footer": "Security Alert",
                        "ts": int(asyncio.get_event_loop().time())
                    }
                ]
            }

            if data:
                for key, value in data.items():
                    payload["attachments"][0]["fields"].append({
                        "title": key.replace("_", " ").title(),
                        "value": str(value),
                        "short": True
                    })

            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload, timeout=10)
                response.raise_for_status()

            return {
                "success": True,
                "message": "Slack notification sent successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send Slack notification: {str(e)}"
            }

    async def _send_email(self, config: Dict, subject: str, message: str, severity: str, data: Dict = None) -> Dict[str, Any]:
        """Send email notification."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import concurrent.futures

        try:
            smtp_host = config["smtp_host"]
            smtp_port = config["smtp_port"]
            from_addr = config["from_addr"]
            to_addrs = config["to_addrs"]
            username = config.get("username")
            password = config.get("password")
            use_tls = config.get("use_tls", True)

            # Build email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{severity.upper()}] {subject}"
            msg['From'] = from_addr
            msg['To'] = ', '.join(to_addrs) if isinstance(to_addrs, list) else to_addrs

            # Plain text body
            text_body = f"{message}\n\n"
            if data:
                text_body += "Additional Details:\n"
                for key, value in data.items():
                    text_body += f"  {key}: {value}\n"

            # HTML body
            html_body = f"""
            <html>
              <body>
                <h2 style="color: {'red' if severity == 'critical' else 'orange' if severity == 'warning' else 'green'};">{subject}</h2>
                <p>{message}</p>
            """
            if data:
                html_body += "<h3>Additional Details:</h3><ul>"
                for key, value in data.items():
                    html_body += f"<li><strong>{key}:</strong> {value}</li>"
                html_body += "</ul>"
            html_body += "</body></html>"

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            # Send email using executor (blocking operation)
            loop = asyncio.get_event_loop()
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

            def send_email_sync():
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                if use_tls:
                    server.starttls()
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
                server.quit()

            await loop.run_in_executor(executor, send_email_sync)

            return {
                "success": True,
                "message": "Email notification sent successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send email notification: {str(e)}"
            }

    async def _send_webhook(self, config: Dict, subject: str, message: str, severity: str, data: Dict = None) -> Dict[str, Any]:
        """Send webhook notification."""
        import httpx

        try:
            url = config["url"]
            method = config.get("method", "POST").upper()
            headers = config.get("headers", {})

            payload = {
                "subject": subject,
                "message": message,
                "severity": severity,
                "timestamp": asyncio.get_event_loop().time()
            }

            if data:
                payload["data"] = data

            async with httpx.AsyncClient() as client:
                if method == "POST":
                    response = await client.post(url, json=payload, headers=headers, timeout=10)
                elif method == "PUT":
                    response = await client.put(url, json=payload, headers=headers, timeout=10)
                else:
                    return {
                        "success": False,
                        "error": f"Unsupported HTTP method: {method}"
                    }

                response.raise_for_status()

            return {
                "success": True,
                "message": "Webhook notification sent successfully",
                "status_code": response.status_code
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send webhook notification: {str(e)}"
            }

    async def _send_teams(self, config: Dict, subject: str, message: str, severity: str, data: Dict = None) -> Dict[str, Any]:
        """Send Microsoft Teams notification."""
        import httpx

        try:
            webhook_url = config["webhook_url"]

            # Map severity to color
            color_map = {
                "info": "0078D4",
                "warning": "FF8C00",
                "critical": "D13438"
            }

            # Build adaptive card
            card = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": subject,
                "themeColor": color_map.get(severity, "0078D4"),
                "sections": [
                    {
                        "activityTitle": subject,
                        "activitySubtitle": f"Severity: {severity.upper()}",
                        "text": message,
                        "facts": []
                    }
                ]
            }

            if data:
                for key, value in data.items():
                    card["sections"][0]["facts"].append({
                        "name": key.replace("_", " ").title(),
                        "value": str(value)
                    })

            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=card, timeout=10)
                response.raise_for_status()

            return {
                "success": True,
                "message": "Teams notification sent successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send Teams notification: {str(e)}"
            }

    async def notify_all(
        self,
        subject: str,
        message: str,
        severity: str = "info",
        data: Dict[str, Any] = None,
        project_id: str = None
    ) -> Dict[str, Any]:
        """Send notification to ALL configured channels.

        Args:
            subject: Notification subject
            message: Notification message
            severity: Severity level
            data: Additional data
            project_id: Project ID

        Returns:
            Dict with success status and results per channel
        """
        from core.database import generate_id, utc_now

        try:
            if not self.channels:
                return {
                    "success": False,
                    "error": "No notification channels configured"
                }

            results = {}
            success_count = 0
            failure_count = 0

            # Send to all channels
            for channel_id in self.channels.keys():
                result = await self.send_notification(
                    channel_id=channel_id,
                    subject=subject,
                    message=message,
                    severity=severity,
                    data=data,
                    project_id=project_id
                )

                results[channel_id] = result

                if result.get("success"):
                    success_count += 1
                else:
                    failure_count += 1

            await self.db.audit(
                action="notify_all",
                resource_type="notification",
                resource_id=generate_id(),
                details={
                    "subject": subject,
                    "severity": severity,
                    "channels_sent": success_count,
                    "channels_failed": failure_count
                },
                project_id=project_id
            )

            return {
                "success": True,
                "channels_sent": success_count,
                "channels_failed": failure_count,
                "total_channels": len(self.channels),
                "results": results
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def notify_finding(self, finding_id: str, project_id: str) -> Dict[str, Any]:
        """Send notification about a security finding.

        Args:
            finding_id: Finding ID
            project_id: Project ID

        Returns:
            Dict with success status
        """
        from core.database import generate_id, utc_now

        try:
            # Look up finding from database
            query = """
                SELECT title, description, severity, cvss_score, status, target_id
                FROM findings
                WHERE id = ? AND project_id = ?
            """

            rows = await self.db.execute_query(query, (finding_id, project_id))

            if not rows:
                return {
                    "success": False,
                    "error": "Finding not found"
                }

            row = rows[0]
            title, description, severity, cvss_score, status, target_id = row

            # Format notification
            subject = f"Security Finding: {title}"
            message = f"{description}\n\nStatus: {status}"

            data = {
                "finding_id": finding_id,
                "severity": severity,
                "cvss_score": cvss_score or "N/A",
                "target_id": target_id,
                "project_id": project_id
            }

            # Send to all channels
            result = await self.notify_all(
                subject=subject,
                message=message,
                severity=severity.lower() if severity else "info",
                data=data,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def notify_scan_complete(self, scan_id: str, project_id: str) -> Dict[str, Any]:
        """Send notification when a scan completes.

        Args:
            scan_id: Scan identifier
            project_id: Project ID

        Returns:
            Dict with success status
        """
        from core.database import generate_id, utc_now

        try:
            # Query findings from this scan (approximate - based on recent findings)
            query = """
                SELECT severity, COUNT(*) as count
                FROM findings
                WHERE project_id = ?
                GROUP BY severity
            """

            rows = await self.db.execute_query(query, (project_id,))

            findings_summary = {}
            total_findings = 0

            for row in rows:
                severity, count = row
                findings_summary[severity] = count
                total_findings += count

            # Format notification
            subject = f"Scan Complete: {scan_id}"
            message = f"Security scan completed. Total findings: {total_findings}"

            data = {
                "scan_id": scan_id,
                "total_findings": total_findings,
                "critical": findings_summary.get("critical", 0),
                "high": findings_summary.get("high", 0),
                "medium": findings_summary.get("medium", 0),
                "low": findings_summary.get("low", 0),
                "info": findings_summary.get("info", 0)
            }

            # Determine severity based on findings
            if findings_summary.get("critical", 0) > 0:
                severity = "critical"
            elif findings_summary.get("high", 0) > 0:
                severity = "warning"
            else:
                severity = "info"

            result = await self.notify_all(
                subject=subject,
                message=message,
                severity=severity,
                data=data,
                project_id=project_id
            )

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def get_notification_history(self, limit: int = 50) -> Dict[str, Any]:
        """Get notification history.

        Args:
            limit: Maximum number of notifications to return

        Returns:
            Dict with success status and notification history
        """
        try:
            # Return from in-memory history
            history = self.notification_history[-limit:] if limit else self.notification_history

            return {
                "success": True,
                "notifications": history,
                "count": len(history)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
