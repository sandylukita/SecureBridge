"""
SecureBridge — Alert Notification Engine
Multi-channel alerting for OT security events

Channels:
- Email (SMTP)
- Telegram Bot
- Dashboard (via shared queue)

Respects minimum severity thresholds.
"""

import os
import sys
import smtplib
import logging
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
))
from config.settings import AlertConfig

logger = logging.getLogger("SecureBridge.Alerts")

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


class AlertNotifier:
    """
    Multi-channel alert dispatcher
    Sends alerts via Email and/or Telegram based on severity threshold
    """

    def __init__(self, config: AlertConfig):
        self.config = config
        self.min_rank = SEVERITY_RANK.get(config.min_severity, 2)
        self._sent_count = 0
        self._failed_count = 0

    def should_alert(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 0) >= self.min_rank

    def send(self, alert_message: str, severity: str,
             device_id: str = "", subject: str = None):
        """
        Send alert to all configured channels

        Args:
            alert_message: formatted alert text
            severity: CRITICAL/HIGH/MEDIUM/LOW
            device_id: for email subject line
            subject: optional custom subject
        """
        if not self.should_alert(severity):
            logger.debug(
                f"Alert suppressed (below threshold): "
                f"{severity} < {self.config.min_severity}"
            )
            return

        email_subject = subject or (
            f"[SecureBridge] {severity} Alert — {device_id} — "
            f"{datetime.now().strftime('%H:%M:%S')}"
        )

        # Send to all channels concurrently
        threads = []

        if self.config.email_enabled:
            t = threading.Thread(
                target=self._send_email,
                args=(email_subject, alert_message),
                daemon=True
            )
            threads.append(t)

        if self.config.telegram_enabled:
            t = threading.Thread(
                target=self._send_telegram,
                args=(alert_message,),
                daemon=True
            )
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=10)

        self._sent_count += 1
        logger.info(
            f"Alert dispatched: {severity} | {device_id} | "
            f"Channels: email={self.config.email_enabled}, "
            f"telegram={self.config.telegram_enabled}"
        )

    def _send_email(self, subject: str, body: str):
        """Send email alert via SMTP"""
        if not self.config.email_from or not self.config.email_to:
            logger.warning("Email not configured (from/to missing)")
            return

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.config.email_from
            msg["To"] = ", ".join(self.config.email_to)

            # Plain text version
            msg.attach(MIMEText(body, "plain"))

            # HTML version
            html_body = self._to_html(body)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(
                self.config.email_smtp,
                self.config.email_port
            ) as server:
                server.starttls()
                server.login(
                    self.config.email_from,
                    self.config.email_password
                )
                server.sendmail(
                    self.config.email_from,
                    self.config.email_to,
                    msg.as_string()
                )

            logger.info(f"Email sent to {self.config.email_to}")

        except Exception as e:
            self._failed_count += 1
            logger.error(f"Email failed: {e}")

    def _send_telegram(self, message: str):
        """Send Telegram alert"""
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            logger.warning("Telegram not configured")
            return

        try:
            import urllib.request
            import urllib.parse

            # Telegram has 4096 char limit
            if len(message) > 4000:
                message = message[:3997] + "..."

            url = (
                f"https://api.telegram.org/bot{self.config.telegram_token}"
                f"/sendMessage"
            )
            data = urllib.parse.urlencode({
                "chat_id": self.config.telegram_chat_id,
                "text": message,
                "parse_mode": "HTML"
            }).encode()

            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = resp.read()
                logger.info("Telegram alert sent successfully")

        except Exception as e:
            self._failed_count += 1
            logger.error(f"Telegram failed: {e}")

    def _to_html(self, text: str) -> str:
        """Convert plain text alert to basic HTML email"""
        lines = text.split("\n")
        html_lines = []

        for line in lines:
            if line.startswith("🚨") or line.startswith("⚠️"):
                html_lines.append(
                    f'<h2 style="color:#c0392b">{line}</h2>'
                )
            elif line.startswith("━"):
                html_lines.append('<hr style="border-color:#ddd">')
            elif line.startswith("📋") or line.startswith("⚡"):
                html_lines.append(f'<h3 style="color:#2c3e50">{line}</h3>')
            elif line.startswith("🔺"):
                html_lines.append(
                    f'<p style="background:#fdecea;padding:8px;'
                    f'border-left:4px solid #c0392b"><b>{line}</b></p>'
                )
            elif line.strip():
                html_lines.append(f'<p style="margin:4px 0">{line}</p>')

        body = "\n".join(html_lines)
        return f"""
        <html><body style="font-family:Arial,sans-serif;max-width:600px">
        <div style="background:#1a2744;padding:16px;color:white">
            <h1 style="margin:0;font-size:20px">🔐 SecureBridge OT Security</h1>
            <p style="margin:4px 0;font-size:12px;color:#b2dfdb">
                PT Optima Sarana Instrument — Security Alert
            </p>
        </div>
        <div style="padding:16px">{body}</div>
        <div style="background:#f5f6fa;padding:12px;
                    font-size:11px;color:#95a5a6;text-align:center">
            SecureBridge OT Security Platform<br>
            Sandy Lukita | PT Optima Sarana Instrument<br>
            sandylukita@gmail.com
        </div>
        </body></html>
        """

    @property
    def stats(self):
        return {
            "sent": self._sent_count,
            "failed": self._failed_count
        }
