"""
brevo_client.py — Official Brevo Free Transactional Email API Client for CyberGuard.

Provides zero-cost, enterprise-grade transactional alert dispatch:
  - Official Brevo API: POST https://api.brevo.com/v3/smtp/email
  - Secure header-based authentication: `api-key`
  - Strict validation of sender and recipient emails
  - Connection & read timeouts with bounded retries for transient 5xx errors
  - Extraction and tracking of provider message IDs
  - Graceful handling of HTTP 429 (rate limits) and IP restriction errors
  - Zero leakage of API keys or sensitive credentials in logs or responses
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# Basic RFC 5322 compatible email validation pattern
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


@dataclass
class BrevoSendResult:
    """Outcome of a transactional email dispatch attempt."""
    success: bool
    delivery_status: str  # PROVIDER_ACCEPTED, SEND_FAILED, CONFIGURATION_REQUIRED
    http_status: Optional[int] = None
    message_id: Optional[str] = None
    error_message: Optional[str] = None
    attempt_count: int = 1
    recipient: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


class BrevoEmailClient:
    """
    Zero-cost Brevo Transactional Email client using official v3 REST API.
    Does not require external paid libraries; uses project-standard httpx.
    """

    BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

    def __init__(
        self,
        api_key: Optional[str] = None,
        default_sender_email: Optional[str] = None,
        default_sender_name: str = "CyberGuard Security",
        timeout_sec: float = 10.0,
        max_retries: int = 2,
        test_mode: bool = False,
        smtp_server: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_login: Optional[str] = None,
        smtp_key: Optional[str] = None,
    ):
        self.api_key = (api_key or "").strip()
        self.default_sender_email = (default_sender_email or "").strip()
        self.default_sender_name = default_sender_name.strip() or "CyberGuard Security"
        self.timeout_sec = max(3.0, float(timeout_sec))
        self.max_retries = max(0, min(max_retries, 3))  # Bounded between 0 and 3
        self.test_mode = bool(test_mode)
        self.smtp_server = smtp_server or os.getenv("BREVO_SMTP_SERVER", "smtp-relay.brevo.com")
        self.smtp_port = int(smtp_port or os.getenv("BREVO_SMTP_PORT", "587"))
        self.smtp_login = smtp_login or os.getenv("BREVO_SMTP_LOGIN", "")
        self.smtp_key = smtp_key or os.getenv("BREVO_SMTP_KEY", self.api_key)

    @staticmethod
    def is_valid_email(email_str: str) -> bool:
        """Validate email format."""
        if not email_str or not isinstance(email_str, str):
            return False
        return bool(EMAIL_REGEX.match(email_str.strip()))

    def _sanitize_error_text(self, text: str) -> str:
        """Ensure secrets or raw key fragments never leak in error messages."""
        if not text:
            return ""
        sanitized = str(text)
        if self.api_key and len(self.api_key) > 8:
            sanitized = sanitized.replace(self.api_key, "[REDACTED_API_KEY]")
        return sanitized

    async def send_alert_email(
        self,
        recipient: str,
        subject: str,
        html_content: str,
        plain_text_content: str,
        sender_email: Optional[str] = None,
        sender_name: Optional[str] = None,
        pdf_bytes: Optional[bytes] = None,
        pdf_filename: Optional[str] = None,
    ) -> BrevoSendResult:
        """
        Transmit a single transactional email via Brevo REST API.

        Returns BrevoSendResult with status PROVIDER_ACCEPTED upon HTTP 201
        or SEND_FAILED / CONFIGURATION_REQUIRED upon provider rejection.
        """
        target_recipient = (recipient or "").strip()
        target_sender = (sender_email or self.default_sender_email or "").strip()
        target_sender_name = (sender_name or self.default_sender_name or "CyberGuard Security").strip()

        # 1. Credential & Configuration Validation
        if not self.api_key:
            return BrevoSendResult(
                success=False,
                delivery_status="CONFIGURATION_REQUIRED",
                error_message="Missing Brevo API key (BREVO_API_KEY not configured).",
                recipient=target_recipient,
            )

        if self.api_key.startswith("xsmtpsib-"):
            return BrevoSendResult(
                success=False,
                delivery_status="CONFIGURATION_REQUIRED",
                http_status=401,
                error_message="Brevo REST API requires an API key ('xkeysib-' prefix from Brevo Dashboard > SMTP & API > API Keys). The configured BREVO_API_KEY is an SMTP password ('xsmtpsib-' prefix).",
                recipient=target_recipient,
            )

        if not target_sender or not self.is_valid_email(target_sender):
            return BrevoSendResult(
                success=False,
                delivery_status="CONFIGURATION_REQUIRED",
                error_message=f"Invalid or missing sender email: '{target_sender}'.",
                recipient=target_recipient,
            )

        if not target_recipient or not self.is_valid_email(target_recipient):
            return BrevoSendResult(
                success=False,
                delivery_status="SEND_FAILED",
                error_message=f"Invalid recipient email address: '{target_recipient}'.",
                recipient=target_recipient,
            )

        # 2. Test / Mock Mode bypass (for deterministic offline testing)
        if self.test_mode:
            mock_id = f"<mock-{abs(hash(subject + target_recipient))}@brevo-simulated.local>"
            logger.info(f"[BrevoClient TEST_MODE] Simulated dispatch accepted to {target_recipient}: {mock_id}")
            return BrevoSendResult(
                success=True,
                delivery_status="PROVIDER_ACCEPTED",
                http_status=201,
                message_id=mock_id,
                recipient=target_recipient,
                details={"mode": "test_mode", "note": "Simulated Brevo acceptance"},
            )

        # 3. Build Brevo v3 Transactional Email Payload
        payload: Dict[str, Any] = {
            "sender": {
                "name": target_sender_name,
                "email": target_sender,
            },
            "to": [
                {
                    "email": target_recipient,
                }
            ],
            "subject": subject,
            "htmlContent": html_content,
            "textContent": plain_text_content,
        }

        if pdf_bytes:
            import base64
            encoded_pdf = base64.b64encode(pdf_bytes).decode("ascii")
            payload["attachment"] = [
                {
                    "name": pdf_filename or "CyberGuard_Forensic_Report.pdf",
                    "content": encoded_pdf,
                }
            ]

        headers = {
            "api-key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CyberGuard-SOC/1.0",
        }

        timeout = httpx.Timeout(
            connect=5.0,
            read=self.timeout_sec,
            write=10.0,
            pool=5.0,
        )

        attempts = 0
        last_error = ""
        last_status = None

        while attempts <= self.max_retries:
            attempts += 1
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.post(
                        self.BREVO_API_URL,
                        headers=headers,
                        json=payload,
                    )
                    last_status = response.status_code

                    # HTTP 201 Created — Accepted by Brevo
                    if response.status_code == 201:
                        resp_data = response.json()
                        message_id = resp_data.get("messageId", f"<brevo-accepted-{attempts}>")
                        logger.info(
                            f"[BrevoClient] Transmitted alert to {target_recipient}. "
                            f"Provider Message-ID: {message_id}"
                        )
                        return BrevoSendResult(
                            success=True,
                            delivery_status="PROVIDER_ACCEPTED",
                            http_status=201,
                            message_id=message_id,
                            attempt_count=attempts,
                            recipient=target_recipient,
                            details={"brevo_response": resp_data},
                        )

                    # HTTP 4xx Client Errors — Do NOT retry permanent errors
                    error_body = response.text
                    clean_msg = self._sanitize_error_text(error_body)
                    try:
                        err_json = response.json()
                        raw_err_msg = err_json.get("message") or err_json.get("code") or clean_msg
                        clean_msg = self._sanitize_error_text(raw_err_msg)
                    except Exception:
                        pass

                    if response.status_code in (400, 401, 402, 403, 404):
                        logger.warning(
                            f"[BrevoClient] Client error {response.status_code} from Brevo: {clean_msg}"
                        )
                        return BrevoSendResult(
                            success=False,
                            delivery_status="SEND_FAILED",
                            http_status=response.status_code,
                            error_message=f"Brevo API error ({response.status_code}): {clean_msg}",
                            attempt_count=attempts,
                            recipient=target_recipient,
                        )

                    # HTTP 429 Too Many Requests — Respect rate limit
                    if response.status_code == 429:
                        logger.warning("[BrevoClient] Rate limited by Brevo (HTTP 429).")
                        return BrevoSendResult(
                            success=False,
                            delivery_status="SEND_FAILED",
                            http_status=429,
                            error_message="Brevo API rate limit exceeded (HTTP 429).",
                            attempt_count=attempts,
                            recipient=target_recipient,
                        )

                    # HTTP 5xx Server Errors — Retry if attempts remain
                    last_error = f"Brevo HTTP {response.status_code}: {clean_msg}"
                    logger.warning(
                        f"[BrevoClient] Transient error (attempt {attempts}/{self.max_retries + 1}): {last_error}"
                    )

            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError) as net_err:
                last_error = f"Network connection error: {type(net_err).__name__}"
                logger.warning(
                    f"[BrevoClient] Network error on attempt {attempts}/{self.max_retries + 1}: {last_error}"
                )
            except Exception as exc:
                last_error = f"Unexpected client error: {self._sanitize_error_text(str(exc))}"
                logger.warning(f"[BrevoClient] Exception on attempt {attempts}: {last_error}")

            # Transient backoff before bounded retry
            if attempts <= self.max_retries:
                await asyncio.sleep(0.5 * attempts)

        return BrevoSendResult(
            success=False,
            delivery_status="SEND_FAILED",
            http_status=last_status,
            error_message=last_error or "Brevo transactional dispatch failed after bounded retries.",
            attempt_count=attempts,
            recipient=target_recipient,
        )

    async def send_smtp_email(
        self,
        recipient: str,
        subject: str,
        html_content: str,
        plain_text_content: str,
        smtp_server: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_login: Optional[str] = None,
        smtp_password: Optional[str] = None,
        sender_email: Optional[str] = None,
        sender_name: Optional[str] = None,
        pdf_bytes: Optional[bytes] = None,
        pdf_filename: Optional[str] = None,
    ) -> BrevoSendResult:
        """
        Transmit a transactional alert via Brevo SMTP Relay (smtp-relay.brevo.com:587).
        Supports MIME multipart with embedded HTML, plaintext, and attached PDF reports.
        """
        target_recipient = (recipient or "").strip()
        target_sender = (sender_email or self.default_sender_email or "").strip()
        target_sender_name = (sender_name or self.default_sender_name or "CyberGuard Security").strip()

        server_host = smtp_server or self.smtp_server or "smtp-relay.brevo.com"
        server_port = int(smtp_port or self.smtp_port or 587)
        login_user = smtp_login or self.smtp_login or ""
        login_pass = smtp_password or self.smtp_key or ""

        if not target_sender or not self.is_valid_email(target_sender):
            return BrevoSendResult(
                success=False,
                delivery_status="CONFIGURATION_REQUIRED",
                error_message=f"Invalid or missing sender email: '{target_sender}'.",
                recipient=target_recipient,
            )

        if not target_recipient or not self.is_valid_email(target_recipient):
            return BrevoSendResult(
                success=False,
                delivery_status="SEND_FAILED",
                error_message=f"Invalid recipient email address: '{target_recipient}'.",
                recipient=target_recipient,
            )

        if self.test_mode:
            mock_id = f"<mock-smtp-{abs(hash(subject + target_recipient))}@smtp-relay.brevo.com>"
            logger.info(f"[BrevoClient TEST_MODE] Simulated SMTP dispatch accepted to {target_recipient}: {mock_id}")
            return BrevoSendResult(
                success=True,
                delivery_status="PROVIDER_ACCEPTED",
                http_status=200,
                message_id=mock_id,
                recipient=target_recipient,
                details={"mode": "test_mode", "note": "Simulated Brevo SMTP acceptance"},
            )

        import email.mime.multipart
        import email.mime.text
        import email.mime.application
        import smtplib
        import time

        msg = email.mime.multipart.MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"] = f"{target_sender_name} <{target_sender}>" if target_sender_name else target_sender
        msg["To"] = target_recipient

        alt_part = email.mime.multipart.MIMEMultipart("alternative")
        alt_part.attach(email.mime.text.MIMEText(plain_text_content, "plain", "utf-8"))
        alt_part.attach(email.mime.text.MIMEText(html_content, "html", "utf-8"))
        msg.attach(alt_part)

        if pdf_bytes:
            pdf_part = email.mime.application.MIMEApplication(pdf_bytes, _subtype="pdf")
            pdf_part.add_header("Content-Disposition", "attachment", filename=pdf_filename or "CyberGuard_Forensic_Report.pdf")
            msg.attach(pdf_part)

        loop = asyncio.get_running_loop()
        try:
            def _dispatch():
                s = smtplib.SMTP(server_host, server_port, timeout=self.timeout_sec)
                try:
                    s.starttls()
                    if login_user and login_pass:
                        s.login(login_user, login_pass)
                    s.sendmail(target_sender, [target_recipient], msg.as_string())
                finally:
                    try:
                        s.quit()
                    except Exception:
                        pass

            await loop.run_in_executor(None, _dispatch)
            msg_id = f"<brevo-smtp-{int(time.time())}@{server_host}>"
            logger.info(f"[BrevoClient SMTP] Successfully sent alert email to {target_recipient} via {server_host}")
            return BrevoSendResult(
                success=True,
                delivery_status="PROVIDER_ACCEPTED",
                http_status=200,
                message_id=msg_id,
                recipient=target_recipient,
                details={"mode": "brevo_smtp", "server": server_host},
            )
        except smtplib.SMTPResponseException as resp_err:
            raw_err = f"SMTP error ({resp_err.smtp_code}): {resp_err.smtp_error.decode('utf-8', errors='ignore') if isinstance(resp_err.smtp_error, bytes) else str(resp_err.smtp_error)}"
            clean_err = self._sanitize_error_text(raw_err)
            if "525" in str(resp_err.smtp_code) or "Unauthorized IP" in clean_err:
                clean_err += " (Brevo SMTP notice: please authorize server IP in Brevo Dashboard under Settings > Security > Authorized IPs or deactivate IP restriction, or configure a Brevo REST API key [xkeysib-...])"
            logger.warning(f"[BrevoClient SMTP] Delivery failed to {target_recipient}: {clean_err}")
            return BrevoSendResult(
                success=False,
                delivery_status="SEND_FAILED",
                http_status=resp_err.smtp_code,
                error_message=clean_err,
                recipient=target_recipient,
            )
        except Exception as exc:
            clean_exc = self._sanitize_error_text(str(exc))
            logger.warning(f"[BrevoClient SMTP] Delivery exception to {target_recipient}: {clean_exc}")
            return BrevoSendResult(
                success=False,
                delivery_status="SEND_FAILED",
                error_message=f"SMTP dispatch error: {clean_exc}",
                recipient=target_recipient,
            )

