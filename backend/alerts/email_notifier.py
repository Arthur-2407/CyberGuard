"""
email_notifier.py — Threshold-based Email Alert Dispatcher for CyberGuard.

Provides:
  - Automated email notifications when security risks exceed configured policy thresholds
  - Enterprise HTML & Plain-Text incident briefing format
  - SMTP transport (SSL/TLS) with seamless fallback to auditable Security Alert Journal
  - Anti-spam cooldown per session / incident
  - In-memory dispatch journal for administrative SOC inspection
"""

from __future__ import annotations

import asyncio
import collections
import datetime
import email.mime.multipart
import email.mime.text
import functools
import json
import logging
import os
import smtplib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class EmailNotifier:
    """
    Threshold-driven email notification engine.
    Listens to AlertManager and Threat pipelines.
    """

    def __init__(self, log_path: str = "data/email_alerts.log"):
        self.log_path = Path(log_path)
        self._journal: collections.deque = collections.deque(maxlen=100)
        self._last_sent_by_target: Dict[str, float] = {}
        self.cooldown_sec: float = 60.0  # Min 60s between duplicate alert emails per target

        # Ensure directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _should_trigger_for_level(self, level: str, threshold: str) -> bool:
        """Evaluate if alert level satisfies configured threshold."""
        levels_order = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        event_rank = levels_order.get(str(level).upper(), 0)
        thresh_rank = levels_order.get(str(threshold).upper(), 4)
        return event_rank >= thresh_rank

    async def notify(self, event: Any) -> None:
        """Invoked by AlertManager on every audio/call stream alert."""
        try:
            from backend.security.enforcement import get_enforcement_engine
            policy = get_enforcement_engine().get_policy()
        except Exception:
            policy = {
                "email_alerts_enabled": True,
                "email_alert_threshold": "CRITICAL",
                "alert_email_recipient": "security-ops@cyberguard.local",
            }

        if not policy.get("email_alerts_enabled", True):
            return

        alert_level = getattr(event, "alert_level", "LOW")
        threshold = policy.get("email_alert_threshold", "CRITICAL")
        if not self._should_trigger_for_level(alert_level, threshold):
            return

        session_id = getattr(event, "session_id", "GLOBAL")
        now_ts = time.time()
        last_sent = self._last_sent_by_target.get(session_id, 0.0)
        if now_ts - last_sent < self.cooldown_sec:
            logger.debug(f"Email alert cooldown active for session {session_id}")
            return

        self._last_sent_by_target[session_id] = now_ts

        # Compose and dispatch
        recipient = policy.get("alert_email_recipient", "security-ops@cyberguard.local")
        risk_score = getattr(event, "risk_score", 0.0)
        rec = getattr(event, "recommendation", {})
        title = rec.get("title", f"{alert_level} Risk Security Alert") if isinstance(rec, dict) else str(rec)
        msg = rec.get("message", "Anomalous synthetic speech or security threat threshold exceeded.") if isinstance(rec, dict) else ""
        actions = rec.get("actions", []) if isinstance(rec, dict) else []

        subject = f"[CyberGuard CRITICAL] {alert_level} Threat Detected — Session {session_id[:8]}"
        await self._dispatch_email(
            recipient=recipient,
            subject=subject,
            alert_level=alert_level,
            risk_score=risk_score,
            title=title,
            description=msg,
            actions=actions,
            target_id=session_id,
            threat_type="Voice Cloning / Acoustic Threat",
        )

    async def notify_threat_event(self, threat_event: Any, custom_subject: Optional[str] = None) -> None:
        """Direct notification for multi-modal threats (phishing, malware, deepfake, URL)."""
        try:
            from backend.security.enforcement import get_enforcement_engine
            policy = get_enforcement_engine().get_policy()
        except Exception:
            policy = {
                "email_alerts_enabled": True,
                "email_alert_threshold": "CRITICAL",
                "alert_email_recipient": "security-ops@cyberguard.local",
            }

        if not policy.get("email_alerts_enabled", True):
            return

        severity = getattr(threat_event, "severity", None)
        sev_val = severity.value if hasattr(severity, "value") else str(severity)
        threshold = policy.get("email_alert_threshold", "CRITICAL")
        if not self._should_trigger_for_level(sev_val, threshold):
            return

        event_id = getattr(threat_event, "event_id", None) or getattr(threat_event, "incident_id", "THREAT")
        now_ts = time.time()
        if now_ts - self._last_sent_by_target.get(event_id, 0.0) < self.cooldown_sec:
            return
        self._last_sent_by_target[event_id] = now_ts

        cat = getattr(threat_event, "threat_category", "UNKNOWN")
        cat_val = cat.value if hasattr(cat, "value") else str(cat)
        source = getattr(threat_event, "source", "Threat Analysis")
        explanation = getattr(threat_event, "explanation", None)
        summary_text = getattr(explanation, "summary", "") if explanation else "Critical security incident detected."
        reasoning_text = getattr(explanation, "reasoning", "") if explanation else ""
        actions = getattr(threat_event, "recommended_actions", [])

        recipient = policy.get("alert_email_recipient", "security-ops@cyberguard.local")
        if custom_subject:
            subject = custom_subject
        elif summary_text and summary_text != "Critical security incident detected.":
            subject = f"[CyberGuard Incident] {sev_val} - {summary_text}"
        else:
            subject = f"[CyberGuard Incident] {sev_val} {cat_val} Detected ({source})"

        await self._dispatch_email(
            recipient=recipient,
            subject=subject,
            alert_level=sev_val,
            risk_score=1.0 if sev_val == "CRITICAL" else 0.8,
            title=f"{sev_val} {cat_val} Alert",
            description=f"{summary_text} {reasoning_text}".strip(),
            actions=actions,
            target_id=event_id,
            threat_type=cat_val,
        )

    async def _dispatch_email(
        self,
        recipient: str,
        subject: str,
        alert_level: str,
        risk_score: float,
        title: str,
        description: str,
        actions: List[str],
        target_id: str,
        threat_type: str,
    ) -> None:
        """Format HTML and transmit via SMTP or write to security journal."""
        timestamp_str = _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Color mapping
        badge_color = "#dc2626" if alert_level == "CRITICAL" else ("#ea580c" if alert_level == "HIGH" else "#eab308")

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f1f5f9; margin: 0; padding: 24px; }}
    .container {{ max-width: 620px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .header {{ border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; }}
    .brand {{ font-size: 14px; font-weight: 700; color: #06b6d4; text-transform: uppercase; letter-spacing: 0.1em; }}
    .title {{ font-size: 22px; font-weight: 800; color: #ffffff; margin: 8px 0 0 0; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 800; text-transform: uppercase; color: #fff; background-color: {badge_color}; margin-top: 8px; }}
    .metric-row {{ display: flex; gap: 16px; background: #020617; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin: 20px 0; }}
    .metric-col {{ flex: 1; }}
    .metric-label {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    .metric-value {{ font-size: 16px; font-weight: 700; color: #38bdf8; margin-top: 4px; }}
    .details {{ color: #cbd5e1; font-size: 14px; line-height: 1.6; margin: 16px 0; }}
    .actions-box {{ background: rgba(6, 182, 212, 0.05); border-left: 4px solid #06b6d4; padding: 14px 16px; border-radius: 0 8px 8px 0; margin-top: 20px; }}
    .actions-title {{ font-size: 13px; font-weight: 700; color: #38bdf8; text-transform: uppercase; margin-bottom: 8px; }}
    .action-item {{ font-size: 13px; color: #cbd5e1; margin-bottom: 4px; }}
    .footer {{ border-top: 1px solid #1e293b; margin-top: 28px; padding-top: 16px; font-size: 12px; color: #64748b; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">CyberGuard SOC Automated Threat Alert</div>
      <div class="title">{title}</div>
      <div class="badge">{alert_level} SEVERITY</div>
    </div>

    <div class="metric-row">
      <div class="metric-col">
        <div class="metric-label">Incident Target / Session</div>
        <div class="metric-value">{target_id}</div>
      </div>
      <div class="metric-col">
        <div class="metric-label">Threat Classification</div>
        <div class="metric-value">{threat_type}</div>
      </div>
      <div class="metric-col">
        <div class="metric-label">Assessed Risk Score</div>
        <div class="metric-value">{risk_score:.2f} / 1.00</div>
      </div>
    </div>

    <div class="details">
      <strong>Incident Summary:</strong><br />
      {description}
    </div>

    <div class="actions-box">
      <div class="actions-title">Recommended Incident Response Actions</div>
      {''.join(f'<div class="action-item">• {act}</div>' for act in (actions or ["Contain affected asset", "Audit access logs", "Contact SOC lead"]))}
    </div>

    <div class="footer">
      Generated automatically by CyberGuard Policy Enforcement Subsystem at {timestamp_str}.<br />
      Please do not reply directly to this automated security dispatch.
    </div>
  </div>
</body>
</html>
"""
        plain_text = (
            f"CYBERGUARD SECURITY ALERT: {alert_level}\n"
            f"Target: {target_id}\n"
            f"Category: {threat_type}\n"
            f"Risk Score: {risk_score:.2f}\n"
            f"Time: {timestamp_str}\n\n"
            f"Details: {description}\n\n"
            f"Recommended Actions:\n" + "\n".join(f"- {a}" for a in actions)
        )

        record = {
            "timestamp": timestamp_str,
            "recipient": recipient,
            "subject": subject,
            "alert_level": alert_level,
            "risk_score": risk_score,
            "target_id": target_id,
            "threat_type": threat_type,
            "delivery_status": "JOURNALED",
        }

        # Check SMTP configuration
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASSWORD")
        smtp_from = os.getenv("SMTP_FROM", "alerts@cyberguard.local")

        if smtp_host and smtp_user:
            loop = asyncio.get_running_loop()
            try:
                def _send_smtp():
                    msg = email.mime.multipart.MIMEMultipart("alternative")
                    msg["Subject"] = subject
                    msg["From"] = smtp_from
                    msg["To"] = recipient
                    msg.attach(email.mime.text.MIMEText(plain_text, "plain"))
                    msg.attach(email.mime.text.MIMEText(html_body, "html"))

                    server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                    try:
                        server.starttls()
                        server.login(smtp_user, smtp_pass)
                        server.sendmail(smtp_from, [recipient], msg.as_string())
                    finally:
                        server.quit()

                await loop.run_in_executor(None, _send_smtp)
                record["delivery_status"] = "SENT_SMTP"
                logger.info(f"[EMAIL ALERT] Successfully sent email to {recipient} via {smtp_host}")
            except Exception as exc:
                record["delivery_status"] = f"SMTP_ERROR: {str(exc)}"
                logger.warning(f"[EMAIL ALERT] SMTP delivery error: {exc}. Retained in security journal.")
        else:
            record["delivery_status"] = "JOURNALED (No external SMTP configured)"
            logger.info(f"[EMAIL ALERT JOURNALED] Dispatched to {recipient}: {subject}")

        # Persist to disk journal & in-memory deque
        self._journal.appendleft(record)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            logger.warning(f"Failed to append email alert to disk log: {exc}")

    def get_recent_email_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recently dispatched email alerts."""
        return list(self._journal)[:limit]


_email_notifier_instance: Optional[EmailNotifier] = None

def get_email_notifier() -> EmailNotifier:
    global _email_notifier_instance
    if _email_notifier_instance is None:
        _email_notifier_instance = EmailNotifier()
    return _email_notifier_instance
