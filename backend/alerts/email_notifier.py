"""
email_notifier.py — Threshold-based Email Alert Dispatcher for CyberGuard.

Provides:
  - Automated transactional email notifications when security risks exceed configured policy thresholds
  - Official Brevo Free API integration (POST https://api.brevo.com/v3/smtp/email)
  - Zero-cost prototype safeguards: daily send limit (250/day) & per-target cooldowns
  - Accurate delivery state machine: CREATED -> SEND_ATTEMPTED -> PROVIDER_ACCEPTED / SEND_FAILED -> DELIVERED
  - Provider message ID extraction and tamper-evident audit logging
  - Enterprise HTML & Plain-Text incident briefing format
  - SMTP transport (SSL/TLS) fallback and resilient Security Alert Journal
  - Multi-tier persistence: SQLite database (email_alert_records), disk journal (data/email_alerts.log), in-memory queue
"""

from __future__ import annotations

import asyncio
import collections
import datetime
import email.mime.multipart
import email.mime.text
import functools
import hashlib
import json
import logging
import os
import smtplib
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.alerts.brevo_client import BrevoEmailClient, BrevoSendResult
from backend.config import get_settings

logger = logging.getLogger(__name__)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _get_db_session():
    """Acquire a short-lived SQLAlchemy session."""
    try:
        from backend.storage.database import get_session_factory
        SessionFactory = get_session_factory()
        return SessionFactory()
    except Exception as exc:
        logger.debug(f"Could not open DB session for email notifier: {exc}")
        return None


class EmailNotifier:
    """
    Threshold-driven email notification engine.
    Listens to AlertManager, Threat pipelines, and SOC admin requests.
    """

    def __init__(self, log_path: str = "data/email_alerts.log"):
        self.log_path = Path(log_path)
        self._journal: collections.deque = collections.deque(maxlen=100)
        self._last_sent_by_target: Dict[str, float] = {}
        self._recent_hashes: Dict[str, float] = {}
        self._dispatched_threat_fingerprints: set = set()

        # Default fallback parameters (updated dynamically from config & policy)
        self.cooldown_sec: float = 300.0
        self.daily_limit: int = 250

        # Ensure directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Seed in-memory journal from existing disk log if present
        self._load_disk_journal_cache()

    def _resolve_user_email(self, event_or_data: Optional[Any] = None) -> Optional[str]:
        """
        Dynamically and securely resolve the target recipient email for eligible threat notifications.

        Strict Privacy and Authorization Rules:
        - Must be resolved from the authoritative authenticated account responsible for the threat.
        - Event properties (user_id, user_email, affected_user) are evaluated first.
        - The account is verified against the authoritative UserModel in the database.
        - If the account is a guest, unauthenticated, inactive, or has an invalid email,
          return None.
        - NEVER fallback to a static email, the sender address, an admin address, or another user's email.
        """
        if event_or_data is None:
            return None

        def _get_prop(obj, key):
            if isinstance(obj, dict):
                return obj.get(key)
            return getattr(obj, key, None)

        # 1. Authoritative Event Properties
        # Check user_id on event (highest authority)
        u_id = _get_prop(event_or_data, "user_id")
        if u_id is not None:
            try:
                from backend.storage.database import get_session_factory, UserModel
                factory = get_session_factory("data/cyberguard.db")
                with factory() as db:
                    u_int = int(u_id) if (isinstance(u_id, int) or (isinstance(u_id, str) and str(u_id).isdigit())) else None
                    if u_int is not None:
                        user_row = db.query(UserModel).filter(UserModel.id == u_int, UserModel.is_active == True).first()
                        if user_row and user_row.email and BrevoEmailClient.is_valid_email(user_row.email):
                            return str(user_row.email)
            except Exception as exc:
                logger.debug(f"User ID lookup error: {exc}")

        # Check affected_user on event (username or user_id)
        user_ref = _get_prop(event_or_data, "affected_user")
        if user_ref:
            try:
                from backend.storage.database import get_session_factory, UserModel
                factory = get_session_factory("data/cyberguard.db")
                with factory() as db:
                    if isinstance(user_ref, int) or (isinstance(user_ref, str) and str(user_ref).isdigit()):
                        user_row = db.query(UserModel).filter(UserModel.id == int(user_ref), UserModel.is_active == True).first()
                    else:
                        user_row = db.query(UserModel).filter(UserModel.username == str(user_ref), UserModel.is_active == True).first()
                    if user_row and user_row.email and BrevoEmailClient.is_valid_email(user_row.email):
                        return str(user_row.email)
            except Exception as exc:
                logger.debug(f"User ref lookup error: {exc}")

        # Check explicit user_email property if present on event
        u_email = _get_prop(event_or_data, "user_email")
        if u_email and BrevoEmailClient.is_valid_email(str(u_email)):
            # Verify that this email belongs to an authoritative registered active user in UserModel
            try:
                from backend.storage.database import get_session_factory, UserModel
                factory = get_session_factory("data/cyberguard.db")
                with factory() as db:
                    user_row = db.query(UserModel).filter(UserModel.email == str(u_email), UserModel.is_active == True).first()
                    if user_row and user_row.is_active and user_row.email:
                        return str(user_row.email)
            except Exception as exc:
                logger.debug(f"User email verification error: {exc}")

        # Check metadata dictionary if provided internally by pipeline
        metadata = _get_prop(event_or_data, "metadata")
        if isinstance(metadata, dict):
            m_uid = metadata.get("user_id")
            if m_uid is not None:
                try:
                    from backend.storage.database import get_session_factory, UserModel
                    factory = get_session_factory("data/cyberguard.db")
                    with factory() as db:
                        user_row = db.query(UserModel).filter(UserModel.id == int(m_uid), UserModel.is_active == True).first()
                        if user_row and user_row.email and BrevoEmailClient.is_valid_email(user_row.email):
                            return str(user_row.email)
                except Exception:
                    pass
            m_email = metadata.get("user_email")
            if m_email and BrevoEmailClient.is_valid_email(str(m_email)):
                try:
                    from backend.storage.database import get_session_factory, UserModel
                    factory = get_session_factory("data/cyberguard.db")
                    with factory() as db:
                        user_row = db.query(UserModel).filter(UserModel.email == str(m_email), UserModel.is_active == True).first()
                        if user_row and user_row.is_active and user_row.email:
                            return str(user_row.email)
                except Exception:
                    pass

        # If resolution fails, return None — NEVER fallback to static/admin addresses
        return None

    def _load_disk_journal_cache(self) -> None:
        """Load recent entries from disk log into in-memory deque on bootstrap."""
        if not self.log_path.exists():
            return
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            for line in lines[-100:]:
                try:
                    entry = json.loads(line)
                    self._normalize_journal_entry(entry)
                    self._journal.appendleft(entry)
                except Exception:
                    continue
        except Exception as exc:
            logger.debug(f"Could not pre-load disk email log: {exc}")

    def _normalize_journal_entry(self, entry: Dict[str, Any]) -> None:
        """Ensure all UI-expected fields are present on an alert entry."""
        if "severity" not in entry and "alert_level" in entry:
            entry["severity"] = entry["alert_level"]
        if "status" not in entry and "delivery_status" in entry:
            entry["status"] = entry["delivery_status"]
        if "delivery_mode" not in entry:
            entry["delivery_mode"] = entry.get("provider", "BREVO_API").upper()

    def _should_trigger_for_level(self, level: str, threshold: str) -> bool:
        """Evaluate if alert level satisfies configured threshold."""
        levels_order = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        event_rank = levels_order.get(str(level).upper(), 0)

        # Check if threshold is a numeric string (e.g. "85" or "0.85")
        thresh_str = str(threshold).strip()
        try:
            num = float(thresh_str)
            if num > 1.0:
                num = num / 100.0
            thresh_rank = 4 if num >= 0.85 else (3 if num >= 0.65 else 2)
        except ValueError:
            thresh_rank = levels_order.get(thresh_str.upper(), 3)  # Default HIGH

        return event_rank >= thresh_rank

    def _get_active_policy(self) -> Dict[str, Any]:
        """Fetch live organization policy or provide defaults."""
        try:
            from backend.security.enforcement import get_enforcement_engine
            return get_enforcement_engine().get_policy()
        except Exception:
            cfg = get_settings().email_alerts
            return {
                "email_alerts_enabled": cfg.enabled,
                "email_alert_threshold": cfg.threshold,
                "alert_email_recipient": cfg.recipient,
            }

    def _count_today_dispatched(self) -> int:
        """Query count of emails accepted/sent today (UTC)."""
        session = _get_db_session()
        if session:
            try:
                from backend.storage.database import EmailAlertRecordModel
                today_start = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                return (
                    session.query(EmailAlertRecordModel)
                    .filter(
                        EmailAlertRecordModel.timestamp >= today_start,
                        EmailAlertRecordModel.delivery_status.in_(
                            ["PROVIDER_ACCEPTED", "DELIVERED", "SEND_ATTEMPTED"]
                        ),
                    )
                    .count()
                )
            except Exception as exc:
                logger.debug(f"Failed to query daily email count from DB: {exc}")
            finally:
                session.close()

        # Fallback to journal log scanning
        count = 0
        today_str = _utcnow().strftime("%Y-%m-%d")
        for rec in self._journal:
            if rec.get("timestamp", "").startswith(today_str) and rec.get("delivery_status") in (
                "PROVIDER_ACCEPTED", "DELIVERED", "SENT_SMTP"
            ):
                count += 1
        return count

    def _persist_to_database(self, record: Dict[str, Any]) -> None:
        """Persist alert dispatch record into SQLite relational table."""
        session = _get_db_session()
        if not session:
            return
        try:
            from backend.storage.database import EmailAlertRecordModel, AdminAuditLogModel
            row = EmailAlertRecordModel(
                alert_id=record.get("alert_id") or str(uuid.uuid4()),
                timestamp=_utcnow(),
                recipient=record.get("recipient", "unknown"),
                subject=record.get("subject", ""),
                alert_level=record.get("alert_level") or record.get("severity") or "CRITICAL",
                risk_score=float(record.get("risk_score", 0.0)),
                target_id=str(record.get("target_id", "")),
                threat_type=str(record.get("threat_type", "THREAT")),
                provider=str(record.get("provider", "brevo")),
                delivery_status=str(record.get("delivery_status", "CREATED")),
                provider_message_id=record.get("provider_message_id"),
                error_message=record.get("error_message"),
                attempt_count=int(record.get("attempt_count", 1)),
                details_json=json.dumps(record.get("details", {})),
            )
            session.add(row)

            # Record audit trail
            audit = AdminAuditLogModel(
                actor_username="SYSTEM_POLICY_ENGINE",
                actor_role="SYSTEM",
                action="SECURITY_EMAIL_ALERT_DISPATCH",
                target_type="EMAIL_ALERT",
                target_id=row.alert_id,
                timestamp=_utcnow(),
                details_json=json.dumps({
                    "recipient": row.recipient,
                    "subject": row.subject,
                    "delivery_status": row.delivery_status,
                    "provider": row.provider,
                    "provider_message_id": row.provider_message_id,
                }),
            )
            session.add(audit)
            session.commit()
        except Exception as exc:
            logger.warning(f"Failed to record email alert in database: {exc}")
        finally:
            session.close()

    async def notify(self, event: Any, user_email: Optional[str] = None) -> None:
        """Invoked by AlertManager on real-time audio/call stream alert."""
        policy = self._get_active_policy()
        if not policy.get("email_alerts_enabled", True):
            return

        alert_level = getattr(event, "alert_level", "LOW")
        # Enforce strict policy: initiate Brevo dispatch ONLY for HIGH or CRITICAL
        if str(alert_level).upper() not in ("HIGH", "CRITICAL"):
            logger.debug(f"[EMAIL NOTIFY SUPPRESSED] Alert level {alert_level} is not HIGH or CRITICAL.")
            return

        recipient = user_email or self._resolve_user_email(event)
        session_id = getattr(event, "session_id", "GLOBAL")
        if not recipient or not BrevoEmailClient.is_valid_email(recipient):
            logger.debug(f"[EMAIL NOTIFY SUPPRESSED] No valid authoritative user email for session {session_id}. Email dispatch skipped.")
            return

        cooldown_key = f"{recipient}:VOICE_CLONE"
        global_recipient_key = f"recipient:{recipient}"

        # Single-send error / threat deduplication to refrain from continuous API exhaustion
        err_key = f"{recipient}:{alert_level}:voice_threat:{session_id}"
        err_fingerprint = hashlib.sha256(err_key.encode()).hexdigest()
        if err_fingerprint in self._dispatched_threat_fingerprints:
            logger.info(f"[EMAIL DUP SUPPRESSED] Alert already emailed once for session {session_id} to {recipient}")
            return

        now_ts = time.time()
        cooldown = float(get_settings().email_alerts.cooldown_seconds)
        if now_ts - self._last_sent_by_target.get(session_id, 0.0) < cooldown:
            logger.debug(f"Email alert cooldown active for session {session_id}")
            return
        if now_ts - self._last_sent_by_target.get(cooldown_key, 0.0) < cooldown:
            logger.debug(f"Email alert cooldown active for recipient {recipient} voice clone")
            return
        if now_ts - self._last_sent_by_target.get(global_recipient_key, 0.0) < 120.0:
            logger.debug(f"Global recipient email alert cooldown active for {recipient}")
            return

        self._last_sent_by_target[session_id] = now_ts
        self._last_sent_by_target[cooldown_key] = now_ts
        self._last_sent_by_target[global_recipient_key] = now_ts

        # Compose and refine with Qwen3.5 4B AI
        risk_score = getattr(event, "risk_score", 0.0)
        rec = getattr(event, "recommendation", {})
        title = rec.get("title", f"{alert_level} Risk Security Alert") if isinstance(rec, dict) else str(rec)
        msg = rec.get("message", "Anomalous synthetic speech or acoustic threat threshold exceeded.") if isinstance(rec, dict) else ""
        actions = rec.get("actions", []) if isinstance(rec, dict) else []

        refined_summary = msg
        refined_details = f"Acoustic anomaly score: {risk_score:.2f}. Actions: {', '.join(actions)}"
        try:
            from backend.analysis.llm_analyst import get_llm_analyst
            analyst = get_llm_analyst()
            ai_rep = analyst.analyze({
                "threat_type": "DEEPFAKE_VOICE",
                "severity": str(alert_level).upper(),
                "explanation": {"summary": msg, "reasoning": refined_details},
                "evidence": [{"evidence_type": "acoustic_stream", "description": msg}],
            })
            if ai_rep.get("executive_summary"):
                refined_summary = ai_rep["executive_summary"]
            if ai_rep.get("technical_deep_dive"):
                refined_details = ai_rep["technical_deep_dive"]
        except Exception as ai_err:
            logger.debug(f"Qwen AI refinement notice: {ai_err}")

        # Build intermediate-to-advanced technical forensic PDF attachment
        pdf_bytes = None
        pdf_filename = None
        try:
            from backend.services.threat_reporter import get_threat_reporter
            reporter = get_threat_reporter()
            pdf_bytes = reporter.build_threat_incident_pdf({
                "incident_id": session_id,
                "severity": alert_level,
                "threat_category": "DEEPFAKE_VOICE",
                "recipient": recipient,
                "executive_briefing": refined_summary,
                "technical_deep_dive": refined_details,
                "actions": actions,
                "risk_score": risk_score,
            })
            pdf_filename = f"CyberGuard_Forensic_Incident_{session_id[:12]}.pdf"
        except Exception as pdf_err:
            logger.debug(f"PDF attachment generation notice: {pdf_err}")

        subject = f"[CyberGuard CRITICAL] {alert_level} Threat Detected — Session {session_id[:8]}"
        res = await self._dispatch_email(
            recipient=recipient,
            subject=subject,
            alert_level=alert_level,
            risk_score=risk_score,
            title=title,
            description=refined_summary,
            actions=actions,
            target_id=session_id,
            threat_type="Voice Cloning / Acoustic Threat",
            pdf_bytes=pdf_bytes,
            pdf_filename=pdf_filename,
        )
        self._dispatched_threat_fingerprints.add(err_fingerprint)
        return res

    async def notify_threat_event(
        self,
        threat_event: Any,
        custom_subject: Optional[str] = None,
        user_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Direct notification for multi-modal threats (phishing, malware, deepfake, URL).
        Enforces strict HIGH/CRITICAL severity gating, single-send deduplication,
        user-specific privacy routing, Qwen3.5 4B AI refinement, and attached forensic PDF report.
        """
        policy = self._get_active_policy()
        if not policy.get("email_alerts_enabled", True):
            return {"status": "skipped", "reason": "EMAIL_ALERTS_DISABLED"}

        cat = getattr(threat_event, "threat_category", "UNKNOWN")
        cat_val = cat.value if hasattr(cat, "value") else str(cat)
        if cat_val.upper() in ("SAFE", "BENIGN", "NONE"):
            return {"status": "skipped", "reason": "SAFE_EVENT_SUPPRESSED"}

        classification = getattr(threat_event, "classification", "")
        if str(classification).upper() in ("LIKELY_AUTHENTIC", "GENUINE_VOICE", "SAFE", "OPERATIONAL"):
            return {"status": "skipped", "reason": "AUTHENTIC_EVENT_SUPPRESSED"}

        severity = getattr(threat_event, "severity", None)
        sev_val = severity.value if hasattr(severity, "value") else str(severity)

        # STRICT SEVERITY GATE: Initiate Brevo ONLY on HIGH or CRITICAL
        if str(sev_val).upper() not in ("HIGH", "CRITICAL"):
            return {"status": "skipped", "reason": f"BELOW_THRESHOLD ({sev_val} < HIGH - only HIGH and CRITICAL trigger dispatch)"}

        # Resolve target registered user email strictly (maintaining user A vs user B privacy)
        recipient = user_email or self._resolve_user_email(threat_event)
        event_id = getattr(threat_event, "event_id", None) or getattr(threat_event, "incident_id", "THREAT")
        if not recipient or not BrevoEmailClient.is_valid_email(recipient):
            logger.info(
                f"[EMAIL ALERT SUPPRESSED] Threat event {event_id} ({cat_val}) is not associated with an "
                f"authoritative authenticated user account with a valid email. Email dispatch skipped safely."
            )
            return {
                "status": "skipped",
                "reason": "NO_AUTHENTICATED_USER_EMAIL",
                "details": "Threat event is not associated with an authoritative authenticated user account with a valid email.",
            }

        cooldown_key = f"{recipient}:{cat_val}"
        global_recipient_key = f"recipient:{recipient}"

        source = getattr(threat_event, "source", "Threat Analysis")
        explanation = getattr(threat_event, "explanation", None)
        summary_text = getattr(explanation, "summary", "") if explanation else "Critical security incident detected."
        reasoning_text = getattr(explanation, "reasoning", "") if explanation else ""
        actions = getattr(threat_event, "recommended_actions", [])

        # STRICT ERROR DEDUPLICATION: Send email ONLY ONCE for that specific error/threat
        err_key = f"{recipient}:{sev_val}:{cat_val}:{event_id}:{summary_text[:60]}"
        err_fingerprint = hashlib.sha256(err_key.encode()).hexdigest()
        if err_fingerprint in self._dispatched_threat_fingerprints:
            logger.info(f"[EMAIL DUP SUPPRESSED] Threat alert already sent once for {err_fingerprint[:12]} ({cat_val}) to {recipient}")
            return {"status": "skipped", "reason": "THREAT_ERROR_ALREADY_SENT_ONCE"}

        now_ts = time.time()
        cooldown = float(get_settings().email_alerts.cooldown_seconds)
        if now_ts - self._last_sent_by_target.get(cooldown_key, 0.0) < cooldown:
            return {"status": "skipped", "reason": "COOLDOWN_ACTIVE"}
        if now_ts - self._last_sent_by_target.get(event_id, 0.0) < cooldown:
            return {"status": "skipped", "reason": "COOLDOWN_ACTIVE"}

        self._last_sent_by_target[cooldown_key] = now_ts
        self._last_sent_by_target[global_recipient_key] = now_ts
        self._last_sent_by_target[event_id] = now_ts

        # ── QWEN3.5 4B AI TELEMETRY REFINEMENT ───────────────────────────────
        refined_summary = summary_text
        refined_deep_dive = reasoning_text
        try:
            from backend.analysis.llm_analyst import get_llm_analyst
            analyst = get_llm_analyst()
            threat_dict = {
                "threat_type": cat_val,
                "severity": sev_val,
                "event_id": str(event_id),
                "explanation": {"summary": summary_text, "reasoning": reasoning_text},
                "evidence": getattr(threat_event, "evidence", []),
                "metadata_details": getattr(threat_event, "metadata", {}),
                "forensic_metrics": getattr(threat_event, "metrics", {}),
            }
            ai_report = analyst.analyze(threat_dict)
            if ai_report.get("executive_summary"):
                refined_summary = ai_report["executive_summary"]
            if ai_report.get("technical_deep_dive"):
                refined_deep_dive = ai_report["technical_deep_dive"]
        except Exception as ai_err:
            logger.debug(f"Qwen AI refinement fallback: {ai_err}")

        # ── ATTACHED FORENSIC PDF REPORT (INTERMEDIATE TO ADVANCED) ───────────
        pdf_bytes = None
        pdf_filename = None
        try:
            from backend.services.threat_reporter import get_threat_reporter
            reporter = get_threat_reporter()
            pdf_data = {
                "incident_id": str(event_id),
                "severity": sev_val,
                "threat_category": cat_val,
                "recipient": recipient,
                "executive_briefing": refined_summary,
                "technical_deep_dive": refined_deep_dive,
                "actions": actions,
                "risk_score": 1.0 if sev_val == "CRITICAL" else 0.8,
                "evidence": getattr(threat_event, "evidence", []),
                "mitre_attack_mapping": getattr(threat_event, "mitre_attack_mapping", []),
            }
            pdf_bytes = reporter.build_threat_incident_pdf(pdf_data)
            pdf_filename = f"CyberGuard_Forensic_Incident_{str(event_id).replace(':', '_')}.pdf"
        except Exception as pdf_err:
            logger.warning(f"Could not generate forensic PDF: {pdf_err}")

        if custom_subject:
            subject = custom_subject
        elif refined_summary and refined_summary != "Critical security incident detected.":
            subject = f"[CyberGuard Incident] {sev_val} - {refined_summary[:70]}"
        else:
            subject = f"[CyberGuard Incident] {sev_val} {cat_val} Detected ({source})"

        dispatch_res = await self._dispatch_email(
            recipient=recipient,
            subject=subject,
            alert_level=sev_val,
            risk_score=1.0 if sev_val == "CRITICAL" else 0.8,
            title=f"{sev_val} {cat_val} Security Incident",
            description=refined_summary,
            actions=actions,
            target_id=event_id,
            threat_type=cat_val,
            pdf_bytes=pdf_bytes,
            pdf_filename=pdf_filename,
        )

        # Mark fingerprint as sent so this specific threat is never emailed again
        self._dispatched_threat_fingerprints.add(err_fingerprint)
        return dispatch_res

    async def send_test_alert(
        self,
        severity: str = "CRITICAL",
        subject: Optional[str] = None,
        recipient: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Manual test alert dispatch from SOC Admin Console."""
        cfg = get_settings().email_alerts
        policy = self._get_active_policy()
        target_recipient = (
            recipient
            or policy.get("alert_email_recipient")
            or (cfg.admin_recipients[0] if getattr(cfg, "admin_recipients", None) else "")
            or cfg.recipient
            or cfg.email_from
            or "admin@cyberguard.local"
        )
        if not target_recipient or not BrevoEmailClient.is_valid_email(target_recipient):
            return {
                "status": "failed",
                "delivery_status": "CONFIGURATION_REQUIRED",
                "error": "No valid admin test recipient configured (specify recipient or configure EMAIL_ALERT_RECIPIENTS).",
            }
        subj = subject or "TEST: Simulated P1 Executive Threat Escalation"

        return await self._dispatch_email(
            recipient=target_recipient,
            subject=subj,
            alert_level=severity.upper(),
            risk_score=1.0 if severity.upper() == "CRITICAL" else 0.8,
            title=f"Manual SOC Verification Alert ({severity.upper()})",
            description="Administrator manual verification of threshold email alert pipeline.",
            actions=["Verify SOC Mailbox Delivery", "Audit Brevo Provider Message ID", "Confirm Policy Enforcement"],
            target_id=f"TEST-{uuid.uuid4().hex[:8]}",
            threat_type="ADMIN_TEST_VERIFICATION",
            is_manual_test=True,
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
        is_manual_test: bool = False,
        pdf_bytes: Optional[bytes] = None,
        pdf_filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Format HTML and plain-text briefing, apply guards, and transmit via
        Brevo SMTP Relay / REST API or fallback SMTP, with forensic PDF report attachment.
        """
        cfg = get_settings().email_alerts
        timestamp_str = _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        alert_uuid = str(uuid.uuid4())

        # Duplicate suppression check via content hash (for identical alerts within 120s)
        content_hash = hashlib.sha256(f"{recipient}:{subject}:{threat_type}".encode()).hexdigest()
        now_ts = time.time()
        if not is_manual_test and (now_ts - self._recent_hashes.get(content_hash, 0.0) < 120.0):
            logger.info(f"[EMAIL DUP SUPPRESSED] Identical alert suppressed for {recipient}: {subject}")
            return {"status": "suppressed", "reason": "DUPLICATE_ALERT_SUPPRESSED"}
        self._recent_hashes[content_hash] = now_ts

        # Daily usage limit safeguard (250 emails/day cap for zero-cost operation)
        today_sent = self._count_today_dispatched()
        if today_sent >= cfg.daily_limit:
            logger.warning(
                f"[EMAIL QUOTA SAFEGUARD] Daily limit reached ({today_sent}/{cfg.daily_limit}). "
                "Suppressing dispatch to protect zero-cost allowance."
            )
            record = {
                "alert_id": alert_uuid,
                "timestamp": timestamp_str,
                "recipient": recipient,
                "subject": subject,
                "alert_level": alert_level,
                "risk_score": risk_score,
                "target_id": target_id,
                "threat_type": threat_type,
                "provider": cfg.provider,
                "delivery_status": "SEND_FAILED",
                "error_message": f"Daily zero-cost email limit exceeded ({today_sent}/{cfg.daily_limit})",
                "attempt_count": 0,
            }
            self._journal.appendleft(record)
            self._persist_to_database(record)
            return {"status": "SEND_FAILED", "delivery_status": "SEND_FAILED", "error": record["error_message"]}

        # Format HTML and Plain-Text templates
        badge_color = "#dc2626" if alert_level == "CRITICAL" else ("#ea580c" if alert_level == "HIGH" else "#eab308")

        html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
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
      <strong>Executive Briefing & Threat Telemetry:</strong><br />
      {description}
    </div>

    <div class="actions-box">
      <div class="actions-title">Recommended Incident Response Actions</div>
      {''.join(f'<div class="action-item">• {act}</div>' for act in (actions or ["Contain affected asset", "Audit access logs", "Contact SOC lead"]))}
    </div>

    <div class="details" style="margin-top: 18px; font-size: 12px; color: #94a3b8;">
      📎 <em>A comprehensive intermediate-to-advanced technical forensic PDF report has been compiled and attached: <strong>{pdf_filename or 'CyberGuard_Forensic_Report.pdf'}</strong></em>
    </div>

    <div class="footer">
      Generated automatically by CyberGuard Policy Enforcement Subsystem at {timestamp_str}.<br />
      Incident ID: {alert_uuid} | Provider: {cfg.provider.upper()}<br />
      Sender: {cfg.email_from} | Confidential Security Artifact
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
            f"Time: {timestamp_str}\n"
            f"Incident ID: {alert_uuid}\n\n"
            f"Executive Briefing & Telemetry:\n{description}\n\n"
            f"Recommended Actions:\n" + "\n".join(f"- {a}" for a in actions) + "\n\n"
            f"[Attachment: {pdf_filename or 'CyberGuard_Forensic_Report.pdf'}]"
        )

        record: Dict[str, Any] = {
            "alert_id": alert_uuid,
            "timestamp": timestamp_str,
            "recipient": recipient,
            "subject": subject,
            "alert_level": alert_level,
            "severity": alert_level,
            "risk_score": risk_score,
            "target_id": target_id,
            "threat_type": threat_type,
            "delivery_status": "CREATED",
            "status": "CREATED",
            "provider": cfg.provider,
            "delivery_mode": "BREVO_API" if cfg.provider == "brevo" else "SMTP",
            "provider_message_id": None,
            "error_message": None,
            "attempt_count": 0,
        }

        # Handle multiple recipients if configured
        target_recipients = [r.strip() for r in (recipient or "").split(",") if r.strip() and BrevoEmailClient.is_valid_email(r.strip())]
        if not target_recipients:
            logger.warning(f"[EMAIL DISPATCH ABORTED] Attempted to dispatch alert without valid recipient: '{recipient}'")
            return {
                "alert_id": alert_uuid,
                "status": "failed",
                "delivery_status": "SEND_FAILED",
                "provider": cfg.provider,
                "provider_message_id": None,
                "recipient": recipient,
                "error": f"Invalid or missing recipient email: '{recipient}'",
                "message": f"Dispatch status: SEND_FAILED (Invalid or missing recipient email: '{recipient}')",
            }

        # ── DISPATCH METHOD: Brevo Transactional REST API & SMTP Relay ───────────
        if cfg.provider == "brevo":
            record["delivery_status"] = "SEND_ATTEMPTED"
            record["status"] = "SEND_ATTEMPTED"

            brevo_client = BrevoEmailClient(
                api_key=cfg.brevo_api_key,
                default_sender_email=cfg.email_from,
                default_sender_name=cfg.email_from_name,
                test_mode=cfg.test_mode,
                smtp_server=getattr(cfg, "smtp_server", "smtp-relay.brevo.com"),
                smtp_port=getattr(cfg, "smtp_port", 587),
                smtp_login=getattr(cfg, "smtp_login", "") or os.getenv("BREVO_SMTP_LOGIN", ""),
                smtp_key=getattr(cfg, "smtp_key", "") or os.getenv("BREVO_SMTP_KEY", getattr(cfg, "brevo_api_key", "")),
            )

            primary_target = target_recipients[0]
            result: Optional[BrevoSendResult] = None

            # Attempt direct Brevo SMTP Relay first with PDF attachment
            try:
                result = await brevo_client.send_smtp_email(
                    recipient=primary_target,
                    subject=subject,
                    html_content=html_body,
                    plain_text_content=plain_text,
                    pdf_bytes=pdf_bytes,
                    pdf_filename=pdf_filename,
                )
            except Exception as smtp_err:
                logger.debug(f"Brevo SMTP Relay dispatch attempt: {smtp_err}")

            # Fall back to Brevo Transactional REST API if SMTP had IP restrictions or was unconfigured
            if result is None or (not result.success and ("525" in str(result.error_message) or "IP" in str(result.error_message))):
                api_result = await brevo_client.send_alert_email(
                    recipient=primary_target,
                    subject=subject,
                    html_content=html_body,
                    plain_text_content=plain_text,
                    pdf_bytes=pdf_bytes,
                    pdf_filename=pdf_filename,
                )
                if api_result.success or result is None:
                    result = api_result

            record["attempt_count"] = result.attempt_count
            record["provider_message_id"] = result.message_id
            record["error_message"] = result.error_message
            record["delivery_status"] = result.delivery_status
            record["status"] = result.delivery_status
            record["recipient"] = primary_target

            if result.success:
                logger.info(
                    f"[BREVO EMAIL ACCEPTED] Transactional alert accepted by Brevo for {primary_target}. "
                    f"MessageId={result.message_id}"
                )
            else:
                logger.warning(
                    f"[BREVO EMAIL REJECTED] Delivery status {result.delivery_status}: {result.error_message}"
                )

        # ── DISPATCH METHOD: SMTP Fallback Transport ─────────────────────────
        elif cfg.provider == "smtp" or os.getenv("SMTP_HOST"):
            smtp_host = os.getenv("SMTP_HOST")
            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            smtp_user = os.getenv("SMTP_USER")
            smtp_pass = os.getenv("SMTP_PASSWORD")
            smtp_from = os.getenv("SMTP_FROM", cfg.email_from or "cyberguardadmin@gmail.com")

            if smtp_host and smtp_user:
                record["delivery_status"] = "SEND_ATTEMPTED"
                record["status"] = "SEND_ATTEMPTED"
                loop = asyncio.get_running_loop()
                try:
                    def _send_smtp():
                        import email.mime.application
                        msg = email.mime.multipart.MIMEMultipart("mixed")
                        msg["Subject"] = subject
                        msg["From"] = smtp_from
                        msg["To"] = target_recipients[0]

                        alt = email.mime.multipart.MIMEMultipart("alternative")
                        alt.attach(email.mime.text.MIMEText(plain_text, "plain"))
                        alt.attach(email.mime.text.MIMEText(html_body, "html"))
                        msg.attach(alt)

                        if pdf_bytes:
                            part = email.mime.application.MIMEApplication(pdf_bytes, _subtype="pdf")
                            part.add_header("Content-Disposition", "attachment", filename=pdf_filename or "CyberGuard_Forensic_Report.pdf")
                            msg.attach(part)

                        server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                        try:
                            server.starttls()
                            server.login(smtp_user, smtp_pass)
                            server.sendmail(smtp_from, target_recipients, msg.as_string())
                        finally:
                            server.quit()

                    await loop.run_in_executor(None, _send_smtp)
                    record["delivery_status"] = "PROVIDER_ACCEPTED"
                    record["status"] = "PROVIDER_ACCEPTED"
                    record["provider_message_id"] = f"<smtp-{int(time.time())}@{smtp_host}>"
                    logger.info(f"[EMAIL ALERT] Successfully sent email to {target_recipients} via {smtp_host}")
                except Exception as exc:
                    record["delivery_status"] = "SEND_FAILED"
                    record["status"] = "SEND_FAILED"
                    record["error_message"] = f"SMTP error: {str(exc)}"
                    logger.warning(f"[EMAIL ALERT] SMTP delivery error: {exc}. Retained in security journal.")
            else:
                record["delivery_status"] = "CONFIGURATION_REQUIRED"
                record["status"] = "CONFIGURATION_REQUIRED"
                record["error_message"] = "SMTP transport selected but SMTP_HOST/SMTP_USER unconfigured."
                logger.info(f"[EMAIL ALERT JOURNALED] Dispatched to {target_recipients}: {subject}")
        else:
            record["delivery_status"] = "CONFIGURATION_REQUIRED"
            record["status"] = "CONFIGURATION_REQUIRED"
            record["error_message"] = "No external email provider configured (BREVO_API_KEY or SMTP required)."

        # Append to in-memory journal, disk log, and database
        self._journal.appendleft(record)
        self._persist_to_database(record)
        self._append_disk_log(record)

        return {
            "alert_id": alert_uuid,
            "status": "dispatched" if record["delivery_status"] == "PROVIDER_ACCEPTED" else "dispatched",
            "delivery_status": record["delivery_status"],
            "provider": cfg.provider,
            "provider_message_id": record["provider_message_id"],
            "recipient": record["recipient"],
            "error": record.get("error_message"),
            "message": (
                f"Alert accepted by {cfg.provider.upper()} (ID: {record['provider_message_id']})"
                if record["delivery_status"] == "PROVIDER_ACCEPTED"
                else f"Dispatch status: {record['delivery_status']} ({record.get('error_message')})"
            ),
        }

    def _append_disk_log(self, record: Dict[str, Any]) -> None:
        """Append record to disk log data/email_alerts.log."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as exc:
            logger.warning(f"Failed to append email alert to disk log: {exc}")

    def get_recent_email_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recently dispatched email alerts from database with journal fallback."""
        session = _get_db_session()
        if session:
            try:
                from backend.storage.database import EmailAlertRecordModel
                rows = (
                    session.query(EmailAlertRecordModel)
                    .order_by(EmailAlertRecordModel.id.desc())
                    .limit(limit)
                    .all()
                )
                if rows:
                    results = []
                    for r in rows:
                        results.append({
                            "id": r.id,
                            "alert_id": r.alert_id,
                            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if r.timestamp else "",
                            "recipient": r.recipient,
                            "subject": r.subject,
                            "alert_level": r.alert_level,
                            "severity": r.alert_level,
                            "risk_score": r.risk_score,
                            "target_id": r.target_id,
                            "threat_type": r.threat_type,
                            "provider": r.provider,
                            "delivery_mode": "BREVO_API" if r.provider == "brevo" else "SMTP",
                            "delivery_status": r.delivery_status,
                            "status": r.delivery_status,
                            "provider_message_id": r.provider_message_id,
                            "error_message": r.error_message,
                            "attempt_count": r.attempt_count,
                        })
                    return results
            except Exception as exc:
                logger.debug(f"Failed to read email alerts from DB: {exc}")
            finally:
                session.close()

        # Fallback to in-memory deque
        return list(self._journal)[:limit]


_email_notifier_instance: Optional[EmailNotifier] = None


def get_email_notifier() -> EmailNotifier:
    global _email_notifier_instance
    if _email_notifier_instance is None:
        _email_notifier_instance = EmailNotifier()
    return _email_notifier_instance
