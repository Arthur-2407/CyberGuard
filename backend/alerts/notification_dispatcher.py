"""
notification_dispatcher.py — Centralized Security Notification Dispatcher for CyberGuard.

Guarantees:
  - Canonical threshold gating: ONLY HIGH and CRITICAL threats trigger security email notifications.
  - LOW, MEDIUM, SAFE, and INFORMATIONAL detections are recorded locally but NEVER trigger automated emails.
  - Durable Outbox pattern: Threat alert records are persisted as QUEUED in email_alert_records prior to transmission.
  - Unified Event Bus: All pipelines (Threat Intel Search, Phishing & URL, Malware Lab, File Scanner,
    QR Scanner, Media Forensics, Anomaly Detector, Call Screening) publish to this single authoritative dispatcher.
  - Idempotent single-send deduplication with configurable cooldown windows to prevent alert storms.
  - Asynchronous retry with exponential backoff and jitter for transient provider failures.
  - Transparent delivery audit history queryable by authorized administrators.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import logging
import random
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.alerts.email_notifier import get_email_notifier, EmailNotifier
from backend.config import get_settings
from backend.threats.models import RiskLevel, ThreatCategory, ThreatEvent

logger = logging.getLogger(__name__)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _get_db_session():
    try:
        from backend.storage.database import get_session_factory
        SessionFactory = get_session_factory()
        return SessionFactory()
    except Exception as exc:
        logger.debug(f"Could not open DB session for notification dispatcher: {exc}")
        return None


class ThreatNotificationDispatcher:
    """
    Centralized event bus and durable outbox manager for all security threat notifications.
    """

    def __init__(self):
        self._email_notifier: Optional[EmailNotifier] = None
        self._in_flight_tasks: set = set()
        self._recent_dispatches: Dict[str, float] = {}

    @property
    def email_notifier(self) -> EmailNotifier:
        if self._email_notifier is None:
            self._email_notifier = get_email_notifier()
        return self._email_notifier

    @staticmethod
    def is_eligible_severity(severity: Any) -> bool:
        """
        Authoritative severity threshold check:
        ONLY HIGH and CRITICAL are eligible for automatic security emails.
        """
        if severity is None:
            return False
        val = severity.value if hasattr(severity, "value") else str(severity)
        normalized = str(val).strip().upper()
        return normalized in ("HIGH", "CRITICAL")

    def resolve_recipient(
        self,
        event: ThreatEvent,
        explicit_email: Optional[str] = None,
        explicit_user_id: Optional[int] = None,
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """
        Resolves the recipient email address with strict priority:
          1. Explicit email parameter passed by authenticated caller
          2. Verified user email from event.user_email or event.user_id account lookup
          3. Configured system alert recipient (fallback for background, CLI, or unauthenticated scans)
        Returns: (user_id, username, recipient_email)
        """
        from backend.alerts.brevo_client import BrevoEmailClient

        # 1. Direct explicit email
        if explicit_email and BrevoEmailClient.is_valid_email(explicit_email.strip()):
            return explicit_user_id, "Analyst", explicit_email.strip().lower()

        # 2. Event user properties
        u_id = explicit_user_id or getattr(event, "user_id", None)
        u_email = getattr(event, "user_email", None)

        if u_id is not None or (u_email and BrevoEmailClient.is_valid_email(str(u_email).strip())):
            user_id, username, email, _ = self.email_notifier._resolve_authenticated_account(
                {"user_id": u_id, "user_email": u_email}
            )
            if email:
                return user_id, username, email

        # 3. System fallback recipient for automated and perimeter scans
        settings = get_settings()
        cfg = settings.email_alerts
        fallback_candidates = [
            cfg.recipient,
            cfg.admin_recipients[0] if getattr(cfg, "admin_recipients", None) else None,
            cfg.email_from,
        ]
        for candidate in fallback_candidates:
            if candidate and BrevoEmailClient.is_valid_email(str(candidate).strip()):
                return None, "Security Team", str(candidate).strip().lower()

        return None, None, None

    def compute_event_fingerprint(self, event: ThreatEvent, recipient: str) -> str:
        """Deterministic hash to guarantee idempotent single delivery per logical threat."""
        sev = getattr(event, "severity", RiskLevel.SAFE)
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        cat = getattr(event, "threat_category", ThreatCategory.SAFE)
        cat_str = cat.value if hasattr(cat, "value") else str(cat)
        src = getattr(event, "source", "unknown")
        evt_id = str(getattr(event, "event_id", "") or "")
        
        indicator = ""
        ti = getattr(event, "threat_intelligence", None)
        if isinstance(ti, dict):
            indicator = ti.get("indicator") or ""
        if not indicator:
            meta = getattr(event, "metadata_details", None)
            if isinstance(meta, dict):
                indicator = meta.get("ioc") or meta.get("filename") or ""
        if not indicator:
            expl = getattr(event, "explanation", None)
            if expl and hasattr(expl, "summary"):
                indicator = expl.summary[:60]

        target_token = indicator or evt_id
        seed = f"{recipient.lower()}:{sev_str.upper()}:{cat_str.upper()}:{src}:{target_token}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    async def dispatch_threat_event(
        self,
        event: ThreatEvent,
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
        background: bool = True,
    ) -> Dict[str, Any]:
        """
        Normalized entrypoint for all threat pipelines.
        Validates severity, persists durable outbox task, and schedules transmission.
        """
        sev = getattr(event, "severity", None)
        sev_str = (sev.value if hasattr(sev, "value") else str(sev)).upper()

        # Strict severity filter
        if not self.is_eligible_severity(sev_str):
            logger.debug(
                f"[DISPATCHER GATE] Threat event {getattr(event, 'event_id', '')} severity '{sev_str}' "
                "is below HIGH/CRITICAL notification threshold. Skipping email dispatch."
            )
            return {
                "status": "skipped",
                "reason": f"SEVERITY_BELOW_THRESHOLD ({sev_str})",
                "severity": sev_str,
                "gated": True,
                "eligible": False,
                "event_id": getattr(event, "event_id", None),
            }

        resolved_uid, resolved_uname, recipient = self.resolve_recipient(
            event, explicit_email=user_email, explicit_user_id=user_id
        )

        if not recipient:
            logger.info(
                f"[DISPATCHER NOTICE] No valid recipient resolved for HIGH/CRITICAL threat event "
                f"{getattr(event, 'event_id', '')}. Delivery skipped."
            )
            return {
                "status": "skipped",
                "reason": "NO_RESOLVED_RECIPIENT",
                "eligible": True,
                "event_id": getattr(event, "event_id", None),
            }

        fingerprint = self.compute_event_fingerprint(event, recipient)
        cooldown_sec = float(get_settings().email_alerts.cooldown_seconds)
        now_ts = time.time()

        if now_ts - self._recent_dispatches.get(fingerprint, 0.0) < cooldown_sec:
            logger.info(f"[DISPATCHER DEDUP] Notification already dispatched within cooldown for fingerprint {fingerprint[:12]}")
            return {
                "status": "skipped",
                "reason": "DUPLICATE_ALERT_COOLDOWN_ACTIVE",
                "eligible": True,
                "fingerprint": fingerprint,
            }

        self._recent_dispatches[fingerprint] = now_ts

        # Create persistent outbox record in SQLite
        outbox_id = str(uuid.uuid4())
        record = self._persist_outbox_record(
            outbox_id=outbox_id,
            event=event,
            recipient=recipient,
            user_id=resolved_uid,
            username=resolved_uname,
            fingerprint=fingerprint,
        )

        # Execute dispatch asynchronously
        if background:
            task = asyncio.create_task(
                self._process_outbox_delivery(
                    outbox_id=outbox_id,
                    event=event,
                    recipient=recipient,
                    user_id=resolved_uid,
                    username=resolved_uname,
                )
            )
            self._in_flight_tasks.add(task)
            task.add_done_callback(self._in_flight_tasks.discard)
            return {
                "status": "queued",
                "outbox_id": outbox_id,
                "recipient": recipient,
                "severity": sev_str,
                "eligible": True,
            }
        else:
            return await self._process_outbox_delivery(
                outbox_id=outbox_id,
                event=event,
                recipient=recipient,
                user_id=resolved_uid,
                username=resolved_uname,
            )

    def _persist_outbox_record(
        self,
        outbox_id: str,
        event: ThreatEvent,
        recipient: str,
        user_id: Optional[int],
        username: Optional[str],
        fingerprint: str,
    ) -> Dict[str, Any]:
        """Persist alert as QUEUED in database before attempting transmission."""
        session = _get_db_session()
        record_dict = {
            "alert_id": outbox_id,
            "timestamp": _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "user_id": user_id,
            "username": username,
            "recipient": recipient,
            "subject": f"[CyberGuard Security Alert] {getattr(event, 'severity', RiskLevel.HIGH).value.upper()} - {getattr(event, 'source', 'Threat Subsystem')}",
            "alert_level": getattr(event, "severity", RiskLevel.HIGH).value.upper(),
            "risk_score": 1.0 if getattr(event, "severity", RiskLevel.HIGH) == RiskLevel.CRITICAL else 0.8,
            "target_id": getattr(event, "event_id", outbox_id),
            "threat_type": getattr(event, "threat_category", ThreatCategory.MALICIOUS_URL).value,
            "provider": get_settings().email_alerts.provider,
            "delivery_status": "QUEUED",
            "provider_message_id": None,
            "error_message": None,
            "attempt_count": 0,
            "details": {
                "event_id": getattr(event, "event_id", None),
                "source": getattr(event, "source", None),
                "classification": getattr(event, "classification", None),
                "fingerprint": fingerprint,
            },
        }

        if session:
            try:
                from backend.storage.database import EmailAlertRecordModel
                row = EmailAlertRecordModel(
                    alert_id=outbox_id,
                    timestamp=_utcnow(),
                    user_id=user_id,
                    recipient=recipient,
                    subject=record_dict["subject"],
                    alert_level=record_dict["alert_level"],
                    risk_score=record_dict["risk_score"],
                    target_id=str(record_dict["target_id"]),
                    threat_type=record_dict["threat_type"],
                    provider=record_dict["provider"],
                    delivery_status="QUEUED",
                    provider_message_id=None,
                    error_message=None,
                    attempt_count=0,
                    details_json=json.dumps(record_dict["details"]),
                )
                session.add(row)
                session.commit()
            except Exception as e:
                logger.warning(f"Could not persist outbox task to DB: {e}")
            finally:
                session.close()

        return record_dict

    async def _process_outbox_delivery(
        self,
        outbox_id: str,
        event: ThreatEvent,
        recipient: str,
        user_id: Optional[int],
        username: Optional[str],
        max_retries: int = 3,
    ) -> Dict[str, Any]:
        """
        Executes transmission with retry, exponential backoff, and state transition updates.
        """
        attempt = 0
        last_error = None
        result: Dict[str, Any] = {}

        while attempt < max_retries:
            attempt += 1
            try:
                # Update status to SEND_ATTEMPTED
                self._update_outbox_status(outbox_id, "SEND_ATTEMPTED", attempt_count=attempt)

                # Send via EmailNotifier
                result = await self.email_notifier.notify_threat_event(
                    threat_event=event,
                    user_email=recipient,
                )

                status = result.get("delivery_status") or result.get("status")
                if status in ("PROVIDER_ACCEPTED", "DELIVERED", "sent"):
                    msg_id = result.get("provider_message_id")
                    self._update_outbox_status(
                        outbox_id,
                        "PROVIDER_ACCEPTED",
                        attempt_count=attempt,
                        provider_message_id=msg_id,
                    )
                    return {
                        "status": "delivered",
                        "delivery_status": "PROVIDER_ACCEPTED",
                        "provider_message_id": msg_id,
                        "attempts": attempt,
                        "recipient": recipient,
                    }
                elif result.get("status") == "skipped":
                    # Skipped cleanly by policy or deduplication
                    self._update_outbox_status(
                        outbox_id,
                        "SUPPRESSED",
                        attempt_count=attempt,
                        error_message=result.get("reason"),
                    )
                    return result
                else:
                    last_error = result.get("error") or result.get("error_message") or "Provider dispatch failed"
                    logger.warning(f"Outbox delivery attempt {attempt}/{max_retries} failed: {last_error}")

            except Exception as exc:
                last_error = str(exc)
                logger.warning(f"Outbox exception on attempt {attempt}/{max_retries}: {exc}")

            if attempt < max_retries:
                # Exponential backoff with random jitter
                backoff_sec = (1.5 ** attempt) + random.uniform(0.1, 0.5)
                self._update_outbox_status(
                    outbox_id,
                    "RETRY_SCHEDULED",
                    attempt_count=attempt,
                    error_message=f"Attempt {attempt} failed: {last_error}",
                )
                await asyncio.sleep(backoff_sec)

        # Permanent failure after exhausted retries
        self._update_outbox_status(
            outbox_id,
            "SEND_FAILED",
            attempt_count=attempt,
            error_message=f"All {max_retries} attempts failed: {last_error}",
        )
        return {
            "status": "failed",
            "delivery_status": "SEND_FAILED",
            "error": last_error,
            "attempts": attempt,
            "recipient": recipient,
        }

    def _update_outbox_status(
        self,
        outbox_id: str,
        status: str,
        attempt_count: int = 1,
        provider_message_id: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Update outbox delivery status in database."""
        session = _get_db_session()
        if not session:
            return
        try:
            from backend.storage.database import EmailAlertRecordModel
            row = session.query(EmailAlertRecordModel).filter(EmailAlertRecordModel.alert_id == outbox_id).first()
            if row:
                row.delivery_status = status
                row.attempt_count = attempt_count
                if provider_message_id:
                    row.provider_message_id = provider_message_id
                if error_message:
                    row.error_message = error_message
                session.commit()
        except Exception as e:
            logger.debug(f"Failed to update outbox record status: {e}")
        finally:
            session.close()

    def get_audit_history(self, limit: int = 50, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return normalized alert delivery history for SOC audit."""
        session = _get_db_session()
        results: List[Dict[str, Any]] = []
        if not session:
            return results
        try:
            from backend.storage.database import EmailAlertRecordModel
            query = session.query(EmailAlertRecordModel)
            if user_id is not None:
                query = query.filter(EmailAlertRecordModel.user_id == user_id)
            rows = query.order_by(EmailAlertRecordModel.timestamp.desc()).limit(limit).all()
            for r in rows:
                results.append({
                    "alert_id": r.alert_id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "recipient": r.recipient,
                    "subject": r.subject,
                    "alert_level": r.alert_level,
                    "severity": r.alert_level,
                    "threat_type": r.threat_type,
                    "provider": r.provider,
                    "delivery_status": r.delivery_status,
                    "status": r.delivery_status,
                    "provider_message_id": r.provider_message_id,
                    "error_message": r.error_message,
                    "attempt_count": r.attempt_count,
                })
        except Exception as e:
            logger.debug(f"Error reading delivery history: {e}")
        finally:
            session.close()
        return results


_dispatcher_instance: Optional[ThreatNotificationDispatcher] = None


def get_notification_dispatcher() -> ThreatNotificationDispatcher:
    global _dispatcher_instance
    if _dispatcher_instance is None:
        _dispatcher_instance = ThreatNotificationDispatcher()
    return _dispatcher_instance
