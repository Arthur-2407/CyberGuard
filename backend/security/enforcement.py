"""
enforcement.py — Enterprise Policy & Technical Threat Enforcement Engine for CyberGuard.

Provides:
  - Dynamic Organization Policy configuration & threshold management
  - Volumetric DDoS detection & active rate-limiting protection
  - Automated & manual IP blocking with configurable expiration
  - Suspicious device fingerprint detection & containment
  - Malicious domain & file hash protection registry
  - Failed authentication brute-force shielding
  - Non-destructive, audit-logged containment actions
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class EnforcementEngine:
    """
    Central enforcement and technical threat protection engine.
    Thread-safe, backed by SQLite with in-memory caching for microsecond-latency checks.
    """

    _instance: Optional["EnforcementEngine"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._mem_lock = threading.RLock()

        # In-memory fast-path lookups
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._blocked_devices: Dict[str, Dict[str, Any]] = {}
        self._blocked_domains: Dict[str, Dict[str, Any]] = {}
        self._blocked_hashes: Dict[str, Dict[str, Any]] = {}
        self._allowlist_ips: Set[str] = {"127.0.0.1", "::1", "localhost"}

        # DDoS rate limiting: ip -> deque of request timestamps
        self._request_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._failed_logins: Dict[str, int] = collections.defaultdict(int)

        # Policy cache
        self._cached_policy: Optional[Dict[str, Any]] = None
        self._policy_last_loaded: float = 0.0

        # Load persisted blocks from database
        self._sync_from_db()

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> "EnforcementEngine":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path=db_path)
            return cls._instance

    # ── Database Synchronisation & Helper ─────────────────────────────────────

    def _get_db_session(self):
        try:
            from backend.storage.database import get_session_factory
            factory = get_session_factory(self._db_path) if self._db_path else get_session_factory()
            return factory()
        except Exception as exc:
            logger.debug(f"Could not open database session for enforcement: {exc}")
            return None

    def _sync_from_db(self) -> None:
        """Load currently active blocked entities from SQLite into memory."""
        session = self._get_db_session()
        if not session:
            return

        try:
            from backend.storage.database import BlockedEntityModel
            now = _utcnow()
            active_blocks = session.query(BlockedEntityModel).filter(
                BlockedEntityModel.is_active.is_(True)
            ).all()

            with self._mem_lock:
                for b in active_blocks:
                    # Check expiration
                    if b.expires_at and b.expires_at < now:
                        b.is_active = False
                        continue

                    entry = {
                        "id": b.id,
                        "entity_type": b.entity_type,
                        "entity_value": b.entity_value,
                        "reason": b.reason,
                        "severity": b.severity,
                        "source_incident_id": b.source_incident_id,
                        "blocked_by": b.blocked_by,
                        "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
                        "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                    }
                    val = b.entity_value.strip().lower()
                    if b.entity_type == "IP":
                        self._blocked_ips[val] = entry
                    elif b.entity_type == "DEVICE":
                        self._blocked_devices[val] = entry
                    elif b.entity_type == "DOMAIN":
                        self._blocked_domains[val] = entry
                    elif b.entity_type == "HASH":
                        self._blocked_hashes[val] = entry

            session.commit()
            logger.info(
                f"EnforcementEngine synchronized {len(active_blocks)} active blocks from database."
            )
        except Exception as exc:
            logger.warning(f"Enforcement database sync notice: {exc}")
        finally:
            session.close()

    # ── Policy Management ─────────────────────────────────────────────────────

    def get_policy(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Fetch current enforcement policy from DB or fallback default."""
        now_ts = time.time()
        if not force_refresh and self._cached_policy and (now_ts - self._policy_last_loaded < 10.0):
            return self._cached_policy

        default_policy = {
            "org_name": "CyberGuard Enterprise SOC",
            "security_level": "HIGH",
            "auto_block_critical_threats": True,
            "auto_block_threshold": 0.85,
            "ddos_protection_enabled": True,
            "ddos_rpm_limit": 120,
            "ddos_burst_limit": 30,
            "failed_login_ban_threshold": 5,
            "ban_duration_minutes": 60,
            "email_alerts_enabled": True,
            "alert_email_recipient": "security-ops@cyberguard.local",
            "email_alert_threshold": "CRITICAL",
            "updated_at": _utcnow().isoformat(),
            "updated_by": "SYSTEM_DEFAULT",
        }

        session = self._get_db_session()
        if not session:
            self._cached_policy = default_policy
            return default_policy

        try:
            from backend.storage.database import EnforcementPolicyModel
            policy_row = session.query(EnforcementPolicyModel).order_by(EnforcementPolicyModel.id.desc()).first()
            if not policy_row:
                # Seed default policy row
                policy_row = EnforcementPolicyModel(
                    org_name=default_policy["org_name"],
                    security_level=default_policy["security_level"],
                    auto_block_critical_threats=default_policy["auto_block_critical_threats"],
                    auto_block_threshold=default_policy["auto_block_threshold"],
                    ddos_protection_enabled=default_policy["ddos_protection_enabled"],
                    ddos_rpm_limit=default_policy["ddos_rpm_limit"],
                    ddos_burst_limit=default_policy["ddos_burst_limit"],
                    failed_login_ban_threshold=default_policy["failed_login_ban_threshold"],
                    ban_duration_minutes=default_policy["ban_duration_minutes"],
                    email_alerts_enabled=default_policy["email_alerts_enabled"],
                    alert_email_recipient=default_policy["alert_email_recipient"],
                    email_alert_threshold=default_policy["email_alert_threshold"],
                    updated_by="SYSTEM_BOOTSTRAP",
                )
                session.add(policy_row)
                session.commit()

            policy_dict = {
                "id": policy_row.id,
                "org_name": policy_row.org_name,
                "security_level": policy_row.security_level,
                "auto_block_critical_threats": bool(policy_row.auto_block_critical_threats),
                "auto_block_threshold": float(policy_row.auto_block_threshold or 0.85),
                "ddos_protection_enabled": bool(policy_row.ddos_protection_enabled),
                "ddos_rpm_limit": int(policy_row.ddos_rpm_limit or 120),
                "ddos_burst_limit": int(policy_row.ddos_burst_limit or 30),
                "failed_login_ban_threshold": int(policy_row.failed_login_ban_threshold or 5),
                "ban_duration_minutes": int(policy_row.ban_duration_minutes or 60),
                "email_alerts_enabled": bool(policy_row.email_alerts_enabled),
                "alert_email_recipient": policy_row.alert_email_recipient or "security-ops@cyberguard.local",
                "email_alert_threshold": policy_row.email_alert_threshold or "CRITICAL",
                "updated_at": policy_row.updated_at.isoformat() if policy_row.updated_at else _utcnow().isoformat(),
                "updated_by": policy_row.updated_by or "SYSTEM",
            }
            # Compatibility aliases for UI and API clients
            policy_dict["policy_name"] = policy_dict["org_name"]
            policy_dict["enforcement_action"] = policy_dict["security_level"]
            policy_dict["auto_block_threat_score"] = policy_dict["auto_block_threshold"]
            policy_dict["ddos_rate_limit_per_min"] = policy_dict["ddos_rpm_limit"]
            policy_dict["ddos_burst_threshold"] = policy_dict["ddos_burst_limit"]
            policy_dict["email_notifications_enabled"] = policy_dict["email_alerts_enabled"]
            policy_dict["email_minimum_severity"] = policy_dict["email_alert_threshold"]
            policy_dict["email_notification_recipients"] = [policy_dict["alert_email_recipient"]]

            with self._mem_lock:
                self._cached_policy = policy_dict
                self._policy_last_loaded = now_ts
            return policy_dict
        except Exception as exc:
            logger.warning(f"Error fetching enforcement policy: {exc}")
            self._cached_policy = default_policy
            return default_policy
        finally:
            session.close()

    def update_policy(self, updates: Dict[str, Any], actor_username: str = "Admin") -> Dict[str, Any]:
        """Update policy parameters with validation and administrative audit log."""
        session = self._get_db_session()
        if not session:
            raise RuntimeError("Database unavailable for policy update.")

        # Normalize aliases
        updates = dict(updates)
        if "policy_name" in updates and "org_name" not in updates:
            updates["org_name"] = updates["policy_name"]
        if "enforcement_action" in updates and "security_level" not in updates:
            updates["security_level"] = updates["enforcement_action"]
        if "auto_block_threat_score" in updates and "auto_block_threshold" not in updates:
            updates["auto_block_threshold"] = updates["auto_block_threat_score"]
        if "ddos_rate_limit_per_min" in updates and "ddos_rpm_limit" not in updates:
            updates["ddos_rpm_limit"] = updates["ddos_rate_limit_per_min"]
        if "ddos_burst_threshold" in updates and "ddos_burst_limit" not in updates:
            updates["ddos_burst_limit"] = updates["ddos_burst_threshold"]
        if "email_notifications_enabled" in updates and "email_alerts_enabled" not in updates:
            updates["email_alerts_enabled"] = updates["email_notifications_enabled"]
        if "email_minimum_severity" in updates and "email_alert_threshold" not in updates:
            updates["email_alert_threshold"] = updates["email_minimum_severity"]
        if "email_notification_recipients" in updates and "alert_email_recipient" not in updates:
            recs = updates["email_notification_recipients"]
            updates["alert_email_recipient"] = ", ".join(recs) if isinstance(recs, list) else str(recs)

        try:
            from backend.storage.database import EnforcementPolicyModel, AdminAuditLogModel
            policy_row = session.query(EnforcementPolicyModel).order_by(EnforcementPolicyModel.id.desc()).first()
            if not policy_row:
                policy_row = EnforcementPolicyModel()
                session.add(policy_row)

            # Apply permitted updates
            allowed_fields = [
                "org_name", "security_level", "auto_block_critical_threats",
                "auto_block_threshold", "ddos_protection_enabled", "ddos_rpm_limit",
                "ddos_burst_limit", "failed_login_ban_threshold", "ban_duration_minutes",
                "email_alerts_enabled", "alert_email_recipient", "email_alert_threshold"
            ]
            changed = {}
            for k in allowed_fields:
                if k in updates and updates[k] is not None:
                    old_v = getattr(policy_row, k, None)
                    setattr(policy_row, k, updates[k])
                    changed[k] = {"before": old_v, "after": updates[k]}

            policy_row.updated_at = _utcnow()
            policy_row.updated_by = actor_username

            # Audit log
            audit = AdminAuditLogModel(
                actor_username=actor_username,
                actor_role="ADMIN",
                action="POLICY_UPDATE",
                target_type="ENFORCEMENT_POLICY",
                target_id=str(policy_row.id),
                timestamp=_utcnow(),
                details_json=json.dumps(changed),
            )
            session.add(audit)
            session.commit()

            # Refresh cache
            return self.get_policy(force_refresh=True)
        except Exception as exc:
            session.rollback()
            logger.error(f"Failed to update policy: {exc}")
            raise
        finally:
            session.close()

    # ── Blocking & Containment Operations ────────────────────────────────────

    def block_entity(
        self,
        entity_type: str,
        entity_value: str,
        reason: str,
        severity: str = "CRITICAL",
        duration_minutes: Optional[int] = None,
        source_incident_id: Optional[str] = None,
        blocked_by: str = "SYSTEM_POLICY",
    ) -> Dict[str, Any]:
        """
        Block an IP, Device, Domain, or Hash.
        Persists to SQLite and updates in-memory fast table.
        """
        entity_type = entity_type.upper().strip()
        val_clean = entity_value.strip().lower()

        if entity_type == "IP" and val_clean in self._allowlist_ips:
            return {"status": "SKIPPED", "message": f"IP {val_clean} is on allowlist and cannot be blocked."}

        now = _utcnow()
        expires_at = None
        if duration_minutes and duration_minutes > 0:
            expires_at = now + datetime.timedelta(minutes=duration_minutes)

        session = self._get_db_session()
        block_id = None
        if session:
            try:
                from backend.storage.database import BlockedEntityModel, AdminAuditLogModel
                # Deactivate any previous entry for this exact value
                existing = session.query(BlockedEntityModel).filter(
                    BlockedEntityModel.entity_type == entity_type,
                    BlockedEntityModel.entity_value == val_clean,
                    BlockedEntityModel.is_active.is_(True),
                ).first()
                if existing:
                    existing.reason = reason
                    existing.severity = severity
                    existing.expires_at = expires_at
                    existing.blocked_by = blocked_by
                    block_id = existing.id
                else:
                    new_block = BlockedEntityModel(
                        entity_type=entity_type,
                        entity_value=val_clean,
                        reason=reason,
                        severity=severity,
                        source_incident_id=source_incident_id,
                        blocked_by=blocked_by,
                        blocked_at=now,
                        expires_at=expires_at,
                        is_active=True,
                    )
                    session.add(new_block)
                    session.flush()
                    block_id = new_block.id

                # Audit trail
                audit = AdminAuditLogModel(
                    actor_username=blocked_by,
                    actor_role="SYSTEM" if "SYSTEM" in blocked_by else "ADMIN",
                    action=f"{entity_type}_BLOCK",
                    target_type=entity_type,
                    target_id=val_clean,
                    timestamp=now,
                    details_json=json.dumps({
                        "reason": reason,
                        "severity": severity,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                        "incident_id": source_incident_id,
                    }),
                )
                session.add(audit)
                session.commit()
            except Exception as exc:
                session.rollback()
                logger.error(f"Error persisting block: {exc}")
            finally:
                session.close()

        entry = {
            "id": block_id or int(time.time()),
            "entity_type": entity_type,
            "entity_value": val_clean,
            "reason": reason,
            "severity": severity,
            "source_incident_id": source_incident_id,
            "blocked_by": blocked_by,
            "blocked_at": now.isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "is_active": True,
        }

        with self._mem_lock:
            if entity_type == "IP":
                self._blocked_ips[val_clean] = entry
            elif entity_type == "DEVICE":
                self._blocked_devices[val_clean] = entry
            elif entity_type == "DOMAIN":
                self._blocked_domains[val_clean] = entry
            elif entity_type == "HASH":
                self._blocked_hashes[val_clean] = entry

        logger.warning(
            f"[ENFORCEMENT] Blocked {entity_type} '{val_clean}' by {blocked_by}: {reason} (Expires: {expires_at})"
        )
        return {"status": "BLOCKED", "entry": entry}

    def unblock_entity(
        self,
        entity_type: str,
        entity_value: str,
        unblocked_by: str = "Admin",
    ) -> Dict[str, Any]:
        """Remove block on an IP, Device, Domain, or Hash."""
        entity_type = entity_type.upper().strip()
        val_clean = entity_value.strip().lower()

        session = self._get_db_session()
        if session:
            try:
                from backend.storage.database import BlockedEntityModel, AdminAuditLogModel
                blocks = session.query(BlockedEntityModel).filter(
                    BlockedEntityModel.entity_type == entity_type,
                    BlockedEntityModel.entity_value == val_clean,
                    BlockedEntityModel.is_active.is_(True),
                ).all()
                for b in blocks:
                    b.is_active = False

                audit = AdminAuditLogModel(
                    actor_username=unblocked_by,
                    actor_role="ADMIN",
                    action=f"{entity_type}_UNBLOCK",
                    target_type=entity_type,
                    target_id=val_clean,
                    timestamp=_utcnow(),
                    details_json=json.dumps({"unblocked_by": unblocked_by}),
                )
                session.add(audit)
                session.commit()
            except Exception as exc:
                session.rollback()
                logger.error(f"Error persisting unblock: {exc}")
            finally:
                session.close()

        with self._mem_lock:
            if entity_type == "IP":
                self._blocked_ips.pop(val_clean, None)
            elif entity_type == "DEVICE":
                self._blocked_devices.pop(val_clean, None)
            elif entity_type == "DOMAIN":
                self._blocked_domains.pop(val_clean, None)
            elif entity_type == "HASH":
                self._blocked_hashes.pop(val_clean, None)

        logger.info(f"[ENFORCEMENT] Unblocked {entity_type} '{val_clean}' by {unblocked_by}.")
        return {"status": "UNBLOCKED", "entity_type": entity_type, "entity_value": val_clean}

    # ── Fast Inspection Methods ───────────────────────────────────────────────

    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Check if an IP address is blocked. Returns (is_blocked, reason)."""
        ip_clean = (ip or "").strip().lower()
        if not ip_clean or ip_clean in self._allowlist_ips:
            return False, None

        with self._mem_lock:
            entry = self._blocked_ips.get(ip_clean)
            if not entry:
                return False, None

            # Check expiration
            expires_at = entry.get("expires_at")
            if expires_at:
                try:
                    exp_dt = datetime.datetime.fromisoformat(expires_at)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=datetime.timezone.utc)
                    if exp_dt < _utcnow():
                        # Expired, clean up
                        self._blocked_ips.pop(ip_clean, None)
                        return False, None
                except Exception:
                    pass

            return True, entry.get("reason", "IP blocked by security policy")

    def is_device_blocked(self, device_fingerprint: str) -> Tuple[bool, Optional[str]]:
        """Check if a device fingerprint is blocked. Returns (is_blocked, reason)."""
        dev_clean = (device_fingerprint or "").strip().lower()
        if not dev_clean:
            return False, None

        with self._mem_lock:
            entry = self._blocked_devices.get(dev_clean)
            if not entry:
                return False, None
            return True, entry.get("reason", "Device blocked by security policy")

    def is_domain_blocked(self, domain: str) -> Tuple[bool, Optional[str]]:
        dom_clean = (domain or "").strip().lower()
        with self._mem_lock:
            entry = self._blocked_domains.get(dom_clean)
            if entry:
                return True, entry.get("reason")
        return False, None

    def is_hash_blocked(self, file_hash: str) -> Tuple[bool, Optional[str]]:
        h_clean = (file_hash or "").strip().lower()
        with self._mem_lock:
            entry = self._blocked_hashes.get(h_clean)
            if entry:
                return True, entry.get("reason")
        return False, None

    # ── Volumetric DDoS Detection & Rate Limiting ─────────────────────────────

    def check_and_record_request(self, ip: str) -> Tuple[bool, Optional[str], int]:
        """
        Record an incoming HTTP request timestamp for IP and verify against DDoS policy.
        Returns: (allowed: bool, violation_reason: Optional[str], retry_after: int)
        """
        ip_clean = (ip or "").strip().lower()
        if not ip_clean or ip_clean in self._allowlist_ips:
            return True, None, 0

        # Check if already banned
        blocked, reason = self.is_ip_blocked(ip_clean)
        if blocked:
            return False, f"Access Forbidden: {reason}", 300

        policy = self.get_policy()
        if not policy.get("ddos_protection_enabled", True):
            return True, None, 0

        rpm_limit = policy.get("ddos_rpm_limit", 120)
        burst_limit = policy.get("ddos_burst_limit", 30)
        now_ts = time.time()

        with self._mem_lock:
            history = self._request_history[ip_clean]
            history.append(now_ts)

            # Purge timestamps older than 60 seconds
            while history and (now_ts - history[0] > 60.0):
                history.popleft()

            # 1. Burst check (last 5 seconds)
            burst_window_start = now_ts - 5.0
            burst_count = sum(1 for ts in history if ts >= burst_window_start)
            if burst_count > burst_limit:
                # Automatic temporary ban
                ban_mins = policy.get("ban_duration_minutes", 60)
                self.block_entity(
                    entity_type="IP",
                    entity_value=ip_clean,
                    reason=f"DDoS Mitigation: Exceeded burst rate ({burst_count} req/5s, limit {burst_limit})",
                    severity="CRITICAL",
                    duration_minutes=ban_mins,
                    blocked_by="DDOS_SHIELD",
                )
                return False, f"DDoS Shield Triggered: Excessive request burst ({burst_count}/5s)", 60

            # 2. RPM check (last 60 seconds)
            rpm_count = len(history)
            if rpm_count > rpm_limit:
                return False, f"Rate limit exceeded: {rpm_count} requests/minute (limit {rpm_limit})", 15

        return True, None, 0

    def record_auth_failure(self, ip: str, username: Optional[str] = None) -> bool:
        """
        Track failed login attempts from IP.
        Auto-blocks IP if failed attempts exceed policy threshold.
        Returns True if IP was blocked as a result.
        """
        ip_clean = (ip or "").strip().lower()
        if not ip_clean or ip_clean in self._allowlist_ips:
            return False

        policy = self.get_policy()
        threshold = policy.get("failed_login_ban_threshold", 5)

        with self._mem_lock:
            self._failed_logins[ip_clean] += 1
            fails = self._failed_logins[ip_clean]

            if fails >= threshold:
                ban_mins = policy.get("ban_duration_minutes", 60)
                self.block_entity(
                    entity_type="IP",
                    entity_value=ip_clean,
                    reason=f"Brute-Force Protection: {fails} consecutive failed authentication attempts (User: {username or 'unknown'})",
                    severity="HIGH",
                    duration_minutes=ban_mins,
                    blocked_by="AUTH_SHIELD",
                )
                self._failed_logins.pop(ip_clean, None)
                return True

        return False

    def reset_auth_failures(self, ip: str) -> None:
        ip_clean = (ip or "").strip().lower()
        with self._mem_lock:
            self._failed_logins.pop(ip_clean, None)

    # ── Automated Threat Containment Handler ──────────────────────────────────

    def evaluate_threat_for_auto_block(self, event: Any) -> Optional[Dict[str, Any]]:
        """
        Evaluate a ThreatEvent. If critical or exceeds policy threshold,
        automatically contains relevant IP, domain, or malicious hash.
        """
        policy = self.get_policy()
        if not policy.get("auto_block_critical_threats", True):
            return None

        # Check severity or confidence
        severity = getattr(event, "severity", None)
        sev_val = severity.value if hasattr(severity, "value") else str(severity).upper()
        if sev_val not in ("CRITICAL", "HIGH"):
            return None

        incident_id = getattr(event, "incident_id", None) or getattr(event, "event_id", None)
        source = getattr(event, "source", "Threat Analysis")
        classification = getattr(event, "classification", "THREAT")

        # Check associated indicators from threat intelligence or evidence
        ti = getattr(event, "threat_intelligence", {}) or {}
        indicator = ti.get("indicator")
        indicator_type = ti.get("indicator_type")
        is_local = ti.get("is_local", False)

        if indicator and not is_local:
            if indicator_type == "ip":
                return self.block_entity(
                    entity_type="IP",
                    entity_value=indicator,
                    reason=f"Automated containment: {classification} detected via {source}",
                    severity=sev_val,
                    source_incident_id=incident_id,
                    duration_minutes=policy.get("ban_duration_minutes", 60),
                    blocked_by="AUTO_CONTAINMENT",
                )
            elif indicator_type == "domain":
                return self.block_entity(
                    entity_type="DOMAIN",
                    entity_value=indicator,
                    reason=f"Automated containment: Malicious domain identified via {source}",
                    severity=sev_val,
                    source_incident_id=incident_id,
                    duration_minutes=policy.get("ban_duration_minutes", 60),
                    blocked_by="AUTO_CONTAINMENT",
                )
            elif indicator_type == "hash":
                return self.block_entity(
                    entity_type="HASH",
                    entity_value=indicator,
                    reason=f"Automated containment: Malware payload hash detected via {source}",
                    severity=sev_val,
                    source_incident_id=incident_id,
                    duration_minutes=None,
                    blocked_by="AUTO_CONTAINMENT",
                )

        return None

    # ── Metrics & Listing ─────────────────────────────────────────────────────

    def get_enforcement_status(self) -> Dict[str, Any]:
        """Telemetry status for admin console & SOC dashboard."""
        policy = self.get_policy()
        with self._mem_lock:
            active_ips = len(self._blocked_ips)
            active_devices = len(self._blocked_devices)
            active_domains = len(self._blocked_domains)
            active_hashes = len(self._blocked_hashes)
            total_traffic_tracked = len(self._request_history)

            # Check if any IP exceeded warning levels
            now_ts = time.time()
            high_traffic_ips = sum(
                1 for ip, hist in self._request_history.items()
                if len(hist) > (policy.get("ddos_rpm_limit", 120) // 2)
            )

        return {
            "status": "OPERATIONAL",
            "enforcement_active": True,
            "ddos_shield_active": policy.get("ddos_protection_enabled", True),
            "ddos_posture": "ATTACK_MITIGATING" if high_traffic_ips > 5 else ("ELEVATED" if high_traffic_ips > 0 else "NORMAL"),
            "blocked_counts": {
                "ips": active_ips,
                "devices": active_devices,
                "domains": active_domains,
                "hashes": active_hashes,
                "total": active_ips + active_devices + active_domains + active_hashes,
            },
            "blocked_ips": list(self._blocked_ips.keys()),
            "blocked_devices": list(self._blocked_devices.keys()),
            "blocked_domains": list(self._blocked_domains.keys()),
            "blocked_hashes": list(self._blocked_hashes.keys()),
            "tracked_sources": total_traffic_tracked,
            "security_level": policy.get("security_level", "HIGH"),
            "auto_blocking_enabled": policy.get("auto_block_critical_threats", True),
            "policy": policy,
        }

    def list_blocked_entities(self, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all active blocked entities."""
        with self._mem_lock:
            results = []
            if not entity_type or entity_type.upper() == "IP":
                results.extend(list(self._blocked_ips.values()))
            if not entity_type or entity_type.upper() == "DEVICE":
                results.extend(list(self._blocked_devices.values()))
            if not entity_type or entity_type.upper() == "DOMAIN":
                results.extend(list(self._blocked_domains.values()))
            if not entity_type or entity_type.upper() == "HASH":
                results.extend(list(self._blocked_hashes.values()))

            # Sort latest first
            results.sort(key=lambda x: x.get("blocked_at", ""), reverse=True)
            return results


_engine_instance: Optional[EnforcementEngine] = None

def get_enforcement_engine() -> EnforcementEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = EnforcementEngine.get_instance()
    return _engine_instance
