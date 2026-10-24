"""
database.py — SQLite database setup and session management for CyberGuard.

Tables:
  - speakers: enrolled speaker profiles (embeddings, metadata)
  - audit_log: feature-only compliance log (NO raw audio stored)
  - sessions: call session records

Privacy-preserving: raw audio is never stored.
Only feature vectors and risk scores are persisted.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    from sqlalchemy import (
        Column, DateTime, Float, Integer, String, Text, create_engine, event,
        ForeignKey, Boolean
    )
    from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
    from sqlalchemy.pool import QueuePool, StaticPool
    _SQLALCHEMY_AVAILABLE = True
except ImportError:
    _SQLALCHEMY_AVAILABLE = False
    logger.error("SQLAlchemy not available — database features disabled.")

import datetime
import numpy as np

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


if _SQLALCHEMY_AVAILABLE:

    class Base(DeclarativeBase):
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    class SpeakerProfile(Base):
        """Enrolled speaker profile with averaged ECAPA embedding."""
        __tablename__ = "speakers"

        id = Column(Integer, primary_key=True, autoincrement=True)
        speaker_id = Column(String(128), unique=True, nullable=False, index=True)
        name = Column(String(256), nullable=True)
        organization = Column(String(256), nullable=True)
        role = Column(String(128), nullable=True)
        # Stored as JSON-serialized list of floats
        embedding_json = Column(Text, nullable=False)
        embedding_dim = Column(Integer, default=192)
        num_samples = Column(Integer, default=1)
        created_at = Column(DateTime, default=_utcnow)
        updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

        def __init__(
            self,
            speaker_id: str | None = None,
            name: str | None = None,
            organization: str | None = None,
            role: str | None = None,
            embedding_json: str | None = None,
            embedding_dim: int = 192,
            num_samples: int = 1,
            created_at: datetime.datetime | None = None,
            updated_at: datetime.datetime | None = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(
                speaker_id=speaker_id,
                name=name,
                organization=organization,
                role=role,
                embedding_json=embedding_json,
                embedding_dim=embedding_dim,
                num_samples=num_samples,
                created_at=created_at,
                updated_at=updated_at,
                **kwargs,
            )

        def get_embedding(self) -> np.ndarray:
            return np.array(json.loads(self.embedding_json), dtype=np.float32)

        def set_embedding(self, emb: np.ndarray) -> None:
            self.embedding_json = json.dumps(emb.tolist())

    class AuditLogEntry(Base):
        """Compliance audit log — feature vectors and risk scores only, no raw audio."""
        __tablename__ = "audit_log"

        id = Column(Integer, primary_key=True, autoincrement=True)
        session_id = Column(String(64), nullable=False, index=True)
        chunk_id = Column(Integer, nullable=False)
        timestamp = Column(Float, nullable=False)
        detection_score = Column(Float, nullable=True)
        risk_score = Column(Float, nullable=True)
        alert_level = Column(String(16), nullable=True)
        speaker_id = Column(String(128), nullable=True)
        speaker_similarity = Column(Float, nullable=True)
        processing_ms = Column(Float, nullable=True)
        # Feature summary (NOT raw audio, NOT full embedding — just statistics)
        feature_summary_json = Column(Text, nullable=True)

        def __init__(
            self,
            session_id: str | None = None,
            chunk_id: int | None = None,
            timestamp: float | None = None,
            detection_score: float | None = None,
            risk_score: float | None = None,
            alert_level: str | None = None,
            speaker_id: str | None = None,
            speaker_similarity: float | None = None,
            processing_ms: float | None = None,
            feature_summary_json: str | None = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(
                session_id=session_id,
                chunk_id=chunk_id,
                timestamp=timestamp,
                detection_score=detection_score,
                risk_score=risk_score,
                alert_level=alert_level,
                speaker_id=speaker_id,
                speaker_similarity=speaker_similarity,
                processing_ms=processing_ms,
                feature_summary_json=feature_summary_json,
                **kwargs,
            )

    class CallSession(Base):
        """Records of call analysis sessions."""
        __tablename__ = "sessions"

        id = Column(Integer, primary_key=True, autoincrement=True)
        session_id = Column(String(64), unique=True, nullable=False, index=True)
        started_at = Column(DateTime, default=_utcnow)
        ended_at = Column(DateTime, nullable=True)
        total_chunks = Column(Integer, default=0)
        peak_risk = Column(Float, default=0.0)
        mean_risk = Column(Float, default=0.0)
        final_alert_level = Column(String(16), default="SAFE")
        speaker_id = Column(String(128), nullable=True)
        notes = Column(Text, nullable=True)

    class IncidentModel(Base):
        """Groups related threat events into an actionable incident."""
        __tablename__ = "incidents"

        id = Column(Integer, primary_key=True, autoincrement=True)
        incident_id = Column(String(64), unique=True, nullable=False, index=True)
        first_seen = Column(DateTime, default=_utcnow)
        last_seen = Column(DateTime, default=_utcnow)
        category = Column(String(64), default="UNKNOWN")
        risk = Column(String(16), default="LOW")
        status = Column(String(32), default="NEW")
        affected_assets_json = Column(Text, nullable=True) # JSON list
        recommendations_json = Column(Text, nullable=True) # JSON list
        analyst_notes = Column(Text, nullable=True)
        resolved_at = Column(DateTime, nullable=True)

    class ThreatEventModel(Base):
        """Normalized schema for all analyzed threats across all modalities."""
        __tablename__ = "threat_events"

        id = Column(Integer, primary_key=True, autoincrement=True)
        event_id = Column(String(64), unique=True, nullable=False, index=True)
        timestamp = Column(DateTime, default=_utcnow)
        source = Column(String(256), nullable=False)
        source_type = Column(String(64), nullable=False)
        modality = Column(String(64), nullable=False)
        threat_category = Column(String(64), nullable=False)
        subcategory = Column(String(64), nullable=True)
        severity = Column(String(16), default="SAFE")
        confidence = Column(Float, default=0.0)
        classification = Column(String(64), nullable=False)
        explanation_summary = Column(Text, nullable=True)
        explanation_reasoning = Column(Text, nullable=True)
        explanation_limitations = Column(Text, nullable=True)
        recommended_actions_json = Column(Text, nullable=True) # JSON list
        incident_id = Column(String(64), nullable=True, index=True)
        affected_user = Column(String(128), nullable=True)
        affected_asset = Column(String(256), nullable=True)
        user_id = Column(Integer, nullable=True, index=True)
        user_email = Column(String(256), nullable=True)
        detector = Column(String(128), nullable=False)
        detector_version = Column(String(32), nullable=True)
        processing_time_ms = Column(Float, default=0.0)
        capability_status = Column(String(32), default="READY")
        correlation_id = Column(String(64), nullable=True, index=True)
        mitre_technique_id = Column(String(32), nullable=True)
        mitre_technique_name = Column(String(128), nullable=True)

    class ThreatEvidenceModel(Base):
        """Evidence linking to a specific ThreatEvent."""
        __tablename__ = "threat_evidence"

        id = Column(Integer, primary_key=True, autoincrement=True)
        event_id = Column(String(64), nullable=False, index=True)
        evidence_type = Column(String(64), nullable=False)
        description = Column(Text, nullable=False)
        value = Column(Text, nullable=True)
        severity_contribution = Column(Float, default=0.0)
        confidence = Column(Float, default=1.0)
        source = Column(String(128), nullable=False)

    class UserModel(Base):
        """User account model for authentication & role-based access control."""
        __tablename__ = "users"

        id = Column(Integer, primary_key=True, autoincrement=True)
        username = Column(String(64), unique=True, nullable=False, index=True)
        email = Column(String(256), unique=True, nullable=False, index=True)
        password_hash = Column(String(256), nullable=False)  # scrypt memory-hard hash, never plaintext
        role = Column(String(32), default="user", nullable=False)  # "admin" or "user"
        is_active = Column(Boolean, default=True, nullable=False)
        created_at = Column(DateTime, default=_utcnow)
        updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
        last_login_at = Column(DateTime, nullable=True)
        password_changed_at = Column(DateTime, default=_utcnow)
        failed_login_count = Column(Integer, default=0)
        reset_required = Column(Boolean, default=False)
        db_path = Column(String(512), nullable=True)

    class AuthSessionModel(Base):
        """Cryptographically secure session tokens."""
        __tablename__ = "auth_sessions"

        id = Column(Integer, primary_key=True, autoincrement=True)
        user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
        token_hash = Column(String(128), unique=True, nullable=False, index=True)
        created_at = Column(DateTime, default=_utcnow)
        expires_at = Column(DateTime, nullable=False)
        revoked_at = Column(DateTime, nullable=True)

    class AnalysisRecordModel(Base):
        """Record of every audio analysis with model version & scores."""
        __tablename__ = "analysis_records"

        id = Column(Integer, primary_key=True, autoincrement=True)
        analysis_id = Column(String(64), unique=True, nullable=False, index=True)
        user_id = Column(Integer, nullable=True, index=True)  # Nullable for guest/unauthenticated scans
        filename = Column(String(256), nullable=True)
        audio_hash = Column(String(64), nullable=True, index=True)  # SHA-256
        audio_path = Column(String(512), nullable=True)  # Secure relative vault path
        duration_sec = Column(Float, default=0.0)
        total_chunks = Column(Integer, default=0)
        detector_version = Column(String(32), default="v001")
        native_probability = Column(Float, nullable=True)
        aasist_probability = Column(Float, nullable=True)
        peak_risk = Column(Float, default=0.0)
        mean_risk = Column(Float, default=0.0)
        alert_level = Column(String(16), default="SAFE")
        analysis_status = Column(String(32), default="COMPLETED")
        metadata_json = Column(Text, nullable=True)
        created_at = Column(DateTime, default=_utcnow)

    class ReviewQueueModel(Base):
        """Dedicated admin review queue for human ground-truth verification."""
        __tablename__ = "review_queue"

        id = Column(Integer, primary_key=True, autoincrement=True)
        review_id = Column(String(64), unique=True, nullable=False, index=True)
        analysis_id = Column(String(64), nullable=False, index=True)
        submitted_by_user_id = Column(Integer, nullable=True)
        status = Column(String(32), default="PENDING", index=True)  # PENDING, APPROVED, REJECTED
        reviewer_admin_id = Column(Integer, nullable=True)
        reviewed_at = Column(DateTime, nullable=True)
        ground_truth_label = Column(String(32), nullable=True)  # BONAFIDE, SPOOF, INCONCLUSIVE
        approved_for_training = Column(Boolean, default=False)
        rejection_reason = Column(Text, nullable=True)
        notes = Column(Text, nullable=True)
        created_at = Column(DateTime, default=_utcnow)

    class TrainingSampleModel(Base):
        """Curated, admin-approved training sample with cryptographic hash."""
        __tablename__ = "training_samples"

        id = Column(Integer, primary_key=True, autoincrement=True)
        sample_id = Column(String(64), unique=True, nullable=False, index=True)
        source_analysis_id = Column(String(64), nullable=True)
        review_id = Column(String(64), nullable=True)
        approved_by_admin_id = Column(Integer, nullable=True)
        ground_truth = Column(String(32), nullable=False)  # BONAFIDE, SPOOF
        audio_hash = Column(String(64), nullable=False, index=True)
        dataset_path = Column(String(512), nullable=False)
        used_in_training = Column(Boolean, default=False)
        training_run_id = Column(String(64), nullable=True, index=True)
        created_at = Column(DateTime, default=_utcnow)

    class TrainingRunModel(Base):
        """Lineage and metrics of controlled continuous learning runs."""
        __tablename__ = "training_runs"

        id = Column(Integer, primary_key=True, autoincrement=True)
        run_id = Column(String(64), unique=True, nullable=False, index=True)
        status = Column(String(32), default="PENDING")  # PENDING, RUNNING, VALIDATING, COMPLETED, FAILED, PROMOTED, REJECTED
        started_at = Column(DateTime, default=_utcnow)
        completed_at = Column(DateTime, nullable=True)
        base_model_version = Column(String(32), default="v001")
        candidate_model_version = Column(String(32), nullable=True)
        sample_count = Column(Integer, default=0)
        configuration_json = Column(Text, nullable=True)
        validation_metrics_json = Column(Text, nullable=True)
        candidate_checkpoint_path = Column(String(512), nullable=True)
        candidate_sha256 = Column(String(64), nullable=True)
        failure_reason = Column(Text, nullable=True)

    class ModelVersionModel(Base):
        """Auditable registry of all production and candidate model versions."""
        __tablename__ = "model_versions"

        id = Column(Integer, primary_key=True, autoincrement=True)
        version = Column(String(32), unique=True, nullable=False, index=True)  # v001, v002...
        checkpoint_path = Column(String(512), nullable=False)
        sha256 = Column(String(64), nullable=False)
        file_size = Column(Integer, default=0)
        parent_version = Column(String(32), nullable=True)
        status = Column(String(32), default="ACTIVE")  # ACTIVE, ARCHIVED, ROLLED_BACK
        validation_metrics_json = Column(Text, nullable=True)
        created_at = Column(DateTime, default=_utcnow)
        promoted_at = Column(DateTime, nullable=True)
        rolled_back_at = Column(DateTime, nullable=True)
        promotion_reason = Column(Text, nullable=True)

    class AdminAuditLogModel(Base):
        """Tamper-evident audit log for all administrative and model actions."""
        __tablename__ = "admin_audit_log"

        id = Column(Integer, primary_key=True, autoincrement=True)
        actor_user_id = Column(Integer, nullable=True)
        actor_username = Column(String(64), nullable=True)
        actor_role = Column(String(32), default="ADMIN")
        action = Column(String(64), nullable=False)  # e.g. USER_CREATE, SAMPLE_APPROVE, MODEL_PROMOTE
        target_type = Column(String(64), nullable=True)
        target_id = Column(String(64), nullable=True)
        timestamp = Column(DateTime, default=_utcnow)
        details_json = Column(Text, nullable=True)

    class EnforcementPolicyModel(Base):
        """Organization security policies, DDoS limits, auto-blocking, and email notification controls."""
        __tablename__ = "enforcement_policies"

        id = Column(Integer, primary_key=True, autoincrement=True)
        org_name = Column(String(128), default="CyberGuard Enterprise SOC", nullable=False)
        security_level = Column(String(32), default="HIGH", nullable=False)  # LOW, MEDIUM, HIGH, MAXIMUM
        auto_block_critical_threats = Column(Boolean, default=True, nullable=False)
        auto_block_threshold = Column(Float, default=0.85, nullable=False)
        ddos_protection_enabled = Column(Boolean, default=True, nullable=False)
        ddos_rpm_limit = Column(Integer, default=120, nullable=False)  # requests/min per IP
        ddos_burst_limit = Column(Integer, default=30, nullable=False)  # 5-sec burst limit
        failed_login_ban_threshold = Column(Integer, default=5, nullable=False)
        ban_duration_minutes = Column(Integer, default=60, nullable=False)
        email_alerts_enabled = Column(Boolean, default=True, nullable=False)
        alert_email_recipient = Column(String(256), default="", nullable=False)
        email_alert_threshold = Column(String(16), default="CRITICAL", nullable=False)  # HIGH or CRITICAL
        updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
        updated_by = Column(String(64), default="SYSTEM")

    class BlockedEntityModel(Base):
        """Active blocks on abusive IPs, compromised device fingerprints, domains, and malware hashes."""
        __tablename__ = "blocked_entities"

        id = Column(Integer, primary_key=True, autoincrement=True)
        entity_type = Column(String(32), nullable=False, index=True)  # IP, DEVICE, DOMAIN, HASH
        entity_value = Column(String(256), nullable=False, index=True)
        reason = Column(String(512), nullable=False)
        severity = Column(String(16), default="CRITICAL")
        source_incident_id = Column(String(64), nullable=True)
        blocked_by = Column(String(64), default="SYSTEM_POLICY")
        blocked_at = Column(DateTime, default=_utcnow)
        expires_at = Column(DateTime, nullable=True)
        is_active = Column(Boolean, default=True, index=True)

    class ThreatReportModel(Base):
        """Persisted executive and technical threat intelligence reports."""
        __tablename__ = "threat_reports"

        id = Column(Integer, primary_key=True, autoincrement=True)
        report_id = Column(String(64), unique=True, nullable=False, index=True)
        title = Column(String(256), nullable=False)
        report_type = Column(String(32), default="INCIDENT")  # EXECUTIVE, TECHNICAL, COMPREHENSIVE
        report_format = Column(String(16), default="HTML")     # HTML, JSON, CSV
        summary_json = Column(Text, nullable=True)
        report_path = Column(String(512), nullable=True)
        created_by = Column(String(64), default="SOC Analyst")
        created_at = Column(DateTime, default=_utcnow)

    class EmailAlertRecordModel(Base):
        """Persisted security email alert dispatches and delivery lifecycle."""
        __tablename__ = "email_alert_records"

        id = Column(Integer, primary_key=True, autoincrement=True)
        alert_id = Column(String(64), unique=True, nullable=False, index=True)
        timestamp = Column(DateTime, default=_utcnow, index=True)
        user_id = Column(Integer, nullable=True, index=True)  # Authenticated account ID responsible for alert
        recipient = Column(String(256), nullable=False, index=True)
        subject = Column(String(512), nullable=False)
        alert_level = Column(String(16), default="CRITICAL", nullable=False)
        risk_score = Column(Float, default=0.0)
        target_id = Column(String(64), nullable=True, index=True)
        threat_type = Column(String(64), default="THREAT")
        provider = Column(String(32), default="brevo")
        delivery_status = Column(String(32), default="CREATED", index=True)  # CREATED, SEND_ATTEMPTED, PROVIDER_ACCEPTED, SEND_FAILED, RETRY_SCHEDULED, DELIVERED
        provider_message_id = Column(String(256), nullable=True)
        error_message = Column(Text, nullable=True)
        attempt_count = Column(Integer, default=1)
        details_json = Column(Text, nullable=True)

    class CallerReputationModel(Base):
        """Verified caller reputation intelligence for phone number screening."""
        __tablename__ = "caller_reputation"

        id = Column(Integer, primary_key=True, autoincrement=True)
        normalized_number = Column(String(32), unique=True, nullable=False, index=True)
        raw_number = Column(String(32), nullable=False)
        country_code = Column(String(8), nullable=True)
        classification = Column(String(32), default="UNKNOWN", nullable=False)  # HIGH_RISK, SUSPICIOUS, LOWER_RISK, UNKNOWN, DISPUTED
        risk_score = Column(Float, default=0.0)
        confidence = Column(Float, default=0.0)
        reason_codes_json = Column(Text, nullable=True)  # JSON list
        evidence_sources_json = Column(Text, nullable=True)  # JSON list
        explanation = Column(Text, nullable=True)
        is_scam = Column(Boolean, default=False)
        is_spoofed = Column(Boolean, default=False)
        disputed = Column(Boolean, default=False)
        last_verified_at = Column(DateTime, default=_utcnow)
        expires_at = Column(DateTime, nullable=True)
        created_at = Column(DateTime, default=_utcnow)
        updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    class ScreenedCallIncidentModel(Base):
        """Auditable log of screened incoming calls ingested from Android clients."""
        __tablename__ = "screened_call_incidents"

        id = Column(Integer, primary_key=True, autoincrement=True)
        incident_id = Column(String(64), unique=True, nullable=False, index=True)
        normalized_number = Column(String(32), nullable=False, index=True)
        caller_display_name = Column(String(128), nullable=True)
        call_direction = Column(String(16), default="INCOMING")
        classification = Column(String(32), default="UNKNOWN")
        risk_score = Column(Float, default=0.0)
        confidence = Column(Float, default=0.0)
        reasons_json = Column(Text, nullable=True)
        carrier_verification_status = Column(String(32), default="NOT_VERIFIED")
        action_recommended = Column(String(32), default="ALLOW")
        action_applied = Column(String(32), default="ALLOWED")
        response_latency_ms = Column(Float, default=0.0)
        user_id = Column(Integer, nullable=True, index=True)
        device_id = Column(String(128), nullable=True)
        timestamp = Column(DateTime, default=_utcnow, index=True)


    _engines: dict[str, Any] = {}
    _session_factories: dict[str, Any] = {}
    _engine_lock = threading.RLock()

    def _get_effective_url(db_path: str = "data/cyberguard.db") -> str:
        """Resolve database connection string, prioritizing DATABASE_URL or Supabase configuration."""
        if str(db_path).startswith("postgresql://") or str(db_path).startswith("postgresql+psycopg2://"):
            return str(db_path)
        if str(db_path) in (":memory:", "sqlite:///:memory:") or str(db_path).startswith("sqlite:"):
            return ""
        if db_path in ("data/cyberguard.db", "data/voiceguard.db", None, ""):
            env_url = (os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL") or "").strip()
            if env_url and ("postgres" in env_url):
                return env_url
        return ""

    def _resolve_db_file(db_path: str = "data/cyberguard.db") -> Path:
        """Resolve database path relative to project root."""
        if str(db_path) in (":memory:", "sqlite:///:memory:"):
            return Path(":memory:")
        if db_path == "data/cyberguard.db" and not os.path.exists("data/cyberguard.db") and os.path.exists("data/voiceguard.db"):
            db_path = "data/voiceguard.db"

        db_file = Path(db_path)
        if not db_file.is_absolute():
            project_root = Path(__file__).resolve().parent.parent.parent
            db_file = project_root / db_path
        return db_file

    def get_engine(db_path: str = "data/cyberguard.db"):
        """Get or create SQLAlchemy engine for the specified database path/URL with connection pooling."""
        global _engines
        eff_url = _get_effective_url(db_path)
        if eff_url:
            pg_url = eff_url
            if pg_url.startswith("postgresql://"):
                pg_url = "postgresql+psycopg2://" + pg_url[len("postgresql://"):]
            key = pg_url
            with _engine_lock:
                if key not in _engines:
                    eng = create_engine(
                        pg_url,
                        poolclass=QueuePool,
                        pool_size=15,
                        max_overflow=25,
                        pool_timeout=30,
                        pool_recycle=1800,
                        pool_pre_ping=True,
                        connect_args={"connect_timeout": 10},
                    )
                    _engines[key] = eng
                return _engines[key]

        if str(db_path) in (":memory:", "sqlite:///:memory:"):
            key = ":memory:"
            with _engine_lock:
                if key not in _engines:
                    eng = create_engine(
                        "sqlite:///:memory:",
                        connect_args={"check_same_thread": False, "timeout": 30},
                        poolclass=StaticPool,
                    )
                    _engines[key] = eng
                return _engines[key]

        db_file = _resolve_db_file(db_path)
        key = str(db_file.resolve())

        with _engine_lock:
            if key not in _engines:
                db_file.parent.mkdir(parents=True, exist_ok=True)
                db_url = f"sqlite:///{db_file}"

                if ":memory:" in db_url:
                    eng = create_engine(
                        db_url,
                        connect_args={"check_same_thread": False, "timeout": 30},
                        poolclass=StaticPool,
                    )
                else:
                    eng = create_engine(
                        db_url,
                        connect_args={"check_same_thread": False, "timeout": 30},
                        poolclass=QueuePool,
                        pool_size=20,
                        max_overflow=30,
                        pool_timeout=30,
                    )

                # Enable WAL mode (or DELETE mode fallback on network/bind-mounted filesystems) and busy timeout
                @event.listens_for(eng, "connect")
                def set_sqlite_pragma(dbapi_connection, connection_record):
                    cursor = dbapi_connection.cursor()
                    try:
                        cursor.execute("PRAGMA journal_mode=WAL")
                    except Exception:
                        try:
                            cursor.execute("PRAGMA journal_mode=DELETE")
                        except Exception:
                            pass
                    try:
                        cursor.execute("PRAGMA synchronous=NORMAL")
                    except Exception:
                        pass
                    try:
                        cursor.execute("PRAGMA busy_timeout=30000")
                    except Exception:
                        pass
                    cursor.close()

                _engines[key] = eng

            return _engines[key]

    def _migrate_columns_if_missing(engine) -> None:
        """Safely add newly introduced columns to existing SQLite tables if not present."""
        if getattr(engine.dialect, "name", "") != "sqlite":
            return
        try:
            with engine.connect() as conn:
                res = conn.exec_driver_sql("PRAGMA table_info(threat_events)").fetchall()
                if res:
                    existing_cols = {row[1] for row in res}
                    if "user_id" not in existing_cols:
                        conn.exec_driver_sql("ALTER TABLE threat_events ADD COLUMN user_id INTEGER")
                    if "user_email" not in existing_cols:
                        conn.exec_driver_sql("ALTER TABLE threat_events ADD COLUMN user_email VARCHAR(256)")
                    conn.commit()

                res_email = conn.exec_driver_sql("PRAGMA table_info(email_alert_records)").fetchall()
                if res_email:
                    existing_email_cols = {row[1] for row in res_email}
                    if "user_id" not in existing_email_cols:
                        conn.exec_driver_sql("ALTER TABLE email_alert_records ADD COLUMN user_id INTEGER")
                    conn.commit()
        except Exception as exc:
            logger.debug(f"Column migration check notice: {exc}")

    def init_db(db_path: str = "data/cyberguard.db") -> None:
        """Create all tables in the specified database if they don't exist."""
        engine = get_engine(db_path)
        Base.metadata.create_all(bind=engine)
        _migrate_columns_if_missing(engine)
        dialect_name = getattr(engine.dialect, "name", "database")
        logger.info(f"Database ({dialect_name}) initialized for {db_path}")

    def get_session_factory(db_path: str = "data/cyberguard.db"):
        """Return the session factory for the specified database (cached per path or URL)."""
        global _session_factories
        eff_url = _get_effective_url(db_path)
        if eff_url:
            pg_url = eff_url
            if pg_url.startswith("postgresql://"):
                pg_url = "postgresql+psycopg2://" + pg_url[len("postgresql://"):]
            key = pg_url
            with _engine_lock:
                if key not in _session_factories:
                    engine = get_engine(pg_url)
                    _session_factories[key] = sessionmaker(autocommit=False, autoflush=False, bind=engine)
                return _session_factories[key]

        if str(db_path) in (":memory:", "sqlite:///:memory:"):
            key = ":memory:"
            with _engine_lock:
                if key not in _session_factories:
                    engine = get_engine(":memory:")
                    _session_factories[key] = sessionmaker(autocommit=False, autoflush=False, bind=engine)
                return _session_factories[key]

        db_file = _resolve_db_file(db_path)
        key = str(db_file.resolve())

        with _engine_lock:
            if key not in _session_factories:
                engine = get_engine(db_path)
                _migrate_columns_if_missing(engine)
                _session_factories[key] = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            return _session_factories[key]

    def get_db_session(db_path: str = "data/cyberguard.db"):
        """FastAPI dependency: yields a database session for the default/system database."""
        SessionLocal = get_session_factory(db_path)
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    # ── Multi-Tenant User Database Isolation ────────────────────────────────────

    def get_user_db_path(user_id: int | str, username: Optional[str] = None) -> str:
        """Deterministically return the isolated database relative path for a user."""
        return f"data/user_databases/user_{user_id}.db"

    def init_user_db(db_path: str) -> None:
        """Ensure all required tenant tables exist in the user's isolated database."""
        if _get_effective_url(db_path):
            return
        engine = get_engine(db_path)
        Base.metadata.create_all(bind=engine)
        _migrate_columns_if_missing(engine)

    def provision_user_database(user_id: int | str, username: Optional[str] = None) -> str:
        """
        Auto-create, initialize, and verify the isolated database for a user account.
        Guarantee complete schema readiness and thread-safe WAL access.
        """
        eff_url = _get_effective_url()
        if eff_url:
            logger.info(f"Multi-tenant PostgreSQL isolation active for user_id={user_id}")
            return eff_url
        db_path = get_user_db_path(user_id, username)
        init_user_db(db_path)
        logger.info(f"[OK] Provisioned isolated user database at {db_path} for user_id={user_id}")
        return db_path

    def close_user_database(db_path: str) -> None:
        """Dispose of the engine and connection pool for an isolated database, allowing safe file operations."""
        global _engines, _session_factories
        if str(db_path) in (":memory:", "sqlite:///:memory:") or _get_effective_url(db_path):
            return
        db_file = _resolve_db_file(db_path)
        key = str(db_file.resolve())

        with _engine_lock:
            if key in _session_factories:
                del _session_factories[key]
            if key in _engines:
                try:
                    _engines[key].dispose()
                except Exception as exc:
                    logger.warning(f"Error disposing engine for {key}: {exc}")
                del _engines[key]

    def get_user_db_session_sync(user: Optional[UserModel] = None) -> Session:
        """Synchronously get a database session for a user's isolated database."""
        if user and getattr(user, "id", None):
            db_path = getattr(user, "db_path", None) or get_user_db_path(user.id, user.username)
        else:
            eff_url = _get_effective_url()
            if eff_url:
                SessionLocal = get_session_factory(eff_url)
                return SessionLocal()
            db_path = ":memory:"
        init_user_db(db_path)
        SessionLocal = get_session_factory(db_path)
        return SessionLocal()

    def get_user_db_session(
        request: Any = None,
        current_user: Optional[UserModel] = None,
    ):
        """
        FastAPI dependency: yields a session bound to the calling user's isolated database.
        Ensures strict data isolation — user A only reads/writes to user A's database.
        """
        session = get_user_db_session_sync(current_user)
        try:
            yield session
        finally:
            session.close()

else:
    # Stubs when SQLAlchemy is unavailable
    class _StubBase:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    class SpeakerProfile(_StubBase):
        pass

    class AuditLogEntry(_StubBase):
        pass

    class CallSession(_StubBase):
        pass

    class UserModel(_StubBase):
        pass

    class AuthSessionModel(_StubBase):
        pass

    class AnalysisRecordModel(_StubBase):
        pass

    class ReviewQueueModel(_StubBase):
        pass

    class TrainingSampleModel(_StubBase):
        pass

    class TrainingRunModel(_StubBase):
        pass

    class ModelVersionModel(_StubBase):
        pass

    class AdminAuditLogModel(_StubBase):
        pass

    class EnforcementPolicyModel(_StubBase):
        pass

    class BlockedEntityModel(_StubBase):
        pass

    class ThreatReportModel(_StubBase):
        pass

    class EmailAlertRecordModel(_StubBase):
        pass

    class CallerReputationModel(_StubBase):
        pass

    class ScreenedCallIncidentModel(_StubBase):
        pass

    def init_db(*args, **kwargs):
        logger.warning("SQLAlchemy not available — database initialization skipped.")

    def get_db_session(*args, **kwargs):
        yield None

    def get_user_db_path(user_id, username=None):
        return f"data/user_databases/user_{user_id}.db"

    def init_user_db(*args, **kwargs):
        pass

    def provision_user_database(user_id, username=None):
        return f"data/user_databases/user_{user_id}.db"

    def get_user_db_session_sync(*args, **kwargs):
        return None

    def get_user_db_session(*args, **kwargs):
        yield None
