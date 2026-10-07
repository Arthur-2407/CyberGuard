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
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    from sqlalchemy import (
        Column, DateTime, Float, Integer, String, Text, create_engine, event,
        ForeignKey, Boolean
    )
    from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
    from sqlalchemy.pool import StaticPool
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
        alert_email_recipient = Column(String(256), default="security-ops@cyberguard.local", nullable=False)
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

    _engine = None
    _SessionLocal = None

    def get_engine(db_path: str = "data/cyberguard.db"):
        """Get or create SQLAlchemy engine."""
        global _engine
        if _engine is None:
            # Non-destructive fallback if cyberguard.db is requested but only voiceguard.db exists
            if db_path == "data/cyberguard.db" and not os.path.exists("data/cyberguard.db") and os.path.exists("data/voiceguard.db"):
                db_path = "data/voiceguard.db"

            db_file = Path(db_path)
            if not db_file.is_absolute():
                project_root = Path(__file__).resolve().parent.parent.parent
                db_file = project_root / db_path

            db_file.parent.mkdir(parents=True, exist_ok=True)
            db_url = f"sqlite:///{db_file}"

            _engine = create_engine(
                db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
            )

            # Enable WAL mode for better concurrent read performance
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

        return _engine

    def init_db(db_path: str = "data/cyberguard.db") -> None:
        """Create all tables if they don't exist."""
        engine = get_engine(db_path)
        Base.metadata.create_all(bind=engine)
        logger.info(f"Database initialized at {db_path}")

    def get_session_factory(db_path: str = "data/cyberguard.db"):
        """Return the session factory (create once, reuse)."""
        global _SessionLocal
        if _SessionLocal is None:
            engine = get_engine(db_path)
            _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return _SessionLocal

    def get_db_session(db_path: str = "data/cyberguard.db"):
        """FastAPI dependency: yields a database session."""
        SessionLocal = get_session_factory(db_path)
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

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

    def init_db(*args, **kwargs):
        logger.warning("SQLAlchemy not available — database initialization skipped.")

    def get_db_session(*args, **kwargs):
        yield None
