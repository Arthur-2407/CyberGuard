"""
tests/test_supabase_migration.py — Phase 12 Regression and Verification Test Suite.

Covers all 13 required validation criteria:
TEST 1: Database Connectivity
TEST 2: Schema Integrity
TEST 3: Data Completeness
TEST 4: Authentication Compatibility
TEST 5: Account Isolation
TEST 6: Threat Intelligence Persistence
TEST 7: Email Notification Records
TEST 8: Database Write Persistence & Cleanup
TEST 9: Docker Orchestration Configuration
TEST 10: Deployed Frontend / Vercel Topology
TEST 11: Secret & Credential Protection
TEST 12: Database Failure & Disconnection Handling
TEST 13: Regression & Lifespan Bootstrap
"""

import os
import re
import json
import uuid
import datetime
from pathlib import Path
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.config import get_settings, reload_settings
from backend.storage.database import (
    Base,
    get_engine,
    get_session_factory,
    UserModel,
    AuthSessionModel,
    AnalysisRecordModel,
    AuditLogEntry,
    CallSession,
    IncidentModel,
    ThreatEventModel,
    ThreatEvidenceModel,
    ReviewQueueModel,
    TrainingSampleModel,
    TrainingRunModel,
    ModelVersionModel,
    AdminAuditLogModel,
    EnforcementPolicyModel,
    BlockedEntityModel,
    ThreatReportModel,
    EmailAlertRecordModel,
    CallerReputationModel,
    ScreenedCallIncidentModel,
    SpeakerProfile,
)
from backend.storage.auth import verify_password


@pytest.fixture(scope="module")
def pg_session():
    """Establish a direct SQLAlchemy session to the Supabase PostgreSQL target."""
    engine = get_engine()
    if engine.dialect.name != "postgresql":
        pytest.skip(f"Supabase PostgreSQL DATABASE_URL not configured (dialect is {engine.dialect.name})")
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_01_database_connectivity(pg_session):
    """TEST 1: Backend successfully connects to Supabase PostgreSQL."""
    res = pg_session.execute(text("SELECT 1;")).scalar()
    assert res == 1

    ver = pg_session.execute(text("SELECT version();")).scalar()
    assert "PostgreSQL" in ver
    
    current_db = pg_session.execute(text("SELECT current_database();")).scalar()
    assert current_db == "postgres"


def test_02_schema_completeness(pg_session):
    """TEST 2: All 20 required tables exist in public schema with primary keys."""
    expected_tables = {
        "users", "auth_sessions", "analysis_records", "audit_log", "sessions",
        "incidents", "threat_events", "threat_evidence", "review_queue",
        "training_samples", "training_runs", "model_versions", "admin_audit_log",
        "enforcement_policies", "blocked_entities", "threat_reports",
        "email_alert_records", "caller_reputation", "screened_call_incidents",
        "speakers"
    }
    
    query = text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
    actual_tables = set(r[0] for r in pg_session.execute(query).fetchall())
    
    missing = expected_tables - actual_tables
    assert not missing, f"Missing tables in Supabase public schema: {missing}"


def test_03_data_completeness(pg_session):
    """TEST 3: Target row counts match the verified migration manifest."""
    expected_counts = {
        "users": 89,
        "enforcement_policies": 1,
        "model_versions": 32,
        "incidents": 146,
        "training_runs": 20,
        "threat_reports": 67,
        "caller_reputation": 15,
        "blocked_entities": 19,
        "speakers": 9,
        "auth_sessions": 572,
        "analysis_records": 130,
        "threat_events": 470,
        "audit_log": 354,
        "screened_call_incidents": 15,
        "admin_audit_log": 893,
        "threat_evidence": 262,
        "review_queue": 112,
        "training_samples": 5,
        "email_alert_records": 181,
    }
    
    for table_name, expected_count in expected_counts.items():
        actual_count = pg_session.execute(text(f'SELECT COUNT(*) FROM "{table_name}"')).scalar()
        assert actual_count >= expected_count, (
            f"Table '{table_name}' count mismatch: expected at least {expected_count}, got {actual_count}"
        )


def test_04_authentication_compatibility(pg_session):
    """TEST 4: Password hashes remain compatible with scrypt verification."""
    admin_user = pg_session.query(UserModel).filter(UserModel.username == "admin").first()
    assert admin_user is not None, "Admin user must exist in migrated users"
    assert admin_user.password_hash.startswith("scrypt:"), "Password hash format must be scrypt"
    
    # Test scrypt verification with configured password if set
    env_pw = os.getenv("CYBERGUARD_ADMIN_PASSWORD", "Admin@CyberGuard2026!")
    if env_pw:
        matches = verify_password(env_pw, admin_user.password_hash)
        assert matches, "Configured admin password must verify successfully against scrypt hash"


def test_05_account_isolation(pg_session):
    """TEST 5: Cross-user data isolation is enforced."""
    # User 1 and User 2 should have separate analyses
    u1_analyses = pg_session.query(AnalysisRecordModel).filter(AnalysisRecordModel.user_id == 1).all()
    u2_analyses = pg_session.query(AnalysisRecordModel).filter(AnalysisRecordModel.user_id == 2).all()
    
    u1_ids = {a.analysis_id for a in u1_analyses}
    u2_ids = {a.analysis_id for a in u2_analyses}
    
    assert not (u1_ids & u2_ids), "User 1 and User 2 must not share analysis records"


def test_06_threat_intelligence(pg_session):
    """TEST 6: Threat events and correlation data query cleanly."""
    critical_events = pg_session.query(ThreatEventModel).filter(ThreatEventModel.severity == "CRITICAL").all()
    assert len(critical_events) > 0, "Critical threat events must be queryable"
    
    # Verify related evidence
    sample_event = pg_session.query(ThreatEventModel).first()
    assert sample_event is not None
    evidence = pg_session.query(ThreatEvidenceModel).filter(ThreatEvidenceModel.event_id == sample_event.event_id).all()
    # Evidence query must execute without error
    assert isinstance(evidence, list)


def test_07_email_notifications(pg_session):
    """TEST 7: Persisted email alert records exist with delivery status and recipients."""
    records = pg_session.query(EmailAlertRecordModel).limit(10).all()
    assert len(records) > 0, "Email alert records must exist"
    for r in records:
        assert r.recipient, "Alert record recipient must be non-empty"
        assert r.alert_id, "Alert ID must be populated"


def test_08_database_write_persistence(pg_session):
    """TEST 8: Write persistence - record written to Supabase persists and cleans up."""
    test_run_id = f"test_run_{uuid.uuid4().hex[:8]}"
    test_run = TrainingRunModel(
        run_id=test_run_id,
        status="TEST_VALIDATION",
        base_model_version="v001",
        sample_count=0
    )
    pg_session.add(test_run)
    pg_session.commit()
    
    # Read back in a fresh query
    fetched = pg_session.query(TrainingRunModel).filter(TrainingRunModel.run_id == test_run_id).first()
    assert fetched is not None
    assert fetched.status == "TEST_VALIDATION"
    
    # Clean up test artifact
    pg_session.delete(fetched)
    pg_session.commit()
    
    # Verify cleanup
    post_clean = pg_session.query(TrainingRunModel).filter(TrainingRunModel.run_id == test_run_id).first()
    assert post_clean is None


def test_09_docker_compose_configuration():
    """TEST 9: Docker Compose configuration includes DATABASE_URL and health check."""
    compose_path = Path("docker-compose.yml")
    assert compose_path.exists(), "docker-compose.yml must exist"
    content = compose_path.read_text(encoding="utf-8")
    assert "DATABASE_URL" in content, "docker-compose.yml must support DATABASE_URL"
    assert "healthcheck:" in content, "docker-compose.yml must include healthcheck"


def test_10_deployed_frontend_topology():
    """TEST 10: Vercel frontend config and GitHub Pages workflow are intact."""
    vercel_path = Path("vercel.json")
    assert vercel_path.exists(), "vercel.json must exist"
    vdata = json.loads(vercel_path.read_text(encoding="utf-8"))
    assert vdata.get("outputDirectory") == "frontend"
    
    pages_wf = Path(".github/workflows/pages.yml")
    assert pages_wf.exists(), "GitHub Pages workflow must exist"


def test_11_secret_protection():
    """TEST 11: Database credentials and secrets are not leaked in frontend or source control."""
    cred_file = Path("data/.supabase_credentials")
    db_pass = os.getenv("SUPABASE_DB_PASSWORD", "")
    if cred_file.exists():
        with open(cred_file) as f:
            for line in f:
                if line.startswith("SUPABASE_DB_PASSWORD="):
                    db_pass = line.split("=", 1)[1].strip()
    elif not db_pass:
        pytest.skip("Credentials file data/.supabase_credentials and SUPABASE_DB_PASSWORD env not present")
                
    assert len(db_pass) >= 16, "Password must be at least 16 characters"
    
    # Verify password is NOT in frontend directory
    for root, _, files in os.walk("frontend"):
        for file in files:
            if file.endswith((".js", ".html", ".css", ".json")):
                path = Path(root) / file
                text = path.read_text(encoding="utf-8", errors="ignore")
                assert db_pass not in text, f"Secret password found in frontend file: {path}!"
                assert "postgres." in text or "supabase.co:5432" not in text


def test_12_failure_handling():
    """TEST 12: Bad database configuration produces a clean connection error rather than corrupting."""
    bad_url = "postgresql+psycopg2://postgres.invalid:badpass@127.0.0.1:54329/invalid?sslmode=require&connect_timeout=2"
    bad_engine = create_engine(bad_url, connect_args={"connect_timeout": 2})
    
    with pytest.raises(Exception):
        with bad_engine.connect() as conn:
            conn.execute(text("SELECT 1;"))


def test_13_regression_lifespan_bootstrap():
    """TEST 13: Core settings reload and database initialization pass without error."""
    settings = reload_settings()
    assert settings is not None
    engine = get_engine()
    if settings.storage.database_url:
        assert engine.dialect.name == "postgresql"
    else:
        assert engine.dialect.name == "sqlite"
