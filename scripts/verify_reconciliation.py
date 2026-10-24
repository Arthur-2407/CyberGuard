"""
scripts/verify_reconciliation.py — Automated verification and reconciliation of Supabase PostgreSQL migration.
"""

import os
import sys
import json
import sqlite3
import datetime
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from backend.storage.database import (
    Base,
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

cred_file = Path("data/.supabase_credentials")
db_pass = ""
with open(cred_file) as f:
    for line in f:
        if line.startswith("SUPABASE_DB_PASSWORD="):
            db_pass = line.split("=", 1)[1].strip()

pg_url = f"postgresql+psycopg2://postgres.qspnpfukzoclwaxxijiu:{db_pass}@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres?sslmode=require"
engine = create_engine(pg_url, pool_pre_ping=True)
Session = sessionmaker(bind=engine)
session = Session()

print("=" * 65)
print("CYBERGUARD RECONCILIATION & AUDIT VERIFICATION")
print("=" * 65)

checks = []

def record_check(name: str, passed: bool, details: str):
    status = "PASS" if passed else "FAIL"
    checks.append({"name": name, "status": status, "details": details})
    print(f"[{status}] {name}: {details}")

# 1. Table Row Counts
tables = [
    ("users", UserModel, 89),
    ("enforcement_policies", EnforcementPolicyModel, 1),
    ("model_versions", ModelVersionModel, 32),
    ("incidents", IncidentModel, 146),
    ("sessions", CallSession, 0),
    ("training_runs", TrainingRunModel, 20),
    ("threat_reports", ThreatReportModel, 67),
    ("caller_reputation", CallerReputationModel, 15),
    ("blocked_entities", BlockedEntityModel, 19),
    ("speakers", SpeakerProfile, 9),
    ("auth_sessions", AuthSessionModel, 572),
    ("analysis_records", AnalysisRecordModel, 130),
    ("threat_events", ThreatEventModel, 470),
    ("audit_log", AuditLogEntry, 354),
    ("screened_call_incidents", ScreenedCallIncidentModel, 15),
    ("admin_audit_log", AdminAuditLogModel, 893),
    ("threat_evidence", ThreatEvidenceModel, 262),
    ("review_queue", ReviewQueueModel, 112),
    ("training_samples", TrainingSampleModel, 5),
    ("email_alert_records", EmailAlertRecordModel, 181),
]

all_counts_match = True
for tname, model, expected in tables:
    cnt = session.query(model).count()
    if cnt != expected:
        all_counts_match = False
        record_check(f"Row count: {tname}", False, f"Expected {expected}, got {cnt}")
    else:
        record_check(f"Row count: {tname}", True, f"{cnt} rows verified")

# 2. Sequence Verification
# Test that next sequence value for incidents is > max(id)
max_incident_id = session.execute(text("SELECT MAX(id) FROM incidents")).scalar() or 0
seq_val = session.execute(text("SELECT last_value FROM incidents_id_seq")).scalar()
seq_ok = seq_val >= max_incident_id
record_check(
    "Sequence Alignment: incidents_id_seq",
    seq_ok,
    f"Sequence last_value={seq_val} >= MAX(id)={max_incident_id}"
)

# 3. User Authentication & Password Hash Integrity
admin_user = session.query(UserModel).filter(UserModel.username == "admin").first()
has_admin = admin_user is not None and bool(admin_user.password_hash)
hash_type_valid = admin_user.password_hash.startswith("scrypt:") if has_admin else False
record_check(
    "Authentication Integrity: Admin Account",
    has_admin and hash_type_valid,
    f"Admin exists (ID={admin_user.id if admin_user else 'None'}), hash prefix='{admin_user.password_hash.split(':')[0] if has_admin else ''}', role='{admin_user.role if admin_user else ''}'"
)

# 4. Foreign Key Integrity: All auth_sessions have valid user_id in users
invalid_fk_count = session.execute(text(
    "SELECT COUNT(*) FROM auth_sessions WHERE user_id NOT IN (SELECT id FROM users)"
)).scalar()
record_check(
    "Referential Integrity: auth_sessions -> users",
    invalid_fk_count == 0,
    f"Orphaned foreign keys: {invalid_fk_count}"
)

# 5. Timestamp Integrity & Timezones
sample_event = session.query(ThreatEventModel).first()
ts_ok = sample_event is not None and isinstance(sample_event.timestamp, datetime.datetime)
record_check(
    "Timestamp Representation: UTC Datetime",
    ts_ok,
    f"Sample timestamp: {sample_event.timestamp.isoformat() if sample_event else 'None'}"
)

# 6. Aggregate Checks: Sum of risk scores
total_risk = session.execute(text("SELECT ROUND(SUM(risk_score)::numeric, 2) FROM audit_log")).scalar()
record_check(
    "Aggregate Verification: audit_log risk sum",
    total_risk is not None and total_risk > 0,
    f"Total audit_log risk score aggregate: {total_risk}"
)

# 7. Non-Null Constraints
null_usernames = session.execute(text("SELECT COUNT(*) FROM users WHERE username IS NULL OR email IS NULL")).scalar()
record_check(
    "Non-Null Integrity: users table",
    null_usernames == 0,
    f"Rows with null mandatory fields: {null_usernames}"
)

# 8. Speaker Profile JSON integrity
sample_speaker = session.query(SpeakerProfile).first()
speaker_valid = False
if sample_speaker:
    try:
        emb = json.loads(sample_speaker.embedding_json)
        speaker_valid = isinstance(emb, list) and len(emb) == sample_speaker.embedding_dim
    except Exception:
        pass
record_check(
    "Speaker Embedding Serialization",
    speaker_valid,
    f"Speaker '{sample_speaker.speaker_id if sample_speaker else ''}': embedding dimension={sample_speaker.embedding_dim if sample_speaker else 0}"
)

# Summary
passed_count = sum(1 for c in checks if c["status"] == "PASS")
failed_count = sum(1 for c in checks if c["status"] == "FAIL")

print("\n" + "=" * 65)
print(f"VERIFICATION SUMMARY: {passed_count}/{len(checks)} CHECKS PASSED, {failed_count} FAILED")
print("=" * 65)

# Save verification report
report_path = Path("data/backups/pre_migration_20261024/reconciliation_report.json")
report_path.write_text(json.dumps({
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "checks_passed": passed_count,
    "checks_failed": failed_count,
    "checks": checks
}, indent=2), encoding="utf-8")
print(f"Report saved to: {report_path}")

session.close()
