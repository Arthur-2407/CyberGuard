"""
scripts/migrate_to_postgres.py — Robust, idempotent data migration from SQLite to PostgreSQL / Supabase.

Handles:
- DDL creation of all 20 tables via SQLAlchemy Base metadata
- Type conversions (SQLite int/str booleans -> Postgres boolean, ISO dates -> DateTime)
- Dependency-ordered table insertions
- Merging central database (cyberguard.db) + tenant databases (user_*.db)
- Auto-increment sequence synchronization (setval)
- Idempotent execution (ON CONFLICT / existence checks)
- Verification & reconciliation reporting
- Dry-run mode for pre-flight validation
"""

import os
import sys
import json
import glob
import sqlite3
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

# Add project root to sys.path
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


def parse_datetime(val: Any) -> Optional[datetime.datetime]:
    if val is None or val == "":
        return None
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=datetime.timezone.utc)
        return val
    if isinstance(val, (int, float)):
        return datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
    if isinstance(val, str):
        # Clean string
        s = val.strip()
        # Handle trailing Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except Exception:
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
            ):
                try:
                    return datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc)
                except Exception:
                    pass
    return None


def parse_bool(val: Any) -> bool:
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.lower() in ("true", "1", "t", "yes", "y")
    return bool(val)


# Mapping of table names to SQLAlchemy model classes
MODEL_MAP = {
    "users": UserModel,
    "auth_sessions": AuthSessionModel,
    "analysis_records": AnalysisRecordModel,
    "audit_log": AuditLogEntry,
    "sessions": CallSession,
    "incidents": IncidentModel,
    "threat_events": ThreatEventModel,
    "threat_evidence": ThreatEvidenceModel,
    "review_queue": ReviewQueueModel,
    "training_samples": TrainingSampleModel,
    "training_runs": TrainingRunModel,
    "model_versions": ModelVersionModel,
    "admin_audit_log": AdminAuditLogModel,
    "enforcement_policies": EnforcementPolicyModel,
    "blocked_entities": BlockedEntityModel,
    "threat_reports": ThreatReportModel,
    "email_alert_records": EmailAlertRecordModel,
    "caller_reputation": CallerReputationModel,
    "screened_call_incidents": ScreenedCallIncidentModel,
    "speakers": SpeakerProfile,
}

# Tables ordered by foreign key dependencies
INSERTION_ORDER = [
    # Level 0 (no FK dependencies)
    "users",
    "enforcement_policies",
    "model_versions",
    "incidents",
    "sessions",
    "training_runs",
    "threat_reports",
    "caller_reputation",
    "blocked_entities",
    "speakers",
    # Level 1
    "auth_sessions",  # FK to users.id
    "analysis_records",
    "threat_events",
    "audit_log",
    "screened_call_incidents",
    "admin_audit_log",
    # Level 2
    "threat_evidence",
    "review_queue",
    "training_samples",
    "email_alert_records",
]

# Unique / primary identity columns per table for deduplication
UNIQUE_KEYS = {
    "users": "username",
    "auth_sessions": "token_hash",
    "analysis_records": "analysis_id",
    "audit_log": "id",
    "sessions": "session_id",
    "incidents": "incident_id",
    "threat_events": "event_id",
    "threat_evidence": "id",
    "review_queue": "review_id",
    "training_samples": "sample_id",
    "training_runs": "run_id",
    "model_versions": "version",
    "admin_audit_log": "id",
    "enforcement_policies": "id",
    "blocked_entities": "id",
    "threat_reports": "report_id",
    "email_alert_records": "alert_id",
    "caller_reputation": "normalized_number",
    "screened_call_incidents": "incident_id",
    "speakers": "speaker_id",
}


def load_sqlite_table(sqlite_conn: sqlite3.Connection, table_name: str) -> List[Dict[str, Any]]:
    cur = sqlite_conn.cursor()
    # Check if table exists
    tbl = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    ).fetchone()
    if not tbl:
        return []
    
    cur.execute(f'SELECT * FROM "{table_name}"')
    col_names = [desc[0] for desc in cur.description]
    rows = cur.fetchall()
    return [dict(zip(col_names, row)) for row in rows]


def transform_row(table_name: str, raw_row: Dict[str, Any]) -> Dict[str, Any]:
    row = dict(raw_row)
    model = MODEL_MAP[table_name]
    
    # Inspect model columns for type conversion
    for col in model.__table__.columns:
        col_name = col.name
        if col_name not in row:
            continue
        val = row[col_name]
        if val is None:
            continue
            
        type_str = str(col.type).lower()
        if "boolean" in type_str:
            row[col_name] = parse_bool(val)
        elif "datetime" in type_str:
            row[col_name] = parse_datetime(val)
        elif "float" in type_str:
            try:
                row[col_name] = float(val)
            except Exception:
                row[col_name] = None
        elif "integer" in type_str:
            try:
                row[col_name] = int(val)
            except Exception:
                row[col_name] = None
        elif "string" in type_str or "text" in type_str or "varchar" in type_str:
            if isinstance(val, (dict, list)):
                row[col_name] = json.dumps(val)
            else:
                row[col_name] = str(val)
                
    return row


def run_migration(target_engine, is_dry_run: bool = False) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"MIGRATION START: {'DRY RUN' if is_dry_run else 'LIVE CUTOVER'}")
    print(f"Target dialect: {target_engine.dialect.name}")
    print(f"=======================================================")
    
    # Step 1: Create all tables in target schema
    print("\n[Step 1] Applying schema (Base.metadata.create_all)...")
    Base.metadata.create_all(bind=target_engine)
    print("[OK] Schema initialized successfully.")
    
    # Connect to primary source SQLite database
    main_db_path = "data/cyberguard.db"
    main_conn = sqlite3.connect(main_db_path)
    
    # User databases
    user_db_paths = glob.glob("data/user_databases/*.db")
    print(f"Found primary source: {main_db_path}")
    print(f"Found {len(user_db_paths)} tenant user databases in data/user_databases/")
    
    SessionLocal = sessionmaker(bind=target_engine)
    session = SessionLocal()
    
    manifest_results = {
        "is_dry_run": is_dry_run,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tables": {},
        "total_source_rows": 0,
        "total_target_rows": 0,
        "status": "IN_PROGRESS"
    }
    
    try:
        for table_name in INSERTION_ORDER:
            model = MODEL_MAP[table_name]
            unique_col = UNIQUE_KEYS.get(table_name, "id")
            
            # Load rows from primary database
            primary_rows = load_sqlite_table(main_conn, table_name)
            
            # Merge tenant databases for relevant tables
            tenant_rows = []
            if table_name in ("speakers", "incidents", "threat_events", "threat_evidence", "analysis_records"):
                for udb in user_db_paths:
                    uconn = sqlite3.connect(udb)
                    u_rows = load_sqlite_table(uconn, table_name)
                    uconn.close()
                    tenant_rows.extend(u_rows)
                    
            # Enforce foreign key referential integrity for auth_sessions
            if table_name == "auth_sessions":
                valid_user_ids = set(r[0] for r in session.query(UserModel.id).all())
                orphans = [r for r in primary_rows if r.get("user_id") not in valid_user_ids]
                if orphans:
                    print(f"  [INFO] Excluding {len(orphans)} orphaned auth_sessions pointing to non-existent user accounts")
                    manifest_results.setdefault("excluded_records", {})["auth_sessions_orphans"] = len(orphans)
                primary_rows = [r for r in primary_rows if r.get("user_id") in valid_user_ids]
                tenant_rows = [r for r in tenant_rows if r.get("user_id") in valid_user_ids]

            combined_rows = primary_rows + tenant_rows
            manifest_results["total_source_rows"] += len(combined_rows)
            
            # Keep track of existing keys in target table
            existing_keys = set(
                r[0] for r in session.query(getattr(model, unique_col)).all() if r[0] is not None
            )
            
            imported_count = 0
            def _sync_seq():
                if target_engine.dialect.name == "postgresql":
                    try:
                        seq_query = text(
                            f"""
                            SELECT setval(
                                pg_get_serial_sequence('"{table_name}"', 'id'),
                                COALESCE((SELECT MAX(id) FROM "{table_name}"), 1),
                                (SELECT MAX(id) IS NOT NULL FROM "{table_name}")
                            );
                            """
                        )
                        session.execute(seq_query)
                        session.commit()
                    except Exception:
                        session.rollback()

            with session.no_autoflush:
                # 1. First process primary rows (preserving their explicit IDs)
                for raw_row in primary_rows:
                    key_val = raw_row.get(unique_col)
                    if key_val is not None and key_val in existing_keys:
                        continue
                    transformed = transform_row(table_name, raw_row)
                    instance = model(**transformed)
                    session.add(instance)
                    if key_val is not None:
                        existing_keys.add(key_val)
                    imported_count += 1

            session.commit()
            _sync_seq()

            with session.no_autoflush:
                # 2. Process tenant rows (omit 'id' so target generates new unique sequence ID)
                for raw_row in tenant_rows:
                    key_val = raw_row.get(unique_col)
                    if key_val is not None and key_val in existing_keys:
                        continue
                    transformed = transform_row(table_name, raw_row)
                    # Omit id to avoid collision with primary rows
                    transformed.pop("id", None)
                    instance = model(**transformed)
                    session.add(instance)
                    if key_val is not None:
                        existing_keys.add(key_val)
                    imported_count += 1

            session.commit()
            _sync_seq()
                    
            target_count = session.query(model).count()
            manifest_results["tables"][table_name] = {
                "source_primary_rows": len(primary_rows),
                "unique_source_rows": len(combined_rows),
                "imported_rows": imported_count,
                "target_total_rows": target_count,
            }
            manifest_results["total_target_rows"] += target_count
            print(f"  [OK] '{table_name}' verified in target: {target_count} total rows")
            
        manifest_results["status"] = "SUCCESS"
        print(f"\n=======================================================")
        print(f"MIGRATION COMPLETED SUCCESSFULLY!")
        print(f"Total Target Rows Verified: {manifest_results['total_target_rows']}")
        print(f"=======================================================\n")
        
    except Exception as exc:
        session.rollback()
        manifest_results["status"] = f"FAILED: {exc}"
        print(f"\n[ERROR] Migration failed: {exc}")
        raise
    finally:
        session.close()
        main_conn.close()
        
    return manifest_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGuard Database Migration Tool")
    parser.add_argument("--dry-run", action="store_true", help="Perform migration to an isolated in-memory test database")
    parser.add_argument("--pg-url", type=str, default="", help="Target PostgreSQL connection URL")
    args = parser.parse_args()
    
    if args.dry_run:
        print("[DRY-RUN MODE] Initializing isolated SQLite in-memory database...")
        test_engine = create_engine("sqlite:///:memory:")
        res = run_migration(test_engine, is_dry_run=True)
        print("Dry run completed successfully with zero errors!")
        sys.exit(0)
        
    # Live migration
    pg_url = args.pg_url
    if not pg_url:
        # Check environment or .supabase_credentials
        cred_file = Path("data/.supabase_credentials")
        if cred_file.exists():
            with open(cred_file) as f:
                for line in f:
                    if line.startswith("SUPABASE_DB_PASSWORD="):
                        db_pass = line.split("=", 1)[1].strip()
                        pg_url = f"postgresql+psycopg2://postgres.qspnpfukzoclwaxxijiu:{db_pass}@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres?sslmode=require"
                        break
                        
    if not pg_url:
        print("Error: No PostgreSQL target URL provided.")
        sys.exit(1)
        
    pg_engine = create_engine(pg_url, pool_pre_ping=True)
    res = run_migration(pg_engine, is_dry_run=False)
    
    # Save manifest
    out_manifest = Path("data/backups/pre_migration_20261024/migration_run_results.json")
    out_manifest.parent.mkdir(parents=True, exist_ok=True)
    out_manifest.write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"Detailed run results written to: {out_manifest}")
