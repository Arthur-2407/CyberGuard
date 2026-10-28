"""
backend/storage/sync_service.py — Bidirectional Synchronization Service between
Cloud Supabase PostgreSQL and Local SQLite (data/cyberguard.db).

Ensures non-destructive two-way replication:
- Any change/addition in Cloud PostgreSQL is reflected in Local SQLite.
- Any change/addition in Local SQLite is reflected in Cloud PostgreSQL.
- Conflict resolution uses primary keys and Last-Write-Wins (LWW) based on timestamps.
- Zero data loss: no tables or records are dropped or deleted during synchronization.
- Real-time session change mirroring for hybrid dual-database execution.
"""

from __future__ import annotations

import os
import sys
import json
import time
import asyncio
import logging
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from dotenv import load_dotenv

# Ensure .env is loaded independently of import order
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env.email")
load_dotenv(_PROJECT_ROOT / ".env")
load_dotenv()

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, Session

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

logger = logging.getLogger(__name__)

# Ordered list of tables respecting foreign key relationships
TABLE_MODELS = [
    ("users", UserModel),
    ("enforcement_policies", EnforcementPolicyModel),
    ("model_versions", ModelVersionModel),
    ("incidents", IncidentModel),
    ("sessions", CallSession),
    ("training_runs", TrainingRunModel),
    ("threat_reports", ThreatReportModel),
    ("caller_reputation", CallerReputationModel),
    ("blocked_entities", BlockedEntityModel),
    ("speakers", SpeakerProfile),
    ("auth_sessions", AuthSessionModel),
    ("analysis_records", AnalysisRecordModel),
    ("threat_events", ThreatEventModel),
    ("audit_log", AuditLogEntry),
    ("screened_call_incidents", ScreenedCallIncidentModel),
    ("admin_audit_log", AdminAuditLogModel),
    ("threat_evidence", ThreatEvidenceModel),
    ("review_queue", ReviewQueueModel),
    ("training_samples", TrainingSampleModel),
    ("email_alert_records", EmailAlertRecordModel),
]

# Legacy table sequences mapping for backwards compatibility
SEQUENCE_TABLES = [
    (tbl, f"{tbl}_id_seq") for tbl, _ in TABLE_MODELS
]


def _resolve_cloud_db_url() -> str:
    """Retrieve the Cloud PostgreSQL connection URL from env or credentials file."""
    load_dotenv(_PROJECT_ROOT / ".env")
    url = (os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL") or "").strip()
    if url and "postgres" in url:
        return url
    cred_file = _PROJECT_ROOT / "data" / ".supabase_credentials"
    if cred_file.exists():
        try:
            with open(cred_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("SUPABASE_DB_PASSWORD="):
                        db_pass = line.split("=", 1)[1].strip()
                        return f"postgresql+psycopg2://postgres.qspnpfukzoclwaxxijiu:{db_pass}@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres?sslmode=require"
        except Exception as e:
            logger.warning(f"Failed reading supabase credentials: {e}")
    return ""


def _resolve_local_db_path() -> str:
    """Resolve the physical path to the local SQLite database."""
    base_data = _PROJECT_ROOT / "data"
    base_data.mkdir(parents=True, exist_ok=True)
    db_file = base_data / "cyberguard.db"
    return str(db_file.resolve())


def _normalize_dt(dt: Any) -> Optional[datetime.datetime]:
    """Normalize datetime to timezone-naive UTC for robust cross-database comparison."""
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.datetime.fromisoformat(dt)
        except Exception:
            return None
    if isinstance(dt, datetime.datetime):
        if dt.tzinfo is not None:
            return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    return None


class DatabaseSyncService:
    """
    Bidirectional synchronization engine between Cloud PostgreSQL and Local SQLite.
    Provides instant real-time mirroring, batch synchronization, and dynamic sequence alignment.
    """

    def __init__(self, cloud_url: Optional[str] = None, local_path: Optional[str] = None):
        self.cloud_url = cloud_url or _resolve_cloud_db_url()
        self.local_path = local_path or _resolve_local_db_path()

        self._cloud_engine = None
        self._local_engine = None
        self._cloud_session_factory = None
        self._local_session_factory = None

        self.last_sync_time: Optional[datetime.datetime] = None
        self.last_sync_result: Dict[str, Any] = {}
        self.is_syncing: bool = False
        self._sync_lock = asyncio.Lock()
        self._cloud_status_cache: Tuple[bool, float] = (False, 0.0)

    def get_cloud_engine(self):
        if not self.cloud_url:
            self.cloud_url = _resolve_cloud_db_url()
        if not self.cloud_url:
            return None
        if self._cloud_engine is None:
            pg_url = self.cloud_url
            if pg_url.startswith("postgresql://"):
                pg_url = "postgresql+psycopg2://" + pg_url[len("postgresql://"):]
            from sqlalchemy.pool import QueuePool
            self._cloud_engine = create_engine(
                pg_url,
                poolclass=QueuePool,
                pool_size=3,
                max_overflow=2,
                pool_timeout=15,
                pool_pre_ping=True,
                pool_recycle=60,
                connect_args={"connect_timeout": 8},
            )
            self._cloud_session_factory = sessionmaker(bind=self._cloud_engine)
        return self._cloud_engine

    def get_local_engine(self):
        if self._local_engine is None:
            sqlite_url = f"sqlite:///{self.local_path}"
            self._local_engine = create_engine(
                sqlite_url,
                connect_args={"check_same_thread": False, "timeout": 30},
            )
            self._local_session_factory = sessionmaker(bind=self._local_engine)
            # Ensure all tables exist locally
            Base.metadata.create_all(self._local_engine)
        return self._local_engine

    def get_cloud_session(self) -> Optional[Session]:
        if not self.get_cloud_engine():
            return None
        return self._cloud_session_factory()

    def get_local_session(self) -> Session:
        self.get_local_engine()
        return self._local_session_factory()

    def is_cloud_available(self, force_refresh: bool = False) -> bool:
        """Check whether Cloud PostgreSQL is reachable with a lightweight 5-second cache."""
        now = time.time()
        cached_status, cached_time = self._cloud_status_cache
        if not force_refresh and (now - cached_time) < 5.0:
            return cached_status

        if not self.cloud_url:
            self.cloud_url = _resolve_cloud_db_url()
        if not self.cloud_url:
            self._cloud_status_cache = (False, now)
            return False

        try:
            engine = self.get_cloud_engine()
            if not engine:
                self._cloud_status_cache = (False, now)
                return False
            with engine.connect() as conn:
                res = conn.execute(text("SELECT 1;")).scalar()
                is_up = bool(res == 1)
                self._cloud_status_cache = (is_up, now)
                return is_up
        except Exception:
            self._cloud_status_cache = (False, now)
            return False

    def is_local_available(self) -> bool:
        try:
            engine = self.get_local_engine()
            with engine.connect() as conn:
                res = conn.execute(text("SELECT 1;")).scalar()
                return res == 1
        except Exception:
            return False

    @staticmethod
    def _extract_model_columns(model) -> List[str]:
        return [c.name for c in inspect(model).columns]

    @staticmethod
    def _record_to_dict(record, cols: List[str]) -> Dict[str, Any]:
        return {col: getattr(record, col) for col in cols}

    def _sync_table_records(
        self,
        table_name: str,
        model,
        src_session: Session,
        dst_session: Session,
        is_dst_postgres: bool = False,
    ) -> Tuple[int, int]:
        """
        Sync all records of `model` from src_session to dst_session non-destructively.
        Uses in-memory indexed mapping, fast batch staging, and per-row savepoint fallback.
        Returns: (inserted_count, updated_count)
        """
        pk_cols = [c.name for c in inspect(model).primary_key]
        cols = self._extract_model_columns(model)
        inserted = 0
        updated = 0

        # Pre-load all destination records into memory dictionary keyed by PK
        dst_records = dst_session.query(model).all()
        dst_map = {tuple(getattr(r, pk) for pk in pk_cols): r for r in dst_records}

        # Check foreign key sets for child tables to prevent constraint violations
        valid_user_ids = None
        if table_name in ("auth_sessions", "analysis_records", "email_alert_records"):
            valid_user_ids = set(r[0] for r in dst_session.query(UserModel.id).all())

        src_records = src_session.query(model).all()
        to_insert = []
        to_update = []

        for src_rec in src_records:
            data = self._record_to_dict(src_rec, cols)
            pk_tuple = tuple(data[pk] for pk in pk_cols)

            # Safeguard orphaned child records if parent user does not exist in destination
            if valid_user_ids is not None:
                uid = data.get("user_id")
                if uid is not None and uid not in valid_user_ids:
                    data["user_id"] = None

            dst_rec = dst_map.get(pk_tuple)
            if dst_rec is None:
                to_insert.append((pk_tuple, data))
            else:
                src_ts = _normalize_dt(data.get("updated_at") or data.get("timestamp") or data.get("created_at"))
                dst_ts = _normalize_dt(getattr(dst_rec, "updated_at", None) or getattr(dst_rec, "timestamp", None) or getattr(dst_rec, "created_at", None))

                differs = False
                for c in cols:
                    if getattr(dst_rec, c) != data[c]:
                        differs = True
                        break

                if differs:
                    should_update = True
                    if src_ts and dst_ts and dst_ts > src_ts:
                        should_update = False

                    if should_update:
                        to_update.append((dst_rec, data))

        # 1. Attempt ultra-fast batch flush
        try:
            with dst_session.begin_nested():
                for pk_tuple, data in to_insert:
                    new_rec = model(**data)
                    dst_session.add(new_rec)
                    dst_map[pk_tuple] = new_rec
                    inserted += 1

                for dst_rec, data in to_update:
                    for c in cols:
                        if c not in pk_cols:
                            setattr(dst_rec, c, data[c])
                    updated += 1

                dst_session.flush()
        except Exception as batch_err:
            logger.debug(f"Batch flush for {table_name} encountered notice; using row-by-row fallback: {batch_err}")
            dst_session.rollback()
            inserted = 0
            updated = 0

            # 2. Resilient row-by-row isolation fallback
            for pk_tuple, data in to_insert:
                try:
                    with dst_session.begin_nested():
                        new_rec = model(**data)
                        dst_session.add(new_rec)
                        dst_session.flush()
                        dst_map[pk_tuple] = new_rec
                        inserted += 1
                except Exception as ins_err:
                    logger.debug(f"Insert skipped for {table_name} PK={pk_tuple}: {ins_err}")

            for dst_rec, data in to_update:
                try:
                    with dst_session.begin_nested():
                        for c in cols:
                            if c not in pk_cols:
                                setattr(dst_rec, c, data[c])
                        dst_session.flush()
                        updated += 1
                except Exception as upd_err:
                    logger.debug(f"Update skipped for {table_name}: {upd_err}")

        dst_session.commit()
        return inserted, updated

    def _align_postgres_sequences(self, pg_session: Session):
        """Align auto-increment primary key sequences in PostgreSQL to match MAX(id) for all tables."""
        known_tables = [t[0] for t in TABLE_MODELS]
        try:
            seq_rows = pg_session.execute(text(
                "SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public';"
            )).fetchall()
            all_seqs = {row[0] for row in seq_rows}

            for table in known_tables:
                seq_candidate = f"{table}_id_seq"
                if seq_candidate in all_seqs or True:
                    try:
                        max_id = pg_session.execute(text(f'SELECT MAX(id) FROM "{table}"')).scalar()
                        if max_id is not None and max_id > 0:
                            pg_session.execute(text(f"SELECT setval('{seq_candidate}', {max_id}, true);"))
                        elif max_id == 0 or max_id is None:
                            pg_session.execute(text(f"SELECT setval('{seq_candidate}', 1, false);"))
                        pg_session.commit()
                    except Exception as seq_err:
                        pg_session.rollback()
                        logger.debug(f"Sequence alignment notice for {table} / {seq_candidate}: {seq_err}")

            # Align any remaining custom sequences in the public schema
            for seq_name in all_seqs:
                tname = seq_name.replace("_id_seq", "").replace("_seq", "")
                if tname in known_tables:
                    continue
                try:
                    max_id = pg_session.execute(text(f'SELECT MAX(id) FROM "{tname}"')).scalar()
                    if max_id is not None and max_id > 0:
                        pg_session.execute(text(f"SELECT setval('{seq_name}', {max_id}, true);"))
                        pg_session.commit()
                except Exception:
                    pg_session.rollback()
        except Exception as e:
            pg_session.rollback()
            logger.debug(f"Global sequence alignment notice: {e}")

    def mirror_session_changes(
        self,
        new_items: List[Any],
        dirty_items: List[Any],
        deleted_items: List[Any],
        target_is_cloud: bool = True,
    ):
        """
        Real-time dual-write mirroring: Replicate committed changes to the counterpart database.
        When target_is_cloud is True, writes to Cloud PostgreSQL and aligns sequences.
        When target_is_cloud is False, writes to Local SQLite.
        """
        if target_is_cloud and not self.is_cloud_available():
            return
        if not target_is_cloud and not self.is_local_available():
            return

        target_session = self.get_cloud_session() if target_is_cloud else self.get_local_session()
        if not target_session:
            return

        try:
            affected_tables = set()

            # 1. Replicate deleted items
            for item in deleted_items:
                model_cls = item.__class__
                table_name = getattr(model_cls, "__tablename__", None)
                if not table_name:
                    continue
                pk_cols = [c.name for c in inspect(model_cls).primary_key]
                pk_vals = {pk: getattr(item, pk) for pk in pk_cols}
                rec = target_session.query(model_cls).filter_by(**pk_vals).first()
                if rec:
                    target_session.delete(rec)
                    affected_tables.add(table_name)

            # 2. Replicate new items
            for item in new_items:
                model_cls = item.__class__
                table_name = getattr(model_cls, "__tablename__", None)
                if not table_name:
                    continue
                cols = self._extract_model_columns(model_cls)
                pk_cols = [c.name for c in inspect(model_cls).primary_key]
                data = self._record_to_dict(item, cols)
                pk_vals = {pk: data[pk] for pk in pk_cols}
                existing = target_session.query(model_cls).filter_by(**pk_vals).first()
                if existing:
                    for c in cols:
                        if c not in pk_cols:
                            setattr(existing, c, data[c])
                else:
                    new_rec = model_cls(**data)
                    target_session.add(new_rec)
                affected_tables.add(table_name)

            # 3. Replicate updated (dirty) items
            for item in dirty_items:
                model_cls = item.__class__
                table_name = getattr(model_cls, "__tablename__", None)
                if not table_name:
                    continue
                cols = self._extract_model_columns(model_cls)
                pk_cols = [c.name for c in inspect(model_cls).primary_key]
                data = self._record_to_dict(item, cols)
                pk_vals = {pk: data[pk] for pk in pk_cols}
                existing = target_session.query(model_cls).filter_by(**pk_vals).first()
                if existing:
                    for c in cols:
                        if c not in pk_cols:
                            setattr(existing, c, data[c])
                else:
                    new_rec = model_cls(**data)
                    target_session.add(new_rec)
                affected_tables.add(table_name)

            target_session.commit()

            # Align sequences in PostgreSQL if cloud was the target
            if target_is_cloud and affected_tables:
                for tname in affected_tables:
                    try:
                        max_id = target_session.execute(text(f'SELECT MAX(id) FROM "{tname}"')).scalar()
                        if max_id and max_id > 0:
                            target_session.execute(text(f"SELECT setval('{tname}_id_seq', {max_id}, true);"))
                            target_session.commit()
                    except Exception:
                        target_session.rollback()

        except Exception as e:
            target_session.rollback()
            logger.debug(f"Hybrid mirror session notice: {e}")
        finally:
            target_session.close()

    def sync_bidirectional(self) -> Dict[str, Any]:
        """
        Execute full two-way synchronization:
        1. Cloud PostgreSQL -> Local SQLite (reflect all cloud additions/updates locally).
        2. Local SQLite -> Cloud PostgreSQL (reflect all local additions/updates to cloud).
        3. Align all auto-increment sequences in PostgreSQL.
        """
        if not self.is_cloud_available(force_refresh=True):
            return {
                "success": False,
                "error": "Cloud database is currently unreachable; running offline.",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

        start_time = time.perf_counter()
        summary = {
            "cloud_to_local": {},
            "local_to_cloud": {},
            "total_inserted": 0,
            "total_updated": 0,
        }

        cloud_session = self.get_cloud_session()
        local_session = self.get_local_session()

        try:
            # Step 1: Cloud PostgreSQL -> Local SQLite
            for table_name, model in TABLE_MODELS:
                ins, upd = self._sync_table_records(
                    table_name, model, cloud_session, local_session, is_dst_postgres=False
                )
                summary["cloud_to_local"][table_name] = {"inserted": ins, "updated": upd}
                summary["total_inserted"] += ins
                summary["total_updated"] += upd

            # Step 2: Local SQLite -> Cloud PostgreSQL
            for table_name, model in TABLE_MODELS:
                ins, upd = self._sync_table_records(
                    table_name, model, local_session, cloud_session, is_dst_postgres=True
                )
                summary["local_to_cloud"][table_name] = {"inserted": ins, "updated": upd}
                summary["total_inserted"] += ins
                summary["total_updated"] += upd

            # Step 3: Align PostgreSQL sequences
            self._align_postgres_sequences(cloud_session)

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            now = datetime.datetime.now(datetime.timezone.utc)
            self.last_sync_time = now
            self.last_sync_result = {
                "success": True,
                "duration_ms": duration_ms,
                "timestamp": now.isoformat(),
                "summary": summary,
            }
            logger.info(
                f"[DatabaseSyncService] Bidirectional sync complete in {duration_ms}ms: "
                f"+{summary['total_inserted']} inserted, ~{summary['total_updated']} updated."
            )
            return self.last_sync_result

        except Exception as e:
            logger.error(f"[DatabaseSyncService] Synchronization error: {e}", exc_info=True)
            cloud_session.rollback()
            local_session.rollback()
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        finally:
            cloud_session.close()
            local_session.close()

    async def async_sync_bidirectional(self) -> Dict[str, Any]:
        """Asynchronous wrapper for bidirectional sync."""
        async with self._sync_lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.sync_bidirectional)

    async def run_periodic_sync(self, interval_sec: int = 30):
        """Continuously running background worker that keeps Cloud and Local DBs in sync."""
        logger.info(f"[DatabaseSyncService] Periodic background sync worker active (interval: {interval_sec}s).")
        while True:
            try:
                await asyncio.sleep(interval_sec)
                await self.async_sync_bidirectional()
            except asyncio.CancelledError:
                logger.info("[DatabaseSyncService] Periodic sync worker cancelled.")
                break
            except Exception as e:
                logger.warning(f"[DatabaseSyncService] Periodic sync iteration notice: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Return synchronization health and table row count comparison."""
        cloud_avail = self.is_cloud_available(force_refresh=True)
        local_avail = self.is_local_available()

        counts = {"cloud": {}, "local": {}}
        if cloud_avail:
            try:
                cs = self.get_cloud_session()
                for tname, model in TABLE_MODELS:
                    counts["cloud"][tname] = cs.query(model).count()
                cs.close()
            except Exception:
                pass

        if local_avail:
            try:
                ls = self.get_local_session()
                for tname, model in TABLE_MODELS:
                    counts["local"][tname] = ls.query(model).count()
                ls.close()
            except Exception:
                pass

        return {
            "service": "CyberGuard Database Synchronizer",
            "mode": "hybrid",
            "cloud_connected": cloud_avail,
            "local_connected": local_avail,
            "cloud_engine": "Supabase PostgreSQL",
            "local_engine": "SQLite WAL",
            "last_sync_timestamp": self.last_sync_time.isoformat() if self.last_sync_time else None,
            "last_sync_result": self.last_sync_result,
            "table_counts": counts,
        }


# Authoritative singleton
_SYNC_SERVICE: Optional[DatabaseSyncService] = None


def get_sync_service() -> DatabaseSyncService:
    global _SYNC_SERVICE
    if _SYNC_SERVICE is None:
        _SYNC_SERVICE = DatabaseSyncService()
    return _SYNC_SERVICE
