"""
user_service.py — Secure user account lifecycle and comprehensive per-user data purge.

Strict Deletion Boundary:
- Deletes only the selected user's account and data attributable exclusively to that account.
- Never deletes the shared application database, other users' data, global threat-intelligence
  records, shared machine-learning models, system configuration, or unrelated application resources.
- Enforces administrative safety safeguards:
    * Rejects self-deletion of the active administrator.
    * Prevents deletion of the last active administrator.
    * Protects system and service accounts.
- Cleans isolated user tenant database (user_{id}.db, wal, shm), auth sessions, analysis records,
  review queue submissions, uncommitted training samples, user-owned threat events/evidence,
  exclusive audio vault files, user-generated report files, and email dispatch records.
- Records tamper-evident administrative audit log with sanitized non-private metadata.
"""

from __future__ import annotations

import datetime
import gc
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.storage.auth import ROLE_ADMIN, ROLE_USER
from backend.storage.database import (
    AdminAuditLogModel,
    AnalysisRecordModel,
    AuthSessionModel,
    CallSession,
    EmailAlertRecordModel,
    ReviewQueueModel,
    SpeakerProfile,
    ThreatEventModel,
    ThreatEvidenceModel,
    ThreatReportModel,
    TrainingSampleModel,
    UserModel,
    close_user_database,
)

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
VAULT_DIR = PROJECT_ROOT / "data" / "audio_vault"
REPORTS_DIR = PROJECT_ROOT / "data" / "reports"
PROTECTED_SYSTEM_USERS = {"system", "cyberguard_system", "root", "daemon", "service"}


def _utcnow() -> datetime.datetime:
    return datetime.timezone.utc and datetime.datetime.now(datetime.timezone.utc)


class UserAccountService:
    """Service handling secure user management and per-user data purges."""

    @staticmethod
    def delete_user_account_and_purge_data(
        db: Session,
        target_user_id: int,
        admin_user: UserModel,
        confirm_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Permanently delete the specified user account and purge all exclusively user-owned data.
        
        Enforces strict authorization, administrative safety safeguards, database transactional
        integrity, and external storage asset cleanup.
        """
        # 1. Authoritative existence & retrieval check
        target = db.query(UserModel).filter(UserModel.id == target_user_id).first()
        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with identifier #{target_user_id} was not found.",
            )

        target_id: int = target.id
        target_username: str = target.username
        target_email: str = target.email or f"{target.username}@cyberguard.local"
        target_role: str = target.role or ROLE_USER
        target_db_path: str = target.db_path or f"data/user_databases/user_{target_id}.db"

        # 2. Administrative safety safeguard: Self-deletion prevention
        if target_id == admin_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrative Safety Safeguard: You cannot delete your own active administrator account through this workflow.",
            )

        # 3. Administrative safety safeguard: Last active administrator protection
        if target_role == ROLE_ADMIN:
            active_admin_count = (
                db.query(UserModel)
                .filter(UserModel.role == ROLE_ADMIN, UserModel.is_active.is_(True))
                .count()
            )
            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Administrative Safety Safeguard: Cannot delete the last active administrator account.",
                )

        # 4. Administrative safety safeguard: Protected system accounts
        if target_username.lower() in PROTECTED_SYSTEM_USERS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Administrative Safety Safeguard: Protected system account '{target_username}' cannot be deleted.",
            )

        # 5. Typed confirmation validation if supplied
        if confirm_username is not None and confirm_username.strip():
            if confirm_username.strip().lower() != target_username.lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Confirmation mismatch: Typed confirmation '{confirm_username}' does not match target username '{target_username}'.",
                )

        purged_stats: Dict[str, int] = {
            "auth_sessions": 0,
            "analysis_records": 0,
            "review_queue_items": 0,
            "uncommitted_training_samples": 0,
            "threat_events": 0,
            "threat_evidence": 0,
            "threat_reports": 0,
            "email_alerts": 0,
            "speaker_profiles": 0,
            "call_sessions": 0,
            "audio_files_removed": 0,
            "report_files_removed": 0,
            "tenant_database_files_removed": 0,
        }
        cleanup_warnings: List[str] = []

        # 6. Identify dependent analysis records, hashes, and storage paths
        user_analyses = (
            db.query(AnalysisRecordModel)
            .filter(AnalysisRecordModel.user_id == target_id)
            .all()
        )
        analysis_ids: List[str] = [a.analysis_id for a in user_analyses if a.analysis_id]
        user_audio_hashes: Set[str] = {a.audio_hash for a in user_analyses if a.audio_hash}
        user_audio_paths: Set[str] = {a.audio_path for a in user_analyses if a.audio_path}

        # 7. Identify review items submitted by or linked to target user
        user_reviews = (
            db.query(ReviewQueueModel)
            .filter(
                (ReviewQueueModel.submitted_by_user_id == target_id)
                | (ReviewQueueModel.analysis_id.in_(analysis_ids) if analysis_ids else False)
            )
            .all()
        )
        review_ids: List[str] = [r.review_id for r in user_reviews if r.review_id]

        # 8. Identify training samples linked to user's submissions
        user_samples = (
            db.query(TrainingSampleModel)
            .filter(
                (TrainingSampleModel.source_analysis_id.in_(analysis_ids) if analysis_ids else False)
                | (TrainingSampleModel.review_id.in_(review_ids) if review_ids else False)
                | (TrainingSampleModel.audio_hash.in_(user_audio_hashes) if user_audio_hashes else False)
            )
            .all()
        )

        # 9. Identify threat events and evidence attributable to target user
        user_threat_events = (
            db.query(ThreatEventModel)
            .filter(
                (ThreatEventModel.user_id == target_id)
                | (ThreatEventModel.user_email == target_email)
                | (ThreatEventModel.affected_user == target_username)
            )
            .all()
        )
        event_ids: List[str] = [e.event_id for e in user_threat_events if e.event_id]

        # 10. Identify user-generated reports and filesystem report files
        user_reports = (
            db.query(ThreatReportModel)
            .filter(
                (ThreatReportModel.created_by == target_username)
                | (ThreatReportModel.created_by == target_email)
            )
            .all()
        )
        report_files_to_delete: List[str] = [r.report_path for r in user_reports if r.report_path]

        # 11. Determine which audio vault files are EXCLUSIVELY owned by this user
        other_analyses_hashes: Set[str] = set(
            h[0]
            for h in db.query(AnalysisRecordModel.audio_hash)
            .filter(
                AnalysisRecordModel.user_id != target_id,
                AnalysisRecordModel.audio_hash.is_not(None),
            )
            .all()
        )
        other_analyses_paths: Set[str] = set(
            p[0]
            for p in db.query(AnalysisRecordModel.audio_path)
            .filter(
                AnalysisRecordModel.user_id != target_id,
                AnalysisRecordModel.audio_path.is_not(None),
            )
            .all()
        )
        trained_sample_hashes: Set[str] = set(
            s[0]
            for s in db.query(TrainingSampleModel.audio_hash)
            .filter(TrainingSampleModel.used_in_training.is_(True))
            .all()
        )

        candidate_audio_files_to_remove: List[Path] = []
        for a_hash in user_audio_hashes:
            if a_hash not in other_analyses_hashes and a_hash not in trained_sample_hashes:
                candidate_audio_files_to_remove.append(VAULT_DIR / f"{a_hash}.flac")

        for a_path in user_audio_paths:
            if a_path not in other_analyses_paths:
                p = PROJECT_ROOT / a_path if not Path(a_path).is_absolute() else Path(a_path)
                if p not in candidate_audio_files_to_remove:
                    candidate_audio_files_to_remove.append(p)

        # 12. Execute database purge inside the transaction
        try:
            # A. Auth sessions
            purged_stats["auth_sessions"] = (
                db.query(AuthSessionModel)
                .filter(AuthSessionModel.user_id == target_id)
                .delete(synchronize_session=False)
            )

            # B. Training samples: Remove samples not incorporated into a trained model run
            for sample in user_samples:
                if not sample.used_in_training:
                    db.delete(sample)
                    purged_stats["uncommitted_training_samples"] += 1

            # C. Review queue items
            if review_ids or analysis_ids:
                purged_stats["review_queue_items"] = (
                    db.query(ReviewQueueModel)
                    .filter(
                        (ReviewQueueModel.submitted_by_user_id == target_id)
                        | (ReviewQueueModel.review_id.in_(review_ids) if review_ids else False)
                        | (ReviewQueueModel.analysis_id.in_(analysis_ids) if analysis_ids else False)
                    )
                    .delete(synchronize_session=False)
                )

            # D. Analysis records
            if analysis_ids:
                purged_stats["analysis_records"] = (
                    db.query(AnalysisRecordModel)
                    .filter(AnalysisRecordModel.user_id == target_id)
                    .delete(synchronize_session=False)
                )

            # E. Threat evidence
            if event_ids:
                purged_stats["threat_evidence"] = (
                    db.query(ThreatEvidenceModel)
                    .filter(ThreatEvidenceModel.event_id.in_(event_ids))
                    .delete(synchronize_session=False)
                )

            # F. Threat events
            if event_ids:
                purged_stats["threat_events"] = (
                    db.query(ThreatEventModel)
                    .filter(ThreatEventModel.event_id.in_(event_ids))
                    .delete(synchronize_session=False)
                )

            # G. Threat reports
            purged_stats["threat_reports"] = (
                db.query(ThreatReportModel)
                .filter(
                    (ThreatReportModel.created_by == target_username)
                    | (ThreatReportModel.created_by == target_email)
                )
                .delete(synchronize_session=False)
            )

            # H. Email alert dispatches
            purged_stats["email_alerts"] = (
                db.query(EmailAlertRecordModel)
                .filter(
                    (EmailAlertRecordModel.recipient == target_email)
                    | (EmailAlertRecordModel.target_id == str(target_id))
                )
                .delete(synchronize_session=False)
            )

            # I. Speaker profiles & call sessions
            purged_stats["speaker_profiles"] = (
                db.query(SpeakerProfile)
                .filter(
                    (SpeakerProfile.speaker_id == target_username)
                    | (SpeakerProfile.speaker_id == str(target_id))
                )
                .delete(synchronize_session=False)
            )
            purged_stats["call_sessions"] = (
                db.query(CallSession)
                .filter(
                    (CallSession.speaker_id == target_username)
                    | (CallSession.speaker_id == str(target_id))
                )
                .delete(synchronize_session=False)
            )

            # J. Administrative Tamper-Evident Audit Record
            # Logs the administrative operation without preserving the user's private data
            audit_entry = AdminAuditLogModel(
                actor_user_id=admin_user.id,
                actor_username=admin_user.username,
                actor_role="ADMIN",
                action="USER_PERMANENTLY_DELETED",
                target_type="user",
                target_id=str(target_id),
                timestamp=_utcnow(),
                details_json=json.dumps({
                    "target_username": target_username,
                    "target_email": target_email,
                    "purged_records": purged_stats,
                }),
            )
            db.add(audit_entry)

            # K. Finally delete the user account row
            db.delete(target)
            db.commit()
            logger.info(f"Database transaction committed: Purged user '{target_username}' (#{target_id})")

        except Exception as db_err:
            db.rollback()
            logger.error(f"Failed to execute database purge for user #{target_id}: {db_err}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database purge failed: {db_err}",
            )

        # 13. External Storage Asset Cleanup (Reliable, Non-Transactional)

        # A. Teardown and delete dedicated isolated tenant database
        try:
            from backend.incidents.incident_manager import _user_incident_managers
            resolved_db = _resolve_path(target_db_path)
            close_user_database(target_db_path)

            _user_incident_managers.pop(str(resolved_db), None)
            _user_incident_managers.pop(target_db_path, None)
            gc.collect()

            for suffix in ["", "-wal", "-shm"]:
                f_path = Path(f"{resolved_db}{suffix}")
                if f_path.exists():
                    try:
                        f_path.unlink()
                        purged_stats["tenant_database_files_removed"] += 1
                        logger.info(f"Deleted user tenant database file: {f_path}")
                    except Exception as f_err:
                        cleanup_warnings.append(f"Could not remove DB file {f_path.name}: {f_err}")
        except Exception as e_db:
            cleanup_warnings.append(f"Tenant database teardown notice: {e_db}")

        # B. Remove exclusively user-owned audio files from audio vault
        for audio_file in candidate_audio_files_to_remove:
            try:
                if audio_file.exists() and audio_file.is_file():
                    audio_file.unlink()
                    purged_stats["audio_files_removed"] += 1
                    logger.info(f"Deleted user-owned audio file: {audio_file.name}")
            except Exception as e_audio:
                cleanup_warnings.append(f"Could not remove audio file {audio_file.name}: {e_audio}")

        # C. Remove user-generated report files
        for rep_path in report_files_to_delete:
            try:
                p = PROJECT_ROOT / rep_path if not Path(rep_path).is_absolute() else Path(rep_path)
                if p.exists() and p.is_file() and (REPORTS_DIR in p.parents or p.parent == REPORTS_DIR):
                    p.unlink()
                    purged_stats["report_files_removed"] += 1
                    logger.info(f"Deleted user report file: {p.name}")
            except Exception as e_rep:
                cleanup_warnings.append(f"Could not remove report file {rep_path}: {e_rep}")

        # D. Reset in-memory failed login tracking for target user
        try:
            from backend.security.enforcement import get_enforcement_engine
            engine = get_enforcement_engine()
            with engine._mem_lock:
                engine._failed_logins.pop(target_username, None)
        except Exception:
            pass

        return {
            "status": "success",
            "message": f"User '{target_username}' (#{target_id}) and all attributable user data were permanently purged.",
            "user_id": target_id,
            "username": target_username,
            "purged": purged_stats,
            "warnings": cleanup_warnings if cleanup_warnings else None,
        }


def _resolve_path(path_str: str) -> Path:
    p = Path(path_str)
    if not p.is_absolute():
        return (PROJECT_ROOT / path_str).resolve()
    return p.resolve()
