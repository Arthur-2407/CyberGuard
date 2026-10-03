"""
routes_admin.py — Dedicated administrative endpoints for CyberGuard.

Strictly protected by require_admin dependency.
Covers:
  - User management (NO plaintext passwords exposed anywhere)
  - Analysis & Training Review Queue
  - Audio playback streaming for verified admins
  - Ground-truth labeling & training approval
  - Continuous learning triggers & validation reports
  - Model promotion & rollback controls
  - Tamper-evident administrative audit logs
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from backend.services.continuous_learning import ContinuousLearningService
from backend.storage.auth import ROLE_ADMIN, ROLE_USER, AuthService, hash_password, require_admin
from backend.storage.database import (
    AdminAuditLogModel,
    AnalysisRecordModel,
    ModelVersionModel,
    ReviewQueueModel,
    TrainingRunModel,
    TrainingSampleModel,
    UserModel,
    get_db_session,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["Admin Operations"])
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ── Pydantic Request & Response Schemas ────────────────────────────────────────

class AdminUserItem(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None
    password_changed_at: Optional[str] = None
    failed_login_count: int = 0
    reset_required: bool = False


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = ROLE_USER


class UpdateUserStatusRequest(BaseModel):
    is_active: Optional[bool] = None
    reset_required: Optional[bool] = None
    new_password: Optional[str] = None


class ReviewDecisionRequest(BaseModel):
    ground_truth: str  # BONAFIDE, SPOOF, INCONCLUSIVE, REJECT
    notes: Optional[str] = None


class PromoteModelRequest(BaseModel):
    run_id: str
    reason: Optional[str] = None


class RollbackModelRequest(BaseModel):
    target_version: str


# ── User Management Endpoints ──────────────────────────────────────────────────

@router.get("/users", response_model=List[AdminUserItem])
async def list_users(
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """List all registered users. Passwords are NEVER included in response."""
    users = db.query(UserModel).order_by(UserModel.id.asc()).all()
    return [
        AdminUserItem(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() if u.created_at else None,
            last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            password_changed_at=u.password_changed_at.isoformat() if u.password_changed_at else None,
            failed_login_count=u.failed_login_count or 0,
            reset_required=bool(u.reset_required),
        )
        for u in users
    ]


@router.post("/users", response_model=AdminUserItem)
async def create_user_by_admin(
    req: CreateUserRequest,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Admin creates a user or another admin."""
    try:
        user = AuthService.create_user(
            db=db,
            username=req.username,
            email=req.email,
            password=req.password,
            role=req.role,
            actor_id=admin.id,
        )
        return AdminUserItem(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else None,
            last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.put("/users/{user_id}/status")
async def update_user_status(
    user_id: int,
    req: UpdateUserStatusRequest,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Activate/deactivate user, or reset user password."""
    target = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    changes = {}
    if req.is_active is not None:
        target.is_active = req.is_active
        changes["is_active"] = req.is_active
    if req.reset_required is not None:
        target.reset_required = req.reset_required
        changes["reset_required"] = req.reset_required
    if req.new_password:
        target.password_hash = hash_password(req.new_password)
        changes["password_reset"] = True

    db.commit()

    AuthService.log_admin_action(
        db,
        actor_user_id=admin.id,
        actor_role="ADMIN",
        action="USER_STATUS_UPDATED",
        target_type="user",
        target_id=str(user_id),
        details=changes,
    )
    return {"status": "success", "user_id": user_id, "changes": changes}


# ── Review Queue Endpoints ─────────────────────────────────────────────────────

@router.get("/reviews")
async def list_review_items(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = 50,
    offset: int = 0,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Fetch review queue items with joined analysis telemetry."""
    query = db.query(ReviewQueueModel, AnalysisRecordModel).join(
        AnalysisRecordModel, ReviewQueueModel.analysis_id == AnalysisRecordModel.analysis_id
    )
    if status_filter:
        query = query.filter(ReviewQueueModel.status == status_filter.upper())

    records = query.order_by(ReviewQueueModel.id.desc()).offset(offset).limit(limit).all()

    items = []
    for r_item, a_item in records:
        submitter = db.query(UserModel).filter(UserModel.id == r_item.submitted_by_user_id).first() if r_item.submitted_by_user_id else None
        items.append({
            "review_id": r_item.review_id,
            "analysis_id": a_item.analysis_id,
            "submitted_by": submitter.username if submitter else "Guest / System",
            "filename": a_item.filename,
            "duration_sec": a_item.duration_sec,
            "native_probability": a_item.native_probability,
            "aasist_probability": a_item.aasist_probability,
            "peak_risk": a_item.peak_risk,
            "alert_level": a_item.alert_level,
            "detector_version": a_item.detector_version,
            "status": r_item.status,
            "ground_truth_label": r_item.ground_truth_label,
            "approved_for_training": r_item.approved_for_training,
            "rejection_reason": r_item.rejection_reason,
            "created_at": r_item.created_at.isoformat() if r_item.created_at else None,
            "has_audio": bool(a_item.audio_path and (PROJECT_ROOT / a_item.audio_path).exists()),
        })

    total_pending = db.query(ReviewQueueModel).filter(ReviewQueueModel.status == "PENDING").count()
    total_approved = db.query(ReviewQueueModel).filter(ReviewQueueModel.status == "APPROVED").count()

    return {
        "items": items,
        "total_pending": total_pending,
        "total_approved": total_approved,
    }


@router.get("/reviews/{review_id}/audio")
async def stream_review_audio(
    review_id: str,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Stream audio recording for admin review playback."""
    review = db.query(ReviewQueueModel).filter(ReviewQueueModel.review_id == review_id).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review item not found.")

    analysis = db.query(AnalysisRecordModel).filter(
        AnalysisRecordModel.analysis_id == review.analysis_id
    ).first()
    if not analysis or not analysis.audio_path:
        raise HTTPException(status_code=404, detail="Audio file not retained for this analysis.")

    audio_file = PROJECT_ROOT / analysis.audio_path
    if not audio_file.exists():
        raise HTTPException(status_code=404, detail="Audio file not found on disk.")

    media_type = "audio/flac" if audio_file.suffix == ".flac" else "audio/mpeg"
    return FileResponse(str(audio_file), media_type=media_type, filename=audio_file.name)


@router.post("/reviews/{review_id}/decision")
async def submit_review_decision(
    review_id: str,
    req: ReviewDecisionRequest,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Admin confirms ground truth and chooses whether to approve sample for training."""
    try:
        result = ContinuousLearningService.approve_review_sample(
            db=db,
            review_id=review_id,
            ground_truth=req.ground_truth,
            admin_id=admin.id,
            admin_username=admin.username,
            notes=req.notes,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Retraining & Validation Endpoints ─────────────────────────────────────────

@router.get("/training/status")
async def get_training_pipeline_status(
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Get active training status, un-used sample count, and recent runs."""
    active_run = db.query(TrainingRunModel).filter(
        TrainingRunModel.status.in_(["RUNNING", "VALIDATING"])
    ).first()

    recent_runs = db.query(TrainingRunModel).order_by(TrainingRunModel.id.desc()).limit(10).all()
    approved_unprocessed = db.query(TrainingSampleModel).filter(
        TrainingSampleModel.used_in_training.is_(False)
    ).count()

    active_version = db.query(ModelVersionModel).filter(
        ModelVersionModel.status == "ACTIVE"
    ).order_by(ModelVersionModel.id.desc()).first()

    return {
        "is_training": bool(active_run),
        "active_run": {
            "run_id": active_run.run_id,
            "status": active_run.status,
            "started_at": active_run.started_at.isoformat() if active_run.started_at else None,
            "sample_count": active_run.sample_count,
        } if active_run else None,
        "approved_samples_in_queue": approved_unprocessed,
        "current_production_version": active_version.version if active_version else "v001",
        "recent_runs": [
            {
                "run_id": r.run_id,
                "status": r.status,
                "base_version": r.base_model_version,
                "candidate_version": r.candidate_model_version,
                "sample_count": r.sample_count,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "candidate_sha256": r.candidate_sha256,
                "validation_metrics": json.loads(r.validation_metrics_json or "{}"),
                "failure_reason": r.failure_reason,
            }
            for r in recent_runs
        ],
    }


@router.post("/training/trigger")
async def trigger_retraining_job(
    epochs: int = Query(5, ge=1, le=50),
    learning_rate: float = Query(1e-4, ge=1e-6, le=1e-2),
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Manually initiate a controlled background retraining job."""
    try:
        result = ContinuousLearningService.start_retraining_job(
            db=db,
            admin_id=admin.id,
            admin_username=admin.username,
            epochs=epochs,
            lr=learning_rate,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Model Registry, Promotion & Rollback Endpoints ─────────────────────────────

@router.get("/models")
async def list_model_versions(
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Fetch complete lineage of production and archived model versions."""
    versions = db.query(ModelVersionModel).order_by(ModelVersionModel.id.desc()).all()
    return [
        {
            "version": m.version,
            "status": m.status,
            "checkpoint_path": m.checkpoint_path,
            "sha256": m.sha256,
            "file_size_bytes": m.file_size,
            "parent_version": m.parent_version,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "promoted_at": m.promoted_at.isoformat() if m.promoted_at else None,
            "promotion_reason": m.promotion_reason,
            "validation_metrics": json.loads(m.validation_metrics_json or "{}"),
        }
        for m in versions
    ]


@router.post("/models/promote")
async def promote_model_candidate(
    req: PromoteModelRequest,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Promote validated candidate checkpoint to active production detector.pt."""
    try:
        result = ContinuousLearningService.promote_candidate_model(
            db=db,
            run_id=req.run_id,
            admin_id=admin.id,
            admin_username=admin.username,
            reason=req.reason,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/models/rollback")
async def rollback_to_previous_model(
    req: RollbackModelRequest,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Instantly roll back production detector.pt to an earlier checkpoint."""
    try:
        result = ContinuousLearningService.rollback_model(
            db=db,
            target_version=req.target_version,
            admin_id=admin.id,
            admin_username=admin.username,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Audit Log Endpoints ────────────────────────────────────────────────────────

@router.get("/audit-logs")
async def get_admin_audit_logs(
    limit: int = 50,
    offset: int = 0,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """View administrative audit trail."""
    logs = db.query(AdminAuditLogModel).order_by(AdminAuditLogModel.id.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": l.id,
            "actor_username": l.actor_username or "System",
            "actor_role": l.actor_role,
            "action": l.action,
            "target_type": l.target_type,
            "target_id": l.target_id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "details": json.loads(l.details_json or "{}"),
        }
        for l in logs
    ]
