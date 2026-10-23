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

import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
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
WEIGHTS_DIR = PROJECT_ROOT / "backend" / "models" / "weights"


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
    review_id: Optional[str] = None
    ground_truth: Optional[str] = None  # BONAFIDE, SPOOF, INCONCLUSIVE, REJECT
    label: Optional[str] = None
    ground_truth_label: Optional[str] = None
    decision: Optional[str] = None      # APPROVE, REJECT
    approve_for_training: Optional[bool] = None
    notes: Optional[str] = None
    auto_update_detector: Optional[bool] = False
    trigger_training: Optional[bool] = False


class ManualDetectorUpdateRequest(BaseModel):
    review_id: Optional[str] = None
    analysis_id: Optional[str] = None
    label: str  # "HUMAN" / "BONAFIDE" or "CLONED" / "SPOOF"
    notes: Optional[str] = None
    learning_rate: Optional[float] = 1e-4
    steps: Optional[int] = 3


class RetrainTriggerRequest(BaseModel):
    epochs: Optional[int] = 5
    learning_rate: Optional[float] = 1e-4


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
@router.patch("/users/{user_id}/status")
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
@router.get("/review/queue")
async def list_review_items(
    status_filter: Optional[str] = Query(None, alias="status"),
    risk_filter: Optional[str] = Query(None, alias="risk"),
    ground_truth_filter: Optional[str] = Query(None, alias="ground_truth"),
    search: Optional[str] = Query(None, alias="q"),
    limit: int = 100,
    offset: int = 0,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Fetch review queue items with joined analysis telemetry and filter parameters."""
    query = db.query(ReviewQueueModel, AnalysisRecordModel).join(
        AnalysisRecordModel, ReviewQueueModel.analysis_id == AnalysisRecordModel.analysis_id
    )

    if status_filter and status_filter.upper() != "ALL":
        query = query.filter(ReviewQueueModel.status == status_filter.upper())

    if risk_filter and risk_filter.upper() != "ALL":
        query = query.filter(AnalysisRecordModel.alert_level == risk_filter.upper())

    if ground_truth_filter and ground_truth_filter.upper() != "ALL":
        gt_target = ground_truth_filter.upper()
        if gt_target == "UNKNOWN":
            query = query.filter(ReviewQueueModel.ground_truth_label.is_(None))
        else:
            query = query.filter(ReviewQueueModel.ground_truth_label == gt_target)

    if search and search.strip():
        q_term = f"%{search.strip()}%"
        query = query.filter(
            (AnalysisRecordModel.filename.ilike(q_term)) |
            (ReviewQueueModel.review_id.ilike(q_term)) |
            (AnalysisRecordModel.analysis_id.ilike(q_term))
        )

    records = query.order_by(ReviewQueueModel.id.desc()).offset(offset).limit(limit).all()

    items = []
    for r_item, a_item in records:
        submitter = db.query(UserModel).filter(UserModel.id == r_item.submitted_by_user_id).first() if r_item.submitted_by_user_id else None
        username = submitter.username if submitter else "Guest / System"

        # Check audio presence
        has_audio = False
        if a_item.audio_path and (PROJECT_ROOT / a_item.audio_path).exists():
            has_audio = True
        elif a_item.audio_hash and (PROJECT_ROOT / "data" / "audio_vault" / f"{a_item.audio_hash}.flac").exists():
            has_audio = True

        items.append({
            "id": r_item.review_id,
            "review_id": r_item.review_id,
            "analysis_id": a_item.analysis_id,
            "username": username,
            "submitted_by": username,
            "filename": a_item.filename or "unknown",
            "duration_s": float(a_item.duration_sec or 0.0),
            "duration_sec": float(a_item.duration_sec or 0.0),
            "synthetic_prob": float(a_item.native_probability) if a_item.native_probability is not None else None,
            "native_probability": float(a_item.native_probability) if a_item.native_probability is not None else None,
            "aasist_probability": float(a_item.aasist_probability) if a_item.aasist_probability is not None else None,
            "peak_risk": float(a_item.peak_risk or 0.0),
            "risk_score": float(a_item.peak_risk or 0.0),
            "risk_level": a_item.alert_level or "SAFE",
            "alert_level": a_item.alert_level or "SAFE",
            "detector_version": a_item.detector_version or "v010",
            "status": r_item.status,
            "assigned_label": r_item.ground_truth_label,
            "ground_truth_label": r_item.ground_truth_label,
            "approved_for_training": bool(r_item.approved_for_training),
            "rejection_reason": r_item.rejection_reason,
            "analyst_notes": r_item.notes,
            "notes": r_item.notes,
            "audio_hash": a_item.audio_hash or "unknown",
            "created_at": r_item.created_at.isoformat() if r_item.created_at else None,
            "reviewed_at": r_item.reviewed_at.isoformat() if r_item.reviewed_at else None,
            "has_audio": has_audio,
        })

    # Exact database aggregations for internal consistency
    total_count = db.query(ReviewQueueModel).count()
    total_pending = db.query(ReviewQueueModel).filter(ReviewQueueModel.status == "PENDING").count()
    total_approved = db.query(ReviewQueueModel).filter(ReviewQueueModel.status == "APPROVED").count()
    total_rejected = db.query(ReviewQueueModel).filter(ReviewQueueModel.status == "REJECTED").count()
    total_inconclusive = db.query(ReviewQueueModel).filter(ReviewQueueModel.ground_truth_label == "INCONCLUSIVE").count()
    total_rejected_or_inconclusive = db.query(ReviewQueueModel).filter(
        (ReviewQueueModel.status == "REJECTED") | (ReviewQueueModel.ground_truth_label == "INCONCLUSIVE")
    ).count()
    total_training_queued = db.query(TrainingSampleModel).filter(TrainingSampleModel.used_in_training.is_(False)).count()

    active_mv = db.query(ModelVersionModel).filter(ModelVersionModel.status == "ACTIVE").order_by(ModelVersionModel.id.desc()).first()
    if active_mv:
        active_ver = active_mv.version
    else:
        manifest_p = WEIGHTS_DIR / "detector_manifest.json"
        if manifest_p.exists():
            try:
                m_data = json.loads(manifest_p.read_text(encoding="utf-8"))
                active_ver = m_data.get("version", "v011")
            except Exception:
                active_ver = "v011"
        else:
            active_ver = "v011"

    is_training_active = ContinuousLearningService.is_active_training()
    last_run = db.query(TrainingRunModel).order_by(TrainingRunModel.id.desc()).first()
    if last_run and last_run.status in ("RUNNING", "VALIDATING") and not is_training_active:
        last_run.status = "FAILED"
        last_run.failure_reason = "Run interrupted by process restart"
        db.commit()

    cand_info = {
        "run_id": last_run.run_id,
        "status": last_run.status,
        "candidate_version": last_run.candidate_model_version or ("Candidate" if last_run.status in ("RUNNING", "VALIDATING", "COMPLETED") else "STANDBY"),
        "sample_count": last_run.sample_count,
        "metrics": json.loads(last_run.validation_metrics_json or "{}") if last_run.validation_metrics_json else {},
    } if last_run else None

    return {
        "items": items,
        "total": total_count,
        "total_count": total_count,
        "total_pending": total_pending,
        "total_approved": total_approved,
        "total_rejected": total_rejected,
        "total_inconclusive": total_inconclusive,
        "total_rejected_or_inconclusive": total_rejected_or_inconclusive,
        "total_training_queued": total_training_queued,
        "active_model_version": active_ver,
        "candidate_info": cand_info,
        "last_run": cand_info,
    }


@router.get("/reviews/{review_id}")
@router.get("/review/item/{review_id}")
async def get_review_detail(
    review_id: str,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Retrieve deep forensics detail for a specific review queue entry."""
    review = db.query(ReviewQueueModel).filter(
        (ReviewQueueModel.review_id == str(review_id)) |
        (ReviewQueueModel.id == (int(review_id) if str(review_id).isdigit() else -1)) |
        (ReviewQueueModel.analysis_id == str(review_id))
    ).first()

    analysis = None
    if review:
        analysis = db.query(AnalysisRecordModel).filter(
            AnalysisRecordModel.analysis_id == review.analysis_id
        ).first()
    else:
        analysis = db.query(AnalysisRecordModel).filter(
            AnalysisRecordModel.analysis_id == str(review_id)
        ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Associated analysis record not found.")

    # Synthesize or extract review representation
    rev_id_str = review.review_id if review else f"REV_{analysis.analysis_id}"
    rev_status = review.status if review else "PENDING"
    gt_label = review.ground_truth_label if review else None
    approved_train = bool(review.approved_for_training) if review else False
    rej_reason = review.rejection_reason if review else None
    rev_notes = review.notes if review else None
    created_ts = review.created_at.isoformat() if review and review.created_at else (analysis.created_at.isoformat() if analysis.created_at else None)
    reviewed_ts = review.reviewed_at.isoformat() if review and review.reviewed_at else None

    submitter = db.query(UserModel).filter(UserModel.id == review.submitted_by_user_id).first() if review and review.submitted_by_user_id else None
    reviewer = db.query(UserModel).filter(UserModel.id == review.reviewer_admin_id).first() if review and review.reviewer_admin_id else None

    has_audio = False
    if analysis.audio_path and (PROJECT_ROOT / analysis.audio_path).exists():
        has_audio = True
    elif analysis.audio_hash and (PROJECT_ROOT / "data" / "audio_vault" / f"{analysis.audio_hash}.flac").exists():
        has_audio = True

    # Audit history for this item
    target_ids = [analysis.analysis_id]
    if review:
        target_ids.append(review.review_id)
    audits = db.query(AdminAuditLogModel).filter(
        AdminAuditLogModel.target_id.in_(target_ids)
    ).order_by(AdminAuditLogModel.id.desc()).all()

    audit_list = [
        {
            "id": a.id,
            "action": a.action,
            "actor": a.actor_username or "System",
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "details": a.details_json or "",
        }
        for a in audits
    ]

    return {
        "review_id": rev_id_str,
        "analysis_id": analysis.analysis_id,
        "filename": analysis.filename or "unknown",
        "audio_hash": analysis.audio_hash or "unknown",
        "has_audio": has_audio,
        "audio_url": f"/api/admin/review/audio/{rev_id_str}",
        "duration_sec": float(analysis.duration_sec or 0.0),
        "total_chunks": int(analysis.total_chunks or 1),
        "native_probability": float(analysis.native_probability) if analysis.native_probability is not None else None,
        "aasist_probability": float(analysis.aasist_probability) if analysis.aasist_probability is not None else None,
        "peak_risk": float(analysis.peak_risk or 0.0),
        "alert_level": analysis.alert_level or "SAFE",
        "detector_version": analysis.detector_version or "v011",
        "status": rev_status,
        "ground_truth_label": gt_label,
        "approved_for_training": approved_train,
        "rejection_reason": rej_reason,
        "notes": rev_notes,
        "submitted_by": submitter.username if submitter else "Guest / System",
        "reviewed_by": reviewer.username if reviewer else None,
        "created_at": created_ts,
        "reviewed_at": reviewed_ts,
        "metadata": json.loads(analysis.metadata_json or "{}") if analysis.metadata_json else {},
        "audit_trail": audit_list,
    }


@router.get("/reviews/{review_id}/audio")
@router.get("/review/audio/{review_id}")
async def stream_review_audio(
    review_id: str,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Stream audio recording for authorized admin review playback."""
    review = db.query(ReviewQueueModel).filter(
        (ReviewQueueModel.review_id == str(review_id)) |
        (ReviewQueueModel.id == (int(review_id) if str(review_id).isdigit() else -1)) |
        (ReviewQueueModel.analysis_id == str(review_id))
    ).first()
    analysis = None
    if review:
        analysis = db.query(AnalysisRecordModel).filter(
            AnalysisRecordModel.analysis_id == review.analysis_id
        ).first()
    else:
        analysis = db.query(AnalysisRecordModel).filter(
            AnalysisRecordModel.analysis_id == str(review_id)
        ).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Audio file not retained for this analysis.")

    audio_file = None
    if analysis.audio_path:
        p = PROJECT_ROOT / analysis.audio_path
        if p.exists():
            audio_file = p

    if not audio_file and analysis.audio_hash:
        p = PROJECT_ROOT / "data" / "audio_vault" / f"{analysis.audio_hash}.flac"
        if p.exists():
            audio_file = p

    if not audio_file or not audio_file.exists():
        raise HTTPException(status_code=404, detail="Audio file not found on disk.")

    ext = audio_file.suffix.lower()
    if ext == ".flac":
        media_type = "audio/flac"
    elif ext == ".mp3":
        media_type = "audio/mpeg"
    elif ext == ".wav":
        media_type = "audio/wav"
    else:
        media_type = "application/octet-stream"

    return FileResponse(
        str(audio_file),
        media_type=media_type,
        filename=audio_file.name,
        headers={"Accept-Ranges": "bytes", "Cache-Control": "private, no-cache"}
    )


@router.post("/reviews/{review_id}/decision")
@router.post("/review/decision")
async def submit_review_decision(
    req: ReviewDecisionRequest,
    review_id: Optional[str] = None,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Admin confirms ground truth and separately chooses whether to approve sample for training."""
    target_id = review_id or req.review_id
    if not target_id:
        raise HTTPException(status_code=400, detail="Missing review_id.")

    gt = req.ground_truth or req.label or req.ground_truth_label
    if not gt:
        raise HTTPException(status_code=400, detail="Missing ground-truth label.")

    review = db.query(ReviewQueueModel).filter(
        (ReviewQueueModel.review_id == str(target_id)) |
        (ReviewQueueModel.id == (int(target_id) if str(target_id).isdigit() else -1)) |
        (ReviewQueueModel.analysis_id == str(target_id))
    ).first()
    if not review:
        raise HTTPException(status_code=404, detail=f"Review item {target_id} not found.")

    auto_update = bool(req.auto_update_detector) if req.auto_update_detector is not None else False
    trigger_train = bool(req.trigger_training) if req.trigger_training is not None else False
    try:
        result = ContinuousLearningService.approve_review_sample(
            db=db,
            review_id=review.review_id,
            ground_truth=gt,
            admin_id=admin.id,
            admin_username=admin.username,
            notes=req.notes,
            auto_update_detector=auto_update,
            approve_for_training=req.approve_for_training,
            decision=req.decision,
            trigger_training=trigger_train,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/detector/manual-update")
async def manual_detector_update(
    label: str = Form(...),
    review_id: Optional[str] = Form(None),
    analysis_id: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    learning_rate: Optional[float] = Form(1e-4),
    steps: Optional[int] = Form(3),
    audio_file: Optional[UploadFile] = File(None),
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """
    Manual mechanism where admin directly classifies audio as Human Voice or Cloned Voice,
    immediately modifying and auto-updating detector.py.
    """
    audio_bytes = None
    filename = None
    if audio_file:
        audio_bytes = await audio_file.read()
        filename = audio_file.filename

    try:
        result = ContinuousLearningService.manual_label_and_update_detector(
            db=db,
            admin_id=admin.id,
            admin_username=admin.username,
            ground_truth=label,
            audio_bytes=audio_bytes,
            filename=filename,
            review_id=review_id,
            analysis_id=analysis_id,
            notes=notes,
            learning_rate=learning_rate or 1e-4,
            steps=steps or 3,
        )
        return result
    except Exception as exc:
        logger.error(f"Manual detector update failed: {exc}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/detector/manual-update-json")
async def manual_detector_update_json(
    req: ManualDetectorUpdateRequest,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """JSON variant of manual detector classification update."""
    try:
        result = ContinuousLearningService.manual_label_and_update_detector(
            db=db,
            admin_id=admin.id,
            admin_username=admin.username,
            ground_truth=req.label,
            review_id=req.review_id,
            analysis_id=req.analysis_id,
            notes=req.notes,
            learning_rate=req.learning_rate or 1e-4,
            steps=req.steps or 3,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Retraining & Validation Endpoints ─────────────────────────────────────────

@router.get("/training/status")
async def get_training_pipeline_status(
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Get active training status, un-used sample count, and recent runs."""
    is_actively_training = ContinuousLearningService.is_active_training()
    active_runs = db.query(TrainingRunModel).filter(
        TrainingRunModel.status.in_(["RUNNING", "VALIDATING"])
    ).all()

    if not is_actively_training and active_runs:
        for r in active_runs:
            cand_p = WEIGHTS_DIR / f"detector_candidate_{r.run_id}.pt"
            if cand_p.exists() and r.validation_metrics_json:
                r.status = "COMPLETED"
                r.candidate_checkpoint_path = str(cand_p.relative_to(PROJECT_ROOT))
            else:
                r.status = "FAILED"
                r.completed_at = _utcnow()
                r.failure_reason = "Run interrupted by process restart"
        db.commit()
        active_runs = []

    active_run = active_runs[0] if active_runs else None

    recent_runs = db.query(TrainingRunModel).order_by(TrainingRunModel.id.desc()).limit(10).all()
    approved_unprocessed = db.query(TrainingSampleModel).filter(
        TrainingSampleModel.used_in_training.is_(False)
    ).count()

    active_version = db.query(ModelVersionModel).filter(
        ModelVersionModel.status == "ACTIVE"
    ).order_by(ModelVersionModel.id.desc()).first()
    active_ver = active_version.version if active_version else "v001"

    prod_path = WEIGHTS_DIR / "detector.pt"
    prod_sha = hashlib.sha256(prod_path.read_bytes()).hexdigest() if prod_path.exists() else "unknown"

    formatted_runs = []
    for r in recent_runs:
        metrics = json.loads(r.validation_metrics_json or "{}")
        formatted_runs.append({
            "run_id": r.run_id,
            "status": r.status,
            "base_version": r.base_model_version,
            "candidate_version": r.candidate_model_version,
            "num_samples": r.sample_count,
            "sample_count": r.sample_count,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "candidate_sha256": r.candidate_sha256,
            "val_f1": metrics.get("f1"),
            "val_eer": metrics.get("eer"),
            "validation_metrics": metrics,
            "failure_reason": r.failure_reason,
        })

    return {
        "is_training": bool(active_run),
        "active_run": {
            "run_id": active_run.run_id,
            "status": active_run.status,
            "started_at": active_run.started_at.isoformat() if active_run.started_at else None,
            "sample_count": active_run.sample_count,
        } if active_run else None,
        "approved_samples_in_queue": approved_unprocessed,
        "approved_training_samples_waiting": approved_unprocessed,
        "current_production_version": active_ver,
        "active_version": active_ver,
        "weights_path": "backend/models/weights/detector.pt",
        "weights_sha256": prod_sha,
        "recent_runs": formatted_runs,
    }


@router.post("/training/trigger")
@router.post("/retrain/trigger")
async def trigger_retraining_job(
    req: Optional[RetrainTriggerRequest] = None,
    epochs: Optional[int] = Query(None, ge=1, le=50),
    learning_rate: Optional[float] = Query(None, ge=1e-6, le=1e-2),
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Manually initiate a controlled background retraining job."""
    ep = (req.epochs if req and req.epochs else None) or epochs or 5
    lr = (req.learning_rate if req and req.learning_rate else None) or learning_rate or 1e-4
    try:
        result = ContinuousLearningService.start_retraining_job(
            db=db,
            admin_id=admin.id,
            admin_username=admin.username,
            epochs=ep,
            lr=lr,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Model Registry, Promotion & Rollback Endpoints ─────────────────────────────

@router.get("/models")
@router.get("/model/versions")
async def list_model_versions(
    request: Request,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Fetch complete lineage of production and archived model versions."""
    versions = db.query(ModelVersionModel).order_by(ModelVersionModel.id.desc()).all()
    items = [
        {
            "version": m.version,
            "version_tag": m.version,
            "description": m.promotion_reason or f"Model {m.version}",
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
    active_m = next((m for m in versions if m.status == "ACTIVE"), None)
    active_ver = active_m.version if active_m else (items[0]["version"] if items else "v011")
    if request.url.path.endswith("/versions"):
        return {
            "versions": items,
            "current_production_version": active_ver,
            "active_version": active_ver,
        }
    return items


@router.post("/models/promote")
@router.post("/model/promote")
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
@router.post("/model/rollback")
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
@router.get("/audit-logs/")
@router.get("/audit")
@router.get("/audit/")
async def get_admin_audit_logs(
    limit: int = 50,
    offset: int = 0,
    admin: UserModel = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """View administrative audit trail."""
    logs = db.query(AdminAuditLogModel).order_by(AdminAuditLogModel.id.desc()).offset(offset).limit(limit).all()
    formatted = [
        {
            "id": l.id,
            "actor_username": l.actor_username or (f"User #{l.actor_user_id}" if l.actor_user_id else "System"),
            "actor_role": l.actor_role,
            "action": l.action,
            "target_entity": l.target_type,
            "target_type": l.target_type,
            "target_id": l.target_id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "created_at": l.timestamp.isoformat() if l.timestamp else None,
            "details": l.details_json or "",
        }
        for l in logs
    ]
    return {"logs": formatted, "total": len(formatted)}


# ── Organization Policy Configuration Endpoints ───────────────────────────────

class PolicyUpdateRequest(BaseModel):
    org_name: Optional[str] = None
    policy_name: Optional[str] = None
    security_level: Optional[str] = None
    enforcement_action: Optional[str] = None
    auto_block_critical_threats: Optional[bool] = None
    auto_block_threshold: Optional[float] = None
    auto_block_threat_score: Optional[float] = None
    ddos_protection_enabled: Optional[bool] = None
    ddos_rpm_limit: Optional[int] = None
    ddos_rate_limit_per_min: Optional[int] = None
    ddos_burst_limit: Optional[int] = None
    ddos_burst_threshold: Optional[int] = None
    failed_login_ban_threshold: Optional[int] = None
    ban_duration_minutes: Optional[int] = None
    email_alerts_enabled: Optional[bool] = None
    email_notifications_enabled: Optional[bool] = None
    alert_email_recipient: Optional[str] = None
    email_notification_recipients: Optional[Any] = None
    email_alert_threshold: Optional[str] = None
    email_minimum_severity: Optional[str] = None


class BlockEntityRequest(BaseModel):
    entity_type: str  # IP, DEVICE, DOMAIN, HASH
    entity_value: str
    reason: str
    severity: Optional[str] = "CRITICAL"
    duration_minutes: Optional[int] = 60
    duration_seconds: Optional[int] = None


class UnblockEntityRequest(BaseModel):
    entity_type: str
    entity_value: str


class GenerateReportRequest(BaseModel):
    report_type: Optional[str] = "INCIDENT"
    report_format: Optional[str] = "HTML"
    title: Optional[str] = None
    incident_id: Optional[str] = None


class TestEmailAlertRequest(BaseModel):
    severity: Optional[str] = "CRITICAL"
    subject: Optional[str] = None


PolicyUpdateRequest.model_rebuild()
BlockEntityRequest.model_rebuild()
UnblockEntityRequest.model_rebuild()
GenerateReportRequest.model_rebuild()
TestEmailAlertRequest.model_rebuild()


@router.get("/policy")
@router.get("/policies")
async def get_admin_policies(admin: UserModel = Depends(require_admin)):
    """Fetch live organization security policy and enforcement thresholds."""
    from backend.security.enforcement import get_enforcement_engine
    return get_enforcement_engine().get_policy()


@router.post("/policy")
@router.put("/policies")
async def update_admin_policies(
    req: PolicyUpdateRequest,
    admin: UserModel = Depends(require_admin),
):
    """Update organization security policy, DDoS limits, and containment rules."""
    from backend.security.enforcement import get_enforcement_engine
    engine = get_enforcement_engine()
    updates = req.model_dump(exclude_unset=True) if hasattr(req, "model_dump") else req.dict(exclude_unset=True)
    res = engine.update_policy(updates, actor_username=admin.username)
    return res


@router.post("/policies/reset")
async def reset_admin_policies(admin: UserModel = Depends(require_admin)):
    """Reset organization policies to factory default configuration."""
    from backend.security.enforcement import get_enforcement_engine
    engine = get_enforcement_engine()
    defaults = {
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
    }
    return engine.update_policy(defaults, actor_username=admin.username)


# ── Enforcement & Technical Containment Endpoints ─────────────────────────────

@router.get("/enforcement/status")
async def get_enforcement_telemetry(admin: UserModel = Depends(require_admin)):
    """Return real-time enforcement status, DDoS posture, and blocked entity metrics."""
    from backend.security.enforcement import get_enforcement_engine
    return get_enforcement_engine().get_enforcement_status()


@router.get("/enforcement/blocked")
async def list_blocked_entities(
    entity_type: Optional[str] = Query(None),
    admin: UserModel = Depends(require_admin),
):
    """List active blocked entities (IPs, devices, domains, hashes)."""
    from backend.security.enforcement import get_enforcement_engine
    return {"blocked": get_enforcement_engine().list_blocked_entities(entity_type=entity_type)}


@router.post("/enforcement/block")
async def block_entity_manually(
    req: BlockEntityRequest,
    admin: UserModel = Depends(require_admin),
):
    """Manually quarantine an IP, device fingerprint, domain, or malware hash."""
    from backend.security.enforcement import get_enforcement_engine
    engine = get_enforcement_engine()
    dur = req.duration_minutes
    if req.duration_seconds is not None:
        dur = max(1, req.duration_seconds // 60)
    res = engine.block_entity(
        entity_type=req.entity_type,
        entity_value=req.entity_value,
        reason=req.reason,
        severity=req.severity or "CRITICAL",
        duration_minutes=dur,
        blocked_by=admin.username,
    )
    if isinstance(res, dict) and "status" in res:
        res["status"] = str(res["status"]).lower()
    return res


@router.post("/enforcement/unblock")
async def unblock_entity_manually(
    req: UnblockEntityRequest,
    admin: UserModel = Depends(require_admin),
):
    """Remove quarantine block from an IP, device, domain, or hash."""
    from backend.security.enforcement import get_enforcement_engine
    engine = get_enforcement_engine()
    res = engine.unblock_entity(
        entity_type=req.entity_type,
        entity_value=req.entity_value,
        unblocked_by=admin.username,
    )
    if isinstance(res, dict) and "status" in res:
        res["status"] = str(res["status"]).lower()
    return res


# ── Email Notification Journal ────────────────────────────────────────────────

@router.get("/email-alerts")
@router.get("/alerts/emails")
async def get_email_alert_journal(
    limit: int = Query(50, ge=1, le=100),
    admin: UserModel = Depends(require_admin),
):
    """View recent threshold-triggered security alert emails dispatched by CyberGuard."""
    from backend.alerts.email_notifier import get_email_notifier
    notifier = get_email_notifier()
    emails = notifier.get_recent_email_alerts(limit=limit)
    return {"emails": emails, "email_alerts": emails}


@router.post("/email-alerts/test")
async def send_test_email_alert(
    req: TestEmailAlertRequest,
    admin: UserModel = Depends(require_admin),
):
    """Dispatch a simulated high-severity threshold alert to verify notification pipeline."""
    from backend.alerts.email_notifier import get_email_notifier
    from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation
    notifier = get_email_notifier()
    test_event = ThreatEvent(
        source="AdminTestConsole",
        source_type="manual_test",
        modality="security_test",
        threat_category=ThreatCategory.ANOMALOUS_BEHAVIOUR,
        severity=RiskLevel.CRITICAL if req.severity == "CRITICAL" else RiskLevel.HIGH,
        classification="TEST_ALERT",
        explanation=Explanation(
            summary=req.subject or "Simulated Executive Security Escalation Test",
            reasoning="Administrator manual verification of threshold email alert pipeline."
        ),
        detector="AdminTestDispatcher"
    )
    await notifier.notify_threat_event(test_event, custom_subject=req.subject)
    return {"status": "dispatched", "message": "Simulated security alert email logged and dispatched."}


# ── Threat Intelligence Reporting Endpoints ───────────────────────────────────

@router.get("/reports/export")
async def export_threat_report_direct(
    format: str = Query("html"),
    timeframe: str = Query("24h"),
    severity: Optional[str] = Query(None),
    admin: UserModel = Depends(require_admin),
):
    """Direct export/download of threat intelligence report by format and timeframe."""
    from backend.services.threat_reporter import get_threat_reporter
    reporter = get_threat_reporter()
    rep = reporter.generate_report(
        report_type="SOC_SUMMARY",
        report_format=format.upper(),
        title=f"CyberGuard Executive Threat Report ({timeframe.upper()})",
        created_by=admin.username,
    )
    rep_id = rep["report_id"]
    ext = format.lower().strip()
    target_file = reporter.output_dir / f"{rep_id}.{ext}"
    media_type = "text/html" if ext == "html" else ("application/json" if ext == "json" else "text/csv")
    return FileResponse(str(target_file), media_type=media_type, filename=f"CyberGuard-Threat-Report-{timeframe}.{ext}")


@router.get("/reports")
async def list_threat_reports(
    limit: int = Query(25, ge=1, le=100),
    admin: UserModel = Depends(require_admin),
):
    """List generated executive and technical threat intelligence reports."""
    from backend.services.threat_reporter import get_threat_reporter
    reporter = get_threat_reporter()
    return {"reports": reporter.list_reports(limit=limit)}


@router.post("/reports/generate")
async def generate_threat_report(
    req: GenerateReportRequest,
    admin: UserModel = Depends(require_admin),
):
    """Generate a formal executive or technical threat intelligence report."""
    from backend.services.threat_reporter import get_threat_reporter
    reporter = get_threat_reporter()
    return reporter.generate_report(
        report_type=req.report_type or "INCIDENT",
        report_format=req.report_format or "HTML",
        title=req.title,
        incident_id=req.incident_id,
        created_by=admin.username,
    )


@router.get("/reports/{report_id}/download")
async def download_threat_report(
    report_id: str,
    format: Optional[str] = Query("HTML"),
    admin: UserModel = Depends(require_admin),
):
    """Download a generated threat intelligence report file."""
    from backend.services.threat_reporter import get_threat_reporter
    reporter = get_threat_reporter()
    ext = (format or "HTML").lower().strip()
    target_file = reporter.output_dir / f"{report_id}.{ext}"

    if not target_file.exists():
        # Check without extension
        candidates = list(reporter.output_dir.glob(f"{report_id}.*"))
        if candidates:
            target_file = candidates[0]
            ext = target_file.suffix.replace(".", "")
        else:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found.")

    media_type = "text/html" if ext == "html" else ("application/json" if ext == "json" else "text/csv")
    return FileResponse(str(target_file), media_type=media_type, filename=target_file.name)


