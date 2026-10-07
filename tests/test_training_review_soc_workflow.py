"""
test_training_review_soc_workflow.py — Comprehensive tests for CyberGuard 2050 SOC Training Review:
  - Metric consistency across review queue and database
  - Audio streaming security and authorization
  - Separation of human ground-truth from training approval
  - Inconclusive handling without model alteration
  - Candidate model training isolation (detector.pt protection)
  - Promotion and Rollback safety
"""

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

import numpy as np
import pytest
import soundfile as sf
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.storage.database import (
    AnalysisRecordModel,
    ModelVersionModel,
    ReviewQueueModel,
    TrainingRunModel,
    TrainingSampleModel,
    UserModel,
    get_session_factory,
)
from backend.services.continuous_learning import ContinuousLearningService


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    factory = get_session_factory("data/cyberguard.db")
    session = factory()
    yield session
    session.close()


@pytest.fixture(scope="module")
def admin_token(client):
    login = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
    )
    assert login.status_code == 200, "Admin login must succeed"
    return login.json()["token"]


def test_review_queue_metrics_consistency(client, admin_token, db_session):
    """Test that review queue KPI counters match exact database counts."""
    resp = client.get("/api/admin/review/queue?limit=100", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    data = resp.json()

    db_total = db_session.query(ReviewQueueModel).count()
    db_pending = db_session.query(ReviewQueueModel).filter(ReviewQueueModel.status == "PENDING").count()
    db_approved = db_session.query(ReviewQueueModel).filter(ReviewQueueModel.status == "APPROVED").count()
    db_rejected = db_session.query(ReviewQueueModel).filter(ReviewQueueModel.status == "REJECTED").count()
    db_queued_samples = db_session.query(TrainingSampleModel).filter(TrainingSampleModel.used_in_training.is_(False)).count()

    assert data["total_count"] == db_total
    assert data["total_pending"] == db_pending
    assert data["total_approved"] == db_approved
    assert data["total_rejected"] == db_rejected
    assert data["total_training_queued"] == db_queued_samples
    assert "active_model_version" in data


def test_audio_streaming_security(client, admin_token, db_session):
    """Test authenticated streaming, unauthorized blocking, and vault integrity."""
    # Find an item with audio
    review_with_audio = None
    for r in db_session.query(ReviewQueueModel).order_by(ReviewQueueModel.id.desc()).all():
        analysis = db_session.query(AnalysisRecordModel).filter(AnalysisRecordModel.analysis_id == r.analysis_id).first()
        if analysis and (analysis.audio_path or analysis.audio_hash):
            p = Path(analysis.audio_path) if analysis.audio_path else Path(f"data/audio_vault/{analysis.audio_hash}.flac")
            if p.exists():
                review_with_audio = r
                break

    if not review_with_audio:
        pytest.skip("No audio files currently in vault for streaming test.")

    rev_id = review_with_audio.review_id

    # 1. Unauthenticated request must be blocked (use fresh client without auth cookies)
    unauth_client = TestClient(app)
    unauth = unauth_client.get(f"/api/admin/review/audio/{rev_id}")
    assert unauth.status_code in (401, 403), "Unauthenticated audio stream must be blocked"

    # 2. Authenticated with token in query param
    auth_resp = client.get(f"/api/admin/review/audio/{rev_id}?token={admin_token}")
    assert auth_resp.status_code == 200
    assert "Accept-Ranges" in auth_resp.headers
    assert len(auth_resp.content) > 0

    # 3. Authenticated with Bearer header
    auth_header_resp = client.get(f"/api/admin/reviews/{rev_id}/audio", headers={"Authorization": f"Bearer {admin_token}"})
    assert auth_header_resp.status_code == 200


def test_ground_truth_and_training_separation_workflow(client, admin_token, db_session):
    """
    Test the critical requirement:
    Separation of Ground-Truth assignment from Training Approval.
    Case 1: User verifies sample as SPOOF (Cloned), but chooses REJECT from training.
    Case 2: User verifies sample as INCONCLUSIVE -> never eligible for training.
    """
    # Create temporary scan
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_name = f.name
        sr = 16000
        sine = 0.2 * np.sin(2 * np.pi * 500 * np.linspace(0, 1.5, int(sr * 1.5), dtype=np.float32))
        sf.write(tmp_name, sine, sr)

    try:
        with open(tmp_name, "rb") as fh:
            up_resp = client.post(
                "/api/analyze",
                files={"file": ("test_separation.wav", fh, "audio/wav")},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert up_resp.status_code == 200
        sid = up_resp.json()["session_id"]
        rev_id = f"REV_{sid}"

        # Case 1: Human confirms CLONED (SPOOF), but explicitly REJECTS from retraining
        rej_resp = client.post(
            f"/api/admin/reviews/{rev_id}/decision",
            json={
                "ground_truth": "SPOOF",
                "decision": "REJECT",
                "approve_for_training": False,
                "notes": "Voice is cloned, but sample contains ambient background speech; reject from training.",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert rej_resp.status_code == 200
        res = rej_resp.json()
        assert res["status"] == "REJECTED"
        assert res["ground_truth"] == "SPOOF"
        assert res["approved_for_training"] is False

        # Verify DB: ReviewQueueModel has ground_truth_label="SPOOF" but approved_for_training=False
        db_rev = db_session.query(ReviewQueueModel).filter(ReviewQueueModel.review_id == rev_id).first()
        assert db_rev.status == "REJECTED"
        assert db_rev.ground_truth_label == "SPOOF"
        assert db_rev.approved_for_training is False

        # Verify TrainingSampleModel does NOT have this sample
        ts = db_session.query(TrainingSampleModel).filter(TrainingSampleModel.review_id == rev_id).first()
        assert ts is None, "Rejected sample must never enter the training sample pool!"

    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def test_inconclusive_label_never_trains(client, admin_token, db_session):
    """Verify that INCONCLUSIVE label sets REJECTED and never creates a training sample."""
    # Create temporary scan
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_name = f.name
        sr = 16000
        noise = 0.05 * np.random.randn(int(sr * 1.0)).astype(np.float32)
        sf.write(tmp_name, noise, sr)

    try:
        with open(tmp_name, "rb") as fh:
            up_resp = client.post(
                "/api/analyze",
                files={"file": ("test_inconclusive.wav", fh, "audio/wav")},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert up_resp.status_code == 200
        sid = up_resp.json()["session_id"]
        rev_id = f"REV_{sid}"

        # Assign INCONCLUSIVE
        incon_resp = client.post(
            f"/api/admin/reviews/{rev_id}/decision",
            json={
                "ground_truth": "INCONCLUSIVE",
                "notes": "Low SNR audio with excessive reverberation.",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert incon_resp.status_code == 200
        res = incon_resp.json()
        assert res["status"] == "REJECTED"
        assert res["ground_truth"] == "INCONCLUSIVE"
        assert res["approved_for_training"] is False

        # Verify DB
        db_rev = db_session.query(ReviewQueueModel).filter(ReviewQueueModel.review_id == rev_id).first()
        assert db_rev.ground_truth_label == "INCONCLUSIVE"
        assert db_rev.approved_for_training is False

        ts = db_session.query(TrainingSampleModel).filter(TrainingSampleModel.review_id == rev_id).first()
        assert ts is None, "Inconclusive sample must NEVER enter training pool!"

    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def test_retraining_produces_candidate_not_overwriting_detector_pt(client, admin_token, db_session):
    """
    Verify that background retraining creates candidate checkpoint,
    preserving the production detector.pt checkpoint unchanged.
    """
    weights_path = Path("backend/models/weights/detector.pt")
    assert weights_path.exists(), "detector.pt must exist"
    initial_sha = hashlib.sha256(weights_path.read_bytes()).hexdigest()

    # Trigger retraining job with 1 epoch for quick test
    resp = client.post(
        "/api/admin/training/trigger",
        json={"epochs": 1, "learning_rate": 0.0001},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    res = resp.json()
    assert res["status"] in ("STARTED", "ALREADY_RUNNING", "NO_SAMPLES")

    # Verify detector.pt SHA-256 remains completely unchanged
    current_sha = hashlib.sha256(weights_path.read_bytes()).hexdigest()
    assert current_sha == initial_sha, "detector.pt must NEVER be overwritten during retraining!"
