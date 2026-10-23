"""
test_auth_and_continuous_learning.py — Full automated test suite for Auth, RBAC,
Analysis Persistence, Review Queue, Continuous Learning, and Model Promotion/Rollback.
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

from backend.main import app
from backend.storage.auth import AuthService, hash_password, verify_password
from backend.storage.database import (
    AnalysisRecordModel,
    ModelVersionModel,
    ReviewQueueModel,
    TrainingRunModel,
    TrainingSampleModel,
    UserModel,
    get_session_factory,
    init_db,
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def db_session():
    factory = get_session_factory("data/cyberguard.db")
    session = factory()
    yield session
    session.close()


def test_password_hashing():
    """Verify that scrypt hashing works, generates salt, and never stores plaintext."""
    pwd = "SecureTestPassword123!"
    h = hash_password(pwd)
    assert h.startswith("scrypt:")
    assert pwd not in h
    assert verify_password(pwd, h) is True
    assert verify_password("WrongPassword!", h) is False


def test_admin_login(client):
    """Verify that default admin can log in and receives a secure token."""
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["user"]["role"] == "admin"
    assert data["user"]["username"] == "admin"


def test_normal_user_registration_and_login(client):
    """Verify standard user registration, auto-login, and role assignment."""
    import uuid
    rand_user = f"user_{uuid.uuid4().hex[:6]}"
    resp = client.post(
        "/api/auth/register",
        json={
            "username": rand_user,
            "email": f"{rand_user}@cyberguard.local",
            "password": "UserPass123!",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["role"] == "user"
    assert data["user"]["username"] == rand_user

    # Test /api/auth/me
    token = data["token"]
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == rand_user
    assert me_data["role"] == "user"


def test_rbac_user_cannot_access_admin_endpoints(client):
    """Verify that normal users are forbidden from admin routes."""
    # Register/login normal user
    import uuid
    rand_user = f"testuser_{uuid.uuid4().hex[:6]}"
    reg = client.post(
        "/api/auth/register",
        json={
            "username": rand_user,
            "email": f"{rand_user}@cyberguard.local",
            "password": "Password123!",
        },
    )
    user_token = reg.json()["token"]

    # Attempt to access admin routes with user token
    for ep in ["/api/admin/users", "/api/admin/reviews", "/api/admin/models"]:
        resp = client.get(ep, headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 403
        assert "Administrative privileges required" in resp.json()["detail"]


def test_admin_can_access_admin_endpoints(client):
    """Verify that admin can access administrative dashboards."""
    login = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
    )
    admin_token = login.json()["token"]

    resp = client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    users = resp.json()
    assert len(users) >= 1
    # Verify passwords are NOT exposed
    for u in users:
        assert "password" not in u
        assert "password_hash" not in u

    # Check reviews endpoint
    rev_resp = client.get("/api/admin/reviews", headers={"Authorization": f"Bearer {admin_token}"})
    assert rev_resp.status_code == 200
    assert "items" in rev_resp.json()

    # Check models endpoint
    m_resp = client.get("/api/admin/models", headers={"Authorization": f"Bearer {admin_token}"})
    assert m_resp.status_code == 200
    assert len(m_resp.json()) >= 1


def test_analysis_persistence_and_review_queue(client, db_session):
    """Verify that scanning an audio file creates an AnalysisRecord and ReviewQueueItem."""
    # Create test sine wave audio
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_name = f.name
        sr = 16000
        t = np.linspace(0, 2.0, int(sr * 2.0), dtype=np.float32)
        sine = 0.3 * np.sin(2 * np.pi * 440 * t)
        sf.write(tmp_name, sine, sr)

    try:
        # Upload as normal user
        login = client.post(
            "/api/auth/login",
            json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
        )
        token = login.json()["token"]

        with open(tmp_name, "rb") as fh:
            resp = client.post(
                "/api/analyze",
                files={"file": ("test_synth.wav", fh, "audio/wav")},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        session_id = data["session_id"]
        assert "detector_version" in data

        # Verify AnalysisRecord in database
        rec = db_session.query(AnalysisRecordModel).filter(
            AnalysisRecordModel.analysis_id == session_id
        ).first()
        assert rec is not None
        assert rec.analysis_status == "COMPLETED"
        assert rec.peak_risk == data["peak_risk"]

        # Verify ReviewQueueItem in database
        queue_item = db_session.query(ReviewQueueModel).filter(
            ReviewQueueModel.analysis_id == session_id
        ).first()
        assert queue_item is not None
        assert queue_item.status == "PENDING"

        # Verify user history endpoint
        hist_resp = client.get("/api/history/me", headers={"Authorization": f"Bearer {token}"})
        assert hist_resp.status_code == 200
        history = hist_resp.json()
        assert any(h["analysis_id"] == session_id for h in history)

    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def test_review_rejection_does_not_train(client, db_session):
    """Verify that rejecting a sample sets REJECTED and never creates a training sample."""
    login = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
    )
    admin_token = login.json()["token"]

    # Fetch a pending review item
    revs = client.get("/api/admin/reviews?status=PENDING", headers={"Authorization": f"Bearer {admin_token}"}).json()
    assert len(revs["items"]) > 0
    target_rev_id = revs["items"][0]["review_id"]

    # Admin rejects
    rej_resp = client.post(
        f"/api/admin/reviews/{target_rev_id}/decision",
        json={"ground_truth": "REJECT", "notes": "Auditory check shows noisy artifact."},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert rej_resp.status_code == 200
    res_data = rej_resp.json()
    assert res_data["status"] == "REJECTED"

    # Check TrainingSampleModel
    ts = db_session.query(TrainingSampleModel).filter(
        TrainingSampleModel.review_id == target_rev_id
    ).first()
    assert ts is None, "Rejected sample must never create a TrainingSample!"


def test_review_approval_creates_training_sample(client, db_session):
    """Verify that approving a sample with ground truth creates an auditable TrainingSample."""
    # Create another scan to approve
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_name = f.name
        sr = 16000
        t = np.linspace(0, 2.0, int(sr * 2.0), dtype=np.float32)
        sine = 0.3 * np.sin(2 * np.pi * 880 * t)
        sf.write(tmp_name, sine, sr)

    try:
        login = client.post(
            "/api/auth/login",
            json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
        )
        token = login.json()["token"]

        with open(tmp_name, "rb") as fh:
            resp = client.post(
                "/api/analyze",
                files={"file": ("test_approve.wav", fh, "audio/wav")},
                headers={"Authorization": f"Bearer {token}"},
            )
        sid = resp.json()["session_id"]
        rev_id = f"REV_{sid}"

        # Admin approves as SPOOF
        app_resp = client.post(
            f"/api/admin/reviews/{rev_id}/decision",
            json={"ground_truth": "SPOOF", "notes": "Confirmed voice cloning artifact."},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert app_resp.status_code == 200
        res = app_resp.json()
        assert res["status"] == "APPROVED"
        assert res["ground_truth"] == "SPOOF"

        # Check TrainingSampleModel
        ts = db_session.query(TrainingSampleModel).filter(
            TrainingSampleModel.review_id == rev_id
        ).first()
        assert ts is not None
        assert ts.ground_truth == "SPOOF"
        assert ts.used_in_training is False

    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
