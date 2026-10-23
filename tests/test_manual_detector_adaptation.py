"""
test_manual_detector_adaptation.py — Verification of manual Human/Cloned labeling and live auto-updating of detector.py.
"""

import io
import os
import tempfile
import numpy as np
import pytest
import soundfile as sf
from fastapi.testclient import TestClient

from backend.main import app, get_app_detector
from backend.storage.database import (
    AdminAuditLogModel,
    AnalysisRecordModel,
    ReviewQueueModel,
    TrainingSampleModel,
    get_session_factory,
)


@pytest.fixture(scope="module", autouse=True)
def preserve_detector_state():
    """Ensure tests that modify detector weights restore original weights upon completion."""
    from pathlib import Path
    import shutil
    pt_path = Path("backend/models/weights/detector.pt")
    calib_path = Path("data/detector_adaptive_calibration.json")
    backup_pt = Path("backend/models/weights/detector_test_orig_backup.pt")
    backup_calib = Path("data/detector_adaptive_calibration_test_backup.json")
    if pt_path.exists():
        shutil.copy2(pt_path, backup_pt)
    if calib_path.exists():
        shutil.copy2(calib_path, backup_calib)
    yield
    if backup_pt.exists():
        shutil.copy2(backup_pt, pt_path)
        backup_pt.unlink()
    if backup_calib.exists():
        shutil.copy2(backup_calib, calib_path)
        backup_calib.unlink()
    det = get_app_detector()
    if det:
        det.initialize()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db_session():
    factory = get_session_factory("data/cyberguard.db")
    session = factory()
    yield session
    session.close()


def _get_admin_token(client):
    login = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
    )
    return login.json()["token"]


def test_detector_adapt_method_directly():
    """Verify that detector.adapt_from_labeled_audio modifies its state and returns telemetry."""
    detector = get_app_detector()
    assert detector is not None

    # Generate synthetic 16kHz sine chunk (2 seconds)
    sr = 16000
    t = np.linspace(0, 2.0, int(sr * 2.0), dtype=np.float32)
    audio = 0.4 * np.sin(2 * np.pi * 440 * t)

    # 1. Adapt as HUMAN
    res_human = detector.adapt_from_labeled_audio(audio, label="HUMAN", steps=1)
    assert res_human["success"] is True
    assert res_human["canonical_label"] == "HUMAN"
    assert res_human["ground_truth_target"] == 0.0
    assert "adapted_probability" in res_human

    # 2. Adapt as CLONED
    res_cloned = detector.adapt_from_labeled_audio(audio, label="CLONED", steps=1)
    assert res_cloned["success"] is True
    assert res_cloned["canonical_label"] == "CLONED"
    assert res_cloned["ground_truth_target"] == 1.0


def test_manual_update_api_endpoint(client, db_session):
    """Verify POST /api/admin/detector/manual-update with audio file upload."""
    token = _get_admin_token(client)

    sr = 16000
    t = np.linspace(0, 2.0, int(sr * 2.0), dtype=np.float32)
    audio = 0.3 * np.sin(2 * np.pi * 880 * t)

    buffer = io.BytesIO()
    sf.write(buffer, audio, sr, format="WAV")
    buffer.seek(0)

    # Admin manually selects Cloned Voice
    resp = client.post(
        "/api/admin/detector/manual-update",
        data={"label": "CLONED", "notes": "Confirmed synthetic artifact"},
        files={"audio_file": ("test_clone.wav", buffer, "audio/wav")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["label_display"] == "CLONED"
    assert data["adaptation"]["success"] is True

    # Check TrainingSampleModel created
    ts = db_session.query(TrainingSampleModel).filter(
        TrainingSampleModel.audio_hash == data["audio_hash"]
    ).first()
    assert ts is not None
    assert ts.ground_truth == "SPOOF"

    # Check Audit log
    audit = db_session.query(AdminAuditLogModel).filter(
        AdminAuditLogModel.action == "DETECTOR_MANUAL_ADAPTATION"
    ).order_by(AdminAuditLogModel.id.desc()).first()
    assert audit is not None
    assert "CLONED" in audit.details_json


def test_manual_update_json_endpoint(client, db_session):
    """Verify POST /api/admin/detector/manual-update-json with an existing review item."""
    token = _get_admin_token(client)

    # First perform a scan to generate an analysis record
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_name = f.name
        sr = 16000
        t = np.linspace(0, 2.0, int(sr * 2.0), dtype=np.float32)
        audio = 0.25 * np.sin(2 * np.pi * 500 * t)
        sf.write(tmp_name, audio, sr)

    try:
        with open(tmp_name, "rb") as fh:
            scan_res = client.post(
                "/api/analyze",
                files={"file": ("test_human.wav", fh, "audio/wav")},
                headers={"Authorization": f"Bearer {token}"},
            )
        sid = scan_res.json()["session_id"]
        rev_id = f"REV_{sid}"

        # Admin manually classifies as HUMAN
        res = client.post(
            "/api/admin/detector/manual-update-json",
            json={"review_id": rev_id, "label": "HUMAN", "notes": "Verified genuine voice"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["label_display"] == "HUMAN"
        assert data["adaptation"]["success"] is True
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def test_review_decision_auto_updates_detector(client, db_session):
    """Verify that approving a sample in review queue auto-updates detector.py when auto_update_detector is True."""
    token = _get_admin_token(client)

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        tmp_name = f.name
        sr = 16000
        t = np.linspace(0, 2.0, int(sr * 2.0), dtype=np.float32)
        audio = 0.35 * np.sin(2 * np.pi * 350 * t)
        sf.write(tmp_name, audio, sr)

    try:
        with open(tmp_name, "rb") as fh:
            scan_res = client.post(
                "/api/analyze",
                files={"file": ("test_approve_adapt.wav", fh, "audio/wav")},
                headers={"Authorization": f"Bearer {token}"},
            )
        sid = scan_res.json()["session_id"]
        rev_id = f"REV_{sid}"

        # Approve with auto_update_detector = True
        app_resp = client.post(
            f"/api/admin/reviews/{rev_id}/decision",
            json={"ground_truth": "BONAFIDE", "auto_update_detector": True, "notes": "Human voice approval with auto-adaptation"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert app_resp.status_code == 200, app_resp.text
        data = app_resp.json()
        assert data["status"] == "APPROVED"
        assert "detector_adaptation" in data
        assert data["detector_adaptation"]["success"] is True
        assert data["detector_adaptation"]["canonical_label"] == "HUMAN"
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)

