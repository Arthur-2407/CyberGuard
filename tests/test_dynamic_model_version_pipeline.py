"""
test_dynamic_model_version_pipeline.py — Verification of automated, dynamic model version propagation.
Ensures zero hardcoding, automatic self-updating across the pipeline, and seamless lineage progression.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.continuous_learning import ContinuousLearningService
from backend.storage.database import (
    ModelVersionModel,
    ReviewQueueModel,
    AnalysisRecordModel,
    get_session_factory,
)


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


def test_service_dynamic_version_resolution(db_session):
    """Verify get_active_model_version and get_next_model_version resolve dynamically without hardcoding."""
    active_ver = ContinuousLearningService.get_active_model_version(db_session)
    assert active_ver.startswith("v")
    assert active_ver[1:].isdigit()

    next_ver = ContinuousLearningService.get_next_model_version(db_session)
    assert next_ver.startswith("v")
    assert next_ver[1:].isdigit()

    active_num = int(active_ver[1:])
    next_num = int(next_ver[1:])
    assert next_num > active_num, f"Next version {next_ver} must be greater than active version {active_ver}"


def test_public_config_status_dynamic_version(client):
    """Verify GET /api/config/status provides active_detector_version dynamically."""
    res = client.get("/api/config/status")
    assert res.status_code == 200
    data = res.json()
    assert "active_detector_version" in data
    assert "detector_version" in data
    assert data["active_detector_version"] == ContinuousLearningService.get_active_model_version()
    assert data["detector_version"] == ContinuousLearningService.get_active_model_version()


def test_admin_review_queue_dynamic_version(client):
    """Verify /api/admin/reviews returns active_model_version and active_version dynamically."""
    token = _get_admin_token(client)
    res = client.get("/api/admin/reviews", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    expected_ver = ContinuousLearningService.get_active_model_version()
    assert data.get("active_model_version") == expected_ver
    assert data.get("active_version") == expected_ver


def test_admin_training_status_dynamic_version(client):
    """Verify /api/admin/training/status returns active_version dynamically."""
    token = _get_admin_token(client)
    res = client.get("/api/admin/training/status", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    expected_ver = ContinuousLearningService.get_active_model_version()
    assert data.get("active_version") == expected_ver
    assert data.get("active_model_version") == expected_ver
    assert data.get("current_production_version") == expected_ver


def test_admin_model_versions_lineage_dynamic(client):
    """Verify /api/admin/model/versions returns active_version dynamically."""
    token = _get_admin_token(client)
    res = client.get("/api/admin/model/versions", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    expected_ver = ContinuousLearningService.get_active_model_version()
    assert data.get("active_version") == expected_ver
    assert data.get("current_production_version") == expected_ver


def test_no_hardcoded_version_fallbacks_in_code():
    """Verify neither routes_admin.py nor index.html contain hardcoded 'v020' or fallback strings."""
    routes_admin_text = Path("backend/api/routes_admin.py").read_text(encoding="utf-8")
    index_html_text = Path("frontend/index.html").read_text(encoding="utf-8")

    # In routes_admin.py, there should be zero occurrences of "v020", "v019", "v010"
    assert '"v020"' not in routes_admin_text, "routes_admin.py must not hardcode 'v020'"
    assert '"v019"' not in routes_admin_text, "routes_admin.py must not hardcode 'v019'"
    assert '"v010"' not in routes_admin_text, "routes_admin.py must not hardcode 'v010'"

    # In index.html, there should be zero occurrences of "v020" or "v019"
    assert "v020" not in index_html_text, "frontend/index.html must not hardcode 'v020'"
    assert "v019" not in index_html_text, "frontend/index.html must not hardcode 'v019'"
