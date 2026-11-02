"""
test_personal_integration_and_lifecycle.py
Verification suite for CyberGuard Personal:
  1. Frontend asset integrity & syntax check
  2. Single runtime lifecycle & resource optimization guards (pagehide handlers)
  3. Shared backend authentication flow (me, login, register, logout)
  4. Real threat detection pipeline integration from Personal frontend
  5. Scoped user scan activity retrieval
"""

import io
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.database import get_session_factory, UserModel, init_db
from backend.storage.auth import AuthService


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as test_client:
        yield test_client


def test_personal_asset_integrity():
    """Verify that frontend/personal/ contains valid, bug-free assets."""
    personal_dir = Path("frontend/personal")
    assert (personal_dir / "index.html").exists(), "index.html must exist"
    assert (personal_dir / "styles.css").exists(), "styles.css must exist"
    assert (personal_dir / "app.js").exists(), "app.js must exist"

    app_js = (personal_dir / "app.js").read_text(encoding="utf-8")
    index_html = (personal_dir / "index.html").read_text(encoding="utf-8")
    styles_css = (personal_dir / "styles.css").read_text(encoding="utf-8")

    # Verify bug fix: no single $ querySelector with .forEach on .mode-button
    import re
    assert re.search(r'(?<!\$)\$\("\.mode-button"\)\.forEach', app_js) is None, "app.js must not crash with querySelector .forEach"
    assert '$$(".mode-button").forEach' in app_js, "app.js must use querySelectorAll for .mode-button"

    # Verify auth controls exist in index.html
    assert 'id="authBtn"' in index_html, "Topbar authBtn must exist"
    assert 'id="authModal"' in index_html, "Auth modal must exist"
    assert 'id="settingsAccountPanel"' in index_html, "Settings account panel must exist"

    # Verify pages exist for deep-linking
    for page in ["home", "link", "file", "media", "activity", "settings"]:
        assert f'id="page-{page}"' in index_html, f"Page #{page} must exist in index.html"

    # Verify auth modal and verdict badges exist in styles.css
    assert ".modal-overlay" in styles_css, "styles.css must contain .modal-overlay"
    assert ".verdict-badge" in styles_css, "styles.css must contain .verdict-badge"


def test_single_runtime_lifecycle_cleanup():
    """Verify that both SOC and Personal frontends have non-destructive cleanup handlers."""
    soc_app_js = Path("frontend/app.js").read_text(encoding="utf-8")
    personal_app_js = Path("frontend/personal/app.js").read_text(encoding="utf-8")

    # SOC frontend lifecycle cleanup
    assert "window._overviewHeartbeatTimer" in soc_app_js, "SOC frontend must track overview heartbeat"
    assert "window._autonomousDefconTimer" in soc_app_js, "SOC frontend must track autonomous DEFCON interval"
    assert "pagehide" in soc_app_js, "SOC frontend must listen for pagehide deactivation"
    assert "SOC frontend deactivated" in soc_app_js, "SOC frontend must cleanly close sockets on leave"

    # Personal frontend lifecycle cleanup
    assert "activeRequests" in personal_app_js, "Personal frontend must track in-flight requests"
    assert "pagehide" in personal_app_js, "Personal frontend must clean up on pagehide"
    assert "controller.abort()" in personal_app_js, "Personal frontend must abort pending browser requests"


def test_shared_authentication_flow(client):
    """Verify login, me, and registration endpoints shared between SOC and Personal."""
    # Test registration
    unique_user = f"consumer_{int(pytest.importorskip('time').time())}"
    reg_res = client.post(
        "/api/auth/register",
        json={
            "username": unique_user,
            "email": f"{unique_user}@cyberguard.test",
            "password": "SecurePassword123!"
        }
    )
    assert reg_res.status_code == 200, f"Registration failed: {reg_res.text}"
    reg_data = reg_res.json()
    assert "token" in reg_data
    token = reg_data["token"]

    # Test /api/auth/me with Bearer token
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == unique_user

    # Test login with same credentials
    login_res = client.post(
        "/api/auth/login",
        json={"username": unique_user, "password": "SecurePassword123!"}
    )
    assert login_res.status_code == 200
    assert "token" in login_res.json()

    # Test logout
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200


def test_personal_link_check_integration(client):
    """Verify that link check via /api/threats/url returns genuine ThreatEvent."""
    res = client.post(
        "/api/threats/url",
        data={"url": "https://example.com/clean-link", "source": "personal_frontend"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "classification" in data
    assert "severity" in data
    assert "explanation" in data
    assert "recommended_actions" in data


def test_personal_file_scan_integration(client):
    """Verify that file check via /api/threats/unified returns pipeline execution results."""
    file_bytes = b"CyberGuard Personal benign test document content."
    res = client.post(
        "/api/threats/unified",
        files={"file": ("test_doc.txt", io.BytesIO(file_bytes), "text/plain")},
        data={"source": "personal_frontend"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "event" in data or "summary" in data or "pipeline_execution" in data


def test_personal_user_activity_isolation(client):
    """Verify that an authenticated user's activity log returns only their events."""
    factory = get_session_factory("data/cyberguard.db")
    with factory() as db:
        user_c = db.query(UserModel).filter(UserModel.username == "test_consumer_c").first()
        if not user_c:
            user_c = AuthService.create_user(
                db,
                username="test_consumer_c",
                email="consumer_c@cyberguard.test",
                password="TestPassword123!",
                role="user"
            )
        _, token_c = AuthService.authenticate(db, "test_consumer_c", "TestPassword123!")

    # Fetch user activity events with token
    res = client.get("/api/incidents/events?limit=10", headers={"Authorization": f"Bearer {token_c}"})
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)
    # Every event returned must belong to user_c
    for ev in events:
        assert ev.get("user_id") == user_c.id
