"""
test_zero_trust_data_isolation.py — Verification suite for:
  1. Issue A: Frontend switching repair (/personal/ serving and redirect)
  2. Issue B: Zero-trust backend authorization enforcement and cross-user data isolation
  3. WebSocket telemetry isolation (User A events never delivered to User B)
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.database import (
    get_session_factory,
    UserModel,
    IncidentModel,
    ThreatEventModel,
    ScreenedCallIncidentModel,
    init_db,
)
from backend.storage.auth import AuthService
from backend.alerts.websocket_notifier import WebSocketNotifier
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def test_users():
    """Create or retrieve two test users (user_a, user_b) and one admin."""
    factory = get_session_factory("data/cyberguard.db")
    with factory() as db:
        # User A
        user_a = db.query(UserModel).filter(UserModel.username == "test_alice").first()
        if not user_a:
            user_a = AuthService.create_user(
                db,
                username="test_alice",
                email="alice@cyberguard.test",
                password="TestPassword123!",
                role="user"
            )
        _, token_a = AuthService.authenticate(db, "test_alice", "TestPassword123!")

        # User B
        user_b = db.query(UserModel).filter(UserModel.username == "test_bob").first()
        if not user_b:
            user_b = AuthService.create_user(
                db,
                username="test_bob",
                email="bob@cyberguard.test",
                password="TestPassword123!",
                role="user"
            )
        _, token_b = AuthService.authenticate(db, "test_bob", "TestPassword123!")

        # Admin
        admin = db.query(UserModel).filter(UserModel.username == "admin").first()
        token_admin = None
        if admin:
            try:
                _, token_admin = AuthService.authenticate(db, "admin", "admin123")
            except Exception:
                pass

        return {
            "alice": {"id": user_a.id, "username": user_a.username, "token": token_a},
            "bob": {"id": user_b.id, "username": user_b.username, "token": token_b},
            "admin": {"id": admin.id if admin else None, "token": token_admin},
        }


# ==============================================================================
# PHASE 1: FRONTEND SWITCHING REPAIR (/personal/)
# ==============================================================================

def test_personal_frontend_route_serves_html(client):
    """GET /personal/ must return 200 OK and render CyberGuard Personal HTML."""
    res = client.get("/personal/")
    assert res.status_code == 200
    assert "CyberGuard" in res.text
    assert "PERSONAL SECURITY" in res.text or "digital safety" in res.text.lower()


def test_personal_frontend_redirect_from_bare_path(client):
    """GET /personal (without trailing slash) must redirect to /personal/."""
    res = client.get("/personal", follow_redirects=False)
    assert res.status_code in (307, 308, 301, 302)
    assert res.headers["location"] == "/personal/"


def test_personal_frontend_assets_exist(client):
    """Static assets under /personal/ must resolve with valid Content-Types."""
    res_css = client.get("/personal/styles.css")
    assert res_css.status_code == 200
    assert "text/css" in res_css.headers.get("content-type", "")

    res_js = client.get("/personal/app.js")
    assert res_js.status_code == 200
    assert "javascript" in res_js.headers.get("content-type", "")

    res_cfg = client.get("/personal/config.js")
    assert res_cfg.status_code == 200
    assert "javascript" in res_cfg.headers.get("content-type", "")


def test_soc_console_and_api_routes_preserved(client):
    """Root SOC console and API routes must remain unaffected by the personal mount."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "CyberGuard" in res_root.text

    res_health = client.get("/health")
    assert res_health.status_code == 200
    data = res_health.json()
    assert data.get("status") == "ok"

    # API 404 must return JSON, NOT SPA HTML fallback
    res_not_found = client.get("/api/nonexistent_test_endpoint_xyz")
    assert res_not_found.status_code == 404
    assert res_not_found.headers.get("content-type", "").startswith("application/json")


# ==============================================================================
# PHASE 2: ZERO-TRUST BACKEND AUTHENTICATION ENFORCEMENT
# ==============================================================================

def test_unauthenticated_requests_blocked_with_401(client):
    """Unauthenticated calls to sensitive data endpoints must be blocked with HTTP 401."""
    endpoints = [
        ("GET", "/api/incidents/"),
        ("GET", "/api/incidents/events"),
        ("GET", "/api/incidents/INC-AUDIT-TEST"),
        ("PUT", "/api/incidents/INC-AUDIT-TEST/status"),
        ("POST", "/api/incidents/containment/emergency"),
        ("GET", "/api/alerts/session/test-session-id"),
    ]

    for method, path in endpoints:
        res = client.request(method, path)
        assert res.status_code == 401, f"{method} {path} should return 401 for unauthenticated request, got {res.status_code}"

    # Summary and telemetry endpoints return 200 with zero baseline for unauthenticated callers (never leak user data)
    res_summary = client.get("/api/incidents/dashboard/summary")
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert summary_data["total_incidents"] == 0
    assert summary_data["open_incidents"] == 0
    assert summary_data["recent_incidents"] == []

    res_alerts = client.get("/api/alerts/recent")
    assert res_alerts.status_code == 200
    assert res_alerts.json()["alerts"] == []

def test_security_cache_control_headers(client, test_users):
    """API responses must include Cache-Control: no-store, private."""
    token = test_users["alice"]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    res = client.get("/api/incidents/dashboard/summary", headers=headers)
    assert res.status_code == 200
    cc = res.headers.get("Cache-Control", "")
    assert "no-store" in cc
    assert "private" in cc


# ==============================================================================
# PHASE 3: CROSS-USER DATA ISOLATION (Alice vs. Bob)
# ==============================================================================

def test_cross_user_data_isolation(client, test_users):
    """
    Verify that User B cannot see, access, or modify User A's private security records:
      - Incidents
      - Dashboard summary
      - Screened calls
      - Incident status updates
    """
    alice = test_users["alice"]
    bob = test_users["bob"]

    headers_alice = {"Authorization": f"Bearer {alice['token']}"}
    headers_bob = {"Authorization": f"Bearer {bob['token']}"}

    # 1. Seed private records for Alice
    from backend.incidents.incident_manager import get_incident_manager_for_user
    alice_inc_id = "inc-alice-unique-12345"
    alice_call_id = "sc-alice-unique-67890"

    mgr_alice = get_incident_manager_for_user({"id": alice["id"], "username": alice["username"]})
    ev = ThreatEvent(
        source="unit_test_alice",
        source_type="unit_test",
        modality="voice",
        threat_category=ThreatCategory.VOICE_CLONING,
        severity=RiskLevel.CRITICAL,
        classification="MALICIOUS",
        evidence=[],
        explanation=Explanation(summary="Alice voice clone", reasoning="Cloning detected"),
        recommended_actions=["Block caller"],
        detector="VoiceCloneDetector",
        user_id=alice["id"],
        correlation_id=alice_inc_id,
    )
    created_inc = mgr_alice.process_event(ev)
    alice_inc_id = created_inc.incident_id

    factory = get_session_factory("data/cyberguard.db")
    with factory() as db:
        db.query(ScreenedCallIncidentModel).filter(ScreenedCallIncidentModel.incident_id == alice_call_id).delete()
        sc = ScreenedCallIncidentModel(
            incident_id=alice_call_id,
            normalized_number="+15551234567",
            caller_display_name="Alice Urgent Notice",
            classification="SUSPECTED_SCAM",
            risk_score=0.95,
            user_id=alice["id"]
        )
        db.add(sc)
        db.commit()

    # 2. Alice retrieves her dashboard summary and incidents
    res_a_sum = client.get("/api/incidents/dashboard/summary", headers=headers_alice)
    assert res_a_sum.status_code == 200
    data_a_sum = res_a_sum.json()
    assert data_a_sum["total_incidents"] >= 1

    res_a_inc = client.get(f"/api/incidents/{alice_inc_id}", headers=headers_alice)
    assert res_a_inc.status_code == 200
    assert res_a_inc.json()["incident_id"] == alice_inc_id

    # 3. Bob queries dashboard summary: must NOT count Alice's incident
    res_b_sum = client.get("/api/incidents/dashboard/summary", headers=headers_bob)
    assert res_b_sum.status_code == 200
    data_b_sum = res_b_sum.json()
    assert data_b_sum["critical_threats"] == 0, "Bob should not see Alice's critical threat in summary"

    # 4. Bob queries all incidents: must NOT include Alice's incident
    res_b_list = client.get("/api/incidents/", headers=headers_bob)
    assert res_b_list.status_code == 200
    bob_inc_ids = [item["incident_id"] for item in res_b_list.json()]
    assert alice_inc_id not in bob_inc_ids, "Bob saw Alice's incident in /api/incidents/!"

    # 5. Bob queries Alice's incident directly by ID: must return 404 Not Found
    res_b_direct = client.get(f"/api/incidents/{alice_inc_id}", headers=headers_bob)
    assert res_b_direct.status_code == 404, "Bob was able to fetch Alice's incident directly!"

    # 6. Bob attempts to modify Alice's incident: must return 404 Not Found
    res_b_update = client.put(
        f"/api/incidents/{alice_inc_id}/status",
        headers=headers_bob,
        json={"status": "CONTAINED", "analyst_notes": "Tampered by Bob"}
    )
    assert res_b_update.status_code == 404, "Bob was able to modify Alice's incident status!"

    # 7. Bob queries screened calls: must NOT include Alice's screened call
    res_b_calls = client.get("/api/threats/screened-calls", headers=headers_bob)
    assert res_b_calls.status_code == 200
    bob_call_ids = [c["incident_id"] for c in res_b_calls.json().get("screened_calls", [])]
    assert alice_call_id not in bob_call_ids, "Bob saw Alice's screened call!"

    # Cleanup
    with factory() as db:
        db.query(ScreenedCallIncidentModel).filter(ScreenedCallIncidentModel.incident_id == alice_call_id).delete()
        db.commit()


# ==============================================================================
# PHASE 4: WEBSOCKET TELEMETRY ISOLATION
# ==============================================================================

@pytest.mark.asyncio
async def test_websocket_telemetry_isolation():
    """
    Verify that WebSocketNotifier routes threat and incident events exclusively
    to the owning user (and admins), never to an unrelated regular user.
    """
    notifier = WebSocketNotifier()

    ws_alice = AsyncMock()
    ws_bob = AsyncMock()
    ws_admin = AsyncMock()

    await notifier.connect(ws_alice, session_id="ses-alice", user_id=101, role="user")
    await notifier.connect(ws_bob, session_id="ses-bob", user_id=102, role="user")
    await notifier.connect(ws_admin, session_id="ses-admin", user_id=999, role="admin")

    assert notifier.connection_count == 3

    # Dispatch a ThreatEvent owned by Alice (user_id=101)
    event_alice = ThreatEvent(
        source="unit_test",
        source_type="unit_test",
        modality="voice",
        threat_category=ThreatCategory.VOICE_CLONING,
        severity=RiskLevel.CRITICAL,
        classification="MALICIOUS",
        evidence=[],
        explanation=Explanation(summary="Alice voice alert", reasoning="Cloning detected"),
        recommended_actions=["Halt call"],
        detector="VoiceCloneDetector",
        user_id=101,
        user_email="alice@cyberguard.test"
    )

    await notifier.notify_threat_event(event_alice)

    # Alice's WS must have received the text
    assert ws_alice.send_text.called, "Alice's WebSocket should have received her threat event"
    # Admin's WS must have received the text
    assert ws_admin.send_text.called, "Admin's WebSocket should have received the threat event"
    # Bob's WS must NEVER have received Alice's event
    assert not ws_bob.send_text.called, "Bob's WebSocket LEAKED Alice's threat event!"

    # Reset mocks
    ws_alice.reset_mock()
    ws_bob.reset_mock()
    ws_admin.reset_mock()

    # Dispatch an Incident Event owned by Alice (user_id=101)
    incident_msg = {
        "type": "incident_update",
        "action": "created_or_updated",
        "incident": {"incident_id": "inc-001", "user_id": 101}
    }
    await notifier.notify_incident_event(incident_msg, user_id=101)

    assert ws_alice.send_text.called, "Alice's WebSocket should have received her incident update"
    assert ws_admin.send_text.called, "Admin's WebSocket should have received the incident update"
    assert not ws_bob.send_text.called, "Bob's WebSocket LEAKED Alice's incident update!"

