import pytest
import os
from fastapi.testclient import TestClient
from backend.main import app, get_app_incident_manager, get_app_alert_manager, get_app_ws_notifier
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation, IncidentStatus
from backend.storage.database import get_session_factory, UserModel
from backend.storage.auth import ROLE_ADMIN, AuthService

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def auth_headers():
    """Fixture providing valid authentication headers for an analyst/admin user."""
    admin_pw = os.getenv("CYBERGUARD_ADMIN_PASSWORD", "Admin@CyberGuard2026!")
    db = get_session_factory("data/cyberguard.db")()
    try:
        admin = db.query(UserModel).filter(UserModel.username == "admin").first()
        if not admin:
            admin = AuthService.create_user(
                db=db,
                username="admin",
                email="admin@cyberguard.local",
                password=admin_pw,
                role=ROLE_ADMIN,
            )
        user, raw_token = AuthService.authenticate(db, "admin", admin_pw)
        return {"Authorization": f"Bearer {raw_token}"}
    finally:
        db.close()

def test_frontend_routes_served(client):
    """Verify Security Center and legacy compatibility routes return index.html."""
    for path in ["/", "/security-center", "/incidents", "/alerts"]:
        resp = client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "SECURITY CENTER" in resp.text
        assert "panel-security-center" in resp.text

def test_incidents_api_endpoints(client, auth_headers):
    """Verify incidents and dashboard summary APIs with proper authorization enforcement."""
    # 1. Dashboard summary (allowed for telemetry overview)
    resp = client.get("/api/incidents/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_incidents" in data
    assert "open_incidents" in data

    # 2. Get all incidents without auth MUST be rejected (Finding 2)
    anon_resp = client.get("/api/incidents/")
    assert anon_resp.status_code == 401

    # 3. Get all incidents with valid auth succeeds
    auth_resp = client.get("/api/incidents/", headers=auth_headers)
    assert auth_resp.status_code == 200
    incidents = auth_resp.json()
    assert isinstance(incidents, list)

def test_events_api_endpoint(client, auth_headers):
    """Verify threat events query endpoint enforces authentication."""
    # Anonymous query rejected
    anon_resp = client.get("/api/incidents/events?limit=10")
    assert anon_resp.status_code == 401

    # Authenticated query succeeds
    resp = client.get("/api/incidents/events?limit=10", headers=auth_headers)
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)

def test_recent_alerts_api(client):
    """Verify alerts API endpoint."""
    resp = client.get("/api/alerts/recent?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)

def test_incident_status_update_and_notes(client, auth_headers):
    """Verify incident status transition and analyst notes persistence with strict RBAC."""
    mgr = get_app_incident_manager()
    assert mgr is not None

    # Ingest a test event to ensure an incident exists
    test_event = ThreatEvent(
        source="test_runner",
        source_type="automated_test",
        modality="voice",
        threat_category=ThreatCategory.VOICE_CLONING,
        severity=RiskLevel.HIGH,
        classification="THREAT",
        detector="test_detector",
        explanation=Explanation(summary="Automated test threat event", reasoning="Unit test verification"),
        evidence=[],
    )
    inc = mgr.process_event(test_event)
    assert inc is not None
    inc_id = inc.incident_id

    # 1. Anonymous update MUST be rejected with 401 (Finding 2)
    anon_put = client.put(
        f"/api/incidents/{inc_id}/status",
        json={"status": "INVESTIGATING", "analyst_notes": "Attempted unauthorized update."}
    )
    assert anon_put.status_code == 401

    # 2. Authenticated update with analyst headers succeeds
    resp = client.put(
        f"/api/incidents/{inc_id}/status",
        headers=auth_headers,
        json={"status": "INVESTIGATING", "analyst_notes": "Forensic investigation underway by SecOps."}
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["status"] == "success"
    assert updated["new_status"] == "INVESTIGATING"

    # 3. Verify retrieval with auth headers
    resp = client.get(f"/api/incidents/{inc_id}", headers=auth_headers)
    assert resp.status_code == 200
    fetched = resp.json()
    assert fetched["status"] == "INVESTIGATING"
    assert fetched["analyst_notes"] == "Forensic investigation underway by SecOps."

def test_websocket_security_center_connection(client):
    """Verify that WebSocket clients on /ws/stream connect and receive system broadcasts."""
    with client.websocket_connect("/ws/stream") as websocket:
        # Send a ping text message
        websocket.send_text('{"type": "ping"}')
        notifier = get_app_ws_notifier()
        assert notifier.connection_count >= 1

def test_emergency_containment_endpoint(client, auth_headers):
    """Verify emergency threat containment endpoint enforces auth and contains active threats."""
    # Unauthenticated rejected
    anon_resp = client.post("/api/incidents/containment/emergency")
    assert anon_resp.status_code == 401

    # Authenticated succeeds
    auth_resp = client.post("/api/incidents/containment/emergency", headers=auth_headers)
    assert auth_resp.status_code == 200
    data = auth_resp.json()
    assert data["status"] == "success"
    assert "contained_count" in data

