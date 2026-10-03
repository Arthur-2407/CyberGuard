import pytest
from fastapi.testclient import TestClient
from backend.main import app, get_app_incident_manager, get_app_alert_manager, get_app_ws_notifier
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation, IncidentStatus

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_frontend_routes_served(client):
    """Verify Security Center and legacy compatibility routes return index.html."""
    for path in ["/", "/security-center", "/incidents", "/alerts"]:
        resp = client.get(path)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "SECURITY CENTER" in resp.text
        assert "panel-security-center" in resp.text

def test_incidents_api_endpoints(client):
    """Verify incidents and dashboard summary APIs."""
    # 1. Dashboard summary
    resp = client.get("/api/incidents/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_incidents" in data
    assert "open_incidents" in data

    # 2. Get all incidents
    resp = client.get("/api/incidents/")
    assert resp.status_code == 200
    incidents = resp.json()
    assert isinstance(incidents, list)

def test_events_api_endpoint(client):
    """Verify threat events query endpoint."""
    resp = client.get("/api/incidents/events?limit=10")
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

def test_incident_status_update_and_notes(client):
    """Verify incident status transition and analyst notes persistence."""
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

    # Update status to INVESTIGATING with analyst notes
    resp = client.put(
        f"/api/incidents/{inc_id}/status",
        json={"status": "INVESTIGATING", "analyst_notes": "Forensic investigation underway by SecOps."}
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["status"] == "success"
    assert updated["new_status"] == "INVESTIGATING"

    # Verify retrieval
    resp = client.get(f"/api/incidents/{inc_id}")
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
