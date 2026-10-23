import io
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from backend.main import app
from backend.security.enforcement import get_enforcement_engine

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def admin_headers(client):
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}

def test_image_forensics_scan(client):
    """Verify visual deepfake and 2D FFT image forensics endpoint."""
    img = Image.new("RGB", (128, 128), color=(73, 109, 137))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    response = client.post(
        "/api/threats/image",
        files={"file": ("test_sample.png", buf, "image/png")},
        data={"source": "pytest"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "severity" in data
    assert "forensic_metrics" in data
    assert "fft_high_freq_ratio" in data["forensic_metrics"]
    assert "edge_variance" in data["forensic_metrics"]
    assert "manipulation_probability" in data["forensic_metrics"]
    assert "evidence" in data

def test_llm_cyber_analyst_layer(client):
    """Verify explainable LLM reasoning, Kill Chain, and MITRE ATT&CK mapping."""
    payload = {
        "incident_context": "Target employee received SMS with urgent link hxxp://secure-bank-login.top demanding 2FA codes.",
        "threat_type": "PHISHING_SOCIAL_ENG",
        "severity": "CRITICAL"
    }
    response = client.post("/api/threats/llm-analysis", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "executive_summary" in data
    assert "mitre_attack_techniques" in data
    assert len(data["mitre_attack_techniques"]) > 0
    assert "kill_chain_stage" in data
    assert "immediate_containment" in data
    assert "incident_response_playbook" in data

def test_organization_policy_lifecycle(client, admin_headers):
    """Verify fetching and enforcing organization security policy."""
    # 1. Fetch current policy
    resp = client.get("/api/admin/policy", headers=admin_headers)
    assert resp.status_code == 200
    current_policy = resp.json()
    assert "org_name" in current_policy or "policy_name" in current_policy
    assert "enforcement_action" in current_policy or "security_level" in current_policy

    # 2. Update policy
    update_data = {
        "policy_name": "Strict SOC Baseline",
        "enforcement_action": "FULL_BLOCK",
        "auto_block_threat_score": 0.80,
        "ddos_rate_limit_per_min": 150,
        "ddos_burst_threshold": 45,
        "email_notifications_enabled": True,
        "email_minimum_severity": "HIGH",
        "email_notification_recipients": ["soc-audit@cyberguard.local"]
    }
    post_resp = client.post("/api/admin/policy", json=update_data, headers=admin_headers)
    assert post_resp.status_code == 200
    updated = post_resp.json()
    assert "Strict SOC Baseline" in (updated.get("org_name", "") or updated.get("policy_name", "") or str(updated))

def test_enforcement_quarantine_registry(client, admin_headers):
    """Verify manual quarantine, status query, and unblocking."""
    engine = get_enforcement_engine()
    test_ip = "198.51.100.99"

    # Ensure unblocked initially
    engine.unblock_entity("ip", test_ip)

    # 1. Manual block
    block_resp = client.post(
        "/api/admin/enforcement/block",
        json={
            "entity_type": "ip",
            "entity_value": test_ip,
            "reason": "Pytest manual isolation test",
            "duration_seconds": 3600
        },
        headers=admin_headers
    )
    assert block_resp.status_code == 200
    assert block_resp.json()["status"] == "blocked"

    # Verify engine reports blocked
    is_blocked, _ = engine.is_ip_blocked(test_ip)
    assert is_blocked is True

    # 2. Query status
    status_resp = client.get("/api/admin/enforcement/status", headers=admin_headers)
    assert status_resp.status_code == 200
    blocked_ips = status_resp.json()["blocked_ips"]
    assert test_ip in blocked_ips

    # 3. Unblock
    unblock_resp = client.post(
        "/api/admin/enforcement/unblock",
        json={"entity_type": "ip", "entity_value": test_ip},
        headers=admin_headers
    )
    assert unblock_resp.status_code == 200
    assert unblock_resp.json()["status"] == "unblocked"
    is_blocked_after, _ = engine.is_ip_blocked(test_ip)
    assert is_blocked_after is False

def test_email_alerts_journal_and_test_dispatch(client, admin_headers):
    """Verify threshold email alerts log and simulated dispatch."""
    # 1. Dispatch test alert
    test_alert_resp = client.post(
        "/api/admin/email-alerts/test",
        json={"severity": "CRITICAL", "subject": "Simulated Automated Threat Escalation"},
        headers=admin_headers
    )
    assert test_alert_resp.status_code == 200
    assert test_alert_resp.json()["status"] == "dispatched"

    # 2. Query journal
    journal_resp = client.get("/api/admin/email-alerts", headers=admin_headers)
    assert journal_resp.status_code == 200
    data = journal_resp.json()
    alerts = data.get("email_alerts") or data.get("emails") or []
    assert len(alerts) > 0
    assert any("Simulated Automated Threat Escalation" in a.get("subject", "") for a in alerts)

def test_threat_report_generation_and_export(client, admin_headers):
    """Verify generating and exporting HTML, JSON, and CSV reports."""
    # 1. Generate report metadata
    gen_resp = client.post(
        "/api/admin/reports/generate",
        json={"incident_id": None, "report_format": "HTML", "title": "Pytest Threat Report"},
        headers=admin_headers
    )
    assert gen_resp.status_code == 200
    rep_meta = gen_resp.json()
    assert "report_id" in rep_meta

    # 2. Export direct report
    html_resp = client.get("/api/admin/reports/export?format=html&timeframe=24h", headers=admin_headers)
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["content-type"]
    assert "CYBERGUARD EXECUTIVE THREAT REPORT" in html_resp.text.upper()

    # 3. Export JSON report
    json_resp = client.get("/api/admin/reports/export?format=json&timeframe=24h", headers=admin_headers)
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]

    # 4. Export CSV report
    csv_resp = client.get("/api/admin/reports/export?format=csv&timeframe=24h", headers=admin_headers)
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
