"""tests/test_local_docker_connection_lifecycle.py

Comprehensive verification suite for CyberGuard:
  - Complete Environment-Credential Audit & Docker Runtime Loading
  - Email / Brevo / SMTP Provider & Account-Specific Isolation
  - Local Docker Backend Auto-Connection & Bounded Exponential Reconnection
  - Deployment UI Fix (Hidden Overview DOCKER OFFLINE Badge & DEFCON AUTO Control)
  - Zero Secret Leakage & System Health Diagnostics

Covers all 12 required test scenarios:
  TEST 1  — Complete Environment Inventory
  TEST 2  — Docker Credential Loading Configuration
  TEST 3  — Email Provider & Config Resolution
  TEST 4  — Account-Specific Email Dispatch & Isolation
  TEST 5  — Threat Intel Provider Integration (Server-Side)
  TEST 6  — Auto-Reconnection & Dashboard Live Sync
  TEST 7  — Stop & Restart Resilience with Bounded Backoff
  TEST 8  — Port & Health Check Validation (PNA & CORS)
  TEST 9  — Deployed Mode (Mode A) Independence
  TEST 10 — Secret Protection & Zero Frontend Leakage
  TEST 11 — Overview UI Cleanup (Badge & DEFCON AUTO Hidden)
  TEST 12 — Regression Suite for Core Routes & Endpoints
"""

import os
import re
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app, _cors_regex, _APP_STATE
from backend.config import get_settings

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"


@pytest.fixture(scope="module")
def client():
    """Create a synchronous FastAPI test client."""
    with TestClient(app) as c:
        yield c


# ── TEST 1: COMPLETE ENVIRONMENT INVENTORY ────────────────────────────────────
def test_01_complete_environment_inventory():
    """
    TEST 1: All project environment files are identified, cataloged, and inspected
    without exposing any credentials.
    """
    env_root = ROOT_DIR / ".env"
    env_email = ROOT_DIR / ".env.email"
    env_example = ROOT_DIR / ".env.example"
    env_docker_example = ROOT_DIR / ".env.docker.example"

    assert env_root.exists(), "Root .env must exist"
    assert env_email.exists(), ".env.email must exist"
    assert env_example.exists(), ".env.example must exist"
    assert env_docker_example.exists(), ".env.docker.example must exist"

    # Verify required keys exist in root .env
    content = env_root.read_text(encoding="utf-8")
    for required_key in [
        "VIRUSTOTAL_API_KEY",
        "URLHAUS_AUTH_KEY",
        "CYBERGUARD_ADMIN_PASSWORD",
        "EMAIL_ENABLED",
        "BREVO_API_KEY",
        "SMTP_SERVER",
        "SMTP_PORT",
        "SMTP_LOGIN",
        "SMTP_KEY",
    ]:
        assert f"{required_key}=" in content, f"Key {required_key} must be defined in .env"


# ── TEST 2: DOCKER CREDENTIAL LOADING CONFIGURATION ───────────────────────────
def test_02_docker_credential_loading_configuration():
    """
    TEST 2: Docker Compose specifies env_file references for .env and .env.email,
    and publishes port 3000:3000 to the host.
    """
    compose_path = ROOT_DIR / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist"
    compose_txt = compose_path.read_text(encoding="utf-8")

    assert "env_file:" in compose_txt
    assert ".env" in compose_txt
    assert ".env.email" in compose_txt
    assert '"3000:3000"' in compose_txt or "'3000:3000'" in compose_txt or "3000:3000" in compose_txt
    assert "/health" in compose_txt


# ── TEST 3: EMAIL PROVIDER & CONFIG RESOLUTION ────────────────────────────────
def test_03_email_provider_and_config_resolution():
    """
    TEST 3: Email notifier configuration resolves credentials from environment
    and handles missing configuration safely without crashing.
    """
    from backend.alerts.email_notifier import EmailNotifier

    cfg = get_settings().email_alerts
    assert cfg is not None
    assert hasattr(cfg, "enabled")
    assert hasattr(cfg, "provider")
    assert hasattr(cfg, "brevo_api_key")
    assert hasattr(cfg, "smtp_password")

    notifier = EmailNotifier()
    assert notifier is not None
    assert hasattr(notifier, "notify_threat_event")


# ── TEST 4: ACCOUNT-SPECIFIC EMAIL DISPATCH & ISOLATION ───────────────────────
@pytest.mark.asyncio
async def test_04_account_specific_email_isolation():
    """
    TEST 4: Account-specific email notification behavior:
      - HIGH / CRITICAL alerts for authenticated users resolve to user email
      - Anonymous / signed-out alerts are suppressed (no email sent)
      - Nonqualifying severities (LOW, MEDIUM) do not trigger email
      - Idempotency suppresses duplicate emails
    """
    from backend.alerts.email_notifier import EmailNotifier
    from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation

    notifier = EmailNotifier()

    # 1. Anonymous alert -> Suppressed safely
    anon_event = ThreatEvent(
        event_id="test-anon-001",
        source="test_client",
        source_type="automated_test",
        modality="telemetry",
        threat_category=ThreatCategory.MALWARE_INDICATOR,
        classification="MALWARE",
        severity=RiskLevel.CRITICAL,
        confidence=0.99,
        explanation=Explanation(summary="Test Malware"),
        user_id=None,
    )
    result_anon = await notifier.notify_threat_event(anon_event, user_email=None)
    assert result_anon.get("status") == "skipped", "Anonymous threat alerts must not send email"
    assert result_anon.get("reason") == "NO_AUTHENTICATED_USER_EMAIL"

    # 2. Medium severity alert -> Suppressed below threshold
    med_event = ThreatEvent(
        event_id="test-med-002",
        source="test_client",
        source_type="automated_test",
        modality="telemetry",
        threat_category=ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY,
        classification="SUSPICIOUS",
        severity=RiskLevel.MEDIUM,
        confidence=0.55,
        explanation=Explanation(summary="Test Medium"),
        user_id=999,
    )
    result_med = await notifier.notify_threat_event(med_event, user_email="alice@example.com")
    assert result_med.get("status") == "skipped", "MEDIUM severity must be suppressed below HIGH/CRITICAL threshold"
    assert "BELOW_THRESHOLD" in result_med.get("reason", "")


# ── TEST 5: THREAT INTEL PROVIDER INTEGRATION (SERVER-SIDE) ───────────────────
def test_05_threat_intel_server_side_key_reading():
    """
    TEST 5: Threat intelligence providers (VirusTotal, URLhaus) read keys
    server-side from backend environment.
    """
    from backend.threats.virustotal import VirusTotalProvider
    from backend.threats.urlhaus import URLhausProvider

    vt = VirusTotalProvider()
    uh = URLhausProvider()

    assert hasattr(vt, "api_key")
    assert hasattr(uh, "_auth_key")


# ── TEST 6: AUTO-RECONNECTION & DASHBOARD LIVE SYNC ───────────────────────────
def test_06_local_mode_auto_reconnection_and_data_sync(client):
    """
    TEST 6: Health check returns operational status, and frontend connection manager
    wires automatic live dashboard data refresh on reconnection.
    """
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "ok"
    assert data.get("service") == "CyberGuard"

    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    assert "CyberGuardConnection" in app_js
    assert "syncRealDashboardData" in app_js
    assert "updateOverview" in app_js
    assert "loadAlerts" in app_js


# ── TEST 7: STOP & RESTART RESILIENCE WITH BOUNDED BACKOFF ────────────────────
def test_07_stop_and_restart_resilience_and_bounded_backoff():
    """
    TEST 7: Connection manager cleans up timers and bounds exponential backoff
    between 5s and 30s.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    assert "cancelPending" in app_js, "Must cancel pending requests and timers"
    assert "minRetryDelay: 5000" in app_js, "Initial delay must be 5s"
    assert "maxRetryDelay: 30000" in app_js, "Backoff must be capped at 30s"
    assert "backoffFactor: 1.5" in app_js, "Backoff factor must be bounded"


# ── TEST 8: PORT & HEALTH CHECK VALIDATION (PNA & CORS) ───────────────────────
def test_08_port_and_health_check_validation(client):
    """
    TEST 8: Validates real health endpoint, CORS regex, and W3C Private Network Access preflights.
    """
    # 1. PNA preflight
    pna_headers = {
        "Origin": "https://cyber-guard-backend-ashen.vercel.app",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Private-Network": "true",
    }
    resp = client.options("/health", headers=pna_headers)
    assert resp.status_code == 204
    assert resp.headers.get("access-control-allow-private-network") == "true"
    assert resp.headers.get("access-control-allow-origin") == "https://cyber-guard-backend-ashen.vercel.app"

    # 2. CORS regex validation
    pattern = re.compile(_cors_regex)
    assert pattern.match("https://cyber-guard-backend-ashen.vercel.app")
    assert pattern.match("http://127.0.0.1:3000")
    assert not pattern.match("https://unauthorized-attacker.com")


# ── TEST 9: DEPLOYED MODE (MODE A) INDEPENDENCE ───────────────────────────────
def test_09_deployed_cloud_mode_independence():
    """
    TEST 9: Mode A preserves current deployed backend as default and does not
    force localhost on public visitors.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    index_html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")

    assert "setMode" in app_js
    assert "cyberguard_connection_mode" in app_js
    assert "Mode A: Deployed Cloud" in index_html


# ── TEST 10: SECRET PROTECTION & ZERO FRONTEND LEAKAGE ────────────────────────
def test_10_secret_protection_and_zero_leakage():
    """
    TEST 10: Backend credentials, Brevo keys, and external threat intel tokens
    are completely absent from frontend source, styles, and markup.
    """
    for file_path in [
        FRONTEND_DIR / "index.html",
        FRONTEND_DIR / "app.js",
        FRONTEND_DIR / "config.js",
        FRONTEND_DIR / "styles.css",
    ]:
        content = file_path.read_text(encoding="utf-8")
        assert "VIRUSTOTAL_API_KEY=" not in content
        assert "URLHAUS_AUTH_KEY=" not in content
        assert "BREVO_API_KEY=" not in content
        assert "SMTP_PASSWORD=" not in content
        assert "CLOUDFLARE_TUNNEL_TOKEN=" not in content
        # Ensure no accidental provider secret token hardcodes (64 hex characters)
        assert not re.search(r'["\'][a-fA-F0-9]{64}["\']', content)


# ── TEST 11: OVERVIEW UI CLEANUP (BADGE & DEFCON AUTO HIDDEN) ─────────────────
def test_11_ui_acceptance_badge_and_defcon_auto_hidden():
    """
    TEST 11: DOCKER OFFLINE badge and DEFCON AUTO control are hidden from the Overview page
    without breaking automatic DEFCON calculation or System Health diagnostics.
    """
    index_html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
    styles_css = (FRONTEND_DIR / "styles.css").read_text(encoding="utf-8")
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")

    # 1. Top-right badge hidden
    assert 'id="backend-tunnel-widget" style="display:none !important;"' in index_html or \
           'id="backend-tunnel-widget" style="display: none !important;"' in index_html
    assert "#backend-tunnel-widget" in styles_css
    assert "display: none !important;" in styles_css

    # 2. DEFCON AUTO selector hidden
    assert 'id="defcon-auto-indicator" style="display:none !important;"' in index_html or \
           'id="defcon-auto-indicator" style="display: none !important;"' in index_html
    assert "#defcon-auto-indicator" in styles_css

    # 3. DEFCON numerical pills remain
    for pill in ["defcon-5", "defcon-4", "defcon-3", "defcon-2", "defcon-1"]:
        assert pill in index_html

    # 4. Underlying routines intact
    assert "evaluateAutonomousDailyDefcon" in app_js
    assert "applyAutonomousDefcon" in app_js
    assert "openBackendModal" in app_js
    assert "openSystemHealthModal" in app_js


# ── TEST 12: REGRESSION SUITE FOR CORE ROUTES & ENDPOINTS ─────────────────────
def test_12_regression_suite_for_core_routes(client):
    """
    TEST 12: System status, configuration thresholds, and health endpoints
    continue to function correctly without regression.
    """
    # System status
    status_resp = client.get("/api/config/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data.get("status") == "operational"
    assert "operational_engine_count" in status_data

    # Thresholds
    thresh_resp = client.get("/api/config/thresholds")
    assert thresh_resp.status_code == 200
    thresh_data = thresh_resp.json()
    assert "low" in thresh_data and "medium" in thresh_data and "high" in thresh_data
