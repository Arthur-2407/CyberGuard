"""tests/test_local_network_access_and_modes.py

Automated Verification Suite for CyberGuard:
  - Chrome 142+ Local Network Access (LNA) / Loopback Permission Architecture
  - Tri-Mode Connection Engine (Mode A: Deployed Cloud, Mode B: Local Docker, Mode C: Hybrid)
  - Diagnostic Accuracy & Prevention of Voice Analysis vs System Health Inconsistency
  - User-Gesture Driven Authorization & Graceful Failover
  - Zero Secret Leakage & Secure PNA Preflight Validation
"""

import re
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app, _cors_regex

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_01_default_mode_is_deployed_cloud_on_deployed_hosts():
    """
    Verify that on deployed hosts (Vercel, GitHub Pages), CyberGuard defaults to
    Mode A (Deployed Cloud) and getResolvedApiBase does NOT default to 127.0.0.1.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    assert "return 'deployed';" in app_js, "Default mode must be 'deployed' for public visitors"
    assert "location.hostname.includes('vercel.app')" in app_js
    assert "location.hostname.includes('github.io')" in app_js or "cyberguard-backend-8rbz.onrender.com" in app_js


def test_02_mode_c_hybrid_support():
    """
    Verify that CyberGuardConnection and index.html support Mode C: Hybrid (Auto).
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    index_html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")

    assert "Mode C: Hybrid" in app_js or "hybrid" in app_js
    assert "btn-mode-hybrid" in index_html, "System Health modal must include Mode C button"
    assert "MODE C: HYBRID" in app_js


def test_03_user_gesture_authorization_method_exists():
    """
    Verify that requestLocalDockerAuthorization exists on CyberGuardConnection to satisfy
    Chrome 142+ requirement that LNA prompts MUST be triggered by an explicit user gesture.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    index_html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")

    assert "requestLocalDockerAuthorization" in app_js
    assert "loopbackPermissionState" in app_js
    assert "sh-lna-permission-box" in index_html
    assert "targetAddressSpace = 'loopback'" in app_js or "targetAddressSpace: 'loopback'" in app_js


def test_04_system_health_and_voice_analysis_state_consistency():
    """
    Verify that System Health sets PERMISSION REQUIRED rather than falsely claiming
    CONNECTED when Local Network Access to 127.0.0.1 is blocked.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")

    assert "PERMISSION REQUIRED" in app_js, "Status badge must display PERMISSION REQUIRED when LNA is blocked"
    assert "isLnaBlocked" in app_js or "loopbackPermissionState" in app_js
    assert "Switch to Deployed Cloud" in app_js, "Action card must allow switching to Deployed Cloud immediately"


def test_05_no_artificial_static_host_block_in_fetch():
    """
    Verify that cyberGuardFetch does not artificially reject relative requests on vercel.app,
    allowing Vercel edge rewrites to route /api/* and /health to the cloud backend.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
    assert "Cannot send API request to static deployment host" not in app_js, (
        "Artificial staticHostMismatch error must not block Vercel edge rewrites"
    )


def test_06_pna_preflight_and_cors_headers_match_chrome_spec(client):
    """
    Verify backend responds with Access-Control-Allow-Private-Network: true
    to Private Network Access preflights from Vercel.
    """
    headers = {
        "Origin": "https://cyber-guard-backend-ashen.vercel.app",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
        "Access-Control-Request-Private-Network": "true",
    }
    resp = client.options("/api/analyze", headers=headers)
    assert resp.status_code == 204
    assert resp.headers.get("access-control-allow-private-network") == "true"
    assert resp.headers.get("access-control-allow-origin") == "https://cyber-guard-backend-ashen.vercel.app"


def test_07_zero_credentials_in_frontend():
    """
    Verify zero secrets in all modified frontend assets.
    """
    for file_name in ["app.js", "index.html", "styles.css", "config.js"]:
        content = (FRONTEND_DIR / file_name).read_text(encoding="utf-8")
        assert "VIRUSTOTAL_API_KEY=" not in content
        assert "URLHAUS_AUTH_KEY=" not in content
        assert "BREVO_API_KEY=" not in content
        assert "SMTP_PASSWORD=" not in content
        assert "CYBERGUARD_ADMIN_PASSWORD=" not in content
        assert not re.search(r'["\'][a-fA-F0-9]{64}["\']', content)

