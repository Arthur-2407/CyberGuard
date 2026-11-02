"""tests/test_audio_analysis_connectivity_repair.py

Automated test suite validating the complete CyberGuard audio-analysis route integration,
PNA loopback security, CORS configuration, centralized API client, and dual-mode reconnection.

Covers:
  - Test 1: Real local health check endpoint
  - Test 2: Audio analysis route contract (POST /api/analyze)
  - Test 3: HTTP 405 method rejection & preflight verification
  - Test 4: HTTP 404 route rejection without simulated security results
  - Test 5: GitHub Pages & Vercel CORS / Private Network Access headers
  - Test 6: Real audio analysis pipeline execution with genuine neural/prosodic inference
  - Test 7: Centralized API client & Chrome PNA targetAddressSpace integration in frontend/app.js
  - Test 8: 5-State connection lifecycle in CyberGuardConnection
  - Test 9: Zero secret leakage across all frontend assets
"""

import io
import re
import wave
import struct
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app, _cors_regex
from backend.storage.database import get_db_session

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _generate_test_wav_bytes(duration_sec=2.0, sample_rate=16000, freq=440.0) -> bytes:
    """Generate a valid, non-mocked 16kHz mono PCM WAV file in memory."""
    num_samples = int(duration_sec * sample_rate)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        # Synthesize a pure sine wave
        import math
        samples = [
            int(32767.0 * 0.5 * math.sin(2.0 * math.pi * freq * (i / sample_rate)))
            for i in range(num_samples)
        ]
        wf.writeframes(struct.pack(f"<{num_samples}h", *samples))
    return buf.getvalue()


# ── TEST 1: HEALTH ENDPOINT VERIFICATION ───────────────────────────────────────
def test_01_health_endpoint_contract(client):
    """Verify /api/health and /health return 200 with service metadata."""
    for path in ["/health", "/api/health"]:
        resp = client.get(path)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "ok"
        assert data.get("service") == "CyberGuard"
        assert "threat_intel" in data
        assert "detector_ready" in data


# ── TEST 2: AUDIO ROUTE CONTRACT (POST /api/analyze) ──────────────────────────
def test_02_audio_route_contract_with_real_wav(client):
    """
    Verify POST /api/analyze receives multipart audio payload,
    executes real analysis pipeline, and returns AnalysisResponse schema.
    """
    wav_bytes = _generate_test_wav_bytes(duration_sec=2.0)
    files = {"file": ("test_acoustic.wav", wav_bytes, "audio/wav")}

    resp = client.post("/api/analyze", files=files)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert "session_id" in data
    assert "filename" in data
    assert "total_chunks" in data
    assert data["total_chunks"] >= 1
    assert "peak_risk" in data
    assert "alert_level" in data
    assert "chunk_scores" in data
    assert "detector_state" in data
    assert "recommendation" in data
    assert isinstance(data["chunk_scores"], list)


# ── TEST 3: HTTP 405 METHOD REJECTION & PREFLIGHT VERIFICATION ─────────────────
def test_03_http_405_and_cors_preflight(client):
    """
    Verify GET /api/analyze is properly rejected with HTTP 405 Method Not Allowed,
    and OPTIONS preflights with PNA return 204 with required security headers.
    """
    # 1. GET is unsupported on POST-only route -> HTTP 405
    get_resp = client.get("/api/analyze")
    assert get_resp.status_code == 405, f"Expected 405, got {get_resp.status_code}"

    # 2. PNA Preflight from GitHub Pages
    gh_headers = {
        "Origin": "https://arthur-2407.github.io",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
        "Access-Control-Request-Private-Network": "true",
    }
    gh_resp = client.options("/api/analyze", headers=gh_headers)
    assert gh_resp.status_code == 204
    assert gh_resp.headers.get("access-control-allow-origin") == "https://arthur-2407.github.io"
    assert gh_resp.headers.get("access-control-allow-private-network") == "true"
    assert gh_resp.headers.get("access-control-allow-credentials") == "true"
    assert "POST" in gh_resp.headers.get("access-control-allow-methods", "")

    # 3. PNA Preflight from Vercel
    vercel_headers = {
        "Origin": "https://cyber-guard-backend-ashen.vercel.app",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
        "Access-Control-Request-Private-Network": "true",
    }
    vercel_resp = client.options("/api/analyze", headers=vercel_headers)
    assert vercel_resp.status_code == 204
    assert vercel_resp.headers.get("access-control-allow-origin") == "https://cyber-guard-backend-ashen.vercel.app"
    assert vercel_resp.headers.get("access-control-allow-private-network") == "true"


# ── TEST 4: HTTP 404 ROUTE REJECTION ──────────────────────────────────────────
def test_04_http_404_route_rejection(client):
    """
    Verify non-existent routes return HTTP 404 and never return fabricated security results.
    """
    resp = client.post("/api/nonexistent_route_test_404")
    assert resp.status_code == 404
    # Ensure no fabricated analysis response is returned
    data = resp.json()
    assert "peak_risk" not in data
    assert "detector_state" not in data


# ── TEST 5: CORS ORIGINS AND ALLOW-PRIVATE-NETWORK ────────────────────────────
def test_05_cors_origins_and_pna_header(client):
    """
    Verify POST requests with Origin headers include Access-Control-Allow-Origin
    and Access-Control-Allow-Private-Network headers.
    """
    resp = client.get("/api/health", headers={"Origin": "https://arthur-2407.github.io"})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "https://arthur-2407.github.io"
    assert resp.headers.get("access-control-allow-private-network") == "true"

    resp_v = client.get("/api/health", headers={"Origin": "https://cyber-guard-backend-ashen.vercel.app"})
    assert resp_v.status_code == 200
    assert resp_v.headers.get("access-control-allow-origin") == "https://cyber-guard-backend-ashen.vercel.app"
    assert resp_v.headers.get("access-control-allow-private-network") == "true"


# ── TEST 6: REAL AUDIO ANALYSIS PIPELINE WITH PITCH INFERENCE ─────────────────
def test_06_real_audio_pipeline_execution(client):
    """
    Verify real audio processing with acoustic feature extraction and pitch analysis.
    """
    # Use real test file from demo if available, otherwise synthetic WAV
    demo_file = ROOT_DIR / "demo" / "demo3.mp3"
    if demo_file.exists():
        payload_bytes = demo_file.read_bytes()
        filename = "demo3.mp3"
        content_type = "audio/mpeg"
    else:
        payload_bytes = _generate_test_wav_bytes(duration_sec=3.0)
        filename = "synthetic.wav"
        content_type = "audio/wav"

    files = {"file": (filename, payload_bytes, content_type)}
    resp = client.post("/api/analyze", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_chunks"] >= 1
    assert "pitch_analysis" in data
    assert "detector_version" in data


# ── TEST 7: CENTRALIZED API CLIENT & PNA IN FRONTEND/APP.JS ───────────────────
def test_07_centralized_api_client_and_pna_target_address_space():
    """
    Verify that frontend/app.js contains centralized CyberGuardClient,
    cyberGuardFetch, loopback detection, and targetAddressSpace: 'loopback'.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")

    assert "window.CyberGuardClient" in app_js, "Must export window.CyberGuardClient"
    assert "window.cyberGuardFetch" in app_js, "Must export window.cyberGuardFetch"
    assert "targetAddressSpace = 'loopback'" in app_js or "targetAddressSpace: 'loopback'" in app_js
    assert "isLoopbackUrl" in app_js
    assert "parseResponseSafely" in app_js
    assert "cyberGuardFetch('/api/analyze'" in app_js or 'cyberGuardFetch("/api/analyze"' in app_js


# ── TEST 8: 5-STATE CONNECTION LIFECYCLE ──────────────────────────────────────
def test_08_five_state_connection_lifecycle():
    """
    Verify that CyberGuardConnection in frontend/app.js implements all 5 states:
    DISCONNECTED, CONNECTING, CONNECTED, DEGRADED, ERROR.
    """
    app_js = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")

    for state in ["DISCONNECTED", "CONNECTING", "CONNECTED", "DEGRADED", "ERROR"]:
        assert state in app_js, f"Connection manager must support state {state}"

    assert "minRetryDelay: 5000" in app_js
    assert "maxRetryDelay: 30000" in app_js
    assert "backoffFactor: 1.5" in app_js
    assert "cancelPending" in app_js


# ── TEST 9: ZERO SECRET LEAKAGE ───────────────────────────────────────────────
def test_09_zero_secret_leakage_in_frontend():
    """
    Verify that no private keys, passwords, or provider tokens are exposed in frontend.
    """
    for file_path in [
        FRONTEND_DIR / "app.js",
        FRONTEND_DIR / "config.js",
        FRONTEND_DIR / "index.html",
        FRONTEND_DIR / "styles.css",
    ]:
        txt = file_path.read_text(encoding="utf-8")
        assert "VIRUSTOTAL_API_KEY=" not in txt
        assert "URLHAUS_AUTH_KEY=" not in txt
        assert "BREVO_API_KEY=" not in txt
        assert "SMTP_PASSWORD=" not in txt
        assert "CYBERGUARD_ADMIN_PASSWORD=" not in txt
        assert not re.search(r'["\'][a-fA-F0-9]{64}["\']', txt)
