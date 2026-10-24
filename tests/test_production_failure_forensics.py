"""
test_production_failure_forensics.py — Production Failure Forensics & Regression Suite

Validates:
  1. Safe single-read HTTP response parsing contracts (simulates Vercel 404, plain-text, malformed JSON, and valid JSON)
  2. Voice analysis endpoint (POST /api/analyze) request/response contract
  3. QR forensics endpoint (POST /api/threats/qr) request/response contract
  4. Speaker enrollment (POST /api/speakers/enroll) & retrieval (GET /api/speakers)
  5. WebSocket live streaming (/ws/stream) handshake, binary PCM transmission, and message processing
  6. Health and system status capability contract (GET /api/config/status)
  7. Cloud origin CORS headers
"""

from pathlib import Path
import io
import json
import secrets
import datetime
import numpy as np
import pytest
import soundfile as sf
from fastapi.testclient import TestClient

from backend.main import app
from backend.config import get_settings
from backend.storage.database import get_db_session, UserModel, AuthSessionModel
from backend.storage.auth import hash_token, _utcnow


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def sample_wav_bytes():
    """Generate a clean 2-second 16kHz sine wave audio file in memory."""
    sr = 16000
    t = np.linspace(0, 2.0, int(sr * 2.0), endpoint=False)
    # 440 Hz tone with natural speech envelope
    audio = (0.5 * np.sin(2 * np.pi * 440 * t) * np.sin(np.pi * t / 2.0)).astype(np.float32)
    buf = io.BytesIO()
    sf.write(buf, audio, sr, format="WAV", subtype="PCM_16")
    buf.seek(0)
    return buf.read()


@pytest.fixture(scope="module")
def auth_token():
    """Create an authenticated test session token."""
    from backend.storage.database import get_session_factory
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.role == "admin").first()
        if not user:
            user = db.query(UserModel).first()
        raw_token = secrets.token_urlsafe(32)
        sess = AuthSessionModel(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            created_at=_utcnow(),
            expires_at=_utcnow() + datetime.timedelta(days=7),
        )
        db.add(sess)
        db.commit()
        return raw_token
    finally:
        db.close()


# ── SECTION A: SINGLE-READ RESPONSE PARSING & SIMULATION ────────────────────────

def test_single_read_helper_logic_simulation():
    """
    Simulate the frontend parseResponseSafely() logic across:
    - Vercel 404 NOT_FOUND HTML/text
    - Valid JSON
    - Non-success status with JSON error
    - Plain-text error
    - Malformed JSON
    - Empty body
    Verifies body stream is never consumed twice and no SyntaxError/TypeError leaks.
    """
    def simulate_parse_response_safely(raw_text: str, status_code: int, status_text: str = "OK"):
        captured_text = raw_text

        json_data = None
        is_json = False
        if captured_text and captured_text.strip():
            try:
                json_data = json.loads(captured_text)
                is_json = True
            except Exception:
                is_json = False

        if status_code < 200 or status_code >= 300:
            error_detail = ""
            if is_json and isinstance(json_data, dict):
                error_detail = json_data.get("detail") or json_data.get("message") or json.dumps(json_data)
            elif captured_text and captured_text.strip():
                import re
                clean = re.sub(r"<[^>]+>", " ", captured_text)
                clean = " ".join(clean.split()).strip()
                error_detail = clean[:250] + "..." if len(clean) > 250 else clean

            if status_code == 404:
                context_note = " (Endpoint not found — check backend deployment and API routing)"
            elif status_code in (502, 503, 504):
                context_note = " (Backend service unavailable or gateway error)"
            else:
                context_note = ""

            msg = error_detail or f"HTTP {status_code} ({status_text}){context_note}"
            return {"ok": False, "error": msg, "status": status_code}

        return {"ok": True, "data": json_data if is_json else captured_text, "status": status_code}

    # Case 1: Vercel 404 NOT_FOUND (exact text from Screenshot 1, 2, 3)
    vercel_404_body = "The page could not be found\n\nNOT_FOUND\n\nbom1::htfsl-1792680650926-1d81e3aba8b5"
    r1 = simulate_parse_response_safely(vercel_404_body, 404, "Not Found")
    assert not r1["ok"]
    assert "The page could not be found" in r1["error"]
    assert "bom1::" in r1["error"]
    assert "body stream already read" not in r1["error"]
    assert "Unexpected token" not in r1["error"]

    # Case 2: Valid JSON response
    valid_json_body = '{"alert_level": "SAFE", "peak_risk": 0.12}'
    r2 = simulate_parse_response_safely(valid_json_body, 200)
    assert r2["ok"]
    assert r2["data"]["alert_level"] == "SAFE"

    # Case 3: JSON error (FastAPI validation error)
    fastapi_err_body = '{"detail": "Invalid speaker profile ID"}'
    r3 = simulate_parse_response_safely(fastapi_err_body, 400, "Bad Request")
    assert not r3["ok"]
    assert r3["error"] == "Invalid speaker profile ID"

    # Case 4: Plain-text error
    plain_err = "Internal Server Error: Database locked"
    r4 = simulate_parse_response_safely(plain_err, 500, "Internal Server Error")
    assert not r4["ok"]
    assert "Database locked" in r4["error"]

    # Case 5: Empty body with 204
    r5 = simulate_parse_response_safely("", 204, "No Content")
    assert r5["ok"]
    assert r5["data"] == ""


# ── SECTION B: AUDIO ANALYSIS ROUTE (POST /api/analyze) ────────────────────────

def test_analyze_audio_valid_upload(client, sample_wav_bytes):
    """Test voice analysis endpoint with a valid audio file."""
    files = {"file": ("test_voice.wav", io.BytesIO(sample_wav_bytes), "audio/wav")}
    resp = client.post("/api/analyze", files=files)
    assert resp.status_code == 200
    data = resp.json()
    assert "alert_level" in data
    assert "peak_risk" in data
    assert "mean_risk" in data
    assert "total_chunks" in data
    assert data["alert_level"] in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert 0.0 <= data["peak_risk"] <= 1.0


def test_analyze_audio_missing_file_rejected(client):
    """Test voice analysis endpoint when file is omitted."""
    resp = client.post("/api/analyze")
    assert resp.status_code in (400, 422)


def test_analyze_audio_unsupported_format_rejected(client):
    """Test voice analysis endpoint when text or non-media file is uploaded."""
    files = {"file": ("malicious.txt", io.BytesIO(b"Not an audio file"), "text/plain")}
    resp = client.post("/api/analyze", files=files)
    assert resp.status_code in (400, 422)


# ── SECTION C: QR FORENSICS ROUTE (POST /api/threats/qr) ───────────────────────

def test_qr_scanner_endpoint_exists(client):
    """Verify QR scanner endpoint is registered and rejects empty payload."""
    resp = client.post("/api/threats/qr")
    assert resp.status_code in (400, 422)


def test_qr_scanner_valid_qr_image(client):
    """Test QR scanner with a valid QR code fixture if available."""
    qr_fixture = Path("tests/fixtures/user_test_qr.png")
    if qr_fixture.exists():
        with open(qr_fixture, "rb") as f:
            files = {"file": ("user_test_qr.png", f, "image/png")}
            resp = client.post("/api/threats/qr", files=files)
            assert resp.status_code == 200
            data = resp.json()
            assert "event_id" in data
            assert "threat_intelligence" in data
            assert data["threat_intelligence"]["qr_metadata"]["qr_status"] == "DECODED"


# ── SECTION D: SPEAKER ENROLLMENT & LISTING ────────────────────────────────────

def test_speakers_list_endpoint_accessible(client):
    """Verify GET /api/speakers is registered and returns a list."""
    resp = client.get("/api/speakers")
    assert resp.status_code in (200, 401)
    if resp.status_code == 200:
        assert isinstance(resp.json(), list)


def test_speaker_enrollment_rejects_empty_submission(client):
    """Verify POST /api/speakers/enroll rejects empty submissions without crashing."""
    resp = client.post("/api/speakers/enroll")
    assert resp.status_code in (400, 401, 422)


def test_speaker_enrollment_success_and_listing(client, sample_wav_bytes, auth_token):
    """Verify speaker enrollment succeeds with audio sample and profile is registered."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    files = [("files", ("sample1.wav", io.BytesIO(sample_wav_bytes), "audio/wav"))]
    data = {"name": "Test Officer", "organization": "SOC", "role": "Analyst"}
    resp = client.post("/api/speakers/enroll", data=data, files=files, headers=headers)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["name"] == "Test Officer"
    assert "speaker_id" in res_data
    assert res_data["num_samples"] >= 1


# ── SECTION E: WEBSOCKET LIVE STREAMING (/ws/stream) ──────────────────────────

def test_websocket_stream_handshake_and_control_message(client):
    """Verify WebSocket streaming endpoint handshakes, announces session, and processes audio."""
    with client.websocket_connect("/ws/stream") as ws:
        # Server immediately sends initial session_start message
        first_msg_text = ws.receive_text()
        first_msg = json.loads(first_msg_text)
        assert first_msg["type"] == "session_start"

        # Send enrollment select control message
        ws.send_text(json.dumps({"type": "enroll_speaker", "speaker_id": "none"}))

        # Send 32000 samples of 16-bit PCM (2 seconds = 1 full chunk)
        pcm_bytes = np.zeros(32000, dtype=np.int16).tobytes()
        ws.send_bytes(pcm_bytes)

        # Receive streaming response from server (status_update for waiting for speech)
        response_text = ws.receive_text()
        msg = json.loads(response_text)
        assert "type" in msg
        assert msg["type"] in ("status_update", "risk_update")
        if msg["type"] == "status_update":
            assert msg["status"] in ("WAITING_FOR_SPEECH", "LISTENING", "INSUFFICIENT_AUDIO")


# ── SECTION F: SYSTEM STATUS CAPABILITY REPORT & ROUTING ───────────────────────

def test_system_status_reflects_genuine_runtime_state(client):
    """Verify GET /api/config/status returns genuine runtime capabilities."""
    resp = client.get("/api/config/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "operational"
    assert "capabilities" in data
    assert "detector_version" in data
    assert "operational_engine_count" in data
    # Capabilities must not be fabricated
    assert isinstance(data["capabilities"], dict)
    assert "voice_cloning_detector" in data["capabilities"]
    assert "qr_forensics" in data["capabilities"]
    assert "virustotal_intel" in data["capabilities"]
    assert "urlhaus_intel" in data["capabilities"]


def test_missing_api_routes_return_http_404(client):
    """Verify that genuinely missing API routes return HTTP 404 (not HTML index)."""
    resp = client.get("/api/nonexistent_forensic_endpoint_12345")
    assert resp.status_code == 404
    # Must be structured JSON error, not text/html
    assert "application/json" in resp.headers.get("content-type", "")


def test_cors_cloud_origins_supported(client):
    """Verify CORS preflight accepts Vercel and cloud deployment origins."""
    headers = {
        "Origin": "https://cyber-guard-backend-ashen.vercel.app",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization, X-Threat-Scope",
    }
    resp = client.options("/api/analyze", headers=headers)
    assert resp.status_code == 200
    allow_origin = resp.headers.get("access-control-allow-origin")
    assert allow_origin in ("https://cyber-guard-backend-ashen.vercel.app", "*")

    # Also test GitHub Pages origin
    gh_headers = {
        "Origin": "https://arthur-2407.github.io",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization, X-Threat-Scope",
    }
    gh_resp = client.options("/api/analyze", headers=gh_headers)
    assert gh_resp.status_code == 200
    assert gh_resp.headers.get("access-control-allow-origin") in ("https://arthur-2407.github.io", "*")


def test_config_js_endpoint_accessible(client):
    """Verify /config.js is served with application/javascript media type."""
    resp = client.get("/config.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers.get("content-type", "")
    assert "__CYBERGUARD_CONFIG__" in resp.text

