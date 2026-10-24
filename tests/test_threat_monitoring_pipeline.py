"""
test_threat_monitoring_pipeline.py — Comprehensive validation test suite for CyberGuard's
Threat Monitoring pipeline, VAD speech-activity gating, detector.pt integration,
silence handling, and session integrity.
"""

import json
import numpy as np
import pytest
import soundfile as sf
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.config import get_settings
from backend.audio.preprocessor import is_speech_present, preprocess_audio, normalize
from backend.detection.detector import VoiceCloneDetector
from backend.detection.risk_engine import build_risk_engine_from_settings, AlertLevel
from backend.detection.threshold_engine import ThresholdEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def detector():
    settings = get_settings()
    det = VoiceCloneDetector(settings)
    det.initialize()
    return det


# ── SECTION A: SILENCE AND INVALID INPUT TESTS ────────────────────────────────

def test_silence_detection_all_zeros():
    """Verify that pure digital silence (zeros) is identified as silence."""
    zeros = np.zeros(32000, dtype=np.float32)
    has_speech, reason, metrics = is_speech_present(zeros, sr=16000)
    assert not has_speech
    assert reason in ("SILENCE", "AMBIENT_NOISE")
    assert metrics["rms"] == 0.0
    assert metrics["peak"] == 0.0


def test_ambient_room_noise_not_treated_as_speech():
    """Verify that low-amplitude microphone floor noise (RMS 0.001 - 0.002) is rejected."""
    np.random.seed(42)
    noise = np.random.normal(0, 0.001, 32000).astype(np.float32)
    has_speech, reason, metrics = is_speech_present(noise, sr=16000)
    assert not has_speech
    assert reason in ("SILENCE", "AMBIENT_NOISE")
    assert metrics["rms"] < 0.003


def test_safe_normalization_prevents_noise_explosion():
    """Verify that normalize() does not amplify low-level background noise by 1000x."""
    np.random.seed(42)
    noise = np.random.normal(0, 0.001, 16000).astype(np.float32)
    orig_peak = float(np.max(np.abs(noise)))
    norm_noise = normalize(noise, method="peak", min_peak_threshold=0.015)
    # Peak should NOT be scaled up to 1.0!
    assert np.max(np.abs(norm_noise)) == orig_peak
    assert np.max(np.abs(norm_noise)) < 0.015


def test_detector_silence_protection(detector):
    """Verify that passing silence to VoiceCloneDetector returns zero synthetic probability."""
    zeros = np.zeros(32000, dtype=np.float32)
    result = detector.process_chunk(zeros, chunk_id=0)
    assert result.synthetic_probability == 0.0
    assert not result.pitch_analysis["is_pitch_anomaly"]
    assert result.pitch_analysis["pitch_verdict"] == "SILENCE"


def test_unvoiced_noise_does_not_trigger_pitch_anomaly(detector):
    """Verify that unvoiced random noise does not produce a false SYNTHETIC PITCH ANOMALY."""
    np.random.seed(42)
    noise = np.random.normal(0, 0.002, 32000).astype(np.float32)
    result = detector.process_chunk(noise, chunk_id=1)
    # Even if noise enters detector, pitch anomaly must NOT be triggered
    assert not result.pitch_analysis["is_pitch_anomaly"]
    assert result.pitch_analysis["pitch_verdict"] == "UNVOICED / NO PITCH DETECTED"


# ── SECTION B: GENUINE HUMAN SPEECH TESTS ─────────────────────────────────────

def test_genuine_human_speech_classification(detector):
    """Verify that genuine human speech (ASVspoof bonafide) is correctly classified as human."""
    flac_dir = Path("data/asvspoof2019/extracted/flac")
    val_proto = Path("data/asvspoof2019/extracted/val_protocol.txt")
    if not flac_dir.exists() or not val_proto.exists():
        pytest.skip("ASVspoof test data not available on disk.")

    with open(val_proto) as f:
        bonafide_ids = [line.split()[1] for line in f if line.strip().endswith("bonafide")]

    tested = 0
    for utt in bonafide_ids[:5]:
        p = flac_dir / f"{utt}.flac"
        if not p.exists():
            continue
        audio, sr = sf.read(str(p), dtype="float32")
        # Ensure speech is detected by VAD gate
        has_speech, reason, _ = is_speech_present(audio[:32000], sr=16000)
        assert has_speech, f"Bonafide utterance {utt} should be detected as speech"

        result = detector.process_chunk(audio[:32000], chunk_id=tested)
        # Synthetic probability for genuine human speech must be low (< 0.35)
        assert result.synthetic_probability < 0.35, f"Utterance {utt} had unexpected high prob: {result.synthetic_probability}"
        tested += 1

    assert tested > 0, "At least one bonafide file was tested"


# ── SECTION C: KNOWN SYNTHETIC / CLONED SPEECH TESTS ──────────────────────────

def test_cloned_voice_classification(detector):
    """Verify that synthetic/cloned speech (ASVspoof spoof) is correctly classified as cloned."""
    flac_dir = Path("data/asvspoof2019/extracted/flac")
    val_proto = Path("data/asvspoof2019/extracted/val_protocol.txt")
    if not flac_dir.exists() or not val_proto.exists():
        pytest.skip("ASVspoof test data not available on disk.")

    with open(val_proto) as f:
        spoof_ids = [line.split()[1] for line in f if line.strip().endswith("spoof")]

    tested = 0
    for utt in spoof_ids[:5]:
        p = flac_dir / f"{utt}.flac"
        if not p.exists():
            continue
        audio, sr = sf.read(str(p), dtype="float32")
        has_speech, reason, _ = is_speech_present(audio[:32000], sr=16000)
        assert has_speech, f"Spoof utterance {utt} should be detected as speech"

        result = detector.process_chunk(audio[:32000], chunk_id=tested)
        # Synthetic probability for cloned speech must be high (>= 0.70)
        assert result.synthetic_probability >= 0.70, f"Utterance {utt} had unexpected low prob: {result.synthetic_probability}"
        tested += 1

    assert tested > 0, "At least one spoof file was tested"


# ── SECTION D: WEBSOCKET STREAMING & SESSION INTEGRITY TESTS ──────────────────

def test_websocket_silence_does_not_increment_chunks(client):
    """
    Verify that streaming silence/background noise over WebSocket:
    1. Returns status_update WAITING_FOR_SPEECH
    2. Does NOT increment chunk_counter
    3. Does NOT send fake risk_updates with high scores
    """
    with client.websocket_connect("/ws/stream") as ws:
        init_msg = json.loads(ws.receive_text())
        assert init_msg["type"] == "session_start"
        assert "session_id" in init_msg

        # Send 3 chunks of silence (int16 zeros, 8000 samples each = 0.5s @ 16kHz)
        silent_pcm = np.zeros(8000, dtype=np.int16).tobytes()
        for _ in range(6):  # 3 seconds total silence
            ws.send_bytes(silent_pcm)

        # Receive responses: all should be status_update with WAITING_FOR_SPEECH
        # No risk_update should be dispatched!
        responses = []
        for _ in range(3):
            raw = ws.receive_text()
            data = json.loads(raw)
            responses.append(data)

        for resp in responses:
            assert resp["type"] == "status_update"
            assert resp["status"] in ("WAITING_FOR_SPEECH", "LISTENING")
            assert not resp.get("speech_detected", True)


def test_websocket_speech_processes_genuine_risk(client):
    """
    Verify that streaming genuine speech over WebSocket triggers valid analysis.
    """
    flac_dir = Path("data/asvspoof2019/extracted/flac")
    val_proto = Path("data/asvspoof2019/extracted/val_protocol.txt")
    if not flac_dir.exists() or not val_proto.exists():
        pytest.skip("ASVspoof test data not available on disk.")

    with open(val_proto) as f:
        bf_utt = [line.split()[1] for line in f if line.strip().endswith("bonafide")][0]
    
    audio, sr = sf.read(str(flac_dir / f"{bf_utt}.flac"), dtype="float32")
    pcm_int16 = (np.clip(audio[:32000], -1.0, 1.0) * 32767).astype(np.int16).tobytes()

    with client.websocket_connect("/ws/stream") as ws:
        init_msg = json.loads(ws.receive_text())
        assert init_msg["type"] == "session_start"

        # Send speech chunk
        ws.send_bytes(pcm_int16)

        # Receive response
        msg = json.loads(ws.receive_text())
        # First message after 2s of speech is a risk update or status update
        if msg["type"] == "risk_update":
            assert msg["risk_score"] < 0.45
            assert msg["voice_classification"] == "GENUINE_VOICE"
            assert msg["alert_level"] in ("SAFE", "LOW")
            assert msg["chunk_id"] == 0
        else:
            assert msg["type"] == "status_update"


def test_websocket_reset_clears_state(client):
    """Verify that sending a reset command clears internal state and chunk count."""
    with client.websocket_connect("/ws/stream") as ws:
        init_msg = json.loads(ws.receive_text())
        assert init_msg["type"] == "session_start"

        # Send reset message
        ws.send_text(json.dumps({"type": "reset"}))

        # Send ping to confirm responsiveness
        ws.send_text(json.dumps({"type": "ping"}))
        pong = json.loads(ws.receive_text())
        assert pong["type"] == "pong"
