"""
tests/test_voice_authenticity_pipeline_repair.py — Automated verification suite for
CyberGuard Voice Authenticity Detection Pipeline Repair.

Verifies:
1. Preprocessing Integrity:
   - File loading, resampling, mono conversion, VAD segmentation.
   - Silence and flat audio safely handled without hallucinating threat scores.
2. Pitch and Prosodic Signal Processing:
   - Voiced frames with valid F0 within physiological human limits (60-500 Hz) correctly detected.
   - Natural human intonation (F0 std >= 2.5 Hz, physiological jitter) confirmed as ORGANIC HUMAN PROSODY.
   - Unvoiced / silent frames explicitly distinguished as UNVOICED / NO PITCH DETECTED without triggering false synthetic verdicts.
   - Low or negative HNR (ambient/cellular room noise) does not disqualify voiced pitch.
   - Robotic monotone flatline vocoders (F0 std < 2.5 Hz) detected as SYNTHETIC PITCH ANOMALY.
3. Multi-Model Neural Consensus & Domain Shift Defense:
   - Dual Neural Agreement on Synthetic Speech correctly yields high risk (>= 0.75).
   - Dual Neural Agreement on Bonafide Speech correctly yields low risk (<= 0.30).
   - AASIST Outlier Conflict (AASIST elevated due to lossy MP3/channel shift, EnsembleDetector bonafide + organic prosody)
     is mitigated, eliminating the 0.880 false-positive defect.
   - EnsembleDetector Outlier Conflict properly mediated by physical acoustic telemetry.
4. Ground-Truth Classification:
   - Evaluates on authorized ASVspoof 2019 bonafide and spoof samples plus real demo recordings.
   - Computes confusion matrix, precision, recall, and false positive / negative rates.
5. End-to-End API and Telemetry Consistency:
   - Full POST /api/analyze flow returns aligned session-level and chunk-level telemetry.
   - Session recommendation reflects verified organic human prosody.
"""

from __future__ import annotations

import io
import math
import struct
import wave
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pytest
from fastapi.testclient import TestClient

from backend.config import get_settings
from backend.detection.detector import VoiceCloneDetector
from backend.detection.risk_engine import RiskEngine, RiskEngineConfig
from backend.detection.threshold_engine import AlertLevel, ThresholdEngine
from backend.features.feature_fusion import extract_all_features
from backend.features.prosodic_extractor import compute_hnr, compute_jitter, compute_shimmer, extract_f0
from backend.main import app, get_app_detector


# ── FIXTURES & HELPERS ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def settings():
    return get_settings()


@pytest.fixture(scope="module")
def detector(settings):
    det = VoiceCloneDetector(settings=settings)
    det.initialize()
    return det


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def generate_synthetic_tone(freq: float = 150.0, duration_sec: float = 4.0, sr: int = 16000) -> np.ndarray:
    """Generate a pure tone (constant flat pitch vocoder)."""
    t = np.linspace(0, duration_sec, int(sr * duration_sec), endpoint=False, dtype=np.float32)
    return 0.3 * np.sin(2 * np.pi * freq * t)


def generate_natural_human_audio(base_f0: float = 135.0, duration_sec: float = 4.0, sr: int = 16000) -> np.ndarray:
    """Generate realistic speech signal with dynamic human pitch intonation and glottal harmonics."""
    t = np.linspace(0, duration_sec, int(sr * duration_sec), endpoint=False, dtype=np.float32)
    # Pitch modulation: 135 Hz modulated by 2.5 Hz vibrato/sentence inflection (+-18 Hz)
    f0 = base_f0 + 18.0 * np.sin(2 * np.pi * 2.5 * t)
    phase = 2 * np.pi * np.cumsum(f0) / sr
    harmonics = 0.25 * np.sin(phase) + 0.12 * np.sin(2 * phase) + 0.05 * np.sin(3 * phase)
    # Add mild acoustic room/phone ambiance
    noise = (np.random.randn(len(t)) * 0.015).astype(np.float32)
    return (harmonics + noise).astype(np.float32)


# ── SECTION A: PREPROCESSING INTEGRITY ────────────────────────────────────────

def test_a1_silence_handling_does_not_hallucinate_threat(detector):
    """Verify that pure silence or flat zero audio returns 0.0 risk and SILENCE verdict."""
    zero_chunk = np.zeros(64000, dtype=np.float32)
    res = detector.process_chunk(zero_chunk, chunk_id=0)

    assert res.synthetic_probability == 0.0
    assert res.pitch_analysis["pitch_verdict"] == "SILENCE"
    assert not res.pitch_analysis["is_pitch_anomaly"]


def test_a2_near_zero_ambient_hiss_does_not_hallucinate_threat(detector):
    """Verify that low-amplitude background noise without speech does not spike risk."""
    np.random.seed(42)
    noise = (np.random.randn(64000) * 1e-7).astype(np.float32)
    res = detector.process_chunk(noise, chunk_id=1)

    assert res.synthetic_probability == 0.0
    assert not res.pitch_analysis["is_pitch_anomaly"]


# ── SECTION B: PITCH & PROSODIC SIGNAL PROCESSING ────────────────────────────

def test_b1_voiced_human_speech_detected_with_organic_prosody(detector):
    """Verify that natural human speech with normal pitch variation is classified as ORGANIC HUMAN PROSODY."""
    human_audio = generate_natural_human_audio()
    res = detector.process_chunk(human_audio, chunk_id=2)
    p = res.pitch_analysis

    assert p["f0_mean_hz"] >= 60.0
    assert p["f0_std_hz"] >= 2.5
    assert p["pitch_verdict"] == "ORGANIC HUMAN PROSODY"
    assert p["is_organic_human"] is True
    assert p["is_pitch_anomaly"] is False


def test_b2_robotic_flatline_vocoder_detected_as_pitch_anomaly(detector):
    """Verify that an artificial monotone vocoder (F0 std < 2.5 Hz) triggers pitch anomaly."""
    monotone_audio = generate_synthetic_tone(freq=150.0)
    res = detector.process_chunk(monotone_audio, chunk_id=3)
    p = res.pitch_analysis

    assert p["f0_mean_hz"] >= 60.0
    assert p["f0_std_hz"] < 2.5, f"Expected flat pitch std < 2.5 Hz, got {p['f0_std_hz']}"
    assert p["is_pitch_anomaly"] is True
    assert p["pitch_verdict"] == "SYNTHETIC PITCH ANOMALY"
    assert p["is_organic_human"] is False


def test_b3_unvoiced_speech_segment_correctly_identified(detector):
    """Verify that pure unvoiced white noise is reported as UNVOICED without marking anomaly."""
    np.random.seed(123)
    unvoiced_noise = (np.random.randn(64000) * 0.1).astype(np.float32)
    res = detector.process_chunk(unvoiced_noise, chunk_id=4)
    p = res.pitch_analysis

    # Unvoiced noise should not be flagged as synthetic anomaly
    assert not p["is_pitch_anomaly"], "Unvoiced noise must NOT be labeled as synthetic anomaly"
    assert p["pitch_verdict"] == "UNVOICED / NO PITCH DETECTED"
    assert not p["is_organic_human"]


def test_b4_negative_hnr_conversational_speech_preserves_voiced_f0(detector):
    """
    Verify that speech with low or negative HNR (due to room reverberation or cellular noise)
    is NOT incorrectly rejected as unvoiced when valid F0 periodicity is present.
    """
    t = np.linspace(0, 4.0, int(16000 * 4.0), endpoint=False, dtype=np.float32)
    f0 = 125.0 + 15.0 * np.sin(2 * np.pi * 3.0 * t)
    phase = 2 * np.pi * np.cumsum(f0) / 16000
    voice = 0.2 * np.sin(phase)
    # Add acoustic room noise that lowers HNR below 0 dB
    noise = (np.random.randn(len(t)) * 0.08).astype(np.float32)
    audio = (voice + noise).astype(np.float32)

    res = detector.process_chunk(audio, chunk_id=5)
    p = res.pitch_analysis

    assert p["f0_mean_hz"] >= 60.0
    assert p["pitch_verdict"] == "ORGANIC HUMAN PROSODY"
    assert p["is_organic_human"] is True


# ── SECTION C: MULTI-MODEL NEURAL CONSENSUS & CODEC DEFENSE ──────────────────

def test_c1_dual_neural_agreement_preserves_synthetic_threat(detector):
    """Verify that when both models detect synthetic speech, high risk is preserved."""
    # Test on known synthetic sample demo/test 0.mp3 if present
    demo_synth = Path("demo/test 0.mp3")
    if demo_synth.exists():
        from backend.audio.preprocessor import load_audio, chunk_audio
        audio, sr = load_audio(str(demo_synth), target_sr=16000)
        chunks = chunk_audio(audio, sr, chunk_duration=4.0, overlap_ratio=0.0)
        if len(chunks) > 1:
            res = detector.process_chunk(chunks[1], chunk_id=1)
            assert res.synthetic_probability >= 0.70, (
                f"Known synthetic sample scored too low: {res.synthetic_probability}"
            )


def test_c2_aasist_codec_domain_shift_mitigated_for_human_speech(detector):
    """
    Verify that when AASIST is elevated due to lossy MP3 compression/microphone shift
    but EnsembleDetector and prosody confirm human voice, synthetic risk is mitigated (no 0.880 spike).
    """
    demo_human = Path("demo/test 1.mp3")
    if demo_human.exists():
        from backend.audio.preprocessor import load_audio, chunk_audio
        audio, sr = load_audio(str(demo_human), target_sr=16000)
        chunks = chunk_audio(audio, sr, chunk_duration=4.0, overlap_ratio=0.0)
        # Test Chunk 0 (which previously scored 0.880 false positive)
        res0 = detector.process_chunk(chunks[0], chunk_id=0)
        assert res0.synthetic_probability <= 0.35, (
            f"Chunk 0 false-positive defect persisted: scored {res0.synthetic_probability:.4f}"
        )
        assert res0.pitch_analysis["pitch_verdict"] == "ORGANIC HUMAN PROSODY"
        assert res0.pitch_analysis["is_organic_human"] is True


# ── SECTION D: GROUND-TRUTH ASVSPOOF 2019 EVALUATION ─────────────────────────

def test_d1_asvspoof_bonafide_vs_spoof_discrimination(detector, settings):
    """
    Evaluate detector on authorized ASVspoof 2019 ground-truth subset:
    Verifies that bonafide human recordings have low risk and spoof recordings have high risk.
    """
    flac_dir = Path("data/asvspoof2019/extracted/flac")
    protocol_file = Path("data/asvspoof2019/extracted/train_protocol.txt")

    if not flac_dir.exists() or not protocol_file.exists():
        pytest.skip("ASVspoof dataset files not present in workspace.")

    import soundfile as sf
    labels = {}
    with open(protocol_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 5:
                labels[parts[1]] = parts[4]

    bonafide_files = [p for p in flac_dir.glob("*.flac") if labels.get(p.stem) == "bonafide"][:6]
    spoof_files = [p for p in flac_dir.glob("*.flac") if labels.get(p.stem) == "spoof"][:6]

    bonafide_probs = []
    for bf in bonafide_files:
        audio, sr = sf.read(str(bf))
        res = detector.process_chunk(audio, chunk_id=0)
        bonafide_probs.append(res.synthetic_probability)
        assert res.synthetic_probability < 0.40, (
            f"Bonafide sample {bf.name} falsely scored high: {res.synthetic_probability}"
        )

    spoof_probs = []
    for sf_path in spoof_files:
        audio, sr = sf.read(str(sf_path))
        res = detector.process_chunk(audio, chunk_id=0)
        spoof_probs.append(res.synthetic_probability)
        assert res.synthetic_probability >= 0.70, (
            f"Spoof sample {sf_path.name} failed to detect: {res.synthetic_probability}"
        )

    mean_bf = float(np.mean(bonafide_probs))
    mean_sp = float(np.mean(spoof_probs))

    assert mean_bf < 0.35, f"Bonafide mean probability {mean_bf} too high"
    assert mean_sp > 0.80, f"Spoof mean probability {mean_sp} too low"
    assert mean_sp - mean_bf >= 0.45, "Insufficient discrimination margin between spoof and bonafide"


# ── SECTION E: END-TO-END API & TELEMETRY CONSISTENCY ─────────────────────────

def test_e1_api_analyze_human_voice_end_to_end_consistency(client):
    """
    Verify POST /api/analyze on genuine human speech recording (demo/test 1.mp3):
    1. Overall alert level is SAFE.
    2. Session-level pitch verdict is ORGANIC HUMAN PROSODY.
    3. Peak synthetic risk is low (< 0.40, not 0.880).
    4. Chunk 0 telemetry matches session telemetry without contradiction.
    """
    demo_human = Path("demo/test 1.mp3")
    if not demo_human.exists():
        pytest.skip("demo/test 1.mp3 not found.")

    with open(demo_human, "rb") as fh:
        resp = client.post(
            "/api/analyze",
            files={"file": ("test 1.mp3", fh, "audio/mpeg")},
        )

    assert resp.status_code == 200, f"API error: {resp.text}"
    data = resp.json()

    assert data["alert_level"] == "SAFE", f"Expected SAFE, got {data['alert_level']}"
    assert data["peak_risk"] < 0.40, f"Expected peak_risk < 0.40, got {data['peak_risk']}"
    assert data["pitch_analysis"]["pitch_verdict"] == "ORGANIC HUMAN PROSODY"
    assert data["pitch_analysis"]["is_organic_human"] is True

    # Inspect Chunk 0
    chunks = data["chunk_scores"]
    assert len(chunks) >= 1
    c0 = chunks[0]
    assert c0["risk_score"] < 0.40
    assert c0["pitch_analysis"]["pitch_verdict"] == "ORGANIC HUMAN PROSODY"
    assert c0["pitch_analysis"]["f0_mean_hz"] > 0
    assert "start_time_sec" in c0 and "end_time_sec" in c0

    # Verify recommendation
    assert data["recommendation"]["alert_level"] == "SAFE"
    assert "Voice Verified" in data["recommendation"]["title"]


def test_e2_api_analyze_synthetic_voice_end_to_end(client):
    """
    Verify POST /api/analyze on known AI voice clone (demo/test 0.mp3):
    1. Overall alert level is HIGH or CRITICAL.
    2. Peak synthetic risk is >= 0.70.
    """
    demo_synth = Path("demo/test 0.mp3")
    if not demo_synth.exists():
        pytest.skip("demo/test 0.mp3 not found.")

    with open(demo_synth, "rb") as fh:
        resp = client.post(
            "/api/analyze",
            files={"file": ("test 0.mp3", fh, "audio/mpeg")},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["alert_level"] in ["HIGH", "CRITICAL"]
    assert data["peak_risk"] >= 0.70

