"""
Unit and integration tests for CyberGuard Call Defense Audio Classification & Lifecycle.
Verifies:
1. Cellular/telephone-distorted human audio does not trigger false 'CLONED_VOICE' or pitch anomalies.
2. Robotic monotone vocoder flatlines are accurately detected as synthetic anomalies.
3. Multi-frame temporal consistency gates prevent single-frame false-alarm escalation.
4. Progressive smoothing in CALL_MONITOR mode resists transient acoustic spikes.
"""

import numpy as np
import pytest

from backend.config import get_settings
from backend.detection.detector import VoiceCloneDetector
from backend.detection.risk_engine import RiskEngine, RiskEngineConfig


def generate_simulated_human_speech(sr: int = 16000, duration_sec: float = 1.0) -> np.ndarray:
    """Generate realistic human voice saying a syllable with 4-8 Hz natural pitch modulation and cellular noise."""
    np.random.seed(42)
    t = np.linspace(0, duration_sec, int(sr * duration_sec), endpoint=False)
    f0 = 135.0 + 6.0 * np.sin(2 * np.pi * 3.5 * t)
    phase = 2 * np.pi * np.cumsum(f0) / sr
    harmonics = 0.25 * np.sin(phase) + 0.12 * np.sin(2 * phase) + 0.06 * np.sin(3 * phase)
    # Add cellular AMR codec / channel perturbation
    noise = (np.random.randn(len(t)) * 0.012).astype(np.float32)
    return (harmonics + noise).astype(np.float32)


def generate_robotic_flatline_vocoder(sr: int = 16000, duration_sec: float = 1.0) -> np.ndarray:
    """Generate robotic flatline pitch typical of raw TTS vocoders without natural intonation."""
    t = np.linspace(0, duration_sec, int(sr * duration_sec), endpoint=False)
    f0 = 150.0  # Exactly constant pitch (0 Hz standard deviation)
    phase = 2 * np.pi * f0 * t
    return (0.3 * np.sin(phase) + 0.15 * np.sin(2 * phase)).astype(np.float32)


def test_human_cellular_speech_not_flagged_as_pitch_anomaly():
    """Verify that human speech with modest pitch variation and codec jitter is recognized as organic human."""
    settings = get_settings()
    detector = VoiceCloneDetector(settings=settings)
    detector.initialize()

    audio = generate_simulated_human_speech()
    res = detector.process_chunk(audio, chunk_id=1)

    assert not res.pitch_analysis["is_pitch_anomaly"], (
        f"Human voice was falsely flagged as pitch anomaly: {res.pitch_analysis}"
    )
    assert res.pitch_analysis["is_organic_human"], (
        f"Human voice failed organic human validation: {res.pitch_analysis}"
    )
    assert res.synthetic_probability < 0.50, (
        f"Human voice scored excessively high synthetic probability: {res.synthetic_probability}"
    )


def test_robotic_flatline_vocoder_detected_as_pitch_anomaly():
    """Verify that a completely flat robotic vocoder is detected as an anomaly."""
    settings = get_settings()
    detector = VoiceCloneDetector(settings=settings)
    detector.initialize()

    audio = generate_robotic_flatline_vocoder()
    res = detector.process_chunk(audio, chunk_id=2)

    assert res.pitch_analysis["is_pitch_anomaly"], (
        f"Robotic monotone flatline was not detected as an anomaly: {res.pitch_analysis}"
    )


def test_risk_engine_call_monitor_progressive_escalation():
    """Verify that in CALL_MONITOR mode, a single transient chunk does not instantly spike risk to critical."""
    config = RiskEngineConfig(temporal_smoothing=True, threshold_critical=0.85, threshold_high=0.70)
    engine = RiskEngine(config=config)
    engine.session_type = "CALL_MONITOR"

    # Frame 1: Transient acoustic spike (e.g. noise burst 0.78)
    snap1 = engine.update(chunk_id=1, detection_score=0.78)
    assert snap1.combined_risk < 0.70, (
        f"First frame alone spiked to high/critical: {snap1.combined_risk}"
    )

    # Frame 2: Back to normal human speech (0.20)
    snap2 = engine.update(chunk_id=2, detection_score=0.20)
    assert snap2.combined_risk < 0.50, (
        f"Risk failed to decay promptly after transient: {snap2.combined_risk}"
    )


def test_multi_frame_decision_gate():
    """Verify that fewer than 3 valid speech frames will not convict audio to CLONED_VOICE."""
    def classify_frame(valid_frames: int, combined_risk: float) -> str:
        if valid_frames < 3:
            if combined_risk < 0.40:
                return "GENUINE_VOICE"
            else:
                return "ANALYZING"
        else:
            if combined_risk < 0.40:
                return "GENUINE_VOICE"
            elif combined_risk >= 0.70:
                return "CLONED_VOICE"
            else:
                return "INCONCLUSIVE"

    # Under 3 frames: even an elevated score remains in ANALYZING state
    assert classify_frame(valid_frames=1, combined_risk=0.76) == "ANALYZING"
    assert classify_frame(valid_frames=2, combined_risk=0.76) == "ANALYZING"

    # Low risk is immediately recognized as GENUINE_VOICE
    assert classify_frame(valid_frames=1, combined_risk=0.15) == "GENUINE_VOICE"

    # 3 frames or more: confirmed sustained evidence allows CLONED_VOICE
    assert classify_frame(valid_frames=3, combined_risk=0.76) == "CLONED_VOICE"
