"""
prosodic_extractor.py — Prosodic feature extraction for CyberGuard.

Extracts speech characteristics that discriminate natural human speech
from neural TTS/voice cloning outputs:
  - Fundamental frequency (F0 / pitch)
  - Jitter (pitch perturbation ratio)
  - Shimmer (amplitude perturbation ratio)
  - Harmonic-to-Noise Ratio (HNR)
  - Speech rate proxy (zero-crossing rate)
  - RMS energy

These features capture prosodic patterns and micro-variations that
neural TTS systems often fail to replicate naturally.
"""

from __future__ import annotations

import logging
import numpy as np
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import librosa
    _LIBROSA_AVAILABLE = True
except ImportError:
    _LIBROSA_AVAILABLE = False
    logger.error("librosa required for prosodic extraction.")


def extract_f0(
    audio: np.ndarray,
    sr: int = 16000,
    fmin: float = 80.0,
    fmax: float = 400.0,
    hop_length: int = 160,
) -> np.ndarray:
    """
    Extract F0 (fundamental frequency) using librosa's yin.

    Changed from pyin → yin: yin is 5-10× faster on CPU while providing
    the same F0 contour used downstream for jitter/shimmer computation.
    pyin adds a probabilistic HMM refinement pass that is computationally
    expensive and not required for the heuristic scoring used here.

    Returns array of F0 values in Hz (0.0 where unvoiced, not NaN).
    """
    if not _LIBROSA_AVAILABLE:
        return np.array([0.0])

    try:
        # yin returns a float array with 0.0 where unvoiced (no NaN)
        f0 = librosa.yin(
            audio,
            fmin=fmin,
            fmax=fmax,
            sr=sr,
            hop_length=hop_length,
        )
        # Replace values at fmin boundary (unvoiced) with 0.0 to match
        # the downstream voiced-frame filter (f0 > 0 check)
        f0 = np.where(f0 <= fmin + 1.0, 0.0, f0)
        return f0.astype(np.float32)
    except Exception as exc:
        logger.warning(f"F0 extraction failed: {exc}")
        return np.array([0.0])


def compute_jitter(f0: np.ndarray) -> float:
    """
    Compute local jitter (relative) from F0 contour.
    Jitter = mean absolute period perturbation / mean period.
    Returns 0.0 if insufficient voiced frames.
    """
    # yin returns 0.0 for unvoiced (no NaN); pyin returned NaN.
    # Both cases: filter to voiced frames only.
    voiced = f0[(~np.isnan(f0)) & (f0 > 0)]
    if len(voiced) < 3:
        return 0.0

    periods = 1.0 / voiced  # convert Hz to period (seconds)
    diffs = np.abs(np.diff(periods))
    if np.mean(periods[:-1]) < 1e-10:
        return 0.0
    return float(np.mean(diffs) / np.mean(periods[:-1]))


def compute_shimmer(audio: np.ndarray, sr: int = 16000, hop_length: int = 160) -> float:
    """
    Compute local shimmer (relative) using RMS energy per frame.
    Shimmer = mean absolute amplitude perturbation / mean amplitude.
    Returns 0.0 if insufficient frames.
    """
    if not _LIBROSA_AVAILABLE:
        return 0.0

    rms = librosa.feature.rms(y=audio, hop_length=hop_length)[0]
    if len(rms) < 3:
        return 0.0
    diffs = np.abs(np.diff(rms))
    mean_rms = np.mean(rms[:-1])
    if mean_rms < 1e-10:
        return 0.0
    return float(np.mean(diffs) / mean_rms)


def compute_hnr(audio: np.ndarray, sr: int = 16000) -> float:
    """
    Estimate Harmonic-to-Noise Ratio (HNR) using FFT-based autocorrelation.
    Higher HNR = more periodic/tonal (typical of natural voiced speech).
    Returns float in dB.

    Changed from np.correlate(mode='full') → FFT-based autocorrelation:
    The original O(n²) full-mode correlation on a 32,000-sample chunk
    (2 s at 16 kHz) was a major bottleneck. FFT autocorrelation is O(n log n)
    and produces numerically equivalent results for this application.
    """
    n = len(audio)
    if n == 0:
        return 0.0

    # FFT-based autocorrelation — O(n log n) vs O(n²)
    # Pad to next power of 2 for efficient FFT
    nfft = 1 << (2 * n - 1).bit_length()
    f_audio = np.fft.rfft(audio, n=nfft)
    power = f_audio * np.conj(f_audio)
    correlation = np.fft.irfft(power)[:n].real

    # Find the first local maximum after zero (fundamental period)
    min_lag = max(1, int(sr / 400))  # max F0 = 400 Hz
    max_lag = int(sr / 60)           # min F0 = 60 Hz

    if max_lag >= len(correlation):
        return 0.0

    segment = correlation[min_lag: max_lag]
    if len(segment) == 0:
        return 0.0

    peak_idx = np.argmax(segment)
    r0 = correlation[0]
    r1 = segment[peak_idx]

    if r0 <= 0 or r1 <= 0:
        return 0.0

    # HNR = 10 * log10(r1 / (r0 - r1))
    denom = r0 - r1
    if denom <= 0:
        return 40.0  # cap at 40 dB

    return float(10.0 * np.log10(r1 / denom))


def compute_zcr(audio: np.ndarray, sr: int = 16000, hop_length: int = 160) -> float:
    """
    Compute mean Zero Crossing Rate — proxy for speech rate and breathiness.
    """
    if not _LIBROSA_AVAILABLE:
        return 0.0
    zcr = librosa.feature.zero_crossing_rate(audio, hop_length=hop_length)[0]
    return float(np.mean(zcr))


def compute_rms_energy(audio: np.ndarray, hop_length: int = 160) -> float:
    """Compute mean RMS energy."""
    if not _LIBROSA_AVAILABLE:
        return float(np.sqrt(np.mean(audio ** 2)))
    rms = librosa.feature.rms(y=audio, hop_length=hop_length)[0]
    return float(np.mean(rms))


def extract_prosodic_features(
    audio: np.ndarray,
    sr: int = 16000,
    hop_length: int = 160,
) -> np.ndarray:
    """
    Extract all prosodic features and return as a flat float32 vector.

    Feature vector (7 elements):
      [0] F0 mean (Hz, voiced frames only)
      [1] F0 std
      [2] Jitter (local relative)
      [3] Shimmer (local relative)
      [4] HNR (dB)
      [5] ZCR mean
      [6] RMS energy mean

    Returns:
        np.ndarray shape [7], dtype float32
    """
    features = np.zeros(7, dtype=np.float32)

    # F0 — yin returns 0.0 for unvoiced (no NaN)
    f0 = extract_f0(audio, sr=sr, hop_length=hop_length)
    voiced = f0[(~np.isnan(f0)) & (f0 > 0)]
    features[0] = float(np.mean(voiced)) if len(voiced) > 0 else 0.0
    features[1] = float(np.std(voiced)) if len(voiced) > 1 else 0.0

    # Jitter
    features[2] = compute_jitter(f0)

    # Shimmer
    features[3] = compute_shimmer(audio, sr=sr, hop_length=hop_length)

    # HNR
    features[4] = compute_hnr(audio, sr=sr)

    # ZCR
    features[5] = compute_zcr(audio, sr=sr, hop_length=hop_length)

    # RMS Energy
    features[6] = compute_rms_energy(audio, hop_length=hop_length)

    return features
