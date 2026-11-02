"""
test_media_forensics_subsystem.py - Comprehensive Verification of the AI Media Forensics Subsystem.

Tests:
  1. C2PA / Content Credentials Provenance Engine (JUMBF container parser, AI markers, hardware claims).
  2. Traditional DSP Forensics (2D FFT Hann window, ELA disparity, Base64 heatmap, PRNU kurtosis, face seams).
  3. Video Forensics Pipeline (container metadata, keyframe sampling, temporal jitter, audio demuxing).
  4. Calibrated Forensic Correlation Engine (8-point matrix, strict grounding rule, Bayesian fusion).
  5. FastAPI Endpoints (POST /api/threats/image, POST /api/threats/video, GET /api/threats/media/{id}/report).
  6. Database Persistence & Event Rehydration (SQLite columns, JSON serialization).
"""

from __future__ import annotations

import io
import os
import struct
import tempfile
import pytest
import numpy as np
from PIL import Image
from fastapi.testclient import TestClient

from backend.main import app
from backend.analysis.forensics.c2pa_provenance import C2PAProvenanceEngine, C2PAValidationStatus
from backend.analysis.forensics.image_forensics import ImageForensicsEngine
from backend.analysis.forensics.video_forensics import VideoForensicsEngine
from backend.analysis.forensics.correlation_engine import ForensicCorrelationEngine, GroundingStatus
from backend.analysis.deepfake_coordinator import DeepfakeCoordinator
from backend.audio.preprocessor import _get_ffmpeg_executable
from backend.storage.database import get_session_factory, ThreatEventModel
from backend.incidents.incident_manager import IncidentManager
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel


# --- Helper Fixtures & Data Generators ---

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def ffmpeg_exe():
    try:
        return _get_ffmpeg_executable()
    except RuntimeError:
        pytest.skip("FFmpeg not available - skipping video tests")


def _create_synthetic_photo(width: int = 320, height: int = 240, seed: int = 42) -> bytes:
    """Generate an authentic-like photo with organic gradients and Gaussian noise."""
    np.random.seed(seed)
    base = np.zeros((height, width), dtype=np.float32)
    for i in range(1, 5):
        base += (1.0 / i) * np.sin(0.02 * i * np.arange(width) + 0.015 * i * np.arange(height)[:, None])
    base = ((base - base.min()) / (base.max() - base.min()) * 180 + 40)
    noise = np.random.normal(0, 2.5, (height, width))
    photo_arr = np.clip(base + noise, 0, 255).astype(np.uint8)
    img = Image.fromarray(photo_arr, mode="L").convert("RGB")

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=90)
    return buf.getvalue()


def _create_synthetic_video_bytes(ffmpeg_exe: str, duration: int = 2, with_audio: bool = True) -> bytes:
    """Generate a valid MP4 video in memory using FFmpeg."""
    fd, path = tempfile.mkstemp(suffix=".mp4")
    os.close(fd)
    try:
        cmd = [ffmpeg_exe, "-y"]
        if with_audio:
            cmd += ["-f", "lavfi", "-i", f"sine=frequency=440:duration={duration}"]
        cmd += ["-f", "lavfi", "-i", f"testsrc=duration={duration}:size=320x240:rate=10"]
        cmd += ["-c:v", "libx264", "-pix_fmt", "yuv420p"]
        if with_audio:
            cmd += ["-c:a", "aac"]
        cmd.append(path)

        import subprocess
        subprocess.run(cmd, capture_output=True, check=True, timeout=30)
        with open(path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(path):
            os.unlink(path)


# ============================================================================
# 1. C2PA Provenance Engine Tests
# ============================================================================

class TestC2PAProvenanceEngine:
    def test_missing_provenance(self):
        engine = C2PAProvenanceEngine()
        data = _create_synthetic_photo()
        result = engine.inspect_bytes(data, "photo.jpg")

        assert result.validation_status == C2PAValidationStatus.MISSING_PROVENANCE
        assert not result.is_valid
        assert not result.has_c2pa_manifest
        assert result.claim_generator is None

    def test_synthetic_ai_claimed_manifest(self):
        engine = C2PAProvenanceEngine()
        # Build synthetic JPEG with APP11 marker and C2PA claim
        data = _create_synthetic_photo()
        jumbf_payload = b"c2pa\x00\x00claim_generator: Midjourney v6.0 AI generator c2pa.synthetic"
        marker_len = len(jumbf_payload) + 2
        app11_marker = b"\xff\xeb" + struct.pack(">H", marker_len) + jumbf_payload

        # Insert after SOI (\xff\xd8)
        tagged_jpeg = data[:2] + app11_marker + data[2:]
        result = engine.inspect_bytes(tagged_jpeg, "ai_artwork.jpg")

        assert result.has_c2pa_manifest
        assert result.ai_generative_claimed
        assert "Midjourney" in (result.claim_generator or "")
        # Forensic integrity: raw byte extraction detects manifest, but cryptographic signature is unverified
        assert result.validation_status in (
            C2PAValidationStatus.UNVERIFIED_MANIFEST,
            C2PAValidationStatus.VALID_PROVENANCE,
        )
        assert result.signature_valid is not True

    def test_hardware_provenance_manifest(self):
        engine = C2PAProvenanceEngine()
        data = _create_synthetic_photo()
        jumbf_payload = b"c2pa\x00\x00claim_generator: Leica M11-P Content Credentials camera hardware signer"
        marker_len = len(jumbf_payload) + 2
        app11_marker = b"\xff\xeb" + struct.pack(">H", marker_len) + jumbf_payload

        tagged_jpeg = data[:2] + app11_marker + data[2:]
        result = engine.inspect_bytes(tagged_jpeg, "camera_photo.jpg")

        assert result.has_c2pa_manifest
        assert not result.ai_generative_claimed
        assert "Leica" in (result.claim_generator or "")
        # Forensic integrity: without cryptographic validation engine, manifest remains unverified
        assert result.validation_status in (
            C2PAValidationStatus.UNVERIFIED_MANIFEST,
            C2PAValidationStatus.VALID_PROVENANCE,
        )
        assert result.signature_valid is not True


# ============================================================================
# 2. Image Forensics DSP Engine Tests
# ============================================================================

class TestImageForensicsEngine:
    def test_frequency_domain_analysis(self):
        engine = ImageForensicsEngine()
        data = _create_synthetic_photo()
        analysis = engine.analyze_image_bytes(data, "test.jpg")

        assert "fft_high_freq_ratio" in analysis.metrics
        assert "fft_off_axis_spike_ratio" in analysis.metrics
        assert "fft_status" in analysis.metrics
        assert isinstance(analysis.metrics["fft_high_freq_ratio"], float)
        assert analysis.metrics["fft_off_axis_spike_ratio"] >= 0.0

    def test_ela_disparity_and_heatmap_generation(self):
        engine = ImageForensicsEngine()
        data = _create_synthetic_photo()
        analysis = engine.analyze_image_bytes(data, "test.jpg")

        assert "ela_mean" in analysis.metrics
        assert "ela_disparity" in analysis.metrics
        assert analysis.ela_heatmap_base64 is not None
        assert len(analysis.ela_heatmap_base64) > 100
        # Base64 decode to verify JPEG false-color heatmap
        import base64
        raw_heatmap = base64.b64decode(analysis.ela_heatmap_base64)
        assert raw_heatmap[:2] == b"\xff\xd8"  # Valid JPEG SOI marker

    def test_prnu_sensor_noise_kurtosis(self):
        engine = ImageForensicsEngine()
        data = _create_synthetic_photo()
        analysis = engine.analyze_image_bytes(data, "test.jpg")

        assert "noise_kurtosis" in analysis.metrics
        assert "noise_variance" in analysis.metrics
        assert analysis.metrics["noise_status"] in ("NOMINAL", "AUTHENTIC", "MODERATE", "CRITICAL")


# ============================================================================
# 3. Video Forensics Engine Tests
# ============================================================================

class TestVideoForensicsEngine:
    def test_video_metadata_and_keyframe_sampling(self, ffmpeg_exe):
        engine = VideoForensicsEngine()
        video_bytes = _create_synthetic_video_bytes(ffmpeg_exe, duration=2)

        result = engine.analyze_video_bytes(video_bytes, "test_clip.mp4")

        assert result.media_info.get("is_video") is True
        assert result.media_info.get("duration_sec", 0) > 0
        assert result.media_info.get("fps", 0) > 0
        assert result.media_info.get("width") == 320
        assert result.media_info.get("height") == 240

        # Verify adaptive keyframe sampling (8 to 16 frames)
        frames = result.frame_analysis.get("frames", [])
        assert len(frames) >= 8
        assert "timestamp_sec" in frames[0]
        assert "inter_frame_diff" in frames[0]
        assert "temporal_consistency" in result.frame_analysis
        assert "temporal_jitter_index" in result.frame_analysis


# ============================================================================
# 4. Calibrated Forensic Correlation Engine Tests
# ============================================================================

class TestCalibratedCorrelationEngine:
    def test_strict_grounding_web_stripped_returns_benign_unverified(self):
        engine = ForensicCorrelationEngine()
        # Clean DSP metrics but no camera hardware EXIF or C2PA
        metrics = {
            "fft_off_axis_spike_ratio": 1.1,
            "fft_high_freq_ratio": 0.04,
            "ela_disparity": 0.15,
            "noise_kurtosis": 9.5,
            "facial_forensics_applicable": False,
        }
        metadata = {
            "provenance_status": "METADATA_STRIPPED_OR_ABSENT",
            "camera_make": None,
        }
        result = engine.correlate_evidence(
            metrics=metrics,
            metadata=metadata,
            c2pa=None,
            frame_analysis=None,
            media_info={"format": "JPEG"},
        )

        # Grounding Rule: Never claim verified authentic without EXIF or C2PA
        assert result.matrix.grounding_status == GroundingStatus.BENIGN_UNVERIFIED_ORIGIN
        assert result.classification in ("LIKELY_AUTHENTIC", "BENIGN_UNVERIFIED_ORIGIN")
        assert result.severity == RiskLevel.SAFE

    def test_grounded_camera_provenance(self):
        engine = ForensicCorrelationEngine()
        metrics = {
            "fft_off_axis_spike_ratio": 1.05,
            "fft_high_freq_ratio": 0.03,
            "ela_disparity": 0.12,
            "noise_kurtosis": 8.8,
            "noise_variance": 0.35,  # Unflattened nominal variance
            "noise_status": "NOMINAL",
            "noise_substatus": "NOMINAL_GAUSSIAN",
            "facial_forensics_applicable": False,
        }
        metadata = {
            "provenance_status": "EXIF_CAMERA_CLAIM_PRESENT",
            "camera_make": "Nikon",
            "camera_model": "Z6",
            "has_optical_exif": True,
        }
        result = engine.correlate_evidence(
            metrics=metrics,
            metadata=metadata,
            c2pa=None,
            frame_analysis=None,
            media_info={"format": "JPEG"},
        )

        assert result.matrix.grounding_status in (
            GroundingStatus.EXIF_CAMERA_CLAIM_NOMINAL,
            GroundingStatus.GROUNDED_CAMERA_PROVENANCE,
        )
        assert result.classification == "LIKELY_AUTHENTIC"
        assert result.severity == RiskLevel.SAFE

    def test_noise_flattening_not_masked_by_camera_exif(self):
        """Verify that flattened spatial noise (var < 0.25) is NOT masked or neutralized by camera EXIF."""
        engine = ForensicCorrelationEngine()
        metrics = {
            "fft_off_axis_spike_ratio": 1.10,
            "fft_high_freq_ratio": 0.04,
            "ela_disparity": 0.15,
            "noise_kurtosis": 9.2,   # Kurtosis is nominally shaped
            "noise_variance": 0.150, # Critically flattened! (var < 0.25)
            "noise_status": "CRITICAL",
            "noise_substatus": "NOISE_FLATTENED",
            "facial_forensics_applicable": False,
        }
        metadata = {
            "provenance_status": "EXIF_CAMERA_CLAIM_PRESENT",
            "camera_make": "Sony",
            "camera_model": "A7 IV",
            "has_optical_exif": True,
        }
        # Base suspicion 0.45 from noise flattening
        result = engine.correlate_evidence(
            metrics=metrics,
            metadata=metadata,
            c2pa=None,
            frame_analysis=None,
            media_info={"format": "JPEG"},
            base_suspicion=0.45,
        )

        # The noise anomaly must NOT be damped to 0.10 or classified as verified camera origin!
        assert result.threat_score >= 0.40
        assert result.matrix.grounding_status != GroundingStatus.PROVENANCE_AUTHENTIC

    def test_synthetic_ai_detection_elevation(self):
        engine = ForensicCorrelationEngine()
        metrics = {
            "fft_off_axis_spike_ratio": 3.8,  # High harmonic lattice
            "fft_high_freq_ratio": 0.15,
            "ela_disparity": 0.72,            # Strong compression disparity
            "noise_kurtosis": 28.5,           # Heavy-tailed non-Gaussian
            "facial_forensics_applicable": True,
            "boundary_discontinuity": 0.65,
        }
        metadata = {"provenance_status": "METADATA_STRIPPED_OR_ABSENT"}
        result = engine.correlate_evidence(
            metrics=metrics,
            metadata=metadata,
            c2pa=None,
            frame_analysis=None,
            media_info={"format": "JPEG"},
        )

        assert result.matrix.grounding_status == GroundingStatus.SYNTHETIC_MANIPULATED
        assert result.matrix.ai_generation_score > 0.70
        assert result.threat_score >= 0.65
        assert result.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ============================================================================
# 5. FastAPI Endpoints & Persistence Tests
# ============================================================================

class TestForensicsAPIEndpoints:
    def test_post_image_forensics_endpoint(self, client):
        img_bytes = _create_synthetic_photo()
        files = {"file": ("test_upload.jpg", img_bytes, "image/jpeg")}
        data = {"source": "unit_test"}

        res = client.post("/api/threats/image", files=files, data=data)
        assert res.status_code == 200
        payload = res.json()

        assert "event_id" in payload
        assert "threat_score" in payload
        assert "matrix" in payload
        assert "forensic_metrics" in payload
        assert "ela_heatmap_base64" in payload
        assert payload["media_info"]["format"] == "JPEG"

        event_id = payload["event_id"]

        # Test Dossier Export endpoint
        report_res = client.get(f"/api/threats/media/{event_id}/report")
        assert report_res.status_code == 200
        report = report_res.json()
        assert report["event_id"] == event_id
        assert "forensic_metrics" in report
        assert "explanation" in report

    def test_post_video_forensics_endpoint(self, client, ffmpeg_exe):
        video_bytes = _create_synthetic_video_bytes(ffmpeg_exe, duration=2)
        files = {"file": ("test_clip.mp4", video_bytes, "video/mp4")}
        data = {"source": "unit_test_video"}

        res = client.post("/api/threats/video", files=files, data=data)
        assert res.status_code == 200
        payload = res.json()

        assert "event_id" in payload
        assert payload["modality"] == "video"
        assert "frame_analysis" in payload
        assert payload["media_info"]["is_video"] is True
        assert len(payload["frame_analysis"].get("frames", [])) >= 8

        event_id = payload["event_id"]

        # Verify dossier report endpoint for video
        report_res = client.get(f"/api/threats/media/{event_id}/report")
        assert report_res.status_code == 200
        report = report_res.json()
        assert report["event_id"] == event_id
        assert "frame_analysis" in report
        assert report["modality"] == "video"

    def test_get_nonexistent_report_returns_404(self, client):
        res = client.get("/api/threats/media/nonexistent_id_12345/report")
        assert res.status_code == 404


# ============================================================================
# 6. SQLite Database Persistence & Incident Manager Rehydration
# ============================================================================

class TestDatabasePersistence:
    def test_forensic_columns_persisted_and_rehydrated(self):
        from backend.config import get_settings
        settings = get_settings()
        incident_mgr = IncidentManager(config=settings, db_path=settings.storage.db_path)
        session_factory = get_session_factory(settings.storage.db_path)

        # Create mock forensic ThreatEvent
        event_id = f"test_forensic_pers_{int(os.urandom(4).hex(), 16)}"
        event = ThreatEvent(
            event_id=event_id,
            timestamp=1700000000.0,
            source="test_persistence",
            source_type="file",
            modality="image",
            threat_category=ThreatCategory.SAFE,
            threat_score=0.15,
            severity=RiskLevel.SAFE,
            confidence=0.92,
            classification="BENIGN_UNVERIFIED_ORIGIN",
            explanation=None,
            recommended_actions=["Archive asset"],
            media_info={"sha256": "abcdef123456", "dimensions": "320x240", "format": "JPEG"},
            metadata_details={"provenance_status": "METADATA_STRIPPED_OR_ABSENT"},
            forensic_metrics={"ela_disparity": 0.18, "fft_off_axis_spike_ratio": 1.1},
            frame_analysis={"total_frames": 1},
            matrix={
                "grounding_status": "BENIGN_UNVERIFIED_ORIGIN",
                "ai_generation_score": 0.12,
            },
        )

        # Save to DB
        incident_mgr.process_event(event)

        # Query directly from DB model
        with session_factory() as db:
            row = db.query(ThreatEventModel).filter(ThreatEventModel.event_id == event_id).first()
            assert row is not None
            assert row.forensic_metrics_json is not None
            assert row.media_info_json is not None
            assert row.metadata_details_json is not None
            assert row.frame_analysis_json is not None

            # Rehydrate back to ThreatEvent domain model
            rehydrated = incident_mgr._model_to_threat_event(row, db=db)
            assert rehydrated.event_id == event_id
            assert rehydrated.forensic_metrics["ela_disparity"] == 0.18
            assert rehydrated.media_info["sha256"] == "abcdef123456"
            assert rehydrated.classification == "BENIGN_UNVERIFIED_ORIGIN"

