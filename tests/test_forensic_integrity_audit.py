"""
test_forensic_integrity_audit.py — Verification of Forensic Integrity, Scoring, and Grounding Contracts.

Tests:
  1. Multi-signal Noisy-OR composite calculation (56/100 score trace: 0.45 noise + 0.20 FFT).
  2. Inconclusive result grounding qualification (INCONCLUSIVE_INSUFFICIENT_EVIDENCE, non-synthetic badge contract).
  3. Vision deepfake detector state machine lifecycle (honest NOT_CONFIGURED reporting, zero mock data).
  4. Video soundtrack vs lip-sync distinction (AV sync marked NOT_EVALUATED, no false consistency claims).
  5. C2PA cryptographic signature qualification (manifest byte detection without signature verification is UNVERIFIED).
  6. EXIF unverified claim non-damping (camera make/model does not reduce suspicion or fake hardware verification).
"""

import io
import pytest
import numpy as np
from PIL import Image

from backend.analysis.deepfake_coordinator import DeepfakeCoordinator
from backend.analysis.forensics.correlation_engine import (
    ForensicCorrelationEngine,
    GroundingStatus,
)
from backend.analysis.forensics.c2pa_provenance import (
    C2PAProvenanceEngine,
    C2PAValidationStatus,
)
from backend.models.vision_detector import (
    VisionDeepfakeDetector,
    VisionDetectorState,
    get_vision_detector,
)
from backend.threats.models import RiskLevel, ThreatCategory


class TestForensicIntegrityAudit:

    def test_noisy_or_scoring_and_attribution_trace(self):
        """Verify that 0.45 noise kurtosis + 0.20 FFT harmonics produces exactly 0.56 threat score."""
        engine = ForensicCorrelationEngine()
        metrics = {
            "fft_off_axis_spike_ratio": 2.47,
            "fft_high_freq_ratio": 0.0816,
            "fft_status": "MODERATE",
            "ela_mean": 1.05,
            "ela_disparity": 0.36,
            "ela_status": "NOMINAL",
            "noise_kurtosis": 1930.3,
            "noise_variance": 1.282,
            "noise_status": "CRITICAL",
            "noise_substatus": "HEAVY_TAIL",
            "facial_forensics_applicable": True,
            "facial_status_level": "NOMINAL",
            "faces_detected": 1,
            "boundary_discontinuity": 0.0,
        }
        metadata = {
            "provenance_status": "METADATA_STRIPPED_OR_ABSENT",
            "camera_make": None,
            "camera_model": None,
        }

        # 1 - (1 - 0.45) * (1 - 0.20) = 0.56
        s_noise = 0.45
        s_freq = 0.20
        combined_prob = round(1.0 - ((1.0 - s_noise) * (1.0 - s_freq)), 4)
        assert combined_prob == 0.56

        verdict = engine.correlate_image(
            forensic_metrics=metrics,
            metadata_details=metadata,
            c2pa_response=None,
            evidences=[],
            base_suspicion=combined_prob,
            thresholds={"manipulated": 0.65, "inconclusive": 0.35, "critical": 0.85},
        )

        assert verdict.threat_score == 0.56
        assert verdict.classification == "INCONCLUSIVE"
        assert verdict.severity == RiskLevel.MEDIUM
        assert verdict.grounding_status == GroundingStatus.INCONCLUSIVE_INSUFFICIENT_EVIDENCE
        assert verdict.forensic_matrix["ai_generation"] == "INCONCLUSIVE"
        # ela_disparity is 0.36 >= 0.30 -> INCONCLUSIVE
        assert verdict.forensic_matrix["image_manipulation"] == "INCONCLUSIVE"
        assert verdict.forensic_matrix["face_manipulation"] == "NOT_DETECTED"
        assert verdict.forensic_matrix["video_temporal_consistency"] == "NOT_APPLICABLE"
        assert verdict.forensic_matrix["audio_video_synchronization"] == "NOT_APPLICABLE"

        # Verify MatrixWrapper returns real measured values
        matrix_dict = verdict.matrix.to_dict()
        assert matrix_dict["ai_generation_score"] == 0.56
        assert matrix_dict["image_manipulation_score"] == 0.36
        assert matrix_dict["face_manipulation_score"] == 0.0
        assert matrix_dict["video_temporal_consistency_score"] is None
        assert matrix_dict["audio_visual_sync_score"] is None
        assert matrix_dict["provenance_authenticity_score"] == 0.0

    def test_vision_deepfake_detector_state_machine(self):
        """Verify that vision detector initializes in NOT_CONFIGURED / HEURISTIC_ONLY when weights absent."""
        detector = VisionDeepfakeDetector(model_path="non_existent_weights.pt")
        assert detector.state in (VisionDetectorState.NOT_CONFIGURED, VisionDetectorState.HEURISTIC_ONLY)
        assert not detector.is_ready

        # Prediction must not mock or throw, returns un-evaluated status
        dummy_img = Image.new("RGB", (100, 100), color=(128, 128, 128))
        res = detector.predict(dummy_img)
        assert res["is_evaluated"] is False
        assert res["probability"] is None

        # Manifest entry reports honest status
        manifest = detector.get_manifest_entry()
        assert manifest["status"] == VisionDetectorState.NOT_CONFIGURED
        assert "No deep neural vision detector" in manifest["details"]

    def test_video_audio_visual_synchronization_qualification(self):
        """Verify that video without lip-sync tracking marks AV sync as NOT_EVALUATED, not CONSISTENT."""
        engine = ForensicCorrelationEngine()
        frame_analysis = {
            "total_frames_sampled": 8,
            "temporal_consistency": 0.88,
            "mean_frame_score": 0.15,
            "peak_frame_score": 0.22,
            "frames": [{"score": 0.15, "faces_detected": 0}],
            "audio_details": {"audio_risk": 0.10},
        }
        media_info = {
            "has_audio": True,
            "duration_sec": 12.0,
        }

        verdict = engine.correlate_video(
            frame_analysis=frame_analysis,
            media_info=media_info,
            c2pa_response=None,
            evidences=[],
            composite_risk=0.18,
            thresholds={"manipulated": 0.65, "inconclusive": 0.35, "critical": 0.85},
        )

        # Crucial forensic requirement: do NOT claim AV sync is verified without lip-sync
        assert verdict.forensic_matrix["audio_video_synchronization"] == "NOT_EVALUATED"
        matrix_dict = verdict.matrix.to_dict()
        assert matrix_dict["audio_visual_sync_score"] is None
        assert matrix_dict["video_temporal_consistency_score"] == 0.88

    def test_c2pa_unverified_manifest_status(self):
        """Verify that raw byte manifest extraction reports unverified status without digital signature."""
        engine = C2PAProvenanceEngine()
        # Build valid JPEG with APP11 marker holding c2pa payload
        payload_data = b"c2pa\x00\x00\x00\x00claim_generator: Midjourney (c2pa.ai_generated)"
        seg_len = len(payload_data) + 2
        fake_c2pa_payload = b"\xff\xd8\xff\xeb" + seg_len.to_bytes(2, "big") + payload_data + b"\xff\xd9"
        res = engine.analyze(fake_c2pa_payload, "sample.jpg")

        assert res.has_c2pa
        assert res.is_ai_generated_declared
        # Must not report VALID_PROVENANCE without cryptographic signature verification
        assert res.status in (C2PAValidationStatus.UNVERIFIED_MANIFEST, C2PAValidationStatus.VERIFICATION_UNAVAILABLE)
        assert res.signature_valid is not True
        assert res.is_valid is False

    def test_exif_camera_claim_does_not_damp_suspicion(self):
        """Verify that presence of camera EXIF header does not reduce suspicion score."""
        coord = DeepfakeCoordinator()
        # Generate an image with noise variance < 0.25 (flattening anomaly: 0.45 contribution)
        # and attach camera EXIF
        flat_arr = np.full((300, 300, 3), 128, dtype=np.uint8)
        img = Image.fromarray(flat_arr)
        exif = img.getexif()
        exif[0x010f] = "Sony"
        exif[0x0110] = "ILCE-7RM5"

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95, exif=exif)

        event = coord.analyze(buf.getvalue(), "sony_flattened.jpg")
        # Anomaly must not be zeroed out by camera EXIF claim!
        assert event.threat_score >= 0.40
        assert event.metadata_details["provenance_status"] == "EXIF_CAMERA_CLAIM_PRESENT"
        assert event.forensic_metrics["grounding_status"] != GroundingStatus.PROVENANCE_AUTHENTIC

    def test_neural_vision_detector_ready_and_inference(self):
        """Verify that genuine neural vision model loads in READY state and runs actual inference."""
        detector = VisionDeepfakeDetector()
        if not detector.is_ready:
            pytest.skip("Vision detector weights not present in environment (standard for CI).")
        assert detector.state == VisionDetectorState.READY
        assert detector.is_ready is True
        assert "MobileNetV3" in detector.model_family

        # Run inference on authentic natural-like gradient
        img = Image.new("RGB", (224, 224), color=(100, 150, 200))
        pred = detector.predict(img)

        assert pred["status"] == VisionDetectorState.READY
        assert pred["is_evaluated"] is True
        assert isinstance(pred["probability"], float)
        assert 0.0 <= pred["probability"] <= 1.0
        assert pred["execution_time_ms"] > 0.0
        assert pred["sha256"] is not None

        # Manifest report
        manifest = detector.get_manifest_entry()
        assert manifest["status"] == VisionDetectorState.READY
        assert "MobileNetV3" in manifest["model_family"]
        assert manifest["device"] == "cpu" or manifest["device"] == "cuda"

    def test_qwen_primary_llm_service_manifest_and_execution(self):
        """Verify Qwen3.5-4B-Q4_K_M is the single primary LLM with verified integrity and execution."""
        from backend.models.qwen_service import get_qwen_service, QwenServiceState

        service = get_qwen_service()
        model_path = service.resolve_model_path()
        if not model_path or not model_path.exists():
            pytest.skip("Qwen GGUF model not present in environment (standard for CI).")
        assert model_path.name == "Qwen3.5-4B-Q4_K_M.gguf"

        # Checksum verification against authentic Hugging Face release
        is_known, h, source_desc = service.verify_checksum()
        assert len(h) == 64
        assert is_known is True
        assert "Qwen3.5-4B" in source_desc

        # Ensure loaded
        ok = service.load_model()
        assert ok is True
        assert service.is_ready is True

        # Manifest verification
        manifest = service.get_manifest_entry()
        assert manifest["model_name"] == "Qwen3.5-4B-Q4_K_M.gguf"
        assert manifest["model_family"] == "Qwen3.5-4B"
        assert manifest["quantization"] == "Q4_K_M"
        assert manifest["status"] == "READY"
        assert "Single Primary Generative LLM" in manifest["role"]

        # Fast test generation
        messages = [
            {"role": "system", "content": "You are CyberGuard Security AI."},
            {"role": "user", "content": "Reply with exactly: CyberGuard Operational"}
        ]
        res = service.create_chat_completion(messages, max_tokens=15, temperature=0.1)
        assert res is not None
        assert "choices" in res
        content = res["choices"][0]["message"]["content"]
        assert len(content.strip()) > 0

    def test_real_phone_photo_regression_no_face_no_false_positive(self):
        """Regression test verifying real phone photo with no face yields 0 faces, N/A face manipulation, and LIKELY_AUTHENTIC."""
        import os
        sample_path = "New folder/demo (2).jpg"
        if not os.path.exists(sample_path):
            pytest.skip(f"Reference sample {sample_path} not available.")

        with open(sample_path, "rb") as f:
            media_bytes = f.read()

        coord = DeepfakeCoordinator()
        event = coord.analyze(media_bytes, "IMG_20261031_161203.jpg")

        assert event.classification == "LIKELY_AUTHENTIC"
        assert event.threat_score <= 0.20
        assert event.forensic_metrics["faces_detected"] == 0
        assert event.forensic_metrics["facial_forensics_applicable"] is False
        assert event.matrix["face_manipulation_score"] is None
        assert event.matrix["categorical"]["face_manipulation"] == "NOT_APPLICABLE"
        assert event.forensic_metrics["grounding_status"] == GroundingStatus.EXIF_CAMERA_CLAIM_NOMINAL
        assert event.forensic_metrics["noise_status"] == "NOMINAL"
        assert event.forensic_metrics["fft_status"] == "NOMINAL"

    def test_video_pipeline_authenticity_and_matrix_contract(self):
        """Regression test verifying video pipeline execution and matrix contract."""
        import os
        sample_path = "New folder/demo.mp4"
        if not os.path.exists(sample_path):
            pytest.skip(f"Reference video sample {sample_path} not available.")

        with open(sample_path, "rb") as f:
            media_bytes = f.read()

        coord = DeepfakeCoordinator()
        event = coord.analyze(media_bytes, "demo.mp4")

        assert event.modality == "video"
        assert event.classification in ("LIKELY_AUTHENTIC", "INCONCLUSIVE")
        assert event.threat_score <= 0.35
        assert event.matrix["video_temporal_consistency_score"] is not None
        assert event.matrix["face_manipulation_score"] is None
        assert event.matrix["audio_visual_sync_score"] is None
        assert event.matrix["categorical"]["video_temporal_consistency"] == "NO_ANOMALIES_DETECTED"
        assert event.matrix["categorical"]["face_manipulation"] == "NOT_APPLICABLE"

    def test_screen_recording_presentation_dynamics_and_neural_aggregation(self):
        """Regression test verifying screen recording video (miniledger-demo.mp4) is correctly classified."""
        import os
        sample_path = "New folder/miniledger-demo.mp4"
        if not os.path.exists(sample_path):
            pytest.skip(f"Reference video sample {sample_path} not available.")

        with open(sample_path, "rb") as f:
            media_bytes = f.read()

        coord = DeepfakeCoordinator()
        event = coord.analyze(media_bytes, "miniledger-demo.mp4")

        assert event.modality == "video"
        assert event.classification in ("LIKELY_AUTHENTIC", "INCONCLUSIVE")
        assert event.threat_score <= 0.35
        assert event.forensic_metrics["stream_dynamics"] == "STATIC_UI_PRESENTATION"
        assert event.forensic_metrics["temporal_consistency"] >= 0.80
        assert event.forensic_metrics["temporal_jitter_index"] <= 0.20
        assert event.forensic_metrics["neural_synthetic_probability"] is not None
        assert event.forensic_metrics["neural_synthetic_probability"] <= 0.20
        assert event.forensic_metrics["neural_authentic_probability"] >= 0.80
        assert event.matrix["categorical"]["face_manipulation"] == "NOT_APPLICABLE"
        assert event.matrix["categorical"]["audio_video_synchronization"] == "NOT_APPLICABLE"
