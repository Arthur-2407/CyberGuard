"""
test_image_forensics_pipeline.py — Comprehensive tests for the calibrated Image & Deepfake Forensics pipeline.

Verifies:
  1. Authentic camera images produce LIKELY_AUTHENTIC / SAFE without false-positive deepfake flags.
  2. Images without faces explicitly report facial forensics as not applicable without penalization.
  3. Generative AI metadata signatures (Stable Diffusion, Midjourney) elevate suspicion score.
  4. Animated media (GIF) extracts multi-frame sequence and populates frame_analysis.
  5. LLM Security Analyst generates evidence-grounded narratives and modality-aware playbooks
     (no host quarantine or hallucinated wire-transfer stories for media uploads).
"""

from __future__ import annotations

import io
import pytest
import numpy as np
from PIL import Image, PngImagePlugin

from backend.analysis.deepfake_coordinator import DeepfakeCoordinator
from backend.analysis.llm_analyst import get_llm_analyst
from backend.threats.models import RiskLevel, ThreatCategory


@pytest.fixture
def coordinator():
    return DeepfakeCoordinator()


@pytest.fixture
def analyst():
    return get_llm_analyst()


def _generate_synthetic_photo(width: int = 400, height: int = 300, seed: int = 42) -> bytes:
    """Generate a natural-like photo with smooth spatial gradients and camera shot noise."""
    np.random.seed(seed)
    base = np.zeros((height, width), dtype=np.float32)
    for i in range(1, 6):
        base += (1.0 / i) * np.sin(0.02 * i * np.arange(width) + 0.015 * i * np.arange(height)[:, None])
    base = ((base - base.min()) / (base.max() - base.min()) * 180 + 40)
    noise = np.random.normal(0, 3.0, (height, width))
    photo_arr = np.clip(base + noise, 0, 255).astype(np.uint8)
    img = Image.fromarray(photo_arr, mode="L").convert("RGB")

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


class TestImageForensicsPipeline:
    def test_authentic_photo_classified_likely_authentic(self, coordinator):
        media_bytes = _generate_synthetic_photo(400, 300)
        event = coordinator.analyze(media_bytes, "landscape_capture.jpg")

        assert event.classification == "LIKELY_AUTHENTIC"
        assert event.severity == RiskLevel.SAFE
        assert event.threat_category == ThreatCategory.SAFE
        assert event.threat_score < 0.35
        assert event.media_info is not None
        assert "sha256" in event.media_info
        assert event.metadata_details is not None

        # Forensic metrics verification
        metrics = event.forensic_metrics
        assert "ela_mean" in metrics
        assert "fft_off_axis_spike_ratio" in metrics
        assert metrics["fft_off_axis_spike_ratio"] < 7.0
        assert "No face detected" in metrics["facial_status"]

    def test_generative_ai_metadata_detection(self, coordinator):
        raw_bytes = _generate_synthetic_photo(300, 300)
        img = Image.open(io.BytesIO(raw_bytes))

        # Add Stable Diffusion prompt in PNG text chunks
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text("parameters", "masterpiece, 8k portrait, model: Stable Diffusion XL, steps: 25")
        buf = io.BytesIO()
        img.save(buf, format="PNG", pnginfo=png_info)
        ai_media_bytes = buf.getvalue()

        event = coordinator.analyze(ai_media_bytes, "ai_artwork.png")

        assert event.classification == "LIKELY_MANIPULATED"
        assert event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert event.threat_score >= 0.65
        assert event.metadata_details["provenance_status"] == "AI_GENERATOR_METADATA_CONFIRMED"
        assert "stable diffusion" in event.metadata_details["ai_generator_tags"]

    def test_content_based_synthetic_image_detection(self, coordinator):
        # Generate an AI-style smooth image with no camera noise or EXIF metadata
        np.random.seed(42)
        base = np.zeros((300, 400), dtype=np.float32)
        for i in range(1, 6):
            base += (1.0 / i) * np.sin(0.02 * i * np.arange(400) + 0.015 * i * np.arange(300)[:, None])
        base = ((base - base.min()) / (base.max() - base.min()) * 180 + 40)
        ai_arr = np.clip(base, 0, 255).astype(np.uint8)
        img = Image.fromarray(ai_arr, mode="L").convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=92)

        event = coordinator.analyze(buf.getvalue(), "ai_no_metadata.jpg")
        assert event.classification == "LIKELY_MANIPULATED"
        assert event.threat_score >= 0.65
        assert event.forensic_metrics["manipulation_probability"] >= 0.65
        assert any(e.evidence_type in ("synthetic_noise_flattening", "spectral_high_freq_attenuation") for e in event.evidence)

    def test_animated_gif_multi_frame_extraction(self, coordinator):
        frames = [Image.fromarray(np.random.randint(60, 190, (80, 100, 3), dtype=np.uint8)) for _ in range(5)]
        buf = io.BytesIO()
        frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:], duration=100, loop=0)
        gif_bytes = buf.getvalue()

        event = coordinator.analyze(gif_bytes, "test_animation.gif")

        assert event.frame_analysis is not None
        assert event.frame_analysis["total_frames_sampled"] == 5
        assert "temporal_consistency" in event.frame_analysis
        assert len(event.frame_analysis["frames"]) == 5

    def test_llm_analyst_authentic_media_grounding(self, coordinator, analyst):
        media_bytes = _generate_synthetic_photo(400, 300)
        event = coordinator.analyze(media_bytes, "authentic_camera_shot.jpg")

        llm_report = analyst.analyze(event.model_dump())

        # Grounded summary & deep dive
        assert "authentic_camera_shot.jpg" in llm_report["executive_summary"]
        assert "wire transfer" not in llm_report["executive_summary"].lower()
        assert "surveillance intercepted" not in llm_report["executive_summary"].lower()

        # Playbook must not quarantine host or revoke user sessions
        playbook_text = str(llm_report["incident_response_playbook"])
        assert "host quarantine" not in playbook_text.lower()
        assert "revoke active session" not in playbook_text.lower()

    def test_llm_analyst_suspicious_media_playbook(self, coordinator, analyst):
        raw_bytes = _generate_synthetic_photo(300, 300)
        img = Image.open(io.BytesIO(raw_bytes))
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text("parameters", "Cyberpunk character, software: Midjourney v6")
        buf = io.BytesIO()
        img.save(buf, format="PNG", pnginfo=png_info)

        event = coordinator.analyze(buf.getvalue(), "synthetic_sample.png")
        llm_report = analyst.analyze(event.model_dump())

        playbook = llm_report["incident_response_playbook"]
        step_names = [p.get("step", "") for p in playbook]
        assert any("Media Quarantine" in s for s in step_names)
        assert any("Provenance" in s for s in step_names)
        assert "host quarantine" not in str(playbook).lower()

    def test_ai_generated_image_with_diffusion_noise_kurtosis(self, coordinator):
        """Verify that AI-generated images with high noise kurtosis and low HF energy are detected (user scenario)."""
        np.random.seed(1234)
        base = np.zeros((200, 200, 3), dtype=np.float32) + 140.0
        # Add non-Gaussian heavy-tailed residual characteristic of latent diffusion steps
        t_noise = np.random.standard_t(df=2.0, size=(200, 200, 3)) * 3.0
        ai_img = Image.fromarray(np.clip(base + t_noise, 0, 255).astype(np.uint8), mode="RGB")
        buf = io.BytesIO()
        ai_img.save(buf, format="PNG")

        event = coordinator.analyze(buf.getvalue(), "ai_diffusion_avatar.png")
        assert event.threat_score >= 0.50
        assert event.severity in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert any(e.evidence_type in ("synthetic_noise_kurtosis_anomaly", "synthetic_noise_flattening") for e in event.evidence)

    def test_camera_exif_grounding_preserves_safe(self, coordinator):
        """Verify that photos with verified optical camera EXIF are grounded as authentic."""
        raw_bytes = _generate_synthetic_photo(300, 300)
        img = Image.open(io.BytesIO(raw_bytes))
        exif = img.getexif()
        exif[0x010f] = "Canon"
        exif[0x0110] = "EOS R5"
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95, exif=exif)

        event = coordinator.analyze(buf.getvalue(), "canon_eos.jpg")
        assert event.classification == "LIKELY_AUTHENTIC"
        assert event.severity == RiskLevel.SAFE
        assert event.threat_score == 0.0
        assert event.metadata_details["provenance_status"] == "CAMERA_PROVENANCE_CONFIRMED"

    def test_high_res_smartphone_photo_with_sharp_edges_is_authentic(self, coordinator):
        """Verify that high-resolution smartphone photos (e.g., 1344x2980 Xiaomi) with sharp edges remain SAFE."""
        np.random.seed(42)
        H, W = 1490, 672  # Scaled simulation of 1344x2980 aspect ratio
        scene = np.zeros((H, W), dtype=np.float32)
        scene[200:1000, 100:300] = 220.0  # Sharp building edge
        scene[300:900, 150:250] = 50.0
        noise = np.random.normal(0, 2.5, (H, W))
        photo_arr = np.clip(scene + noise, 0, 255).astype(np.uint8)
        img = Image.fromarray(photo_arr, mode="L").convert("RGB")
        exif = img.getexif()
        exif[0x010f] = "Xiaomi"
        exif[0x0110] = "REDMI Note 15 5G"
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=90, exif=exif)

        event = coordinator.analyze(buf.getvalue(), "IMG_20261008_190422.jpg")
        assert event.classification == "LIKELY_AUTHENTIC"
        assert event.severity == RiskLevel.SAFE
        assert event.threat_score < 0.35
        assert event.metadata_details["provenance_status"] == "CAMERA_PROVENANCE_CONFIRMED"
        assert event.forensic_metrics["noise_kurtosis"] < 25.0
        assert event.forensic_metrics["noise_status"] == "NOMINAL"
        assert "thresholds" in event.forensic_metrics

    def test_configurable_thresholds_honored(self):
        """Verify that DeepfakeCoordinator honors custom ImageForensicsConfig without hardcoded behavior."""
        from backend.config import Settings, ImageForensicsConfig
        custom_cfg = Settings(
            image_forensics=ImageForensicsConfig(
                threshold_manipulated=0.50,
                threshold_inconclusive=0.20,
                noise_kurtosis_critical=50.0,
            )
        )
        custom_coord = DeepfakeCoordinator(config=custom_cfg)
        assert custom_coord.image_config.threshold_manipulated == 0.50
        assert custom_coord.image_config.threshold_inconclusive == 0.20
        assert custom_coord.image_config.noise_kurtosis_critical == 50.0
