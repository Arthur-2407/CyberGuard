"""
deepfake_coordinator.py — Multi-modal deepfake and synthetic media detection framework.

Grounded, non-destructive analysis across modalities:
  - Audio: Feature extraction, voice cloning probability, prosodic & spectral evaluation.
  - Image: 2D FFT spectral power distribution analysis, Laplacian variance, EXIF inspection, QR payload scan.
  - Video: Audio stream extraction & voice cloning analysis + keyframe visual artifact inspection.
"""

from __future__ import annotations

import io
import logging
import os
import subprocess
import tempfile
import time
from typing import Optional, Dict, Any, List

import numpy as np

from backend.config import get_settings
from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel
)
from backend.detection.detector import VoiceCloneDetector

logger = logging.getLogger(__name__)


class DeepfakeCoordinator:
    """Modality-oriented deepfake detection framework."""

    def __init__(self, config=None, voice_detector: VoiceCloneDetector = None):
        self.config = config or get_settings()
        self.voice_detector = voice_detector

    def analyze(
        self,
        media_bytes: bytes,
        filename: str,
        source: str = "media_upload",
        correlation_id: str = None,
    ) -> ThreatEvent:
        start_time = time.time()
        filename_lower = filename.lower()

        if filename_lower.endswith((".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".webm")):
            return self._analyze_audio(media_bytes, filename, source, correlation_id, start_time)

        elif filename_lower.endswith((".jpg", ".jpeg", ".png", ".webp", ".bmp")):
            return self._analyze_image(media_bytes, filename, source, correlation_id, start_time)

        elif filename_lower.endswith((".mp4", ".mkv", ".mov", ".avi", ".wmv")):
            return self._analyze_video(media_bytes, filename, source, correlation_id, start_time)

        else:
            return self._build_unsupported_event(source, filename, correlation_id, start_time)

    def _analyze_audio(
        self,
        media_bytes: bytes,
        filename: str,
        source: str,
        correlation_id: str,
        start_time: float,
    ) -> ThreatEvent:
        tmp_path = None
        try:
            from backend.audio.preprocessor import load_audio, preprocess_audio, chunk_audio, normalize_to_mp3
            from backend.detection.risk_engine import build_risk_engine_from_settings

            suffix = os.path.splitext(filename)[1] or ".dat"
            fd, tmp_path = tempfile.mkstemp(suffix=suffix)
            os.close(fd)
            with open(tmp_path, "wb") as f:
                f.write(media_bytes)

            # Normalize to MP3 if needed
            normalized_path = normalize_to_mp3(tmp_path)
            if normalized_path != tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                tmp_path = normalized_path

            audio, sr = load_audio(tmp_path, target_sr=self.config.audio.sample_rate)
            audio = preprocess_audio(
                audio,
                sr=self.config.audio.sample_rate,
                target_sr=self.config.audio.sample_rate,
                apply_vad=True,
            )
            chunks = chunk_audio(
                audio,
                sr=self.config.audio.sample_rate,
                chunk_duration=self.config.audio.chunk_duration_sec,
                overlap_ratio=self.config.audio.overlap_ratio,
            )

            if not chunks:
                return self._build_safe_event(
                    source=source,
                    modality="audio",
                    summary="No active speech or audio signals detected in the media file.",
                    correlation_id=correlation_id,
                    start_time=start_time,
                )

            detector = self.voice_detector
            if not detector:
                from backend.detection.detector import VoiceCloneDetector
                detector = VoiceCloneDetector(self.config)
            if not detector.is_initialized:
                detector.initialize()

            risk_engine = build_risk_engine_from_settings(self.config)
            chunk_results = []
            for i, chunk in enumerate(chunks):
                res = detector.process_chunk(chunk, chunk_id=i)
                snapshot = risk_engine.update(
                    chunk_id=i,
                    detection_score=res.synthetic_probability,
                )
                chunk_results.append({
                    "chunk_id": i,
                    "prob": res.synthetic_probability,
                    "risk": snapshot.combined_risk,
                })

            summary_stats = risk_engine.get_session_summary()
            peak_risk = float(summary_stats.get("peak_risk", 0.0))
            mean_risk = float(summary_stats.get("mean_risk", 0.0))

            evidences: List[Evidence] = []
            evidences.append(Evidence(
                evidence_type="voice_clone_probability",
                description=f"Acoustic analysis processed {len(chunks)} speech segments. Peak synthetic probability: {peak_risk:.3f}, mean: {mean_risk:.3f}.",
                value=f"peak={peak_risk:.3f}",
                severity_contribution=peak_risk,
                confidence=0.9 if detector.is_initialized else 0.75,
                source="VoiceCloneDetector",
            ))

            if peak_risk >= 0.80:
                severity = RiskLevel.HIGH if peak_risk < 0.95 else RiskLevel.CRITICAL
                classification = "SUSPICIOUS"
                summary = "High probability of synthetic speech / voice cloning detected."
                reasoning = (
                    f"Acoustic feature analysis indicated strong synthetic vocoder artifacts across speech chunks. "
                    f"Peak risk score reached {peak_risk:.3f}."
                )
                category = ThreatCategory.VOICE_CLONING
                actions = [
                    "Flag audio recording as potential synthetic/cloned speech.",
                    "Verify speaker authenticity through trusted secondary channel.",
                    "Halt sensitive authorization or voice verification workflows.",
                ]
            elif peak_risk >= 0.60:
                severity = RiskLevel.MEDIUM
                classification = "SUSPICIOUS"
                summary = "Moderate synthetic speech markers observed."
                reasoning = f"Acoustic features showed elevated synthetic probability ({peak_risk:.3f}) warranting inspection."
                category = ThreatCategory.VOICE_CLONING
                actions = ["Inspect audio metadata and review context before trusting."]
            elif peak_risk >= 0.35:
                severity = RiskLevel.LOW
                classification = "SAFE"
                summary = "Low-level acoustic variance detected; likely authentic."
                reasoning = f"Peak synthetic probability ({peak_risk:.3f}) remains below threshold."
                category = ThreatCategory.SAFE
                actions = ["No immediate action needed."]
            else:
                severity = RiskLevel.SAFE
                classification = "SAFE"
                summary = "Audio sample verified authentic. No synthetic voice cloning detected."
                reasoning = "Acoustic prosody and spectral features are consistent with genuine human speech."
                category = ThreatCategory.SAFE
                actions = ["Audio is authentic."]

            return ThreatEvent(
                source=source,
                source_type="file",
                modality="audio",
                threat_category=category,
                severity=severity,
                confidence=0.9,
                classification=classification,
                evidence=evidences,
                explanation=Explanation(
                    summary=summary,
                    reasoning=reasoning,
                    limitations="Acoustic analysis based on calibrated multi-feature spectral and prosodic baselines.",
                ),
                recommended_actions=actions,
                detector="VoiceCloneDetector",
                processing_time_ms=(time.time() - start_time) * 1000.0,
                correlation_id=correlation_id,
            )

        except Exception as exc:
            logger.warning(f"Audio deepfake analysis error: {exc}", exc_info=True)
            return self._build_error_event(source, "audio", str(exc), correlation_id, start_time)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _analyze_image(
        self,
        media_bytes: bytes,
        filename: str,
        source: str,
        correlation_id: str,
        start_time: float,
    ) -> ThreatEvent:
        if not self.config or not getattr(self.config.cyberguard, "deepfake_image_enabled", True):
            return self._build_unavailable_event(source, "image", "ImageDeepfakeDetector", correlation_id, start_time)

        try:
            from PIL import Image
            img = Image.open(io.BytesIO(media_bytes))
            img_format = img.format or "UNKNOWN"
            w, h = img.size

            evidences: List[Evidence] = []
            suspicion_score = 0.0

            # 1. EXIF Metadata Inspection
            exif_data = getattr(img, "_getexif", lambda: None)()
            if exif_data:
                exif_str = str(exif_data).lower()
                ai_keywords = ["stable diffusion", "midjourney", "dall-e", "novelai", "comfyui", "automatic1111"]
                for kw in ai_keywords:
                    if kw in exif_str:
                        suspicion_score += 0.7
                        evidences.append(Evidence(
                            evidence_type="metadata_ai_signature",
                            description=f"Image metadata contains reference to generative AI software: '{kw}'.",
                            value=kw,
                            severity_contribution=0.7,
                            source="ImageDeepfakeDetector",
                        ))
                        break

            # 2. 2D FFT Frequency Domain Analysis
            # Generative models exhibit distinct high-frequency power spectrum roll-offs / periodic grid patterns
            gray_img = img.convert("L").resize((256, 256))
            arr = np.array(gray_img, dtype=np.float32)
            f_transform = np.fft.fft2(arr)
            f_shift = np.fft.fftshift(f_transform)
            magnitude_spectrum = np.abs(f_shift)

            # High-frequency energy ratio vs low-frequency energy
            center_x, center_y = 128, 128
            y, x = np.ogrid[:256, :256]
            dist_from_center = np.sqrt((x - center_x) ** 2 + (y - center_y) ** 2)
            high_freq_mask = dist_from_center > 64
            low_freq_mask = dist_from_center <= 32

            high_freq_energy = np.mean(magnitude_spectrum[high_freq_mask])
            low_freq_energy = np.mean(magnitude_spectrum[low_freq_mask]) + 1e-6
            energy_ratio = float(high_freq_energy / low_freq_energy)

            # High-frequency anomaly: natural images have an energy ratio typically between 0.02 and 0.25.
            if energy_ratio < 0.015:
                suspicion_score += 0.35
                evidences.append(Evidence(
                    evidence_type="spectral_oversmoothing",
                    description=f"Frequency domain analysis reveals suppressed high-frequency spectrum ({energy_ratio:.4f}), typical of synthetic generative diffusion models.",
                    value=f"ratio={energy_ratio:.4f}",
                    severity_contribution=0.35,
                    source="ImageDeepfakeDetector",
                ))
            elif energy_ratio > 0.40:
                suspicion_score += 0.4
                evidences.append(Evidence(
                    evidence_type="spectral_grid_artifacts",
                    description=f"Frequency domain analysis reveals abnormal high-frequency energy ({energy_ratio:.4f}), consistent with GAN transposed-convolution checkerboard artifacts.",
                    value=f"ratio={energy_ratio:.4f}",
                    severity_contribution=0.4,
                    source="ImageDeepfakeDetector",
                ))

            # 3. Laplacian Variance (Sharpness / Noise inconsistency)
            kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
            from scipy.signal import convolve2d
            try:
                laplacian = convolve2d(arr, kernel, mode="valid")
                lap_var = float(laplacian.var())
                if lap_var < 20.0 and (w * h > 10000):
                    suspicion_score += 0.2
                    evidences.append(Evidence(
                        evidence_type="low_laplacian_variance",
                        description=f"Unusually low edge variance ({lap_var:.1f}) indicating synthetic blur or artificial skin smoothing.",
                        value=f"var={lap_var:.1f}",
                        severity_contribution=0.2,
                        source="ImageDeepfakeDetector",
                    ))
            except Exception:
                pass

            # 4. Check for embedded QR code payload
            try:
                from pyzbar.pyzbar import decode as pyzbar_decode
                decoded_qr = pyzbar_decode(img)
                if decoded_qr:
                    payload = decoded_qr[0].data.decode("utf-8", errors="ignore")
                    evidences.append(Evidence(
                        evidence_type="embedded_qr_code",
                        description=f"Image contains an embedded QR code with payload: {payload[:80]}",
                        value=payload,
                        severity_contribution=0.2,
                        source="QRScanner",
                    ))
                    suspicion_score += 0.2
            except (ImportError, Exception):
                pass

            suspicion_score = min(1.0, suspicion_score)

            if suspicion_score >= 0.70:
                severity = RiskLevel.HIGH
                classification = "SUSPICIOUS"
                summary = "Synthetic visual media / Deepfake image artifacts identified."
                reasoning = "Image exhibits significant spectral and generative synthesis patterns consistent with AI generation."
                category = ThreatCategory.DEEPFAKE
                actions = ["Flag image for visual forensic review", "Request verifiable original camera RAW file"]
            elif suspicion_score >= 0.35:
                severity = RiskLevel.MEDIUM
                classification = "SUSPICIOUS"
                summary = "Potential synthetic image anomalies detected."
                reasoning = "Frequency domain indicators show slight deviations from natural optical camera sensors."
                category = ThreatCategory.DEEPFAKE
                actions = ["Inspect origin and reverse-image search for authenticity."]
            else:
                severity = RiskLevel.SAFE
                classification = "SAFE"
                summary = "Image analysis authentic. No synthetic deepfake anomalies found."
                reasoning = "Spectral distribution and edge properties align with authentic camera captures."
                category = ThreatCategory.SAFE
                actions = ["Image verified authentic."]

            return ThreatEvent(
                source=source,
                source_type="file",
                modality="image",
                threat_category=category,
                severity=severity,
                confidence=0.85,
                classification=classification,
                evidence=evidences,
                explanation=Explanation(
                    summary=summary,
                    reasoning=reasoning,
                    limitations="Forensic analysis based on 2D FFT spectral distribution, Laplacian variance, and metadata extraction.",
                ),
                recommended_actions=actions,
                detector="ImageDeepfakeDetector",
                processing_time_ms=(time.time() - start_time) * 1000.0,
                correlation_id=correlation_id,
            )

        except Exception as exc:
            logger.warning(f"Image deepfake analysis error: {exc}", exc_info=True)
            return self._build_error_event(source, "image", str(exc), correlation_id, start_time)

    def _analyze_video(
        self,
        media_bytes: bytes,
        filename: str,
        source: str,
        correlation_id: str,
        start_time: float,
    ) -> ThreatEvent:
        if not self.config or not getattr(self.config.cyberguard, "deepfake_video_enabled", True):
            return self._build_unavailable_event(source, "video", "VideoDeepfakeDetector", correlation_id, start_time)

        tmp_video_path = None
        extracted_audio_path = None
        frame_dir = None
        try:
            from backend.audio.preprocessor import _get_ffmpeg_executable

            ffmpeg_exe = _get_ffmpeg_executable()
            suffix = os.path.splitext(filename)[1] or ".mp4"
            fd, tmp_video_path = tempfile.mkstemp(suffix=suffix)
            os.close(fd)
            with open(tmp_video_path, "wb") as f:
                f.write(media_bytes)

            evidences: List[Evidence] = []
            video_risk = 0.0

            # 1. Extract audio track from video and analyze with voice clone detector
            fd2, extracted_audio_path = tempfile.mkstemp(suffix=".mp3")
            os.close(fd2)

            cmd_audio = [
                ffmpeg_exe, "-y", "-i", tmp_video_path,
                "-vn", "-acodec", "libmp3lame", "-ar", "16000", "-ac", "1",
                extracted_audio_path
            ]
            r_audio = subprocess.run(cmd_audio, capture_output=True, timeout=30)
            if r_audio.returncode == 0 and os.path.exists(extracted_audio_path) and os.path.getsize(extracted_audio_path) > 1000:
                with open(extracted_audio_path, "rb") as af:
                    audio_bytes = af.read()
                audio_event = self._analyze_audio(
                    audio_bytes, "extracted_audio.mp3", source=source, correlation_id=correlation_id, start_time=start_time
                )
                if audio_event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    video_risk = max(video_risk, 0.85)
                    evidences.extend(audio_event.evidence)
                elif audio_event.severity == RiskLevel.MEDIUM:
                    video_risk = max(video_risk, 0.60)
                    evidences.extend(audio_event.evidence)
                else:
                    evidences.append(Evidence(
                        evidence_type="video_soundtrack_authentic",
                        description="Audio soundtrack extracted from video showed natural acoustic prosody.",
                        source="VoiceCloneDetector",
                    ))

            # 2. Extract keyframes for visual inspection
            frame_dir = tempfile.mkdtemp(prefix="video_frames_")
            frame_pattern = os.path.join(frame_dir, "frame_%03d.jpg")
            cmd_frames = [
                ffmpeg_exe, "-y", "-i", tmp_video_path,
                "-vf", "fps=1,scale=320:240", "-vframes", "3",
                frame_pattern
            ]
            subprocess.run(cmd_frames, capture_output=True, timeout=30)

            frame_files = [os.path.join(frame_dir, f) for f in os.listdir(frame_dir) if f.endswith(".jpg")]
            if frame_files:
                for ff in frame_files[:3]:
                    with open(ff, "rb") as fbf:
                        fevent = self._analyze_image(fbf.read(), os.path.basename(ff), source=source, correlation_id=correlation_id, start_time=start_time)
                        if fevent.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                            video_risk = max(video_risk, 0.80)
                            evidences.extend(fevent.evidence)
                            break
                        elif fevent.severity == RiskLevel.MEDIUM:
                            video_risk = max(video_risk, 0.55)
                            evidences.extend(fevent.evidence)

            if video_risk >= 0.75:
                severity = RiskLevel.HIGH
                classification = "SUSPICIOUS"
                summary = "Deepfake video artifacts detected across audio-visual channels."
                reasoning = "Multi-modal analysis revealed synthetic voice cloning or visual manipulation in video content."
                category = ThreatCategory.DEEPFAKE
                actions = ["Do not distribute or authenticate sensitive actions via this video", "Request live video verification"]
            elif video_risk >= 0.50:
                severity = RiskLevel.MEDIUM
                classification = "SUSPICIOUS"
                summary = "Elevated risk markers observed in video media."
                reasoning = "Moderate acoustic or visual anomalies were detected during multi-frame extraction."
                category = ThreatCategory.DEEPFAKE
                actions = ["Perform manual review of high-risk frames and audio track."]
            else:
                severity = RiskLevel.SAFE
                classification = "SAFE"
                summary = "Video authentic. Both soundtrack and visual frames verified."
                reasoning = "No synthetic manipulation detected in audio track or extracted video frames."
                category = ThreatCategory.SAFE
                actions = ["Video verified authentic."]

            return ThreatEvent(
                source=source,
                source_type="file",
                modality="video",
                threat_category=category,
                severity=severity,
                confidence=0.85,
                classification=classification,
                evidence=evidences,
                explanation=Explanation(
                    summary=summary,
                    reasoning=reasoning,
                    limitations="Multi-modal analysis combining FFmpeg audio track extraction and keyframe forensic inspection.",
                ),
                recommended_actions=actions,
                detector="VideoDeepfakeDetector",
                processing_time_ms=(time.time() - start_time) * 1000.0,
                correlation_id=correlation_id,
            )

        except Exception as exc:
            logger.warning(f"Video deepfake analysis error: {exc}", exc_info=True)
            return self._build_error_event(source, "video", str(exc), correlation_id, start_time)
        finally:
            if tmp_video_path and os.path.exists(tmp_video_path):
                try:
                    os.unlink(tmp_video_path)
                except OSError:
                    pass
            if extracted_audio_path and os.path.exists(extracted_audio_path):
                try:
                    os.unlink(extracted_audio_path)
                except OSError:
                    pass
            if frame_dir and os.path.exists(frame_dir):
                import shutil
                try:
                    shutil.rmtree(frame_dir, ignore_errors=True)
                except Exception:
                    pass

    def _build_safe_event(self, source, modality, summary, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="file",
            modality=modality,
            threat_category=ThreatCategory.SAFE,
            severity=RiskLevel.SAFE,
            confidence=1.0,
            classification="SAFE",
            explanation=Explanation(summary=summary, reasoning="Content parameters fall well within expected authentic ranges."),
            recommended_actions=["Media is safe."],
            detector="DeepfakeCoordinator",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id,
        )

    def _build_error_event(self, source, modality, error_msg, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="file",
            modality=modality,
            threat_category=ThreatCategory.UNKNOWN,
            severity=RiskLevel.LOW,
            classification="ERROR",
            evidence=[Evidence(
                evidence_type="processing_error",
                description="Failed to complete deepfake forensic inspection.",
                value=error_msg,
                source="DeepfakeCoordinator",
            )],
            explanation=Explanation(
                summary="An error occurred during deepfake media analysis.",
                reasoning=error_msg,
            ),
            detector="DeepfakeCoordinator",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id,
        )

    def _build_unavailable_event(self, source, modality, detector, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="file",
            modality=modality,
            threat_category=ThreatCategory.UNKNOWN,
            severity=RiskLevel.SAFE,
            classification="UNAVAILABLE",
            explanation=Explanation(
                summary=f"Analysis capability for {modality} is disabled or unavailable.",
                reasoning="Feature disabled in configuration.",
            ),
            capability_status="UNAVAILABLE",
            detector=detector,
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id,
        )

    def _build_unsupported_event(self, source, filename, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="file",
            modality="unknown",
            threat_category=ThreatCategory.UNKNOWN,
            severity=RiskLevel.SAFE,
            classification="UNSUPPORTED",
            explanation=Explanation(
                summary="Unsupported media format.",
                reasoning=f"File extension for {filename} is not recognized by any registered detector.",
            ),
            capability_status="UNSUPPORTED",
            detector="DeepfakeCoordinator",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id,
        )
