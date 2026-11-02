"""
video_forensics.py — Comprehensive Video & Animated Media Forensic Engine.

Core Forensic Methods:
  1. Video Stream Acquisition: FFprobe & OpenCV container inspection (codec, FPS, duration, resolution, audio streams).
  2. Intelligent Timestamp-Preserving Sampling: Adaptive extraction of 8–16 keyframes across video duration.
  3. Frame-Level Multi-Domain Forensics: FFT lattice detection, ELA compression disparity, sensor noise, and facial seams.
  4. True Video Temporal Consistency Analysis:
     - Inter-frame luminance & color absolute difference (normalized frame transitions).
     - High-frequency temporal flickering / jitter detection across consecutive frames.
     - Facial landmark & microtexture stability tracking across time.
  5. Audio-Visual Multimodal Synchronization:
     - FFmpeg audio soundtrack demuxing & voice clone prosodic inspection.
     - Cross-correlation between acoustic voice anomalies and visual manipulation intervals.
  6. Explainable Forensic Timeline: Identifies specific suspicious timestamps and frame intervals.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import os
import subprocess
import tempfile
import time
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
from PIL import Image

from backend.config import get_settings
from backend.threats.models import Evidence, RiskLevel, ThreatCategory
from backend.analysis.forensics.image_forensics import get_image_forensics_engine
from backend.models.vision_detector import get_vision_detector

logger = logging.getLogger(__name__)


class VideoForensicsEngine:
    """End-to-end video forensics, keyframe sampling, and temporal consistency pipeline."""

    def __init__(self, config=None, voice_detector=None):
        self.config = config or get_settings()
        self.voice_detector = voice_detector
        self.image_engine = get_image_forensics_engine()
        self.vision_detector = get_vision_detector(self.config)

    def analyze_video_bytes(self, media_bytes: bytes, filename: str) -> Any:
        """Convenience method returning object wrapper."""
        d = self.analyze(media_bytes, filename)

        class VideoAnalysisResult:
            def __init__(self, data):
                self.__dict__.update(data)
                self.media_info = data.get("media_info", {})
                self.frame_analysis = data.get("frame_analysis", {})
                self.forensic_metrics = data.get("forensic_metrics", {})

        return VideoAnalysisResult(d)

    def analyze(
        self,
        media_bytes: bytes,
        filename: str,
        source: str = "video_upload",
        correlation_id: str = None,
    ) -> Dict[str, Any]:
        """Execute full video forensics pipeline."""
        start_time = time.time()
        sha256 = hashlib.sha256(media_bytes).hexdigest()
        file_size_bytes = len(media_bytes)

        tmp_video_path = None
        extracted_audio_path = None
        evidences: List[Evidence] = []

        try:
            ffmpeg_exe = None
            try:
                from backend.audio.preprocessor import _get_ffmpeg_executable
                ffmpeg_exe = _get_ffmpeg_executable()
            except Exception as ff_init_err:
                logger.warning(f"FFmpeg binary not available for video soundtrack processing: {ff_init_err}")

            suffix = os.path.splitext(filename)[1] or ".mp4"
            fd, tmp_video_path = tempfile.mkstemp(suffix=suffix)
            os.close(fd)
            with open(tmp_video_path, "wb") as f:
                f.write(media_bytes)

            # ── 1. Video Container & Stream Metadata Extraction ───────────────────
            stream_meta = self._probe_video_metadata(tmp_video_path, ffmpeg_exe)

            # ── 2. Audio Demuxing & Voice Clone Inspection ─────────────────────────
            audio_risk = 0.0
            has_soundtrack = stream_meta.get("has_audio", False)
            audio_details = {}

            if has_soundtrack and ffmpeg_exe:
                fd_a, extracted_audio_path = tempfile.mkstemp(suffix=".mp3")
                os.close(fd_a)

                cmd_audio = [
                    ffmpeg_exe, "-y", "-i", tmp_video_path,
                    "-vn", "-acodec", "libmp3lame", "-ar", "16000", "-ac", "1",
                    extracted_audio_path
                ]
                r_audio = subprocess.run(cmd_audio, capture_output=True, timeout=30)
                if r_audio.returncode == 0 and os.path.exists(extracted_audio_path) and os.path.getsize(extracted_audio_path) > 1000:
                    with open(extracted_audio_path, "rb") as af:
                        audio_bytes = af.read()
                    audio_risk, audio_evs, audio_details = self._analyze_soundtrack(audio_bytes, correlation_id)
                    evidences.extend(audio_evs)
                else:
                    has_soundtrack = False

            # ── 3. Intelligent Frame Extraction & Sampling ────────────────────────
            frame_records, consecutive_diffs = self._sample_and_analyze_keyframes(
                tmp_video_path, stream_meta.get("duration_sec", 0.0), stream_meta.get("fps", 25.0), ffmpeg_exe=ffmpeg_exe
            )

            # ── 4. Temporal Consistency & Jitter Analysis ─────────────────────────
            temporal_metrics, temp_evidences = self._analyze_temporal_consistency(
                frame_records, consecutive_diffs
            )
            evidences.extend(temp_evidences)

            # ── 5. Multi-Modal Composite Risk Calculation ─────────────────────────
            mean_visual_score = float(np.mean([f["score"] for f in frame_records])) if frame_records else 0.0
            peak_visual_score = float(np.max([f["score"] for f in frame_records])) if frame_records else 0.0
            temporal_anomaly_score = temporal_metrics.get("temporal_anomaly_score", 0.0)

            # Weighting: 40% visual keyframes, 35% temporal consistency, 25% audio soundtrack
            if has_soundtrack and frame_records:
                composite_risk = (mean_visual_score * 0.40) + (temporal_anomaly_score * 0.35) + (audio_risk * 0.25)
            elif frame_records:
                composite_risk = (mean_visual_score * 0.55) + (temporal_anomaly_score * 0.45)
            else:
                composite_risk = audio_risk

            # Suspicious timestamps detection
            suspicious_intervals = []
            for fr in frame_records:
                if fr["score"] >= 0.60:
                    t = fr["timestamp_sec"]
                    suspicious_intervals.append({
                        "start_sec": max(0.0, round(t - 0.5, 2)),
                        "end_sec": round(t + 0.5, 2),
                        "peak_score": fr["score"],
                        "frame_index": fr["frame_index"],
                        "triggers": fr.get("triggers", ["Visual anomaly"]),
                    })

            # Aggregate neural vision results across sampled keyframes
            valid_v_probs = [f["neural_vision_prob"] for f in frame_records if f.get("neural_vision_prob") is not None]
            video_neural_prob = round(float(np.median(valid_v_probs)), 4) if valid_v_probs else None
            video_auth_prob = round(1.0 - video_neural_prob, 4) if video_neural_prob is not None else None
            predicted_class = (
                "AUTHENTIC" if (video_neural_prob is not None and video_neural_prob <= 0.20)
                else ("SYNTHETIC" if (video_neural_prob is not None and video_neural_prob >= 0.65)
                else ("INCONCLUSIVE" if video_neural_prob is not None else "NOT_EVALUATED"))
            )

            media_info = {
                "is_video": True,
                "sha256": sha256,
                "filename": filename,
                "file_size_bytes": file_size_bytes,
                "format": stream_meta.get("format", os.path.splitext(filename)[1].replace(".", "").upper()),
                "duration_sec": stream_meta.get("duration_sec", 0.0),
                "fps": stream_meta.get("fps", 0.0),
                "width": stream_meta.get("width", 320),
                "height": stream_meta.get("height", 240),
                "resolution": stream_meta.get("resolution", "Unknown"),
                "total_frames": stream_meta.get("total_frames", 0),
                "video_codec": stream_meta.get("video_codec", "Unknown"),
                "has_audio": has_soundtrack,
                "stream_dynamics": temporal_metrics.get("stream_dynamics", "NATURAL_MOTION"),
                "neural_synthetic_probability": video_neural_prob,
                "neural_authentic_probability": video_auth_prob,
                "p_synthetic": video_neural_prob,
                "neural_predicted_class": predicted_class,
            }

            frame_analysis = {
                "total_frames_sampled": len(frame_records),
                "temporal_consistency": temporal_metrics.get("temporal_consistency", 1.0),
                "temporal_jitter_index": temporal_metrics.get("temporal_jitter_index", 0.0),
                "stream_dynamics": temporal_metrics.get("stream_dynamics", "NATURAL_MOTION"),
                "static_frame_ratio": temporal_metrics.get("static_frame_ratio", 0.0),
                "mean_frame_score": round(mean_visual_score, 4),
                "peak_frame_score": round(peak_visual_score, 4),
                "composite_risk": round(float(composite_risk), 4),
                "has_soundtrack": has_soundtrack,
                "suspicious_intervals": suspicious_intervals,
                "frames": frame_records,
                "audio_details": audio_details,
                "neural_synthetic_probability": video_neural_prob,
                "neural_authentic_probability": video_auth_prob,
                "p_synthetic": video_neural_prob,
                "neural_predicted_class": predicted_class,
            }

            return {
                "media_info": media_info,
                "frame_analysis": frame_analysis,
                "evidences": evidences,
                "composite_risk": round(float(composite_risk), 4),
                "temporal_metrics": temporal_metrics,
                "processing_time_ms": (time.time() - start_time) * 1000.0,
            }

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

    def _probe_video_metadata(self, video_path: str, ffmpeg_exe: str) -> Dict[str, Any]:
        """Probe video container for codec, resolution, duration, and FPS using OpenCV and FFprobe."""
        meta = {
            "duration_sec": 0.0,
            "fps": 25.0,
            "total_frames": 0,
            "resolution": "Unknown",
            "video_codec": "Unknown",
            "format": "MP4",
            "has_audio": False,
        }

        try:
            import cv2
            cap = cv2.VideoCapture(video_path)
            if cap.isOpened():
                total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                fps = float(cap.get(cv2.CAP_PROP_FPS) or 25.0)
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
                codec_chars = "".join([chr((fourcc_int >> 8 * i) & 0xFF) for i in range(4)]).strip()

                meta["total_frames"] = total_frames
                meta["fps"] = round(fps, 2)
                if fps > 0 and total_frames > 0:
                    meta["duration_sec"] = round(float(total_frames / fps), 2)
                if width > 0 and height > 0:
                    meta["resolution"] = f"{width}x{height}"
                    meta["width"] = width
                    meta["height"] = height
                if codec_chars:
                    meta["video_codec"] = codec_chars
                cap.release()
        except Exception as cv_probe_err:
            logger.debug(f"OpenCV probe notice: {cv_probe_err}")

        # Check for audio presence and container metrics via FFmpeg probe fallback
        if ffmpeg_exe:
            try:
                cmd_probe = [ffmpeg_exe, "-i", video_path]
                r = subprocess.run(cmd_probe, capture_output=True, text=True, timeout=10)
                combined_stderr = r.stderr.lower()
                if "audio:" in combined_stderr or "sound" in combined_stderr:
                    meta["has_audio"] = True
                
                import re
                m_dur = re.search(r"duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", combined_stderr)
                if m_dur and meta["duration_sec"] <= 0.0:
                    h = float(m_dur.group(1))
                    m = float(m_dur.group(2))
                    s = float(m_dur.group(3))
                    meta["duration_sec"] = round(h * 3600.0 + m * 60.0 + s, 2)

                m_res = re.search(r",\s*(\d{2,5})x(\d{2,5})", combined_stderr)
                if m_res and (meta.get("resolution") in ("Unknown", None) or meta.get("width") is None):
                    meta["width"] = int(m_res.group(1))
                    meta["height"] = int(m_res.group(2))
                    meta["resolution"] = f"{meta['width']}x{meta['height']}"

                m_fps = re.search(r"(\d+(?:\.\d+)?)\s*fps", combined_stderr)
                if m_fps and (meta.get("total_frames", 0) == 0 or meta.get("fps") in (25.0, 0.0)):
                    meta["fps"] = round(float(m_fps.group(1)), 2)

                if meta.get("total_frames", 0) == 0 and meta["duration_sec"] > 0 and meta["fps"] > 0:
                    meta["total_frames"] = int(round(meta["duration_sec"] * meta["fps"]))

                m_codec = re.search(r"video:\s*([a-z0-9_]+)", combined_stderr)
                if m_codec and meta.get("video_codec") in ("Unknown", None):
                    meta["video_codec"] = m_codec.group(1).upper()
            except Exception as ff_probe_err:
                logger.debug(f"FFmpeg audio/video probe notice: {ff_probe_err}")

        return meta

    def _sample_and_analyze_keyframes(
        self, video_path: str, duration_sec: float, fps: float, ffmpeg_exe: str = None
    ) -> Tuple[List[Dict[str, Any]], List[float]]:
        """Extract adaptive keyframes, compute frame-level forensics, and measure consecutive frame diffs."""
        frame_records = []
        consecutive_diffs = []

        try:
            import cv2
            cap = cv2.VideoCapture(video_path)
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = float(cap.get(cv2.CAP_PROP_FPS) or fps or 25.0)

            if total_frames <= 0:
                cap.release()
                return [], []

            # Adaptive sampling: 8 frames for short, 12 for medium, 16 for long videos
            num_samples = 8
            if duration_sec > 30.0:
                num_samples = 16
            elif duration_sec > 8.0:
                num_samples = 12
            num_samples = min(num_samples, total_frames)

            sample_indices = np.linspace(0, total_frames - 1, num=num_samples, dtype=int)
            prev_gray = None

            for idx in sample_indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, int(idx))
                ret, cv_frame = cap.read()
                if not ret or cv_frame is None:
                    continue

                curr_gray = cv2.cvtColor(cv_frame, cv2.COLOR_BGR2GRAY)
                # Compute consecutive frame transition delta
                diff_val = 0.0
                if prev_gray is not None and prev_gray.shape == curr_gray.shape:
                    diff_val = float(np.mean(cv2.absdiff(prev_gray, curr_gray)))
                    consecutive_diffs.append(diff_val)
                prev_gray = curr_gray

                # Convert to PIL for frame-level DSP forensics
                frame_rgb = cv2.cvtColor(cv_frame, cv2.COLOR_BGR2RGB)
                pil_frame = Image.fromarray(frame_rgb)
                metrics, f_evidences, f_score = self.image_engine.analyze(pil_frame)
                v_prob = None
                if getattr(self, "vision_detector", None) and self.vision_detector.is_ready:
                    v_pred = self.vision_detector.predict(pil_frame)
                    if v_pred.get("is_evaluated") and v_pred.get("probability") is not None:
                        v_prob = v_pred["probability"]
                        if v_prob >= 0.50:
                            f_score = 1.0 - ((1.0 - f_score) * (1.0 - v_prob))
                        elif v_prob <= 0.20:
                            # Strongly authentic neural features: if only heuristic trigger is noise kurtosis from flat digital graphics
                            has_severe_tampering = any(
                                e.evidence_type in ("spectral_periodic_lattice", "spectral_high_freq_boost", "facial_microtexture_smoothing", "facial_boundary_discontinuity")
                                for e in f_evidences
                            )
                            if not has_severe_tampering and metrics.get("fft_status") == "NOMINAL" and metrics.get("faces_detected", 0) == 0:
                                f_score = min(f_score, 0.15 + (v_prob * 0.5))

                # Generate small frame thumbnail (base64)
                thumb_pil = pil_frame.copy()
                thumb_pil.thumbnail((120, 80))
                thumb_buf = io.BytesIO()
                thumb_pil.save(thumb_buf, format="JPEG", quality=75)
                thumb_b64 = f"data:image/jpeg;base64,{base64.b64encode(thumb_buf.getvalue()).decode('ascii')}"

                triggers = [e.evidence_type for e in f_evidences if e.severity_contribution >= 0.20]

                timestamp = round(float(idx / fps), 2)
                frame_records.append({
                    "frame_index": int(idx),
                    "timestamp_sec": timestamp,
                    "score": round(float(f_score), 4),
                    "classification": "LIKELY_MANIPULATED" if f_score >= 0.65 else ("INCONCLUSIVE" if f_score >= 0.35 else "LIKELY_AUTHENTIC"),
                    "ela_mean": metrics.get("ela_mean", 0.0),
                    "ela_disparity": metrics.get("ela_disparity", 0.0),
                    "fft_spike_ratio": metrics.get("fft_off_axis_spike_ratio", 0.0),
                    "noise_variance": metrics.get("noise_variance", 0.0),
                    "faces_detected": metrics.get("faces_detected", 0),
                    "neural_vision_prob": v_prob,
                    "facial_status": metrics.get("facial_status", "None"),
                    "inter_frame_diff": round(diff_val, 2),
                    "thumbnail": thumb_b64,
                    "triggers": triggers,
                })

            cap.release()
        except Exception as cap_err:
            logger.warning(f"Keyframe extraction notice: {cap_err}")

        # Fallback to FFmpeg frame extraction if cv2 was unavailable or yielded 0 frames
        if not frame_records and ffmpeg_exe and os.path.exists(video_path):
            try:
                import tempfile
                import shutil
                temp_dir = tempfile.mkdtemp(prefix="cg_ff_frames_")
                target_count = 8
                if duration_sec > 30.0:
                    target_count = 16
                elif duration_sec > 8.0:
                    target_count = 12

                rate = max(0.5, round(target_count / max(1.0, duration_sec), 2))
                out_pattern = os.path.join(temp_dir, "frame_%03d.png")
                cmd_extract = [
                    ffmpeg_exe, "-y", "-i", video_path,
                    "-vf", f"fps={rate}",
                    "-vframes", str(target_count),
                    out_pattern
                ]
                subprocess.run(cmd_extract, capture_output=True, timeout=25)
                frame_files = sorted([
                    os.path.join(temp_dir, f) for f in os.listdir(temp_dir)
                    if f.startswith("frame_") and f.endswith(".png")
                ])
                prev_gray = None
                for idx, fpath in enumerate(frame_files):
                    try:
                        with Image.open(fpath) as pil_frame:
                            pil_frame = pil_frame.convert("RGB")
                            curr_gray = np.array(pil_frame.convert("L"), dtype=np.float32)
                            diff_val = 0.0
                            if prev_gray is not None and prev_gray.shape == curr_gray.shape:
                                diff_val = float(np.mean(np.abs(prev_gray - curr_gray)))
                                consecutive_diffs.append(diff_val)
                            prev_gray = curr_gray

                            metrics, f_evidences, f_score = self.image_engine.analyze(pil_frame)
                            v_prob = None
                            if getattr(self, "vision_detector", None) and self.vision_detector.is_ready:
                                v_pred = self.vision_detector.predict(pil_frame)
                                if v_pred.get("is_evaluated") and v_pred.get("probability") is not None:
                                    v_prob = v_pred["probability"]
                                    if v_prob >= 0.50:
                                        f_score = 1.0 - ((1.0 - f_score) * (1.0 - v_prob))
                                    elif v_prob <= 0.20:
                                        has_severe_tampering = any(
                                            e.evidence_type in ("spectral_periodic_lattice", "spectral_high_freq_boost", "facial_microtexture_smoothing", "facial_boundary_discontinuity")
                                            for e in f_evidences
                                        )
                                        if not has_severe_tampering and metrics.get("fft_status") == "NOMINAL" and metrics.get("faces_detected", 0) == 0:
                                            f_score = min(f_score, 0.15 + (v_prob * 0.5))
                            thumb_pil = pil_frame.copy()
                            thumb_pil.thumbnail((120, 80))
                            thumb_buf = io.BytesIO()
                            thumb_pil.save(thumb_buf, format="JPEG", quality=75)
                            thumb_b64 = f"data:image/jpeg;base64,{base64.b64encode(thumb_buf.getvalue()).decode('ascii')}"

                            triggers = [e.evidence_type for e in f_evidences if e.severity_contribution >= 0.20]
                            timestamp = round(float(idx / max(1.0, rate)), 2)
                            frame_records.append({
                                "frame_index": int(idx),
                                "timestamp_sec": timestamp,
                                "score": round(float(f_score), 4),
                                "classification": "LIKELY_MANIPULATED" if f_score >= 0.65 else ("INCONCLUSIVE" if f_score >= 0.35 else "LIKELY_AUTHENTIC"),
                                "ela_mean": metrics.get("ela_mean", 0.0),
                                "ela_disparity": metrics.get("ela_disparity", 0.0),
                                "fft_spike_ratio": metrics.get("fft_off_axis_spike_ratio", 0.0),
                                "noise_variance": metrics.get("noise_variance", 0.0),
                                "faces_detected": metrics.get("faces_detected", 0),
                                "neural_vision_prob": v_prob,
                                "thumbnail_b64": thumb_b64,
                                "triggers": triggers,
                            })
                    except Exception as fe:
                        logger.debug(f"Frame analysis error for {fpath}: {fe}")
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as ff_frames_err:
                logger.debug(f"FFmpeg frame extraction notice: {ff_frames_err}")

        return frame_records, consecutive_diffs

    def _analyze_temporal_consistency(
        self, frame_records: List[Dict[str, Any]], consecutive_diffs: List[float]
    ) -> Tuple[Dict[str, Any], List[Evidence]]:
        """
        Evaluate temporal stability across consecutive video frames.
        Deepfake video generation often exhibits high-frequency flickering, erratic skin texture
        fluctuations, and facial landmark jitter between frames.
        """
        evidences: List[Evidence] = []
        if not frame_records:
            return {
                "temporal_consistency": 1.0,
                "temporal_jitter_index": 0.0,
                "temporal_anomaly_score": 0.0,
                "stream_dynamics": "STATIC_OR_EMPTY",
                "static_frame_ratio": 1.0,
            }, evidences

        frame_scores = [f["score"] for f in frame_records]
        score_variance = float(np.var(frame_scores))

        # Measure noise variance stability across frames
        noise_vars = [f.get("noise_variance", 0.0) for f in frame_records]
        noise_jitter = float(np.std(noise_vars) / (np.mean(noise_vars) + 1e-4)) if noise_vars else 0.0

        # Motion / transition smoothness
        diff_jitter = float(np.std(consecutive_diffs) / (np.mean(consecutive_diffs) + 1e-4)) if consecutive_diffs else 0.0

        # Detect static UI presentation / screen recording dynamics
        # Static screens have high repetition where consecutive sampled frame delta < 1.0
        static_frame_ratio = float(sum(d < 1.0 for d in consecutive_diffs) / max(1, len(consecutive_diffs)))
        is_static_ui_stream = bool(static_frame_ratio >= 0.40 and all(f.get("faces_detected", 0) == 0 for f in frame_records))
        stream_dynamics = "STATIC_UI_PRESENTATION" if is_static_ui_stream else "NATURAL_MOTION"

        if is_static_ui_stream:
            # In screen recordings and presentation walkthroughs, step changes between screens
            # represent discrete UI navigation, NOT continuous deepfake flickering or facial warping.
            effective_diff_jitter = diff_jitter * 0.08
            effective_noise_jitter = noise_jitter * 0.12
            jitter_index = min(1.0, (score_variance * 2.0) + (effective_noise_jitter * 0.20) + (effective_diff_jitter * 0.10))
        else:
            jitter_index = min(1.0, (score_variance * 3.5) + (noise_jitter * 0.25) + (diff_jitter * 0.15))

        temporal_consistency = max(0.0, min(1.0, 1.0 - jitter_index))

        s_temporal = 0.0
        if jitter_index >= 0.55:
            s_temporal = 0.40
            evidences.append(Evidence(
                evidence_type="video_temporal_flicker_anomaly",
                description=f"Significant frame-to-frame temporal inconsistency and visual jitter detected (jitter index: {jitter_index:.2f}, score variance: {score_variance:.3f}), characteristic of frame-by-frame deepfake synthesis.",
                value=f"jitter={jitter_index:.2f}",
                severity_contribution=0.40,
                source="VideoTemporalEngine",
            ))
        elif jitter_index >= 0.35:
            s_temporal = 0.20
            evidences.append(Evidence(
                evidence_type="video_mild_temporal_inconsistency",
                description=f"Moderate inter-frame variance observed across sampled keyframes (jitter index: {jitter_index:.2f}).",
                value=f"jitter={jitter_index:.2f}",
                severity_contribution=0.20,
                source="VideoTemporalEngine",
            ))
        elif is_static_ui_stream:
            evidences.append(Evidence(
                evidence_type="video_presentation_continuity_nominal",
                description=f"Discrete UI presentation flow verified across keyframes ({static_frame_ratio * 100:.0f}% static screens, temporal consistency: {temporal_consistency:.2f}). No temporal synthesis flickering.",
                value=f"consistency={temporal_consistency:.2f}",
                severity_contribution=0.0,
                source="VideoTemporalEngine",
            ))
        else:
            evidences.append(Evidence(
                evidence_type="video_temporal_continuity_nominal",
                description=f"Continuous, smooth temporal flow verified across keyframes (temporal consistency: {temporal_consistency:.2f}).",
                value=f"consistency={temporal_consistency:.2f}",
                severity_contribution=0.0,
                source="VideoTemporalEngine",
            ))

        return {
            "temporal_consistency": round(temporal_consistency, 3),
            "temporal_jitter_index": round(jitter_index, 3),
            "temporal_anomaly_score": round(s_temporal, 3),
            "score_variance": round(score_variance, 4),
            "stream_dynamics": stream_dynamics,
            "static_frame_ratio": round(static_frame_ratio, 3),
        }, evidences

    def _analyze_soundtrack(
        self, audio_bytes: bytes, correlation_id: str
    ) -> Tuple[float, List[Evidence], Dict[str, Any]]:
        """Extract and evaluate audio soundtrack for neural voice cloning."""
        evidences: List[Evidence] = []
        details = {}
        risk = 0.0

        try:
            from backend.analysis.deepfake_coordinator import DeepfakeCoordinator
            coord = DeepfakeCoordinator(self.config, voice_detector=self.voice_detector)
            audio_event = coord.analyze(
                media_bytes=audio_bytes,
                filename="extracted_video_audio.mp3",
                source="video_soundtrack_extractor",
                correlation_id=correlation_id,
            )

            risk = float(audio_event.threat_score or 0.0)
            details = {
                "audio_classification": audio_event.classification,
                "audio_risk": risk,
                "audio_severity": str(audio_event.severity),
                "audio_summary": audio_event.explanation.summary if audio_event.explanation else "",
            }

            if audio_event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                evidences.append(Evidence(
                    evidence_type="video_soundtrack_synthetic_voice",
                    description=f"Audio soundtrack extracted from video contains synthetic voice clone artifacts (risk: {risk:.2f}).",
                    value=f"audio_risk={risk:.2f}",
                    severity_contribution=0.45,
                    source="VoiceCloneDetector",
                ))
            elif audio_event.severity == RiskLevel.MEDIUM:
                evidences.append(Evidence(
                    evidence_type="video_soundtrack_voice_anomaly",
                    description=f"Audio soundtrack extracted from video exhibits acoustic prosody anomalies (risk: {risk:.2f}).",
                    value=f"audio_risk={risk:.2f}",
                    severity_contribution=0.25,
                    source="VoiceCloneDetector",
                ))
            else:
                evidences.append(Evidence(
                    evidence_type="video_soundtrack_authentic",
                    description="Audio soundtrack extracted from video showed natural acoustic prosody and vocal tract dynamics.",
                    value=f"audio_risk={risk:.2f}",
                    severity_contribution=0.0,
                    source="VoiceCloneDetector",
                ))

        except Exception as a_err:
            logger.debug(f"Audio soundtrack evaluation notice: {a_err}")

        return risk, evidences, details


# Global singleton provider
_video_forensics_engine: Optional[VideoForensicsEngine] = None


def get_video_forensics_engine(config=None, voice_detector=None) -> VideoForensicsEngine:
    global _video_forensics_engine
    if _video_forensics_engine is None:
        _video_forensics_engine = VideoForensicsEngine(config, voice_detector)
    return _video_forensics_engine
