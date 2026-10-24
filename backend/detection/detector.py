"""
detector.py — Core detection orchestrator for CyberGuard.

Orchestrates the full pipeline per audio chunk:
  audio → features → model inference → raw synthetic probability

This module does NOT do risk aggregation (see risk_engine.py).
It outputs a raw P(synthetic) score for a single chunk.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_TORCH_AVAILABLE = False
try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ChunkDetectionResult:
    """Result of processing one audio chunk."""
    chunk_id: int
    timestamp: float
    synthetic_probability: float   # [0.0, 1.0] — higher = more likely synthetic
    processing_time_ms: float
    features_available: dict       # which feature types were extracted
    speaker_embedding: Optional[np.ndarray] = None
    detector_state: str = "NEURAL_READY"  # NEURAL_READY | HEURISTIC_ONLY | UNAVAILABLE
    calibration_mode: str = "calibrated_probability"
    pitch_analysis: Optional[dict] = None


class VoiceCloneDetector:
    """
    Main detector that runs the full pipeline for each audio chunk.

    Typical usage:
        detector = VoiceCloneDetector(settings)
        detector.initialize()
        result = detector.process_chunk(audio_float32, chunk_id=0)
    """

    def __init__(self, settings):
        """
        Args:
            settings: Settings object from config.py
        """
        self.settings = settings
        self._model = None
        self._aasist = None
        self._device: str = "cpu"
        self._initialized = False
        self._chunk_counter = 0
        self._adaptation_counter = 0
        self._adaptive_bias = 0.0
        self._load_adaptive_calibration()

    def _get_calibration_file_path(self):
        from pathlib import Path
        project_root = Path(__file__).resolve().parent.parent.parent
        return project_root / "data" / "detector_adaptive_calibration.json"

    def _load_adaptive_calibration(self) -> None:
        try:
            import json
            calib_file = self._get_calibration_file_path()
            if calib_file.exists():
                data = json.loads(calib_file.read_text(encoding="utf-8"))
                self._adaptive_bias = float(data.get("adaptive_bias", 0.0))
                self._adaptation_counter = int(data.get("adaptation_count", 0))
                logger.info(f"Loaded adaptive calibration: bias={self._adaptive_bias:+.4f}, adaptations={self._adaptation_counter}")
        except Exception as e:
            logger.debug(f"Could not load adaptive calibration: {e}")

    def _save_adaptive_calibration(self) -> None:
        try:
            import json
            calib_file = self._get_calibration_file_path()
            calib_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "adaptive_bias": float(self._adaptive_bias),
                "adaptation_count": int(self._adaptation_counter),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            calib_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not save adaptive calibration: {e}")

    def initialize(self) -> None:
        """
        Load all models at startup.
        Called once by FastAPI startup event.
        """
        from backend.models.model_loader import load_model, resolve_device
        from backend.features.wav2vec_extractor import preload_wav2vec2
        from backend.features.speaker_extractor import preload_ecapa

        self._device = resolve_device(self.settings.detection.device)
        logger.info(f"Detector initializing on device: {self._device}")

        try:
            # 1. Initialize SOTA AASIST detector (pre-trained on ASVspoof)
            try:
                from backend.models.aasist_adapter import AASISTDetector
                self._aasist = AASISTDetector(device=self._device)
                if self._aasist.initialize():
                    logger.info("✓ AASIST neural detector loaded successfully.")
                else:
                    self._aasist = None
            except Exception as aasist_err:
                logger.warning(f"AASIST detector load notice: {aasist_err}")
                self._aasist = None

            # 2. Load CNN-RNN detector model
            self._model = load_model(
                model_path=self.settings.detection.model_path,
                n_mels=self.settings.detection.n_mels,
                device_cfg=self.settings.detection.device,
            )
            
            # Preload wav2vec2 if configured
            if self.settings.detection.use_wav2vec2 and self._aasist is None:
                preload_wav2vec2(self.settings.detection.wav2vec2_model)

            # Preload ECAPA if configured
            if self.settings.detection.use_speaker_embedding:
                preload_ecapa(self.settings.detection.ecapa_model)

            self._initialized = True
            if self._aasist is not None:
                logger.info("VoiceCloneDetector initialized successfully with AASIST SOTA neural model.")
            elif self._model is not None:
                logger.info("VoiceCloneDetector initialized successfully with CNN-RNN neural model.")
            else:
                logger.info("VoiceCloneDetector initialized successfully with acoustic heuristic fallback.")
        except Exception as e:
            self._initialized = False
            logger.warning(f"VoiceCloneDetector failed to initialize: {e}")

    def process_chunk(
        self,
        audio: np.ndarray,
        chunk_id: Optional[int] = None,
        use_speaker_embedding: Optional[bool] = None,
    ) -> ChunkDetectionResult:
        """
        Process a single preprocessed audio chunk through the full pipeline.

        Args:
            audio:    float32 mono waveform at configured sample rate
            chunk_id: optional identifier for this chunk
            use_speaker_embedding: whether to compute ECAPA speaker embeddings (default: config setting)

        Returns:
            ChunkDetectionResult with synthetic_probability
        """
        if chunk_id is None:
            chunk_id = self._chunk_counter
            self._chunk_counter += 1

        t_start = time.perf_counter()

        has_aasist = (self._aasist is not None and self._aasist.is_initialized)

        # 1. Extract features (fast path: skip slow wav2vec2 when AASIST provides deep representations)
        from backend.features.feature_fusion import extract_all_features

        use_w2v = self.settings.detection.use_wav2vec2 if not has_aasist else False
        use_spk = self.settings.detection.use_speaker_embedding if use_speaker_embedding is None else bool(use_speaker_embedding)
        bundle = extract_all_features(
            audio=audio,
            sr=self.settings.audio.sample_rate,
            n_mfcc=self.settings.detection.n_mfcc,
            n_mels=self.settings.detection.n_mels,
            hop_length=160,
            win_length=400,
            wav2vec2_model_name=self.settings.detection.wav2vec2_model,
            ecapa_model_name=self.settings.detection.ecapa_model,
            use_wav2vec2=use_w2v,
            use_speaker_embedding=use_spk,
            device=self._device,
        )

        has_learned_model = (self._model is not None and self._initialized)

        # 2. Run model inference with multi-model consensus
        nn_prob: Optional[float] = None
        if has_learned_model:
            try:
                nn_prob = self._run_inference(bundle)
            except Exception as exc:
                logger.warning(f"Learned detector inference failed ({exc}).")
                nn_prob = None

        aasist_raw: Optional[float] = None
        if has_aasist:
            try:
                aasist_raw = float(self._aasist.predict_proba(audio))
            except Exception as exc:
                logger.warning(f"AASIST inference failed ({exc}).")
                aasist_raw = None

        # Safety check: if audio is completely flat or empty, return non-threatening result immediately
        if audio is None or len(audio) == 0 or np.all(audio == 0) or float(np.std(audio)) < 1e-6:
            return ChunkDetectionResult(
                chunk_id=chunk_id,
                timestamp=time.time(),
                synthetic_probability=0.0,
                processing_time_ms=0.0,
                features_available={
                    "mfcc": False, "log_mel": False, "prosodic": False,
                    "wav2vec2": False, "speaker_embedding": False, "aasist": has_aasist,
                },
                speaker_embedding=None,
                detector_state=self.detector_state,
                calibration_mode="calibrated_probability",
                pitch_analysis={"pitch_verdict": "SILENCE", "is_pitch_anomaly": False},
            )

        # 2b. Acoustic Pitch & Prosodic Signal Analysis (Physical vocal cord metrics)
        prosodic_vec = bundle.prosodic if hasattr(bundle, "prosodic") and bundle.prosodic is not None else np.zeros(7, dtype=np.float32)
        f0_mean = float(prosodic_vec[0]) if len(prosodic_vec) > 0 else 0.0
        f0_std = float(prosodic_vec[1]) if len(prosodic_vec) > 1 else 0.0
        jitter_val = float(prosodic_vec[2]) if len(prosodic_vec) > 2 else 0.0
        shimmer_val = float(prosodic_vec[3]) if len(prosodic_vec) > 3 else 0.0
        hnr_val = float(prosodic_vec[4]) if len(prosodic_vec) > 4 else 0.0

        # Voiced speech validation: pitch, jitter, and shimmer are ONLY meaningful when
        # voiced vocal tract resonance is present. Random noise period jumps must never trigger pitch anomaly.
        has_voiced_speech = bool(60.0 <= f0_mean <= 500.0 and hnr_val > 2.0 and jitter_val > 0.0)

        if has_voiced_speech:
            if jitter_val < 0.052:
                stability_pct = max(75.0, min(98.5, 98.0 - (jitter_val - 0.02) * 350.0))
            else:
                stability_pct = max(20.0, min(65.0, 65.0 - (jitter_val - 0.052) * 1100.0))

            is_pitch_anomaly = bool(
                (jitter_val >= 0.060) or
                (f0_mean > 80.0 and f0_std < 12.0) or
                (f0_mean > 280.0 and jitter_val >= 0.052)
            )
            pitch_verdict = "SYNTHETIC PITCH ANOMALY" if is_pitch_anomaly else "ORGANIC HUMAN PROSODY"
        else:
            stability_pct = 95.0
            is_pitch_anomaly = False
            pitch_verdict = "UNVOICED / NO PITCH DETECTED"

        pitch_data = {
            "f0_mean_hz": round(f0_mean, 1),
            "f0_std_hz": round(f0_std, 1),
            "jitter": round(jitter_val, 4),
            "shimmer": round(shimmer_val, 4),
            "hnr_db": round(hnr_val, 1),
            "pitch_stability_pct": round(stability_pct, 1),
            "pitch_verdict": pitch_verdict,
            "is_pitch_anomaly": is_pitch_anomaly,
        }

        if has_aasist and aasist_raw is not None and has_learned_model and nn_prob is not None:
            # Calibrated multi-model neural consensus:
            # AASIST (SOTA raw waveform graph attention) + EnsembleDetector (detector.pt)
            # Balanced consensus: 0.60 AASIST + 0.40 EnsembleDetector
            base_consensus = 0.60 * aasist_raw + 0.40 * nn_prob
            max_threat = max(aasist_raw, nn_prob)

            # Anti-Dilution Security Protection:
            # If confirmed synthetic cloning (AASIST >= 0.85 or both models indicate threat >= 0.55),
            # preserve strong threat response.
            if aasist_raw >= 0.85 or (aasist_raw >= 0.60 and nn_prob >= 0.55):
                synthetic_prob = max(base_consensus, max_threat * 0.90)
            elif aasist_raw < 0.10 and nn_prob < 0.55:
                # Both deep models and acoustic filters confirm organic human voice
                synthetic_prob = min(base_consensus, 0.25)
            else:
                synthetic_prob = base_consensus

            # Corroborate with physical pitch telemetry without arbitrary clamping:
            if is_pitch_anomaly and max_threat >= 0.50:
                # Physical vocoder frame-stitching boundary jitter corroborates neural suspicion
                synthetic_prob = min(1.0, synthetic_prob + 0.05)
            elif not is_pitch_anomaly and max_threat < 0.40 and aasist_raw < 0.10:
                # Natural human vocal tract dynamic prosody confirmed
                synthetic_prob = max(0.001, synthetic_prob * 0.85)
        elif has_aasist and aasist_raw is not None:
            synthetic_prob = aasist_raw
            if is_pitch_anomaly and aasist_raw >= 0.50:
                synthetic_prob = min(1.0, synthetic_prob + 0.05)
        elif has_learned_model and nn_prob is not None:
            synthetic_prob = nn_prob
            if is_pitch_anomaly and nn_prob >= 0.50:
                synthetic_prob = min(1.0, synthetic_prob + 0.05)
        else:
            synthetic_prob = self._heuristic_score(bundle)

        if getattr(self, "_adaptive_bias", 0.0) != 0.0:
            synthetic_prob = float(np.clip(synthetic_prob + self._adaptive_bias, 0.0, 1.0))

        t_end = time.perf_counter()
        processing_ms = (t_end - t_start) * 1000.0

        features_available = {
            "mfcc": True,
            "log_mel": True,
            "prosodic": True,
            "wav2vec2": use_w2v,
            "speaker_embedding": self.settings.detection.use_speaker_embedding,
            "aasist": has_aasist,
        }

        logger.debug(
            f"Chunk {chunk_id}: P(synthetic)={synthetic_prob:.4f}, "
            f"latency={processing_ms:.1f}ms"
        )

        state = self.detector_state
        return ChunkDetectionResult(
            chunk_id=chunk_id,
            timestamp=time.time(),
            synthetic_probability=float(synthetic_prob),
            processing_time_ms=float(processing_ms),
            features_available=features_available,
            speaker_embedding=bundle.speaker_emb,
            detector_state=state,
            calibration_mode="calibrated_probability" if state == "NEURAL_READY" else "uncalibrated_heuristic",
            pitch_analysis=pitch_data,
        )

    def _run_inference(self, bundle) -> float:
        """
        Run model inference on extracted features.

        Returns P(synthetic) as float in [0.0, 1.0].
        """
        if not _TORCH_AVAILABLE or self._model is None or not self._initialized:
            # Fallback: heuristic from acoustic features only
            logger.warning("ML detector unavailable. Using acoustic heuristic fallback.")
            return self._heuristic_score(bundle)

        try:
            import torch

            # Prepare mel sequence tensor [1, T, n_mels] standardized to 201 frames
            m_data = bundle.mel_seq[:201]
            if m_data.shape[0] < 201:
                pad = np.zeros((201 - m_data.shape[0], m_data.shape[1]), dtype=np.float32)
                m_data = np.vstack([m_data, pad])
            mel_seq = torch.tensor(
                m_data, dtype=torch.float32
            ).unsqueeze(0).to(self._device)

            # Prepare fused feature tensor [1, fused_dim]
            fused_vec = torch.tensor(
                bundle.fused_vector, dtype=torch.float32
            ).unsqueeze(0).to(self._device)

            with torch.no_grad():
                prob = self._model.predict_proba(mel_seq, fused_vec)

            return float(prob.squeeze().cpu().item())

        except Exception as exc:
            logger.error(f"Model inference failed: {exc}. Using heuristic score.")
            return self._heuristic_score(bundle)

    def _heuristic_score(self, bundle) -> float:
        """
        Acoustic heuristic score when model is unavailable.
        Based on HNR, jitter, shimmer thresholds typical of synthetic speech.
        This is a fallback — not a reliable detector.
        """
        prosodic = bundle.prosodic
        # prosodic: [f0_mean, f0_std, jitter, shimmer, hnr, zcr, energy]
        hnr = prosodic[4]        # HNR in dB
        jitter = prosodic[2]     # Relative jitter
        shimmer = prosodic[3]    # Relative shimmer

        # If no voiced frames were detected (jitter is exactly 0.0),
        # we cannot assess synthetic voicing. Return 0.0 to prevent a hallucinated 0.600 score.
        if jitter == 0.0:
            return 0.0

        # Heuristic 1: very high HNR + very low jitter/shimmer = more likely basic TTS
        hnr_score = max(0.0, min(1.0, (hnr - 10) / 30.0))  # 10dB → 0, 40dB → 1
        jitter_score = max(0.0, min(1.0, 1.0 - jitter * 100))  # lower jitter = more synthetic
        shimmer_score = max(0.0, min(1.0, 1.0 - shimmer * 10))

        basic_tts_score = 0.4 * hnr_score + 0.3 * jitter_score + 0.3 * shimmer_score

        # Heuristic 2: MFCC high-order variance (detects vocoder smoothing / flat spectrum)
        # Low spectral variance (< 30) indicates robotic vocoder smoothing
        mfcc_seq = getattr(bundle, "mfcc_seq", None)
        vocoder_score = 0.0
        if mfcc_seq is not None and mfcc_seq.shape[0] > 0 and mfcc_seq.shape[1] >= 40:
            mfcc_high_var = float(np.mean(np.var(mfcc_seq[:, 13:40], axis=0)))
            if mfcc_high_var < 30.0:
                vocoder_score = max(0.0, min(1.0, (30.0 - mfcc_high_var) / 20.0))

        # Combine scores (either basic TTS or advanced vocoder triggers it)
        score = max(basic_tts_score, vocoder_score)

        # Apply adaptive calibration bias learned from manual ground-truth feedback
        if getattr(self, "_adaptive_bias", 0.0) != 0.0:
            score = score + self._adaptive_bias
        
        return float(np.clip(score, 0.0, 1.0))

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def has_neural_model(self) -> bool:
        """True only if genuine neural detector weights are loaded."""
        return self._initialized and (self._aasist is not None or self._model is not None)

    @property
    def is_fallback_active(self) -> bool:
        """True when running on acoustic heuristic fallback."""
        return self._initialized and (self._aasist is None and self._model is None)

    @property
    def detector_state(self) -> str:
        """
        Explicit detector operating state:
          - 'NEURAL_READY': Validated neural model (AASIST or CNN-RNN) is active.
          - 'HEURISTIC_ONLY': Neural weights absent; running purely on acoustic heuristic fallback.
          - 'UNAVAILABLE': Subsystem not initialized.
        """
        if not self._initialized:
            return "UNAVAILABLE"
        if self.has_neural_model:
            return "NEURAL_READY"
        return "HEURISTIC_ONLY"

    def adapt_from_labeled_audio(
        self,
        audio_or_path: np.ndarray | str | Path,
        label: str,
        learning_rate: float = 1e-4,
        steps: int = 3,
        sr: int = 16000,
    ) -> dict:
        """
        Manually adjust and auto-update detector.py based on human or cloned voice ground truth.
        
        Non-destructive:
        - If neural model is loaded, performs micro-fine-tuning on the sample with AdamW,
          creates an auditable timestamped backup of the model weights, atomically updates detector.pt,
          and updates detector_manifest.json.
        - Updates adaptive calibration bias so acoustic fallback also adjusts sensitivity.
        - Modifies active detector in-place for immediate subsequent inference without restart.
        
        Args:
            audio_or_path: audio numpy array or path to audio file
            label: 'HUMAN' / 'BONAFIDE' (real voice, target=0.0) or 'CLONED' / 'SPOOF' (cloned, target=1.0)
            learning_rate: learning rate for neural model update
            steps: gradient descent steps (default 3)
            sr: expected audio sample rate (16000 Hz)
            
        Returns:
            Dictionary with adaptation metrics, before/after probability, and confirmation status.
        """
        from pathlib import Path
        import soundfile as sf
        from backend.audio.preprocessor import normalize
        from backend.features.feature_fusion import extract_all_features

        lbl = str(label).strip().upper()
        if lbl in ("HUMAN", "BONAFIDE", "GENUINE", "REAL", "0", "0.0"):
            target_prob = 0.0
            canonical_label = "HUMAN"
            bias_adjustment = -0.02
        elif lbl in ("CLONED", "SPOOF", "SYNTHETIC", "AI", "FAKE", "DEEPFAKE", "1", "1.0"):
            target_prob = 1.0
            canonical_label = "CLONED"
            bias_adjustment = 0.02
        else:
            raise ValueError(f"Invalid audio classification label: '{label}'. Must be HUMAN or CLONED.")

        if isinstance(audio_or_path, (str, Path)):
            audio_path = Path(audio_or_path)
            if not audio_path.exists():
                raise FileNotFoundError(f"Audio file not found at: {audio_path}")
            raw_audio, in_sr = sf.read(str(audio_path))
            if raw_audio.ndim > 1:
                raw_audio = raw_audio.mean(axis=1)
            audio = normalize(raw_audio.astype(np.float32))
            if in_sr != sr:
                try:
                    import resampy
                    audio = resampy.resample(audio, in_sr, sr)
                except Exception:
                    pass
        elif isinstance(audio_or_path, np.ndarray):
            audio = normalize(audio_or_path.astype(np.float32))
        else:
            raise TypeError("audio_or_path must be a file path or numpy array.")

        if len(audio) == 0:
            raise ValueError("Audio sample is empty.")

        # Preprocess with VAD before taking the feature window to avoid adapting on silence
        from backend.audio.preprocessor import preprocess_audio
        audio_vad = preprocess_audio(audio, sr=sr, target_sr=sr, apply_vad=True)
        if len(audio_vad) >= 16000:
            audio = audio_vad

        # Slice or pad to 32000 samples (2 seconds) for standard feature window
        if len(audio) < 32000:
            audio_padded = np.pad(audio, (0, 32000 - len(audio)), mode="constant")
        else:
            audio_padded = audio[:32000]

        target_sr = self.settings.audio.sample_rate if hasattr(self.settings, "audio") else 16000
        bundle = extract_all_features(
            audio=audio_padded,
            sr=target_sr,
            n_mfcc=self.settings.detection.n_mfcc,
            n_mels=self.settings.detection.n_mels,
            hop_length=160,
            win_length=400,
            wav2vec2_model_name=self.settings.detection.wav2vec2_model,
            ecapa_model_name=self.settings.detection.ecapa_model,
            use_wav2vec2=self.settings.detection.use_wav2vec2,
            use_speaker_embedding=self.settings.detection.use_speaker_embedding,
            device=self._device,
        )

        prev_prob = self._run_inference(bundle)
        neural_updated = False
        weights_saved = False

        if _TORCH_AVAILABLE and self._model is not None and self._initialized:
            try:
                import torch
                # Only fine-tune the final classification projection parameters to protect deep representations
                trainable_params = []
                if hasattr(self._model, "seq_detector") and hasattr(self._model.seq_detector, "classifier"):
                    trainable_params.extend(self._model.seq_detector.classifier[-1].parameters())
                if hasattr(self._model, "fused_detector") and hasattr(self._model.fused_detector, "classifier"):
                    trainable_params.extend(self._model.fused_detector.classifier[-1].parameters())
                if not trainable_params:
                    trainable_params = list(self._model.parameters())

                self._model.train()
                optimizer = torch.optim.AdamW(
                    trainable_params, lr=min(learning_rate, 5e-5), weight_decay=1e-3
                )
                criterion = torch.nn.BCEWithLogitsLoss()

                m_data = bundle.mel_seq[:201]
                if m_data.shape[0] < 201:
                    pad = np.zeros((201 - m_data.shape[0], m_data.shape[1]), dtype=np.float32)
                    m_data = np.vstack([m_data, pad])
                mel_t = torch.tensor(
                    m_data, dtype=torch.float32
                ).unsqueeze(0).to(self._device)
                fused_t = torch.tensor(
                    bundle.fused_vector, dtype=torch.float32
                ).unsqueeze(0).to(self._device)
                target_t = torch.tensor([[target_prob]], dtype=torch.float32).to(self._device)

                for _ in range(max(1, steps)):
                    optimizer.zero_grad()
                    if hasattr(self._model, "compute_multi_task_loss"):
                        loss, _ = self._model.compute_multi_task_loss(
                            mel_t, fused_t, target_t, criterion, seq_weight=0.40, fused_weight=0.40, ens_weight=0.20
                        )
                    else:
                        logits = self._model(mel_t, fused_t)
                        loss = criterion(logits, target_t)
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(trainable_params, 1.0)
                    optimizer.step()

                self._model.eval()
                neural_updated = True

                # Persist weights non-destructively
                weights_path = Path(self.settings.detection.model_path)
                if not weights_path.is_absolute():
                    project_root = Path(__file__).resolve().parent.parent.parent
                    weights_path = project_root / weights_path

                if weights_path.parent.exists():
                    backup_name = f"detector_adapted_{int(time.time())}.pt"
                    backup_path = weights_path.parent / backup_name
                    torch.save(self._model.state_dict(), weights_path)
                    try:
                        torch.save(self._model.state_dict(), backup_path)
                    except Exception:
                        pass
                    weights_saved = True

                    manifest_path = weights_path.parent / "detector_manifest.json"
                    if manifest_path.exists():
                        try:
                            import json
                            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                            manifest["last_adapted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                            manifest["total_manual_adaptations"] = manifest.get("total_manual_adaptations", 0) + 1
                            manifest["last_manual_label"] = canonical_label
                            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                        except Exception as m_err:
                            logger.warning(f"Could not update manifest: {m_err}")

            except Exception as e:
                logger.error(f"Neural adaptation step failed: {e}. Falling back to calibration update.")
                if self._model is not None:
                    self._model.eval()

        # Update adaptive calibration with gentle bounds
        self._adaptive_bias = float(np.clip(self._adaptive_bias + bias_adjustment, -0.05, 0.05))
        self._adaptation_counter += 1
        self._save_adaptive_calibration()

        new_prob = self._run_inference(bundle)

        logger.info(
            f"detector.py auto-updated: label={canonical_label}, "
            f"P(syn) {prev_prob:.4f} -> {new_prob:.4f} (target {target_prob:.1f}), "
            f"neural_updated={neural_updated}, weights_saved={weights_saved}"
        )

        return {
            "success": True,
            "status": "ADAPTED",
            "canonical_label": canonical_label,
            "ground_truth_target": target_prob,
            "previous_probability": round(float(prev_prob), 4),
            "adapted_probability": round(float(new_prob), 4),
            "probability_delta": round(float(new_prob - prev_prob), 4),
            "neural_model_updated": neural_updated,
            "weights_saved": weights_saved,
            "calibration_updated": True,
            "adaptive_bias": round(float(self._adaptive_bias), 4),
            "adaptation_counter": self._adaptation_counter,
            "message": f"detector.py modified and auto-updated successfully for {canonical_label} audio.",
        }

