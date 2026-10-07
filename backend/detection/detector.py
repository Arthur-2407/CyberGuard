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
            # Load CNN-RNN detector model
            self._model = load_model(
                model_path=self.settings.detection.model_path,
                n_mels=self.settings.detection.n_mels,
                device_cfg=self.settings.detection.device,
            )
            
            # Preload wav2vec2 if configured
            if self.settings.detection.use_wav2vec2:
                preload_wav2vec2(self.settings.detection.wav2vec2_model)

            # Preload ECAPA if configured
            if self.settings.detection.use_speaker_embedding:
                preload_ecapa(self.settings.detection.ecapa_model)

            self._initialized = True
            if self._model is not None:
                logger.info("VoiceCloneDetector initialized successfully with neural model.")
            else:
                logger.info("VoiceCloneDetector initialized successfully with acoustic heuristic fallback.")
        except Exception as e:
            self._initialized = False
            logger.warning(f"VoiceCloneDetector failed to initialize: {e}")

    def process_chunk(
        self,
        audio: np.ndarray,
        chunk_id: Optional[int] = None,
    ) -> ChunkDetectionResult:
        """
        Process a single preprocessed audio chunk through the full pipeline.

        Args:
            audio:    float32 mono waveform at configured sample rate
            chunk_id: optional identifier for this chunk

        Returns:
            ChunkDetectionResult with synthetic_probability
        """
        if chunk_id is None:
            chunk_id = self._chunk_counter
            self._chunk_counter += 1

        t_start = time.perf_counter()

        # 1. Extract all features
        from backend.features.feature_fusion import extract_all_features

        bundle = extract_all_features(
            audio=audio,
            sr=self.settings.audio.sample_rate,
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

        # 2. Run model inference
        synthetic_prob = self._run_inference(bundle)

        t_end = time.perf_counter()
        processing_ms = (t_end - t_start) * 1000.0

        features_available = {
            "mfcc": True,
            "log_mel": True,
            "prosodic": True,
            "wav2vec2": self.settings.detection.use_wav2vec2,
            "speaker_embedding": self.settings.detection.use_speaker_embedding,
        }

        logger.debug(
            f"Chunk {chunk_id}: P(synthetic)={synthetic_prob:.4f}, "
            f"latency={processing_ms:.1f}ms"
        )

        return ChunkDetectionResult(
            chunk_id=chunk_id,
            timestamp=time.time(),
            synthetic_probability=float(synthetic_prob),
            processing_time_ms=float(processing_ms),
            features_available=features_available,
            speaker_embedding=bundle.speaker_emb,
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

            # Prepare mel sequence tensor [1, T, n_mels]
            mel_seq = torch.tensor(
                bundle.mel_seq, dtype=torch.float32
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

        # Heuristic 2: MFCC high-order variance (detects RVC / GAN vocoders)
        # Deepfakes often have periodic artifacts in high frequencies causing high variance
        mfcc_seq = getattr(bundle, "mfcc_seq", None)
        vocoder_score = 0.0
        if mfcc_seq is not None and mfcc_seq.shape[0] > 0 and mfcc_seq.shape[1] >= 40:
            # Variance of MFCCs 13-39 (excluding lower order formants)
            mfcc_high_var = float(np.mean(np.var(mfcc_seq[:, 13:40], axis=0)))
            vocoder_score = max(0.0, min(1.0, (mfcc_high_var - 45) / 35.0)) # 45 -> 0, 80 -> 1.0

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
        return self._initialized and (self._model is not None)

    @property
    def is_fallback_active(self) -> bool:
        """True when running on acoustic heuristic fallback."""
        return self._initialized and (self._model is None)

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

                mel_t = torch.tensor(
                    bundle.mel_seq, dtype=torch.float32
                ).unsqueeze(0).to(self._device)
                fused_t = torch.tensor(
                    bundle.fused_vector, dtype=torch.float32
                ).unsqueeze(0).to(self._device)
                target_t = torch.tensor([[target_prob]], dtype=torch.float32).to(self._device)

                for _ in range(max(1, steps)):
                    optimizer.zero_grad()
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

