"""
aasist_adapter.py — SOTA Spectro-Temporal Graph Attention Network (AASIST) Adapter.

Wraps the official Clova AI AASIST architecture and pre-trained weights into
CyberGuard's detection interface.

Architecture:
  - SincNet front-end (70 filters)
  - Residual CNN blocks
  - Heterogeneous Spectro-Temporal Graph Attention (HtrgGAT)
  - Graph pooling + Max/Avg readouts
  - 297,866 parameters

Input Contract:
  - Raw audio waveform: 16 kHz mono float32
  - Auto-padded / tiled to 64,600 samples (4.0s) as expected by AASIST

Output Contract:
  - P(synthetic) in [0.0, 1.0] via softmax over 2-class logits (index 0 = spoof, index 1 = bonafide)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Union

import numpy as np
import torch

from backend.models.aasist import Model

logger = logging.getLogger(__name__)

AASIST_CONFIG = {
    "architecture": "AASIST",
    "nb_samp": 64600,
    "first_conv": 128,
    "filts": [70, [1, 32], [32, 32], [32, 64], [64, 64]],
    "gat_dims": [64, 32],
    "pool_ratios": [0.5, 0.7, 0.5, 0.5],
    "temperatures": [2.0, 2.0, 100.0, 100.0],
}


class AASISTDetector:
    """
    Adapter integrating AASIST into CyberGuard.
    """

    def __init__(
        self,
        weights_path: Optional[Union[str, Path]] = None,
        device: str = "cpu",
    ):
        if weights_path is None:
            models_dir = Path(__file__).resolve().parent
            weights_path = models_dir / "weights" / "aasist" / "AASIST.pth"

        self.weights_path = Path(weights_path)
        self.device = torch.device(device if torch.cuda.is_available() and device == "cuda" else "cpu")
        self._model: Optional[Model] = None
        self._initialized = False

    def initialize(self) -> bool:
        """Load AASIST model weights safely."""
        if not self.weights_path.exists():
            logger.warning(f"AASIST checkpoint not found at {self.weights_path}")
            self._initialized = False
            return False

        try:
            model = Model(AASIST_CONFIG)
            state_dict = torch.load(self.weights_path, map_location=self.device, weights_only=True)
            model.load_state_dict(state_dict)
            model.to(self.device)
            model.eval()
            self._model = model
            self._initialized = True
            logger.info(f"✓ AASIST model successfully loaded from {self.weights_path} ({sum(p.numel() for p in model.parameters()):,} params)")
            return True
        except Exception as exc:
            logger.error(f"Failed to load AASIST model: {exc}")
            self._initialized = False
            return False

    def predict_proba(self, audio: np.ndarray) -> float:
        """
        Process raw 16 kHz audio chunk and return P(synthetic) in [0.0, 1.0].
        """
        if not self._initialized or self._model is None:
            raise RuntimeError("AASISTDetector is not initialized.")

        # Ensure 1D float32
        audio = np.asarray(audio, dtype=np.float32).flatten()

        # AASIST expects 64,600 samples (approx 4.0s @ 16kHz)
        target_len = AASIST_CONFIG["nb_samp"]
        if len(audio) < target_len:
            # Tile or pad to target length
            repeats = int(np.ceil(target_len / max(1, len(audio))))
            audio_tiled = np.tile(audio, repeats)[:target_len]
        elif len(audio) > target_len:
            start = (len(audio) - target_len) // 2
            audio_tiled = audio[start : start + target_len]
        else:
            audio_tiled = audio

        tensor = torch.tensor(audio_tiled, dtype=torch.float32, device=self.device).unsqueeze(0)  # [1, 64600]

        with torch.no_grad():
            _, output = self._model(tensor)
            # output: [1, 2] -> index 0 is spoof, index 1 is bonafide
            probs = torch.softmax(output, dim=-1)
            # P(synthetic) is probability of spoof
            spoof_prob = float(probs[0, 0].cpu().item())

        return float(np.clip(spoof_prob, 0.0, 1.0))

    @property
    def is_initialized(self) -> bool:
        return self._initialized
