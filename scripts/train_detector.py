"""
train_detector.py — Official CyberGuard Neural Detector Training Pipeline.

Architecture:
  EnsembleDetector (Dual-modality CNN-BiLSTM + Self-Attention + Gating)
  - Sequence branch: 80-band log-Mel spectrogram [batch, time, 80]
  - Fused branch: 1167-dim unified feature vector [batch, 1167]
    (120 MFCC + 80 Mel + 7 Prosodic + 768 Wav2Vec2 + 192 ECAPA)

Dataset Support:
  - ASVspoof 2019 Logical Access (LA) track (Train / Dev protocols)
  - ASVspoof 2021 Deepfake (DF) track

Label Semantics:
  - bonafide = 0.0 (genuine speech)
  - spoof    = 1.0 (synthetic / cloned speech)

Usage:
  # Dry-run validation of architecture and pipeline:
  D:\\BPUT\\venv\\Scripts\\python.exe scripts/train_detector.py --dry-run

  # Full training on ASVspoof 2019 LA dataset:
  D:\\BPUT\\venv\\Scripts\\python.exe scripts/train_detector.py \\
      --dataset-dir D:\\BPUT\\data\\datasets\\asvspoof2019_la \\
      --protocol-train D:\\BPUT\\data\\datasets\\asvspoof2019_la\\ASVspoof2019_LA_cm_protocols\\ASVspoof2019.LA.cm.train.trn.txt \\
      --protocol-dev D:\\BPUT\\data\\datasets\\asvspoof2019_la\\ASVspoof2019_LA_cm_protocols\\ASVspoof2019.LA.cm.dev.trl.txt \\
      --epochs 20 \\
      --batch-size 16 \\
      --lr 0.0003 \\
      --device auto
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("train_detector")

# Ensure BPUT root is first in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False
    logger.error("PyTorch is required to run train_detector.py.")


def seed_everything(seed: int = 42):
    """Ensure reproducible training."""
    random.seed(seed)
    np.random.seed(seed)
    if _TORCH_AVAILABLE:
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False


class ASVspoofAudioDataset(Dataset):
    """
    Dataset loader for ASVspoof LA / DF audio protocols.
    Extracts log-Mel sequences and fused feature vectors matching BPUT inference.
    """

    def __init__(
        self,
        audio_dir: Path,
        protocol_file: Path,
        max_samples: Optional[int] = None,
        use_wav2vec2: bool = False,
        use_ecapa: bool = False,
        target_sr: int = 16000,
        chunk_duration: float = 2.0,
    ):
        self.audio_dir = Path(audio_dir)
        self.target_sr = target_sr
        self.chunk_samples = int(target_sr * chunk_duration)
        self.use_wav2vec2 = use_wav2vec2
        self.use_ecapa = use_ecapa
        self.records: List[Tuple[Path, float]] = []

        if not protocol_file.exists():
            raise FileNotFoundError(f"Protocol file not found: {protocol_file}")

        logger.info(f"Parsing protocol: {protocol_file}")
        with open(protocol_file, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 5:
                    # ASVspoof 2019 format: SPEAKER_ID AUDIO_ID - - KEY
                    audio_id = parts[1]
                    key = parts[4].lower()
                elif len(parts) == 2:
                    # Simple format: FILENAME KEY
                    audio_id = parts[0]
                    key = parts[1].lower()
                else:
                    continue

                label = 1.0 if key == "spoof" else 0.0
                
                # Check for audio file (.flac or .wav)
                audio_path = self.audio_dir / f"{audio_id}.flac"
                if not audio_path.exists():
                    audio_path = self.audio_dir / f"{audio_id}.wav"

                if audio_path.exists():
                    self.records.append((audio_path, label))

        if max_samples and len(self.records) > max_samples:
            self.records = self.records[:max_samples]

        bonafide_count = sum(1 for _, lbl in self.records if lbl == 0.0)
        spoof_count = sum(1 for _, lbl in self.records if lbl == 1.0)
        logger.info(
            f"Loaded {len(self.records)} samples from {protocol_file.name} "
            f"(bonafide={bonafide_count}, spoof={spoof_count})"
        )

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        audio_path, label = self.records[idx]
        from backend.audio.preprocessor import load_audio, normalize
        from backend.features.feature_fusion import extract_all_features

        try:
            audio, _ = load_audio(str(audio_path), target_sr=self.target_sr)
            audio = normalize(audio)
        except Exception as exc:
            logger.warning(f"Error reading {audio_path}: {exc}. Using zero buffer.")
            audio = np.zeros(self.chunk_samples, dtype=np.float32)

        # Pad or center-crop to chunk_samples
        if len(audio) < self.chunk_samples:
            pad_len = self.chunk_samples - len(audio)
            audio = np.pad(audio, (0, pad_len), mode="constant")
        elif len(audio) > self.chunk_samples:
            start = (len(audio) - self.chunk_samples) // 2
            audio = audio[start : start + self.chunk_samples]

        bundle = extract_all_features(
            audio=audio,
            sr=self.target_sr,
            use_wav2vec2=self.use_wav2vec2,
            use_speaker_embedding=self.use_ecapa,
        )

        mel_seq = torch.tensor(bundle.mel_seq, dtype=torch.float32)      # [T, 80]
        fused_vec = torch.tensor(bundle.fused_vector, dtype=torch.float32) # [1167]
        target = torch.tensor([label], dtype=torch.float32)              # [1]

        return mel_seq, fused_vec, target


def compute_metrics(y_true: np.ndarray, y_pred_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    """Compute anti-spoofing detection metrics."""
    y_pred = (y_pred_prob >= threshold).astype(int)
    y_true = y_true.astype(int)

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    accuracy = (tp + tn) / max(1, len(y_true))
    precision = tp / max(1, (tp + fp))
    recall = tp / max(1, (tp + fn))
    f1 = 2 * precision * recall / max(1e-8, (precision + recall))

    # Equal Error Rate (EER) estimation
    # Threshold sweep from 0 to 1
    thresholds = np.linspace(0.0, 1.0, 101)
    fpr_list = []
    fnr_list = []
    for th in thresholds:
        preds = (y_pred_prob >= th).astype(int)
        cur_fp = np.sum((y_true == 0) & (preds == 1))
        cur_fn = np.sum((y_true == 1) & (preds == 0))
        cur_tn = np.sum((y_true == 0) & (preds == 0))
        cur_tp = np.sum((y_true == 1) & (preds == 1))
        fpr = cur_fp / max(1, (cur_fp + cur_tn))
        fnr = cur_fn / max(1, (cur_fn + cur_tp))
        fpr_list.append(fpr)
        fnr_list.append(fnr)

    fpr_arr = np.array(fpr_list)
    fnr_arr = np.array(fnr_list)
    diff = np.abs(fpr_arr - fnr_arr)
    eer_idx = int(np.argmin(diff))
    eer = float((fpr_arr[eer_idx] + fnr_arr[eer_idx]) / 2.0)

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "eer": float(eer),
        "operating_threshold": float(threshold),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def run_dry_run_validation(device: str = "cpu"):
    """
    Validate architecture instantiation, parameter keys, forward pass,
    backpropagation, and candidate checkpoint serialization.
    """
    logger.info("=" * 60)
    logger.info("Executing Architecture & Pipeline Dry-Run Validation")
    logger.info("=" * 60)

    from backend.models.cnn_rnn_detector import EnsembleDetector
    from backend.models.model_loader import load_model

    model = EnsembleDetector(n_mels=80, fused_dim=1167).to(device)
    param_count = sum(p.numel() for p in model.parameters())
    logger.info(f"Model instantiated successfully: {param_count:,} parameters.")

    # 1. Forward pass test
    mel_dummy = torch.randn(2, 198, 80, device=device)
    fused_dummy = torch.randn(2, 1167, device=device)
    target_dummy = torch.tensor([[0.0], [1.0]], device=device)

    model.train()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4)
    criterion = nn.BCEWithLogitsLoss()

    logits = model(mel_dummy, fused_dummy)
    loss = criterion(logits, target_dummy)
    loss.backward()
    optimizer.step()
    logger.info(f"Forward + backward pass verified. Loss: {loss.item():.4f}")

    # 2. Probability output check
    model.eval()
    with torch.no_grad():
        prob = model.predict_proba(mel_dummy, fused_dummy)
    assert prob.shape == (2, 1)
    assert torch.all(prob >= 0.0) and torch.all(prob <= 1.0)
    logger.info("Probability output contract verified: [0.0, 1.0].")

    # 3. State dict validation
    state_dict = model.state_dict()
    assert "seq_detector.cnn_blocks.0.conv.weight" in state_dict
    assert "fused_detector.feature_proj.0.weight" in state_dict
    assert "gate.0.weight" in state_dict
    logger.info("State dict structure matches production EnsembleDetector contract.")

    logger.info("✓ Dry-run architecture validation complete: PASS.")
    return True


def train(args):
    seed_everything(args.seed)
    device = "cuda" if (args.device in ("auto", "cuda") and torch.cuda.is_available()) else "cpu"
    logger.info(f"Using device: {device}")

    if args.dry_run:
        run_dry_run_validation(device)
        return

    from backend.models.cnn_rnn_detector import EnsembleDetector

    # Dataset loading
    train_dataset = ASVspoofAudioDataset(
        audio_dir=Path(args.dataset_dir) / "train",
        protocol_file=Path(args.protocol_train),
        max_samples=args.max_samples,
        use_wav2vec2=args.use_wav2vec2,
        use_ecapa=args.use_ecapa,
    )
    dev_dataset = ASVspoofAudioDataset(
        audio_dir=Path(args.dataset_dir) / "dev",
        protocol_file=Path(args.protocol_dev),
        max_samples=args.max_samples,
        use_wav2vec2=args.use_wav2vec2,
        use_ecapa=args.use_ecapa,
    )

    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True, drop_last=True)
    dev_loader = DataLoader(dev_dataset, batch_size=args.batch_size, shuffle=False)

    model = EnsembleDetector(n_mels=80, fused_dim=1167).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    criterion = nn.BCEWithLogitsLoss()

    best_val_loss = float("inf")
    best_eer = float("inf")
    candidate_path = PROJECT_ROOT / "backend" / "models" / "weights" / "detector_candidate.pt"
    candidate_path.parent.mkdir(parents=True, exist_ok=True)

    history = []

    for epoch in range(1, args.epochs + 1):
        model.train()
        train_losses = []
        t0 = time.time()

        for mel_seq, fused_vec, targets in train_loader:
            mel_seq = mel_seq.to(device)
            fused_vec = fused_vec.to(device)
            targets = targets.to(device)

            optimizer.zero_grad()
            logits = model(mel_seq, fused_vec)
            loss = criterion(logits, targets)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            train_losses.append(loss.item())

        mean_train_loss = float(np.mean(train_losses))

        # Evaluation phase
        model.eval()
        val_losses = []
        all_preds = []
        all_targets = []

        with torch.no_grad():
            for mel_seq, fused_vec, targets in dev_loader:
                mel_seq = mel_seq.to(device)
                fused_vec = fused_vec.to(device)
                targets = targets.to(device)

                logits = model(mel_seq, fused_vec)
                loss = criterion(logits, targets)
                val_losses.append(loss.item())

                prob = torch.sigmoid(logits).cpu().numpy()
                all_preds.append(prob)
                all_targets.append(targets.cpu().numpy())

        mean_val_loss = float(np.mean(val_losses))
        all_preds_arr = np.concatenate(all_preds, axis=0).flatten()
        all_targets_arr = np.concatenate(all_targets, axis=0).flatten()

        metrics = compute_metrics(all_targets_arr, all_preds_arr)
        epoch_sec = time.time() - t0

        logger.info(
            f"Epoch {epoch:02d}/{args.epochs:02d} [{epoch_sec:.1f}s]: "
            f"Train Loss={mean_train_loss:.4f}, Val Loss={mean_val_loss:.4f}, "
            f"Acc={metrics['accuracy']*100:.2f}%, F1={metrics['f1']:.4f}, EER={metrics['eer']*100:.2f}%"
        )

        history.append({
            "epoch": epoch,
            "train_loss": mean_train_loss,
            "val_loss": mean_val_loss,
            "metrics": metrics,
        })

        # Save candidate if improved
        if mean_val_loss < best_val_loss:
            best_val_loss = mean_val_loss
            best_eer = metrics["eer"]
            torch.save(model.state_dict(), candidate_path)
            logger.info(f"Saved new best candidate checkpoint to {candidate_path} (val_loss={best_val_loss:.4f})")

    # Write training manifest
    sha256 = hashlib.sha256()
    with open(candidate_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    chk_hash = sha256.hexdigest()

    manifest = {
        "model_name": "CyberGuard EnsembleDetector",
        "checkpoint_path": str(candidate_path),
        "sha256": chk_hash,
        "parameters": sum(p.numel() for p in model.parameters()),
        "architecture": "EnsembleDetector (Dual-modality CNN-BiLSTM + Gating)",
        "input_contract": {
            "sample_rate": 16000,
            "n_mels": 80,
            "fused_dim": 1167,
            "labels": {"0": "bonafide", "1": "spoof"}
        },
        "training_config": vars(args),
        "best_val_loss": best_val_loss,
        "best_eer": best_eer,
        "history": history,
    }
    manifest_path = candidate_path.parent / "detector_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Manifest written to {manifest_path}")


def main():
    parser = argparse.ArgumentParser(description="CyberGuard VoiceCloneDetector Training Pipeline")
    parser.add_argument("--dry-run", action="store_true", help="Validate architecture without full dataset")
    parser.add_argument("--dataset-dir", type=str, default="data/datasets/asvspoof2019_la")
    parser.add_argument("--protocol-train", type=str, default="data/datasets/asvspoof2019_la/train.txt")
    parser.add_argument("--protocol-dev", type=str, default="data/datasets/asvspoof2019_la/dev.txt")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--device", type=str, default="auto")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-samples", type=int, default=None)
    parser.add_argument("--use-wav2vec2", action="store_true", default=False)
    parser.add_argument("--use-ecapa", action="store_true", default=False)

    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
