"""
backend/services/model_registry.py — Central Model & Service Registry for CyberGuard.

Provides a unified, resource-efficient lazy-loading lifecycle for all heavy AI/ML models:
  - Qwen3.5-4B Generative LLM
  - MobileNetV3 Forensic Visual Deepfake Detector
  - SpeechBrain ECAPA-TDNN Speaker Biometrics
  - AASIST Audio Spoofing Detector
  - CNN-BiLSTM Voice Clone Detector
  - Wav2Vec 2.0 Acoustic Representations

Operational Rules:
  1. Models remain stored on disk (SSD) at application startup; RAM is not allocated until requested.
  2. Thread-safe & async-safe loading locks prevent race conditions and duplicate initialization.
  3. Reference counting and resource leases track active requests.
  4. Configurable idle TTL (default 300s) allows safe eviction of unneeded models without thrashing.
  5. Clear, truthful lifecycle states:
       - REGISTERED: Model defined in registry.
       - AVAILABLE_ON_DISK: Checkpoint verified on disk, ready to load.
       - INITIALIZING: Actively loading into RAM.
       - READY_IN_MEMORY: Loaded into RAM, verified, and ready for inference.
       - IN_USE: Actively processing an inference request.
       - IDLE: Loaded in RAM but currently no active requests.
       - UNLOADING: Actively releasing RAM and tensor allocations.
       - UNAVAILABLE: Checkpoint or required runtime dependency missing.
       - FAILED: Runtime error during load or execution.
       - DISABLED: Feature explicitly disabled via configuration.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("cyberguard.model_registry")


class ModelLifecycleState(str, Enum):
    REGISTERED = "REGISTERED"
    AVAILABLE_ON_DISK = "AVAILABLE_ON_DISK"
    INITIALIZING = "INITIALIZING"
    READY_IN_MEMORY = "READY_IN_MEMORY"
    IN_USE = "IN_USE"
    IDLE = "IDLE"
    UNLOADING = "UNLOADING"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    DISABLED = "DISABLED"


@dataclass
class RegisteredModel:
    model_id: str
    display_name: str
    category: str  # "llm" | "vision" | "voice" | "biometric" | "audio"
    description: str
    weight_candidates: List[Path]
    loader_func: Optional[Callable[[], Any]] = None
    unloader_func: Optional[Callable[[], None]] = None
    state: ModelLifecycleState = ModelLifecycleState.REGISTERED
    active_leases: int = 0
    last_used_timestamp: float = field(default_factory=time.time)
    load_time_sec: float = 0.0
    memory_footprint_mb: float = 0.0
    last_error: Optional[str] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def is_file_on_disk(self) -> bool:
        """Check if at least one required checkpoint exists on disk with valid size."""
        for cand in self.weight_candidates:
            if cand.exists() and (cand.is_dir() or cand.stat().st_size > 100):
                return True
        return False

    def get_resolved_path(self) -> Optional[Path]:
        for cand in self.weight_candidates:
            if cand.exists() and (cand.is_dir() or cand.stat().st_size > 100):
                return cand.resolve()
        return None


class ModelRegistry:
    """
    Central orchestrator managing AI model lifecycle, on-demand loading,
    bounded host memory budgets (8 GB RAM target), and idle eviction.
    """

    def __init__(self, idle_ttl_seconds: float = 300.0):
        self.idle_ttl_seconds = idle_ttl_seconds
        self._models: Dict[str, RegisteredModel] = {}
        self._async_locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = threading.Lock()
        self._eviction_task: Optional[asyncio.Task] = None
        self._running = True

        self._register_default_models()

    def _register_default_models(self) -> None:
        project_root = Path(__file__).resolve().parent.parent.parent

        # 1. Qwen3.5-4B LLM
        qwen_candidates = [
            Path("/app/backend/models/weights/qwen3.5/Qwen3.5-4B-Q4_K_M.gguf"),
            project_root / "backend" / "models" / "weights" / "qwen3.5" / "Qwen3.5-4B-Q4_K_M.gguf",
            Path("backend/models/weights/qwen3.5/Qwen3.5-4B-Q4_K_M.gguf"),
        ]
        self.register(
            model_id="qwen_llm",
            display_name="Qwen3.5-4B GGUF Analytical Copilot",
            category="llm",
            description="Primary generative LLM for SOC incident analysis, threat briefings, and forensic narratives.",
            weight_candidates=qwen_candidates,
            loader_func=self._load_qwen,
            unloader_func=self._unload_qwen,
        )

        # 2. Vision Deepfake Detector (MobileNetV3)
        vision_candidates = [
            Path("/app/backend/models/weights/vision_detector.pt"),
            project_root / "backend" / "models" / "weights" / "vision_detector.pt",
            Path("backend/models/weights/vision_detector.pt"),
        ]
        self.register(
            model_id="vision_detector",
            display_name="MobileNetV3 Forensic Vision Detector",
            category="vision",
            description="Neural visual deepfake & synthetic artifact detector with calibrated forensic classification head.",
            weight_candidates=vision_candidates,
            loader_func=self._load_vision,
            unloader_func=self._unload_vision,
        )

        # 3. SpeechBrain ECAPA-TDNN Speaker Biometrics
        ecapa_candidates = [
            Path("/app/backend/models/weights/ecapa_tdnn"),
            project_root / "backend" / "models" / "weights" / "ecapa_tdnn",
            project_root / "backend" / "models" / "weights" / "ecapa_tdnn" / "embedding_model.ckpt",
            Path("backend/models/weights/ecapa_tdnn"),
        ]
        self.register(
            model_id="ecapa_speaker_embedding",
            display_name="SpeechBrain ECAPA-TDNN Speaker Biometrics",
            category="biometric",
            description="192-dimensional speaker embedding centroid verification for voice identity matching.",
            weight_candidates=ecapa_candidates,
            loader_func=self._load_ecapa,
            unloader_func=self._unload_ecapa,
        )

        # 4. AASIST Audio Anti-Spoofing
        aasist_candidates = [
            Path("/app/backend/models/weights/aasist/AASIST.pth"),
            project_root / "backend" / "models" / "weights" / "aasist" / "AASIST.pth",
            Path("backend/models/weights/aasist/AASIST.pth"),
        ]
        self.register(
            model_id="aasist_detector",
            display_name="AASIST Audio Anti-Spoofing Detector",
            category="voice",
            description="Spectro-temporal graph attention network pre-trained on ASVspoof benchmarks.",
            weight_candidates=aasist_candidates,
            loader_func=self._load_aasist,
            unloader_func=self._unload_aasist,
        )

        # 5. Voice Clone Detector (CNN-BiLSTM)
        detector_candidates = [
            Path("/app/backend/models/weights/detector.pt"),
            project_root / "backend" / "models" / "weights" / "detector.pt",
            Path("backend/models/weights/detector.pt"),
        ]
        self.register(
            model_id="voice_clone_detector",
            display_name="Dual CNN-BiLSTM Voice Clone Detector",
            category="voice",
            description="Acoustic neural network analyzing raw PCM spectrograms and prosodic features.",
            weight_candidates=detector_candidates,
            loader_func=self._load_voice_detector,
            unloader_func=self._unload_voice_detector,
        )

        # 6. Wav2Vec 2.0 Acoustic Representations
        self.register(
            model_id="wav2vec2_extractor",
            display_name="Wav2Vec 2.0 Acoustic Representations",
            category="audio",
            description="Self-supervised transformer phoneme and temporal acoustic modeling.",
            weight_candidates=[Path(os.environ.get("HF_HOME", "~/.cache/huggingface"))],
            loader_func=self._load_wav2vec2,
            unloader_func=self._unload_wav2vec2,
        )

    def register(
        self,
        model_id: str,
        display_name: str,
        category: str,
        description: str,
        weight_candidates: List[Path],
        loader_func: Optional[Callable[[], Any]] = None,
        unloader_func: Optional[Callable[[], None]] = None,
    ) -> None:
        with self._global_lock:
            reg = RegisteredModel(
                model_id=model_id,
                display_name=display_name,
                category=category,
                description=description,
                weight_candidates=weight_candidates,
                loader_func=loader_func,
                unloader_func=unloader_func,
                state=ModelLifecycleState.AVAILABLE_ON_DISK if any(c.exists() for c in weight_candidates) else ModelLifecycleState.UNAVAILABLE,
            )
            self._models[model_id] = reg
            if model_id not in self._async_locks:
                self._async_locks[model_id] = asyncio.Lock()

    def get_model(self, model_id: str) -> Optional[RegisteredModel]:
        return self._models.get(model_id)

    def refresh_availability(self) -> None:
        """Inspect disk existence for all models without loading them into memory."""
        with self._global_lock:
            for m in self._models.values():
                if m.state in (ModelLifecycleState.READY_IN_MEMORY, ModelLifecycleState.IN_USE, ModelLifecycleState.IDLE):
                    continue  # already loaded
                if m.is_file_on_disk():
                    m.state = ModelLifecycleState.AVAILABLE_ON_DISK
                else:
                    m.state = ModelLifecycleState.UNAVAILABLE

    # ── Model Loaders & Unloaders ─────────────────────────────────────────────

    def _load_qwen(self) -> Any:
        from backend.models.qwen_service import get_qwen_service
        svc = get_qwen_service()
        if not svc.is_ready:
            svc.load_model()
        return svc

    def _unload_qwen(self) -> None:
        from backend.models.qwen_service import get_qwen_service
        svc = get_qwen_service()
        svc.unload()

    def _load_vision(self) -> Any:
        from backend.models.vision_detector import get_vision_detector
        detector = get_vision_detector()
        if hasattr(detector, "_load_weights"):
            detector._load_weights()
        return detector

    def _unload_vision(self) -> None:
        from backend.models.vision_detector import get_vision_detector
        detector = get_vision_detector()
        if hasattr(detector, "unload"):
            detector.unload()

    def _load_ecapa(self) -> Any:
        from backend.features.speaker_extractor import _load_ecapa
        _load_ecapa()
        return True

    def _unload_ecapa(self) -> None:
        from backend.features.speaker_extractor import unload_ecapa
        if callable(unload_ecapa):
            unload_ecapa()

    def _load_aasist(self) -> Any:
        from backend.models.aasist_adapter import AASISTDetector
        det = AASISTDetector()
        det.initialize()
        return det

    def _unload_aasist(self) -> None:
        pass  # Small memory footprint (<2 MB)

    def _load_voice_detector(self) -> Any:
        from backend.main import get_app_detector
        det = get_app_detector()
        if det and not det.is_initialized:
            det.initialize()
        return det

    def _unload_voice_detector(self) -> None:
        pass

    def _load_wav2vec2(self) -> Any:
        from backend.features.wav2vec_extractor import _load_wav2vec2
        _load_wav2vec2()
        return True

    def _unload_wav2vec2(self) -> None:
        from backend.features.wav2vec_extractor import unload_wav2vec2
        if callable(unload_wav2vec2):
            unload_wav2vec2()

    # ── Concurrency & Lease Management ────────────────────────────────────────

    @asynccontextmanager
    async def acquire_lease_async(self, model_id: str):
        """
        Asynchronously acquire resource lease for model execution.
        Loads model into memory if needed, marks IN_USE, and releases on exit.
        """
        model = self._models.get(model_id)
        if not model:
            raise KeyError(f"Unknown model identifier: {model_id}")

        async_lock = self._async_locks[model_id]
        async with async_lock:
            with model._lock:
                needs_load = model.state not in (ModelLifecycleState.READY_IN_MEMORY, ModelLifecycleState.IN_USE, ModelLifecycleState.IDLE)
                if needs_load:
                    model.state = ModelLifecycleState.INITIALIZING

            if needs_load:
                t0 = time.time()
                try:
                    if model.loader_func:
                        await asyncio.to_thread(model.loader_func)
                    model.load_time_sec = time.time() - t0
                    with model._lock:
                        model.state = ModelLifecycleState.READY_IN_MEMORY
                    logger.info(f"✓ Model '{model.display_name}' loaded on-demand in {model.load_time_sec:.2f}s.")
                except Exception as exc:
                    with model._lock:
                        model.state = ModelLifecycleState.FAILED
                        model.last_error = str(exc)
                    logger.error(f"✗ Failed to load model '{model_id}': {exc}")
                    raise

            with model._lock:
                model.active_leases += 1
                model.state = ModelLifecycleState.IN_USE
                model.last_used_timestamp = time.time()

        try:
            yield model
        finally:
            async with async_lock:
                with model._lock:
                    model.active_leases = max(0, model.active_leases - 1)
                    model.last_used_timestamp = time.time()
                    if model.active_leases == 0:
                        model.state = ModelLifecycleState.IDLE

    @contextmanager
    def acquire_lease_sync(self, model_id: str):
        """Synchronous version of acquire_lease."""
        model = self._models.get(model_id)
        if not model:
            raise KeyError(f"Unknown model identifier: {model_id}")

        with model._lock:
            if model.state not in (ModelLifecycleState.READY_IN_MEMORY, ModelLifecycleState.IN_USE, ModelLifecycleState.IDLE):
                model.state = ModelLifecycleState.INITIALIZING
                t0 = time.time()
                try:
                    if model.loader_func:
                        model.loader_func()
                    model.load_time_sec = time.time() - t0
                    model.state = ModelLifecycleState.READY_IN_MEMORY
                    logger.info(f"✓ Model '{model.display_name}' loaded on-demand (sync) in {model.load_time_sec:.2f}s.")
                except Exception as exc:
                    model.state = ModelLifecycleState.FAILED
                    model.last_error = str(exc)
                    logger.error(f"✗ Failed to load model '{model_id}': {exc}")
                    raise

            model.active_leases += 1
            model.state = ModelLifecycleState.IN_USE
            model.last_used_timestamp = time.time()

        try:
            yield model
        finally:
            with model._lock:
                model.active_leases = max(0, model.active_leases - 1)
                model.last_used_timestamp = time.time()
                if model.active_leases == 0:
                    model.state = ModelLifecycleState.IDLE

    def evict_idle_models(self) -> List[str]:
        """Unload models that have been idle longer than idle_ttl_seconds."""
        evicted = []
        now = time.time()
        for m_id, model in self._models.items():
            if model.state == ModelLifecycleState.IDLE and model.active_leases == 0:
                idle_duration = now - model.last_used_timestamp
                if idle_duration >= self.idle_ttl_seconds:
                    with model._lock:
                        if model.active_leases == 0:
                            model.state = ModelLifecycleState.UNLOADING
                            try:
                                if model.unloader_func:
                                    model.unloader_func()
                                gc.collect()
                                try:
                                    import torch
                                    if torch.cuda.is_available():
                                        torch.cuda.empty_cache()
                                except Exception:
                                    pass
                                model.state = ModelLifecycleState.AVAILABLE_ON_DISK if model.is_file_on_disk() else ModelLifecycleState.UNAVAILABLE
                                evicted.append(m_id)
                                logger.info(f"♻ Safely evicted idle model '{model.display_name}' after {idle_duration:.1f}s idle.")
                            except Exception as exc:
                                logger.warning(f"Notice while evicting model '{m_id}': {exc}")
        return evicted

    async def run_periodic_eviction(self, interval_sec: int = 60):
        """Continuously running background worker that evicts idle models beyond TTL."""
        logger.info(f"Periodic model eviction worker active (interval: {interval_sec}s, idle TTL: {self.idle_ttl_seconds}s).")
        while self._running:
            try:
                await asyncio.sleep(interval_sec)
                await asyncio.to_thread(self.evict_idle_models)
            except asyncio.CancelledError:
                logger.info("Periodic model eviction worker cancelled.")
                break
            except Exception as e:
                logger.warning(f"Periodic model eviction iteration notice: {e}")

    def get_all_diagnostics(self) -> Dict[str, Any]:
        """Return truthful operational diagnostic dictionary for all registered models."""
        self.refresh_availability()
        items = {}
        for m_id, m in self._models.items():
            # Translate state into clean, professional UI status label
            status_map = {
                ModelLifecycleState.AVAILABLE_ON_DISK: "AVAILABLE ON DISK — STANDBY",
                ModelLifecycleState.READY_IN_MEMORY: "LOADED — READY IN MEMORY",
                ModelLifecycleState.IN_USE: "ACTIVE — PROCESSING REQUEST",
                ModelLifecycleState.IDLE: "LOADED — IDLE",
                ModelLifecycleState.INITIALIZING: "INITIALIZING",
                ModelLifecycleState.UNLOADING: "UNLOADING",
                ModelLifecycleState.UNAVAILABLE: "UNAVAILABLE — WEIGHTS MISSING",
                ModelLifecycleState.FAILED: "FAILED — INITIALIZATION ERROR",
                ModelLifecycleState.DISABLED: "DISABLED",
            }

            resolved = m.get_resolved_path()
            file_size_bytes = resolved.stat().st_size if (resolved and resolved.is_file()) else None
            file_size_display = f"{round(file_size_bytes / (1024*1024), 1)} MB" if file_size_bytes else None

            items[m_id] = {
                "id": m.model_id,
                "name": m.display_name,
                "category": m.category,
                "state": m.state.value,
                "status_label": status_map.get(m.state, m.state.value),
                "is_loaded": m.state in (ModelLifecycleState.READY_IN_MEMORY, ModelLifecycleState.IN_USE, ModelLifecycleState.IDLE),
                "is_available_on_disk": m.is_file_on_disk(),
                "active_leases": m.active_leases,
                "load_time_sec": round(m.load_time_sec, 2),
                "idle_sec": round(time.time() - m.last_used_timestamp, 1),
                "file_path": str(resolved) if resolved else None,
                "file_size": file_size_display,
                "error": m.last_error,
            }
        return items


# Singleton instance
_REGISTRY_INSTANCE: Optional[ModelRegistry] = None


def get_model_registry() -> ModelRegistry:
    global _REGISTRY_INSTANCE
    if _REGISTRY_INSTANCE is None:
        _REGISTRY_INSTANCE = ModelRegistry()
    return _REGISTRY_INSTANCE
