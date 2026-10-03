"""
config.py — Configuration loader for CyberGuard.

Loads config.yaml from the project root and exposes a typed Settings dataclass.
All parameters are driven from config.yaml; nothing is hardcoded here.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml
from dotenv import load_dotenv

# Project root = two levels up from this file (backend/config.py → project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load environment variables, guaranteeing project-level .env is loaded
load_dotenv(_PROJECT_ROOT / ".env")
load_dotenv()

logger = logging.getLogger(__name__)


def _clean_secret(val: Optional[str]) -> str:
    """Strip whitespace and surrounding quotes from secret strings."""
    if not val:
        return ""
    s = str(val).strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    return s


def _load_yaml() -> dict:
    """Load config.yaml from the project root."""
    config_path = _PROJECT_ROOT / "config.yaml"
    if not config_path.exists():
        raise FileNotFoundError(
            f"config.yaml not found at {config_path}. "
            "Please ensure you are running from the CyberGuard project directory."
        )
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@dataclass
class AudioConfig:
    sample_rate: int = 16000
    chunk_duration_sec: float = 2.0
    overlap_ratio: float = 0.8  # Increased from 0.5 for faster sliding window
    channels: int = 1
    format: str = "float32"
    vad_aggressiveness: int = 2


@dataclass
class AlertThresholds:
    low: float = 0.35
    medium: float = 0.60
    high: float = 0.80
    critical: float = 0.95


@dataclass
class DetectionConfig:
    model_path: str = "backend/models/weights/detector.pt"
    device: str = "auto"
    batch_size: int = 1
    n_mels: int = 80
    n_mfcc: int = 40
    use_wav2vec2: bool = True
    wav2vec2_model: str = "facebook/wav2vec2-base"
    use_speaker_embedding: bool = True
    ecapa_model: str = "speechbrain/spkrec-ecapa-voxceleb"


@dataclass
class RiskConfig:
    window_size: int = 3  # Reduced from 5
    detection_weight: float = 0.70
    consistency_weight: float = 0.30
    temporal_smoothing: bool = True
    smoothing_alpha: float = 0.7  # Increased from 0.3 for faster response
    alert_cooldown_sec: float = 15.0
    alert_thresholds: AlertThresholds = field(default_factory=AlertThresholds)


@dataclass
class SpeakerConfig:
    embedding_dim: int = 192
    consistency_threshold: float = 0.75


@dataclass
class PrivacyConfig:
    retain_audio: bool = False
    log_features_only: bool = True
    audit_log_path: str = "data/audit.log"


@dataclass
class StorageConfig:
    db_path: str = "data/cyberguard.db"


@dataclass
class UploadConfig:
    max_file_size_bytes: int = 209715200  # 200 MB default
    max_duration_sec: float = 600.0       # 10-minute default


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 3000
    cors_origins: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class WebhookConfig:
    enabled: bool = False
    callback_url: str = ""
    secret_token: str = ""
    retry_attempts: int = 3
    retry_delay_sec: float = 2.0


@dataclass
class CyberGuardConfig:
    phishing_analysis_enabled: bool = True
    url_analysis_enabled: bool = True
    qr_analysis_enabled: bool = True
    deepfake_image_enabled: bool = True
    deepfake_video_enabled: bool = True
    technical_anomaly_enabled: bool = True
    threat_intelligence_enabled: bool = False
    mitre_mapping_enabled: bool = True
    incident_management_enabled: bool = True
    simulation_mode_enabled: bool = True


@dataclass
class VirusTotalConfig:
    enabled: bool = False
    timeout_sec: int = 10
    poll_interval_sec: int = 15
    max_file_size_bytes: int = 33554432
    cache_enabled: bool = True
    # API key is sourced from env (or config override), with whitespace and quotes stripped for safety.
    api_key: str = field(default_factory=lambda: _clean_secret(os.getenv("VIRUSTOTAL_API_KEY", "")))


@dataclass
class URLhausConfig:
    enabled: bool = False
    timeout_sec: int = 10
    cache_enabled: bool = True
    # Auth-Key is sourced from environment only — never stored in YAML or source code.
    auth_key: str = field(default_factory=lambda: _clean_secret(os.getenv("URLHAUS_AUTH_KEY", "")))


@dataclass
class Settings:
    audio: AudioConfig = field(default_factory=AudioConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    speaker: SpeakerConfig = field(default_factory=SpeakerConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    upload: UploadConfig = field(default_factory=UploadConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    webhooks: WebhookConfig = field(default_factory=WebhookConfig)
    cyberguard: CyberGuardConfig = field(default_factory=CyberGuardConfig)
    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    urlhaus: URLhausConfig = field(default_factory=URLhausConfig)
    project_root: Path = field(default_factory=lambda: _PROJECT_ROOT)

    def abs_path(self, relative: str) -> Path:
        """Resolve a path relative to the project root."""
        return self.project_root / relative


def _build_settings(raw: dict) -> Settings:
    audio_raw = raw.get("audio", {})
    detection_raw = raw.get("detection", {})
    risk_raw = raw.get("risk", {})
    speaker_raw = raw.get("speaker", {})
    privacy_raw = raw.get("privacy", {})
    storage_raw = raw.get("storage", {})
    server_raw = raw.get("server", {})
    webhooks_raw = raw.get("webhooks", {})
    upload_raw = raw.get("upload", {})
    cyberguard_raw = raw.get("cyberguard", {})
    virustotal_raw = raw.get("virustotal", {})
    urlhaus_raw = raw.get("urlhaus", {})

    thresholds_raw = risk_raw.get("alert_thresholds", {})

    vt_env_key = _clean_secret(os.getenv("VIRUSTOTAL_API_KEY", ""))
    vt_cfg_key = _clean_secret(virustotal_raw.get("api_key", ""))
    vt_key = vt_env_key or vt_cfg_key
    vt_enabled = bool(virustotal_raw.get("enabled", False))
    if "VIRUSTOTAL_ENABLED" in os.environ:
        vt_enabled = os.environ.get("VIRUSTOTAL_ENABLED", "").lower() in ("true", "1", "yes")

    uh_enabled = bool(urlhaus_raw.get("enabled", False))
    if "URLHAUS_ENABLED" in os.environ:
        uh_enabled = os.environ.get("URLHAUS_ENABLED", "").lower() in ("true", "1", "yes")

    storage_db = storage_raw.get("db_path", "data/cyberguard.db")
    if storage_db == "data/cyberguard.db" and not os.path.exists("data/cyberguard.db") and os.path.exists("data/voiceguard.db"):
        storage_db = "data/voiceguard.db"

    return Settings(
        audio=AudioConfig(

            sample_rate=audio_raw.get("sample_rate", 16000),
            chunk_duration_sec=audio_raw.get("chunk_duration_sec", 2.0),
            overlap_ratio=audio_raw.get("overlap_ratio", 0.8),
            channels=audio_raw.get("channels", 1),
            format=audio_raw.get("format", "float32"),
            vad_aggressiveness=audio_raw.get("vad_aggressiveness", 2),
        ),
        detection=DetectionConfig(
            model_path=detection_raw.get("model_path", "backend/models/weights/detector.pt"),
            device=detection_raw.get("device", "auto"),
            batch_size=detection_raw.get("batch_size", 1),
            n_mels=detection_raw.get("n_mels", 80),
            n_mfcc=detection_raw.get("n_mfcc", 40),
            use_wav2vec2=detection_raw.get("use_wav2vec2", True),
            wav2vec2_model=detection_raw.get("wav2vec2_model", "facebook/wav2vec2-base"),
            use_speaker_embedding=detection_raw.get("use_speaker_embedding", True),
            ecapa_model=detection_raw.get("ecapa_model", "speechbrain/spkrec-ecapa-voxceleb"),
        ),
        risk=RiskConfig(
            window_size=risk_raw.get("window_size", 3),
            detection_weight=risk_raw.get("detection_weight", 0.70),
            consistency_weight=risk_raw.get("consistency_weight", 0.30),
            temporal_smoothing=risk_raw.get("temporal_smoothing", True),
            smoothing_alpha=risk_raw.get("smoothing_alpha", 0.7),
            alert_cooldown_sec=risk_raw.get("alert_cooldown_sec", 15.0),
            alert_thresholds=AlertThresholds(
                low=thresholds_raw.get("low", 0.35),
                medium=thresholds_raw.get("medium", 0.60),
                high=thresholds_raw.get("high", 0.80),
                critical=thresholds_raw.get("critical", 0.95),
            ),
        ),
        speaker=SpeakerConfig(
            embedding_dim=speaker_raw.get("embedding_dim", 192),
            consistency_threshold=speaker_raw.get("consistency_threshold", 0.75),
        ),
        privacy=PrivacyConfig(
            retain_audio=privacy_raw.get("retain_audio", False),
            log_features_only=privacy_raw.get("log_features_only", True),
            audit_log_path=privacy_raw.get("audit_log_path", "data/audit.log"),
        ),
        storage=StorageConfig(
            db_path=storage_db,
        ),
        upload=UploadConfig(
            max_file_size_bytes=upload_raw.get("max_file_size_bytes", 209715200),
            max_duration_sec=float(upload_raw.get("max_duration_sec", 600.0)),
        ),
        server=ServerConfig(
            host=server_raw.get("host", "0.0.0.0"),
            port=int(server_raw.get("port", 3000)),
            cors_origins=server_raw.get("cors_origins", ["*"]),
        ),
        webhooks=WebhookConfig(
            enabled=webhooks_raw.get("enabled", False),
            callback_url=webhooks_raw.get("callback_url", ""),
            secret_token=os.getenv("WEBHOOK_SECRET", webhooks_raw.get("secret_token", "")),
            retry_attempts=webhooks_raw.get("retry_attempts", 3),
            retry_delay_sec=webhooks_raw.get("retry_delay_sec", 2.0),
        ),
        cyberguard=CyberGuardConfig(
            phishing_analysis_enabled=cyberguard_raw.get("phishing_analysis_enabled", True),
            url_analysis_enabled=cyberguard_raw.get("url_analysis_enabled", True),
            qr_analysis_enabled=cyberguard_raw.get("qr_analysis_enabled", True),
            deepfake_image_enabled=cyberguard_raw.get("deepfake_image_enabled", True),
            deepfake_video_enabled=cyberguard_raw.get("deepfake_video_enabled", True),
            technical_anomaly_enabled=cyberguard_raw.get("technical_anomaly_enabled", True),
            threat_intelligence_enabled=cyberguard_raw.get("threat_intelligence_enabled", False),
            mitre_mapping_enabled=cyberguard_raw.get("mitre_mapping_enabled", True),
            incident_management_enabled=cyberguard_raw.get("incident_management_enabled", True),
            simulation_mode_enabled=cyberguard_raw.get("simulation_mode_enabled", True),
        ),
        virustotal=VirusTotalConfig(
            enabled=vt_enabled,
            timeout_sec=virustotal_raw.get("timeout_sec", 10),
            poll_interval_sec=virustotal_raw.get("poll_interval_sec", 15),
            max_file_size_bytes=virustotal_raw.get("max_file_size_bytes", 33554432),
            cache_enabled=virustotal_raw.get("cache_enabled", True),
            api_key=vt_key,
        ),
        urlhaus=URLhausConfig(
            enabled=uh_enabled,
            timeout_sec=urlhaus_raw.get("timeout_sec", 10),
            cache_enabled=urlhaus_raw.get("cache_enabled", True),
            auth_key=_clean_secret(os.getenv("URLHAUS_AUTH_KEY", urlhaus_raw.get("auth_key", ""))),
        ),
    )



# Module-level singleton — loaded once at import time.
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the singleton Settings instance, loading from config.yaml on first call."""
    global _settings
    if _settings is None:
        try:
            raw = _load_yaml()
            _settings = _build_settings(raw)
            logger.info("Configuration loaded from config.yaml")
        except Exception as exc:
            logger.warning(f"Failed to load config.yaml ({exc}), using defaults.")
            _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Force reload of settings from disk and environment."""
    global _settings
    load_dotenv(_PROJECT_ROOT / ".env", override=True)
    load_dotenv(override=True)
    _settings = None
    return get_settings()
