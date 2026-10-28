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

# Load environment variables, guaranteeing project-level .env and isolated secret files are loaded
load_dotenv(_PROJECT_ROOT / ".env.email")
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
    low: float = 0.25
    medium: float = 0.50
    high: float = 0.70
    critical: float = 0.85


@dataclass
class DetectionConfig:
    model_path: str = "backend/models/weights/detector.pt"
    device: str = "auto"
    batch_size: int = 1
    n_mels: int = 80
    n_mfcc: int = 40
    use_wav2vec2: bool = False
    wav2vec2_model: str = "facebook/wav2vec2-base"
    use_speaker_embedding: bool = False
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
    database_url: str = ""


@dataclass
class UploadConfig:
    max_file_size_bytes: int = 209715200  # 200 MB default
    max_duration_sec: float = 600.0       # 10-minute default


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 3000
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    trusted_proxies: List[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])


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
    cache_ttl_sec: float = 86400.0  # 24-hour report cache for API quota/token conservation
    isolated_enclave_only: bool = True  # Strict boundary isolation to Phishing & URL tab only
    # API key is sourced from env (or config override), with whitespace and quotes stripped for safety.
    api_key: str = field(default_factory=lambda: _clean_secret(os.getenv("VIRUSTOTAL_API_KEY", "")))


@dataclass
class URLhausConfig:
    enabled: bool = False
    timeout_sec: int = 10
    cache_enabled: bool = True
    cache_ttl_sec: float = 86400.0  # 24-hour report cache for API quota/token conservation
    isolated_enclave_only: bool = True  # Strict boundary isolation to Phishing & URL tab only
    # Auth-Key is sourced from environment only — never stored in YAML or source code.
    auth_key: str = field(default_factory=lambda: _clean_secret(os.getenv("URLHAUS_AUTH_KEY", "")))


@dataclass
class EnforcementConfig:
    enabled: bool = True
    auto_block_critical: bool = True
    auto_block_threshold: float = 0.85
    ddos_protection: bool = True
    ddos_rpm_limit: int = 120
    ddos_burst_limit: int = 30
    ban_duration_minutes: int = 60


@dataclass
class EmailAlertsConfig:
    enabled: bool = True
    provider: str = "brevo"
    brevo_api_key: str = ""
    email_from: str = "cyberguardadmin@gmail.com"
    email_from_name: str = "CyberGuard Security"
    recipient: str = ""
    recipients: List[str] = field(default_factory=list)
    admin_recipients: List[str] = field(default_factory=list)
    threshold: str = "CRITICAL"
    min_severity: str = "HIGH"
    score_threshold: float = 0.85
    cooldown_seconds: float = 300.0
    daily_limit: int = 250
    test_mode: bool = False
    smtp_server: str = "smtp-relay.brevo.com"
    smtp_port: int = 587
    smtp_login: str = ""
    smtp_key: str = ""
    smtp_password: str = ""



@dataclass
class ImageForensicsConfig:
    """Configurable parameters, thresholds, and factors for Image & Deepfake Forensics."""
    # Decision classification thresholds
    threshold_manipulated: float = 0.65       # Minimum manipulation score for LIKELY_MANIPULATED
    threshold_inconclusive: float = 0.35      # Minimum score for INCONCLUSIVE
    threshold_critical: float = 0.85          # Minimum score for CRITICAL severity

    # Grounding factors
    camera_provenance_dampener: float = 0.35  # Grounding dampener for verified optical camera hardware
    ai_metadata_suspicion: float = 0.85       # Minimum suspicion when explicit generative AI signature detected

    # 2D FFT Spectral Analysis
    fft_high_freq_attenuation_critical: float = 0.012
    fft_high_freq_attenuation_moderate: float = 0.022
    fft_high_freq_boost_threshold: float = 0.45
    fft_lattice_spike_critical: float = 4.0
    fft_lattice_spike_moderate: float = 2.3
    fft_lattice_min_peaks: int = 4

    # Sensor Noise & PRNU Kurtosis (at native 1:1 scale with edge masking)
    noise_crop_size: int = 512                # Native patch crop size (prevents downsampling interpolation artifacts)
    noise_kurtosis_critical: float = 70.0
    noise_kurtosis_moderate: float = 30.0
    noise_kurtosis_mild: float = 18.0
    noise_kurtosis_camera_max: float = 25.0   # Upper bound of acceptable sensor kurtosis for camera grounding
    noise_variance_flattened: float = 0.25    # Unnaturally low noise variance (synthetic smoothing)
    noise_edge_mask_percentile: float = 85.0  # Exclude structural edges to measure true sensor PRNU

    # Error Level Analysis (ELA)
    ela_quality: int = 95
    ela_disparity_critical: float = 10.0
    ela_disparity_moderate: float = 6.0
    ela_max_diff_threshold: float = 60.0
    ela_nominal_max: float = 8.0

    # Facial Forensics
    face_skin_to_edge_ratio: float = 0.16
    face_skin_lap_min: float = 20.0
    face_edge_lap_min: float = 35.0
    face_seam_ratio_threshold: float = 2.2
    face_eye_asymmetry_threshold: float = 0.35

    # Color Channel Gradient Correlation
    color_decorrelation_critical: float = 0.35
    color_decorrelation_moderate: float = 0.50


@dataclass
class MalwareAnalysisConfig:
    enabled: bool = True
    clamscan_path: str = "clamscan"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    clamd_socket: str = ""
    clamd_enabled: bool = True
    yara_enabled: bool = True
    yara_rules_dir: str = "data/yara_rules"
    max_scan_size_bytes: int = 1073741824  # 1GB (1024 * 1024 * 1024)
    scan_timeout_sec: float = 60.0
    archive_max_files: int = 1000
    archive_max_total_bytes: int = 1073741824  # 1GB
    archive_max_ratio: float = 50.0


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
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    email_alerts: EmailAlertsConfig = field(default_factory=EmailAlertsConfig)
    image_forensics: ImageForensicsConfig = field(default_factory=ImageForensicsConfig)
    malware: MalwareAnalysisConfig = field(default_factory=MalwareAnalysisConfig)
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
    enforcement_raw = raw.get("enforcement", {})
    email_alerts_raw = raw.get("email_alerts", {})
    image_forensics_raw = raw.get("image_forensics", {})
    malware_raw = raw.get("malware", {})

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
            use_wav2vec2=os.getenv("CYBERGUARD_USE_WAV2VEC2", "false").lower() == "true" if "CYBERGUARD_USE_WAV2VEC2" in os.environ else detection_raw.get("use_wav2vec2", False),
            wav2vec2_model=detection_raw.get("wav2vec2_model", "facebook/wav2vec2-base"),
            use_speaker_embedding=os.getenv("CYBERGUARD_USE_SPEAKER_EMBEDDING", "false").lower() == "true" if "CYBERGUARD_USE_SPEAKER_EMBEDDING" in os.environ else detection_raw.get("use_speaker_embedding", False),
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
            database_url=_clean_secret(
                os.getenv("DATABASE_URL")
                or os.getenv("SUPABASE_DB_URL")
                or storage_raw.get("database_url", "")
            ),
        ),
        upload=UploadConfig(
            max_file_size_bytes=upload_raw.get("max_file_size_bytes", 209715200),
            max_duration_sec=float(upload_raw.get("max_duration_sec", 600.0)),
        ),
        server=ServerConfig(
            host=server_raw.get("host", "0.0.0.0"),
            port=int(server_raw.get("port", 3000)),
            cors_origins=[o for o in server_raw.get("cors_origins", ["*"]) if o and str(o).lower() != "null"] if isinstance(server_raw.get("cors_origins"), list) else ["*"],
            trusted_proxies=[p.strip() for p in os.getenv("CYBERGUARD_TRUSTED_PROXIES", "").split(",") if p.strip()] if os.getenv("CYBERGUARD_TRUSTED_PROXIES") else server_raw.get("trusted_proxies", ["127.0.0.1", "::1"]),
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
            cache_ttl_sec=float(virustotal_raw.get("cache_ttl_sec", 86400.0)),
            isolated_enclave_only=bool(virustotal_raw.get("isolated_enclave_only", True)),
            api_key=vt_key,
        ),
        urlhaus=URLhausConfig(
            enabled=uh_enabled,
            timeout_sec=urlhaus_raw.get("timeout_sec", 10),
            cache_enabled=urlhaus_raw.get("cache_enabled", True),
            cache_ttl_sec=float(urlhaus_raw.get("cache_ttl_sec", 86400.0)),
            isolated_enclave_only=bool(urlhaus_raw.get("isolated_enclave_only", True)),
            auth_key=_clean_secret(os.getenv("URLHAUS_AUTH_KEY", urlhaus_raw.get("auth_key", ""))),
        ),
        enforcement=EnforcementConfig(
            enabled=bool(enforcement_raw.get("enabled", True)),
            auto_block_critical=bool(enforcement_raw.get("auto_block_critical", True)),
            auto_block_threshold=float(enforcement_raw.get("auto_block_threshold", 0.85)),
            ddos_protection=bool(enforcement_raw.get("ddos_protection", True)),
            ddos_rpm_limit=int(enforcement_raw.get("ddos_rpm_limit", 120)),
            ddos_burst_limit=int(enforcement_raw.get("ddos_burst_limit", 30)),
            ban_duration_minutes=int(enforcement_raw.get("ban_duration_minutes", 60)),
        ),
        email_alerts=EmailAlertsConfig(
            enabled=bool(os.environ.get("EMAIL_ENABLED", "").lower() in ("true", "1", "yes") if "EMAIL_ENABLED" in os.environ else email_alerts_raw.get("enabled", True)),
            provider=os.getenv("EMAIL_PROVIDER", email_alerts_raw.get("provider", "brevo")).lower().strip(),
            brevo_api_key=_clean_secret(os.getenv("BREVO_API_KEY", email_alerts_raw.get("brevo_api_key", ""))),
            email_from=os.getenv("EMAIL_FROM", email_alerts_raw.get("email_from", "cyberguardadmin@gmail.com")).strip() or "cyberguardadmin@gmail.com",
            email_from_name=os.getenv("EMAIL_FROM_NAME", email_alerts_raw.get("email_from_name", "CyberGuard Security")).strip() or "CyberGuard Security",
            recipient=str(os.getenv("EMAIL_ALERT_RECIPIENTS", email_alerts_raw.get("recipient", "")).split(",")[0].strip()),
            recipients=[r.strip() for r in os.getenv("EMAIL_ALERT_RECIPIENTS", email_alerts_raw.get("recipient", "")).split(",") if r.strip()],
            admin_recipients=[r.strip() for r in os.getenv("EMAIL_ALERT_RECIPIENTS", email_alerts_raw.get("recipient", "")).split(",") if r.strip()],
            threshold=os.getenv("EMAIL_ALERT_THRESHOLD") or str(email_alerts_raw.get("threshold", "CRITICAL")),
            min_severity=os.getenv("EMAIL_ALERT_MIN_SEVERITY") or str(email_alerts_raw.get("min_severity", "HIGH")),
            score_threshold=float(os.getenv("EMAIL_ALERT_THRESHOLD")) / 100.0 if (os.getenv("EMAIL_ALERT_THRESHOLD") and os.getenv("EMAIL_ALERT_THRESHOLD").replace(".", "", 1).isdigit() and float(os.getenv("EMAIL_ALERT_THRESHOLD")) > 1.0) else (float(os.getenv("EMAIL_ALERT_THRESHOLD")) if (os.getenv("EMAIL_ALERT_THRESHOLD") and os.getenv("EMAIL_ALERT_THRESHOLD").replace(".", "", 1).isdigit()) else 0.85),
            cooldown_seconds=float(os.getenv("EMAIL_ALERT_COOLDOWN_SECONDS", email_alerts_raw.get("cooldown_seconds", 300.0))),
            daily_limit=int(os.getenv("EMAIL_DAILY_LIMIT", email_alerts_raw.get("daily_limit", 250))),
            test_mode=bool(os.environ.get("EMAIL_TEST_MODE", "").lower() in ("true", "1", "yes")),
            smtp_server=os.getenv("SMTP_SERVER", os.getenv("SMTP_HOST", email_alerts_raw.get("smtp_server", "smtp-relay.brevo.com"))).strip(),
            smtp_port=int(os.getenv("SMTP_PORT", email_alerts_raw.get("smtp_port", 587))),
            smtp_login=_clean_secret(os.getenv("SMTP_LOGIN", os.getenv("SMTP_USER", email_alerts_raw.get("smtp_login", "")))),
            smtp_key=_clean_secret(os.getenv("SMTP_KEY", os.getenv("SMTP_PASSWORD", os.getenv("BREVO_API_KEY", email_alerts_raw.get("smtp_key", ""))))),
            smtp_password=_clean_secret(os.getenv("SMTP_PASSWORD", os.getenv("SMTP_KEY", os.getenv("BREVO_API_KEY", email_alerts_raw.get("smtp_password", ""))))),
        ),
        image_forensics=ImageForensicsConfig(
            threshold_manipulated=float(os.getenv("IMAGE_FORENSICS_THRESHOLD_MANIPULATED", image_forensics_raw.get("threshold_manipulated", 0.65))),
            threshold_inconclusive=float(os.getenv("IMAGE_FORENSICS_THRESHOLD_INCONCLUSIVE", image_forensics_raw.get("threshold_inconclusive", 0.35))),
            threshold_critical=float(os.getenv("IMAGE_FORENSICS_THRESHOLD_CRITICAL", image_forensics_raw.get("threshold_critical", 0.85))),
            camera_provenance_dampener=float(os.getenv("IMAGE_FORENSICS_CAMERA_DAMPENER", image_forensics_raw.get("camera_provenance_dampener", 0.35))),
            ai_metadata_suspicion=float(os.getenv("IMAGE_FORENSICS_AI_METADATA_SUSPICION", image_forensics_raw.get("ai_metadata_suspicion", 0.85))),
            fft_high_freq_attenuation_critical=float(image_forensics_raw.get("fft_high_freq_attenuation_critical", 0.012)),
            fft_high_freq_attenuation_moderate=float(image_forensics_raw.get("fft_high_freq_attenuation_moderate", 0.022)),
            fft_high_freq_boost_threshold=float(image_forensics_raw.get("fft_high_freq_boost_threshold", 0.45)),
            fft_lattice_spike_critical=float(image_forensics_raw.get("fft_lattice_spike_critical", 4.0)),
            fft_lattice_spike_moderate=float(image_forensics_raw.get("fft_lattice_spike_moderate", 2.3)),
            fft_lattice_min_peaks=int(image_forensics_raw.get("fft_lattice_min_peaks", 4)),
            noise_crop_size=int(image_forensics_raw.get("noise_crop_size", 512)),
            noise_kurtosis_critical=float(image_forensics_raw.get("noise_kurtosis_critical", 70.0)),
            noise_kurtosis_moderate=float(image_forensics_raw.get("noise_kurtosis_moderate", 30.0)),
            noise_kurtosis_mild=float(image_forensics_raw.get("noise_kurtosis_mild", 18.0)),
            noise_kurtosis_camera_max=float(image_forensics_raw.get("noise_kurtosis_camera_max", 25.0)),
            noise_variance_flattened=float(image_forensics_raw.get("noise_variance_flattened", 0.25)),
            noise_edge_mask_percentile=float(image_forensics_raw.get("noise_edge_mask_percentile", 85.0)),
            ela_quality=int(image_forensics_raw.get("ela_quality", 95)),
            ela_disparity_critical=float(image_forensics_raw.get("ela_disparity_critical", 10.0)),
            ela_disparity_moderate=float(image_forensics_raw.get("ela_disparity_moderate", 6.0)),
            ela_max_diff_threshold=float(image_forensics_raw.get("ela_max_diff_threshold", 60.0)),
            ela_nominal_max=float(image_forensics_raw.get("ela_nominal_max", 8.0)),
            face_skin_to_edge_ratio=float(image_forensics_raw.get("face_skin_to_edge_ratio", 0.16)),
            face_skin_lap_min=float(image_forensics_raw.get("face_skin_lap_min", 20.0)),
            face_edge_lap_min=float(image_forensics_raw.get("face_edge_lap_min", 35.0)),
            face_seam_ratio_threshold=float(image_forensics_raw.get("face_seam_ratio_threshold", 2.2)),
            face_eye_asymmetry_threshold=float(image_forensics_raw.get("face_eye_asymmetry_threshold", 0.35)),
            color_decorrelation_critical=float(image_forensics_raw.get("color_decorrelation_critical", 0.35)),
            color_decorrelation_moderate=float(image_forensics_raw.get("color_decorrelation_moderate", 0.50)),
        ),
        malware=MalwareAnalysisConfig(
            enabled=bool(os.environ.get("MALWARE_SCAN_ENABLED", "").lower() in ("true", "1", "yes") if "MALWARE_SCAN_ENABLED" in os.environ else malware_raw.get("enabled", True)),
            clamscan_path=os.getenv("CLAMSCAN_PATH", malware_raw.get("clamscan_path", "clamscan")),
            clamd_host=os.getenv("CLAMD_HOST", malware_raw.get("clamd_host", "127.0.0.1")),
            clamd_port=int(os.getenv("CLAMD_PORT", malware_raw.get("clamd_port", 3310))),
            clamd_socket=os.getenv("CLAMD_SOCKET", malware_raw.get("clamd_socket", "")),
            clamd_enabled=bool(os.environ.get("CLAMD_ENABLED", "").lower() in ("true", "1", "yes") if "CLAMD_ENABLED" in os.environ else malware_raw.get("clamd_enabled", True)),
            yara_enabled=bool(os.environ.get("YARA_ENABLED", "").lower() in ("true", "1", "yes") if "YARA_ENABLED" in os.environ else malware_raw.get("yara_enabled", True)),
            yara_rules_dir=os.getenv("YARA_RULES_DIR", malware_raw.get("yara_rules_dir", "data/yara_rules")),
            max_scan_size_bytes=int(os.getenv("MALWARE_MAX_FILE_SIZE_BYTES", malware_raw.get("max_scan_size_bytes", 1073741824))),
            scan_timeout_sec=float(os.getenv("MALWARE_SCAN_TIMEOUT_SEC", malware_raw.get("scan_timeout_sec", 60.0))),
            archive_max_files=int(malware_raw.get("archive_max_files", 1000)),
            archive_max_total_bytes=int(malware_raw.get("archive_max_total_bytes", 1073741824)),
            archive_max_ratio=float(malware_raw.get("archive_max_ratio", 50.0)),
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
    load_dotenv(_PROJECT_ROOT / ".env.email", override=True)
    load_dotenv(_PROJECT_ROOT / ".env", override=True)
    load_dotenv(override=True)
    _settings = None
    return get_settings()

