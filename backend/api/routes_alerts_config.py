"""
routes_alerts.py — Alert history REST API.
routes_config.py — Threshold configuration REST API.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.storage.auth import require_admin
from backend.storage.database import UserModel

logger = logging.getLogger(__name__)

# ── Alerts Router ──────────────────────────────────────────────────────────────
alerts_router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@alerts_router.get("/recent")
async def get_recent_alerts(limit: int = 50):
    """Get the most recent alerts across all sessions."""
    from backend.main import get_app_alert_manager
    return {"alerts": get_app_alert_manager().get_recent_alerts(limit=limit)}


@alerts_router.get("/session/{session_id}")
async def get_session_alerts(session_id: str):
    """Get all alerts for a specific session."""
    from backend.main import get_app_alert_manager
    alerts = get_app_alert_manager().get_session_history(session_id)
    return {"session_id": session_id, "alerts": alerts}


# ── Config Router ──────────────────────────────────────────────────────────────
config_router = APIRouter(prefix="/api/config", tags=["Configuration"])


class ThresholdUpdateRequest(BaseModel):
    low: float = Field(ge=0.0, le=1.0, description="LOW alert threshold")
    medium: float = Field(ge=0.0, le=1.0, description="MEDIUM alert threshold")
    high: float = Field(ge=0.0, le=1.0, description="HIGH alert threshold")
    critical: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="CRITICAL alert threshold")


@config_router.get("/thresholds")
async def get_thresholds():
    """Get current alert threshold configuration."""
    from backend.main import app_settings
    return {
        "low": app_settings.risk.alert_thresholds.low,
        "medium": app_settings.risk.alert_thresholds.medium,
        "high": app_settings.risk.alert_thresholds.high,
        "critical": app_settings.risk.alert_thresholds.critical,
    }


@config_router.put("/thresholds")
async def update_thresholds(
    body: ThresholdUpdateRequest,
    admin: UserModel = Depends(require_admin),
):
    """Update alert thresholds at runtime (without restart). Requires ADMIN privileges."""
    from backend.main import app_settings

    new_critical = body.critical if body.critical is not None else app_settings.risk.alert_thresholds.critical

    if not (body.low < body.medium < body.high < new_critical):
        raise HTTPException(
            status_code=422,
            detail=f"Thresholds must satisfy: low < medium < high < critical (got {body.low} < {body.medium} < {body.high} < {new_critical})"
        )

    app_settings.risk.alert_thresholds.low = body.low
    app_settings.risk.alert_thresholds.medium = body.medium
    app_settings.risk.alert_thresholds.high = body.high
    if body.critical is not None:
        app_settings.risk.alert_thresholds.critical = body.critical

    return {
        "message": "Thresholds updated.",
        "low": body.low,
        "medium": body.medium,
        "high": body.high,
        "critical": app_settings.risk.alert_thresholds.critical,
    }


@config_router.get("/status")
async def get_system_status():
    """Return current system health and model status."""
    from backend.main import get_app_detector, app_settings, get_app_ws_notifier
    from backend.features.wav2vec_extractor import is_wav2vec2_available
    from backend.features.speaker_extractor import is_ecapa_available

    from backend.threats.virustotal import get_virustotal_provider
    from backend.threats.urlhaus import get_urlhaus_provider

    app_detector    = get_app_detector()
    app_ws_notifier = get_app_ws_notifier()
    vt_provider     = get_virustotal_provider()
    uh_provider     = get_urlhaus_provider()
    vt_configured   = bool(app_settings.virustotal.enabled and app_settings.virustotal.api_key)
    uh_configured   = bool(app_settings.urlhaus.enabled and app_settings.urlhaus.auth_key)
    # Use cached or configuration-derived status to prevent consuming external API quotas during routine system health checks
    vt_cached = getattr(vt_provider, "_cached_status", None) if vt_provider else None
    uh_cached = getattr(uh_provider, "_cached_status", None) if uh_provider else None
    vt_st = vt_cached.get("status") if vt_cached else ("READY" if vt_configured else "NOT_CONFIGURED")
    uh_st = uh_cached.get("status") if uh_cached else ("READY" if uh_configured else "NOT_CONFIGURED")

    has_neural = bool(app_detector and app_detector.has_neural_model)
    fallback_active = bool(app_detector and app_detector.is_fallback_active)

    capabilities = {
        "voice_cloning_detector": "NEURAL_READY" if has_neural else ("HEURISTIC_ONLY" if fallback_active else "UNAVAILABLE"),
        "speaker_embedding": "READY" if is_ecapa_available() else "UNAVAILABLE",
        "wav2vec2": "READY" if is_wav2vec2_available() else "UNAVAILABLE",
        "phishing_nlp": "READY" if getattr(app_settings.cyberguard, "phishing_analysis_enabled", True) else "DISABLED",
        "url_forensics": "READY" if getattr(app_settings.cyberguard, "url_analysis_enabled", True) else "DISABLED",
        "qr_forensics": "READY" if getattr(app_settings.cyberguard, "qr_analysis_enabled", True) else "DISABLED",
        "image_forensics": "READY" if getattr(app_settings.cyberguard, "deepfake_image_enabled", True) else "DISABLED",
        "video_forensics": "READY" if getattr(app_settings.cyberguard, "deepfake_video_enabled", True) else "DISABLED",
        "virustotal_intel": vt_st,
        "urlhaus_intel": uh_st,
        "enforcement_shield": "ACTIVE" if getattr(app_settings.enforcement, "enabled", True) else "DISABLED",
    }
    operational_count = sum(
        1 for v in capabilities.values()
        if v in ("READY", "NEURAL_READY", "ACTIVE", "HEURISTIC_ONLY")
    )

    from backend.services.continuous_learning import ContinuousLearningService
    active_det_ver = ContinuousLearningService.get_active_model_version()

    return {
        "status": "operational",
        "active_detector_version": active_det_ver,
        "detector_version": active_det_ver,
        "detector_initialized": has_neural,
        "neural_detector_ready": has_neural,
        "heuristic_fallback_active": fallback_active,
        "detector_mode": "NEURAL" if has_neural else ("HEURISTIC_FALLBACK" if fallback_active else "UNAVAILABLE"),
        "wav2vec2_available": is_wav2vec2_available(),
        "ecapa_available": is_ecapa_available(),
        "connected_clients": app_ws_notifier.connection_count if app_ws_notifier else 0,
        "virustotal_enabled": bool(app_settings.virustotal.enabled),
        "virustotal_configured": bool(app_settings.virustotal.enabled and app_settings.virustotal.api_key),
        "virustotal_status": vt_st,
        "urlhaus_enabled": bool(app_settings.urlhaus.enabled),
        "urlhaus_configured": bool(app_settings.urlhaus.enabled and app_settings.urlhaus.auth_key),
        "urlhaus_status": uh_st,
        "threat_intel_active": (vt_st == "READY") and (uh_st == "READY"),
        "capabilities": capabilities,
        "operational_engine_count": operational_count,
        "total_engine_count": len(capabilities),
        "config": {
            "sample_rate": app_settings.audio.sample_rate,
            "chunk_duration_sec": app_settings.audio.chunk_duration_sec,
            "device": app_settings.detection.device,
            "thresholds": {
                "low": app_settings.risk.alert_thresholds.low,
                "medium": app_settings.risk.alert_thresholds.medium,
                "high": app_settings.risk.alert_thresholds.high,
                "critical": app_settings.risk.alert_thresholds.critical,
            },
        },
    }
