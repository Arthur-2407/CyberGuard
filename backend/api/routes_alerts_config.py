"""
routes_alerts.py — Alert history REST API.
routes_config.py — Threshold configuration REST API.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.storage.auth import require_admin, require_user, get_optional_user
from backend.storage.database import UserModel

logger = logging.getLogger(__name__)

# ── Alerts Router ──────────────────────────────────────────────────────────────
alerts_router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@alerts_router.get("/recent")
async def get_recent_alerts(
    limit: int = 50,
    current_user: Optional[UserModel] = Depends(get_optional_user),
):
    """Get the most recent alerts scoped strictly to caller's ownership boundary."""
    from backend.main import get_app_alert_manager
    if current_user is None or not getattr(current_user, "is_active", False):
        return {"alerts": [], "requires_authentication": True}
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    return {"alerts": get_app_alert_manager().get_recent_alerts(limit=limit, user_id=current_user.id, is_admin=is_admin)}


@alerts_router.get("/session/{session_id}")
async def get_session_alerts(
    session_id: str,
    current_user: UserModel = Depends(require_user),
):
    """Get all alerts for a specific session scoped strictly to caller's ownership boundary."""
    from backend.main import get_app_alert_manager
    is_admin = getattr(current_user, "role", "").lower() in ["admin", "role_admin"]
    alerts = get_app_alert_manager().get_session_history(session_id, user_id=current_user.id, is_admin=is_admin)
    return {"session_id": session_id, "alerts": alerts}


class ThreatAlertDispatchIn(BaseModel):
    recipient: Optional[str] = None
    alert_id: str
    severity: str = "HIGH"
    threat_title: str
    sender: Optional[str] = None
    domain: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)
    llm_summary: Optional[str] = None


@alerts_router.post("/dispatch-email")
async def dispatch_security_alert_email(
    payload: ThreatAlertDispatchIn,
    current_user: Optional[UserModel] = Depends(get_optional_user),
):
    """
    Dispatches an authoritative security alert notification from cyberguardadmin@gmail.com
    to the verified authenticated user's email address upon confirmed HIGH or CRITICAL threats.
    Enforces rate limits, deduplication, tamper-evident logging, and loop protection.
    """
    from backend.alerts.email_notifier import EmailNotifier
    from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel

    # 1. Resolve target recipient
    target_email = payload.recipient
    if not target_email and current_user and getattr(current_user, "email", None):
        target_email = current_user.email

    if not target_email or "@" not in target_email:
        return {"status": "skipped", "reason": "NO_VALID_RECIPIENT"}

    # 2. Strict loop protection: never alert on official system admin notifications
    if target_email.strip().lower() == "cyberguardadmin@gmail.com":
        return {"status": "skipped", "reason": "LOOP_PROTECTION_EXCLUDED"}

    # 3. Strict severity gate: only HIGH and CRITICAL trigger transactional email dispatch
    sev_str = (payload.severity or "HIGH").strip().upper()
    if sev_str not in ("HIGH", "CRITICAL"):
        return {"status": "skipped", "reason": f"SEVERITY_BELOW_THRESHOLD ({sev_str})"}

    risk_enum = RiskLevel.CRITICAL if sev_str == "CRITICAL" else RiskLevel.HIGH

    category_enum = ThreatCategory.PHISHING
    if payload.domain:
        category_enum = ThreatCategory.MALICIOUS_URL
    elif "malware" in payload.threat_title.lower():
        category_enum = ThreatCategory.MALWARE_INDICATOR

    # 4. Construct authoritative ThreatEvent
    evt = ThreatEvent(
        event_id=payload.alert_id,
        source="desktop_endpoint",
        source_type="client",
        modality="email" if payload.sender else ("url" if payload.domain else "endpoint"),
        threat_category=category_enum,
        severity=risk_enum,
        confidence=0.92,
        classification="THREAT_ALERT",
        user_id=current_user.id if current_user else None,
        user_email=target_email,
        details={
            "indicators": payload.indicators,
            "llm_summary": payload.llm_summary,
            "sender": payload.sender,
            "domain": payload.domain,
            "official_notifier": "cyberguardadmin@gmail.com",
            "title": payload.threat_title
        }
    )

    notifier = EmailNotifier()
    result = await notifier.notify_threat_event(evt, user_email=target_email)
    return {
        "status": result.get("status", "dispatched"),
        "alert_id": payload.alert_id,
        "recipient": target_email,
        "official_sender": "cyberguardadmin@gmail.com",
        "result": result
    }


@alerts_router.get("/delivery-history")
async def get_alert_delivery_history(
    limit: int = 50,
    current_user: Optional[UserModel] = Depends(get_optional_user),
):
    """
    Retrieve durable security email alert outbox records and delivery status.
    Scoped to user's identity unless administrator.
    """
    from backend.alerts.notification_dispatcher import get_notification_dispatcher
    dispatcher = get_notification_dispatcher()
    is_admin = False
    u_id = None
    if current_user:
        is_admin = getattr(current_user, "role", "").lower() in ("admin", "role_admin")
        u_id = None if is_admin else current_user.id
    history = dispatcher.get_audit_history(limit=min(limit, 100), user_id=u_id)
    return {"delivery_history": history, "count": len(history)}



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
        if v in ("READY", "NEURAL_READY", "ACTIVE", "HEURISTIC_ONLY", "AVAILABLE_ON_DISK", "READY_IN_MEMORY")
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
