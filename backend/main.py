"""
main.py — CyberGuard FastAPI Application Entry Point.

Initializes:
  - Configuration loading
  - Database setup
  - Model preloading
  - Alert infrastructure (WebSocket notifier + webhook + alert manager)
  - API router registration
  - Static file serving (frontend)
  - CORS configuration

Run with (from project root directory):
  python -m uvicorn backend.main:app --host 0.0.0.0 --port 3000 --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure project root is on PYTHONPATH
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.config import get_settings

# Configure logging
settings = get_settings()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Application-level singletons ───────────────────────────────────────────────
# Use a single authoritative state dict so that every `from backend.main import …`
# call—across reloads and circular imports—always resolves to the same live object.
from backend.detection.detector import VoiceCloneDetector
from backend.alerts.alert_manager import AlertManager
from backend.alerts.websocket_notifier import WebSocketNotifier
from backend.alerts.webhook_notifier import WebhookNotifier
from backend.incidents.incident_manager import IncidentManager

app_settings = get_settings()

_APP_STATE: dict = {
    "detector": None,
    "ws_notifier": None,
    "alert_manager": None,
    "incident_manager": None,
    "virustotal_provider": None,
    "urlhaus_provider": None,
}


def _get_state() -> dict:
    """Return the single authoritative application state dict."""
    return _APP_STATE


def get_app_detector() -> VoiceCloneDetector:
    """Return the live detector singleton."""
    return _APP_STATE["detector"]


def get_app_ws_notifier() -> WebSocketNotifier:
    """Return the live WebSocket notifier singleton."""
    return _APP_STATE["ws_notifier"]


def get_app_alert_manager() -> AlertManager:
    """Return the live alert manager singleton."""
    return _APP_STATE["alert_manager"]

def get_app_incident_manager() -> IncidentManager:
    """Return the live incident manager singleton."""
    return _APP_STATE["incident_manager"]


def get_app_virustotal_provider():
    """Return the live VirusTotal provider singleton."""
    return _APP_STATE["virustotal_provider"]


def get_app_urlhaus_provider():
    """Return the live URLhaus provider singleton."""
    return _APP_STATE["urlhaus_provider"]

# ---------------------------------------------------------------------------
# Backwards-compatible module-level properties:
# Route files that do `from backend.main import app_detector` will get a
# reference to the _APP_STATE dict value at call time via the getter above.
# For legacy attribute access we expose the same objects below, but they are
# re-resolved each request through the getter functions in each route file.
# ---------------------------------------------------------------------------


def _setup_alert_infrastructure():
    """Instantiate and register all notifiers with the alert manager."""
    # Instantiate singletons into the state dict (replaces any prior objects)
    _APP_STATE["ws_notifier"]    = WebSocketNotifier()
    _APP_STATE["alert_manager"]  = AlertManager()
    _APP_STATE["detector"]       = VoiceCloneDetector(app_settings)
    _APP_STATE["incident_manager"] = IncidentManager(
        config=app_settings, 
        db_path=str(app_settings.abs_path(app_settings.storage.db_path))
    ) if getattr(app_settings.cyberguard, "incident_management_enabled", True) else None

    _APP_STATE["alert_manager"].register_notifier(_APP_STATE["ws_notifier"])

    from backend.threats.virustotal import get_virustotal_provider
    from backend.threats.urlhaus import get_urlhaus_provider
    _APP_STATE["virustotal_provider"] = get_virustotal_provider(app_settings)
    _APP_STATE["urlhaus_provider"] = get_urlhaus_provider(app_settings)

    if app_settings.webhooks.enabled and app_settings.webhooks.callback_url:
        webhook = WebhookNotifier(
            callback_url=app_settings.webhooks.callback_url,
            secret_token=app_settings.webhooks.secret_token,
            retry_attempts=app_settings.webhooks.retry_attempts,
            retry_delay_sec=app_settings.webhooks.retry_delay_sec,
            enabled=True,
        )
        _APP_STATE["alert_manager"].register_notifier(webhook)
        logger.info(f"Webhook notifier registered: {app_settings.webhooks.callback_url}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info("=" * 60)
    logger.info("CyberGuard — AI Threat & Voice Cloning Detection System")
    logger.info("Starting up...")
    logger.info("=" * 60)

    # 1. Initialize database & bootstrap auth/model registry
    from backend.storage.database import init_db
    from backend.storage.auth import bootstrap_system
    db_path = str(app_settings.abs_path(app_settings.storage.db_path))
    init_db(db_path)
    bootstrap_system()

    # 2. Create model weights directory
    weights_dir = app_settings.abs_path("backend/models/weights")
    weights_dir.mkdir(parents=True, exist_ok=True)

    # 3. Create data directory
    data_dir = app_settings.abs_path("data")
    data_dir.mkdir(parents=True, exist_ok=True)

    # 4. Set up alert infrastructure + create singletons
    _setup_alert_infrastructure()

    # 5. Initialize detector (loads models)
    logger.info("Initializing detection models (this may take a moment)...")
    try:
        _APP_STATE["detector"].initialize()
        if _APP_STATE["detector"].has_neural_model:
            logger.info("✓ Neural detection model loaded and active.")
        elif _APP_STATE["detector"].is_fallback_active:
            logger.info("✓ Acoustic heuristic fallback active (neural detector.pt absent).")
        else:
            logger.warning("Detection subsystem unavailable.")
    except Exception as exc:
        logger.error(f"Model initialization error: {exc}")
        logger.warning("Detection models unavailable; server running in limited mode.")

    # 6. Set up Zeroconf for local network discovery
    zeroconf_instance = None
    zeroconf_status = "FAILED"
    try:
        from zeroconf import ServiceInfo
        from zeroconf.asyncio import AsyncZeroconf
        import socket
        
        # Determine active local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = '127.0.0.1'
        finally:
            s.close()
            
        if local_ip != '127.0.0.1' and app_settings.server.host == '0.0.0.0':
            desc = {'path': '/health', 'version': '1.0.0', 'app': 'CyberGuard'}
            info_cyber = ServiceInfo(
                "_cyberguard._tcp.local.",
                f"CyberGuard_{local_ip.replace('.', '-')}._cyberguard._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=app_settings.server.port,
                properties=desc,
                server=f"cyberguard-{local_ip.replace('.', '-')}.local.",
            )
            info_voice = ServiceInfo(
                "_voiceguard._tcp.local.",
                f"CyberGuard_{local_ip.replace('.', '-')}._voiceguard._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=app_settings.server.port,
                properties=desc,
                server=f"cyberguard-{local_ip.replace('.', '-')}.local.",
            )
            zeroconf_instance = AsyncZeroconf()
            await zeroconf_instance.async_register_service(info_cyber)
            await zeroconf_instance.async_register_service(info_voice)
            logger.info(f"Zeroconf mDNS service registered (_cyberguard & _voiceguard) on {local_ip}:{app_settings.server.port}")
            zeroconf_status = "READY"
        else:
            logger.info("Zeroconf skipped: Server not bound to 0.0.0.0 or LAN IP unavailable.")
            zeroconf_status = "SKIPPED"
    except ImportError:
        logger.warning("Zeroconf not installed. Automatic network discovery will be unavailable.")
        zeroconf_status = "UNAVAILABLE"
    except Exception as exc:
        logger.exception(f"Failed to start Zeroconf service: {exc}")
        zeroconf_status = "FAILED"

    # 7. Auto-start & link Threat Intelligence Pipeline (VirusTotal + URLhaus)
    from backend.threats.virustotal import init_virustotal_pipeline
    from backend.threats.urlhaus import init_urlhaus_pipeline

    async def _auto_start_threat_intel_pipeline():
        try:
            logger.info("Auto-linking Threat Intelligence Pipeline (VirusTotal & URLhaus)...")
            vt_res, uh_res = await asyncio.gather(
                init_virustotal_pipeline(app_settings),
                init_urlhaus_pipeline(app_settings),
                return_exceptions=True,
            )
            vt_st = vt_res.get("status", "UNAVAILABLE") if isinstance(vt_res, dict) else "ERROR"
            uh_st = uh_res.get("status", "UNAVAILABLE") if isinstance(uh_res, dict) else "ERROR"
            logger.info(f"✓ Threat Intelligence Pipeline connected & operational: VirusTotal={vt_st}, URLhaus={uh_st}")

            ws = _APP_STATE.get("ws_notifier")
            if ws and hasattr(ws, "broadcast_raw"):
                await ws.broadcast_raw({
                    "type": "pipeline_status",
                    "virustotal": vt_res if isinstance(vt_res, dict) else {"status": "ERROR"},
                    "urlhaus": uh_res if isinstance(uh_res, dict) else {"status": "ERROR"},
                })
        except Exception as exc:
            logger.warning(f"Threat Intelligence Pipeline auto-start notice: {exc}")

    # Launch non-blocking background connection task on server startup
    asyncio.create_task(_auto_start_threat_intel_pipeline())

    vt_summary = "READY (auto-linked)" if (app_settings.virustotal.enabled and app_settings.virustotal.api_key) else "DISABLED"
    uh_summary = "READY (auto-linked)" if (app_settings.urlhaus.enabled and app_settings.urlhaus.auth_key) else "DISABLED"

    # Capability Report
    pytorch_status = "UNAVAILABLE"
    wav2vec2_status = "UNAVAILABLE"
    ecapa_status = "UNAVAILABLE"
    
    try:
        import torch
        pytorch_status = "READY"
    except ImportError:
        pass
        
    try:
        import speechbrain
        ecapa_status = "READY"
    except ImportError:
        pass

    try:
        import transformers
        wav2vec2_status = "READY"
    except ImportError:
        pass

    if _APP_STATE.get("detector") and _APP_STATE["detector"].has_neural_model:
        detector_status_str = "READY (Neural Model Active)"
    elif _APP_STATE.get("detector") and _APP_STATE["detector"].is_fallback_active:
        detector_status_str = "FALLBACK (Acoustic Heuristic Active — detector.pt absent)"
    else:
        detector_status_str = "UNAVAILABLE"

    logger.info("=== CAPABILITY REPORT ===")
    logger.info("  Server:      READY")
    logger.info("  WebSocket:   READY")
    logger.info(f"  PyTorch:     {pytorch_status}")
    logger.info(f"  SpeechBrain: {ecapa_status}")
    logger.info(f"  Wav2Vec2:    {wav2vec2_status}")
    logger.info(f"  ECAPA:       {ecapa_status}")
    logger.info(f"  Detector:    {detector_status_str}")
    logger.info(f"  Zeroconf:    {zeroconf_status}")
    logger.info(f"  VirusTotal:  {vt_summary}")
    logger.info(f"  URLhaus:     {uh_summary}")
    logger.info("=========================")

    logger.info("CyberGuard is ready.")
    logger.info(f"  API:      http://{app_settings.server.host}:{app_settings.server.port}")
    logger.info(f"  Frontend: http://127.0.0.1:{app_settings.server.port}")
    logger.info(f"  Docs:     http://127.0.0.1:{app_settings.server.port}/docs")

    yield

    # Shutdown
    logger.info("CyberGuard shutting down...")
    from backend.models.model_loader import unload_model
    unload_model()
    
    if zeroconf_instance:
        try:
            await zeroconf_instance.async_unregister_all_services()
            await zeroconf_instance.async_close()
            logger.info("Zeroconf service unregistered.")
        except Exception as exc:
            logger.error(f"Error unregistering Zeroconf: {exc}")
            
    logger.info("Goodbye.")


# ── FastAPI Application ────────────────────────────────────────────────────────
app = FastAPI(
    title="CyberGuard — SOC Threat Intelligence & Multi-Modal AI Defense Console",
    description=(
        "Real-time enterprise cyber threat detection, AI voice clone defense, "
        "phishing, QR forensics, and multi-provider threat intelligence."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS (configurable origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=app_settings.server.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Route Registration ─────────────────────────────────────────────────────────
from backend.api.routes_stream import router as stream_router
from backend.api.routes_analyze import router as analyze_router
from backend.api.routes_enroll import router as enroll_router
from backend.api.routes_alerts_config import alerts_router, config_router
from backend.api.routes_threats import router as threats_router
from backend.api.routes_incidents import router as incidents_router
from backend.api.routes_auth import router as auth_router
from backend.api.routes_admin import router as admin_router

app.include_router(auth_router)       # REST: /api/auth/*
app.include_router(admin_router)      # REST: /api/admin/*
app.include_router(stream_router)     # WebSocket: /ws/stream
app.include_router(analyze_router)    # REST: /api/analyze
app.include_router(enroll_router)     # REST: /api/speakers/*
app.include_router(alerts_router)     # REST: /api/alerts/*
app.include_router(config_router)     # REST: /api/config/*
app.include_router(threats_router)    # REST: /api/threats/*
app.include_router(incidents_router)  # REST: /api/incidents/*

# ── Serve Frontend ─────────────────────────────────────────────────────────────
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"
if _FRONTEND_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(_FRONTEND_DIR)),
        name="static",
    )

    @app.get("/", include_in_schema=False)
    @app.get("/security-center", include_in_schema=False)
    @app.get("/incidents", include_in_schema=False)
    @app.get("/alerts", include_in_schema=False)
    async def serve_frontend():
        return FileResponse(str(_FRONTEND_DIR / "index.html"))

# ── Health Check ───────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "service": "CyberGuard",
        "version": "1.0.0",
    }
