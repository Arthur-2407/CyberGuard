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
from typing import Optional

# Ensure project root is on PYTHONPATH
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Bound thread stack overhead in containerized environments (Render / Linux cgroups)
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

try:
    import torch
    default_threads = int(os.getenv("TORCH_NUM_THREADS", str(min(4, os.cpu_count() or 1))))
    torch.set_num_threads(default_threads)
    if hasattr(torch, "set_num_interop_threads"):
        try:
            torch.set_num_interop_threads(min(2, default_threads))
        except Exception:
            pass
except Exception:
    pass

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import get_settings

# Configure logging with sensitive parameter redaction
import re

class SensitiveDataFilter(logging.Filter):
    """Redact sensitive credentials (tokens, auth keys, passwords) from access & server logs."""
    _PATTERN = re.compile(r'([?&](?:token|key|secret|password|auth|api_key)=)[^&\s]+', re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            new_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    new_args.append(self._PATTERN.sub(r'\1[REDACTED]', arg))
                else:
                    new_args.append(arg)
            record.args = tuple(new_args)
        if isinstance(record.msg, str):
            record.msg = self._PATTERN.sub(r'\1[REDACTED]', record.msg)
        return True

settings = get_settings()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Attach sensitive data redactor to all loggers including uvicorn.access
sensitive_filter = SensitiveDataFilter()
logging.getLogger().addFilter(sensitive_filter)
logging.getLogger("uvicorn.access").addFilter(sensitive_filter)

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
    detector = _APP_STATE.get("detector")
    if detector is None:
        detector = VoiceCloneDetector(app_settings)
        detector.initialize()
        _APP_STATE["detector"] = detector
    return detector


def get_app_ws_notifier() -> WebSocketNotifier:
    """Return the live WebSocket notifier singleton with lazy init."""
    if _APP_STATE.get("ws_notifier") is None:
        _setup_alert_infrastructure()
    return _APP_STATE["ws_notifier"]


def get_app_alert_manager() -> AlertManager:
    """Return the live alert manager singleton with lazy init."""
    if _APP_STATE.get("alert_manager") is None:
        _setup_alert_infrastructure()
    return _APP_STATE["alert_manager"]


def get_app_incident_manager() -> Optional[IncidentManager]:
    """Return the live incident manager singleton with lazy init."""
    if _APP_STATE.get("incident_manager") is None and getattr(app_settings.cyberguard, "incident_management_enabled", True):
        _setup_alert_infrastructure()
    return _APP_STATE["incident_manager"]


def get_app_virustotal_provider():
    """Return the live VirusTotal provider singleton with lazy init."""
    provider = _APP_STATE.get("virustotal_provider")
    if provider is None:
        from backend.threats.virustotal import get_virustotal_provider
        provider = get_virustotal_provider(app_settings)
        _APP_STATE["virustotal_provider"] = provider
    return provider


def get_app_urlhaus_provider():
    """Return the live URLhaus provider singleton with lazy init."""
    provider = _APP_STATE.get("urlhaus_provider")
    if provider is None:
        from backend.threats.urlhaus import get_urlhaus_provider
        provider = get_urlhaus_provider(app_settings)
        _APP_STATE["urlhaus_provider"] = provider
    return provider

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

    from backend.alerts.email_notifier import get_email_notifier
    _APP_STATE["email_notifier"] = get_email_notifier()
    _APP_STATE["alert_manager"].register_notifier(_APP_STATE["email_notifier"])

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

    # 4b. Initialize Policy Enforcement & DDoS Protection Engine
    from backend.security.enforcement import get_enforcement_engine
    get_enforcement_engine()
    logger.info("✓ Security Policy Enforcement & DDoS Shield active.")

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
        
        # Enumerate all active local non-loopback IPv4 addresses
        local_ips = []
        try:
            _, _, host_ips = socket.gethostbyname_ex(socket.gethostname())
            for ip in host_ips:
                if not ip.startswith('127.') and not ip.startswith('169.254.') and ip not in local_ips:
                    local_ips.append(ip)
        except Exception:
            pass

        # Also fallback to default route socket probe
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            sock_ip = s.getsockname()[0]
            if sock_ip not in local_ips and not sock_ip.startswith('127.'):
                local_ips.append(sock_ip)
        except Exception:
            pass
        finally:
            s.close()

        if local_ips and app_settings.server.host == '0.0.0.0':
            desc = {'path': '/health', 'version': '1.0.0', 'app': 'CyberGuard'}
            zeroconf_instance = AsyncZeroconf()
            registered_count = 0
            for ip in local_ips:
                try:
                    safe_ip = ip.replace('.', '-')
                    info_cyber = ServiceInfo(
                        "_cyberguard._tcp.local.",
                        f"CyberGuard_{safe_ip}._cyberguard._tcp.local.",
                        addresses=[socket.inet_aton(ip)],
                        port=app_settings.server.port,
                        properties=desc,
                        server=f"cyberguard-{safe_ip}.local.",
                    )
                    info_voice = ServiceInfo(
                        "_voiceguard._tcp.local.",
                        f"CyberGuard_{safe_ip}._voiceguard._tcp.local.",
                        addresses=[socket.inet_aton(ip)],
                        port=app_settings.server.port,
                        properties=desc,
                        server=f"cyberguard-{safe_ip}.local.",
                    )
                    await zeroconf_instance.async_register_service(info_cyber)
                    await zeroconf_instance.async_register_service(info_voice)
                    registered_count += 1
                except Exception as reg_err:
                    logger.warning(f"Zeroconf registration notice for interface {ip}: {reg_err}")

            if registered_count > 0:
                logger.info(f"Zeroconf mDNS registered across {registered_count} interfaces ({', '.join(local_ips)}) on port {app_settings.server.port}")
                zeroconf_status = "READY"
            else:
                zeroconf_status = "DEGRADED"
        else:
            logger.info("Zeroconf skipped: Server not bound to 0.0.0.0 or LAN IP unavailable.")
            zeroconf_status = "SKIPPED"
    except ImportError:
        logger.warning("Zeroconf not installed. Automatic network discovery will be unavailable.")
        zeroconf_status = "UNAVAILABLE"
    except Exception as exc:
        logger.warning(f"Zeroconf service initialization notice: {exc}")
        zeroconf_status = "FAILED"

    # 7. Threat Intelligence Pipeline Setup (VirusTotal + URLhaus)
    # Providers are configured in memory without making outbound API requests on startup or reload.
    # Outbound queries are exclusively initiated when interacting within the Phishing & URL tab.
    from backend.threats.virustotal import get_virustotal_provider
    from backend.threats.urlhaus import get_urlhaus_provider

    vt_prov = get_virustotal_provider(app_settings)
    uh_prov = get_urlhaus_provider(app_settings)
    vt_is_ready = vt_prov.is_configured
    uh_is_ready = uh_prov.is_configured

    vt_summary = "READY (configured)" if vt_is_ready else "DISABLED"
    uh_summary = "READY (configured)" if uh_is_ready else "DISABLED"
    logger.info(f"Threat Intelligence Subsystem initialized: VirusTotal={vt_summary}, URLhaus={uh_summary}")

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

    # 8. Bidirectional Database Synchronization (Cloud PostgreSQL <-> Local SQLite)
    sync_task = None
    try:
        from backend.storage.sync_service import get_sync_service
        sync_svc = get_sync_service()
        if sync_svc.is_cloud_available():
            logger.info("Scheduling non-blocking baseline bidirectional database sync in background...")
            asyncio.create_task(sync_svc.async_sync_bidirectional())
            logger.info("✓ Continuous bidirectional database sync active (Cloud Supabase <-> Local SQLite).")
        else:
            logger.info("Cloud database unreachable at startup; operating in local resilient mode.")

        # Always start periodic sync so reconnection automatically triggers cloud sync
        sync_task = asyncio.create_task(sync_svc.run_periodic_sync(interval_sec=30))
    except Exception as sync_exc:
        logger.warning(f"Database sync service initialization notice: {sync_exc}")

    logger.info("CyberGuard is ready.")
    logger.info(f"  API:      http://{app_settings.server.host}:{app_settings.server.port}")
    logger.info(f"  Frontend: http://127.0.0.1:{app_settings.server.port}")
    logger.info(f"  Docs:     http://127.0.0.1:{app_settings.server.port}/docs")

    yield

    # Shutdown
    logger.info("CyberGuard shutting down...")
    if sync_task:
        sync_task.cancel()
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

# CORS (configurable origins with cloud deployment support)
_default_trusted_origins = [
    "https://arthur-2407.github.io",
    "https://cyber-guard-backend-ashen.vercel.app",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]
_cors_origins = list(app_settings.server.cors_origins)
for o in _default_trusted_origins:
    if o not in _cors_origins:
        _cors_origins.append(o)

_env_origins = os.getenv("CYBERGUARD_CORS_ORIGINS", "")
if _env_origins:
    _cors_origins.extend([o.strip() for o in _env_origins.split(",") if o.strip()])

_cors_regex = os.getenv(
    "CYBERGUARD_CORS_REGEX",
    r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|.*\.vercel\.app|.*\.pages\.dev|.*\.github\.io|.*\.trycloudflare\.com|.*\.ngrok-free\.app|.*\.loca\.lt)(:\d+)?$"
)

_cors_pattern = re.compile(_cors_regex)

class PrivateNetworkAccessMiddleware(BaseHTTPMiddleware):
    """
    Handle W3C Private Network Access (PNA) preflights and response headers.
    Enables secure loopback / LAN connectivity from deployed HTTPS frontends (e.g. GitHub Pages, Vercel)
    to the Docker container backend on localhost without browser CORS or PNA rejections.
    """
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin", "")
        is_pna = request.headers.get("access-control-request-private-network") == "true"
        is_allowed = bool(origin and (_cors_pattern.match(origin) or origin in _cors_origins))

        if request.method == "OPTIONS" and is_pna:
            resp = Response(status_code=204)
            if is_allowed:
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Credentials"] = "true"
            elif "*" in _cors_origins:
                resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Access-Control-Allow-Private-Network"] = "true"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"
            req_headers = request.headers.get("access-control-request-headers")
            resp.headers["Access-Control-Allow-Headers"] = req_headers or "Authorization, Content-Type, Accept, X-Requested-With, X-Session-ID, X-Threat-Scope, X-Device-Fingerprint"
            resp.headers["Access-Control-Max-Age"] = "86400"
            resp.headers["Vary"] = "Origin, Access-Control-Request-Private-Network, Access-Control-Request-Method, Access-Control-Request-Headers"
            return resp

        response = await call_next(request)
        if is_pna or is_allowed:
            response.headers["Access-Control-Allow-Private-Network"] = "true"
        return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=_cors_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_private_network=True,
)
app.add_middleware(PrivateNetworkAccessMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Enforcement & DDoS Shield Middleware
from backend.security.middleware import EnforcementMiddleware
app.add_middleware(EnforcementMiddleware)

@app.middleware("http")
async def malware_upload_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/threats/malware/scan") and request.method == "POST":
        content_length = request.headers.get("content-length")
        max_bytes = getattr(app_settings.malware, "max_scan_size_bytes", 1073741824)
        if content_length and content_length.isdigit() and int(content_length) > max_bytes:
            size_str = "1 GB" if max_bytes >= 1073741824 else f"{max_bytes / (1024*1024):.0f} MB"
            return JSONResponse(
                status_code=413,
                content={"detail": f"Uploaded artifact exceeds maximum authorized scan size ({size_str})."}
            )
    return await call_next(request)

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

    @app.get("/styles.css", include_in_schema=False)
    async def serve_styles():
        return FileResponse(
            str(_FRONTEND_DIR / "styles.css"),
            media_type="text/css",
            headers={"Cache-Control": "public, max-age=300, stale-while-revalidate=86400"},
        )

    @app.get("/app.js", include_in_schema=False)
    async def serve_app():
        return FileResponse(
            str(_FRONTEND_DIR / "app.js"),
            media_type="application/javascript",
            headers={"Cache-Control": "public, max-age=300, stale-while-revalidate=86400"},
        )

    @app.get("/config.js", include_in_schema=False)
    async def serve_config():
        config_file = _FRONTEND_DIR / "config.js"
        if config_file.exists():
            return FileResponse(str(config_file), media_type="application/javascript")
        return Response(content="window.__CYBERGUARD_CONFIG__ = window.__CYBERGUARD_CONFIG__ || {};", media_type="application/javascript")

    @app.get("/logo_full.png", include_in_schema=False)
    @app.get("/logo.png", include_in_schema=False)
    async def serve_logo():
        return FileResponse(str(_FRONTEND_DIR / "logo_full.png"), media_type="image/png")

    @app.get("/sounds/{filename}", include_in_schema=False)
    async def serve_sounds(filename: str):
        sound_file = _FRONTEND_DIR / "sounds" / filename
        if sound_file.exists():
            media = "audio/wav" if filename.endswith(".wav") else "audio/mpeg"
            return FileResponse(str(sound_file), media_type=media)
        return Response(status_code=404)

# ── Health & Favicon ───────────────────────────────────────────────────────────
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Return CyberGuard SVG shield favicon with 24h client-side caching."""
    svg_favicon = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<path fill="#020617" d="M0 0h32v32H0z"/>'
        '<path fill="#06b6d4" d="M16 3l11 4v8c0 8.5-5 13-11 14C10 28 5 23.5 5 15V7l11-4z"/>'
        '<path fill="#0f172a" d="M16 6.5l8 3v5.5c0 6.5-3.5 10-8 11-4.5-1-8-4.5-8-11V9.5l8-3z"/>'
        '<circle cx="16" cy="15" r="3.5" fill="#38bdf8"/>'
        '</svg>'
    )
    return Response(
        content=svg_favicon,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
async def health_check():
    detector = _APP_STATE.get("detector")
    detector_ready = detector is not None and (detector.has_neural_model or detector.is_fallback_active)
    vt_prov = _APP_STATE.get("virustotal_provider")
    uh_prov = _APP_STATE.get("urlhaus_provider")
    is_docker = os.path.exists("/.dockerenv") or os.getenv("RUNNING_IN_DOCKER", "").lower() in ("true", "1")
    backend_env = os.getenv("CYBERGUARD_BACKEND_ENV") or ("docker-local" if is_docker else "host-native")
    return {
        "status": "ok",
        "service": "CyberGuard",
        "version": "1.0.0",
        "backend": backend_env,
        "environment": backend_env,
        "database": "connected",
        "detector_ready": bool(detector_ready),
        "threat_intel": {
            "virustotal_configured": bool(vt_prov and vt_prov.is_configured),
            "urlhaus_configured": bool(uh_prov and uh_prov.is_configured),
        }
    }


@app.get("/api/sync/status", tags=["Database"])
async def get_db_sync_status():
    """Return live status of Cloud PostgreSQL and Local SQLite synchronization."""
    from backend.storage.sync_service import get_sync_service
    return get_sync_service().get_status()


@app.post("/api/sync/bidirectional", tags=["Database"])
async def trigger_db_sync():
    """Trigger an on-demand bidirectional synchronization run."""
    from backend.storage.sync_service import get_sync_service
    return await get_sync_service().async_sync_bidirectional()
# Auto-reload trigger: v008 restored

