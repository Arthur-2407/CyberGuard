"""
middleware.py — FastAPI Enforcement, Rate-Limiting & DDoS Shield Middleware.

Intercepts requests to:
  - Filter blocked IPs and quarantined device fingerprints
  - Enforce volumetric DDoS mitigation and burst protection
  - Allow seamless passthrough for static assets, health checks, and admin loopback
"""

from __future__ import annotations

import hashlib
import logging
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.security.enforcement import get_enforcement_engine

logger = logging.getLogger(__name__)

# Paths and static extensions that bypass active blocking checks to prevent lockouts
_BYPASS_PREFIXES = (
    "/static/",
    "/favicon.ico",
    "/health",
    "/api/health",
    "/docs",
    "/openapi.json",
    "/sounds/",
)

_STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".mp3", ".wav", ".webmanifest",
)

_STATIC_PATHS = {
    "/", "/styles.css", "/app.js", "/config.js", "/logo_full.png", "/logo.png",
    "/favicon.ico", "/index.html", "/health.json",
}


def _is_docker_bridge_gateway(ip: str) -> bool:
    """Detect if an IP is within Docker's default RFC1918 bridge subnet (172.16.0.0/12)."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        try:
            return 16 <= int(parts[1]) <= 31
        except ValueError:
            return False
    return False


class EnforcementMiddleware(BaseHTTPMiddleware):
    """
    Non-destructive security middleware for automatic containment and DDoS mitigation.
    Ensures legitimate application navigation and static assets are never blocked while
    actively shielding APIs and protected services against abusive traffic.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Preflight OPTIONS requests must never be throttled or blocked
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path

        # Always permit static assets, favicon, frontend bundle, and health checks
        if path in _STATIC_PATHS or any(path.endswith(ext) for ext in _STATIC_EXTENSIONS):
            return await call_next(request)

        for prefix in _BYPASS_PREFIXES:
            if path.startswith(prefix) or path == prefix:
                return await call_next(request)

        # Extract Client IP securely
        socket_host = request.client.host if request.client else "127.0.0.1"
        from backend.config import get_settings
        server_cfg = getattr(get_settings(), "server", None)
        trusted_proxies = set(getattr(server_cfg, "trusted_proxies", ["127.0.0.1", "::1"]))

        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for and (socket_host in trusted_proxies or _is_docker_bridge_gateway(socket_host)):
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = socket_host

        # Extract or synthesize device fingerprint
        user_agent = request.headers.get("User-Agent", "Unknown")
        device_header = request.headers.get("X-Device-Fingerprint")
        if device_header:
            device_fp = device_header.strip()
        else:
            # Deterministic fingerprint from User-Agent + Accept-Language
            accept_lang = request.headers.get("Accept-Language", "")
            raw_fp = f"{user_agent}|{accept_lang}"
            device_fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:24]

        request.state.client_ip = client_ip
        request.state.device_fingerprint = device_fp

        engine = get_enforcement_engine()

        # Isolate rate limiting key: if behind shared Docker container bridge NAT gateway,
        # key by IP + device fingerprint to prevent multiple local clients from starving one another.
        if _is_docker_bridge_gateway(client_ip):
            rate_key = f"{client_ip}#{device_fp}"
        else:
            rate_key = client_ip

        # 1. Check IP Blocklist (enforced on API and WebSocket routes)
        is_api_or_ws = path.startswith("/api/") or path.startswith("/ws/")
        if is_api_or_ws:
            is_blocked, ip_reason = engine.is_ip_blocked(client_ip)
            if is_blocked:
                logger.warning(f"[ENFORCEMENT 403] Blocked IP '{client_ip}' attempted access to {path}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access Denied by CyberGuard Policy Enforcement",
                        "reason": ip_reason or "IP address is currently quarantined.",
                        "client_ip": client_ip,
                        "incident_response": "Contact your SOC administrator or authenticate with admin privileges to request unblock.",
                    },
                    headers={"X-CyberGuard-Blocked": "true", "X-CyberGuard-Entity": "IP"},
                )

            # 2. Check Device Quarantine
            is_dev_blocked, dev_reason = engine.is_device_blocked(device_fp)
            if is_dev_blocked:
                logger.warning(f"[ENFORCEMENT 403] Blocked Device '{device_fp}' attempted access to {path}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Device Quarantined by CyberGuard Policy Enforcement",
                        "reason": dev_reason or "Device hardware/browser signature has been revoked.",
                        "device_fingerprint": device_fp,
                    },
                    headers={"X-CyberGuard-Blocked": "true", "X-CyberGuard-Entity": "DEVICE"},
                )

        # 3. DDoS Rate Limiting & Burst Protection
        allowed, ddos_reason, retry_after = engine.check_and_record_request(
            rate_key, path=path, client_ip=client_ip, method=request.method
        )
        if not allowed:
            logger.warning(f"[DDOS SHIELD 429] Key '{rate_key}' throttled on {path}: {ddos_reason}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests (CyberGuard DDoS Shield Active)",
                    "message": ddos_reason or "Request volume exceeds configured policy rate limits.",
                    "retry_after_seconds": retry_after or 5,
                },
                headers={
                    "Retry-After": str(retry_after or 5),
                    "X-CyberGuard-DDoS-Mitigation": "active",
                },
            )

        # Process the request
        return await call_next(request)
