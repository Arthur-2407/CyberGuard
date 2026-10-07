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

# Paths that bypass active blocking checks to prevent lockouts
_BYPASS_PREFIXES = (
    "/static/",
    "/favicon.ico",
    "/health",
    "/docs",
    "/openapi.json",
)


class EnforcementMiddleware(BaseHTTPMiddleware):
    """
    Non-destructive security middleware for automatic containment and DDoS mitigation.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Always permit static assets, favicon, and health checks
        for prefix in _BYPASS_PREFIXES:
            if path.startswith(prefix) or path == prefix:
                return await call_next(request)

        # Extract Client IP
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "127.0.0.1"

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

        # 1. Check IP Blocklist
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
        allowed, ddos_reason, retry_after = engine.check_and_record_request(client_ip)
        if not allowed:
            logger.warning(f"[DDOS SHIELD 429] IP '{client_ip}' throttled on {path}: {ddos_reason}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests (CyberGuard DDoS Shield Active)",
                    "message": ddos_reason or "Request volume exceeds configured policy rate limits.",
                    "retry_after_seconds": retry_after or 30,
                },
                headers={
                    "Retry-After": str(retry_after or 30),
                    "X-CyberGuard-DDoS-Mitigation": "active",
                },
            )

        # Process the request
        return await call_next(request)
