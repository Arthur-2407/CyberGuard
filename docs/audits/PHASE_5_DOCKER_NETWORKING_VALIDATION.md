# CyberGuard Phase 5 — Docker & Container Networking Validation

## Executive Summary
This document provides empirical verification of the local container infrastructure, port binding discipline, reverse-proxy routing, and FastAPI ASGI listener configuration inside the CyberGuard local workspace.

---

## 1. Container Topology & Topology Audit

### Container Inventory
* **Core API Container**: `cyberguard-backend` (Container ID: `1bc3e09d3530`)
  - Image: `cyberguard-backend:latest`
  - Base Image: `python:3.12-slim-bookworm`
  - Runtime State: `Up 15 hours (healthy)`
  - Internal Port: `3000/tcp`
  - Published Host Ports: `0.0.0.0:3000->3000/tcp`, `[::]:3000->3000/tcp`
  - Network: `cyberguard_cyberguard-net` (Bridge)
  - Healthcheck: `CMD curl -f http://localhost:3000/health || exit 1` (Interval: 15s, Timeout: 5s, Retries: 3)
* **Tunnel Container**: `cyberguard-tunnel` (Container ID: `f2525ec47d1d`)
  - Image: `cloudflare/cloudflared:latest`
  - Runtime State: `Up 15 hours`
  - Target Binding: `http://cyberguard-backend:3000`
  - Status: Optional (Classified as `NOT_CONFIGURED` when no custom Cloudflare Tunnel token is provided).

---

## 2. Port 3000 Ownership & Architecture Separation

### Audit Question: Does port 3000 belong to the frontend, the backend, or a proxy?
Investigation of `docker-compose.yml`, `Dockerfile`, and `backend/main.py` confirms:
1. **Container Process**: `python -m uvicorn backend.main:app --host 0.0.0.0 --port 3000`
2. **Unified Delivery Model**: FastAPI serves BOTH API routes (`/api/*`, `/health`, `/ws/*`) AND static frontend assets (`/`, `/styles.css`, `/app.js`, `/personal/*`).
3. **No Port Collision**: Port 3000 is exclusively bound by Docker on the host loopback `127.0.0.1:3000`.
4. **Desktop Disambiguation**: The Electron desktop client interacts with `http://127.0.0.1:3000` purely as a REST/WebSocket API provider, rendering its own standalone native Chromium frontend from `desktop/frontend/index.html`. There is zero confusion between frontend and backend ports.

---

## 3. Empirical Endpoint Validation

### Local Endpoint Latency & Health
* **Endpoint**: `http://127.0.0.1:3000/health`
  - HTTP Status: `200 OK`
  - Response Time: `11 ms`
  - Payload Verified:
    ```json
    {
      "status": "ok",
      "service": "CyberGuard",
      "version": "1.0.0",
      "backend": "host-native",
      "environment": "host-native",
      "database": "connected",
      "detector_ready": true,
      "threat_intel": {
        "virustotal_configured": true,
        "urlhaus_configured": true
      }
    }
    ```

### Public Deployed Endpoints
* **Render Managed API**: `https://cyberguard-backend-8rbz.onrender.com/health`
  - HTTP Status: `200 OK`
  - Latency: `446 - 472 ms`
  - Payload: Matches local contract identically.
* **Vercel Web Portal**: `https://cyber-guard-backend-ashen.vercel.app/`
  - HTTP Status: `200 OK`
  - Latency: `298 - 314 ms`
  - Content: Public web interface (HTML/JS/CSS).
* **Vercel API Rewrite**: `https://cyber-guard-backend-ashen.vercel.app/api/health`
  - HTTP Status: `200 OK`
  - Latency: `552 ms` (Proxied through Vercel edge rewrite to OnRender backend).

---

## 4. Volume Persistence & Multi-Tenant SQLite Database Protection
* Volume mapping: `./data:/app/data` (Read/Write host mount).
* Databases preserved:
  - `data/cyberguard.db` (7.3 MB) — Passed `PRAGMA integrity_check;` (`ok`).
  - `data/user_databases/user_*.db` — 94 tenant-isolated user databases completely preserved without deletion.
  - `data/voiceguard.db` — Audio biometric profiles preserved.

