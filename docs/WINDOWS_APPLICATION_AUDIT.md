# CyberGuard Windows Application — Comprehensive Forensic Audit & Baseline Report

**Document ID:** `CG-WIN-AUDIT-001`  
**Date:** November 8, 2026  
**Auditor:** Principal Windows Security Architect & Systems Protection Engineer  
**Workspace Root:** `D:\BPUT`  
**Baseline Commit:** `ecfaeb3` (feat: switchable SOC/Personal modes, zero-trust isolation, calibrated forensics)

---

## 1. Executive Summary & Purpose

This forensic audit report establishes the authoritative baseline for the CyberGuard Windows desktop transformation. Following the mandate defined in the Master Hyper-Prompt (`hyper.md`), this investigation examined the complete repository structure, the supplied executable build artifacts (`dist/windows/CyberGuard-Setup.exe` and `win-unpacked/CyberGuard.exe`), the Electron desktop scaffolding, the FastAPI backend routes and database schemas, the Android client implementation, the Chrome extension shield, and the deployed cloud environment.

### Core Architectural Finding
The existing desktop package was essentially a web browser wrapper bundling the central web console (`frontend/index.html`) inside an Electron shell without an independent desktop security architecture:
1. **Packaging Deficit:** While the NSIS installer (`CyberGuard-Setup.exe`, 82.9 MB) and unpacked build (`win-unpacked/CyberGuard.exe`, 188.9 MB) exist, no standalone Portable Edition executable existed.
2. **Security Vulnerability:** `desktop/main.js` globally intercepted and mutated all outgoing and incoming HTTP headers (`*://*/*`), forcibly injecting wildcard CORS (`access-control-allow-origin: *`) and credentials (`access-control-allow-credentials: true`) across the entire session to circumvent `file://` origin constraints.
3. **Configuration Drift:** `desktop/preload.js` hardcoded a fallback cloud endpoint to `https://cyberguard-backend-8rbz.onrender.com`, while the public web deployment is hosted at `https://cyber-guard-backend-ashen.vercel.app` (which proxies `/api/*` to the OnRender service via `vercel.json`).
4. **Missing Native Endpoint Controls:** The desktop lacked real-time filesystem change monitoring (event queues, crypto hashing, PE entropy analysis), process/execution observation, a safe quarantine vault, desktop notification handlers tied to real threats, and native DNS/network blocking integration.
5. **UI Mismatch:** The desktop UI presented the website's dark neon HUD layout with top-horizontal navigation, rather than an independent endpoint security product featuring a clean left navigation rail, light neutral palette, and genuine host protection telemetry.

---

## 2. Windows Executable & Distribution Audit (`dist/windows`)

### 2.1 File Inventory and Hashes
| Artifact | Path | Size | SHA-256 Hash | Status |
| :--- | :--- | :--- | :--- | :--- |
| **NSIS Installer** | `dist\windows\CyberGuard-Setup.exe` | 82,880,974 B (~82.9 MB) | `DCEA9EB1C9347CA15B8E4221BE0DB62D4F3C60E171E0899AA2D53083F5D51CBA` | Verified Present |
| **Unpacked Executable** | `dist\windows\win-unpacked\CyberGuard.exe` | 188,850,688 B (~188.9 MB) | `E6FE3FCE0D19359A37A645E2946C8FEC673E97B356E064B7E24E8ED1C64DE2C5` | Verified Present |
| **Packaged ASAR** | `dist\windows\win-unpacked\resources\app.asar` | 4,743,479 B (~4.7 MB) | `0B1C43BEBFA4C1085F17A93F5CAFE8D8C4EE0AE88B673E3FE6B29C69493B13C6` | Verified Present |
| **Portable Edition** | `CyberGuard-Portable.exe` | N/A | Missing | **Absent from dist/** |

*Safety Measure:* The initial installer artifact was backed up to `dist_backup/CyberGuard-Setup.original.exe` (SHA-256 verified) to ensure 100% non-destructive engineering.

### 2.2 Electron Architecture & Packaging Manifest (`desktop/package.json`)
The desktop project is configured with:
- Electron version: `^33.2.1`
- electron-builder version: `^25.1.8`
- Target configuration:
  ```json
  "win": {
    "target": [{ "target": "nsis", "arch": ["x64"] }],
    "icon": "assets/icon.ico"
  }
  ```
- **Portable Edition Evaluation:** `electron-builder` natively supports the `portable` target alongside `nsis`. The configuration omitted `"portable"` from the target list, explaining why no portable executable was generated in the previous build.
- **Build Script:** `"dist": "npm run sync-frontend && electron-builder --win nsis --x64"`. This directly mirrored `../frontend` into `./frontend` without desktop-specific adaptations.

### 2.3 Electron Process Security Audit (`desktop/main.js` & `preload.js`)
1. **Chromium Sandbox:** `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true` are enabled in `BrowserWindow.webPreferences`. This is a solid baseline.
2. **Critical Flaw — Wildcard CORS & Header Tampering (`main.js` lines 88-110):**
   ```javascript
   defaultSession.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
     const headers = { ...details.responseHeaders };
     headers['access-control-allow-origin'] = ['*'];
     headers['access-control-allow-credentials'] = ['true'];
     headers['access-control-allow-headers'] = ['*'];
     // ...
   });
   ```
   *Risk Analysis:* Intercepting every network call across Chromium and blindly allowing wildcard origins and credentials violates the Chromium security model and could expose cookies/sessions across origins.  
   *Remediation Plan:* Remove global wildcard CORS rewrites. Utilize the native Electron IPC channel (`ipcRenderer.invoke` -> `ipcMain.handle`) for privileged backend communication, local file operations, and security queries, eliminating CORS problems at the architectural root.
3. **Preload Exposure (`desktop/preload.js`):**
   Exposed only 4 minimal primitives:
   - `cyberguardDesktop.isDesktop`
   - `cyberguardDesktop.openExternal(url)`
   - `cyberguardDesktop.showNotification(title, body)`
   - Hardcoded `cyberguardDesktop.defaultCloudEndpoint = 'https://cyberguard-backend-8rbz.onrender.com'`
   Missing primitives for:
   - File system monitoring and scan-on-drop
   - Process observation
   - Local quarantine operations (list, quarantine, restore, delete)
   - Connection mode switching (Local, Cloud, Hybrid)
   - Local threat cache / SQLite synchronization
   - DNS and Web shield coordination

---

## 3. Backend & Detection Engine Audit (`backend/`)

### 3.1 API Surface & Endpoints
The FastAPI application (`backend/main.py`) exposes modular routers:
1. **Authentication (`/api/auth/*`):**
   - `POST /api/auth/login`: Authenticates username/email + password, returns JWT session token, sets `cyberguard_session` HTTP-only cookie.
   - `POST /api/auth/register`: Creates new user account (`role=user`).
   - `POST /api/auth/logout`: Revokes session token.
   - `GET /api/auth/me`: Retrieves authenticated user profile (`id`, `username`, `email`, `role`, `is_active`).
   - Strict tenant boundary: All subsequent threat events, browsing records, and incident histories are filtered strictly by `current_user.id`.
2. **Malware Lab & Scanning (`/api/threats/malware/*`):**
   - `POST /api/threats/malware/scan`: Accepts file upload or local path. Invokes `MalwareCoordinator` combining:
     - `FileFormatAnalyzer`: Shannon entropy, PE header parsing (sections, imports, compile timestamp), ZIP bomb inspection.
     - `ClamAVScanner`: Multi-engine daemon / CLI fallback.
     - `YaraScanner`: Custom and standard YARA rulesets.
     - Static hash reputation lookup against VirusTotal and URLhaus.
   - `POST /api/threats/malware/explain`: Qwen LLM-driven explainability report.
3. **Multimodal Media Forensics (`/api/threats/*`):**
   - `/api/threats/image`: Error Level Analysis (ELA), 2D-FFT frequency spectrum analysis, spatial noise kurtosis, MobileNetV3 deepfake detector, C2PA provenance extraction.
   - `/api/threats/video`: Frame-level temporal consistency and deepfake detection.
   - `/api/threats/deepfake` & `/api/analyze`: Neural audio cloning and speaker verification (ECAPA-TDNN).
   - `/api/threats/qr` & `/api/threats/url`: Phishing heuristics, punycode detection, URLhaus / VirusTotal lookup.
4. **Security Incidents & Normalized Events (`/api/incidents/*` & `/api/threats/events`):**
   - `POST /api/threats/events`: Ingests normalized `ThreatEvent` instances.
   - `GET /api/incidents/events`: Retrieves threat events scoped to `user_id`. Supports `source` and `source_type` attributes (`windows`, `android`, `web`).
   - `GET /api/incidents/dashboard/summary`: Scoped aggregate metrics.
5. **Browsing History & DNS Intelligence (`/api/browsing-history/*`):**
   - `GET /api/browsing-history`: Retrieves DNS query records for `current_user.id` with `ALLOWED` vs `BLOCKED` filters.
   - `POST /api/browsing-history/sync`: Batch ingestion endpoint for client DNS observations.

### 3.2 Connectivity Modes & Infrastructure
- **Mode 1 (Local):** Localhost FastAPI server (`http://127.0.0.1:3000` or `http://127.0.0.1:8000`).
- **Mode 2 (Cloud):** Deployed endpoint (`https://cyber-guard-backend-ashen.vercel.app` frontend/proxy and `https://cyberguard-backend-8rbz.onrender.com` backend API).
- **Mode 3 (Hybrid):** Three-stage fallback: Local Docker -> Custom Cloudflare Tunnel (`*.trycloudflare.com`) -> Cloud Backend.

---

## 4. Android & Browser Shield Ecosystem Audit

### 4.1 Android Client Reference (`android/`)
- Implements `CyberGuardVpnService.kt` to intercept DNS queries and enforce local blocklists on device.
- Implements `PackageChangeReceiver.kt` to monitor application installs/updates and trigger malware analysis.
- Connects to backend via `ConnectionManager.kt` supporting Local, Cloud, and Hybrid modes.
- Provides precedent for cross-platform event correlation: Events originating from Android carry `source_type: "android"`.

### 4.2 Chrome Browser Shield Reference (`extension/`)
- Manifest V3 extension in `extension/`:
  - `manifest.json`: Uses `declarativeNetRequest`, `webNavigation`, `storage`, `tabs`.
  - `background.js`: Monitors navigations, performs punycode and lookalike detection, enforces rules via `chrome.declarativeNetRequest`, redirects blocked domains to `blocked.html`.
  - Communicates with backend at `DEFAULT_BACKEND_URL = "http://127.0.0.1:3000"` with offline fallback cache.

---

## 5. Architectural Gap Analysis: Existing vs Required

| Architectural Dimension | Existing Desktop Status | Required Desktop Security Client |
| :--- | :--- | :--- |
| **Visual Architecture** | Cloned website HUD; dark neon theme; top navigation bar | Independent desktop design; Nothing OS/McAfee-inspired light neutral aesthetic; persistent left navigation rail |
| **Process Separation** | Single Electron renderer displaying web app; no native worker | Electron Main process + Secure Preload + Desktop UI + Native Endpoint Services (Watcher, Scanner, Quarantine) |
| **Real-Time File Monitoring** | None (manual upload only) | Local filesystem monitoring service watching critical drop directories (Downloads, Documents, Temp) with debounce, SHA-256, static PE/Entropy inspection |
| **Malware Quarantine** | None | Safe isolated quarantine folder (`%APPDATA%/CyberGuard/quarantine`), metadata ledger, restore, and delete capabilities |
| **Application & Process Watcher** | None | Process event monitor observing new process launches and unsigned executable drops |
| **Web & DNS Protection** | External browser extension only; not integrated into desktop UI | Desktop Web Protection hub communicating with local blocklists, browser extension state, and browsing history sync |
| **Security Alerts Center** | Incidents tab showing unified web events | Dedicated Alerts section with multi-source filtering: **Website**, **Android**, **Windows Application** |
| **Email Protection (Gmail)** | Backend route placeholder | User-consented Gmail OAuth integration UI, spam/phishing classification, CyberGuard admin email whitelist (`cyberguardadmin@gmail.com`) |
| **Packaging & Distribution** | NSIS setup only (`CyberGuard-Setup.exe`) | Dual distribution: **Standard Installer (NSIS)** + **Portable Edition (`CyberGuard-Portable.exe`)** with full feature parity |

---

## 6. Audit Conclusion & Phase Transition

The baseline audit confirms that while the backend, threat intelligence, and detection pipelines are robust and verified, the Windows desktop application requires a complete transformation:
1. Replace the duplicated website frontend with a dedicated, professional desktop endpoint application.
2. Build native Windows background security engines (filesystem monitoring, static scanner, process observer, quarantine).
3. Harden the Electron IPC architecture, completely eliminating global CORS tampering.
4. Update packaging to build both **Standard Installer** and **Portable Edition** with verified SHA-256 integrity.

Proceeding immediately to **Phase 2: Recovery Snapshot & Architecture Specification**.

