# CyberGuard Windows Desktop Security Client — Architectural Blueprint

**Document ID:** `CG-WIN-ARCH-002`  
**Date:** November 8, 2026  
**Status:** Approved for Implementation  
**Target Platform:** Windows 10 / 11 (x64) — Standard Installer & Portable Edition  

---

## 1. Architectural Philosophy & Separation of Concerns

CyberGuard Windows is designed as an independent, enterprise-grade endpoint security client, decoupled from the centralized web portal. While the web platform serves as the central SOC and cloud intelligence console, the Windows client acts as an autonomous on-device security guard.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CYBERGUARD DESKTOP ARCHITECTURE                      │
├────────────────────────────────────────────────────────────────────────┤
│  [ DESKTOP UI LAYER ] (Electron Renderer Process)                     │
│   • Left Navigation Rail (Home, Protection, Scanner, Web, Alerts, etc.) │
│   • Light Neutral High-Clarity Design System (Nothing/McAfee Aesthetic) │
│   • Sandboxed Execution (contextIsolation: true, nodeIntegration: false) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ IPC Bridge (cyberguardEndpoint)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  [ SECURITY HOST LAYER ] (Electron Main & Security Engine)              │
│   • Window Lifecycle & Native Tray Controller                          │
│   • Input-Validated IPC Handlers (ipcMain.handle)                      │
│   • SafeStorage Token Vault (Windows DPAPI)                            │
│   ┌───────────────────────┬──────────────────────┬───────────────────┐ │
│   │ File Watcher Service  │ Process Monitor      │ Quarantine Vault  │ │
│   │ (Debounced, SHA-256,  │ (WMI / Process Watch │ (Isolated storage,│ │
│   │  PE / Entropy Static) │  Suspicious launch)  │  atomic restore)  │ │
│   └───────────────────────┴──────────────────────┴───────────────────┘ │
│   ┌───────────────────────┬──────────────────────┬───────────────────┐ │
│   │ Web & DNS Shield      │ Gmail OAuth Module   │ Three-Mode Sync   │ │
│   │ (Extension Bridge &   │ (Loopback OAuth,     │ (Local/Cloud/     │ │
│   │  Local Blocklist)     │  Admin whitelist)    │  Hybrid + Queue)  │ │
│   └───────────────────────┴──────────────────────┴───────────────────┘ │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTPS / REST / WS
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  [ BACKEND INTELLIGENCE LAYER ] (FastAPI SOC Server)                   │
│   • /api/auth/me (User session authentication & tenant isolation)      │
│   • /api/threats/malware/scan (Multi-engine ClamAV, YARA, PE analyzer) │
│   • /api/threats/events (Normalized multi-source incident aggregation) │
│   • /api/browsing-history/sync (Cross-platform DNS history)            │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Visual Design System: "Refined Light Neutral"

Guided by the Master Prompt's aesthetic direction:
- **Surface Palette:** Crisp, calming light neutrals. Background `#F8FAFC`, card surfaces `#FFFFFF`, borders `#E2E8F0`, hover states `#F1F5F9`.
- **Typography:** Modern grotesque desktop typography with clear tabular figures for metrics, dark slate body text `#0F172A`, muted metadata `#64748B`.
- **Status Accents:**
  - **Protected / Secure:** Muted emerald green `#10B981` (used only when services are genuinely active).
  - **Warning / Attention:** Warm amber `#F59E0B`.
  - **Critical Threat:** High-urgency crimson `#EF4444` (strictly reserved for confirmed malware or phishing).
  - **Brand / Accent:** Professional indigo/violet `#6366F1` and slate accents.
- **Window Framework:**
  - Left persistent navigation rail (width: 240px).
  - Top clean status bar with user identity, connection mode indicator, and real-time shield status.
  - Central dynamic content pane.
  - Zero decorative neon grid animations, zero fake graphs, zero simulated scans.

---

## 3. Core Endpoint Subsystems & Technical Specifications

### 3.1 Real-Time File Monitoring Service (`engine/file_watcher.js`)
- **Monitored Locations:** Configurable drop zones including User Downloads (`%USERPROFILE%/Downloads`), Desktop, and Documents.
- **Event Handling:** Event-driven watching via Node.js native filesystem events with a 500ms sliding debounce window to handle multi-chunk writes (e.g. browser downloads `.crdownload`).
- **File Stability & Verification:** Verifies file size stability across consecutive intervals before releasing to inspection.
- **Static Inspection Pipeline:**
  1. Computes cryptographic SHA-256 and MD5 hashes.
  2. Parses file magic numbers (PE32/PE32+, ELF, ZIP, PDF, OLE, Script headers).
  3. Calculates byte-level Shannon entropy ($H = -\sum p_i \log_2 p_i$). Entropy $> 7.2$ on executable sections flags high-probability packing/encryption.
  4. Scans against local signature database and known malware hashes (including EICAR test signature).
- **Containment Action:** Automatically isolates high-confidence threats to the Quarantine Vault if real-time containment policy is set to `AUTO_ISOLATE`. Dispatches native Windows notification.

### 3.2 Process & Execution Observer (`engine/process_monitor.js`)
- **Mechanism:** Low-overhead periodic process snapshotting and execution observation.
- **Execution Rules:** Flags processes launched from temporary directories (`%TEMP%`, `%APPDATA%`), unsigned binaries with high entropy, and script hosts (`powershell.exe`, `wscript.exe`, `cscript.exe`) spawned with encoded command arguments.
- **Resource Footprint:** Capped at $< 1.0\%$ average CPU utilization during idle operation.

### 3.3 Quarantine Vault (`engine/quarantine_manager.js`)
- **Storage Location:** `%APPDATA%/CyberGuard/quarantine/` (Standard) or `<app_data>/quarantine/` (Portable).
- **Safety Protocol:**
  - Files are moved atomically and encrypted with XOR/AES key with `.cgq` extension to prevent accidental OS execution.
  - Metadata ledger (`quarantine_index.json`) records original path, original permissions, SHA-256, detection engine, threat name, and quarantine timestamp.
  - Actions supported: **Restore File** (verifies target path and recreates original file), **Permanently Delete** (secure overwrite shredding), **Whitelist / False Positive Exemption**.

### 3.4 Live Web & DNS Shield Integration (`engine/web_shield.js`)
- **Browser Coordination:** Integrates with the CyberGuard Chrome Browser Shield (`extension/`).
- **Local Threat Intelligence Cache:** Maintains an in-memory Trie/Set of known malicious phishing and malware domains (synchronized with URLhaus and VirusTotal cache).
- **DNS Observation & Sync:** Collects DNS query telemetry locally and syncs in batches to `POST /api/browsing-history/sync` under the authenticated user's ID.

### 3.5 Gmail Protection Add-On (`engine/gmail_client.js`)
- **Authentication:** Standard Google OAuth 2.0 PKCE loopback authorization code grant. Never collects or stores raw Google passwords.
- **Token Vault:** Tokens are encrypted on-disk using Electron's `safeStorage` (backed by Windows Data Protection API - DPAPI).
- **Whitelisting:** Enforces strict bypass for official CyberGuard administrative communications:
  - Trusted Sender: `cyberguardadmin@gmail.com`
  - Validates `From`, `Sender`, and `Authentication-Results` (SPF/DKIM pass) to prevent header spoofing.
- **Heuristics:** Checks email bodies for phishing URLs, credential harvesting phrases, and malicious attachment extensions.

### 3.6 Multi-Tenant Isolation & Authentication (`engine/auth_manager.js`)
- Communicates with `/api/auth/login`, `/api/auth/logout`, and `/api/auth/me`.
- All local caches, scan histories, alerts, and browsing events are strictly tagged with `user_id`.
- On logout: Active sync queues are terminated, in-memory tokens wiped, and local display states cleared to guarantee absolute zero-trust tenant boundary enforcement.

---

## 4. Packaging Strategy: Standard Installer vs Portable Edition

| Attribute | Standard Installer (`CyberGuard-Setup.exe`) | Portable Edition (`CyberGuard-Portable.exe`) |
| :--- | :--- | :--- |
| **Packaging Target** | NSIS (`nsis`) | Electron Portable (`portable`) |
| **Output File** | `dist/windows/CyberGuard-Setup.exe` | `dist/windows/CyberGuard-Portable.exe` |
| **Installation Required** | Yes (standard user or per-machine) | None (single executable launch) |
| **Data Directory** | `%APPDATA%/CyberGuard/` | `%APPDATA%/CyberGuard-Portable/` or alongside executable |
| **Registry & Startup** | Optional Run key for auto-start | Zero registry writes; no auto-start |
| **System Services** | Can interact with elevated service if installed | User-space only; never silently installs drivers |
| **Security Parity** | 100% Core Engine Parity | 100% Core Engine Parity |

---

## 5. Security & IPC Boundary Matrix

1. **Context Isolation:** Enabled (`contextIsolation: true`). The DOM and JavaScript execution environment cannot access Node.js globals (`require`, `process`, `Buffer`).
2. **IPC Channel Contracts:**
   - `cyberguard:auth-login`
   - `cyberguard:auth-logout`
   - `cyberguard:auth-get-session`
   - `cyberguard:scanner-scan-file`
   - `cyberguard:scanner-scan-path`
   - `cyberguard:watcher-get-status`
   - `cyberguard:watcher-toggle`
   - `cyberguard:watcher-get-events`
   - `cyberguard:quarantine-list`
   - `cyberguard:quarantine-restore`
   - `cyberguard:quarantine-delete`
   - `cyberguard:web-get-history`
   - `cyberguard:web-toggle-shield`
   - `cyberguard:gmail-get-status`
   - `cyberguard:gmail-authorize`
   - `cyberguard:gmail-scan-inbox`
   - `cyberguard:connection-get-mode`
   - `cyberguard:connection-set-mode`
   - `cyberguard:connection-get-health`
   - `cyberguard:alerts-get`
   - `cyberguard:open-external`
   - `cyberguard:notify`
3. **No Wildcard CORS:** Global header mutation in `session.defaultSession` is eliminated. All backend queries can be brokered directly through the privileged main process IPC, eliminating CORS completely from the desktop client.

