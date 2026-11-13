# CyberGuard Windows Release & Distribution Verification

**Document ID:** `CG-WIN-REL-004`  
**Date:** November 8, 2026  
**Auditor:** Principal Windows Security Architect & Release Engineer  
**Status:** DUAL DISTRIBUTION VERIFIED & SIGN-OFF COMPLETE  

---

## 1. Verified Release Artifact Inventory

Both required Windows distributions were built from the clean, hardened desktop source using `electron-builder` version 25.1.8 targeting Windows x64.

| Distribution Target | Artifact Filename | Exact File Path | Byte Size | Size (MB) | SHA-256 Hash |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Standard Installer** | `CyberGuard-Setup.exe` | `D:\BPUT\dist\windows\CyberGuard-Setup.exe` | 82,686,075 | 82.68 MB | `D461001471EFA703B7AA16252F513660E61CC51B945132FE9BA27C8BF227785A` |
| **Portable Edition** | `CyberGuard-Portable.exe` | `D:\BPUT\dist\windows\CyberGuard-Portable.exe` | 82,484,834 | 82.48 MB | `E99A87C244DEE353B62FE09BA1BBD8CF47CFA47DD745FE4E6136FBDB74ED50EF` |
| **Unpacked Executable** | `CyberGuard.exe` | `D:\BPUT\dist\windows\win-unpacked\CyberGuard.exe` | 188,850,688 | 188.85 MB | `BDE4B58C4D158CCB11237E86E967FC31CB77C3FBDF9716D4BD5CEDBD8AC21511` |

*Baseline Preservation Note:* The original supplied archive installer was verified and safely preserved at `D:\BPUT\dist_backup\CyberGuard-Setup.original.exe` (SHA-256: `DCEA9EB1C9347CA15B8E4221BE0DB62D4F3C60E171E0899AA2D53083F5D51CBA`).

---

## 2. Packaged ASAR Verification (`dist/windows/win-unpacked/resources/app.asar`)

The internal application archive was unpacked and inspected to guarantee complete bundling of all native security engines, desktop UI assets, and configuration modules:

```text
app.asar/
├── assets/
│   ├── icon.ico
│   └── icon.png
├── engine/
│   ├── file_watcher.js
│   ├── gmail_service.js
│   ├── local_store.js
│   ├── process_monitor.js
│   ├── quarantine_manager.js
│   └── web_shield.js
├── frontend/
│   ├── app.js
│   ├── index.html
│   ├── styles.css
│   └── logo.png
├── main.js
├── package.json
└── preload.js
```

### Bundle Integrity Confirmations:
1. **Zero Web Overwrite:** `desktop/frontend` is completely decoupled from `../frontend` and contains the dedicated endpoint security client.
2. **Native Engines Included:** All 6 backend security engines (`file_watcher`, `process_monitor`, `quarantine_manager`, `web_shield`, `gmail_service`, `local_store`) are embedded.
3. **Hardened Preload:** `preload.js` exposes typed `cyberguardEndpoint` primitives with full context isolation.
4. **No CORS Rewriting:** Global header tampering code is permanently removed.

---

## 3. Standard Installer vs Portable Edition Feature Parity Matrix

| Feature / Subsystem | Standard Installer (`CyberGuard-Setup.exe`) | Portable Edition (`CyberGuard-Portable.exe`) | Parity Status |
| :--- | :--- | :--- | :--- |
| **Real-Time File Monitoring** | Active (Downloads, Temp, User Directories) | Active (Downloads, Temp, User Directories) | **100% IDENTICAL** |
| **Process & App Execution Monitor** | Active (Differential LOLBin & Temp observer) | Active (Differential LOLBin & Temp observer) | **100% IDENTICAL** |
| **Manual Multimodal File Scanner** | PE, Image, Audio, Video, Document forensics | PE, Image, Audio, Video, Document forensics | **100% IDENTICAL** |
| **Quarantine Vault & Atomic Rollback** | `%APPDATA%/CyberGuard/quarantine/` | `%APPDATA%/CyberGuard-Portable/quarantine/` | **100% EQUIVALENT** |
| **Web & DNS Protection Shield** | Active blocklist & MV3 extension integration | Active blocklist & MV3 extension integration | **100% IDENTICAL** |
| **Tri-Source Security Alerts** | Windows, Android, Website tabs & filters | Windows, Android, Website tabs & filters | **100% IDENTICAL** |
| **Gmail Protection & Admin Whitelist** | OAuth 2.0 + `cyberguardadmin@gmail.com` bypass | OAuth 2.0 + `cyberguardadmin@gmail.com` bypass | **100% IDENTICAL** |
| **Three Connectivity Modes** | Local, Deployed Cloud, Hybrid Auto-Failover | Local, Deployed Cloud, Hybrid Auto-Failover | **100% IDENTICAL** |
| **Windows Toast Notifications** | Native Windows 10/11 Action Center | Native Windows 10/11 Action Center | **100% IDENTICAL** |
| **System Installation Footprint** | Installs to `%LOCALAPPDATA%/Programs/CyberGuard` | Zero installation; runs directly from executable | Mode-appropriate |
| **Uninstaller** | Complete uninstallation support | None needed (single-file deletion) | Mode-appropriate |

---

## 4. Reproducible Build Instructions

To build both distributions from the project root at any time:

```powershell
# 1. Navigate to desktop directory
cd D:\BPUT\desktop

# 2. Install dependencies (if fresh clone)
npm ci

# 3. Build both Standard Installer and Portable Edition
npm run dist

# 4. Or build individual targets:
npm run dist:installer   # Produces CyberGuard-Setup.exe
npm run dist:portable    # Produces CyberGuard-Portable.exe
```

Output directory: `D:\BPUT\dist\windows`

