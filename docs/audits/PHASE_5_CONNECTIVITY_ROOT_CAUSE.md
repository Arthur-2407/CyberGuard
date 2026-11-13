# CyberGuard Phase 5 — Connectivity Forensic Investigation & Root Cause Analysis

## Executive Summary
This document records the exhaustive forensic investigation into the contradictory health-state failure observed in the CyberGuard Windows desktop application (`Connectivity & Threat Intelligence Sync` screen), where the application-level header reported `● OFFLINE` (red dot), individual service cards remained frozen in `PROBING...` / `Checking...`, while the bottom resolved active API reported `ACTIVE HEALTH: ONLINE` in green.

---

## 1. Initial Failure Reproduction & Visual Discrepancy

### Observed Symptoms (Screenshot Artifact `media_1794164595331_2af06875.jpg`)
* **Top Header Pill**: Displayed red status indicator dot with label `● OFFLINE`.
* **Selected Mode**: `MODE 2 (Deployed Cloud Mode)` active.
* **Service Cards 1, 2, 4**:
  - `1. Local Docker Engine`: Badge stuck in `PROBING...`, Status: `Checking...`, Latency: `-- ms`
  - `2. Cloud Backend API`: Badge stuck in `PROBING...`, Status: `Checking...`, Latency: `-- ms`
  - `4. Vercel Web Portal`: Badge stuck in `PROBING...`, Status: `Checking...`, Latency: `-- ms`
* **Service Card 3**:
  - `3. Cloudflare Tunnel`: Badge `UNCONFIGURED`, Route State: `Optional`, Origin: `--`
* **Bottom Active Status Strip**:
  - `RESOLVED ACTIVE API: https://cyberguard-backend-8rbz.onrender.com`
  - `ACTIVE HEALTH: ONLINE` (green `.active` status tag).

### The Inherent State Contradiction
The application presented an impossible duality: declaring the aggregate endpoint `OFFLINE` at the header level while simultaneously declaring the resolved backend `ONLINE` at the bottom, all while the component cards remained suspended in `PROBING...`.

---

## 2. Root Cause Analysis

### 2.1 The DOM Initialization Flaw in `index.html`
In `desktop/frontend/index.html` (line 897), the DOM element for active backend health was statically authored with initial HTML:
```html
<span id="active-backend-health" class="status-tag active ml-2">ONLINE</span>
```
When `initConnectionSettings()` runs upon page mount or mode selection, `updateActiveApiBaseDisplay()` updates `#active-api-base` to the target origin (`https://cyberguard-backend-8rbz.onrender.com`), but left `#active-backend-health` untouched until asynchronous network probes complete.

### 2.2 The Object Key Mismatch & Unhandled `TypeError` in `app.js`
In `desktop/engine/connectivity_service.js`, the diagnostic probe engine returned:
```javascript
return {
  timestamp: new Date().toISOString(),
  local,   // Tier 1 object
  cloud,   // Tier 2 object
  tunnel,  // Tier 3 object
  vercel   // Tier 4 object
};
```
However, in `desktop/frontend/app.js` (line 782), `runDiagnosticProbe` was written with mismatched property expectations:
```javascript
if (diag.localDocker.reachable) { ... }
```
Because `diag.localDocker` was `undefined`, accessing `.reachable` immediately triggered an unhandled runtime error:
```
TypeError: Cannot read properties of undefined (reading 'reachable')
```

### 2.3 The Faulty Exception Boundary
When the `TypeError` occurred, execution immediately jumped to the `catch (err)` block:
```javascript
} catch (err) {
  console.error('[Diagnostics Error]:', err);
  setDiagnosticPillStatus('offline', 'OFFLINE');
}
```
In this error handler:
1. `setDiagnosticPillStatus('offline', 'OFFLINE')` mutated the top titlebar pill to `● OFFLINE` (red).
2. The cards (`#diag-badge-local`, `#diag-badge-cloud`, `#diag-badge-vercel`) were never updated, leaving them stuck in their initial HTML placeholder state: `PROBING...`, `Checking...`, `-- ms`.
3. `#active-backend-health` was never modified, leaving its static initial HTML green `ONLINE` text intact.
4. The user was presented with a split-brain interface where header = `OFFLINE`, cards = `PROBING...`, and footer = `ONLINE`.

---

## 3. Architecture Correction: Authoritative State Single Source of Truth

### 3.1 Standardized State Machine
Adopted explicit semantic states across all networking layers:
- `HEALTHY`: 200 OK verified within acceptable latency (<2500ms).
- `DEGRADED`: Reachable, but latency > 2500ms or partial API rewrite degraded.
- `OFFLINE`: Port closed, host unreachable, or non-zero connection error.
- `TIMEOUT`: Probe exceeded maximum allowable socket window (4000ms).
- `AUTH_REQUIRED`: HTTP 401/403 received; host is online but requires credentials.
- `NOT_CONFIGURED`: Optional service (e.g., custom Cloudflare tunnel) omitted.
- `PROBING`: Active evaluation currently in flight.

### 3.2 Dual-Key Normalization & Forward/Backward Compatibility
`desktop/engine/connectivity_service.js` now exports both primary normalized keys and legacy aliases:
- `diag.local` and `diag.localDocker`
- `diag.cloud` and `diag.cloudBackend`
- `diag.tunnel` and `diag.cloudflareTunnel`
- `diag.vercel` and `diag.vercelPortal`
- Both `online: boolean` and `reachable: boolean` on every tier.

### 3.3 Atomic UI State Synchronization (`applyAuthoritativeHealthState`)
In `desktop/frontend/app.js`, individual ad-hoc DOM mutations have been replaced by a single authoritative state applier:
```javascript
function applyAuthoritativeHealthState(diag, mode, activeApiBase)
```
- Sets titlebar pill, component cards, active API base, and active health tag atomically.
- Uses `setProbingState()` to transition all components into `PROBING...` synchronously before network I/O.
- Uses `setDiagnosticErrorState(err)` in the `catch` block to mark all cards as `ERROR` and footer as `OFFLINE (Probe failed)`. It is mathematically impossible for the footer to remain `ONLINE` if an error occurs.
- Fixed `desktop/frontend/index.html` initial placeholder from `ONLINE` to `<span id="active-backend-health" class="status-tag neutral ml-2">INITIALIZING...</span>`.

