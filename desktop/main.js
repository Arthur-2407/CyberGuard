/**
 * CyberGuard SOC AI — Enterprise Desktop Application
 * Main Electron Host Process
 *
 * Security Model:
 *  - nodeIntegration: false (strict renderer process sandboxing)
 *  - contextIsolation: true (independent context for preload script)
 *  - sandbox: true (OS-level Chromium sandbox)
 *  - Controlled permission request handler
 *  - Strict navigation gating (external links open in default OS browser)
 *  - Single-instance application lock & clean shutdown
 *  - Native Endpoint Security Services (File Watcher, Process Monitor, Quarantine, Web Shield)
 */

// Ensure child processes don't inherit node-mode override
if (process.env.ELECTRON_RUN_AS_NODE) {
  delete process.env.ELECTRON_RUN_AS_NODE;
}

const { app, BrowserWindow, shell, ipcMain, session, Notification, dialog, Menu } = require('electron');
const path = require('path');
const https = require('https');
const http = require('http');

// Forward CDP debugging switch if passed via CLI for automated verification
for (const arg of process.argv) {
  if (arg.startsWith('--remote-debugging-port=')) {
    const debugPort = arg.split('=')[1];
    if (debugPort) {
      app.commandLine.appendSwitch('remote-debugging-port', debugPort);
    }
  }
}

// Endpoint Engines
const localStore = require('./engine/local_store');
const connectivityService = require('./engine/connectivity_service');
const fileWatcher = require('./engine/file_watcher');
const processMonitor = require('./engine/process_monitor');
const quarantineManager = require('./engine/quarantine_manager');
const webShield = require('./engine/web_shield');
const gmailService = require('./engine/gmail_service');
const multimodalScanner = require('./engine/multimodal_scanner');

// Single-instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
  process.exit(0);
}

let mainWindow = null;

function createWindow() {
  const iconPath = path.join(__dirname, 'assets', 'icon.ico');

  mainWindow = new BrowserWindow({
    title: 'CyberGuard — Endpoint Security & Multi-Modal Threat Defense',
    width: 1440,
    height: 900,
    minWidth: 1080,
    minHeight: 720,
    backgroundColor: '#F8FAFC',
    icon: iconPath,
    show: false, // Flicker-free display
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false
    }
  });

  // Configure application menu with standard Edit role accelerators (Cut, Copy, Paste, Select All)
  // while keeping the native menu bar hidden for a clean modern interface.
  const menuTemplate = [
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(menuTemplate));
  mainWindow.setMenuBarVisibility(false);

  // Context menu for cut / copy / paste on editable input fields
  mainWindow.webContents.on('context-menu', (event, params) => {
    if (params.isEditable) {
      const contextMenu = Menu.buildFromTemplate([
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { type: 'separator' },
        { role: 'selectAll' }
      ]);
      contextMenu.popup({ window: mainWindow, x: params.x, y: params.y });
    }
  });

  // Load the dedicated desktop UI
  const entryPoint = path.join(__dirname, 'frontend', 'index.html');
  mainWindow.loadFile(entryPoint);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // Safe navigation control: Open external URLs in default web browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:') || url.startsWith('mailto:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    const isLocalFile = url.startsWith('file://');
    if (!isLocalFile) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ── Native Notification Dispatcher ──
function dispatchDesktopNotification({ title, body, severity = 'INFO' }) {
  if (Notification.isSupported()) {
    try {
      new Notification({
        title: title || 'CyberGuard Security Alert',
        body: body || '',
        icon: path.join(__dirname, 'assets', 'icon.ico'),
        urgency: severity === 'CRITICAL' ? 'critical' : 'normal'
      }).show();
    } catch (e) {
      console.warn('[Notification] Dispatch failed:', e.message);
    }
  }
}

// ── Low-Overhead Direct HTTP/HTTPS Backend Request Engine ──
function executeBackendRequest(targetUrl, { method = 'GET', headers = {}, body = null, timeout = 15000 } = {}) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(targetUrl);
      const client = parsed.protocol === 'https:' ? https : http;
      let postData = null;
      if (body !== null && body !== undefined) {
        postData = typeof body === 'string' ? body : JSON.stringify(body);
        if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(postData);
      }
      const req = client.request({
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + (parsed.search || ''),
        method: method.toUpperCase(),
        headers,
        timeout
      }, (res) => {
        let respBody = '';
        res.on('data', chunk => {
          if (respBody.length < 10485760) respBody += chunk;
        });
        res.on('end', () => {
          let data = null;
          try { data = JSON.parse(respBody); } catch (_) { data = respBody; }
          const ok = res.statusCode >= 200 && res.statusCode < 400;
          let errMsg = null;
          if (!ok) {
            if (data && typeof data === 'object') {
              errMsg = data.detail || data.message || `HTTP ${res.statusCode}`;
              if (Array.isArray(errMsg)) errMsg = errMsg[0]?.msg || JSON.stringify(errMsg);
            } else {
              errMsg = `HTTP ${res.statusCode}`;
            }
          }
          resolve({ ok, status: res.statusCode, data, error: errMsg, raw: respBody });
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 408, error: 'Request timed out' }); });
      req.on('error', (e) => resolve({ ok: false, status: 0, error: e.message, code: e.code }));
      if (postData) req.write(postData);
      req.end();
    } catch (err) {
      resolve({ ok: false, status: 0, error: err.message });
    }
  });
}

function resolveBackendTargets(explicitEndpoint = null) {
  const cfg = localStore.getConfig();
  const mode = cfg.connectionMode || 'hybrid';
  const localPort = cfg.localPort || 3000;
  const cloudUrl = 'https://cyberguard-backend-8rbz.onrender.com';
  const tunnelUrl = cfg.customTunnel && cfg.customTunnel.trim() ? cfg.customTunnel.trim().replace(/\/+$/, '') : null;

  if (explicitEndpoint && !explicitEndpoint.includes('127.0.0.1:3000')) {
    return [explicitEndpoint.replace(/\/+$/, ''), cloudUrl];
  }
  if (mode === 'local') {
    return [`http://127.0.0.1:${localPort}`];
  }
  if (mode === 'deployed') {
    return [cloudUrl];
  }
  // Hybrid mode: local first, then tunnel, then deployed cloud
  const list = [`http://127.0.0.1:${localPort}`];
  if (tunnelUrl) list.push(tunnelUrl);
  list.push(cloudUrl);
  return list;
}

// ── Initialize App & Register Services ──
app.whenReady().then(() => {
  // Security Hardening (Part 9 & AC-21/AC-22):
  // Strictly enforce that launching CyberGuard begins with a clean, unauthenticated state.
  localStore.clearSession();
  const defaultSession = session.defaultSession;

  // Strict CSP Header Injection for file:// renderer
  defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self' file: data: blob:; " +
          "script-src 'self' 'unsafe-inline' file:; " +
          "style-src 'self' 'unsafe-inline' file: https://fonts.googleapis.com; " +
          "font-src 'self' file: data: https://fonts.gstatic.com; " +
          "img-src 'self' file: data: blob: https:; " +
          "connect-src 'self' http://127.0.0.1:* http://localhost:* https://cyberguard-backend-8rbz.onrender.com https://cyber-guard-backend-ashen.vercel.app https://*.trycloudflare.com ws://127.0.0.1:* wss://cyberguard-backend-8rbz.onrender.com wss://*.trycloudflare.com;"
        ]
      }
    });
  });

  // Controlled permission request handler
  defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    if (permission === 'media') {
      callback(true); // Microphone for Voice Analysis
      return;
    }
    callback(false);
  });

  // Wire notifications from background engines
  fileWatcher.setNotificationHandler(dispatchDesktopNotification);
  processMonitor.setNotificationHandler(dispatchDesktopNotification);
  multimodalScanner.setNotificationHandler(dispatchDesktopNotification);

  // Forward background events to renderer
  fileWatcher.onEvent(evt => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('cyberguard:security-event', evt);
    }
  });

  processMonitor.onEvent(evt => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('cyberguard:security-event', evt);
    }
  });

  // Start background services if enabled in config
  const cfg = localStore.getConfig();
  if (cfg.realtimeFileMonitoring !== false) {
    fileWatcher.start();
  }
  if (cfg.processMonitoring !== false) {
    processMonitor.start();
  }

  // ── Register IPC Handlers ──
  setupIpcHandlers();

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

function setupIpcHandlers() {
  // Safe External URL
  ipcMain.handle('cyberguard:open-external', (event, url) => {
    if (typeof url === 'string' && (url.startsWith('https://') || url.startsWith('http://'))) {
      shell.openExternal(url);
      return true;
    }
    return false;
  });

  // Native Notification
  ipcMain.handle('cyberguard:notify', (event, { title, body, severity }) => {
    dispatchDesktopNotification({ title, body, severity });
    return true;
  });

  // Dialogs
  ipcMain.handle('cyberguard:select-file', async () => {
    if (!mainWindow) return null;
    const res = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      title: 'Select File for CyberGuard Forensic Analysis'
    });
    if (res.canceled || res.filePaths.length === 0) return null;
    return res.filePaths[0];
  });

  ipcMain.handle('cyberguard:select-folder', async () => {
    if (!mainWindow) return null;
    const res = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory'],
      title: 'Select Monitored Directory'
    });
    if (res.canceled || res.filePaths.length === 0) return null;
    return res.filePaths[0];
  });

  // Configuration
  ipcMain.handle('cyberguard:get-config', () => localStore.getConfig());
  ipcMain.handle('cyberguard:save-config', (event, updates) => localStore.saveConfig(updates));

  // Independent Diagnostics & Health
  ipcMain.handle('cyberguard:diagnose-connectivity', (event, params) => connectivityService.runFullDiagnostics(params));
  ipcMain.handle('cyberguard:check-health', async (event, { mode, endpoint }) => {
    const probe = await connectivityService._probeUrl((endpoint || 'http://127.0.0.1:3000') + '/health', 3500);
    return {
      online: probe.ok,
      statusCode: probe.statusCode,
      latencyMs: probe.latencyMs,
      data: probe.data,
      error: probe.ok ? null : (probe.error || `HTTP ${probe.statusCode}`)
    };
  });

  // Session & Authentication (Zero-Trust Server Validation & Auto Hybrid Failover)
  ipcMain.handle('cyberguard:auth-login', async (event, { usernameOrEmail, password, endpoint }) => {
    const targets = resolveBackendTargets(endpoint);
    let lastError = 'Authentication service unreachable.';

    for (const base of targets) {
      const url = `${base}/api/auth/login`;
      const res = await executeBackendRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { username_or_email: usernameOrEmail, password },
        timeout: 15000
      });

      if (res.ok && res.data && res.data.user && res.data.token) {
        localStore.setSession(res.data.user, res.data.token);
        return { success: true, user: res.data.user, token: res.data.token };
      }

      if (res.status === 401 || res.status === 403 || res.status === 422) {
        return { success: false, error: res.error || 'Authentication rejected' };
      }

      lastError = res.error || lastError;
      // If network refused/down, try next target in hybrid chain
    }

    return { success: false, error: lastError };
  });

  ipcMain.handle('cyberguard:auth-register', async (event, { username, email, password, endpoint }) => {
    const targets = resolveBackendTargets(endpoint);
    let lastError = 'Registration service unreachable.';

    for (const base of targets) {
      const url = `${base}/api/auth/register`;
      const res = await executeBackendRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { username, email, password },
        timeout: base.includes('127.0.0.1') ? 3500 : 15000
      });

      if (res.ok && res.data && res.data.user && res.data.token) {
        localStore.setSession(res.data.user, res.data.token);
        return { success: true, user: res.data.user, token: res.data.token };
      }

      if (res.status === 400 || res.status === 409 || res.status === 422) {
        return { success: false, error: res.error || 'Registration rejected' };
      }

      lastError = res.error || lastError;
    }

    return { success: false, error: lastError };
  });

  ipcMain.handle('cyberguard:auth-verify', async (event, { endpoint }) => {
    const session = localStore.getSession();
    if (!session || !session.token) {
      return { valid: false };
    }

    const targets = resolveBackendTargets(endpoint);
    for (const base of targets) {
      const url = `${base}/api/auth/me`;
      const res = await executeBackendRequest(url, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${session.token}` },
        timeout: 4000
      });

      if (res.ok && res.data) {
        return { valid: true, user: res.data, token: session.token };
      }
      if (res.status === 401 || res.status === 403) {
        localStore.clearSession();
        return { valid: false };
      }
    }

    return { valid: false };
  });

  ipcMain.handle('cyberguard:auth-get-session', () => localStore.getSession());
  ipcMain.handle('cyberguard:auth-logout', () => {
    localStore.clearSession();
    return { success: true };
  });

  // ── Universal Main-Process API Request Broker (Zero CORS / Zero PNA / Auto Hybrid Failover) ──
  ipcMain.handle('cyberguard:api-request', async (event, reqOptions = {}) => {
    const apiPath = (reqOptions && (reqOptions.path || reqOptions.url)) || '/';
    const method = ((reqOptions && reqOptions.method) || 'GET').toUpperCase();
    const headers = (reqOptions && reqOptions.headers) || {};
    const body = (reqOptions && reqOptions.body) !== undefined ? reqOptions.body : null;
    const params = (reqOptions && reqOptions.params) || null;
    const endpoint = (reqOptions && reqOptions.endpoint) || null;

    const session = localStore.getSession();
    const reqHeaders = { ...headers };
    if (session && session.token && !reqHeaders['Authorization']) {
      reqHeaders['Authorization'] = `Bearer ${session.token}`;
      reqHeaders['X-Session-Token'] = session.token;
    }

    let searchStr = '';
    if (params && typeof params === 'object') {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null) q.append(k, String(v));
      }
      const s = q.toString();
      if (s) searchStr = (apiPath.includes('?') ? '&' : '?') + s;
    }
    const fullPath = (apiPath.startsWith('/') ? apiPath : `/${apiPath}`) + searchStr;

    const targets = resolveBackendTargets(endpoint);
    let lastResult = null;

    for (const base of targets) {
      const url = `${base}${fullPath}`;
      const res = await executeBackendRequest(url, {
        method,
        headers: reqHeaders,
        body,
        timeout: 15000
      });

      if (res.ok) {
        return res;
      }
      lastResult = res;

      // Fail over to next backend in hybrid chain only on network/availability errors
      if (res.code === 'ECONNREFUSED' || res.status === 0 || res.status === 408 || res.status === 502) {
        continue;
      }

      // Explicit HTTP application status (400, 401, 403, 404, 422, etc.) is authoritative
      return res;
    }

    return lastResult || { ok: false, status: 503, error: 'Security service unavailable.' };
  });

  // Network Telemetry & Active Interface
  ipcMain.handle('cyberguard:get-network-interface', () => webShield.getActiveNetworkInterface());

  // File Watcher
  ipcMain.handle('cyberguard:file-watcher-status', () => fileWatcher.getStatus());
  ipcMain.handle('cyberguard:file-watcher-start', () => { fileWatcher.start(); return fileWatcher.getStatus(); });
  ipcMain.handle('cyberguard:file-watcher-stop', () => { fileWatcher.stop(); return fileWatcher.getStatus(); });
  ipcMain.handle('cyberguard:file-watcher-set-paths', (event, paths) => {
    fileWatcher.updateMonitoredPaths(paths);
    return fileWatcher.getStatus();
  });
  ipcMain.handle('cyberguard:scan-local-file', (event, filePath) => fileWatcher.analyzeLocalFile(filePath));

  // Multimodal Forensic Scanner & Deep Inspection
  ipcMain.handle('cyberguard:multimodal-detect-modality', (event, filePath) => multimodalScanner.detectModality(filePath));
  ipcMain.handle('cyberguard:multimodal-scan', (event, { filePath, options }) => multimodalScanner.scanFile(filePath, options));
  ipcMain.handle('cyberguard:multimodal-explain', (event, { scanId, sha256, forceRefresh }) => multimodalScanner.explainMalware(scanId, sha256, forceRefresh));

  // Process Monitor
  ipcMain.handle('cyberguard:process-monitor-status', () => processMonitor.getStatus());
  ipcMain.handle('cyberguard:process-monitor-start', () => { processMonitor.start(); return processMonitor.getStatus(); });
  ipcMain.handle('cyberguard:process-monitor-stop', () => { processMonitor.stop(); return processMonitor.getStatus(); });

  // Quarantine Vault
  ipcMain.handle('cyberguard:quarantine-list', () => quarantineManager.listItems());
  ipcMain.handle('cyberguard:quarantine-file', (event, { filePath, threatInfo }) => {
    return quarantineManager.quarantineFile(filePath, threatInfo);
  });
  ipcMain.handle('cyberguard:quarantine-restore', (event, { id, targetPath }) => {
    return quarantineManager.restoreFile(id, targetPath);
  });
  ipcMain.handle('cyberguard:quarantine-delete', (event, id) => {
    return quarantineManager.deleteFile(id);
  });

  // Web Shield
  ipcMain.handle('cyberguard:web-shield-status', () => webShield.getStatus());
  ipcMain.handle('cyberguard:web-shield-toggle', (event, enabled) => webShield.toggle(enabled));
  ipcMain.handle('cyberguard:web-shield-domains', () => webShield.getBlockedDomains());
  ipcMain.handle('cyberguard:web-shield-evaluate', (event, url) => webShield.evaluateUrl(url));
  ipcMain.handle('cyberguard:web-shield-evaluate-live', (event, { url, userId }) => webShield.evaluateUrlLive(url, userId));
  ipcMain.handle('cyberguard:web-shield-record', (event, { domain, action, reason, userId, extra }) => {
    return webShield.recordObservation(domain, action, reason, userId, extra);
  });

  // Gmail Protection
  ipcMain.handle('cyberguard:gmail-status', (event, userId) => gmailService.getStatus(userId));
  ipcMain.handle('cyberguard:gmail-start-oauth', (event, { userId, userEmail } = {}) => gmailService.startOAuthFlow(userId, userEmail));
  ipcMain.handle('cyberguard:gmail-simulate', (event, userId) => gmailService.simulateTestAccount(userId));
  ipcMain.handle('cyberguard:gmail-sync', (event, userId) => gmailService.syncMailbox(userId));
  ipcMain.handle('cyberguard:gmail-authorize', (event, email, tokens, userId) => gmailService.authorize(email, tokens, userId));
  ipcMain.handle('cyberguard:gmail-revoke', (event, userId) => gmailService.revoke(userId));
  ipcMain.handle('cyberguard:gmail-inspect', (event, { emailData, userId }) => gmailService.inspectEmail(emailData || event, userId));
  ipcMain.handle('cyberguard:gmail-findings', (event, userId) => gmailService.getFindings(userId));
  ipcMain.handle('cyberguard:gmail-update-category', (event, { emailId, category, userId }) => gmailService.updateCategory(emailId, category, userId));
  ipcMain.handle('cyberguard:gmail-save-client-id', (event, clientId) => localStore.saveGoogleClientId(clientId));
  ipcMain.handle('cyberguard:gmail-get-client-id', () => localStore.getGoogleClientId());
  ipcMain.handle('cyberguard:gmail-clear-emails', (event, userId) => localStore.clearEmails(userId));

  // Alerts, Scans, Browsing History
  ipcMain.handle('cyberguard:alerts-list', () => localStore.getAlerts());
  ipcMain.handle('cyberguard:alerts-add', (event, alert) => localStore.addAlert(alert));
  ipcMain.handle('cyberguard:alerts-resolve', (event, id) => localStore.resolveAlert(id));
  ipcMain.handle('cyberguard:scans-history', () => localStore.getScanHistory());
  ipcMain.handle('cyberguard:browsing-history', () => localStore.getBrowsingHistory());
}

// Single-instance focus handling
app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

// Security Hardening (Part 9 & AC-21/AC-22):
// Clear active session and stop background engines on application exit.
function handleApplicationShutdown() {
  fileWatcher.stop();
  processMonitor.stop();
  localStore.clearSession();
}

app.on('window-all-closed', () => {
  handleApplicationShutdown();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  handleApplicationShutdown();
});
