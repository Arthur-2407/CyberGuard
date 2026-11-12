/**
 * CyberGuard Desktop — Hardened Preload Security Bridge
 * 
 * Strict Isolation Model:
 *  - Runs in an isolated execution context (contextIsolation: true)
 *  - Exposes narrow, typed asynchronous IPC invocations to the renderer
 *  - ZERO direct access to Node.js require, Buffer, or process
 */

const { contextBridge, ipcRenderer } = require('electron');

// ── Compatibility layer for legacy desktop checks ──
contextBridge.exposeInMainWorld('cyberguardDesktop', {
  isDesktop: true,
  platform: process.platform,
  arch: process.arch,
  version: '1.0.0',
  defaultCloudEndpoint: 'https://cyberguard-backend-8rbz.onrender.com',
  getAppVersion: () => '1.0.0',
  openExternal: (url) => ipcRenderer.invoke('cyberguard:open-external', url),
  showNotification: (title, body) => ipcRenderer.invoke('cyberguard:notify', { title, body })
});

// ── Enterprise Endpoint Security Client Bridge ──
contextBridge.exposeInMainWorld('cyberguardEndpoint', {
  // System & Environment
  isDesktop: true,
  platform: process.platform,
  version: '1.0.0',

  // Dialogs & Native OS
  selectFile: () => ipcRenderer.invoke('cyberguard:select-file'),
  selectFolder: () => ipcRenderer.invoke('cyberguard:select-folder'),
  openExternal: (url) => ipcRenderer.invoke('cyberguard:open-external', url),
  showNotification: (title, body, severity) => ipcRenderer.invoke('cyberguard:notify', { title, body, severity }),
  getNetworkInterface: () => ipcRenderer.invoke('cyberguard:get-network-interface'),

  // Configuration & Connection Modes
  getConfig: () => ipcRenderer.invoke('cyberguard:get-config'),
  saveConfig: (updates) => ipcRenderer.invoke('cyberguard:save-config', updates),
  getConnectionHealth: (mode, endpoint) => ipcRenderer.invoke('cyberguard:check-health', { mode, endpoint }),
  diagnoseConnectivity: (params) => ipcRenderer.invoke('cyberguard:diagnose-connectivity', params),

  // Authentication & Zero-Trust Session
  login: (usernameOrEmail, password, endpoint) => ipcRenderer.invoke('cyberguard:auth-login', { usernameOrEmail, password, endpoint }),
  register: (username, email, password, endpoint) => ipcRenderer.invoke('cyberguard:auth-register', { username, email, password, endpoint }),
  verifySession: (endpoint) => ipcRenderer.invoke('cyberguard:auth-verify', { endpoint }),
  logout: () => ipcRenderer.invoke('cyberguard:auth-logout'),
  getSession: () => ipcRenderer.invoke('cyberguard:auth-get-session'),

  // Real-Time File Monitoring
  getFileWatcherStatus: () => ipcRenderer.invoke('cyberguard:file-watcher-status'),
  startFileWatcher: () => ipcRenderer.invoke('cyberguard:file-watcher-start'),
  stopFileWatcher: () => ipcRenderer.invoke('cyberguard:file-watcher-stop'),
  updateMonitoredPaths: (paths) => ipcRenderer.invoke('cyberguard:file-watcher-set-paths', paths),
  scanLocalFile: (filePath) => ipcRenderer.invoke('cyberguard:scan-local-file', filePath),

  // Multimodal Forensic Scanner & Deep Inspection
  detectModality: (filePath) => ipcRenderer.invoke('cyberguard:multimodal-detect-modality', filePath),
  scanMultimodalFile: (filePath, options) => ipcRenderer.invoke('cyberguard:multimodal-scan', { filePath, options }),
  explainMalware: (scanId, sha256, forceRefresh) => ipcRenderer.invoke('cyberguard:multimodal-explain', { scanId, sha256, forceRefresh }),

  // Application & Process Monitoring
  getProcessMonitorStatus: () => ipcRenderer.invoke('cyberguard:process-monitor-status'),
  startProcessMonitor: () => ipcRenderer.invoke('cyberguard:process-monitor-start'),
  stopProcessMonitor: () => ipcRenderer.invoke('cyberguard:process-monitor-stop'),

  // Quarantine Vault
  getQuarantineItems: () => ipcRenderer.invoke('cyberguard:quarantine-list'),
  quarantineFile: (filePath, threatInfo) => ipcRenderer.invoke('cyberguard:quarantine-file', { filePath, threatInfo }),
  restoreQuarantineFile: (id, targetPath) => ipcRenderer.invoke('cyberguard:quarantine-restore', { id, targetPath }),
  deleteQuarantineFile: (id) => ipcRenderer.invoke('cyberguard:quarantine-delete', id),

  // Web & Live DNS Shield
  getWebShieldStatus: () => ipcRenderer.invoke('cyberguard:web-shield-status'),
  toggleWebShield: (enabled) => ipcRenderer.invoke('cyberguard:web-shield-toggle', enabled),
  getBlockedDomains: () => ipcRenderer.invoke('cyberguard:web-shield-domains'),
  evaluateUrl: (url) => ipcRenderer.invoke('cyberguard:web-shield-evaluate', url),
  evaluateUrlLive: (url, userId) => ipcRenderer.invoke('cyberguard:web-shield-evaluate-live', { url, userId }),
  recordBrowsingObservation: (domain, action, reason, userId, extra) => ipcRenderer.invoke('cyberguard:web-shield-record', { domain, action, reason, userId, extra }),

  // Generic Main-Process API Request Broker (Zero CORS / Zero PNA / Auto Hybrid Failover)
  apiRequest: (options) => ipcRenderer.invoke('cyberguard:api-request', options),

  // Gmail Protection
  getGmailStatus: (userId) => ipcRenderer.invoke('cyberguard:gmail-status', userId),
  startGmailOAuth: (userId, userEmail) => ipcRenderer.invoke('cyberguard:gmail-start-oauth', { userId, userEmail }),
  simulateGmail: (userId) => ipcRenderer.invoke('cyberguard:gmail-simulate', userId),
  syncGmail: (userId) => ipcRenderer.invoke('cyberguard:gmail-sync', userId),
  authorizeGmail: (email, tokens, userId) => ipcRenderer.invoke('cyberguard:gmail-authorize', email, tokens, userId),
  revokeGmail: (userId) => ipcRenderer.invoke('cyberguard:gmail-revoke', userId),
  inspectEmail: (emailData, userId) => ipcRenderer.invoke('cyberguard:gmail-inspect', { emailData, userId }),
  getGmailFindings: (userId) => ipcRenderer.invoke('cyberguard:gmail-findings', userId),
  updateGmailCategory: (emailId, category, userId) => ipcRenderer.invoke('cyberguard:gmail-update-category', { emailId, category, userId }),
  saveGoogleClientId: (clientId) => ipcRenderer.invoke('cyberguard:gmail-save-client-id', clientId),
  getGoogleClientId: () => ipcRenderer.invoke('cyberguard:gmail-get-client-id'),
  clearGmailEmails: (userId) => ipcRenderer.invoke('cyberguard:gmail-clear-emails', userId),

  // Security Alerts & Scans History
  getAlerts: (userId) => ipcRenderer.invoke('cyberguard:alerts-list', userId),
  addAlert: (alert) => ipcRenderer.invoke('cyberguard:alerts-add', alert),
  resolveAlert: (id) => ipcRenderer.invoke('cyberguard:alerts-resolve', id),
  getScanHistory: (userId) => ipcRenderer.invoke('cyberguard:scans-history', userId),
  getBrowsingHistory: (userId) => ipcRenderer.invoke('cyberguard:browsing-history', userId),

  // Real-Time Event Subscription (From Node backend to Renderer)
  onSecurityEvent: (callback) => {
    const subscription = (event, data) => callback(data);
    ipcRenderer.on('cyberguard:security-event', subscription);
    return () => ipcRenderer.removeListener('cyberguard:security-event', subscription);
  }
});
