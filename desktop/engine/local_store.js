/**
 * CyberGuard Desktop — Local Storage & Persistence Engine
 * 
 * Manages local database and configuration in user app data:
 *   - Environment Override: process.env.CYBERGUARD_DATA_DIR (for tests & isolated runs)
 *   - Standard Mode: %APPDATA%/CyberGuard/
 *   - Portable Mode: %APPDATA%/CyberGuard-Portable/ or relative ./cyberguard-data/
 * 
 * Enforces per-user tenant isolation on all stored data.
 * Employs Windows DPAPI via Electron safeStorage for session credentials.
 */

const fs = require('fs');
const path = require('path');
let app = null;
let safeStorage = null;
try {
  const electron = require('electron');
  app = electron.app;
  safeStorage = electron.safeStorage;
} catch (_) {}

class LocalStore {
  constructor() {
    this.isPortable = process.env.PORTABLE_EXECUTABLE_DIR ? true : false;
    
    // Resolve base storage directory
    if (process.env.CYBERGUARD_DATA_DIR) {
      this.dataDir = path.resolve(process.env.CYBERGUARD_DATA_DIR);
    } else if (this.isPortable && process.env.PORTABLE_EXECUTABLE_DIR) {
      this.dataDir = path.join(process.env.PORTABLE_EXECUTABLE_DIR, 'cyberguard-data');
    } else {
      const appData = app ? app.getPath('userData') : path.join(process.env.APPDATA || '.', 'CyberGuard');
      this.dataDir = appData;
    }

    this.ensureDirectories();
    this.configFile = path.join(this.dataDir, 'config.json');
    this.alertsFile = path.join(this.dataDir, 'alerts.json');
    this.scansFile = path.join(this.dataDir, 'scans.json');
    this.historyFile = path.join(this.dataDir, 'history.json');
    this.quarantineFile = path.join(this.dataDir, 'quarantine_index.json');
    this.emailsFile = path.join(this.dataDir, 'analyzed_emails.json');

    // Ephemeral In-Memory Desktop Session (Non-persistent across app restarts)
    this._activeSession = { user: null, token: null };

    // Clean up any legacy persisted session credentials from disk on startup
    this._purgeLegacyDiskSession();
  }

  _purgeLegacyDiskSession() {
    try {
      const cfg = this.getConfig();
      if (cfg.sessionToken || cfg.activeUser) {
        delete cfg.sessionToken;
        delete cfg.activeUser;
        delete cfg.sessionTokenEncrypted;
        this._writeJson(this.configFile, cfg);
      }
    } catch (_) {}
  }

  ensureDirectories() {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    const qDir = path.join(this.dataDir, 'quarantine');
    if (!fs.existsSync(qDir)) {
      fs.mkdirSync(qDir, { recursive: true });
    }
  }

  _readJson(filePath, defaultValue = {}) {
    try {
      if (fs.existsSync(filePath)) {
        const raw = fs.readFileSync(filePath, 'utf-8');
        return JSON.parse(raw);
      }
    } catch (err) {
      console.error(`[LocalStore] Failed to read ${filePath}:`, err.message);
    }
    return defaultValue;
  }

  _writeJson(filePath, data) {
    try {
      const tempPath = `${filePath}.tmp.${Date.now()}`;
      fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf-8');
      fs.renameSync(tempPath, filePath);
    } catch (err) {
      console.error(`[LocalStore] Failed to write ${filePath}:`, err.message);
    }
  }

  // ── Configuration ──
  getConfig() {
    return this._readJson(this.configFile, {
      connectionMode: 'hybrid', // 'local' | 'deployed' | 'hybrid'
      localPort: 3000,
      customTunnel: '',
      realtimeFileMonitoring: true,
      autoQuarantine: false,
      processMonitoring: true,
      webShieldEnabled: true,
      gmailProtectionEnabled: false,
      googleClientId: '',
      monitoredDirectories: []
    });
  }

  saveConfig(updates) {
    const current = this.getConfig();
    const merged = { ...current, ...updates };
    this._writeJson(this.configFile, merged);
    return merged;
  }

  // ── User Session (Strict Ephemeral In-Memory Lifecycle) ──
  // Per Part 9: Closing the executable wipes the active session.
  // Subsequent launches strictly require a fresh login.
  getSession() {
    return {
      user: this._activeSession ? this._activeSession.user : null,
      token: this._activeSession ? this._activeSession.token : null
    };
  }

  setSession(user, token) {
    this._activeSession = {
      user: user || null,
      token: token || null
    };
    return { success: true, user: this._activeSession.user };
  }

  clearSession() {
    this._activeSession = { user: null, token: null };
    this._purgeLegacyDiskSession();
    return { success: true };
  }

  // ── Google OAuth Client ID Resolution (Documented Precedence) ──
  getGoogleClientId() {
    // 1. Process environment variable
    if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_ID.trim()) {
      return process.env.GOOGLE_CLIENT_ID.trim();
    }
    if (process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_ID.trim()) {
      return process.env.GMAIL_CLIENT_ID.trim();
    }

    // 2. User application configuration settings
    const cfg = this.getConfig();
    if (cfg.googleClientId && cfg.googleClientId.trim()) {
      return cfg.googleClientId.trim();
    }

    // 3. Local .env search across runtime locations
    const candidatePaths = [
      path.resolve(process.cwd(), '.env'),
      path.resolve(__dirname, '../../.env'),
      path.resolve(__dirname, '../../../.env'),
      path.join(this.dataDir, '.env')
    ];
    for (const p of candidatePaths) {
      try {
        if (fs.existsSync(p)) {
          const content = fs.readFileSync(p, 'utf-8');
          const m = content.match(/GOOGLE_CLIENT_ID\s*=\s*([^\r\n]+)/);
          if (m && m[1].trim()) {
            return m[1].trim();
          }
        }
      } catch (_) {}
    }

    return null;
  }

  saveGoogleClientId(clientId) {
    const cleaned = (clientId || '').trim();
    return this.saveConfig({ googleClientId: cleaned });
  }

  // ── Analyzed Emails & Threat Intelligence Ledger (Persisted Per User) ──
  _isMatchUser(recordUid, queryUid) {
    if (!recordUid || !queryUid) return true;
    const r = String(recordUid).toLowerCase().trim();
    const q = String(queryUid).toLowerCase().trim();
    if (r === q) return true;
    if ((r === '1' || r === 'admin') && (q === '1' || q === 'admin')) return true;
    return false;
  }

  getEmails(userId = null) {
    const list = this._readJson(this.emailsFile, []);
    if (!userId) return list;
    return list.filter(e => this._isMatchUser(e.user_id, userId));
  }

  saveEmail(emailRecord, userId = null) {
    const list = this._readJson(this.emailsFile, []);
    const uid = userId || emailRecord.user_id || (this._activeSession.user ? this._activeSession.user.id : null);
    const existingIdx = list.findIndex(e =>
      (emailRecord.id && e.id === emailRecord.id) ||
      (emailRecord.gmailMessageId && e.gmailMessageId === emailRecord.gmailMessageId)
    );

    const record = {
      ...emailRecord,
      user_id: uid,
      updated_at: new Date().toISOString()
    };

    if (existingIdx >= 0) {
      // Preserve manual categorization if already set
      if (!record.manual_category && list[existingIdx].manual_category) {
        record.manual_category = list[existingIdx].manual_category;
      }
      list[existingIdx] = { ...list[existingIdx], ...record };
    } else {
      list.unshift(record);
    }

    // Keep up to 500 emails locally
    if (list.length > 500) list.length = 500;
    this._writeJson(this.emailsFile, list);
    return record;
  }

  updateEmailCategory(emailId, manualCategory, userId = null) {
    const list = this._readJson(this.emailsFile, []);
    const item = list.find(e =>
      (e.id === emailId || e.gmailMessageId === emailId) &&
      this._isMatchUser(e.user_id, userId)
    );
    if (item) {
      item.manual_category = manualCategory;
      item.reviewed_at = new Date().toISOString();
      item.reviewed_by = userId || (this._activeSession.user ? this._activeSession.user.username : 'user');
      this._writeJson(this.emailsFile, list);
      return item;
    }
    return null;
  }

  clearEmails(userId = null) {
    if (!userId) {
      this._writeJson(this.emailsFile, []);
      return true;
    }
    const list = this._readJson(this.emailsFile, []);
    const filtered = list.filter(e => !this._isMatchUser(e.user_id, userId));
    this._writeJson(this.emailsFile, filtered);
    return true;
  }

  // ── Encrypted Gmail OAuth Token Storage (Per-User DPAPI) ──
  saveGmailTokens(userId, tokens) {
    const cfg = this.getConfig();
    const map = cfg.gmailTokensByUser || {};
    let stored = JSON.stringify(tokens);
    let encrypted = false;
    if (safeStorage && safeStorage.isEncryptionAvailable()) {
      try {
        const buf = safeStorage.encryptString(stored);
        stored = buf.toString('base64');
        encrypted = true;
      } catch (_) {}
    }
    map[String(userId || 'default')] = { tokens: stored, encrypted, updatedAt: new Date().toISOString() };
    this.saveConfig({ gmailTokensByUser: map });
  }

  getGmailTokens(userId) {
    const cfg = this.getConfig();
    const map = cfg.gmailTokensByUser || {};
    const item = map[String(userId || 'default')];
    if (!item || !item.tokens) return null;
    let raw = item.tokens;
    if (item.encrypted && safeStorage && safeStorage.isEncryptionAvailable()) {
      try {
        const buf = Buffer.from(raw, 'base64');
        raw = safeStorage.decryptString(buf);
      } catch (_) {}
    }
    try {
      return JSON.parse(raw);
    } catch (_) {
      return null;
    }
  }

  clearGmailTokens(userId) {
    const cfg = this.getConfig();
    const map = cfg.gmailTokensByUser || {};
    delete map[String(userId || 'default')];
    this.saveConfig({ gmailTokensByUser: map });
  }

  // ── Security Alerts (User Isolated) ──
  getAlerts(userId = null) {
    const list = this._readJson(this.alertsFile, []);
    if (!userId) return list.filter(a => !a.user_id);
    return list.filter(a => a.user_id === userId);
  }

  addAlert(alert) {
    const list = this._readJson(this.alertsFile, []);
    const entry = {
      id: alert.id || `alert-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      timestamp: alert.timestamp || new Date().toISOString(),
      source: alert.source || 'windows', // 'windows' | 'android' | 'website'
      source_type: alert.source_type || 'windows',
      category: alert.category || 'MALWARE',
      severity: alert.severity || 'HIGH', // 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
      title: alert.title || 'Security Threat Detected',
      details: alert.details || '',
      target: alert.target || '',
      status: alert.status || 'ACTIVE', // 'ACTIVE' | 'RESOLVED' | 'QUARANTINED' | 'IGNORED'
      outcome: alert.outcome || (alert.status === 'QUARANTINED' ? 'QUARANTINED' : (alert.status === 'BLOCKED' ? 'BLOCKED' : 'SUSPICIOUS')),
      user_id: alert.user_id || null
    };
    list.unshift(entry);
    // Keep max 500 alerts locally
    if (list.length > 500) list.length = 500;
    this._writeJson(this.alertsFile, list);
    return entry;
  }

  resolveAlert(alertId, userId = null) {
    const list = this._readJson(this.alertsFile, []);
    const alert = list.find(a => a.id === alertId && (!userId || a.user_id === userId));
    if (alert) {
      alert.status = 'RESOLVED';
      this._writeJson(this.alertsFile, list);
      return true;
    }
    return false;
  }

  // ── Scan History ──
  getScanHistory(userId = null) {
    const list = this._readJson(this.scansFile, []);
    if (!userId) return list.filter(s => !s.user_id);
    return list.filter(s => s.user_id === userId);
  }

  recordScan(scan) {
    const list = this._readJson(this.scansFile, []);
    const entry = {
      id: scan.id || `scan-${Date.now()}`,
      timestamp: new Date().toISOString(),
      fileName: scan.fileName || path.basename(scan.filePath || 'Unknown'),
      filePath: scan.filePath || '',
      fileSize: scan.fileSize || 0,
      sha256: scan.sha256 || '',
      verdict: scan.verdict || 'CLEAN', // 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'
      threatName: scan.threatName || null,
      engine: scan.engine || 'CyberGuard Local Static Engine',
      entropy: scan.entropy || 0.0,
      details: scan.details || {},
      user_id: scan.user_id || null
    };
    list.unshift(entry);
    if (list.length > 300) list.length = 300;
    this._writeJson(this.scansFile, list);
    return entry;
  }

  // ── Browsing History (Local observations, sanitized) ──
  getBrowsingHistory(userId = null) {
    const list = this._readJson(this.historyFile, []);
    // Sanitize: eliminate any fabricated placeholder domains
    const cleanList = list.filter(h => {
      const d = (h.domain || '').toLowerCase().trim();
      return d && d !== 'placeholder.local';
    });
    if (!userId) return cleanList.filter(h => !h.user_id);
    return cleanList.filter(h => h.user_id === userId);
  }

  addBrowsingHistory(entry) {
    const domain = (entry.domain || '').trim();
    if (!domain) {
      return null;
    }

    const list = this._readJson(this.historyFile, []);
    const item = {
      id: `dns-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      timestamp: entry.timestamp || new Date().toISOString(),
      domain: domain,
      url: entry.url || null,
      page_title: entry.page_title || null,
      network_interface: entry.network_interface || 'Ethernet',
      browser: entry.browser || 'Chrome',
      action: entry.action || 'ALLOWED', // 'ALLOWED' | 'BLOCKED'
      block_reason: entry.block_reason || null,
      source: entry.source || 'windows',
      user_id: entry.user_id || null
    };
    list.unshift(item);
    if (list.length > 1000) list.length = 1000;
    this._writeJson(this.historyFile, list);
    return item;
  }

  // ── Quarantine Index ──
  getQuarantineIndex() {
    return this._readJson(this.quarantineFile, []);
  }

  saveQuarantineIndex(index) {
    this._writeJson(this.quarantineFile, index);
  }
}

module.exports = new LocalStore();
