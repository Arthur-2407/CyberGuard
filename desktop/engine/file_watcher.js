/**
 * CyberGuard Desktop — Real-Time File Monitoring & Threat Interceptor
 *
 * Capabilities:
 *   - Event-driven filesystem observation with bounded sliding debounce queue
 *   - File write stability detection (handles in-progress browser downloads)
 *   - Cryptographic SHA-256 fingerprinting & content magic-byte verification
 *   - Shannon entropy calculation ($H = -\sum p_i \log_2 p_i$)
 *   - EICAR test string & packed binary heuristic detection
 *   - Safe quarantine containment & native Windows Toast Notifications
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const localStore = require('./local_store');
const quarantineManager = require('./quarantine_manager');

// EICAR Standard Antivirus Test Pattern
const EICAR_PATTERN = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

class FileWatcherService {
  constructor() {
    this.isActive = false;
    this.watchers = new Map(); // path -> fs.FSWatcher
    this.monitoredPaths = [];
    this.debounceMap = new Map(); // path -> timeoutId
    this.processedHashes = new Set(); // deduplication cache
    this.notificationCallback = null;
    this.eventListeners = [];

    // Initialize default target directories
    this.initDefaultPaths();
  }

  initDefaultPaths() {
    const userHome = os.homedir();
    const defaults = [];

    const downloads = path.join(userHome, 'Downloads');
    if (fs.existsSync(downloads)) defaults.push(downloads);

    const tempDir = os.tmpdir();
    if (fs.existsSync(tempDir)) defaults.push(tempDir);

    const saved = localStore.getConfig().monitoredDirectories || [];
    this.monitoredPaths = saved.length > 0 ? saved : defaults;
  }

  setNotificationHandler(callback) {
    this.notificationCallback = callback;
  }

  onEvent(callback) {
    this.eventListeners.push(callback);
  }

  emitEvent(event) {
    this.eventListeners.forEach(cb => {
      try { cb(event); } catch (e) { /* ignore listener err */ }
    });
  }

  getStatus() {
    return {
      active: this.isActive,
      serviceType: 'user_space_fs_watcher',
      monitoredPaths: this.monitoredPaths,
      watcherCount: this.watchers.size,
      cachedHashesCount: this.processedHashes.size,
      limitations: 'User-mode event-driven directory observation; post-write detection, does not replace kernel minifilter pre-execution driver'
    };
  }

  start() {
    if (this.isActive) return;
    this.isActive = true;

    for (const dirPath of this.monitoredPaths) {
      this._watchDirectory(dirPath);
    }

    localStore.saveConfig({ realtimeFileMonitoring: true });
    console.log(`[FileWatcher] Real-time file monitoring activated on ${this.monitoredPaths.length} locations.`);
  }

  stop() {
    if (!this.isActive) return;
    this.isActive = false;

    for (const [dir, watcher] of this.watchers.entries()) {
      try {
        watcher.close();
      } catch (err) {
        console.warn(`[FileWatcher] Error closing watcher for ${dir}:`, err.message);
      }
    }
    this.watchers.clear();
    this.debounceMap.clear();

    localStore.saveConfig({ realtimeFileMonitoring: false });
    console.log('[FileWatcher] Real-time file monitoring paused.');
  }

  updateMonitoredPaths(paths) {
    const wasActive = this.isActive;
    if (wasActive) this.stop();

    this.monitoredPaths = paths.filter(p => fs.existsSync(p));
    localStore.saveConfig({ monitoredDirectories: this.monitoredPaths });

    if (wasActive) this.start();
  }

  _watchDirectory(dirPath) {
    if (!fs.existsSync(dirPath)) return;

    try {
      const watcher = fs.watch(dirPath, { recursive: false }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(dirPath, filename);
        this._scheduleInspection(fullPath, eventType);
      });

      watcher.on('error', (err) => {
        console.warn(`[FileWatcher] Watcher error on ${dirPath}:`, err.message);
      });

      this.watchers.set(dirPath, watcher);
    } catch (err) {
      console.warn(`[FileWatcher] Failed to attach watch on ${dirPath}:`, err.message);
    }
  }

  _scheduleInspection(filePath, eventType) {
    // Ignore internal temporary and quarantine files
    if (filePath.endsWith('.tmp') || filePath.endsWith('.cgq') || filePath.includes('quarantine')) {
      return;
    }

    if (this.debounceMap.has(filePath)) {
      clearTimeout(this.debounceMap.get(filePath));
    }

    // 500ms debounce window
    const timer = setTimeout(() => {
      this.debounceMap.delete(filePath);
      this._inspectFileSafely(filePath, eventType);
    }, 500);

    this.debounceMap.set(filePath, timer);
  }

  async _inspectFileSafely(filePath, eventType) {
    if (!fs.existsSync(filePath)) return;

    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile() || stat.size === 0) return;

      // File stability check: verify size doesn't change over 300ms (in-progress download)
      await new Promise(res => setTimeout(res, 300));
      if (!fs.existsSync(filePath)) return;
      const stat2 = fs.statSync(filePath);
      if (stat2.size !== stat.size) {
        // Still writing, reschedule
        this._scheduleInspection(filePath, eventType);
        return;
      }

      const analysis = this.analyzeLocalFile(filePath);
      if (!analysis) return;

      // Notify UI
      this.emitEvent({
        type: 'FILE_INSPECTED',
        filePath: filePath,
        fileName: path.basename(filePath),
        verdict: analysis.verdict,
        entropy: analysis.entropy,
        threatName: analysis.threatName,
        sha256: analysis.sha256,
        timestamp: new Date().toISOString()
      });

      // Record in local scan history
      const config = localStore.getConfig();
      const activeUser = config.activeUser ? config.activeUser.id : null;
      localStore.recordScan({
        filePath: filePath,
        fileName: path.basename(filePath),
        fileSize: stat.size,
        sha256: analysis.sha256,
        verdict: analysis.verdict,
        threatName: analysis.threatName,
        engine: analysis.engine,
        entropy: analysis.entropy,
        details: analysis.details,
        user_id: activeUser
      });

      if (analysis.verdict === 'MALICIOUS' || analysis.verdict === 'SUSPICIOUS') {
        const title = analysis.verdict === 'MALICIOUS' ? 'Malware Threat Intercepted' : 'Suspicious File Activity';
        const body = `${path.basename(filePath)} (${analysis.threatName})`;

        // Trigger native notification
        if (this.notificationCallback) {
          this.notificationCallback({
            title: title,
            body: `${body} — Detected in real-time.`,
            severity: analysis.verdict === 'MALICIOUS' ? 'CRITICAL' : 'HIGH'
          });
        }

        // Auto-quarantine if enabled or high confidence
        if (config.autoQuarantine && analysis.verdict === 'MALICIOUS') {
          quarantineManager.quarantineFile(filePath, {
            threatName: analysis.threatName,
            category: 'MALWARE',
            severity: 'CRITICAL',
            engine: analysis.engine
          }, activeUser);

          this.emitEvent({
            type: 'FILE_QUARANTINED',
            filePath: filePath,
            fileName: path.basename(filePath),
            quarantinedAt: new Date().toISOString()
          });
        }
      }
    } catch (err) {
      console.warn(`[FileWatcher] Error inspecting file ${filePath}:`, err.message);
    }
  }

  // ── Static Inspection Logic ──
  analyzeLocalFile(filePath) {
    if (!fs.existsSync(filePath)) return null;

    const buffer = fs.readFileSync(filePath);
    const size = buffer.length;

    // Cryptographic hash
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // Shannon entropy: H = -sum(p * log2(p))
    const entropy = this._calculateEntropy(buffer);

    // Header inspection
    const headerHex = buffer.slice(0, 4).toString('hex').toUpperCase();
    const isPE = buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A; // MZ header
    const isELF = headerHex.startsWith('7F454C46');
    const isZip = headerHex.startsWith('504B0304');

    // Check EICAR standard test pattern
    const contentAscii = buffer.slice(0, Math.min(buffer.length, 4096)).toString('ascii');
    if (contentAscii.includes(EICAR_PATTERN)) {
      return {
        verdict: 'MALICIOUS',
        threatName: 'EICAR-Test-Signature.Standard',
        severity: 'HIGH',
        confidence: 1.0,
        entropy: Number(entropy.toFixed(2)),
        sha256: sha256,
        engine: 'CyberGuard Static Signature Engine',
        details: { magic: isPE ? 'PE32/MZ' : 'ASCII', size: size, rule: 'EICAR_STANDARD' }
      };
    }

    // Double extension check (e.g. filename.pdf.exe)
    const base = path.basename(filePath).toLowerCase();
    const isDoubleExt = /\.(pdf|docx|xlsx|jpg|png|txt)\.(exe|vbs|bat|cmd|ps1|scr|js)$/i.test(base);
    if (isDoubleExt) {
      return {
        verdict: 'SUSPICIOUS',
        threatName: 'Heuristic.DoubleExtensionMasking',
        severity: 'HIGH',
        confidence: 0.88,
        entropy: Number(entropy.toFixed(2)),
        sha256: sha256,
        engine: 'CyberGuard Heuristic Inspector',
        details: { filename: base, size: size, indicator: 'Double extension disguise detected' }
      };
    }

    // High PE entropy check (Packed / Encrypted executable)
    if (isPE && entropy >= 7.35 && size > 16384) {
      return {
        verdict: 'SUSPICIOUS',
        threatName: 'Heuristic.HighEntropyPackedBinary',
        severity: 'MEDIUM',
        confidence: 0.76,
        entropy: Number(entropy.toFixed(2)),
        sha256: sha256,
        engine: 'CyberGuard Structural Entropy Engine',
        details: { magic: 'PE32/MZ', entropy: entropy, size: size, indicator: 'High entropy packing detected' }
      };
    }

    // Clean file
    return {
      verdict: 'CLEAN',
      threatName: null,
      severity: 'INFO',
      confidence: 0.99,
      entropy: Number(entropy.toFixed(2)),
      sha256: sha256,
      engine: 'CyberGuard Local Static Engine',
      details: { magic: isPE ? 'PE/MZ' : isZip ? 'ZIP' : 'RAW', size: size }
    };
  }

  _calculateEntropy(buffer) {
    if (buffer.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      freq[buffer[i]]++;
    }
    let entropy = 0;
    const len = buffer.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }
}

module.exports = new FileWatcherService();
