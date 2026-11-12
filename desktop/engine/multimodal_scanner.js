/**
 * CyberGuard Desktop — Multi-Modal Forensic Scanner Engine
 * 
 * Coordinates deep forensic analysis across:
 *   - Neural Voice Clone Defense & Speaker Authenticity (/api/analyze)
 *   - Multimodal Image Forensics (ELA / 2D-FFT / C2PA / MobileNetV3 via /api/threats/image)
 *   - Temporal Video Forensics (Multi-frame consistency via /api/threats/video)
 *   - Multi-Engine Malware Lab (ClamAV / YARA / PE / Documents via /api/threats/malware/scan)
 *   - Evidence-Grounded Qwen Threat Explanation (/api/threats/malware/explain)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const localStore = require('./local_store');

// Supported file extension groupings
const AUDIO_EXTS = new Set(['.wav', '.mp3', '.m4a', '.flac', '.ogg', '.aac', '.wma', '.opus']);
const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.bmp', '.tiff', '.tif', '.gif']);
const VIDEO_EXTS = new Set(['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v']);
const EXEC_EXTS  = new Set(['.exe', '.dll', '.sys', '.bin', '.elf', '.msi', '.scr', '.vbs', '.bat', '.ps1', '.cmd', '.com']);
const DOC_EXTS   = new Set(['.pdf', '.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt', '.rtf', '.odt']);
const ARCH_EXTS  = new Set(['.zip', '.tar', '.gz', '.7z', '.rar', '.bz2', '.iso']);

class MultimodalScanner {
  constructor() {
    this.notificationCallback = null;
  }

  setNotificationHandler(callback) {
    this.notificationCallback = callback;
  }

  /**
   * Determine modality from file extension and header bytes.
   */
  detectModality(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    if (AUDIO_EXTS.has(ext)) return 'AUDIO';
    if (IMAGE_EXTS.has(ext)) return 'IMAGE';
    if (VIDEO_EXTS.has(ext)) return 'VIDEO';
    if (EXEC_EXTS.has(ext))  return 'MALWARE';
    if (DOC_EXTS.has(ext))   return 'DOCUMENT';
    if (ARCH_EXTS.has(ext))  return 'ARCHIVE';
    return 'GENERIC';
  }

  /**
   * Fast on-disk cryptographic and entropy fingerprinting.
   */
  calculateStaticMetrics(filePath) {
    const stat = fs.statSync(filePath);
    const buffer = fs.readFileSync(filePath);
    
    // SHA-256
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    // Shannon Entropy: H = -sum(p * log2(p))
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      freq[buffer[i]]++;
    }
    let entropy = 0.0;
    const len = buffer.length || 1;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }

    // Magic bytes identification
    let magic = 'Unknown Binary / Text';
    if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
      magic = 'PE Executable / DLL (MZ)';
    } else if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
      magic = 'ELF Executable (Linux/POSIX)';
    } else if (buffer.length >= 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
      magic = 'PNG Image';
    } else if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
      magic = 'JPEG Image';
    } else if (buffer.length >= 4 && buffer.toString('utf8', 0, 4) === 'RIFF') {
      magic = 'RIFF Container (WAV / AVI / WebP)';
    } else if (buffer.length >= 4 && buffer.toString('utf8', 0, 4) === '%PDF') {
      magic = 'PDF Document';
    } else if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4B && (buffer[2] === 0x03 || buffer[2] === 0x05)) {
      magic = 'ZIP Archive / Office OpenXML';
    }

    return {
      fileSize: stat.size,
      sha256,
      entropy: parseFloat(entropy.toFixed(3)),
      magic
    };
  }

  /**
   * Resolve active backend base URL from desktop configuration.
   */
  getBackendBaseUrl() {
    const cfg = localStore.getConfig();
    const mode = cfg.connectionMode || 'hybrid';
    if (mode === 'local') {
      const port = cfg.localPort || 3000;
      return `http://127.0.0.1:${port}`;
    }
    if (mode === 'deployed') {
      return (cfg.cloudEndpoint || 'https://cyberguard-backend-8rbz.onrender.com').replace(/\/+$/, '');
    }
    // Hybrid mode: Use configured tunnel or default cloud
    if (cfg.customTunnel && cfg.customTunnel.trim().length > 0) {
      return cfg.customTunnel.trim().replace(/\/+$/, '');
    }
    return (cfg.cloudEndpoint || 'https://cyberguard-backend-8rbz.onrender.com').replace(/\/+$/, '');
  }

  /**
   * Run full modality-aware multimodal forensic scan against backend pipelines.
   */
  async scanFile(filePath, options = {}) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Target file does not exist: ${filePath}`);
    }

    const fileName = path.basename(filePath);
    const staticMetrics = this.calculateStaticMetrics(filePath);
    const modality = options.forcedModality || this.detectModality(filePath);
    const backendBase = options.backendOverride || this.getBackendBaseUrl();
    const session = localStore.getSession();
    const token = session?.token || null;

    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const correlationId = options.correlationId || `scan_${crypto.randomBytes(6).toString('hex')}`;
    const startTime = Date.now();

    let scanResult = {
      scanId: correlationId,
      fileName,
      filePath,
      modality,
      fileSize: staticMetrics.fileSize,
      sha256: staticMetrics.sha256,
      entropy: staticMetrics.entropy,
      magic: staticMetrics.magic,
      backendUrl: backendBase,
      timestamp: new Date().toISOString(),
      verdict: 'UNKNOWN',
      threatCategory: 'NONE',
      severity: 'LOW',
      confidence: 1.0,
      engine: 'CyberGuard Forensic Pipeline',
      evidence: [],
      details: {},
      limitations: null,
      processingTimeMs: 0
    };

    try {
      if (modality === 'AUDIO') {
        scanResult = await this._scanAudio(filePath, fileName, backendBase, headers, scanResult);
      } else if (modality === 'IMAGE') {
        scanResult = await this._scanImage(filePath, fileName, backendBase, headers, correlationId, scanResult);
      } else if (modality === 'VIDEO') {
        scanResult = await this._scanVideo(filePath, fileName, backendBase, headers, correlationId, scanResult);
      } else {
        // MALWARE, DOCUMENT, ARCHIVE, or GENERIC -> Multi-engine malware coordinator
        scanResult = await this._scanMalware(filePath, fileName, backendBase, headers, correlationId, scanResult);
      }
    } catch (apiErr) {
      console.warn(`[MultimodalScanner] Backend pipeline error for ${modality}:`, apiErr.message);
      scanResult.verdict = 'INCONCLUSIVE';
      scanResult.severity = 'MEDIUM';
      scanResult.limitations = `Backend forensic connection error (${apiErr.message}). Local static metrics preserved.`;
      scanResult.evidence.push({
        type: 'CONNECTION_LIMITATION',
        description: `Failed to contact backend at ${backendBase}: ${apiErr.message}`
      });
    }

    scanResult.processingTimeMs = Date.now() - startTime;

    // Record scan in local user history
    localStore.recordScan({
      scanId: scanResult.scanId,
      fileName: scanResult.fileName,
      fileSize: scanResult.fileSize,
      entropy: scanResult.entropy,
      verdict: scanResult.verdict,
      sha256: scanResult.sha256,
      modality: scanResult.modality,
      severity: scanResult.severity,
      engine: scanResult.engine,
      threatCategory: scanResult.threatCategory,
      timestamp: scanResult.timestamp,
      user_id: session?.user?.id || null
    });

    // Threat Notification Policy: ONLY alert if genuine malware or critical threat
    if (this.notificationCallback && (scanResult.verdict === 'MALICIOUS' || scanResult.severity === 'CRITICAL')) {
      // Do not classify synthetic media as malware in notification
      const notifTitle = scanResult.modality === 'AUDIO' || scanResult.modality === 'IMAGE' || scanResult.modality === 'VIDEO'
        ? `Synthetic Media Detected: ${fileName}`
        : `Malware Blocked: ${fileName}`;
      this.notificationCallback({
        title: notifTitle,
        body: `Threat Category: ${scanResult.threatCategory} | Severity: ${scanResult.severity}`,
        severity: scanResult.severity
      });
    }

    return scanResult;
  }

  async _scanAudio(filePath, fileName, backendBase, headers, baseResult) {
    const fileBuffer = fs.readFileSync(filePath);
    const fileBlob = new Blob([fileBuffer], { type: 'audio/wav' });
    const formData = new FormData();
    formData.append('file', fileBlob, fileName);

    const res = await fetch(`${backendBase}/api/analyze`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const data = await res.json();
    baseResult.scanId = data.session_id || baseResult.scanId;
    baseResult.threatCategory = 'VOICE_CLONE_DEEPFAKE';
    baseResult.severity = data.alert_level || 'LOW';
    baseResult.engine = `AASIST / ECAPA-TDNN (${data.detector_version || 'v2'})`;
    baseResult.confidence = parseFloat((data.peak_risk || 0.0).toFixed(4));
    baseResult.verdict = (data.alert_level === 'CRITICAL' || data.alert_level === 'HIGH') ? 'SYNTHETIC_SPOOF' : 'NATURAL_SPEECH';
    baseResult.details = {
      peakRisk: data.peak_risk,
      meanRisk: data.mean_risk,
      finalRisk: data.final_risk,
      recommendation: data.recommendation,
      chunkScores: data.chunk_scores,
      pitchAnalysis: data.pitch_analysis,
      calibrationNotice: data.calibration_notice
    };
    baseResult.evidence = [
      {
        sensor: 'AASIST Neural Acoustic Model',
        metric: `Peak Voice Spoof Probability: ${(data.peak_risk * 100).toFixed(1)}%`,
        alertLevel: data.alert_level
      }
    ];
    return baseResult;
  }

  async _scanImage(filePath, fileName, backendBase, headers, correlationId, baseResult) {
    const fileBuffer = fs.readFileSync(filePath);
    const fileBlob = new Blob([fileBuffer], { type: 'image/png' });
    const formData = new FormData();
    formData.append('file', fileBlob, fileName);
    formData.append('source', 'windows_desktop_scanner');
    if (correlationId) formData.append('correlation_id', correlationId);

    const res = await fetch(`${backendBase}/api/threats/image`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const event = await res.json();
    baseResult.scanId = event.event_id || baseResult.scanId;
    baseResult.threatCategory = event.threat_category || 'DEEPFAKE_MEDIA';
    baseResult.severity = event.severity || 'LOW';
    baseResult.confidence = parseFloat((event.confidence || 0.0).toFixed(4));
    baseResult.engine = event.detector || 'MobileNetV3 / ELA / 2D-FFT Forensics';
    baseResult.verdict = event.classification || 'INCONCLUSIVE';
    baseResult.details = {
      forensicMetrics: event.forensic_metrics,
      c2paProvenance: event.c2pa_provenance,
      explanation: event.explanation,
      matrix: event.matrix,
      recommendedActions: event.recommended_actions,
      elaHeatmapBase64: event.ela_heatmap_base64
    };
    baseResult.evidence = event.evidence || [];
    return baseResult;
  }

  async _scanVideo(filePath, fileName, backendBase, headers, correlationId, baseResult) {
    const fileBuffer = fs.readFileSync(filePath);
    const fileBlob = new Blob([fileBuffer], { type: 'video/mp4' });
    const formData = new FormData();
    formData.append('file', fileBlob, fileName);
    formData.append('source', 'windows_desktop_scanner');
    if (correlationId) formData.append('correlation_id', correlationId);

    const res = await fetch(`${backendBase}/api/threats/video`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const event = await res.json();
    baseResult.scanId = event.event_id || baseResult.scanId;
    baseResult.threatCategory = event.threat_category || 'DEEPFAKE_MEDIA';
    baseResult.severity = event.severity || 'LOW';
    baseResult.confidence = parseFloat((event.confidence || 0.0).toFixed(4));
    baseResult.engine = event.detector || 'Video Multi-Frame Consistency Engine';
    baseResult.verdict = event.classification || 'INCONCLUSIVE';
    baseResult.details = {
      frameAnalysis: event.frame_analysis,
      forensicMetrics: event.forensic_metrics,
      explanation: event.explanation,
      recommendedActions: event.recommended_actions
    };
    baseResult.evidence = event.evidence || [];
    return baseResult;
  }

  async _scanMalware(filePath, fileName, backendBase, headers, correlationId, baseResult) {
    const fileBuffer = fs.readFileSync(filePath);
    const fileBlob = new Blob([fileBuffer], { type: 'application/octet-stream' });
    const formData = new FormData();
    formData.append('file', fileBlob, fileName);
    if (correlationId) formData.append('correlation_id', correlationId);

    const res = await fetch(`${backendBase}/api/threats/malware/scan`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const report = await res.json();
    baseResult.scanId = report.scan_id || baseResult.scanId;
    const verdictObj = report.verdict || {};
    baseResult.verdict = verdictObj.verdict || report.status || 'NO_DETECTION';
    baseResult.severity = verdictObj.severity || 'LOW';
    baseResult.confidence = parseFloat((verdictObj.confidence || 1.0).toFixed(4));
    baseResult.threatCategory = verdictObj.threat_category || 'MALWARE';
    baseResult.engine = 'ClamAV / YARA / PE / ThreatIntel Multi-Engine';
    baseResult.details = {
      engineBreakdown: verdictObj.engine_breakdown,
      fileInspection: report.file_inspection,
      recommendedActions: verdictObj.recommended_actions,
      mitreTechniqueId: verdictObj.mitre_technique_id,
      mitreTechniqueName: verdictObj.mitre_technique_name
    };
    baseResult.evidence = verdictObj.evidence || [];
    return baseResult;
  }

  /**
   * Evidence-grounded Qwen LLM explanation request.
   */
  async explainMalware(scanId, sha256 = null, forceRefresh = false) {
    const backendBase = this.getBackendBaseUrl();
    const session = localStore.getSession();
    const token = session?.token || null;

    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const payload = {
      scan_id: scanId,
      sha256: sha256 || undefined,
      force_refresh: Boolean(forceRefresh)
    };

    const res = await fetch(`${backendBase}/api/threats/malware/explain`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    return await res.json();
  }
}

module.exports = new MultimodalScanner();

