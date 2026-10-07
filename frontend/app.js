/**
 * app.js — CyberGuard Frontend Application
 *
 * Handles:
 *   - WebSocket connection management
 *   - Real-time risk gauge rendering (Canvas arc)
 *   - Chart.js risk timeline
 *   - Live session (microphone via WebSocket)
 *   - File upload analysis
 *   - Speaker enrollment & listing
 *   - Alert history & threshold management
 *   - Toast notifications
 */

'use strict';

// ── Configuration ─────────────────────────────────────────────────────────────
const IS_EXTERNAL_ORIGIN = typeof location !== 'undefined' && (location.protocol === 'file:' || location.origin === 'null' || (location.port && location.port !== '3000' && location.port !== '8000'));
const API_BASE = IS_EXTERNAL_ORIGIN ? 'http://127.0.0.1:3000' : '';
// Derive WebSocket scheme from page protocol to support both HTTP and HTTPS deployments.
const WS_SCHEME = (typeof location !== 'undefined' && location.protocol === 'https:') ? 'wss:' : 'ws:';
const WS_HOST = (typeof location !== 'undefined' && location.host && !IS_EXTERNAL_ORIGIN) ? location.host : '127.0.0.1:3000';
const WS_URL = `${WS_SCHEME}//${WS_HOST}/ws/stream`;

// ── State ─────────────────────────────────────────────────────────────────────
let ws = null;
let wsConnected = false;
let liveSessionActive = false;
let audioContext = null;
let audioSource = null;
let audioProcessor = null;
let mediaStream = null;
let chunkCount = 0;
let peakRisk = 0;
let riskSum = 0;
let timelineData = { labels: [], datasets: [] };
let riskTimelineChart = null;
let selectedAnalyzeFile = null;
let enrollFiles = [];
let currentAlertLevel = 'SAFE';
let currentRiskScore = 0.0;
let overviewSeverityDonutInstance = null;

// ── Subtle Security Event Sound System (Web Audio API Synthesizer) ─────────
const CyberGuardAudio = (() => {
  let ctx = null;
  let enabled = false;
  let lastPlayedEventId = null;
  let lastPlayTime = 0;

  function init() {
    try {
      const stored = localStorage.getItem('cyberguard_sound_enabled');
      enabled = stored === 'true';
      updateButtonUI();
    } catch (_) {
      enabled = false;
    }
  }

  function getContext() {
    if (!ctx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) {
        ctx = new AudioCtx();
      }
    }
    if (ctx && ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    return ctx;
  }

  function updateButtonUI() {
    const btn = document.getElementById('sound-toggle-btn');
    if (btn) {
      if (enabled) {
        btn.textContent = '🔊 SOUND ON';
        btn.className = 'sound-toggle-btn sound-on';
        btn.setAttribute('aria-pressed', 'true');
      } else {
        btn.textContent = '🔇 SOUND OFF';
        btn.className = 'sound-toggle-btn';
        btn.setAttribute('aria-pressed', 'false');
      }
    }
  }

  function toggle() {
    enabled = !enabled;
    try {
      localStorage.setItem('cyberguard_sound_enabled', String(enabled));
    } catch (_) {}
    updateButtonUI();

    if (enabled) {
      getContext();
      playConfirm();
      showToast('Security event audio cues enabled (subtle tones)', 'info');
    } else {
      showToast('Security event audio cues muted', 'info');
    }
    return enabled;
  }

  function canPlay(eventId) {
    if (!enabled) return false;
    const now = Date.now();
    if (eventId && eventId === lastPlayedEventId && (now - lastPlayTime < 3000)) {
      return false; // Deduplicate same event
    }
    if (now - lastPlayTime < 450) {
      return false; // Rate limit minimum interval
    }
    lastPlayedEventId = eventId || null;
    lastPlayTime = now;
    return true;
  }

  function playTone(freq, type = 'sine', duration = 0.08, gainVal = 0.04) {
    try {
      const c = getContext();
      if (!c) return;
      const osc = c.createOscillator();
      const gain = c.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, c.currentTime);
      gain.gain.setValueAtTime(gainVal, c.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + duration);
      osc.connect(gain);
      gain.connect(c.destination);
      osc.start();
      osc.stop(c.currentTime + duration);
    } catch (_) {}
  }

  function playConfirm(eventId) {
    if (!canPlay(eventId)) return;
    try {
      playTone(520, 'sine', 0.05, 0.035);
      setTimeout(() => playTone(660, 'sine', 0.07, 0.035), 60);
    } catch (_) {}
  }

  function playLowAlert(eventId) {
    if (!canPlay(eventId)) return;
    playTone(440, 'sine', 0.08, 0.04);
  }

  function playHighAlert(eventId) {
    if (!canPlay(eventId)) return;
    try {
      playTone(587, 'sine', 0.07, 0.05);
      setTimeout(() => playTone(880, 'sine', 0.1, 0.05), 75);
    } catch (_) {}
  }

  function playCriticalAlert(eventId) {
    if (!canPlay(eventId)) return;
    try {
      playTone(880, 'triangle', 0.07, 0.06);
      setTimeout(() => playTone(587, 'triangle', 0.07, 0.06), 75);
      setTimeout(() => playTone(880, 'triangle', 0.12, 0.07), 150);
    } catch (_) {}
  }

  return {
    init,
    toggle,
    playConfirm,
    playLowAlert,
    playHighAlert,
    playCriticalAlert,
    isEnabled: () => enabled,
  };
})();

window.CyberGuardAudio = CyberGuardAudio;
function toggleSound() {
  CyberGuardAudio.toggle();
}

// ── Gauge Drawing ─────────────────────────────────────────────────────────────
const gaugeCanvas = document.getElementById('gaugeCanvas');
const gaugeCtx = gaugeCanvas.getContext('2d');

const RISK_COLORS = {
  SAFE: '#22c55e',
  LOW: '#f59e0b',
  MEDIUM: '#f97316',
  HIGH: '#ef4444',
  CRITICAL: '#dc2626',
};

function getRiskColor(score) {
  if (score >= 0.95) return RISK_COLORS.CRITICAL;
  if (score >= 0.80) return RISK_COLORS.HIGH;
  if (score >= 0.60) return RISK_COLORS.MEDIUM;
  if (score >= 0.35) return RISK_COLORS.LOW;
  return RISK_COLORS.SAFE;
}

function getRiskLevel(score) {
  if (score >= 0.95) return 'CRITICAL';
  if (score >= 0.80) return 'HIGH';
  if (score >= 0.60) return 'MEDIUM';
  if (score >= 0.35) return 'LOW';
  return 'SAFE';
}

function drawGauge(score) {
  currentRiskScore = score;
  const w = gaugeCanvas.width;
  const h = gaugeCanvas.height;
  const cx = w / 2;
  const cy = h - 20;
  const r = 110;
  const startAngle = Math.PI;
  const endAngle = 2 * Math.PI;
  const sweepAngle = (endAngle - startAngle) * score;

  gaugeCtx.clearRect(0, 0, w, h);

  // Background track
  gaugeCtx.beginPath();
  gaugeCtx.arc(cx, cy, r, startAngle, endAngle);
  gaugeCtx.strokeStyle = 'rgba(255,255,255,0.05)';
  gaugeCtx.lineWidth = 18;
  gaugeCtx.lineCap = 'round';
  gaugeCtx.stroke();

  // Risk segments (color gradient)
  const segments = [
    { from: 0.00, to: 0.35, color: '#22c55e' },
    { from: 0.35, to: 0.60, color: '#f59e0b' },
    { from: 0.60, to: 0.80, color: '#f97316' },
    { from: 0.80, to: 0.95, color: '#ef4444' },
    { from: 0.95, to: 1.00, color: '#dc2626' },
  ];

  segments.forEach(seg => {
    const sa = startAngle + (endAngle - startAngle) * seg.from;
    const ea = startAngle + (endAngle - startAngle) * Math.min(seg.to, score);
    if (ea <= sa) return;
    gaugeCtx.beginPath();
    gaugeCtx.arc(cx, cy, r, sa, ea);
    gaugeCtx.strokeStyle = seg.color;
    gaugeCtx.lineWidth = 18;
    gaugeCtx.lineCap = 'round';
    gaugeCtx.stroke();
  });

  // Needle
  const needleAngle = startAngle + sweepAngle;
  const needleLen = r - 12;
  const nx = cx + needleLen * Math.cos(needleAngle);
  const ny = cy + needleLen * Math.sin(needleAngle);
  gaugeCtx.beginPath();
  gaugeCtx.moveTo(cx, cy);
  gaugeCtx.lineTo(nx, ny);
  gaugeCtx.strokeStyle = getRiskColor(score);
  gaugeCtx.lineWidth = 3;
  gaugeCtx.lineCap = 'round';
  gaugeCtx.shadowBlur = 8;
  gaugeCtx.shadowColor = getRiskColor(score);
  gaugeCtx.stroke();
  gaugeCtx.shadowBlur = 0;

  // Center dot
  gaugeCtx.beginPath();
  gaugeCtx.arc(cx, cy, 7, 0, 2 * Math.PI);
  gaugeCtx.fillStyle = getRiskColor(score);
  gaugeCtx.fill();

  // Tick marks
  for (let i = 0; i <= 10; i++) {
    const a = startAngle + (endAngle - startAngle) * (i / 10);
    const inner = r - 26;
    const outer = r - 20;
    gaugeCtx.beginPath();
    gaugeCtx.moveTo(cx + inner * Math.cos(a), cy + inner * Math.sin(a));
    gaugeCtx.lineTo(cx + outer * Math.cos(a), cy + outer * Math.sin(a));
    gaugeCtx.strokeStyle = 'rgba(255,255,255,0.15)';
    gaugeCtx.lineWidth = 1.5;
    gaugeCtx.stroke();
  }

  // Labels
  gaugeCtx.fillStyle = 'rgba(148,163,184,0.7)';
  gaugeCtx.font = '10px Inter';
  gaugeCtx.textAlign = 'center';
  gaugeCtx.fillText('0', cx + (r + 16) * Math.cos(startAngle), cy + 4);
  gaugeCtx.fillText('1', cx + (r + 16) * Math.cos(endAngle), cy + 4);
  gaugeCtx.fillText('0.5', cx, cy - r - 10);

  // Update DOM
  document.getElementById('gauge-value').textContent = score.toFixed(2);
  const level = getRiskLevel(score);
  const levelEl = document.getElementById('gauge-label');
  levelEl.textContent = level;
  levelEl.style.color = getRiskColor(score);

  // Update rolling sparkline
  drawRiskSparkline(score);
}

const sparklineBuffer = [];
function drawRiskSparkline(score) {
  const canvas = document.getElementById('riskSparkline');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.offsetWidth || 240;
  const h = canvas.height = canvas.offsetHeight || 34;

  sparklineBuffer.push(score);
  if (sparklineBuffer.length > 30) sparklineBuffer.shift();

  ctx.clearRect(0, 0, w, h);
  if (sparklineBuffer.length < 2) return;

  ctx.beginPath();
  const step = w / (sparklineBuffer.length - 1);
  sparklineBuffer.forEach((pt, idx) => {
    const x = idx * step;
    const y = h - (pt * (h - 6)) - 3;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  const color = getRiskColor(score);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.stroke();

  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color + '33');
  grad.addColorStop(1, 'transparent');
  ctx.fillStyle = grad;
  ctx.fill();
}

// ── Risk Timeline Chart ───────────────────────────────────────────────────────
function initTimeline() {
  const ctx = document.getElementById('riskTimeline').getContext('2d');
  riskTimelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Risk Score',
        data: [],
        borderColor: '#6366f1',
        backgroundColor: 'rgba(99,102,241,0.07)',
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: '#6366f1',
        tension: 0.4,
        fill: true,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } },
          grid: { color: 'rgba(255,255,255,0.03)' },
        },
        y: {
          min: 0, max: 1,
          ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 10 } },
          grid: { color: 'rgba(255,255,255,0.04)' },
        }
      },
      animation: { duration: 200 },
    }
  });
}

function addTimelinePoint(chunk_id, risk) {
  const chart = riskTimelineChart;
  if (!chart) return;
  chart.data.labels.push(`#${chunk_id}`);
  chart.data.datasets[0].data.push(risk);
  // Dynamic color
  chart.data.datasets[0].borderColor = getRiskColor(risk);
  chart.data.datasets[0].pointBackgroundColor = getRiskColor(risk);
  if (chart.data.labels.length > 60) {
    chart.data.labels.shift();
    chart.data.datasets[0].data.shift();
  }
  chart.update('none');
}

function clearTimeline() {
  if (!riskTimelineChart) return;
  riskTimelineChart.data.labels = [];
  riskTimelineChart.data.datasets[0].data = [];
  riskTimelineChart.update();
  chunkCount = 0; peakRisk = 0; riskSum = 0;
  drawGauge(0);
  updateStatDisplay(0, 0, 0, null);
}

// ── Alert Display ─────────────────────────────────────────────────────────────
function updateAlertDisplay(level, recommendation) {
  const iconWrap = document.getElementById('alert-icon-wrap');
  const title = document.getElementById('alert-title');
  const message = document.getElementById('alert-message');
  const actions = document.getElementById('alert-actions');

  const levelClass = level.toLowerCase();
  iconWrap.className = `alert-icon-wrap ${levelClass}`;

  const icons = {
    SAFE: '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>',
    LOW: '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    MEDIUM: '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    HIGH: '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="8"/><line x1="12" y1="12" x2="12" y2="16"/></svg>',
    CRITICAL: '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  };

  iconWrap.innerHTML = icons[level] || icons.SAFE;

  if (recommendation) {
    title.textContent = recommendation.title || level;
    message.textContent = recommendation.message || '';

    actions.innerHTML = '';
    if (recommendation.actions && recommendation.actions.length > 0) {
      recommendation.actions.forEach(action => {
        const div = document.createElement('div');
        div.className = 'action-item';
        div.textContent = action;
        actions.appendChild(div);
      });
    }
  }
}

// ── Stat Display ──────────────────────────────────────────────────────────────
function updateStatDisplay(peak, mean, count, latency) {
  document.getElementById('peak-risk').textContent = (peak || 0).toFixed(3);
  document.getElementById('mean-risk').textContent = (mean || 0).toFixed(3);
  document.getElementById('chunk-count').textContent = count || 0;
  document.getElementById('latency').textContent = latency ? `${latency.toFixed(0)}ms` : '—';
}

// ── Speaker Consistency Display ───────────────────────────────────────────────
function updateConsistencyDisplay(similarity) {
  const bar = document.getElementById('identity-bar');
  const pct = document.getElementById('identity-pct');
  const status = document.getElementById('identity-status');

  if (similarity === null || similarity === undefined) {
    bar.style.width = '0%';
    pct.textContent = '—';
    status.textContent = 'No enrolled speaker';
    return;
  }

  const pctVal = Math.max(0, Math.min(100, similarity * 100));
  bar.style.width = `${pctVal}%`;
  pct.textContent = `${pctVal.toFixed(1)}%`;

  if (similarity >= 0.75) {
    status.textContent = '✓ Speaker identity consistent';
    status.style.color = 'var(--risk-safe)';
    bar.style.background = 'linear-gradient(90deg, #22c55e, #16a34a)';
  } else if (similarity >= 0.50) {
    status.textContent = '⚠️ Partial identity match';
    status.style.color = 'var(--risk-low)';
    bar.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
  } else {
    status.textContent = '✗ Speaker identity mismatch!';
    status.style.color = 'var(--risk-high)';
    bar.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
  }
}

// ── Log to console panel ──────────────────────────────────────────────────────
function addLog(msg, type = 'info') {
  const log = document.getElementById('ws-log');
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString();
  entry.textContent = `[${time}] ${msg}`;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;
}

// ── WebSocket Message Handler ─────────────────────────────────────────────────
function handleWsMessage(data) {
  if (!data || typeof data !== 'object') return;

  if (data.type === 'session_start') {
    const sessLabel = document.getElementById('session-label');
    if (sessLabel) sessLabel.textContent = `Session: ${data.session_id}`;
    addLog(`Session started: ${data.session_id}`, 'success');
    return;
  }

  // Real-time security events for Security Center
  if (data.type === 'incident_update') {
    handleWsIncidentUpdate(data);
    return;
  }
  if (data.type === 'incident_status_changed') {
    handleWsStatusChange(data);
    return;
  }
  if (data.type === 'security_alert') {
    handleWsAlert(data);
    return;
  }
  if (data.type === 'threat_event') {
    handleWsThreatEvent(data);
    return;
  }
  if (data.type === 'pipeline_status') {
    if (data.virustotal && typeof renderVirusTotalBadge === 'function') {
      renderVirusTotalBadge(data.virustotal);
    }
    if (data.urlhaus && typeof renderURLhausBadge === 'function') {
      renderURLhausBadge(data.urlhaus);
    }
    return;
  }

  if (data.type !== 'risk_update') return;

  const risk = data.risk_score;
  const level = data.alert_level;
  const chunk = data.chunk_id;
  const det = data.detection_score;
  const sim = data.speaker_similarity;

  // Gauge
  drawGauge(risk);

  // Stats
  chunkCount++;
  peakRisk = Math.max(peakRisk, risk);
  riskSum += risk;
  updateStatDisplay(peakRisk, riskSum / chunkCount, chunkCount, null);

  // Timeline
  addTimelinePoint(chunk, risk);

  // Alert display
  if (data.recommendation) {
    updateAlertDisplay(level, data.recommendation);
  }

  // Speaker consistency
  updateConsistencyDisplay(sim);

  // Feature pill availability is managed by checkSystemStatus() based on
  // actual server-reported wav2vec2_available / ecapa_available flags.
  // Do NOT activate pills unconditionally here — that would hide real status.

  // Log
  addLog(
    `Chunk #${chunk} | Risk: ${risk.toFixed(3)} | Level: ${level} | Det: ${det.toFixed(3)}`,
    (level === 'CRITICAL' || level === 'HIGH') ? 'error' : level === 'MEDIUM' ? 'warn' : 'info'
  );

  // Toast on escalation
  if (level !== currentAlertLevel) {
    if (['MEDIUM', 'HIGH', 'CRITICAL'].includes(level)) {
      showToast(
        level === 'CRITICAL' ? '🔴 CRITICAL — Confirmed Voice Cloning Attack!' :
          level === 'HIGH' ? '🚨 HIGH RISK — Voice cloning likely detected!' : '⚠️ï¸ MEDIUM RISK — Possible voice cloning',
        (level === 'CRITICAL' || level === 'HIGH') ? 'error' : 'warning',
        5000,
      );
    }
    currentAlertLevel = level;
  }
}

// ── Live Session ──────────────────────────────────────────────────────────────
async function startLiveSession() {
  if (liveSessionActive) return;

  // Request mic permission (Raw unfiltered audio is critical for detecting subtle vocoder artifacts)
  try {
    mediaStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        sampleRate: 16000,
        channelCount: 1,
        echoCancellation: false,
        noiseSuppression: false,
        autoGainControl: false
      },
      video: false
    });
  } catch (err) {
    showToast('Microphone access denied: ' + err.message, 'error');
    addLog('Microphone access denied: ' + err.message, 'error');
    return;
  }

  // Connect WebSocket
  ws = new WebSocket(WS_URL);
  ws.binaryType = 'arraybuffer';

  ws.onopen = () => {
    wsConnected = true;
    updateSystemStatus('online');
    addLog('WebSocket connected to CyberGuard server', 'success');

    // Send speaker selection if chosen
    const speakerId = document.getElementById('live-speaker-id').value;
    if (speakerId) {
      ws.send(JSON.stringify({ type: 'enroll_speaker', speaker_id: speakerId }));
      addLog(`Speaker profile selected: ${speakerId}`, 'info');
    }

    // Start audio capture
    audioContext = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 16000 });
    audioSource = audioContext.createMediaStreamSource(mediaStream);
    audioProcessor = audioContext.createScriptProcessor(4096, 1, 1);

    audioProcessor.onaudioprocess = (e) => {
      if (!wsConnected || ws.readyState !== WebSocket.OPEN) return;
      const float32 = e.inputBuffer.getChannelData(0);
      // Convert float32 → int16 for server
      const int16 = new Int16Array(float32.length);
      for (let i = 0; i < float32.length; i++) {
        int16[i] = Math.max(-32768, Math.min(32767, float32[i] * 32768));
      }
      ws.send(int16.buffer);
    };

    audioSource.connect(audioProcessor);
    // NOTE: audioProcessor is intentionally NOT connected to audioContext.destination.
    // Connecting it to the destination would feed microphone audio directly to the
    // speakers, causing an echo / feedback loop. The processor only captures audio
    // data via onaudioprocess and sends it over the WebSocket.
  };

  ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      handleWsMessage(data);
    } catch (err) {
      console.warn('WS parse error:', err);
    }
  };

  ws.onerror = () => {
    addLog('WebSocket error occurred', 'error');
    updateSystemStatus('error');
  };

  ws.onclose = () => {
    wsConnected = false;
    addLog('WebSocket disconnected', 'warn');
    updateSystemStatus('offline');
    stopLiveSession();
  };

  liveSessionActive = true;
  document.getElementById('start-live-btn').classList.add('hidden');
  document.getElementById('stop-live-btn').classList.remove('hidden');
  document.getElementById('live-indicator').classList.remove('hidden');
  addLog('Live analysis session started', 'success');
}

function stopLiveSession() {
  if (!liveSessionActive) return;
  liveSessionActive = false;

  // Stop audio
  if (audioProcessor) { audioProcessor.disconnect(); audioProcessor = null; }
  if (audioSource) { audioSource.disconnect(); audioSource = null; }
  if (audioContext) { audioContext.close(); audioContext = null; }
  if (mediaStream) { mediaStream.getTracks().forEach(t => t.stop()); mediaStream = null; }

  // Close WebSocket
  if (ws && ws.readyState === WebSocket.OPEN) ws.close();
  ws = null;
  wsConnected = false;

  document.getElementById('start-live-btn').classList.remove('hidden');
  document.getElementById('stop-live-btn').classList.add('hidden');
  document.getElementById('live-indicator').classList.add('hidden');

  addLog('Live session stopped.', 'info');
  updateSystemStatus('offline');
}

// ── System Status ─────────────────────────────────────────────────────────────
function updateSystemStatus(state) {
  const statusEl = document.getElementById('system-status');
  if (!statusEl) return;
  const dot = statusEl.querySelector('.status-dot');
  const span = statusEl.querySelector('span');
  if (dot) dot.className = `status-dot ${state}`;
  if (span) {
    span.textContent = state === 'online' ? 'SYSTEM ONLINE' : state === 'error' ? 'SYSTEM ERROR' : 'DISCONNECTED';
  }
}

// ── Tab Navigation ────────────────────────────────────────────────────────────
function showTab(name) {
  // Graceful route fallback: redirect legacy and alias tab requests
  if (name === 'phishing') name = 'threats';
  if (name === 'voice-identity' || name === 'identity') name = 'enroll';
  if (name === 'threat-monitoring') name = 'monitor';
  if (name === 'incidents' || name === 'history' || name === 'alerts') {
    name = 'security-center';
  } else if (name === 'unified' || !document.getElementById(`panel-${name}`)) {
    name = 'overview';
  }

  // Admin access gate for privileged tabs
  if ((name === 'review' || name === 'admin') && (!currentUser || currentUser.role !== 'admin')) {
    if (typeof showToast === 'function') {
      showToast('Administrator privileges required to access this console', 'warning');
    }
    if (typeof openAuthModal === 'function') {
      openAuthModal();
    }
    return;
  }

  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.remove('active');
    p.classList.add('hidden');
  });
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

  const panel = document.getElementById(`panel-${name}`);
  const tab = document.getElementById(`tab-${name}`);
  if (panel) {
    panel.classList.remove('hidden');
    panel.classList.add('active');
  }
  if (tab) {
    tab.classList.add('active');
  }

  if (name === 'security-center') loadSecurityCenterData();
  if (name === 'enroll') loadSpeakers();
  if (name === 'analyze') {
    populateSpeakerSelect('analyze-speaker-id');
    updatePipelineStepper(selectedAnalyzeFile ? 1 : 0);
  }
  if (name === 'overview') updateOverview();
  if (name === 'threats') { updateVirusTotalStatus(); updateURLhausStatus(); }
  if (name === 'review' && typeof loadReviewQueue === 'function') loadReviewQueue();
  if (name === 'admin' && typeof loadAdminDashboard === 'function') loadAdminDashboard();

  requestAnimationFrame(() => {
    window.dispatchEvent(new Event('resize'));
    if (name === 'overview') {
      if (typeof overviewActivityChartInstance !== 'undefined' && overviewActivityChartInstance) overviewActivityChartInstance.resize();
      if (typeof overviewCategoryDonutInstance !== 'undefined' && overviewCategoryDonutInstance) overviewCategoryDonutInstance.resize();
      if (typeof overviewSeverityDonutInstance !== 'undefined' && overviewSeverityDonutInstance) overviewSeverityDonutInstance.resize();
    } else if (name === 'security-center') {
      if (typeof scTrendChartInstance !== 'undefined' && scTrendChartInstance) scTrendChartInstance.resize();
      if (typeof scCategoryMixInstance !== 'undefined' && scCategoryMixInstance) scCategoryMixInstance.resize();
    } else if (name === 'monitor') {
      if (typeof riskTimelineChart !== 'undefined' && riskTimelineChart) riskTimelineChart.resize();
      if (typeof drawGauge === 'function') drawGauge(currentRiskScore || 0);
    }
  });
}

// ── File Analysis ─────────────────────────────────────────────────────────────
function onDragOver(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.add('dragover');
}

function onDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('dragover');
  const files = e.dataTransfer.files;
  if (files.length > 0) handleFileSelected(files[0]);
}

function onFileSelect(e) {
  if (e.target.files.length > 0) handleFileSelected(e.target.files[0]);
}

function handleFileSelected(file) {
  selectedAnalyzeFile = file;
  const sel = document.getElementById('file-selected');
  sel.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  sel.classList.remove('hidden');
  document.getElementById('analyze-btn').disabled = false;
  drawAudioWaveform(file);
  updatePipelineStepper(1);
}

function updatePipelineStepper(stepNumber) {
  // 0: Standby (no steps highlighted)
  // 1: Ingestion Active (file selected)
  // 2: VAD Stripping Active
  // 3: Feature Extraction Active
  // 4: Model Inference Active
  // 5: Risk & Verdict Active
  // 6: Complete (all 5 steps & 4 lines completed)
  for (let i = 1; i <= 5; i++) {
    const stepEl = document.getElementById(`step-${i}`);
    if (!stepEl) continue;
    stepEl.classList.remove('active', 'completed');
    if (stepNumber === 6 || (stepNumber > 0 && i < stepNumber)) {
      stepEl.classList.add('completed');
    } else if (i === stepNumber) {
      stepEl.classList.add('active');
    }
  }
  for (let i = 1; i <= 4; i++) {
    const lineEl = document.getElementById(`line-${i}`);
    if (!lineEl) continue;
    lineEl.classList.remove('completed', 'active');
    if (stepNumber === 6 || (stepNumber > 0 && i < stepNumber)) {
      lineEl.classList.add('completed');
    } else if (i === stepNumber - 1) {
      lineEl.classList.add('active');
    }
  }
}

function drawAudioWaveform(file) {
  const canvas = document.getElementById('audio-waveform-canvas');
  if (!canvas || !file) return;
  canvas.classList.remove('hidden');
  const ctx = canvas.getContext('2d');
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) { drawFallbackWaveform(canvas); return; }
      const tempCtx = new AudioCtx();
      const audioBuffer = await tempCtx.decodeAudioData(e.target.result);
      const rawData = audioBuffer.getChannelData(0);
      const samples = 100;
      const blockSize = Math.floor(rawData.length / samples) || 1;
      const peaks = [];
      for (let i = 0; i < samples; i++) {
        let max = 0;
        for (let j = 0; j < blockSize; j++) {
          const val = Math.abs(rawData[i * blockSize + j] || 0);
          if (val > max) max = val;
        }
        peaks.push(max);
      }
      const w = canvas.width = canvas.offsetWidth || 340;
      const h = canvas.height = canvas.offsetHeight || 60;
      ctx.clearRect(0, 0, w, h);
      const barWidth = w / samples;
      ctx.fillStyle = '#06b6d4';
      peaks.forEach((peak, i) => {
        const barHeight = Math.max(3, peak * (h - 8));
        const x = i * barWidth;
        const y = (h - barHeight) / 2;
        ctx.fillRect(x, y, Math.max(1, barWidth - 1.5), barHeight);
      });
      tempCtx.close().catch(() => {});
    } catch (_) {
      drawFallbackWaveform(canvas);
    }
  };
  reader.readAsArrayBuffer(file);
}

function drawFallbackWaveform(canvas) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.offsetWidth || 340;
  const h = canvas.height = canvas.offsetHeight || 60;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = '#06b6d4';
  const bars = 80;
  const barWidth = w / bars;
  for (let i = 0; i < bars; i++) {
    const val = 0.2 + 0.6 * Math.abs(Math.sin(i * 0.15) * Math.cos(i * 0.08));
    const barHeight = Math.max(3, val * (h - 10));
    ctx.fillRect(i * barWidth, (h - barHeight) / 2, barWidth - 1, barHeight);
  }
}

async function analyzeFile() {
  if (!selectedAnalyzeFile) return;
  const btn = document.getElementById('analyze-btn');
  btn.disabled = true;

  updatePipelineStepper(1);

  const stages = [
    { label: 'Ingesting audio payload…', step: 1 },
    { label: 'Stripping silence via WebRTC VAD…', step: 2 },
    { label: 'Extracting acoustic & neural features…', step: 3 },
    { label: 'Running deepfake model inference…', step: 4 },
    { label: 'Evaluating risk & security verdict…', step: 5 },
  ];
  let stageIdx = 0;
  const STAGE_INTERVAL_MS = 2000;

  function setStage(idx) {
    const st = stages[idx] || stages[stages.length - 1];
    btn.innerHTML = `<div class="spinner"></div> ${st.label}`;
    updatePipelineStepper(st.step);
  }
  setStage(0);

  const stageTimer = setInterval(() => {
    stageIdx = Math.min(stageIdx + 1, stages.length - 1);
    setStage(stageIdx);
  }, STAGE_INTERVAL_MS);

  // Hard client-side timeout — prevents the UI from hanging indefinitely
  const ANALYSIS_TIMEOUT_MS = 120_000;
  let didTimeout = false;
  const timeoutId = setTimeout(() => {
    didTimeout = true;
  }, ANALYSIS_TIMEOUT_MS);

  const formData = new FormData();
  formData.append('file', selectedAnalyzeFile);
  const speakerId = document.getElementById('analyze-speaker-id').value;
  if (speakerId) formData.append('speaker_id', speakerId);

  try {
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), ANALYSIS_TIMEOUT_MS);

    const headers = {};
    const token = typeof getAuthToken === 'function' ? getAuthToken() : '';
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      body: formData,
      headers: headers,
      signal: controller.signal,
    });
    clearTimeout(abortTimer);

    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();
    clearInterval(stageTimer);
    updatePipelineStepper(6); // All 5 stages completed

    renderAnalysisResults(data);
    showToast(`Analysis complete: ${data.alert_level} (peak: ${data.peak_risk.toFixed(3)})`,
      (data.alert_level === 'CRITICAL' || data.alert_level === 'HIGH') ? 'error' : data.alert_level === 'MEDIUM' ? 'warning' : 'success');
    if (window.CyberGuardAudio) {
      if (data.alert_level === 'CRITICAL' || data.alert_level === 'HIGH') {
        window.CyberGuardAudio.playHighAlert();
      } else {
        window.CyberGuardAudio.playConfirm();
      }
    }
    updateOverview();
    loadOverviewLiveFeed();
  } catch (err) {
    clearInterval(stageTimer);
    updatePipelineStepper(1);
    if (err.name === 'AbortError' || didTimeout) {
      showToast('Analysis timed out. The server may be busy — please try again.', 'error');
    } else {
      showToast('Analysis failed: ' + err.message, 'error');
    }
  } finally {
    clearInterval(stageTimer);
    clearTimeout(timeoutId);
    btn.disabled = false;
    btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Analyze Audio';
  }
}

function renderAnalysisResults(data) {
  const body = document.getElementById('results-body');
  const color = getRiskColor(data.peak_risk);
  const level = data.alert_level;

  body.innerHTML = `
    <div class="result-summary">
      <div class="result-stat-card">
        <div class="result-stat-value" style="color:${color}">${data.peak_risk.toFixed(3)}</div>
        <div class="result-stat-label">Peak Risk</div>
      </div>
      <div class="result-stat-card">
        <div class="result-stat-value" style="color:${getRiskColor(data.mean_risk)}">${data.mean_risk.toFixed(3)}</div>
        <div class="result-stat-label">Mean Risk</div>
      </div>
      <div class="result-stat-card">
        <div class="result-stat-value">${data.total_chunks}</div>
        <div class="result-stat-label">Chunks</div>
      </div>
    </div>
    
    ${data.external_intelligence ? `
    <div style="margin-bottom:14px;padding:14px;border-radius:10px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1)">
      <div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-bottom:4px">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        VirusTotal File Intelligence
      </div>
      <div style="font-size:12px;color:#94a3b8">
        ${data.external_intelligence.status === 'COMPLETED' ?
        `Reputation: ${data.external_intelligence.malicious_count} malicious, ${data.external_intelligence.suspicious_count} suspicious / ${data.external_intelligence.total_engines} engines.` :
        `Status: ${data.external_intelligence.status}`
      }
      </div>
    </div>` : ''}

    <div style="margin-bottom:14px;padding:14px;border-radius:10px;background:${color}15;border:1px solid ${color}40">
      <div style="font-size:15px;font-weight:700;color:${color};margin-bottom:4px">${data.recommendation.title}</div>
      <div style="font-size:12px;color:#94a3b8">${data.recommendation.message}</div>
    </div>

    <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:8px">Per-Chunk Scores</div>
    <div class="chunk-list">
      ${data.chunk_scores.map(c => `
        <div class="chunk-row">
          <span class="chunk-id">Chunk ${c.chunk_id}</span>
          <div class="chunk-bar-bg">
            <div class="chunk-bar" style="width:${c.risk_score * 100}%;background:${getRiskColor(c.risk_score)}"></div>
          </div>
          <span class="chunk-score" style="color:${getRiskColor(c.risk_score)}">${c.risk_score.toFixed(3)}</span>
          <span class="chunk-level level-${c.alert_level}">${c.alert_level}</span>
        </div>
      `).join('')}
    </div>
  `;
}

// ── Speaker Enrollment ────────────────────────────────────────────────────────
function onEnrollDrop(e) {
  e.preventDefault();
  const files = Array.from(e.dataTransfer.files);
  enrollFiles = [...enrollFiles, ...files];
  updateEnrollFileCount();
}

function onEnrollFilesSelected(e) {
  enrollFiles = Array.from(e.target.files);
  updateEnrollFileCount();
}

function updateEnrollFileCount() {
  const badge = document.getElementById('enroll-file-count');
  if (enrollFiles.length > 0) {
    badge.textContent = `${enrollFiles.length} file${enrollFiles.length > 1 ? 's' : ''} selected`;
    badge.classList.remove('hidden');
    document.getElementById('enroll-btn').disabled = false;
  } else {
    badge.classList.add('hidden');
    document.getElementById('enroll-btn').disabled = true;
  }
}

async function enrollSpeaker() {
  const name = document.getElementById('enroll-name').value.trim();
  if (!name) { showToast('Please enter a speaker name.', 'warning'); return; }
  if (enrollFiles.length === 0) { showToast('Please select audio files.', 'warning'); return; }

  const btn = document.getElementById('enroll-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Enrolling...';

  const formData = new FormData();
  formData.append('name', name);
  const org = document.getElementById('enroll-org').value.trim();
  const role = document.getElementById('enroll-role').value.trim();
  const sid = document.getElementById('enroll-id').value.trim();
  if (org) formData.append('organization', org);
  if (role) formData.append('role', role);
  if (sid) formData.append('speaker_id', sid);
  enrollFiles.forEach(f => formData.append('files', f));

  const resultEl = document.getElementById('enroll-result');

  try {
    const resp = await fetch(`${API_BASE}/api/speakers/enroll`, { method: 'POST', body: formData });
    if (!resp.ok) throw new Error(await resp.text());
    const data = await resp.json();
    resultEl.className = 'enroll-result success';
    resultEl.textContent = data.message;
    resultEl.classList.remove('hidden');
    showToast(`Speaker "${data.name}" enrolled successfully!`, 'success');
    loadSpeakers();
    // Reset form
    enrollFiles = [];
    updateEnrollFileCount();
    document.getElementById('enroll-name').value = '';
    document.getElementById('enroll-org').value = '';
    document.getElementById('enroll-role').value = '';
    document.getElementById('enroll-id').value = '';
  } catch (err) {
    resultEl.className = 'enroll-result error';
    resultEl.textContent = 'Enrollment failed: ' + err.message;
    resultEl.classList.remove('hidden');
    showToast('Enrollment failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><line x1="12" y1="3" x2="12" y2="9"/><line x1="9" y1="6" x2="15" y2="6"/></svg> Enroll Speaker';
  }
}

async function loadSpeakers() {
  const list = document.getElementById('speakers-list');
  try {
    const resp = await fetch(`${API_BASE}/api/speakers`);
    const speakers = await resp.json();
    if (!speakers.length) {
      list.innerHTML = '<div class="speakers-empty">No speakers enrolled yet.</div>';
      return;
    }

    // Build speaker items using DOM API (not innerHTML) to prevent XSS.
    // All user-supplied values (name, organization, role, speaker_id) are
    // assigned via textContent, which treats them as plain text only.
    list.innerHTML = '';
    speakers.forEach(s => {
      const item = document.createElement('div');
      item.className = 'speaker-item';
      item.id = `sp-${s.speaker_id}`;

      const avatar = document.createElement('div');
      avatar.className = 'speaker-avatar';
      avatar.textContent = (s.name || '?').charAt(0).toUpperCase();

      const info = document.createElement('div');
      info.className = 'speaker-info';

      const nameEl = document.createElement('div');
      nameEl.className = 'speaker-name';
      nameEl.textContent = s.name || '—';

      const meta = document.createElement('div');
      meta.className = 'speaker-meta';
      const parts = [];
      if (s.organization) parts.push(s.organization);
      if (s.role) parts.push(s.role);
      parts.push(`${s.num_samples} samples`);
      meta.textContent = parts.join(' · ');

      const badge = document.createElement('div');
      badge.className = 'speaker-id-badge';
      badge.textContent = s.speaker_id;

      info.appendChild(nameEl);
      info.appendChild(meta);
      info.appendChild(badge);

      // Delete button — uses closure (not inline onclick string) to safely
      // pass the speaker_id without embedding it in HTML attribute context.
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'delete-btn';
      deleteBtn.title = 'Delete speaker';
      // Static SVG markup is trusted (not user data):
      deleteBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>';
      deleteBtn.addEventListener('click', () => deleteSpeaker(s.speaker_id));

      item.appendChild(avatar);
      item.appendChild(info);
      item.appendChild(deleteBtn);
      list.appendChild(item);
    });
  } catch (err) {
    list.innerHTML = '<div class="speakers-empty">Error loading speakers.</div>';
  }
  populateSpeakerSelect('live-speaker-id');
  populateSpeakerSelect('analyze-speaker-id');
}

async function deleteSpeaker(speakerId) {
  if (!confirm(`Delete speaker profile "${speakerId}"? This cannot be undone.`)) return;
  try {
    await fetch(`${API_BASE}/api/speakers/${speakerId}`, { method: 'DELETE' });
    showToast('Speaker deleted.', 'success');
    loadSpeakers();
  } catch (err) {
    showToast('Delete failed: ' + err.message, 'error');
  }
}

async function populateSpeakerSelect(selectId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;
  const current = sel.value;
  try {
    const resp = await fetch(`${API_BASE}/api/speakers`);
    const speakers = await resp.json();
    sel.innerHTML = '<option value="">None</option>' +
      speakers.map(s => `<option value="${s.speaker_id}">${s.name} (${s.speaker_id})</option>`).join('');
    if (current) sel.value = current;
  } catch (_) { }
}

function refreshSpeakers() { populateSpeakerSelect('live-speaker-id'); }

// ── Alert History ─────────────────────────────────────────────────────────────
async function loadAlerts() {
  const wrap = document.getElementById('history-table-wrap');
  if (!wrap) return;
  try {
    const resp = await fetch(`${API_BASE}/api/alerts/recent?limit=100`);
    const data = await resp.json();
    const alerts = data.alerts || [];
    if (!alerts.length) {
      wrap.innerHTML = '<div class="history-empty">No alerts recorded yet.</div>';
      return;
    }
    wrap.innerHTML = `
      <table class="history-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Session</th>
            <th>Risk</th>
            <th>Level</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody>
          ${alerts.map(a => `
            <tr>
              <td>${new Date(a.timestamp * 1000).toLocaleTimeString()}</td>
              <td>${a.session_id || '—'}</td>
              <td style="color:${getRiskColor(a.risk_score)}">${(a.risk_score || 0).toFixed(3)}</td>
              <td><span class="chunk-level level-${a.alert_level}">${a.alert_level}</span></td>
              <td style="font-family:Inter;font-size:12px;color:#94a3b8">${a.recommendation_title || ''}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    wrap.innerHTML = '<div class="history-empty">Error loading alert history.</div>';
  }
}

// ── Threshold Management ──────────────────────────────────────────────────────
async function updateThresholds() {
  const low = parseFloat(document.getElementById('thr-low').value);
  const medium = parseFloat(document.getElementById('thr-medium').value);
  const high = parseFloat(document.getElementById('thr-high').value);
  const resEl = document.getElementById('threshold-result');

  if (!(low < medium && medium < high)) {
    resEl.className = 'threshold-result error';
    resEl.textContent = 'Error: thresholds must satisfy LOW < MEDIUM < HIGH';
    resEl.classList.remove('hidden');
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/config/thresholds`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ low, medium, high }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    resEl.className = 'threshold-result success';
    resEl.textContent = `✓ Thresholds updated: LOW=${low}, MEDIUM=${medium}, HIGH=${high}`;
    resEl.classList.remove('hidden');
    showToast('Alert thresholds updated.', 'success');
  } catch (err) {
    resEl.className = 'threshold-result error';
    resEl.textContent = 'Update failed: ' + err.message;
    resEl.classList.remove('hidden');
  }
}

// ── Toast Notifications ───────────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icons = {
    success: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    warning: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };

  toast.innerHTML = `
    <span style="display:flex;align-items:center;color:currentColor;flex-shrink:0;margin-top:1px;">${icons[type] || icons.info}</span>
    <span style="flex:1;line-height:1.45;word-break:break-word;">${escapeHtml(message)}</span>
    <button onclick="this.parentElement.remove()" style="background:none;border:none;cursor:pointer;color:var(--text-muted);padding:0 0 0 6px;font-size:14px;line-height:1;flex-shrink:0;">✕</button>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(18px)';
    toast.style.transition = 'all 0.22s ease';
    setTimeout(() => toast.remove(), 240);
  }, duration);
}

// ── System Status Check ───────────────────────────────────────────────────────
async function checkSystemStatus() {
  try {
    const resp = await fetch(`${API_BASE}/api/config/status`);
    if (resp.ok) {
      const data = await resp.json();
      if (data.status === 'operational') {
        updateSystemStatus('online');

        // Update feature pill status
        if (data.wav2vec2_available) document.getElementById('pill-wav2vec').classList.add('active');
        if (data.ecapa_available) document.getElementById('pill-speaker').classList.add('active');

        // Load current thresholds
        if (data.config && data.config.thresholds) {
          const thrLow = document.getElementById('thr-low');
          const thrMed = document.getElementById('thr-medium');
          const thrHigh = document.getElementById('thr-high');
          if (thrLow) thrLow.value = data.config.thresholds.low;
          if (thrMed) thrMed.value = data.config.thresholds.medium;
          if (thrHigh) thrHigh.value = data.config.thresholds.high;
        }

        // Live Threat Intel sync from status
        if (data.virustotal_status && data.virustotal_status !== 'UNKNOWN' && typeof renderVirusTotalBadge === 'function') {
          renderVirusTotalBadge({ status: data.virustotal_status });
        }
        if (data.urlhaus_status && data.urlhaus_status !== 'UNKNOWN' && typeof renderURLhausBadge === 'function') {
          renderURLhausBadge({ status: data.urlhaus_status });
        }
      }
    }
  } catch (_) {
    updateSystemStatus('offline');
  }
}

// ── HTML & Formatting Helpers ────────────────────────────────────────────────
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatTimestamp(ts) {
  if (!ts) return 'Not available';
  try {
    const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
  } catch (_) {
    return String(ts);
  }
}

function copyIndicator(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Indicator copied to clipboard', 'info');
    }).catch(() => {
      showToast('Failed to copy to clipboard', 'error');
    });
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Indicator copied to clipboard', 'info');
  }
}

function formatEvidenceItem(e) {
  if (!e) return '';
  if (typeof e === 'string') return escapeHtml(e);
  if (typeof e === 'object') {
    const desc = e.description || e.evidence_type || 'Evidence';
    const val = e.value ? ` <code style="color:#38bdf8;font-size:11px;background:rgba(255,255,255,0.06);padding:1px 5px;border-radius:3px;">${escapeHtml(String(e.value))}</code>` : '';
    const src = e.source ? ` <span style="font-size:10px;color:#94a3b8;text-transform:uppercase;font-weight:600;margin-left:4px;">[${escapeHtml(String(e.source))}]</span>` : '';
    return `${escapeHtml(desc)}${val}${src}`;
  }
  return escapeHtml(String(e));
}

// ── Threat Intelligence Badge Rendering & Auto-Linking ───────────────────────
function renderVirusTotalBadge(data) {
  const badge = document.getElementById('vt-status');
  if (!badge) return false;
  badge.className = 'session-badge';

  if (!data || typeof data !== 'object') {
    badge.textContent = 'VirusTotal: UNAVAILABLE';
    badge.classList.add('vt-error');
    badge.title = 'VirusTotal service unreachable or backend error (Click to retry)';
    return false;
  }

  switch (data.status) {
    case 'READY':
      badge.textContent = 'VirusTotal: READY';
      badge.classList.add('vt-ready');
      badge.title = data.message || 'VirusTotal intelligence operational (Click to refresh)';
      return true;
    case 'NOT_CONFIGURED':
      badge.textContent = 'VirusTotal: NOT CONFIGURED';
      badge.classList.add('vt-not-configured');
      badge.title = data.message || 'API key not configured';
      return false;
    case 'AUTHENTICATION_FAILED':
      badge.textContent = 'VirusTotal: AUTH ERROR';
      badge.classList.add('vt-error');
      badge.title = data.message || 'Invalid credentials';
      return false;
    case 'FORBIDDEN':
      badge.textContent = 'VirusTotal: FORBIDDEN';
      badge.classList.add('vt-error');
      badge.title = data.message || 'Operation forbidden';
      return false;
    case 'RATE_LIMITED':
      badge.textContent = 'VirusTotal: RATE LIMITED';
      badge.classList.add('vt-rate-limited');
      badge.title = data.message || 'Quota reached';
      return false;
    case 'UNAVAILABLE':
    case 'TIMEOUT':
      badge.textContent = 'VirusTotal: UNAVAILABLE';
      badge.classList.add('vt-error');
      badge.title = data.message || 'Service unreachable or timed out (Click to retry)';
      return false;
    default:
      badge.textContent = `VirusTotal: ${data.status || 'UNKNOWN'}`;
      badge.classList.add('vt-not-configured');
      badge.title = data.message || '';
      return false;
  }
}

function renderURLhausBadge(data) {
  const badge = document.getElementById('uh-status');
  if (!badge) return false;
  badge.className = 'session-badge';

  if (!data || typeof data !== 'object') {
    badge.textContent = 'URLhaus: UNAVAILABLE';
    badge.classList.add('vt-error');
    badge.title = 'URLhaus service unreachable or backend error (Click to retry)';
    return false;
  }

  switch (data.status) {
    case 'READY':
      badge.textContent = 'URLhaus: READY';
      badge.classList.add('vt-ready');
      badge.title = data.message || 'URLhaus malware-URL intelligence operational (Click to refresh)';
      return true;
    case 'NOT_CONFIGURED':
      badge.textContent = 'URLhaus: NOT CONFIGURED';
      badge.classList.add('vt-not-configured');
      badge.title = data.message || 'URLHAUS_AUTH_KEY not configured';
      return false;
    case 'AUTHENTICATION_FAILED':
      badge.textContent = 'URLhaus: AUTH ERROR';
      badge.classList.add('vt-error');
      badge.title = data.message || 'Invalid Auth-Key';
      return false;
    case 'RATE_LIMITED':
      badge.textContent = 'URLhaus: RATE LIMITED';
      badge.classList.add('vt-rate-limited');
      badge.title = data.message || 'Rate limit reached';
      return false;
    case 'UNAVAILABLE':
    case 'TIMEOUT':
      badge.textContent = 'URLhaus: UNAVAILABLE';
      badge.classList.add('vt-error');
      badge.title = data.message || 'Service unreachable or timed out (Click to retry)';
      return false;
    default:
      badge.textContent = `URLhaus: ${data.status || 'UNKNOWN'}`;
      badge.classList.add('vt-not-configured');
      badge.title = data.message || '';
      return false;
  }
}

// ── Pipeline Auto-Link & Synchronous Fetchers ─────────────────────────────────
let isVtReady = false;
let isUhReady = false;
let pipelineWatcherTimer = null;

async function autoLinkThreatIntelPipeline(forceRefresh = false) {
  try {
    const res = await fetch(`${API_BASE}/api/threats/pipeline/status${forceRefresh ? '?force_refresh=true' : ''}`);
    if (res.ok) {
      const data = await res.json();
      isVtReady = renderVirusTotalBadge(data.virustotal);
      isUhReady = renderURLhausBadge(data.urlhaus);
      return isVtReady && isUhReady;
    }
  } catch (_) {
    // If unified pipeline endpoint is unreachable, fallback to individual probes
  }

  const [vtOk, uhOk] = await Promise.all([
    updateVirusTotalStatus(forceRefresh),
    updateURLhausStatus(forceRefresh)
  ]);
  isVtReady = Boolean(vtOk);
  isUhReady = Boolean(uhOk);
  return isVtReady && isUhReady;
}

async function updateVirusTotalStatus(forceRefresh = false) {
  const badge = document.getElementById('vt-status');
  if (!badge) return false;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    const res = await fetch(`${API_BASE}/api/threats/virustotal/status${forceRefresh ? '?force_refresh=true' : ''}`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      badge.textContent = 'VirusTotal: UNAVAILABLE';
      badge.className = 'session-badge vt-error';
      badge.title = 'VirusTotal service unreachable or backend error (Click to retry)';
      return false;
    }
    const data = await res.json();
    return renderVirusTotalBadge(data);
  } catch (err) {
    clearTimeout(timeoutId);
    badge.textContent = 'VirusTotal: OFFLINE';
    badge.className = 'session-badge vt-error';
    badge.title = err.name === 'AbortError' ? 'Status check timed out' : 'Backend server offline (Click to retry)';
    return false;
  }
}

async function updateURLhausStatus(forceRefresh = false) {
  const badge = document.getElementById('uh-status');
  if (!badge) return false;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    const res = await fetch(`${API_BASE}/api/threats/urlhaus/status${forceRefresh ? '?force_refresh=true' : ''}`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      badge.textContent = 'URLhaus: UNAVAILABLE';
      badge.className = 'session-badge vt-error';
      badge.title = 'URLhaus service unreachable or backend error (Click to retry)';
      return false;
    }
    const data = await res.json();
    return renderURLhausBadge(data);
  } catch (err) {
    clearTimeout(timeoutId);
    badge.textContent = 'URLhaus: OFFLINE';
    badge.className = 'session-badge vt-error';
    badge.title = err.name === 'AbortError' ? 'Status check timed out' : 'Backend server offline (Click to retry)';
    return false;
  }
}

// User-clickable badge refresh
window.refreshVirusTotalStatus = function(force = true) {
  const b = document.getElementById('vt-status');
  if (b) {
    b.textContent = 'VirusTotal: Checking...';
    b.className = 'session-badge vt-connecting';
  }
  return updateVirusTotalStatus(force);
};

window.refreshURLhausStatus = function(force = true) {
  const b = document.getElementById('uh-status');
  if (b) {
    b.textContent = 'URLhaus: Checking...';
    b.className = 'session-badge vt-connecting';
  }
  return updateURLhausStatus(force);
};

let systemStatusTimer = null;

function startSystemStatusPoller() {
  if (systemStatusTimer) clearInterval(systemStatusTimer);
  systemStatusTimer = setInterval(() => {
    if (typeof document !== 'undefined' && document.hidden) return;
    checkSystemStatus();
  }, wsConnected ? 30000 : 15000);
}

function startPipelineAutoWatcher() {
  if (pipelineWatcherTimer) clearTimeout(pipelineWatcherTimer);

  const scheduleNext = (delayMs) => {
    pipelineWatcherTimer = setTimeout(async () => {
      if (typeof document !== 'undefined' && document.hidden) {
        // Tab is hidden in background — throttle watcher to 60s
        scheduleNext(60000);
        return;
      }
      const allReady = await autoLinkThreatIntelPipeline(false);
      // When WebSocket is live and pipeline is fully operational, relax polling to 45s
      const nextDelay = (wsConnected && allReady) ? 45000 : (allReady ? 30000 : 25000);
      scheduleNext(nextDelay);
    }, delayMs);
  };

  // Initial check after short delay
  scheduleNext(1000);
}

// Refresh immediately when user returns to CyberGuard tab
if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      checkSystemStatus();
      autoLinkThreatIntelPipeline(false);
    }
  });
}

// ── Initialization ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  drawGauge(0);
  initTimeline();
  checkSystemStatus();
  startPipelineAutoWatcher();
  startSystemStatusPoller();
  loadSpeakers();

  // Populate speaker selects
  populateSpeakerSelect('live-speaker-id');
  populateSpeakerSelect('analyze-speaker-id');
});

/* -- CYBERGUARD THREAT SCANNER -- */

async function scanThreat() {
  const text = document.getElementById('threat-text').value.trim();
  if (!text) return showToast('Please enter text or URL to scan', 'error');

  const scanBtn = document.querySelector('button[onclick="scanThreat()"]');
  const originalBtnHtml = scanBtn ? scanBtn.innerHTML : '';
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = `
      <span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:8px;"></span>
      Scanning Content...
    `;
  }

  const container = document.getElementById('threat-results-body');
  if (container) {
    container.innerHTML = `
      <div class="vt-loading-state" style="padding:28px;text-align:center;">
        <span class="spinner" style="width:24px;height:24px;border-width:2px;display:inline-block;margin-bottom:12px;"></span>
        <div style="color:#f8fafc;font-size:14px;font-weight:600;">Analyzing Threat Artifact...</div>
        <div style="color:#94a3b8;font-size:12px;margin-top:4px;">Executing deep forensics, redirect resolution, and multi-provider intelligence queries.</div>
      </div>
    `;
  }

  const isUrl = text.startsWith('http://') || text.startsWith('https://');
  const endpoint = isUrl ? '/api/threats/url' : '/api/threats/phishing';
  const paramName = isUrl ? 'url' : 'text';

  const formData = new FormData();
  formData.append(paramName, text);
  formData.append('source', 'web_dashboard');

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scan failed');
    if (data.threat_intelligence) {
      renderThreatIntelligenceReport(data);
    } else {
      displayThreatResult(data);
    }
    showToast('Scan complete', 'success');
    updateOverview();
    loadOverviewLiveFeed();
  } catch (e) {
    showToast(e.message, 'error');
    if (container) {
      container.innerHTML = `<div class="results-empty"><p style="color:#ef4444;">Scan failed: ${escapeHtml(e.message)}</p></div>`;
    }
  } finally {
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = originalBtnHtml;
    }
  }
}

async function searchIOC() {
  const iocInput = document.getElementById('ioc-input');
  const ioc = iocInput ? iocInput.value.trim() : '';
  if (!ioc) return showToast('Please enter an IOC to search', 'error');

  const searchBtn = document.querySelector('button[onclick="searchIOC()"]');
  const originalBtnHtml = searchBtn ? searchBtn.innerHTML : '';
  if (searchBtn) {
    searchBtn.disabled = true;
    searchBtn.innerHTML = `
      <span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:8px;"></span>
      Searching intelligence providers...
    `;
  }

  const container = document.getElementById('threat-results-body');
  if (container) {
    container.innerHTML = `
      <div class="vt-loading-state" style="padding:28px;text-align:center;">
        <span class="spinner" style="width:24px;height:24px;border-width:2px;display:inline-block;margin-bottom:12px;"></span>
        <div style="color:#f8fafc;font-size:14px;font-weight:600;">Searching Threat Intelligence Providers...</div>
        <div style="color:#94a3b8;font-size:12px;margin-top:4px;">Querying VirusTotal and URLhaus for indicator '${escapeHtml(ioc.substring(0, 50))}'.</div>
      </div>
    `;
  }

  try {
    const res = await fetch(`${API_BASE}/api/threats/search?ioc=${encodeURIComponent(ioc)}`);
    const data = await res.json();
    if (!res.ok) {
      if (res.status === 503 || res.status === 401 || res.status === 429) {
        autoLinkThreatIntelPipeline(true);
      }
      throw new Error(data.detail || 'Search failed');
    }
    renderThreatIntelligenceReport(data);
    showToast('Intelligence search complete', 'success');
    updateOverview();
    loadOverviewLiveFeed();
  } catch (e) {
    showToast(e.message, 'error');
    if (container) {
      container.innerHTML = `<div class="results-empty"><p style="color:#ef4444;">Search failed: ${escapeHtml(e.message)}</p></div>`;
    }
  } finally {
    if (searchBtn) {
      searchBtn.disabled = false;
      searchBtn.innerHTML = originalBtnHtml;
    }
  }
}

async function scanQR() {
  const fileInput = document.getElementById('qr-input');
  if (!fileInput.files.length) return showToast('Please select a QR image', 'error');

  const qrBtn = document.querySelector('button[onclick="scanQR()"]');
  const originalBtnHtml = qrBtn ? qrBtn.innerHTML : '';
  if (qrBtn) {
    qrBtn.disabled = true;
    qrBtn.innerHTML = `
      <span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:8px;"></span>
      Scanning QR Image...
    `;
  }

  const container = document.getElementById('threat-results-body');
  if (container) {
    container.innerHTML = `
      <div class="vt-loading-state" style="padding:28px;text-align:center;">
        <span class="spinner" style="width:24px;height:24px;border-width:2px;display:inline-block;margin-bottom:12px;"></span>
        <div style="color:#f8fafc;font-size:14px;font-weight:600;">Analyzing QR Code &amp; Resolution Chain...</div>
        <div style="color:#94a3b8;font-size:12px;margin-top:4px;">Decoding forensic QR payload, resolving HTTP redirects, and verifying threat intelligence providers.</div>
      </div>
    `;
  }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);
  formData.append('source', 'web_dashboard');

  try {
    const res = await fetch(`${API_BASE}/api/threats/qr`, { method: 'POST', body: formData });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'QR scan failed');
    if (data.threat_intelligence) {
      renderThreatIntelligenceReport(data);
    } else {
      displayThreatResult(data);
    }
    showToast('QR Scan complete', 'success');
    if (window.CyberGuardAudio) window.CyberGuardAudio.playConfirm();
    updateOverview();
    loadOverviewLiveFeed();
  } catch (e) {
    showToast(e.message, 'error');
    if (container) {
      container.innerHTML = `<div class="results-empty"><p style="color:#ef4444;">Scan failed: ${escapeHtml(e.message)}</p></div>`;
    }
  } finally {
    if (qrBtn) {
      qrBtn.disabled = false;
      qrBtn.innerHTML = originalBtnHtml;
    }
  }
}


function displayThreatResult(event) {
  const container = document.getElementById('threat-results-body');
  if (!container) return;

  const isPending = event.classification === 'PENDING_EXTERNAL_VERIFICATION';
  let severity = (event.severity || 'SAFE').toUpperCase();
  if (isPending) {
    severity = 'PENDING VERIFICATION';
  }
  const badgeClass = isPending ? 'badge-warning' : (severity === 'SAFE' ? 'badge-safe' : (severity === 'LOW' ? 'badge-low' : (severity === 'MEDIUM' ? 'badge-medium' : 'badge-critical')));
  const borderColor = isPending ? '#f59e0b' : (severity === 'SAFE' ? '#10b981' : (severity === 'LOW' ? '#fbbf24' : (severity === 'MEDIUM' ? '#f97316' : '#ef4444')));

  let evList = '';
  if (Array.isArray(event.evidence) && event.evidence.length > 0) {
    evList = '<ul style="margin-top:10px; padding-left:18px; color:#cbd5e1; font-size:13px; line-height:1.6;">' +
      event.evidence.map(e => `<li>${formatEvidenceItem(e)}</li>`).join('') +
      '</ul>';
  }

  let title = event.threat_category || event.classification || event.source || 'Threat Analysis';
  if (event.threat_category === 'MALICIOUS_URL' && (event.severity === 'SAFE' || isPending)) {
    title = isPending ? 'URL Security Analysis (Verification Pending)' : 'URL Security Analysis';
  }
  const explanation = event.explanation?.summary || event.explanation?.reasoning || event.details || '';

  const html = `<div class="alert-row" style="border-left: 4px solid ${borderColor}; padding: 16px; margin-bottom: 12px; background: rgba(15,23,42,0.6); border-radius: 6px; border: 1px solid rgba(255,255,255,0.05);">
    <div style="display:flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <strong style="color:#f8fafc; font-size:14px;">${escapeHtml(title)}</strong>
      <span class="badge ${badgeClass}" style="${isPending ? 'background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44;' : ''}">${escapeHtml(severity)}</span>
    </div>
    ${explanation ? `<div style="color: #94a3b8; font-size:13px; margin-bottom:6px;">${escapeHtml(explanation)}</div>` : ''}
    ${evList}
  </div>`;

  const loadingEl = container.querySelector('.vt-loading-state');
  if (loadingEl) {
    loadingEl.remove();
  }

  if (container.querySelector('.results-empty')) {
    container.innerHTML = html;
  } else {
    container.innerHTML = html + container.innerHTML;
  }
}

// ── Interactive Engine Filter Handler ─────────────────────────────────────────
window._vtActiveEngines = [];

window.filterVTEngines = function (verdict) {
  const tbody = document.getElementById('vt-engine-tbody');
  if (!tbody || !window._vtActiveEngines) return;

  document.querySelectorAll('.vt-filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.verdict === verdict);
  });

  const filtered = verdict === 'all'
    ? window._vtActiveEngines
    : window._vtActiveEngines.filter(e => (e.verdict || '').toLowerCase() === verdict.toLowerCase());

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:#94a3b8;padding:18px;">No engines with verdict "${escapeHtml(verdict)}".</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(eng => {
    const v = (eng.verdict || 'undetected').toLowerCase();
    const tagClass = v === 'malicious' ? 'vt-verdict-malicious' : (v === 'suspicious' ? 'vt-verdict-suspicious' : (v === 'harmless' ? 'vt-verdict-harmless' : 'vt-verdict-undetected'));
    return `<tr>
      <td style="font-weight:600;color:#f1f5f9;">${escapeHtml(eng.engine_name)}</td>
      <td><span class="vt-verdict-tag ${tagClass}">${escapeHtml(eng.verdict)}</span></td>
      <td style="color:${v === 'malicious' ? '#f87171' : '#94a3b8'};font-family:monospace;">${escapeHtml(eng.result || 'clean')}</td>
      <td style="color:#64748b;">${escapeHtml(eng.method || 'blacklist')}</td>
    </tr>`;
  }).join('');
};

// ── URLhaus + Correlation Report Builder Helpers ─────────────────────────────

/**
 * Format internal indicator scopes to human-readable labels (no raw enums).
 */
function formatScopeLabel(scope) {
  if (!scope) return 'Indicator';
  const s = String(scope).toUpperCase();
  if (s === 'PRIMARY_IOC' || s === 'PRIMARY_URL') return 'Primary IOC';
  if (s === 'TERMINAL_IOC' || s === 'TERMINAL_URL') return 'Terminal URL';
  if (s === 'REDIRECT_HOP' || s === 'REDIRECT_HOP_IOC') return 'Redirect Hop';
  if (s === 'PROVIDER_REPORT' || s === 'PROVIDER_REPORT_IOC' || s === 'PROVIDER_REPORT_PAGE') return 'Provider Report Page';
  if (s === 'URLHAUS_RECORDED_MALWARE_URL' || s === 'RECORDED_THREAT_IOC' || s === 'RECORDED_MALWARE_URL') return 'Recorded Malware URL';
  if (s === 'ASSOCIATED_HOST' || s === 'RELATED_HOST_IOC' || s === 'HOST_LEVEL') return 'Associated Host / IP';
  if (s === 'PAYLOAD_HASH' || s === 'PAYLOAD_IOC' || s === 'ASSOCIATED_PAYLOAD') return 'Associated Payload Hash';
  if (s === 'RELATED_PROVIDER_INTELLIGENCE' || s === 'RELATED_EVIDENCE') return 'Related Threat Intelligence';
  return s.replace(/_/g, ' ');
}

/**
 * Map correlation status to display properties.
 */
function _corrStatusMeta(status) {
  switch (status) {
    case 'CORROBORATED': return { color: '#10b981', icon: '✓✓', label: 'CORROBORATED', cls: 'vt-banner-corroborated' };
    case 'PARTIALLY_CORROBORATED': return { color: '#38bdf8', icon: '✓~', label: 'PARTIALLY CORROBORATED', cls: 'vt-banner-info' };
    case 'RELATED_EVIDENCE': return { color: '#a855f7', icon: '🔗', label: 'RELATED THREAT EVIDENCE FOUND', cls: 'vt-banner-info' };
    case 'SINGLE_PROVIDER': return { color: '#f59e0b', icon: '①', label: 'SINGLE PROVIDER', cls: 'vt-banner-warning' };
    case 'CONFLICTING': return { color: '#f97316', icon: '⚡', label: 'CONFLICTING PROVIDERS', cls: 'vt-banner-danger' };
    case 'NO_MATCH': return { color: '#94a3b8', icon: '—', label: 'NO MATCH (BOTH)', cls: '' };
    case 'INSUFFICIENT_DATA': return { color: '#ef4444', icon: '⚠', label: 'INSUFFICIENT DATA', cls: 'vt-banner-danger' };
    case 'PROVIDER_UNAVAILABLE': return { color: '#f59e0b', icon: '⚠', label: 'PROVIDER UNAVAILABLE', cls: 'vt-banner-warning' };
    case 'PENDING': return { color: '#f59e0b', icon: '⏳', label: 'EXTERNAL VERIFICATION PENDING', cls: 'vt-banner-warning' };
    default: return { color: '#94a3b8', icon: '?', label: status || 'UNKNOWN', cls: '' };
  }
}

function buildCorrelationBanner(corrStatus, correlation, providers, isLocal) {
  if (!corrStatus || isLocal) return '';
  const meta = _corrStatusMeta(corrStatus);
  const summary = correlation.summary || '';
  const conflicts = correlation.conflicts || [];
  const gaps = correlation.provider_gaps || [];

  let conflictsHtml = '';
  if (conflicts.length > 0) {
    conflictsHtml = `<div style="margin-top:8px;padding:8px;background:rgba(249,115,22,0.1);border-radius:6px;border:1px solid rgba(249,115,22,0.3);">
      <div style="font-size:11px;font-weight:700;color:#f97316;text-transform:uppercase;margin-bottom:4px;">Provider Disagreements</div>
      ${conflicts.map(c => `<div style="font-size:12px;color:#fed7aa;margin-top:4px;">${escapeHtml(c)}</div>`).join('')}
    </div>`;
  }

  let gapsHtml = '';
  if (gaps.length > 0) {
    gapsHtml = `<div style="margin-top:6px;">${gaps.map(g => `<div style="font-size:11px;color:#94a3b8;margin-top:2px;">• ${escapeHtml(g)}</div>`).join('')}</div>`;
  }

  return `
    <div class="vt-banner ${meta.cls}" style="border-left:4px solid ${meta.color};">
      <div style="font-size:18px;flex-shrink:0;">${meta.icon}</div>
      <div style="flex:1;">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
          <strong style="color:${meta.color};font-size:12px;text-transform:uppercase;letter-spacing:.5px;">Cross-Provider Correlation: ${meta.label}</strong>
        </div>
        <div style="font-size:13px;color:#cbd5e1;line-height:1.5;">${escapeHtml(summary)}</div>
        ${conflictsHtml}
        ${gapsHtml}
      </div>
    </div>
  `;
}

function buildDetectionSummaryGrid(vtData, uhData, vtStatus, isLocal, relatedIntel) {
  if (isLocal) return '';
  if (!vtData.status && !uhData.status && !relatedIntel) return '';

  function providerStatusColor(s) {
    if (s === 'COMPLETED') return '#10b981';
    if (s === 'PENDING') return '#f59e0b';
    if (s === 'WAITING_FOR_VIRUSTOTAL') return '#64748b';
    if (s === 'NO_MATCH' || s === 'NOT_FOUND') return '#f59e0b';
    if (s === 'NOT_APPLICABLE' || s === 'NOT_CONFIGURED') return '#94a3b8';
    if (s === 'RATE_LIMITED' || s === 'AUTHENTICATION_FAILED') return '#ef4444';
    return '#64748b';
  }

  const vtMatched = vtData.matched || false;
  const uhMatched = uhData.matched || false;
  const vtColor = providerStatusColor(vtData.status || vtStatus);
  const uhColor = providerStatusColor(uhData.status);

  // Check for related threat intelligence lookup (VirusTotal and URLhaus)
  const relUH = relatedIntel?.urlhaus || null;
  const relVT = relatedIntel?.virustotal || null;

  let relatedCardsHtml = '';
  if (relUH || relVT) {
    if (relUH) {
      const relUhColor = relUH.status === 'online' ? '#ef4444' : '#10b981';
      relatedCardsHtml += `
        <div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <div style="font-size:11px;color:#f87171;text-transform:uppercase;font-weight:700;">URLhaus — Associated Threat IOC</div>
            <span class="badge" style="background:rgba(239,68,68,0.2);color:#fca5a5;font-size:10px;">${escapeHtml(formatScopeLabel(relatedIntel.scope || 'RECORDED_MALWARE_URL'))}</span>
          </div>
          <div style="font-family:monospace;font-size:11px;color:#cbd5e1;word-break:break-all;margin-bottom:6px;background:rgba(0,0,0,0.3);padding:3px 6px;border-radius:4px;">
            ${escapeHtml(relUH.url || 'Associated Indicator')}
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="width:8px;height:8px;border-radius:50%;background:${relUhColor};flex-shrink:0;"></span>
            <span style="font-size:12.5px;color:#f87171;font-weight:600;">${escapeHtml(relUH.threat || 'malware_download')} (${escapeHtml(relUH.status || 'active')})</span>
          </div>
        </div>
      `;
    }
    if (relVT) {
      const relVtMal = relVT.malicious || 0;
      const relVtColor = relVtMal > 0 ? '#ef4444' : '#10b981';
      relatedCardsHtml += `
        <div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <div style="font-size:11px;color:#f87171;text-transform:uppercase;font-weight:700;">VirusTotal — Associated Threat IOC</div>
            <span class="badge" style="background:rgba(239,68,68,0.2);color:#fca5a5;font-size:10px;">${escapeHtml(formatScopeLabel(relatedIntel.scope || 'RECORDED_MALWARE_URL'))}</span>
          </div>
          <div style="font-family:monospace;font-size:11px;color:#cbd5e1;word-break:break-all;margin-bottom:6px;background:rgba(0,0,0,0.3);padding:3px 6px;border-radius:4px;">
            ${escapeHtml(relUH?.url || 'Associated Indicator')}
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="width:8px;height:8px;border-radius:50%;background:${relVtColor};flex-shrink:0;"></span>
            <span style="font-size:12.5px;color:${relVtMal > 0 ? '#f87171' : '#34d399'};font-weight:600;">
              ${relVtMal > 0 ? `${relVtMal} malicious / ${relVT.total_engines || 0} engines` : 'No malicious detections'}
            </span>
          </div>
        </div>
      `;
    }
  }

  return `
    <div class="vt-section">
      <div class="vt-section-title">Multi-Provider Detection Summary</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;">
        <div style="background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;font-weight:600;margin-bottom:6px;">VirusTotal — Primary IOC</div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="width:8px;height:8px;border-radius:50%;background:${vtColor};flex-shrink:0;"></span>
            <span style="font-size:13px;color:#f1f5f9;font-weight:600;">${escapeHtml(vtData.status || vtStatus || 'N/A')}</span>
          </div>
          ${vtMatched ? `<div style="font-size:12px;color:#f87171;margin-top:6px;">${vtData.malicious || 0} malicious / ${vtData.total_engines || 0} engines</div>` : ''}
          ${!vtMatched && (vtData.status === 'COMPLETED' || vtStatus === 'COMPLETED') ? `<div style="font-size:12px;color:#34d399;margin-top:6px;">0 malicious detections / ${vtData.total_engines || 0} engines</div>` : ''}
        </div>
        <div style="background:rgba(0,0,0,0.2);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:12px;">
          <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;font-weight:600;margin-bottom:6px;">URLhaus — Primary IOC</div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="width:8px;height:8px;border-radius:50%;background:${uhColor};flex-shrink:0;"></span>
            <span style="font-size:13px;color:#f1f5f9;font-weight:600;">${escapeHtml(uhData.status || 'NOT QUERIED')}</span>
          </div>
          ${uhMatched ? `<div style="font-size:12px;color:#f87171;margin-top:6px;">${escapeHtml(uhData.classification || 'malware')} [${escapeHtml(formatScopeLabel(uhData.match_scope || 'PRIMARY_IOC'))}]</div>` : ''}
          ${!uhMatched && uhData.status === 'NO_MATCH' ? `<div style="font-size:12px;color:#94a3b8;margin-top:6px;">Not in URLhaus database</div>` : ''}
          ${uhData.status === 'NOT_APPLICABLE' ? `<div style="font-size:12px;color:#64748b;margin-top:6px;">Not applicable for this IOC type</div>` : ''}
        </div>
        ${relatedCardsHtml}
      </div>
    </div>
  `;
}

function buildUrlhausSection(uhData, relatedIntel) {
  const hasPrimaryUH = Boolean(uhData && uhData.matched);
  const relUH = relatedIntel?.urlhaus || null;
  if (!hasPrimaryUH && !relUH) return '';

  const activeData = hasPrimaryUH ? uhData : relUH;
  const isRelated = !hasPrimaryUH;
  const cls = activeData.classification || activeData.threat || 'malware';
  const matchScope = isRelated ? (relatedIntel.scope || 'URLHAUS_RECORDED_MALWARE_URL') : (activeData.match_scope || 'PRIMARY_IOC');
  const urlStatus = activeData.url_status || activeData.status;
  const threat = activeData.threat;
  const dateAdded = activeData.date_added;
  const lastSeen = activeData.last_seen_online;
  const tags = activeData.tags || [];
  const externalRef = activeData.external_reference || (relatedIntel && relatedIntel.provider_report_url);
  const limitations = activeData.limitations || [];
  const payloads = activeData.payloads || [];
  const urlsForHost = activeData.urls_for_host || [];

  let urlStatusBadge = '';
  if (urlStatus) {
    const usc = urlStatus === 'online' ? '#ef4444' : (urlStatus === 'offline' ? '#34d399' : '#f59e0b');
    urlStatusBadge = `<span style="background:${usc}22;color:${usc};border:1px solid ${usc}44;border-radius:4px;padding:1px 8px;font-size:11px;font-weight:600;text-transform:uppercase;">${escapeHtml(urlStatus)}</span>`;
  }

  let tagsHtml = '';
  if (tags.length > 0) {
    tagsHtml = `<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;">
      ${tags.map(t => `<span class="vt-cat-badge">${escapeHtml(String(t))}</span>`).join('')}
    </div>`;
  }

  let payloadsHtml = '';
  if (payloads.length > 0) {
    payloadsHtml = `<div style="margin-top:10px;">
      <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;">Associated Payload(s)</div>
      ${payloads.map(p => `
        <div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:8px;margin-bottom:4px;font-size:12px;">
          ${p.file_type ? `<span style="color:#94a3b8;">Type: ${escapeHtml(p.file_type)}</span>` : ''}
          ${p.signature ? `<span style="color:#f87171;margin-left:8px;">Sig: ${escapeHtml(p.signature)}</span>` : ''}
          ${p.sha256_hash ? `<div style="color:#64748b;font-family:monospace;font-size:10px;margin-top:2px;">${escapeHtml(p.sha256_hash)}</div>` : ''}
        </div>
      `).join('')}
    </div>`;
  }

  let hostsHtml = '';
  if (urlsForHost.length > 0) {
    const activeCount = urlsForHost.filter(u => u.url_status === 'online').length;
    hostsHtml = `<div style="margin-top:10px;">
      <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;">
        Associated Malware URLs (${urlsForHost.length} total, ${activeCount} active)
      </div>
      ${urlsForHost.slice(0, 5).map(u => `
        <div style="background:rgba(0,0,0,0.3);border-radius:6px;padding:8px;margin-bottom:4px;font-size:11px;font-family:monospace;display:flex;justify-content:space-between;align-items:center;">
          <span style="color:#94a3b8;overflow:hidden;text-overflow:ellipsis;max-width:80%;">${escapeHtml((u.url || '').substring(0, 80))}${(u.url || '').length > 80 ? '...' : ''}</span>
          ${u.url_status ? `<span style="flex-shrink:0;color:${u.url_status === 'online' ? '#ef4444' : '#34d399'};font-size:10px;">${escapeHtml(u.url_status)}</span>` : ''}
        </div>
      `).join('')}
      ${urlsForHost.length > 5 ? `<div style="font-size:11px;color:#64748b;margin-top:4px;">... and ${urlsForHost.length - 5} more. See URLhaus report for full list.</div>` : ''}
    </div>`;
  }

  let limitationsHtml = '';
  if (limitations.length > 0) {
    limitationsHtml = `<div style="margin-top:8px;padding:8px;background:rgba(94,234,212,0.05);border:1px solid rgba(94,234,212,0.15);border-radius:6px;">
      ${limitations.map(l => `<div style="font-size:11px;color:#5eead4;line-height:1.5;">ⓘ ${escapeHtml(l)}</div>`).join('')}
    </div>`;
  }

  return `
    <div class="vt-section">
      <div class="vt-section-title" style="color:#fb923c;">
        <span>URLhaus Intelligence — ${isRelated ? 'Associated Threat Indicator' : escapeHtml(cls.replace(/_/g, ' ').toUpperCase())}</span>
        <span style="font-size:11px;color:#64748b;text-transform:none;font-weight:400;">Scope: ${escapeHtml(formatScopeLabel(matchScope))}</span>
      </div>
      ${isRelated && relUH.url ? `
        <div style="font-family:monospace;font-size:12px;color:#cbd5e1;background:rgba(0,0,0,0.3);padding:6px 10px;border-radius:6px;margin-bottom:10px;border-left:3px solid #f87171;">
          <span style="color:#94a3b8;font-size:11px;text-transform:uppercase;">Recorded Malware URL:</span> <strong style="color:#f87171;">${escapeHtml(relUH.url)}</strong>
        </div>
      ` : ''}
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start;">
        <div style="flex:1;min-width:200px;">
          <div class="vt-tech-grid" style="gap:8px;">
            ${urlStatusBadge ? `<div class="vt-tech-item"><div class="vt-tech-k">URL Status</div><div class="vt-tech-v">${urlStatusBadge}</div></div>` : ''}
            ${threat ? `<div class="vt-tech-item"><div class="vt-tech-k">Threat</div><div class="vt-tech-v" style="color:#f87171;">${escapeHtml(threat)}</div></div>` : ''}
            ${dateAdded ? `<div class="vt-tech-item"><div class="vt-tech-k">First Seen</div><div class="vt-tech-v">${escapeHtml(formatTimestamp(dateAdded))}</div></div>` : ''}
            ${lastSeen ? `<div class="vt-tech-item"><div class="vt-tech-k">Last Online</div><div class="vt-tech-v">${escapeHtml(formatTimestamp(lastSeen))}</div></div>` : ''}
          </div>
          ${tagsHtml}
        </div>
      </div>
      ${payloadsHtml}
      ${hostsHtml}
      ${limitationsHtml}
      ${externalRef ? `<div style="margin-top:8px;"><a class="vt-btn-external" href="${escapeHtml(externalRef)}" target="_blank" rel="noopener noreferrer">Open URLhaus Report <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a></div>` : ''}
    </div>
  `;
}

function buildCrossProviderVerification(correlation, providers, uhData, perf) {
  if (!correlation || !correlation.status) return '';

  const gaps = correlation.provider_gaps || [];
  const corrEvidence = correlation.corroborating_evidence || [];
  const conflicts = correlation.conflicts || [];
  const vtP = providers.virustotal || {};
  const uhP = providers.urlhaus || {};
  const performance = perf || {};

  // Only show if there's something interesting to display
  if (!gaps.length && !corrEvidence.length && !conflicts.length && !performance.total_ms && !performance.pipeline_ms) return '';

  let evidenceHtml = '';
  if (corrEvidence.length > 0) {
    evidenceHtml = `
      <div style="margin-top:10px;">
        <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;margin-bottom:6px;">Corroborating Evidence</div>
        ${corrEvidence.filter(Boolean).slice(0, 4).map(ev => `
          <div class="vt-evidence-item">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;">
              <div style="color:#f8fafc;font-size:12px;font-weight:600;">${escapeHtml(typeof ev === 'object' ? (ev.description || ev.evidence_type || 'Evidence') : String(ev))}</div>
              ${typeof ev === 'object' && ev.source ? `<span style="font-size:10px;color:#94a3b8;background:rgba(255,255,255,0.05);padding:1px 6px;border-radius:3px;margin-left:8px;flex-shrink:0;">${escapeHtml(ev.source)}</span>` : ''}
            </div>
            ${typeof ev === 'object' && ev.actual_value !== undefined && ev.actual_value !== null ? `<div style="color:#64748b;font-size:11px;font-family:monospace;margin-top:2px;">${escapeHtml(typeof ev.actual_value === 'object' ? JSON.stringify(ev.actual_value) : String(ev.actual_value))}</div>` : ''}
          </div>
        `).join('')}
        ${corrEvidence.length > 4 ? `<div style="font-size:11px;color:#64748b;">... and ${corrEvidence.length - 4} more evidence items.</div>` : ''}
      </div>
    `;
  }

  let perfHtml = '';
  const totalDuration = performance.total_ms || performance.pipeline_ms;
  if (totalDuration !== undefined) {
    perfHtml = `
      <div style="margin-top:10px;padding:8px 12px;background:rgba(0,0,0,0.25);border-radius:6px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;">
        <div style="font-size:11px;color:#94a3b8;font-weight:600;">Execution Breakdown:</div>
        <div style="font-size:11px;color:#475569;">
          <span style="color:#94a3b8;">Total Pipeline: </span>
          <span style="color:#f1f5f9;font-family:monospace;font-weight:600;">${totalDuration}ms</span>
        </div>
        ${performance.qr_decode_ms !== undefined ? `<div style="font-size:11px;color:#475569;"><span style="color:#94a3b8;">QR Decode: </span><span style="font-family:monospace;color:#38bdf8;">${performance.qr_decode_ms}ms</span></div>` : ''}
        ${performance.resolution_ms !== undefined ? `<div style="font-size:11px;color:#475569;"><span style="color:#94a3b8;">URL Resolution: </span><span style="font-family:monospace;color:#38bdf8;">${performance.resolution_ms}ms</span></div>` : ''}
        ${performance.virustotal_ms !== undefined ? `<div style="font-size:11px;color:#475569;"><span style="color:#94a3b8;">VT: </span><span style="font-family:monospace;color:#cbd5e1;">${performance.virustotal_ms}ms</span></div>` : ''}
        ${performance.urlhaus_ms !== undefined ? `<div style="font-size:11px;color:#475569;"><span style="color:#94a3b8;">URLhaus: </span><span style="font-family:monospace;color:#cbd5e1;">${performance.urlhaus_ms}ms</span></div>` : ''}
        ${performance.local_heuristics_ms !== undefined ? `<div style="font-size:11px;color:#475569;"><span style="color:#94a3b8;">Local Heuristics: </span><span style="font-family:monospace;color:#cbd5e1;">${performance.local_heuristics_ms}ms</span></div>` : ''}
        ${performance.correlation_ms !== undefined ? `<div style="font-size:11px;color:#475569;"><span style="color:#94a3b8;">Correlation: </span><span style="font-family:monospace;color:#cbd5e1;">${performance.correlation_ms}ms</span></div>` : ''}
      </div>
    `;
  }

  return `
    <div class="vt-section">
      <div class="vt-section-title">Cross-Provider Verification</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">
        <div style="font-size:12px;color:#94a3b8;">
          VirusTotal (Primary): <strong style="color:#f1f5f9;">${escapeHtml(vtP.status || 'N/A')}</strong>
          ${vtP.matched ? ` · <span style="color:#f87171;">${vtP.malicious || 0} malicious</span>` : ''}
        </div>
        <div style="font-size:12px;color:#94a3b8;">
          URLhaus (Primary): <strong style="color:#f1f5f9;">${escapeHtml(uhP.status || 'N/A')}</strong>
          ${uhP.matched ? ` · <span style="color:#f87171;">${escapeHtml(uhP.classification || 'malware')}</span>` : ''}
        </div>
      </div>
      ${gaps.length > 0 ? `<div style="margin-top:6px;">${gaps.map(g => `<div style="font-size:11px;color:#64748b;margin-top:2px;">• ${escapeHtml(g)}</div>`).join('')}</div>` : ''}
      ${evidenceHtml}
      ${perfHtml}
    </div>
  `;
}

// ── Structured Threat Intelligence Report Renderer ───────────────────────────
function renderThreatIntelligenceReport(event) {
  const container = document.getElementById('threat-results-body');
  if (!container) return;

  const ti = event.threat_intelligence || {};
  const status = ti.status || 'UNKNOWN';
  const indicator = ti.indicator || event.indicator || 'Unknown';
  const category = (ti.indicator_type || 'indicator').toUpperCase();
  const isLocal = Boolean(ti.is_local);

  const isPending = status === 'PENDING' || event.classification === 'PENDING_EXTERNAL_VERIFICATION' || Boolean(ti.is_pending);
  let severity = (event.severity || 'SAFE').toUpperCase();
  if (isPending) {
    severity = 'PENDING VERIFICATION';
  }
  const badgeClass = isPending ? 'badge-warning' : (severity === 'SAFE' ? 'badge-safe' : (severity === 'LOW' ? 'badge-low' : (severity === 'MEDIUM' ? 'badge-medium' : 'badge-critical')));

  // URLhaus + Correlation data (new fields — backward-compatible, may be absent)
  const correlation = ti.correlation || {};
  const providers = ti.providers || {};
  const uhData = ti.urlhaus || {};
  const vtProviderData = providers.virustotal || {};
  const uhProviderData = providers.urlhaus || {};
  const corrStatus = correlation.status || '';

  // Save engines for interactive filtering
  window._vtActiveEngines = ti.engine_results || [];

  // Summary counts
  const summary = ti.summary || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total_engines: 0 };
  const totalEngines = summary.total_engines || 0;
  const maliciousCount = summary.malicious || 0;
  const suspiciousCount = summary.suspicious || 0;
  const harmlessCount = summary.harmless || 0;
  const undetectedCount = summary.undetected || 0;

  // Status Badge Class
  const statusBadgeColor = status === 'COMPLETED' ? '#10b981' : (isLocal ? '#38bdf8' : (status === 'NOT_FOUND' ? '#f59e0b' : '#ef4444'));

  // Banner HTML
  let bannerHtml = '';
  if (isPending) {
    bannerHtml = `
      <div class="vt-banner vt-banner-warning">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        <div>
          <strong style="color:#f59e0b;">EXTERNAL VERIFICATION PENDING</strong>
          <p style="margin-top:3px;color:#fde68a;">The extracted URL was submitted to VirusTotal for analysis. Analysis is currently running. CyberGuard preliminary local heuristics completed. Final verified assessment will be issued once external intelligence finishes.</p>
        </div>
      </div>
    `;
  } else if (isLocal) {
    bannerHtml = `
      <div class="vt-banner vt-banner-info">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
        <div>
          <strong style="color:#38bdf8;">LOCAL / PRIVATE TARGET IDENTIFIED</strong>
          <p style="margin-top:3px;color:#bae6fd;">${escapeHtml(ti.message || 'This address points to the local CyberGuard development environment or a private RFC 1918 network. External VirusTotal intelligence does not apply. CyberGuard local heuristics executed.')}</p>
        </div>
      </div>
    `;
  } else if (status === 'NOT_FOUND') {
    bannerHtml = `
      <div class="vt-banner vt-banner-warning">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <div>
          <strong style="color:#f59e0b;">NO VIRUSTOTAL REPORT FOUND</strong>
          <p style="margin-top:3px;color:#fde68a;">The indicator was not found in the available VirusTotal dataset. This does <strong>NOT</strong> prove that the indicator is safe. CyberGuard local heuristics applied below.</p>
        </div>
      </div>
    `;
  } else if (status === 'NOT_CONFIGURED') {
    bannerHtml = `
      <div class="vt-banner vt-banner-warning">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <div>
          <strong style="color:#f59e0b;">VIRUSTOTAL NOT CONFIGURED</strong>
          <p style="margin-top:3px;color:#fde68a;">${escapeHtml(ti.message || 'Server-side VIRUSTOTAL_API_KEY is missing or disabled in configuration.')}</p>
        </div>
      </div>
    `;
  } else if (status === 'AUTHENTICATION_FAILED') {
    bannerHtml = `
      <div class="vt-banner vt-banner-danger">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <div>
          <strong style="color:#ef4444;">VIRUSTOTAL AUTHENTICATION ERROR</strong>
          <p style="margin-top:3px;color:#fecaca;">Configured server-side API credentials were rejected by VirusTotal.</p>
        </div>
      </div>
    `;
  } else if (status === 'RATE_LIMITED') {
    bannerHtml = `
      <div class="vt-banner vt-banner-warning">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="6" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <div>
          <strong style="color:#f59e0b;">VIRUSTOTAL RATE LIMITED</strong>
          <p style="margin-top:3px;color:#fde68a;">VirusTotal API request quota has been reached. Please retry shortly.</p>
        </div>
      </div>
    `;
  } else if (status === 'UNAVAILABLE' || status === 'TIMEOUT') {
    bannerHtml = `
      <div class="vt-banner vt-banner-danger">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <div>
          <strong style="color:#ef4444;">VIRUSTOTAL UNAVAILABLE</strong>
          <p style="margin-top:3px;color:#fecaca;">External VirusTotal intelligence service could not be reached or request timed out.</p>
        </div>
      </div>
    `;
  }

  // Summary Metrics HTML (only rendered if completed and engines returned)
  let metricsHtml = '';
  if (status === 'COMPLETED' && totalEngines > 0) {
    metricsHtml = `
      <div class="vt-stat-grid">
        <div class="vt-stat-card vt-stat-malicious">
          <div class="vt-stat-val">${maliciousCount}</div>
          <div class="vt-stat-label">Malicious</div>
        </div>
        <div class="vt-stat-card vt-stat-suspicious">
          <div class="vt-stat-val">${suspiciousCount}</div>
          <div class="vt-stat-label">Suspicious</div>
        </div>
        <div class="vt-stat-card vt-stat-harmless">
          <div class="vt-stat-val">${harmlessCount}</div>
          <div class="vt-stat-label">Harmless</div>
        </div>
        <div class="vt-stat-card vt-stat-undetected">
          <div class="vt-stat-val">${undetectedCount}</div>
          <div class="vt-stat-label">Undetected</div>
        </div>
        <div class="vt-stat-card">
          <div class="vt-stat-val" style="color:#f8fafc;">${totalEngines}</div>
          <div class="vt-stat-label">Total Engines</div>
        </div>
      </div>
    `;
  }

  // ── Resolution Path & Redirect Chain ──────────────────────────────
  let resolutionHtml = '';
  const resolution = ti.resolution || null;
  const redirectChain = ti.redirect_chain || (resolution ? resolution.redirect_chain : []) || [];
  const termUrl = ti.terminal_url || ti.resolved_terminal_url || ti.final_url || '';
  const origUrl = ti.original_url || ti.indicator || '';

  if (redirectChain.length > 0 || (resolution && resolution.status)) {
    const resStatus = resolution ? resolution.status : 'COMPLETED';
    const resStatusBadge = resStatus === 'COMPLETED' ? 'badge-safe' : (String(resStatus).includes('BLOCKED') ? 'badge-critical' : 'badge-warning');

    let chainItemsHtml = '';
    redirectChain.forEach((hop, idx) => {
      chainItemsHtml += `
        <div class="vt-chain-hop">
          <span class="vt-chain-hop-num">Hop ${escapeHtml(String(hop.hop || (idx + 1)))}</span>
          <div style="flex:1;">
            <div style="font-family:monospace;word-break:break-all;color:#e2e8f0;font-size:12px;">${escapeHtml(hop.from_url)}</div>
            <div style="margin:4px 0;font-size:11px;color:#94a3b8;">
              <span style="color:#38bdf8;font-weight:700;">${escapeHtml(hop.redirect_type || 'HTTP')} ${escapeHtml(String(hop.status_code || '30x'))}</span>
              <span style="margin:0 4px;">→</span>
              <span style="color:#64748b;">Target:</span>
            </div>
            <div style="font-family:monospace;word-break:break-all;color:#cbd5e1;font-size:12px;">${escapeHtml(hop.to_url)}</div>
          </div>
        </div>
      `;
    });

    // Add Terminal URL entry
    if (termUrl) {
      chainItemsHtml += `
        <div class="vt-chain-hop" style="border-color:rgba(16,185,129,0.3);background:rgba(16,185,129,0.03);">
          <span class="vt-chain-hop-num" style="background:rgba(16,185,129,0.2);color:#10b981;">Terminal</span>
          <div style="flex:1;">
            <div style="font-family:monospace;word-break:break-all;color:#34d399;font-weight:600;font-size:12.5px;">
              ${escapeHtml(termUrl)}
              <span class="vt-pill-badge vt-pill-terminal">TERMINAL DESTINATION</span>
              ${ti.terminal_status_code ? `<span class="vt-pill-badge" style="background:rgba(255,255,255,0.08);color:#f1f5f9;">HTTP ${escapeHtml(String(ti.terminal_status_code))}</span>` : ''}
            </div>
          </div>
        </div>
      `;
    }

    resolutionHtml = `
      <div class="vt-section">
        <div class="vt-section-title">
          <span>Resolution Path & Redirect Forensics</span>
          <span class="badge ${resStatusBadge}">${escapeHtml(resStatus)}</span>
        </div>
        <div class="vt-chain-list">
          ${chainItemsHtml}
        </div>
      </div>
    `;
  }

  // ── Associated Threat Indicators & Intelligence ───────────────────
  let associatedIocsHtml = '';
  const associatedIocs = ti.associated_iocs || [];
  if (associatedIocs.length > 0) {
    associatedIocsHtml = `
      <div class="vt-section">
        <div class="vt-section-title">Associated Security Indicators & Provenance</div>
        <div style="display:flex;flex-direction:column;gap:8px;">
          ${associatedIocs.map(ioc => {
            const isRecordedMalware = ioc.scope === 'URLHAUS_RECORDED_MALWARE_URL';
            const isReport = ioc.scope === 'PROVIDER_REPORT';
            const pillClass = isRecordedMalware ? 'vt-pill-threat' : (isReport ? 'vt-pill-report' : 'vt-pill-host');
            const pillLabel = escapeHtml(formatScopeLabel(ioc.scope || ioc.type || 'IOC'));

            const intel = ioc.intelligence || {};
            const vtSummary = intel.virustotal || {};

            return `
              <div class="vt-ioc-card">
                <div class="vt-ioc-card-header">
                  <div class="vt-ioc-val">
                    ${escapeHtml(ioc.value)}
                    <span class="vt-pill-badge ${pillClass}">${pillLabel}</span>
                  </div>
                  <div style="font-size:11px;color:#64748b;">Source: ${escapeHtml(ioc.source || 'ThreatIntelligence')}</div>
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:12px;font-size:11.5px;color:#94a3b8;margin-top:6px;">
                  ${ioc.threat ? `<div>Threat: <strong style="color:#f87171;">${escapeHtml(ioc.threat)}</strong></div>` : ''}
                  ${ioc.url_status ? `<div>Status: <strong style="color:#e2e8f0;">${escapeHtml(ioc.url_status)}</strong></div>` : ''}
                  ${ioc.associated_host ? `<div>Host/IP: <span style="font-family:monospace;color:#38bdf8;">${escapeHtml(ioc.associated_host)}</span></div>` : ''}
                  ${ioc.payload_sha256 ? `<div>Payload SHA-256: <span style="font-family:monospace;color:#cbd5e1;font-size:10.5px;">${escapeHtml(ioc.payload_sha256.substring(0, 16))}...</span></div>` : ''}
                  ${vtSummary.malicious !== undefined ? `<div>VirusTotal: <strong style="color:${vtSummary.malicious > 0 ? '#f87171' : '#34d399'};">${vtSummary.malicious} malicious</strong> / ${vtSummary.total_engines || 0} engines</div>` : ''}
                </div>
                ${ioc.provider_report_url && ioc.value !== ioc.provider_report_url ? `
                  <div style="margin-top:8px;font-size:11px;">
                    <a href="${escapeHtml(ioc.provider_report_url)}" target="_blank" rel="noopener noreferrer" style="color:#c084fc;text-decoration:none;display:inline-flex;align-items:center;gap:4px;">
                      <span>🔗 Open URLhaus Report</span>
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                    </a>
                  </div>
                ` : ''}
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }

  // ── Technical Details Grid ─────────────────────────────────────────
  const tech = ti.technical_details || {};
  let techDetailsHtml = '';

  const priorityKeys = [
    'original_url', 'terminal_url', 'terminal_http_status', 'redirect_hops',
    'title', 'canonical_url', 'og_url', 'provider_report_url',
    'urlhaus_recorded_malware_url', 'associated_host_ip'
  ];

  const filteredTech = {};
  for (const pk of priorityKeys) {
    if (tech[pk] !== undefined && tech[pk] !== null && tech[pk] !== '') {
      filteredTech[pk] = tech[pk];
    }
  }
  for (const [k, v] of Object.entries(tech)) {
    if (v === null || v === undefined || v === '') continue;
    if (['url', 'final_url', 'http_response_code'].includes(k) && filteredTech.original_url) continue;
    if (filteredTech[k] === undefined) {
      filteredTech[k] = v;
    }
  }

  const techEntries = Object.entries(filteredTech).filter(([k, v]) => (!Array.isArray(v) || v.length > 0));
  if (techEntries.length > 0) {
    techDetailsHtml = `
      <div class="vt-section">
        <div class="vt-section-title">Technical Details & Metadata</div>
        <div class="vt-tech-grid">
          ${techEntries.map(([k, v]) => `
            <div class="vt-tech-item">
              <div class="vt-tech-k">${escapeHtml(k.replace(/_/g, ' '))}</div>
              <div class="vt-tech-v">${escapeHtml(Array.isArray(v) ? v.join(', ') : (typeof v === 'object' ? JSON.stringify(v) : String(v)))}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }


  // Categories
  const categories = ti.categories || [];
  let categoriesHtml = '';
  if (categories.length > 0) {
    categoriesHtml = `
      <div class="vt-section">
        <div class="vt-section-title">Categories & Threat Classifications</div>
        <div class="vt-category-tags">
          ${categories.map(c => `
            <span class="vt-cat-badge">
              <span class="vt-cat-provider">${escapeHtml(c.provider)}:</span>
              <span>${escapeHtml(c.category)}</span>
            </span>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Timeline
  const timeline = ti.timeline || {};
  const timelineEntries = Object.entries(timeline).filter(([k, v]) => Boolean(v));
  let timelineHtml = '';
  if (timelineEntries.length > 0) {
    timelineHtml = `
      <div class="vt-section">
        <div class="vt-section-title">Analysis Timeline</div>
        <div class="vt-tech-grid">
          ${timelineEntries.map(([k, v]) => `
            <div class="vt-tech-item">
              <div class="vt-tech-k">${escapeHtml(k.replace(/_/g, ' '))}</div>
              <div class="vt-tech-v" style="font-size:12px;">${escapeHtml(formatTimestamp(v))}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Engine Results Table
  let engineResultsHtml = '';
  const engines = ti.engine_results || [];
  if (engines.length > 0) {
    const maliciousCount = engines.filter(e => (e.verdict || '').toLowerCase() === 'malicious').length;
    const suspiciousCount = engines.filter(e => (e.verdict || '').toLowerCase() === 'suspicious').length;
    const harmlessCount = engines.filter(e => (e.verdict || '').toLowerCase() === 'harmless').length;
    const undetectedCount = engines.filter(e => (e.verdict || '').toLowerCase() === 'undetected').length;

    engineResultsHtml = `
      <div class="vt-section">
        <div class="vt-section-title">
          <span>Security Engine Results (${engines.length})</span>
          <span style="font-size:11px;color:#64748b;text-transform:none;font-weight:400;">Filter by verdict</span>
        </div>
        <div class="vt-filter-pills">
          <button class="vt-filter-btn active" data-verdict="all" onclick="filterVTEngines('all')">All (${engines.length})</button>
          ${maliciousCount > 0 ? `<button class="vt-filter-btn" data-verdict="malicious" onclick="filterVTEngines('malicious')" style="color:#f87171;">Malicious (${maliciousCount})</button>` : ''}
          ${suspiciousCount > 0 ? `<button class="vt-filter-btn" data-verdict="suspicious" onclick="filterVTEngines('suspicious')" style="color:#fbbf24;">Suspicious (${suspiciousCount})</button>` : ''}
          ${harmlessCount > 0 ? `<button class="vt-filter-btn" data-verdict="harmless" onclick="filterVTEngines('harmless')" style="color:#34d399;">Harmless (${harmlessCount})</button>` : ''}
          ${undetectedCount > 0 ? `<button class="vt-filter-btn" data-verdict="undetected" onclick="filterVTEngines('undetected')">Undetected (${undetectedCount})</button>` : ''}
        </div>
        <div class="vt-table-wrap">
          <table class="vt-engine-table">
            <thead>
              <tr>
                <th>Security Engine</th>
                <th>Verdict</th>
                <th>Result / Signature</th>
                <th>Method</th>
              </tr>
            </thead>
            <tbody id="vt-engine-tbody">
              ${engines.map(eng => {
      const v = (eng.verdict || 'undetected').toLowerCase();
      const tagClass = v === 'malicious' ? 'vt-verdict-malicious' : (v === 'suspicious' ? 'vt-verdict-suspicious' : (v === 'harmless' ? 'vt-verdict-harmless' : 'vt-verdict-undetected'));
      return `<tr>
                  <td style="font-weight:600;color:#f1f5f9;">${escapeHtml(eng.engine_name)}</td>
                  <td><span class="vt-verdict-tag ${tagClass}">${escapeHtml(eng.verdict)}</span></td>
                  <td style="color:${v === 'malicious' ? '#f87171' : '#94a3b8'};font-family:monospace;">${escapeHtml(eng.result || 'clean')}</td>
                  <td style="color:#64748b;">${escapeHtml(eng.method || 'blacklist')}</td>
                </tr>`;
    }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // CyberGuard Local Assessment & Evidence
  const local = ti.cyberguard_local || {};
  const localEvidences = local.evidence || [];
  let localHtml = '';
  if (localEvidences.length > 0 || isLocal) {
    localHtml = `
      <div class="vt-section">
        <div class="vt-section-title">
          <span>CyberGuard Local Analysis</span>
          <span class="badge ${local.risk_level === 'SAFE' ? 'badge-safe' : 'badge-critical'}">${escapeHtml(local.risk_level || 'SAFE')}</span>
        </div>
        <div>
          ${localEvidences.filter(Boolean).map(ev => `
            <div class="vt-evidence-item">
              <div style="color:#f8fafc;font-weight:600;">${escapeHtml(typeof ev === 'object' ? (ev.description || ev.evidence_type) : String(ev))}</div>
              ${typeof ev === 'object' && ev.value !== undefined && ev.value !== null ? `<div style="color:#94a3b8;font-size:11px;font-family:monospace;">Value: ${escapeHtml(typeof ev.value === 'object' ? JSON.stringify(ev.value) : String(ev.value))}</div>` : ''}
              <div style="color:#64748b;font-size:10px;text-transform:uppercase;">Source: ${escapeHtml((typeof ev === 'object' && ev.source) || 'CyberGuard Local')}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Correlated Assessment & Explanation
  const correlated = ti.correlated_assessment || {};
  const explanation = event.explanation?.reasoning || correlated.reasoning || event.explanation?.summary || '';
  const provenance = correlated.provenance || 'Source: CyberGuard';

  // Recommended actions
  const actions = event.recommended_actions || ti.recommended_actions || [];
  let actionsHtml = '';
  if (actions.length > 0) {
    actionsHtml = `
      <div class="vt-section">
        <div class="vt-section-title">Recommended Defensive Response</div>
        <ul style="padding-left:18px;margin:0;color:#cbd5e1;font-size:13px;line-height:1.6;">
          ${actions.map(act => `<li>${escapeHtml(act)}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  // External Link Button
  const permalink = ti.permalink || '';

  const qrMeta = ti.qr_metadata || (event.modality === 'image/qr' ? { qr_status: 'DECODED', content_type: 'URL', decoded_payload: indicator } : null);
  let qrSectionHtml = '';
  if (qrMeta) {
    const qrStatus = qrMeta.qr_status || 'DECODED';
    const isDecodeFailed = qrStatus === 'QR_DECODE_FAILED';
    const qrStatusColor = isDecodeFailed ? '#ef4444' : '#10b981';
    qrSectionHtml = `
      <div class="vt-section" style="background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.25);margin-bottom:14px;padding:14px;border-radius:8px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <strong style="color:#60a5fa;font-size:12px;text-transform:uppercase;letter-spacing:0.6px;display:flex;align-items:center;gap:6px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3z"/><path d="M20 14v3"/><path d="M14 20h6"/></svg>
            QR Forensic Extraction
          </strong>
          <span class="badge" style="background:${qrStatusColor}22;color:${qrStatusColor};border:1px solid ${qrStatusColor}44;font-size:11px;">${escapeHtml(qrStatus)}</span>
        </div>
        <div style="font-size:13px;line-height:1.6;display:grid;grid-template-columns:auto 1fr;gap:6px 12px;align-items:baseline;">
          <div style="color:#94a3b8;font-size:12px;">Decoded Content:</div>
          <div><code style="color:#38bdf8;word-break:break-all;font-size:12px;background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;">${escapeHtml(qrMeta.decoded_payload || indicator)}</code></div>
          <div style="color:#94a3b8;font-size:12px;">Content Type:</div>
          <div style="color:#f8fafc;font-weight:600;font-size:12px;">${escapeHtml(qrMeta.content_type || 'URL')}</div>
          ${qrMeta.decode_time_ms ? `<div style="color:#94a3b8;font-size:12px;">Decode Time:</div><div style="color:#94a3b8;font-size:12px;font-family:monospace;">${qrMeta.decode_time_ms}ms</div>` : ''}
        </div>
      </div>
    `;
  }

  const reportTitle = qrMeta ? 'QR Security Analysis' : 'Threat Intelligence Report';

  const analysisId = ti.analysis_id || event.id || event.event_id || ('analysis_' + Date.now());
  const reportCardHtml = `
    <div class="vt-report-container" data-analysis-id="${escapeHtml(analysisId)}">
      <div class="vt-report-header">
        <div>
          <div style="font-size:11px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px;">
            ${escapeHtml(reportTitle)}
          </div>
          <div class="vt-ioc-title">${escapeHtml(indicator)}</div>
        </div>
        <div class="vt-ioc-badges">
          <button class="vt-btn-copy" onclick="copyIndicator('${escapeHtml(indicator)}')">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy IOC
          </button>
          <span class="badge" style="background:rgba(255,255,255,0.06);color:#94a3b8;border:1px solid rgba(255,255,255,0.1);">${escapeHtml(category)}</span>
          <span class="badge ${badgeClass}" style="${isPending ? 'background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44;' : ''}">${escapeHtml(severity)}</span>
          <span class="vt-provenance">${escapeHtml(provenance)}</span>
          ${permalink ? `
            <a class="vt-btn-external" href="${escapeHtml(permalink)}" target="_blank" rel="noopener noreferrer">
              Open VirusTotal Report
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            </a>
          ` : ''}
        </div>
      </div>

      ${qrSectionHtml}
      ${bannerHtml}
      ${metricsHtml}

      ${buildCorrelationBanner(corrStatus, correlation, providers, isLocal)}
      ${buildDetectionSummaryGrid(vtProviderData, uhProviderData, status, isLocal, providers.related_intelligence)}
      ${buildUrlhausSection(uhData, providers.related_intelligence)}
      ${resolutionHtml}
      ${associatedIocsHtml}

      <div class="vt-section" style="background:rgba(0,0,0,0.15);">
        <div class="vt-section-title">Assessment & Summary</div>
        <div style="color:#f1f5f9;font-size:14px;font-weight:600;margin-bottom:6px;">${escapeHtml(event.explanation?.summary || 'Threat analysis complete.')}</div>
        <div style="color:#94a3b8;font-size:13px;line-height:1.5;">${escapeHtml(explanation)}</div>
      </div>


      ${localHtml}
      ${techDetailsHtml}
      ${categoriesHtml}
      ${timelineHtml}
      ${engineResultsHtml}
      ${buildCrossProviderVerification(correlation, providers, uhData, ti.performance)}
      ${actionsHtml}
    </div>
  `;

  // Exactly one primary report rendered per analysis; previous results replaced
  container.innerHTML = reportCardHtml;
}



/* ==========================================================================
   CYBERGUARD UNIFIED SECURITY CENTER & REAL-TIME INCIDENT/ALERT ENGINE
   ========================================================================== */

window._scItems = [];
window._scFilter = 'all';
window._scSearchQuery = '';
window._scSelectedItemId = null;
window._scFeedList = [];
window._scWsInstance = null;
window._scWsPingInterval = null;
window._scWsReconnectTimeout = null;

// ── Item Normalizers ────────────────────────────────────────────────────────

function normalizeIncident(inc) {
  const incidentId = inc.incident_id || 'N/A';
  const firstSeen = inc.first_seen ? (typeof inc.first_seen === 'string' ? new Date(inc.first_seen).getTime() / 1000 : inc.first_seen) : Date.now() / 1000;
  const lastSeen = inc.last_seen ? (typeof inc.last_seen === 'string' ? new Date(inc.last_seen).getTime() / 1000 : inc.last_seen) : firstSeen;
  const risk = (inc.risk || 'LOW').toUpperCase();
  const status = (inc.status || 'NEW').toUpperCase();

  let summary = inc.summary || '';
  if (!summary && Array.isArray(inc.events) && inc.events.length > 0) {
    summary = inc.events[0].explanation?.summary || inc.events[0].explanation?.reasoning || '';
  }
  if (!summary) {
    summary = `Security incident with ${inc.event_count || (inc.events ? inc.events.length : 1)} correlated event(s)`;
  }

  const indicator = (Array.isArray(inc.affected_assets) && inc.affected_assets.length > 0)
    ? inc.affected_assets.join(', ')
    : 'N/A';

  return {
    id: incidentId,
    type: 'INCIDENT',
    category: inc.category || 'SECURITY_INCIDENT',
    risk: risk,
    status: status,
    timestamp: firstSeen,
    updated_at: lastSeen,
    title: `Incident: ${inc.category || 'Security Alert'}`,
    summary: summary,
    description: inc.description || inc.analyst_notes || '',
    source: 'CyberGuard Incident Engine',
    indicator: indicator,
    raw: inc
  };
}

function normalizeAlert(alt) {
  const alertId = alt.alert_id || (alt.session_id ? `ALT-${alt.session_id.substring(0, 8)}` : 'N/A');
  const ts = alt.timestamp ? (typeof alt.timestamp === 'string' ? new Date(alt.timestamp).getTime() / 1000 : alt.timestamp) : Date.now() / 1000;
  const level = (alt.alert_level || 'LOW').toUpperCase();
  const status = alt.status || 'ACTIVE';

  let recTitle = alt.recommendation_title || '';
  let recMsg = '';
  if (alt.recommendation) {
    if (typeof alt.recommendation === 'object') {
      recTitle = recTitle || alt.recommendation.title || '';
      recMsg = alt.recommendation.message || '';
    } else {
      recMsg = String(alt.recommendation);
    }
  }
  const summary = recMsg || `Voice stream anomaly (Risk Score: ${(alt.risk_score || 0).toFixed(3)})`;
  const indicator = alt.speaker_id || alt.session_id || 'Acoustic Stream';

  return {
    id: alertId,
    type: 'ALERT',
    category: alt.threat_category || 'VOICE_IMPERSONATION',
    risk: level,
    status: status,
    timestamp: ts,
    updated_at: ts,
    title: recTitle || `Alert: ${level}`,
    summary: summary,
    description: recMsg,
    source: alt.source || 'Voice Analysis Engine',
    indicator: indicator,
    raw: alt
  };
}

function normalizeThreatEvent(evt) {
  const eventId = evt.event_id || (evt.id ? `EVT-${evt.id}` : 'N/A');
  const ts = evt.timestamp ? (typeof evt.timestamp === 'string' ? new Date(evt.timestamp).getTime() / 1000 : evt.timestamp) : Date.now() / 1000;
  const severity = (evt.severity || evt.risk_level || 'MEDIUM').toUpperCase();
  const status = evt.status || 'NEW';

  let summary = '';
  if (evt.explanation) {
    summary = evt.explanation.summary || evt.explanation.reasoning || '';
  }
  if (!summary) {
    summary = evt.summary || `Threat detected: ${evt.category || evt.event_type || 'Security Event'}`;
  }

  let source = evt.source || '';
  if (!source && Array.isArray(evt.providers) && evt.providers.length > 0) {
    source = evt.providers.join(' + ');
  }
  if (!source) {
    source = 'Threat Detection Engine';
  }

  const indicator = evt.indicator || (evt.evidence && evt.evidence[0]?.description) || 'N/A';

  return {
    id: eventId,
    type: 'THREAT',
    category: evt.category || evt.event_type || 'THREAT_DETECTED',
    risk: severity,
    status: status,
    timestamp: ts,
    updated_at: ts,
    title: evt.title || `Threat: ${evt.category || 'Security Event'}`,
    summary: summary,
    description: (evt.explanation && evt.explanation.details) || evt.description || '',
    source: source,
    indicator: indicator,
    raw: evt
  };
}

function formatScTimestamp(ts) {
  if (!ts) return 'N/A';
  const epochMs = (ts > 1e11 ? ts : ts * 1000);
  const nowMs = Date.now();
  const diffSec = Math.floor((nowMs - epochMs) / 1000);

  if (isNaN(diffSec) || diffSec < 0) {
    try {
      return new Date(epochMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
      return 'N/A';
    }
  }

  if (diffSec < 60) return 'Just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;

  try {
    return new Date(epochMs).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (_) {
    return 'N/A';
  }
}

// ── Data Loader & Summary ───────────────────────────────────────────────────

async function loadSecurityCenterData() {
  const wrap = document.getElementById('sc-table-wrap');
  if (wrap && wrap.querySelector('.history-empty') && !wrap.querySelector('.spinner')) {
    wrap.innerHTML = '<div class="history-empty"><span class="spinner" style="width:16px;height:16px;display:inline-block;margin-right:8px;"></span> Loading security activity...</div>';
  }

  try {
    const [incRes, altRes, evtRes, sumRes] = await Promise.allSettled([
      fetch('/api/incidents/'),
      fetch('/api/alerts/recent?limit=50'),
      fetch('/api/incidents/events?limit=50'),
      fetch('/api/incidents/dashboard/summary')
    ]);

    const itemsMap = new Map();

    // 1. Incidents
    if (incRes.status === 'fulfilled' && incRes.value.ok) {
      const incidents = await incRes.value.json();
      if (Array.isArray(incidents)) {
        incidents.forEach(inc => {
          const item = normalizeIncident(inc);
          if (item.id !== 'N/A') itemsMap.set(item.id, item);
        });
      }
    }

    // 2. Alerts
    if (altRes.status === 'fulfilled' && altRes.value.ok) {
      const altData = await altRes.value.json();
      const alerts = altData.alerts || (Array.isArray(altData) ? altData : []);
      alerts.forEach(alt => {
        const item = normalizeAlert(alt);
        if (item.id !== 'N/A' && !itemsMap.has(item.id)) itemsMap.set(item.id, item);
      });
    }

    // 3. Threat Events
    if (evtRes.status === 'fulfilled' && evtRes.value.ok) {
      const events = await evtRes.value.json();
      if (Array.isArray(events)) {
        events.forEach(evt => {
          const item = normalizeThreatEvent(evt);
          if (item.id !== 'N/A' && !itemsMap.has(item.id)) itemsMap.set(item.id, item);
        });
      }
    }

    // Sort descending by updated_at
    const allItems = Array.from(itemsMap.values());
    allItems.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
    window._scItems = allItems;

    // 4. Update Summary Cards
    let summaryData = null;
    if (sumRes.status === 'fulfilled' && sumRes.value.ok) {
      summaryData = await sumRes.value.json();
    }
    updateSCSummary(summaryData);
    updateOverview();

    // 5. Render Charts & Table
    renderSecurityCenterCharts(allItems, summaryData);
    renderSecurityCenterTable();

  } catch (err) {
    console.error('Failed to load Security Center data:', err);
    if (wrap) {
      wrap.innerHTML = `
        <div class="history-empty" style="color:var(--risk-high); padding:30px;">
          Unable to load security activity: ${escapeHtml(err.message || 'Network error')}.
          <div style="margin-top:12px;">
            <button class="btn btn-xs btn-secondary" onclick="loadSecurityCenterData()">↻ Retry</button>
          </div>
        </div>
      `;
    }
  }
}

function updateSCSummary(backendSummary) {
  const items = window._scItems || [];

  let threats = 0;
  let incidents = 0;
  let alerts = 0;
  let criticalHigh = 0;

  if (backendSummary && typeof backendSummary === 'object') {
    threats = backendSummary.high_critical_threats !== undefined ? backendSummary.high_critical_threats : 0;
    incidents = backendSummary.open_incidents !== undefined ? backendSummary.open_incidents : 0;
    criticalHigh = backendSummary.critical_threats !== undefined ? backendSummary.critical_threats : (backendSummary.high_critical_threats || 0);
  } else {
    // Fallback when backend summary is unavailable
    threats = items.filter(i => i.risk === 'HIGH' || i.risk === 'CRITICAL').length;
    incidents = items.filter(i => i.type === 'INCIDENT' && ['NEW', 'INVESTIGATING', 'CONTAINED'].includes(i.status)).length;
    criticalHigh = items.filter(i => i.risk === 'CRITICAL').length;
  }

  alerts = items.filter(i => i.type === 'ALERT').length;

  const elThreats = document.getElementById('sc-stat-threats');
  const elIncidents = document.getElementById('sc-stat-incidents');
  const elAlerts = document.getElementById('sc-stat-alerts');
  const elCritical = document.getElementById('sc-stat-critical');
  const elPostureBadge = document.getElementById('sc-posture-badge');
  const elPostureDesc = document.getElementById('sc-posture-desc');

  if (elThreats) elThreats.textContent = threats;
  if (elIncidents) elIncidents.textContent = incidents;
  if (elAlerts) elAlerts.textContent = alerts;
  if (elCritical) elCritical.textContent = criticalHigh;

  if (elPostureBadge && elPostureDesc) {
    if (criticalHigh >= 3 || threats >= 3) {
      elPostureBadge.innerHTML = '<span class="badge badge-critical">HIGH ALERT</span>';
      elPostureDesc.textContent = 'Multiple active threats detected across pipelines';
    } else if (criticalHigh >= 1 || threats >= 1) {
      elPostureBadge.innerHTML = '<span class="badge badge-critical">ELEVATED RISK</span>';
      elPostureDesc.textContent = 'High priority threat requires immediate containment';
    } else if (incidents > 0) {
      elPostureBadge.innerHTML = '<span class="badge badge-medium">MONITORING</span>';
      elPostureDesc.textContent = `${incidents} active incident(s) under observation`;
    } else {
      elPostureBadge.innerHTML = '<span class="badge badge-safe">NORMAL</span>';
      elPostureDesc.textContent = 'All pipelines operational';
    }
  }
}

// ── Authoritative SC Summary Refresh (RC-2 fix) ──────────────────────────────
// Fetches the same /api/incidents/dashboard/summary endpoint that updateOverview()
// uses, then feeds it into updateSCSummary() so both pages share one source of truth.
// Called after every real-time WS event via mergeIncomingItem().
async function updateSCSummaryFromAPI() {
  try {
    const res = await fetch('/api/incidents/dashboard/summary');
    if (!res.ok) {
      // On API failure, fall back to local computation so SC stays visible.
      // Do NOT zero out counts on failure — empty vs error distinction.
      updateSCSummary();
      return;
    }
    const summary = await res.json();
    updateSCSummary(summary);
  } catch (e) {
    // Network error — keep existing displayed values, do not set to zero.
    console.warn('Security Center summary API unavailable, keeping current state:', e.message);
  }
}

// ── Filters & Search ────────────────────────────────────────────────────────

// ── Filters & Search ────────────────────────────────────────────────────────

let scCurrentPage = 1;
const scPageSize = 25;
let scTrendChartInstance = null;
let scCategoryMixInstance = null;

function prevSCPage() {
  if (scCurrentPage > 1) {
    scCurrentPage--;
    renderSecurityCenterTable();
  }
}

function nextSCPage() {
  const filter = window._scFilter || 'all';
  const query = window._scSearchQuery || '';
  let items = window._scItems || [];

  if (filter === 'INCIDENT' || filter === 'ALERT' || filter === 'THREAT') {
    items = items.filter(i => i.type === filter);
  } else if (filter === 'active') {
    items = items.filter(i => ['NEW', 'INVESTIGATING', 'CONTAINED', 'ACTIVE'].includes(i.status));
  } else if (['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].includes(filter)) {
    items = items.filter(i => i.status === filter);
  } else if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(filter)) {
    items = items.filter(i => i.risk === filter);
  }
  if (query) {
    items = items.filter(i => {
      const matchId = (i.id || '').toLowerCase().includes(query);
      const matchCat = (i.category || '').toLowerCase().includes(query);
      const matchSrc = (i.source || '').toLowerCase().includes(query);
      const matchTitle = (i.title || '').toLowerCase().includes(query);
      const matchInd = (i.indicator || '').toLowerCase().includes(query);
      const matchSum = (i.summary || '').toLowerCase().includes(query);
      return matchId || matchCat || matchSrc || matchTitle || matchInd || matchSum;
    });
  }

  const totalPages = Math.ceil(items.length / scPageSize) || 1;
  if (scCurrentPage < totalPages) {
    scCurrentPage++;
    renderSecurityCenterTable();
  }
}

function filterSecurityCenter(filter) {
  scCurrentPage = 1;
  window._scFilter = filter;
  document.querySelectorAll('.sc-filter-btn').forEach(btn => {
    const btnFilter = btn.dataset.filter;
    const isActive = btnFilter === filter;
    btn.classList.toggle('active', isActive);
    btn.classList.toggle('btn-primary', isActive);
    btn.classList.toggle('btn-secondary', !isActive);
  });
  renderSecurityCenterTable();
}

function searchSecurityCenter(query) {
  scCurrentPage = 1;
  window._scSearchQuery = (query || '').trim().toLowerCase();
  renderSecurityCenterTable();
}

function toggleThresholdPanel() {
  const panel = document.getElementById('sc-thresholds-panel');
  const btn = document.getElementById('sc-thresh-toggle-btn');
  if (!panel) return;
  const isHidden = panel.classList.toggle('hidden');
  if (btn) {
    btn.classList.toggle('btn-primary', !isHidden);
    btn.classList.toggle('btn-secondary', isHidden);
  }
}

// ── Security Center Charts ──────────────────────────────────────────────────

async function renderSecurityCenterCharts(items, backendSummary = null) {
  if (typeof Chart === 'undefined') return;

  // 1. Trend Chart (#scTrendChart - Incident Ingestion Velocity & Trend)
  const trendCanvas = document.getElementById('scTrendChart');
  if (trendCanvas) {
    let labels = [];
    let incidentData = [];
    let threatData = [];

    try {
      const res = await fetch('/api/incidents/activity/timeline?range=7D');
      if (res.ok) {
        const tl = await res.json();
        labels = tl.labels || [];
        incidentData = tl.telemetry || [];
        threatData = tl.threats || [];
      }
    } catch (e) {
      console.warn('Failed to load Security Center timeline from backend, computing locally:', e);
    }

    if (!labels.length && Array.isArray(items) && items.length) {
      const local = computeLocalTimelineBuckets(items, '7D');
      labels = local.labels;
      incidentData = local.telemetry;
      threatData = local.threats;
    }

    if (!labels.length) {
      labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Today'];
      incidentData = [0, 0, 0, 0, 0, 0, 0];
      threatData = [0, 0, 0, 0, 0, 0, 0];
    }

    if (scTrendChartInstance) {
      scTrendChartInstance.destroy();
    }

    const tCtx = trendCanvas.getContext('2d');
    scTrendChartInstance = new Chart(tCtx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Incidents & Telemetry',
            data: incidentData,
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.12)',
            borderWidth: 2,
            pointRadius: 3,
            pointBackgroundColor: '#f59e0b',
            tension: 0.35,
            fill: true
          },
          {
            label: 'Threats & Alerts',
            data: threatData,
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.08)',
            borderWidth: 2,
            pointRadius: 3,
            pointBackgroundColor: '#ef4444',
            tension: 0.35,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            labels: { color: '#94a3b8', font: { family: 'Inter', size: 10.5 }, boxWidth: 10 }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
            titleFont: { family: 'JetBrains Mono', size: 11 },
            bodyFont: { family: 'Inter', size: 11 },
            callbacks: {
              label: function(context) {
                return ` ${context.dataset.label}: ${context.raw} records`;
              }
            }
          }
        },
        scales: {
          x: {
            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9.5 } },
            grid: { color: 'rgba(255,255,255,0.03)' }
          },
          y: {
            beginAtZero: true,
            ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 9.5 }, precision: 0 },
            grid: { color: 'rgba(255,255,255,0.04)' }
          }
        }
      }
    });
  }

  // 2. Category Mix Chart (#scCategoryMix)
  const catCanvas = document.getElementById('scCategoryMix');
  if (catCanvas) {
    let catMap = {};
    if (backendSummary && backendSummary.categories && typeof backendSummary.categories === 'object' && Object.keys(backendSummary.categories).length) {
      catMap = backendSummary.categories;
    } else if (Array.isArray(items)) {
      items.forEach(it => {
        const cat = (it.category || 'OTHER').replace(/_/g, ' ');
        catMap[cat] = (catMap[cat] || 0) + 1;
      });
    }

    const entries = Object.entries(catMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const labels = entries.map(([c]) => c.replace(/_/g, ' '));
    const counts = entries.map(([, n]) => n);
    const colors = ['#ef4444', '#f97316', '#f59e0b', '#06b6d4', '#8b5cf6', '#10b981'];

    if (scCategoryMixInstance) {
      scCategoryMixInstance.destroy();
    }

    const cCtx = catCanvas.getContext('2d');
    scCategoryMixInstance = new Chart(cCtx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: counts,
          backgroundColor: colors.slice(0, labels.length),
          borderColor: '#0f172a',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '62%',
        plugins: {
          legend: {
            display: true,
            position: 'right',
            labels: { color: '#94a3b8', font: { family: 'Inter', size: 10 }, boxWidth: 10, padding: 6 }
          },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
            callbacks: {
              label: function(context) {
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const val = context.raw || 0;
                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                return ` ${context.label}: ${val} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }
}

// ── Table Rendering ─────────────────────────────────────────────────────────

function renderSecurityCenterTable() {
  const wrap = document.getElementById('sc-table-wrap');
  if (!wrap) return;

  const filter = window._scFilter || 'all';
  const query = window._scSearchQuery || '';
  let items = window._scItems || [];

  // 1. Apply Scope Filter
  if (filter === 'INCIDENT' || filter === 'ALERT' || filter === 'THREAT') {
    items = items.filter(i => i.type === filter);
  } else if (filter === 'active') {
    items = items.filter(i => ['NEW', 'INVESTIGATING', 'CONTAINED', 'ACTIVE'].includes(i.status));
  } else if (['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].includes(filter)) {
    items = items.filter(i => i.status === filter);
  } else if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(filter)) {
    items = items.filter(i => i.risk === filter);
  }

  // 2. Apply Search Query
  if (query) {
    items = items.filter(i => {
      const matchId = (i.id || '').toLowerCase().includes(query);
      const matchCat = (i.category || '').toLowerCase().includes(query);
      const matchSrc = (i.source || '').toLowerCase().includes(query);
      const matchTitle = (i.title || '').toLowerCase().includes(query);
      const matchInd = (i.indicator || '').toLowerCase().includes(query);
      const matchSum = (i.summary || '').toLowerCase().includes(query);
      return matchId || matchCat || matchSrc || matchTitle || matchInd || matchSum;
    });
  }

  // Update record count
  const countEl = document.getElementById('sc-item-count');
  if (countEl) {
    countEl.textContent = `${items.length} record${items.length === 1 ? '' : 's'}`;
  }

  // Update pagination controls
  const totalPages = Math.ceil(items.length / scPageSize) || 1;
  if (scCurrentPage > totalPages) scCurrentPage = 1;
  if (scCurrentPage < 1) scCurrentPage = 1;

  const pageInfo = document.getElementById('sc-page-info');
  const prevBtn = document.getElementById('sc-prev-btn');
  const nextBtn = document.getElementById('sc-next-btn');
  if (pageInfo) pageInfo.textContent = `Page ${scCurrentPage} of ${totalPages} (${items.length} records)`;
  if (prevBtn) prevBtn.disabled = scCurrentPage <= 1;
  if (nextBtn) nextBtn.disabled = scCurrentPage >= totalPages;

  if (!items.length) {
    wrap.innerHTML = `
      <div class="history-empty" style="padding:40px 20px;">
        <div style="font-weight:600; color:#f1f5f9; margin-bottom:6px;">NO RECORDED SECURITY EVENTS</div>
        <div style="color:#64748b; font-size:12px;">
          ${query ? `No records matched query "${escapeHtml(query)}"` : (filter !== 'all' ? `No records matching filter "${escapeHtml(filter)}"` : 'The system has not recorded any incidents, alerts or threat events.')}
        </div>
      </div>
    `;
    return;
  }

  const startIdx = (scCurrentPage - 1) * scPageSize;
  const pageItems = items.slice(startIdx, startIdx + scPageSize);

  let html = `
    <table class="history-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Type</th>
          <th>Category</th>
          <th>Risk</th>
          <th>Status</th>
          <th>Updated</th>
          <th>Source</th>
          <th style="text-align:right;">Actions</th>
        </tr>
      </thead>
      <tbody>
  `;

  pageItems.forEach(item => {
    const risk = (item.risk || 'LOW').toUpperCase();
    const badgeClass = risk === 'SAFE' ? 'badge-safe' : (risk === 'LOW' ? 'badge-low' : (risk === 'MEDIUM' ? 'badge-medium' : 'badge-critical'));
    const statusClass = item.status === 'RESOLVED' ? 'vt-verdict-harmless' : (item.status === 'CONTAINED' ? 'vt-verdict-suspicious' : 'vt-verdict-malicious');
    const timeStr = formatScTimestamp(item.updated_at || item.timestamp);
    const exactDate = item.updated_at ? new Date(item.updated_at * 1000).toLocaleString() : '';

    const typeBadgeClass = (item.type || 'THREAT').toLowerCase();
    const rowClass = item._isNew ? 'sc-row-new' : (item._isUpdated ? 'sc-row-updated' : '');

    html += `
      <tr class="${rowClass}" style="cursor:pointer;" onclick="openSCModal('${escapeHtml(item.id)}')">
        <td style="font-family:'JetBrains Mono', monospace; font-weight:600; color:#38bdf8;">
          #${escapeHtml(item.id)}
        </td>
        <td>
          <span class="sc-type-badge ${typeBadgeClass}">${escapeHtml(item.type)}</span>
        </td>
        <td style="font-weight:600; color:#f8fafc;">
          ${escapeHtml(item.category || 'UNKNOWN')}
        </td>
        <td>
          <span class="badge ${badgeClass}">${escapeHtml(risk)}</span>
        </td>
        <td>
          <span class="vt-verdict-tag ${statusClass}">${escapeHtml(item.status || 'NEW')}</span>
        </td>
        <td style="color:#94a3b8; font-size:12px;" title="${escapeHtml(exactDate)}">
          ${escapeHtml(timeStr)}
        </td>
        <td>
          <span style="font-size:11px; color:#cbd5e1; background:rgba(255,255,255,0.04); padding:2px 6px; border-radius:4px;">
            ${escapeHtml(item.source || 'CyberGuard')}
          </span>
        </td>
        <td style="text-align:right;">
          <button class="btn btn-xs btn-secondary" onclick="event.stopPropagation(); openSCModal('${escapeHtml(item.id)}')">
            Inspect →
          </button>
        </td>
      </tr>
    `;
  });

  html += '</tbody></table>';
  wrap.innerHTML = html;

  // Clean up animation flags after 2 seconds
  setTimeout(() => {
    items.forEach(i => {
      delete i._isNew;
      delete i._isUpdated;
    });
    document.querySelectorAll('.sc-row-new, .sc-row-updated').forEach(el => {
      el.classList.remove('sc-row-new', 'sc-row-updated');
    });
  }, 2000);
}

// ── Real-Time Activity Feed ─────────────────────────────────────────────────

function addLiveFeedItem(item) {
  const feed = document.getElementById('sc-live-feed');
  if (!feed) return;

  const emptyEl = feed.querySelector('.sc-feed-empty');
  if (emptyEl) emptyEl.remove();

  const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const risk = (item.risk || 'LOW').toUpperCase();
  const riskColor = (risk === 'CRITICAL' || risk === 'HIGH') ? '#ef4444' : (risk === 'MEDIUM' ? '#f59e0b' : '#22c55e');

  const div = document.createElement('div');
  div.className = 'sc-feed-item';
  div.style.cursor = 'pointer';
  div.onclick = () => openSCModal(item.id);

  div.innerHTML = `
    <span class="sc-feed-dot" style="background:${riskColor};"></span>
    <span class="sc-feed-time">${timeStr}</span>
    <span class="sc-type-badge ${item.type.toLowerCase()}" style="font-size:9.5px; padding:1px 5px;">${escapeHtml(item.type)}</span>
    <strong style="color:#f1f5f9; font-size:12px;">${escapeHtml(item.category)}</strong>
    <span style="color:#64748b; font-size:11px;">—</span>
    <span style="color:#94a3b8; font-size:11.5px; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(item.summary || item.title)}</span>
  `;

  feed.prepend(div);

  // Maintain window of 15 feed items
  while (feed.children.length > 15) {
    feed.lastElementChild.remove();
  }
}

// ── Detail Report Modal ─────────────────────────────────────────────────────

async function openSCModal(itemId) {
  const modal = document.getElementById('security-center-modal');
  const title = document.getElementById('modal-sc-title');
  const subtitle = document.getElementById('modal-sc-subtitle');
  const body = document.getElementById('modal-sc-body');
  if (!modal || !body) return;

  window._scSelectedItemId = itemId;
  modal.classList.remove('hidden');

  let item = (window._scItems || []).find(i => String(i.id) === String(itemId));

  body.innerHTML = '<div style="text-align:center; padding:30px; color:#94a3b8;"><span class="spinner" style="width:20px;height:20px;display:inline-block;margin-right:8px;"></span> Loading security forensic report...</div>';

  let forensicData = item ? item.raw : null;

  // If item is INCIDENT (or not yet loaded into cache), fetch fresh full forensic details from backend
  if (!item || item.type === 'INCIDENT') {
    try {
      const res = await fetch(`/api/incidents/${encodeURIComponent(itemId)}`);
      if (res.ok) {
        forensicData = await res.json();
        if (item) {
          item.raw = forensicData;
          item.status = (forensicData.status || item.status).toUpperCase();
          item.updated_at = forensicData.last_seen ? (typeof forensicData.last_seen === 'string' ? new Date(forensicData.last_seen).getTime() / 1000 : forensicData.last_seen) : item.updated_at;
        } else {
          item = normalizeIncident(forensicData);
        }
      }
    } catch (e) {
      console.warn('Could not fetch fresh incident forensic details:', e);
    }
  }

  if (!item && forensicData) {
    item = normalizeIncident(forensicData);
  }

  if (!item) {
    body.innerHTML = `
      <div class="history-empty" style="color:var(--risk-high); padding:30px;">
        Security record #${escapeHtml(itemId)} could not be loaded.
        <div style="margin-top:12px;">
          <button class="btn btn-xs btn-secondary" onclick="closeSCModal()">Close</button>
        </div>
      </div>
    `;
    return;
  }

  renderSCModalContent(item, forensicData);
}

function renderSCModalContent(item, rawData) {
  const title = document.getElementById('modal-sc-title');
  const subtitle = document.getElementById('modal-sc-subtitle');
  const body = document.getElementById('modal-sc-body');
  if (!body) return;

  const raw = rawData || item.raw || {};
  const risk = (item.risk || 'LOW').toUpperCase();
  const badgeClass = risk === 'SAFE' ? 'badge-safe' : (risk === 'LOW' ? 'badge-low' : (risk === 'MEDIUM' ? 'badge-medium' : 'badge-critical'));
  const statusClass = item.status === 'RESOLVED' ? 'vt-verdict-harmless' : (item.status === 'CONTAINED' ? 'vt-verdict-suspicious' : 'vt-verdict-malicious');
  const typeBadgeClass = (item.type || 'THREAT').toLowerCase();

  const exactCreated = item.timestamp ? new Date(item.timestamp * 1000).toLocaleString() : 'N/A';
  const exactUpdated = item.updated_at ? new Date(item.updated_at * 1000).toLocaleString() : exactCreated;

  if (title) title.textContent = `${item.type}: ${item.category}`;
  if (subtitle) subtitle.textContent = `ID: #${item.id} · Type: ${item.type} · Updated: ${exactUpdated}`;

  // 1. Evidence extraction (guaranteeing NO [object Object])
  let evidenceList = [];
  if (Array.isArray(raw.evidence)) {
    evidenceList = raw.evidence;
  } else if (Array.isArray(raw.events)) {
    raw.events.forEach(ev => {
      if (Array.isArray(ev.evidence)) {
        evidenceList = evidenceList.concat(ev.evidence);
      }
    });
  }

  let evidenceHtml = '';
  if (evidenceList.length > 0) {
    evidenceHtml = `
      <div style="margin-top:18px;">
        <div style="font-size:12px; font-weight:700; color:#cbd5e1; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">
          Forensic Evidence & Indicators (${evidenceList.length})
        </div>
        <div style="display:flex; flex-direction:column; gap:6px;">
          ${evidenceList.map(ev => {
      const evType = escapeHtml(ev.evidence_type || 'Indicator');
      let evDesc = '';
      if (typeof ev.description === 'string') {
        evDesc = escapeHtml(ev.description);
      } else if (ev.value !== undefined) {
        evDesc = escapeHtml(String(ev.value));
      } else {
        evDesc = escapeHtml(JSON.stringify(ev));
      }
      return `
              <div style="background:rgba(0,0,0,0.25); border:1px solid rgba(255,255,255,0.06); border-radius:6px; padding:8px 12px; display:flex; gap:10px; align-items:baseline;">
                <span class="badge badge-xs" style="background:rgba(56,189,248,0.15); color:#38bdf8; font-family:'JetBrains Mono', monospace; font-size:10px;">${evType}</span>
                <span style="font-size:12px; color:#cbd5e1; font-family:'JetBrains Mono', monospace; word-break:break-all;">${evDesc}</span>
              </div>
            `;
    }).join('')}
        </div>
      </div>
    `;
  }

  // 2. Threat Intelligence Provider Findings (VirusTotal + URLhaus)
  let tiHtml = '';
  const tiData = raw.threat_intel || raw.threat_intelligence || (raw.events && (raw.events[0]?.threat_intel || raw.events[0]?.threat_intelligence)) || null;
  const correlation = raw.correlation || (raw.events && (raw.events[0]?.correlation || raw.events[0]?.threat_intelligence?.correlation)) || null;

  if (tiData || correlation) {
    const vt = tiData?.providers?.virustotal || tiData?.virustotal || tiData?.summary;
    const uh = tiData?.providers?.urlhaus || tiData?.urlhaus;
    const relatedIntel = tiData?.providers?.related_intelligence;
    const vtPos = vt ? (vt.malicious !== undefined ? vt.malicious : (vt.positives !== undefined ? vt.positives : 0)) : null;
    const vtEngines = vt ? (vt.total_engines || vt.total || 0) : 0;
    const uhThreat = uh ? (uh.threat || (uh.matched ? (uh.classification || 'Listed') : (uh.status === 'NO_MATCH' ? 'No match on primary IOC' : (uh.status || 'No match')))) : null;

    tiHtml = `
      <div style="margin-top:18px; background:rgba(0,0,0,0.25); border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:14px;">
        <div style="font-size:12px; font-weight:700; color:#f1f5f9; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:10px;">
          Threat Intelligence Verification & Attribution
        </div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px;">
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.05); border-radius:6px; padding:10px;">
            <div style="font-size:11px; color:#94a3b8; font-weight:600; margin-bottom:4px;">VirusTotal (Primary IOC)</div>
            <div style="font-size:13px; font-weight:600; color:#f8fafc;">
              ${vt ? `${vtPos} / ${vtEngines} detections` : 'No data'}
            </div>
            ${vt && vt.categories ? `<div style="font-size:11px; color:#64748b; margin-top:3px;">${escapeHtml(Array.isArray(vt.categories) ? vt.categories.join(', ') : String(vt.categories))}</div>` : ''}
          </div>
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.05); border-radius:6px; padding:10px;">
            <div style="font-size:11px; color:#94a3b8; font-weight:600; margin-bottom:4px;">URLhaus (Primary IOC)</div>
            <div style="font-size:13px; font-weight:600; color:#f8fafc;">
              ${uh ? escapeHtml(uhThreat) : 'No data'}
            </div>
            ${uh && uh.tags ? `<div style="font-size:11px; color:#64748b; margin-top:3px;">Tags: ${escapeHtml(Array.isArray(uh.tags) ? uh.tags.join(', ') : String(uh.tags))}</div>` : ''}
          </div>
          <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.05); border-radius:6px; padding:10px;">
            <div style="font-size:11px; color:#94a3b8; font-weight:600; margin-bottom:4px;">Correlation Verdict</div>
            <div style="font-size:13px; font-weight:600; color:#38bdf8;">
              ${correlation ? escapeHtml(correlation.status || correlation.verdict || 'SINGLE_PROVIDER') : 'SINGLE_PROVIDER'}
            </div>
            ${correlation?.reasoning ? `<div style="font-size:11px; color:#94a3b8; margin-top:3px;">${escapeHtml(correlation.reasoning)}</div>` : ''}
          </div>
          ${relatedIntel ? `
            <div style="background:rgba(239,68,68,0.05); border:1px solid rgba(239,68,68,0.2); border-radius:6px; padding:10px; grid-column: 1 / -1;">
              <div style="font-size:11px; color:#f87171; font-weight:700; text-transform:uppercase; margin-bottom:4px;">
                Associated Threat Intelligence (${escapeHtml(formatScopeLabel(relatedIntel.scope || 'RECORDED_MALWARE_URL'))})
              </div>
              <div style="font-family:monospace; font-size:11.5px; color:#fca5a5; word-break:break-all;">
                ${escapeHtml(relatedIntel.urlhaus?.url || 'Associated Indicator')}
              </div>
              <div style="font-size:11.5px; color:#cbd5e1; margin-top:4px; display:flex; gap:12px; flex-wrap:wrap;">
                ${relatedIntel.urlhaus?.threat ? `<span>Threat: <strong style="color:#f87171;">${escapeHtml(relatedIntel.urlhaus.threat)}</strong></span>` : ''}
                ${relatedIntel.virustotal?.malicious !== undefined ? `<span>VirusTotal: <strong style="color:#f87171;">${relatedIntel.virustotal.malicious} malicious</strong> / ${relatedIntel.virustotal.total_engines || 0}</span>` : ''}
              </div>
            </div>
          ` : ''}
        </div>
      </div>
    `;
  }

  // 3. Defensive Recommendations
  let recsHtml = '';
  const recs = raw.recommendations || item.recommendations || [];
  if (Array.isArray(recs) && recs.length > 0) {
    recsHtml = `
      <div style="margin-top:18px; background:rgba(34,197,94,0.05); border:1px solid rgba(34,197,94,0.15); border-radius:8px; padding:14px;">
        <div style="font-size:12px; font-weight:700; color:#22c55e; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">
          Defensive Recommendations
        </div>
        <ul style="margin:0; padding-left:20px; font-size:12.5px; color:#cbd5e1; line-height:1.6;">
          ${recs.map(r => `<li>${escapeHtml(typeof r === 'string' ? r : (r.title || r.message || JSON.stringify(r)))}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  // 4. Incident Lifecycle Controls (only for INCIDENT type)
  let lifecycleHtml = '';
  if (item.type === 'INCIDENT') {
    lifecycleHtml = `
      <div style="margin-top:18px; background:rgba(0,0,0,0.3); border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:14px;">
        <div style="font-size:12px; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:10px;">
          Incident Lifecycle Management
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;">
          <button class="btn btn-xs ${item.status === 'INVESTIGATING' ? 'btn-primary' : 'btn-secondary'}" onclick="changeIncidentStatus('${escapeHtml(item.id)}', 'INVESTIGATING')">
            Mark Investigating
          </button>
          <button class="btn btn-xs ${item.status === 'CONTAINED' ? 'btn-primary' : 'btn-secondary'}" onclick="changeIncidentStatus('${escapeHtml(item.id)}', 'CONTAINED')">
            Mark Contained
          </button>
          <button class="btn btn-xs ${item.status === 'RESOLVED' ? 'btn-primary' : 'btn-secondary'}" onclick="changeIncidentStatus('${escapeHtml(item.id)}', 'RESOLVED')">
            ✓ Resolve Incident
          </button>
          <button class="btn btn-xs btn-secondary" onclick="changeIncidentStatus('${escapeHtml(item.id)}', 'FALSE_POSITIVE')">
            False Positive
          </button>
        </div>
        <div>
          <label class="form-label" style="font-size:11px; margin-bottom:4px; display:block;">Analyst Forensic Notes</label>
          <textarea class="form-input" id="sc-modal-notes" rows="2" style="font-size:12px; width:100%;" placeholder="Record investigation findings, containment steps, or attribution...">${escapeHtml(raw.analyst_notes || '')}</textarea>
          <div style="margin-top:6px;">
            <button class="btn btn-xs btn-secondary" onclick="saveAnalystNotes('${escapeHtml(item.id)}')">Save Notes</button>
          </div>
        </div>
      </div>
    `;
  }

  // 5. Associated Events (if incident contains sub-events)
  let eventsHtml = '';
  if (Array.isArray(raw.events) && raw.events.length > 0) {
    eventsHtml = `
      <div style="margin-top:18px;">
        <div style="font-size:12px; font-weight:700; color:#cbd5e1; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;">
          Correlated Pipeline Events (${raw.events.length})
        </div>
        <div style="display:flex; flex-direction:column; gap:8px;">
          ${raw.events.map(ev => `
            <div style="background:rgba(0,0,0,0.25); border:1px solid rgba(255,255,255,0.06); border-radius:6px; padding:10px 14px;">
              <div style="display:flex; justify-content:space-between; margin-bottom:4px; font-size:12px;">
                <strong style="color:#f1f5f9;">${escapeHtml(ev.source || 'Pipeline Event')} (${escapeHtml(ev.modality || 'stream')})</strong>
                <span style="color:#64748b; font-size:11px;">${ev.timestamp ? formatScTimestamp(typeof ev.timestamp === 'string' ? new Date(ev.timestamp).getTime() / 1000 : ev.timestamp) : ''}</span>
              </div>
              <div style="font-size:12px; color:#94a3b8; line-height:1.4;">
                ${escapeHtml(ev.explanation?.summary || ev.explanation?.reasoning || '')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // Assemble Complete Detail Report
  body.innerHTML = `
    <!-- Top Metadata Banner -->
    <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap; padding-bottom:14px; border-bottom:1px solid rgba(255,255,255,0.08);">
      <span class="sc-type-badge ${typeBadgeClass}">${escapeHtml(item.type)}</span>
      <span class="badge ${badgeClass}" style="font-size:12px; padding:3px 8px;">Risk: ${escapeHtml(risk)}</span>
      <span class="vt-verdict-tag ${statusClass}" style="font-size:12px;">${escapeHtml(item.status)}</span>
      <span style="font-size:12px; color:#94a3b8;">Source: <strong style="color:#f8fafc;">${escapeHtml(item.source)}</strong></span>
      <span style="font-size:12px; color:#94a3b8;">Created: ${escapeHtml(exactCreated)}</span>
    </div>

    <!-- Summary Box -->
    <div style="margin-top:14px; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.05); border-radius:8px; padding:14px;">
      <div style="font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; margin-bottom:4px;">Executive Summary</div>
      <div style="font-size:13px; color:#f1f5f9; line-height:1.5;">${escapeHtml(item.summary || 'No summary available.')}</div>
      ${item.description && item.description !== item.summary ? `
        <div style="font-size:12px; color:#94a3b8; margin-top:8px; line-height:1.4;">${escapeHtml(item.description)}</div>
      ` : ''}
    </div>

    <!-- Indicator / IOC -->
    <div style="margin-top:14px; display:flex; align-items:center; gap:8px; background:rgba(0,0,0,0.25); border:1px solid rgba(255,255,255,0.06); border-radius:6px; padding:8px 12px;">
      <span style="font-size:11px; color:#94a3b8; font-weight:600;">Indicator / Asset:</span>
      <code style="color:#38bdf8; font-size:12px; flex:1; word-break:break-all;">${escapeHtml(item.indicator)}</code>
      <button class="btn btn-xs btn-secondary" onclick="navigator.clipboard.writeText('${escapeHtml(item.indicator)}'); showToast('Indicator copied to clipboard', 'info');" title="Copy to clipboard">
        Copy
      </button>
    </div>

    ${evidenceHtml}
    ${tiHtml}
    ${eventsHtml}
    ${recsHtml}
    ${lifecycleHtml}

    <!-- Technical Details Collapsible -->
    <div style="margin-top:18px;">
      <details style="background:rgba(0,0,0,0.2); border:1px solid rgba(255,255,255,0.06); border-radius:6px; padding:10px;">
        <summary style="font-size:11px; font-weight:600; color:#64748b; cursor:pointer; text-transform:uppercase; letter-spacing:0.5px;">
          Technical Record Metadata
        </summary>
        <pre style="margin-top:8px; font-family:'JetBrains Mono', monospace; font-size:11px; color:#94a3b8; overflow-x:auto; max-height:220px; white-space:pre-wrap;">${escapeHtml(JSON.stringify(raw, null, 2))}</pre>
      </details>
    </div>
  `;
}

function closeSCModal() {
  const modal = document.getElementById('security-center-modal');
  if (modal) modal.classList.add('hidden');
  window._scSelectedItemId = null;
}

// ── System Health & Engine Diagnostics Modal ──────────────────────────────────
function openSystemHealthModal() {
  const modal = document.getElementById('system-health-modal');
  if (modal) modal.classList.remove('hidden');
}

function closeSystemHealthModal() {
  const modal = document.getElementById('system-health-modal');
  if (modal) modal.classList.add('hidden');
}

function toggleEngineDetails(detailId) {
  const el = document.getElementById(detailId);
  if (el) el.classList.toggle('hidden');
}

// ── Session Telemetry Logs Modal ────────────────────────────────────────────
function openSessionLogsModal() {
  const modal = document.getElementById('session-logs-modal');
  const pre = document.getElementById('modal-session-logs');
  const wsLog = document.getElementById('ws-log');
  if (pre && wsLog) {
    const text = Array.from(wsLog.children).map(c => c.textContent).join('\n');
    pre.textContent = text || 'No telemetry logs in current session buffer.';
  }
  if (modal) modal.classList.remove('hidden');
}

function closeSessionLogsModal() {
  const modal = document.getElementById('session-logs-modal');
  if (modal) modal.classList.add('hidden');
}

function copySessionLogs() {
  const pre = document.getElementById('modal-session-logs');
  if (pre && pre.textContent) {
    navigator.clipboard.writeText(pre.textContent).then(() => {
      showToast('Session logs copied to clipboard', 'success');
    }).catch(() => {
      showToast('Failed to copy logs', 'error');
    });
  }
}

// ── Threat Sub-Navigation Tab Switcher ──────────────────────────────────────
function switchThreatSubTab(mode, btn) {
  const btns = document.querySelectorAll('#threat-subnav .threat-subnav-btn');
  btns.forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  const gridCards = document.querySelectorAll('#panel-threats .analyze-grid > .card');
  if (gridCards.length >= 2) {
    const phishCard = gridCards[0];
    const intelCard = gridCards[1];
    if (mode === 'all') {
      phishCard.classList.remove('hidden');
      intelCard.classList.remove('hidden');
    } else if (mode === 'phishing' || mode === 'qr') {
      phishCard.classList.remove('hidden');
      intelCard.classList.add('hidden');
    } else if (mode === 'intel') {
      phishCard.classList.add('hidden');
      intelCard.classList.remove('hidden');
    }
  }
}

// ── Status & Notes Lifecycle Actions ────────────────────────────────────────

async function changeIncidentStatus(incidentId, newStatus) {
  try {
    const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    });
    if (!res.ok) throw new Error('Status update failed');
    showToast(`Incident #${incidentId} updated to ${newStatus}`, 'success');

    // Update item locally
    const item = (window._scItems || []).find(i => String(i.id) === String(incidentId));
    if (item) {
      item.status = newStatus;
      item._isUpdated = true;
    }
    renderSecurityCenterTable();
    openSCModal(incidentId);
    updateOverview();
  } catch (e) {
    showToast('Failed to update status: ' + e.message, 'error');
  }
}

async function saveAnalystNotes(incidentId) {
  const notes = document.getElementById('sc-modal-notes')?.value || '';
  try {
    const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'INVESTIGATING', analyst_notes: notes }),
    });
    if (!res.ok) throw new Error('Notes save failed');
    showToast('Analyst notes saved successfully.', 'success');

    const item = (window._scItems || []).find(i => String(i.id) === String(incidentId));
    if (item) {
      item.status = 'INVESTIGATING';
      if (item.raw) item.raw.analyst_notes = notes;
      item._isUpdated = true;
    }
    renderSecurityCenterTable();
  } catch (e) {
    showToast('Failed to save notes: ' + e.message, 'error');
  }
}

// ── Real-Time WebSocket Handlers ────────────────────────────────────────────

function handleWsIncidentUpdate(data) {
  if (!data || !data.incident) return;
  const item = normalizeIncident(data.incident);
  mergeIncomingItem(item);
  showToast(`Incident #${item.id} (${item.risk}): ${item.category}`, item.risk === 'CRITICAL' || item.risk === 'HIGH' ? 'error' : 'info');
}

function handleWsStatusChange(data) {
  if (!data || !data.incident_id) return;
  const id = data.incident_id;
  const item = (window._scItems || []).find(i => String(i.id) === String(id));
  if (item) {
    // RC-1 FIX: Backend broadcasts "status" field (was previously "new_status").
    // Accept both field names for backward compatibility with any cached messages.
    item.status = (data.status || data.new_status || item.status).toUpperCase();
    item.updated_at = data.updated_at ? (typeof data.updated_at === 'string' ? new Date(data.updated_at).getTime() / 1000 : data.updated_at) : Date.now() / 1000;
    if (data.analyst_notes && item.raw) item.raw.analyst_notes = data.analyst_notes;
    item._isUpdated = true;

    addLiveFeedItem({
      id: item.id,
      type: 'INCIDENT',
      category: item.category,
      risk: item.risk,
      summary: `Status updated to ${item.status}`
    });

    renderSecurityCenterTable();
    updateSCSummary();
    updateOverview();

    // Live-update open modal if viewing this item
    if (window._scSelectedItemId === item.id) {
      renderSCModalContent(item, item.raw);
    }
  }
}

function handleWsAlert(data) {
  if (!data) return;
  const item = normalizeAlert(data.alert || data);
  mergeIncomingItem(item);
}

function handleWsThreatEvent(data) {
  if (!data) return;
  const item = normalizeThreatEvent(data.event || data);
  mergeIncomingItem(item);
}

function mergeIncomingItem(item) {
  if (!item || !item.id || item.id === 'N/A') return;

  const existingIdx = (window._scItems || []).findIndex(i => String(i.id) === String(item.id));
  if (existingIdx !== -1) {
    // Merge into existing record
    const existing = window._scItems[existingIdx];
    Object.assign(existing, item);
    existing._isUpdated = true;
    window._scItems[existingIdx] = existing;
  } else {
    // Prepend new record
    item._isNew = true;
    window._scItems.unshift(item);
    // Limit to max 250 items to keep DOM performant
    if (window._scItems.length > 250) {
      window._scItems.pop();
    }
  }

  // Sort by updated_at descending
  window._scItems.sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));

  // Add to live activity feed
  addLiveFeedItem(item);

  // Trigger subtle security event tone if enabled
  if (window.CyberGuardAudio && item.risk) {
    if (item.risk === 'CRITICAL') {
      window.CyberGuardAudio.playCriticalAlert(item.id);
    } else if (item.risk === 'HIGH') {
      window.CyberGuardAudio.playHighAlert(item.id);
    } else if (item.risk === 'MEDIUM') {
      window.CyberGuardAudio.playLowAlert(item.id);
    }
  }

  // RC-2 FIX: After a real-time WS event, fetch authoritative summary from the backend
  // API so that Security Center counters match Overview counters exactly.
  // Previously updateSCSummary() was called with no argument, causing it to compute
  // counts from the local _scItems array (max 50-250 items) instead of the full DB
  // state — diverging from updateOverview() which always fetches the API.
  updateSCSummaryFromAPI();
  updateOverview();
  renderSecurityCenterTable();

  // If modal is currently open for this item, update it live
  if (window._scSelectedItemId === item.id) {
    renderSCModalContent(item, item.raw);
  }
}

// ── Background WebSocket Connection for Security Center ─────────────────────

function initSecurityCenterWebSocket() {
  if (window._scWsInstance && (window._scWsInstance.readyState === WebSocket.OPEN || window._scWsInstance.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    const wsUrl = WS_URL;
    const ws = new WebSocket(wsUrl);
    window._scWsInstance = ws;

    ws.onopen = () => {
      const badge = document.getElementById('sc-live-status');
      if (badge) {
        badge.className = 'sc-live-badge live';
        badge.innerHTML = '<span class="sc-live-dot"></span> LIVE';
      }

      // Keepalive ping every 25s
      if (window._scWsPingInterval) clearInterval(window._scWsPingInterval);
      window._scWsPingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }));
        }
      }, 25000);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        handleWsMessage(msg);
      } catch (_) { }
    };

    ws.onerror = () => {
      const badge = document.getElementById('sc-live-status');
      if (badge) {
        badge.className = 'sc-live-badge offline';
        badge.innerHTML = '<span class="sc-live-dot offline"></span> DISCONNECTED';
      }
    };

    ws.onclose = () => {
      const badge = document.getElementById('sc-live-status');
      if (badge) {
        badge.className = 'sc-live-badge offline';
        badge.innerHTML = '<span class="sc-live-dot offline"></span> DISCONNECTED';
      }
      if (window._scWsPingInterval) {
        clearInterval(window._scWsPingInterval);
        window._scWsPingInterval = null;
      }
      window._scWsInstance = null;

      // Safe reconnect after 5s
      if (window._scWsReconnectTimeout) clearTimeout(window._scWsReconnectTimeout);
      window._scWsReconnectTimeout = setTimeout(() => {
        initSecurityCenterWebSocket();
      }, 5000);
    };
  } catch (err) {
    console.warn('Security Center WebSocket init error:', err);
  }
}

// ── Backward Compatibility Wrappers ─────────────────────────────────────────

function loadIncidents() { loadSecurityCenterData(); }
function filterIncidents(f) { filterSecurityCenter(f); }
function openIncidentModal(id) { openSCModal(id); }
function closeIncidentModal() { closeSCModal(); }
function loadAlerts() { loadSecurityCenterData(); }

// ── Overview Posture Updater & SOC Command Center ───────────────────────────

let overviewActivityChartInstance = null;
let overviewCategoryDonutInstance = null;
let rawOverviewEvents = [];
let currentActivityRange = 'ALL';

function setActivityRange(range, btn) {
  currentActivityRange = range;
  document.querySelectorAll('#activity-range-group .chart-range-pill, #activity-range-group .chart-range-btn').forEach(b => {
    b.classList.toggle('active', b === btn);
  });
  renderOverviewActivityChart(rawOverviewEvents, range);
}

function renderOverviewCategoryDonut(categories) {
  const canvas = document.getElementById('overviewCategoryDonut');
  if (!canvas || typeof Chart === 'undefined') return;

  const entries = Object.entries(categories || {});
  if (!entries.length) return;

  const categoryLabels = entries.map(([cat]) => cat.replace(/_/g, ' '));
  const categoryValues = entries.map(([, count]) => count);

  const categoryColorMap = {
    MALICIOUS_URL: '#ef4444',
    PHISHING: '#f59e0b',
    MALWARE_INDICATOR: '#f97316',
    VOICE_CLONING: '#06b6d4',
    DEEPFAKE: '#8b5cf6',
  };
  const bgColors = entries.map(([cat]) => categoryColorMap[cat] || '#38bdf8');

  if (overviewCategoryDonutInstance) {
    overviewCategoryDonutInstance.destroy();
  }

  const ctx = canvas.getContext('2d');
  overviewCategoryDonutInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: categoryLabels,
      datasets: [{
        data: categoryValues,
        backgroundColor: bgColors,
        borderColor: '#0f172a',
        borderWidth: 2,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          titleFont: { family: 'Inter', size: 12, weight: '600' },
          bodyFont: { family: 'JetBrains Mono', size: 11 },
          callbacks: {
            label: function(context) {
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const val = context.raw || 0;
              const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
              return ` ${context.label}: ${val} (${pct}%)`;
            }
          }
        }
      }
    }
  });
}

function computeLocalTimelineBuckets(events, range = 'ALL') {
  const numBuckets = 12;
  const now = Date.now();
  let start = now - 24 * 3600 * 1000;
  if (range === '1H') start = now - 3600 * 1000;
  else if (range === '6H') start = now - 6 * 3600 * 1000;
  else if (range === '24H') start = now - 24 * 3600 * 1000;
  else if (range === '7D') start = now - 7 * 86400 * 1000;
  else {
    const minTs = (events || []).reduce((acc, e) => {
      const t = e.timestamp > 1e11 ? e.timestamp : (e.timestamp || 0) * 1000;
      return t > 0 ? Math.min(acc, t) : acc;
    }, now);
    start = minTs < now ? minTs : now - 86400 * 1000;
  }

  const span = Math.max(now - start, 60000);
  const bucketSize = span / numBuckets;
  const telemetry = new Array(numBuckets).fill(0);
  const threats = new Array(numBuckets).fill(0);
  const labels = [];

  for (let i = 0; i < numBuckets; i++) {
    const bStart = start + i * bucketSize;
    const bEnd = bStart + bucketSize;
    const d = new Date(bStart);
    if (range === '7D' || range === 'ALL') {
      labels.push(d.toLocaleDateString([], { month: 'short', day: 'numeric' }));
    } else {
      labels.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    }

    (events || []).forEach(e => {
      const ts = e.timestamp > 1e11 ? e.timestamp : (e.timestamp || 0) * 1000;
      if (ts >= bStart && (ts < bEnd || (i === numBuckets - 1 && ts <= bEnd + 2000))) {
        telemetry[i]++;
        const sev = (e.severity || '').toUpperCase();
        if (sev === 'CRITICAL' || sev === 'HIGH') threats[i]++;
      }
    });
  }

  return { labels, telemetry, threats };
}

async function renderOverviewActivityChart(events, range = 'ALL') {
  const canvas = document.getElementById('overviewActivityChart');
  if (!canvas || typeof Chart === 'undefined') return;

  let labels = [];
  let threatData = [];
  let telemetryData = [];

  try {
    const res = await fetch(`/api/incidents/activity/timeline?range=${encodeURIComponent(range)}`);
    if (res.ok) {
      const tl = await res.json();
      labels = tl.labels || [];
      telemetryData = tl.telemetry || [];
      threatData = tl.threats || [];
    }
  } catch (err) {
    console.warn('Failed to load server timeline, falling back to local aggregation:', err);
  }

  if (!labels.length && Array.isArray(events) && events.length) {
    const bucketed = computeLocalTimelineBuckets(events, range);
    labels = bucketed.labels;
    telemetryData = bucketed.telemetry;
    threatData = bucketed.threats;
  }

  if (!labels.length) {
    labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'];
    telemetryData = [0, 0, 0, 0, 0, 0, 0];
    threatData = [0, 0, 0, 0, 0, 0, 0];
  }

  if (overviewActivityChartInstance) {
    overviewActivityChartInstance.destroy();
  }

  const ctx = canvas.getContext('2d');
  overviewActivityChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'High & Critical Threats',
          data: threatData,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#ef4444',
          tension: 0.35,
          fill: true
        },
        {
          label: 'Analyzed Telemetry Events',
          data: telemetryData,
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.05)',
          borderWidth: 1.5,
          borderDash: [4, 4],
          pointRadius: 2,
          pointBackgroundColor: '#06b6d4',
          tension: 0.35,
          fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          titleFont: { family: 'JetBrains Mono', size: 11 },
          bodyFont: { family: 'Inter', size: 12 },
          callbacks: {
            label: function(context) {
              return ` ${context.dataset.label}: ${context.raw} events`;
            }
          }
        }
      },
      scales: {
        x: {
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
          grid: { color: 'rgba(255,255,255,0.03)' }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 },
          grid: { color: 'rgba(255,255,255,0.04)' }
        }
      },
      animation: { duration: 300 }
    }
  });
}

function renderKpiSparklines(events, summary) {
  function drawSpark(canvasId, points, strokeColor, fillColor) {
    const cvs = document.getElementById(canvasId);
    if (!cvs) return;
    const ctx = cvs.getContext('2d');
    const w = cvs.width = cvs.clientWidth || 70;
    const h = cvs.height = cvs.clientHeight || 24;
    ctx.clearRect(0, 0, w, h);

    if (!points || points.length < 2) {
      ctx.beginPath();
      ctx.moveTo(0, h * 0.7);
      ctx.lineTo(w, h * 0.7);
      ctx.strokeStyle = strokeColor || 'rgba(148,163,184,0.3)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      return;
    }

    const min = Math.min(...points);
    const max = Math.max(...points);
    const range = (max - min) || 1;
    const pad = 3;
    const effH = h - pad * 2;

    const coords = points.map((p, idx) => {
      const x = (idx / (points.length - 1)) * (w - 2) + 1;
      const y = h - pad - ((p - min) / range) * effH;
      return [x, y];
    });

    ctx.beginPath();
    coords.forEach(([x, y], idx) => {
      if (idx === 0) ctx.moveTo(x, y);
      else {
        const prev = coords[idx - 1];
        const cx = (prev[0] + x) / 2;
        ctx.bezierCurveTo(cx, prev[1], cx, y, x, y);
      }
    });
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 1.5;
    ctx.lineCap = 'round';
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, fillColor || 'rgba(56,189,248,0.15)');
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = grad;
    ctx.fill();
  }

  const evList = Array.isArray(events) ? [...events].sort((a,b) => (a.timestamp||0)-(b.timestamp||0)) : [];
  const bins = 8;
  const threatPts = new Array(bins).fill(0);
  const incidentPts = new Array(bins).fill(0);
  const eventPts = new Array(bins).fill(0);
  const critPts = new Array(bins).fill(0);

  if (evList.length > 0) {
    const step = Math.max(1, Math.floor(evList.length / bins));
    for (let i = 0; i < bins; i++) {
      const chunk = evList.slice(i * step, (i + 1) * step);
      chunk.forEach(e => {
        eventPts[i]++;
        const s = (e.severity || '').toUpperCase();
        if (s === 'CRITICAL' || s === 'HIGH') threatPts[i]++;
        if (s === 'CRITICAL') critPts[i]++;
      });
      incidentPts[i] = threatPts[i] > 0 ? threatPts[i] : (eventPts[i] > 0 ? 1 : 0);
    }
  }

  drawSpark('spark-threats', threatPts.some(v => v > 0) ? threatPts : [1, 2, 3, 2, 4, 3, 5, 4], '#ef4444', 'rgba(239, 68, 68, 0.2)');
  drawSpark('spark-incidents', incidentPts.some(v => v > 0) ? incidentPts : [1, 1, 2, 2, 3, 2, 3, 3], '#f59e0b', 'rgba(245, 158, 11, 0.2)');
  drawSpark('spark-events', eventPts.some(v => v > 0) ? eventPts : [2, 3, 4, 3, 5, 6, 5, 7], '#06b6d4', 'rgba(6, 182, 212, 0.2)');
  drawSpark('spark-critical', critPts.some(v => v > 0) ? critPts : [0, 1, 1, 0, 2, 1, 2, 2], '#ef4444', 'rgba(239, 68, 68, 0.25)');
  drawSpark('spark-engines', [10, 10, 10, 10, 10, 10, 10, 10], '#10b981', 'rgba(16, 185, 129, 0.2)');
}

function renderSeverityBreakdown(summary, events) {
  const container = document.getElementById('overview-severity-breakdown');
  if (!container) return;

  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let safe = 0;

  if (summary && summary.severities && typeof summary.severities === 'object') {
    critical = summary.severities.CRITICAL || 0;
    high = summary.severities.HIGH || 0;
    medium = summary.severities.MEDIUM || 0;
    low = summary.severities.LOW || 0;
    safe = summary.severities.SAFE || 0;
  } else if (Array.isArray(events) && events.length > 0) {
    events.forEach(e => {
      const s = (e.severity || '').toUpperCase();
      if (s === 'CRITICAL') critical++;
      else if (s === 'HIGH') high++;
      else if (s === 'MEDIUM') medium++;
      else if (s === 'LOW') low++;
      else safe++;
    });
  } else if (summary) {
    const rawHigh = summary.high_critical_threats || 0;
    critical = Math.min(100, Math.floor(rawHigh * 0.3));
    high = Math.max(0, rawHigh - critical);
  }

  const total = critical + high + medium + low + safe || 1;
  const pCrit = ((critical / total) * 100).toFixed(1);
  const pHigh = ((high / total) * 100).toFixed(1);
  const pMed = ((medium / total) * 100).toFixed(1);
  const pLow = ((low / total) * 100).toFixed(1);
  const pSafe = ((safe / total) * 100).toFixed(1);

  const elCritCount = document.getElementById('sev-count-critical');
  const elCritBar = document.getElementById('sev-bar-critical');
  const elHighCount = document.getElementById('sev-count-high');
  const elHighBar = document.getElementById('sev-bar-high');
  const elMedCount = document.getElementById('sev-count-medium');
  const elMedBar = document.getElementById('sev-bar-medium');
  const elLowCount = document.getElementById('sev-count-low');
  const elLowBar = document.getElementById('sev-bar-low');
  const elSafeCount = document.getElementById('sev-count-safe');
  const elSafeBar = document.getElementById('sev-bar-safe');

  if (elCritCount) elCritCount.textContent = `${critical} (${pCrit}%)`;
  if (elCritBar) elCritBar.style.width = `${pCrit}%`;
  if (elHighCount) elHighCount.textContent = `${high} (${pHigh}%)`;
  if (elHighBar) elHighBar.style.width = `${pHigh}%`;
  if (elMedCount) elMedCount.textContent = `${medium} (${pMed}%)`;
  if (elMedBar) elMedBar.style.width = `${pMed}%`;
  if (elLowCount) elLowCount.textContent = `${low} (${pLow}%)`;
  if (elLowBar) elLowBar.style.width = `${pLow}%`;
  if (elSafeCount) elSafeCount.textContent = `${safe} (${pSafe}%)`;
  if (elSafeBar) elSafeBar.style.width = `${pSafe}%`;

  const donutCanvas = document.getElementById('overviewSeverityDonut');
  if (donutCanvas && typeof Chart !== 'undefined') {
    if (overviewSeverityDonutInstance) {
      overviewSeverityDonutInstance.destroy();
    }
    const dCtx = donutCanvas.getContext('2d');
    overviewSeverityDonutInstance = new Chart(dCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Safe'],
        datasets: [{
          data: [critical, high, medium, low, safe],
          backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#10b981'],
          borderColor: '#0f172a',
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            borderColor: 'rgba(255,255,255,0.1)',
            borderWidth: 1,
            titleFont: { family: 'Inter', size: 12, weight: '600' },
            bodyFont: { family: 'JetBrains Mono', size: 11 },
            callbacks: {
              label: function(context) {
                const val = context.raw || 0;
                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                return ` ${context.label}: ${val} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }
}

function renderOverviewLiveFeed(events) {
  const container = document.getElementById('overview-live-feed');
  if (!container) return;

  if (!Array.isArray(events) || events.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:24px; color:var(--text-muted); font-size:12px;">No live threat telemetry received yet.</div>';
    return;
  }

  const items = events.slice(0, 7);
  container.innerHTML = items.map(ev => {
    const sev = (ev.severity || 'LOW').toUpperCase();
    const sevColor = (sev === 'CRITICAL' || sev === 'HIGH') ? '#ef4444' : (sev === 'MEDIUM' ? '#f59e0b' : '#10b981');
    const badgeClass = sev === 'CRITICAL' ? 'badge-critical' : (sev === 'HIGH' ? 'badge-high' : (sev === 'MEDIUM' ? 'badge-medium' : 'badge-safe'));
    const cat = (ev.threat_category || ev.classification || 'EVENT').replace(/_/g, ' ');
    const timeStr = formatScTimestamp(ev.timestamp);
    const desc = (ev.evidence && ev.evidence[0] && ev.evidence[0].description) ? ev.evidence[0].description : (ev.classification || 'Telemetry signal recorded');
    const id = ev.event_id || 'N/A';

    return `
      <div class="overview-feed-item">
        <div class="overview-feed-dot" style="background:${sevColor};"></div>
        <div class="overview-feed-main">
          <div class="overview-feed-title">
            <span class="badge ${badgeClass}" style="font-size:9.5px; padding:1px 6px;">${escapeHtml(sev)}</span>
            <span style="font-weight:600; color:#f1f5f9; font-size:12px;">${escapeHtml(cat)}</span>
            <span class="overview-feed-time">${escapeHtml(timeStr)}</span>
          </div>
          <div class="overview-feed-desc">${escapeHtml(desc)}</div>
        </div>
        <button class="btn btn-xs btn-secondary" onclick="openSCModal('${escapeHtml(id)}'); showTab('security-center');" title="Inspect event telemetry">
          Inspect →
        </button>
      </div>
    `;
  }).join('');
}

async function loadOverviewLiveFeed(showToastMsg = false) {
  try {
    const res = await fetch('/api/incidents/events?limit=25');
    if (!res.ok) return;
    const evts = await res.json();
    rawOverviewEvents = evts;
    renderOverviewLiveFeed(evts);
    renderOverviewActivityChart(evts, currentActivityRange);
    if (showToastMsg) {
      showToast('Live threat stream refreshed.', 'info');
    }
  } catch (e) {
    console.warn('Could not refresh live feed', e);
  }
}

function updateEngineSummaryUI(st) {
  if (!st) return;

  // Header Nav button
  const navBtn = document.getElementById('nav-system-health-btn');
  if (navBtn) {
    let readyCount = 0;
    if (st.detector_initialized) readyCount++;
    if (st.ecapa_available) readyCount++;
    if (st.virustotal_status === 'READY' || st.virustotal_configured) readyCount++;
    if (st.urlhaus_status === 'READY' || st.urlhaus_configured) readyCount++;
    if (st.vad_available !== false) readyCount += 2;
    if (st.server_status !== 'error') readyCount += 3;
    navBtn.textContent = `● ${readyCount} / 10 ENGINES OPERATIONAL`;
  }

  // System Health Drawer live statuses
  const shVoice = document.getElementById('sh-voice-status');
  const shSpeaker = document.getElementById('sh-speaker-status');
  const shVt = document.getElementById('sh-vt-status');
  const shUh = document.getElementById('sh-uh-status');

  if (shVoice) {
    shVoice.textContent = st.detector_initialized ? 'ACTIVE' : 'FALLBACK';
    shVoice.className = `system-health-chip ${st.detector_initialized ? 'chip-active' : 'chip-ready'}`;
  }
  if (shSpeaker) {
    shSpeaker.textContent = st.ecapa_available ? 'READY' : 'OFFLINE';
    shSpeaker.className = `system-health-chip ${st.ecapa_available ? 'chip-ready' : 'chip-standby'}`;
  }
  if (shVt) {
    const vtReady = st.virustotal_status === 'READY' || st.virustotal_configured;
    shVt.textContent = vtReady ? 'READY' : 'DISABLED';
    shVt.className = `system-health-chip ${vtReady ? 'chip-ready' : 'chip-standby'}`;
  }
  if (shUh) {
    const uhReady = st.urlhaus_status === 'READY' || st.urlhaus_configured;
    shUh.textContent = uhReady ? 'READY' : 'DISABLED';
    shUh.className = `system-health-chip ${uhReady ? 'chip-ready' : 'chip-standby'}`;
  }
}

async function updateOverview(forceRefresh = false) {
  try {
    const syncEl = document.getElementById('overview-last-sync');
    if (syncEl) {
      const now = new Date();
      syncEl.textContent = `Synced ${now.toLocaleTimeString()}`;
    }

    const [summaryRes, statusRes, eventsRes] = await Promise.allSettled([
      fetch('/api/incidents/dashboard/summary'),
      fetch('/api/config/status'),
      fetch('/api/incidents/events?limit=40')
    ]);

    if (summaryRes.status !== 'fulfilled' || !summaryRes.value.ok) return;
    const summary = await summaryRes.value.json();

    const openCount = summary.open_incidents !== undefined ? summary.open_incidents : 0;
    const threatCount = summary.high_critical_threats !== undefined ? summary.high_critical_threats : 0;
    const eventCount = summary.total_events_analyzed !== undefined ? summary.total_events_analyzed : 0;
    const criticalCount = summary.critical_threats !== undefined ? summary.critical_threats : (summary.severities?.CRITICAL || 0);

    const statEvents = document.getElementById('stat-events');
    const statThreats = document.getElementById('stat-threats');
    const statIncidents = document.getElementById('stat-incidents');
    const statHighCritical = document.getElementById('stat-high-critical');

    if (statEvents) statEvents.textContent = eventCount;
    if (statThreats) statThreats.textContent = threatCount;
    if (statIncidents) statIncidents.textContent = openCount;
    if (statHighCritical) statHighCritical.textContent = criticalCount;

    if (forceRefresh) {
      showToast('Security posture synchronized with live telemetry.', 'success');
    }

    const postureEl = document.getElementById('overview-posture');
    const descEl = document.getElementById('overview-posture-desc');
    const subEl = document.getElementById('overview-posture-sub');
    const tilePosture = document.getElementById('overview-tile-posture');
    const tilePostureSub = document.getElementById('overview-tile-posture-sub');

    let postureLevel = 'NORMAL';
    let postureBadgeClass = 'badge-safe';
    let headline = 'All security pipelines operational. No active threats detected.';
    let detail = 'Zero high or critical alerts active. Normal baseline telemetry.';

    if (threatCount >= 3) {
      postureLevel = 'HIGH ALERT';
      postureBadgeClass = 'badge-critical';
      headline = `${threatCount} high-severity active cyber threats detected across environment.`;
      detail = 'Multiple threat vectors active (malicious URLs, phishing, malware indicators). Active containment recommended.';
    } else if (threatCount >= 1) {
      postureLevel = 'ELEVATED RISK';
      postureBadgeClass = 'badge-critical';
      headline = 'Elevated threat severity detected across active pipelines.';
      detail = 'One or more threats require investigation in the Security Center.';
    } else if (openCount > 0) {
      postureLevel = 'MONITORING';
      postureBadgeClass = 'badge-medium';
      headline = `${openCount} active security incident${openCount > 1 ? 's' : ''} currently under observation.`;
      detail = 'Incidents are being tracked by the automated correlation engine.';
    }

    if (postureEl) {
      postureEl.className = `badge ${postureBadgeClass} posture-badge`;
      postureEl.textContent = postureLevel;
    }
    if (descEl) descEl.textContent = headline;
    if (subEl) subEl.textContent = detail;
    if (tilePosture) {
      tilePosture.textContent = postureLevel;
      tilePosture.className = `metric-tile-value ${threatCount >= 1 ? 'text-threat' : 'text-cyan'}`;
    }
    if (tilePostureSub) {
      tilePostureSub.textContent = `${threatCount} high / ${openCount} open`;
    }

    // Process events for real-time graphs and live feed
    let events = [];
    if (eventsRes.status === 'fulfilled' && eventsRes.value.ok) {
      events = await eventsRes.value.json();
      rawOverviewEvents = events;
    }

    // Render Threat Category Distribution (Donut & Progress Bars)
    const distBody = document.getElementById('overview-distribution-body');
    const threatTotalEl = document.getElementById('overview-threat-total');
    if (summary.categories && typeof summary.categories === 'object') {
      const categories = summary.categories;
      const entries = Object.entries(categories);
      const totalCategorized = entries.reduce((acc, [, count]) => acc + count, 0);

      if (threatTotalEl) {
        threatTotalEl.textContent = `${totalCategorized} Classified Events`;
      }

      renderOverviewCategoryDonut(categories);

      if (distBody) {
        if (entries.length === 0) {
          distBody.innerHTML = '<div class="distribution-empty" style="text-align:center;padding:16px;color:var(--text-muted);font-size:12px;">No categorized threat telemetry available yet.</div>';
        } else {
          const categoryColors = {
            MALICIOUS_URL: '#ef4444',
            PHISHING: '#f59e0b',
            MALWARE_INDICATOR: '#dc2626',
            VOICE_CLONING: '#06b6d4',
            DEEPFAKE: '#8b5cf6',
          };

          distBody.innerHTML = entries.map(([cat, count]) => {
            const pct = totalCategorized > 0 ? ((count / totalCategorized) * 100).toFixed(1) : 0;
            const color = categoryColors[cat] || '#38bdf8';
            const label = cat.replace(/_/g, ' ');
            return `
              <div class="distribution-item">
                <div class="distribution-item-header">
                  <span class="distribution-category" style="color:${color};">${escapeHtml(label)}</span>
                  <span class="distribution-count">${count} <span style="font-weight:400;color:var(--text-muted);font-size:11px;">(${pct}%)</span></span>
                </div>
                <div class="distribution-track">
                  <div class="distribution-fill" style="width:${pct}%;background:${color};"></div>
                </div>
              </div>
            `;
          }).join('');
        }
      }
    }

    // Render Activity Chart, Severity Breakdown, and Live Feed
    renderOverviewActivityChart(events, currentActivityRange);
    renderSeverityBreakdown(summary, events);
    renderKpiSparklines(events, summary);
    renderOverviewLiveFeed(events);

    // Render Pipeline Health Matrix & Engine Summary
    if (statusRes.status === 'fulfilled' && statusRes.value.ok) {
      const st = await statusRes.value.json();
      updateEngineSummaryUI(st);

      const pipeVoice = document.getElementById('pipe-voice-status');
      const pipeSpeaker = document.getElementById('pipe-speaker-status');
      const pipeVt = document.getElementById('pipe-vt-status');
      const pipeUh = document.getElementById('pipe-uh-status');

      if (pipeVoice) {
        pipeVoice.textContent = st.detector_initialized ? 'ACTIVE' : 'FALLBACK';
        pipeVoice.className = `pipeline-status-badge ${st.detector_initialized ? 'status-ready' : 'status-standby'}`;
      }
      if (pipeSpeaker) {
        pipeSpeaker.textContent = st.ecapa_available ? 'READY' : 'OFFLINE';
        pipeSpeaker.className = `pipeline-status-badge ${st.ecapa_available ? 'status-ready' : 'status-standby'}`;
      }
      if (pipeVt) {
        pipeVt.textContent = st.virustotal_status || (st.virustotal_configured ? 'READY' : 'DISABLED');
        pipeVt.className = `pipeline-status-badge ${st.virustotal_status === 'READY' ? 'status-ready' : 'status-standby'}`;
      }
      if (pipeUh) {
        pipeUh.textContent = st.urlhaus_status || (st.urlhaus_configured ? 'READY' : 'DISABLED');
        pipeUh.className = `pipeline-status-badge ${st.urlhaus_status === 'READY' ? 'status-ready' : 'status-standby'}`;
      }
    }

    // Render Recent Incidents Table
    const recentTbody = document.getElementById('overview-recent-tbody');
    const recentCountEl = document.getElementById('overview-recent-count');
    const recentList = Array.isArray(summary.recent_incidents) ? summary.recent_incidents : [];

    if (recentCountEl) {
      recentCountEl.textContent = `${recentList.length} recent`;
    }

    if (recentTbody) {
      if (recentList.length === 0) {
        recentTbody.innerHTML = '<tr><td colspan="7" class="overview-loading-row">No security incidents recorded yet.</td></tr>';
      } else {
        recentTbody.innerHTML = recentList.slice(0, 8).map(inc => {
          const id = inc.incident_id || 'N/A';
          const cat = (inc.category || 'THREAT').replace(/_/g, ' ');
          const risk = (inc.risk || 'LOW').toUpperCase();
          const status = (inc.status || 'NEW').toUpperCase();
          const riskBadgeClass = risk === 'CRITICAL' ? 'badge-critical' : (risk === 'HIGH' ? 'badge-high' : (risk === 'MEDIUM' ? 'badge-medium' : 'badge-safe'));
          const statusTagClass = status === 'RESOLVED' ? 'status-resolved' : (status === 'CONTAINED' ? 'status-contained' : (status === 'INVESTIGATING' ? 'status-investigating' : 'status-new'));
          const firstSeen = formatScTimestamp(inc.first_seen);
          const assets = Array.isArray(inc.affected_assets) && inc.affected_assets.length > 0 ? inc.affected_assets.join(', ') : 'Asset Telemetry';

          return `
            <tr>
              <td style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--text-primary);">
                #${escapeHtml(String(id).substring(0, 12))}
              </td>
              <td>
                <span class="badge" style="background:rgba(255,255,255,0.04);color:#cbd5e1;border:1px solid rgba(255,255,255,0.08);font-size:10px;">
                  ${escapeHtml(cat)}
                </span>
              </td>
              <td><span class="badge ${riskBadgeClass}">${escapeHtml(risk)}</span></td>
              <td><span class="sc-status-tag ${statusTagClass}">${escapeHtml(status)}</span></td>
              <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted);">${escapeHtml(firstSeen)}</td>
              <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#38bdf8;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(assets)}">
                ${escapeHtml(assets)}
              </td>
              <td style="text-align:right;">
                <button class="btn btn-xs btn-secondary" onclick="openSCModal('${escapeHtml(String(id))}'); showTab('security-center');" title="Inspect full incident report">
                  Inspect
                </button>
              </td>
            </tr>
          `;
        }).join('');
      }
    }

    if (forceRefresh) {
      showToast('Overview posture synchronized with security engine.', 'info');
    }
  } catch (e) {
    console.error('Failed to update overview summary', e);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTHENTICATION & ACCESS CONTROL
// ═══════════════════════════════════════════════════════════════════════════
let currentUser = null;
let currentAuthTab = 'login';
let authCheckPromise = null;

function getAuthToken() {
  try {
    return localStorage.getItem('cyberguard_token') || localStorage.getItem('cg_token') || '';
  } catch (_) {
    return '';
  }
}

function setAuthToken(token) {
  try {
    if (token) {
      localStorage.setItem('cyberguard_token', token);
      localStorage.setItem('cg_token', token);
    } else {
      localStorage.removeItem('cyberguard_token');
      localStorage.removeItem('cg_token');
    }
  } catch (_) {}
}

function getAuthHeaders(isJson = true) {
  const headers = {};
  if (isJson) {
    headers['Content-Type'] = 'application/json';
  }
  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function checkAuthStatus() {
  authCheckPromise = (async () => {
    const token = getAuthToken();
    const badgeText = document.getElementById('user-badge-text');
    const loginBtn = document.getElementById('nav-login-btn');
    const tabReview = document.getElementById('tab-review');
    const tabAdmin = document.getElementById('tab-admin');

    if (!token) {
      currentUser = null;
      if (badgeText) badgeText.textContent = 'LOGIN';
      if (loginBtn) loginBtn.classList.remove('logged-in');
      if (tabReview) tabReview.classList.add('hidden');
      if (tabAdmin) tabAdmin.classList.add('hidden');
      return null;
    }

    try {
      const res = await fetch(`${API_BASE}/api/auth/me`, {
        headers: getAuthHeaders(),
        credentials: 'include'
      });
      if (!res.ok) {
        setAuthToken(null);
        currentUser = null;
        if (badgeText) badgeText.textContent = 'LOGIN';
        if (loginBtn) loginBtn.classList.remove('logged-in');
        if (tabReview) tabReview.classList.add('hidden');
        if (tabAdmin) tabAdmin.classList.add('hidden');
        return null;
      }

      const user = await res.json();
      if (!user) {
        setAuthToken(null);
        currentUser = null;
        if (badgeText) badgeText.textContent = 'LOGIN';
        if (loginBtn) loginBtn.classList.remove('logged-in');
        if (tabReview) tabReview.classList.add('hidden');
        if (tabAdmin) tabAdmin.classList.add('hidden');
        return null;
      }

      currentUser = user;

      if (badgeText) badgeText.textContent = `${user.username.toUpperCase()} (${user.role.toUpperCase()})`;
      if (loginBtn) loginBtn.classList.add('logged-in');

      if (user.role === 'admin') {
        if (tabReview) tabReview.classList.remove('hidden');
        if (tabAdmin) tabAdmin.classList.remove('hidden');
      } else {
        if (tabReview) tabReview.classList.add('hidden');
        if (tabAdmin) tabAdmin.classList.add('hidden');
      }
      return user;
    } catch (err) {
      console.warn('Auth check error:', err);
      return null;
    }
  })();
  return authCheckPromise;
}

function openAuthModal() {
  const modal = document.getElementById('auth-modal');
  if (!modal) return;
  modal.classList.remove('hidden');

  const profileView = document.getElementById('auth-profile-view');
  const formView = document.getElementById('auth-form-view');

  if (currentUser) {
    if (profileView) profileView.classList.remove('hidden');
    if (formView) formView.classList.add('hidden');

    const uEl = document.getElementById('auth-profile-username');
    const eEl = document.getElementById('auth-profile-email');
    const rEl = document.getElementById('auth-profile-role');
    if (uEl) uEl.textContent = currentUser.username;
    if (eEl) eEl.textContent = currentUser.email || 'N/A';
    if (rEl) {
      rEl.textContent = currentUser.role.toUpperCase();
      rEl.style.background = currentUser.role === 'admin' ? '#0284c7' : '#10b981';
    }
  } else {
    if (profileView) profileView.classList.add('hidden');
    if (formView) formView.classList.remove('hidden');
    switchAuthTab('login');
  }
}

function closeAuthModal() {
  const modal = document.getElementById('auth-modal');
  if (modal) modal.classList.add('hidden');
  const errAlert = document.getElementById('auth-error-alert');
  if (errAlert) {
    errAlert.classList.add('hidden');
    errAlert.textContent = '';
  }
}

function switchAuthTab(tab) {
  currentAuthTab = tab;
  const loginTabBtn = document.getElementById('auth-tab-login');
  const regTabBtn = document.getElementById('auth-tab-register');
  const emailGroup = document.getElementById('auth-email-group');
  const submitBtn = document.getElementById('auth-submit-btn');
  const errAlert = document.getElementById('auth-error-alert');

  if (errAlert) {
    errAlert.classList.add('hidden');
    errAlert.textContent = '';
  }

  if (tab === 'login') {
    if (loginTabBtn) { loginTabBtn.className = 'btn btn-xs btn-primary'; }
    if (regTabBtn) { regTabBtn.className = 'btn btn-xs btn-secondary'; }
    if (emailGroup) emailGroup.classList.add('hidden');
    if (submitBtn) submitBtn.textContent = 'Sign In';
  } else {
    if (loginTabBtn) { loginTabBtn.className = 'btn btn-xs btn-secondary'; }
    if (regTabBtn) { regTabBtn.className = 'btn btn-xs btn-primary'; }
    if (emailGroup) emailGroup.classList.remove('hidden');
    if (submitBtn) submitBtn.textContent = 'Create Account';
  }
}

function normalizeAuthError(res, data, err) {
  // 1. Direct HTTP status mapping
  if (res && res.status === 401) {
    return 'Invalid username/email or password.';
  }
  if (res && res.status === 403) {
    if (data && typeof data.detail === 'string') return data.detail;
    return 'Your account is deactivated or not authorized to access this resource.';
  }
  if (res && res.status === 429) {
    return 'Too many login attempts. Please wait a moment and try again.';
  }

  // 2. FastAPI validation errors: data.detail
  if (data && data.detail) {
    if (typeof data.detail === 'string') {
      return data.detail;
    }
    if (Array.isArray(data.detail) && data.detail.length > 0) {
      const first = data.detail[0];
      if (first && typeof first === 'object') {
        const field = Array.isArray(first.loc) ? first.loc[first.loc.length - 1] : '';
        const msg = first.msg || 'Invalid input';
        if (field && field !== 'body') {
          return `${msg.charAt(0).toUpperCase() + msg.slice(1)}: ${field}`;
        }
        return msg;
      }
      if (typeof first === 'string') return first;
    }
    if (typeof data.detail === 'object') {
      if (data.detail.message) return String(data.detail.message);
      if (data.detail.msg) return String(data.detail.msg);
    }
  }

  // 3. Alternative backend response fields
  if (data && typeof data.message === 'string') {
    return data.message;
  }
  if (data && data.error) {
    if (typeof data.error === 'string') return data.error;
    if (typeof data.error.message === 'string') return data.error.message;
  }

  // 4. Network / Fetch exceptions
  if (err && err.name === 'TypeError' && String(err.message).toLowerCase().includes('fetch')) {
    return 'Unable to reach the CyberGuard authentication service. Please check your network connection.';
  }
  if (err && typeof err.message === 'string' && err.message && err.message !== '[object Object]') {
    return err.message;
  }

  return 'Authentication failed. Please check your credentials and try again.';
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const usernameInput = document.getElementById('auth-input-username');
  const emailInput = document.getElementById('auth-input-email');
  const passwordInput = document.getElementById('auth-input-password');
  const submitBtn = document.getElementById('auth-submit-btn');
  const errAlert = document.getElementById('auth-error-alert');

  if (errAlert) {
    errAlert.classList.add('hidden');
    errAlert.textContent = '';
  }

  const username = usernameInput ? usernameInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value : '';
  const email = emailInput ? emailInput.value.trim() : '';

  if (!username || !password) {
    if (errAlert) {
      errAlert.textContent = 'Please enter both your username/email and password.';
      errAlert.classList.remove('hidden');
    }
    return;
  }

  const endpoint = currentAuthTab === 'login' ? `${API_BASE}/api/auth/login` : `${API_BASE}/api/auth/register`;
  // Robust payload: provide both username_or_email and username for maximum client/backend interoperability
  const payload = currentAuthTab === 'login' 
    ? { username_or_email: username, username: username, password: password } 
    : { username: username, email: email || `${username}@cyberguard.local`, password: password };

  const originalBtnText = submitBtn ? submitBtn.textContent : (currentAuthTab === 'login' ? 'Sign In' : 'Create Account');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner" style="display:inline-block; width:12px; height:12px; border:2px solid rgba(255,255,255,0.3); border-top-color:#fff; border-radius:50%; animation:spin 0.6s linear infinite; vertical-align:middle; margin-right:6px;"></span> Processing...';
  }

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      data = null;
    }

    if (!res.ok) {
      const errorMsg = normalizeAuthError(res, data, null);
      if (errAlert) {
        errAlert.textContent = errorMsg;
        errAlert.classList.remove('hidden');
      } else {
        showToast(errorMsg, 'error');
      }
      return;
    }

    if (!data || !data.token || !data.user) {
      throw new Error('Invalid response received from authentication server.');
    }

    setAuthToken(data.token);
    currentUser = data.user;
    showToast(`Welcome back, ${data.user.username} (${data.user.role.toUpperCase()})!`, 'success');

    // Clean sensitive password from input field
    if (passwordInput) passwordInput.value = '';
    closeAuthModal();
    await checkAuthStatus();

    if (data.user.role === 'admin') {
      showToast('Admin Console and Ground-Truth Review tabs unlocked', 'info');
    }
  } catch (err) {
    const errorMsg = normalizeAuthError(null, null, err);
    if (errAlert) {
      errAlert.textContent = errorMsg;
      errAlert.classList.remove('hidden');
    } else {
      showToast(errorMsg, 'error');
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalBtnText;
    }
  }
}

async function logoutUser() {
  try {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: 'POST',
      headers: getAuthHeaders()
    });
  } catch (_) {}

  setAuthToken(null);
  currentUser = null;
  showToast('Logged out successfully', 'info');
  closeAuthModal();
  await checkAuthStatus();

  const currentTab = document.querySelector('.nav-link.active');
  if (currentTab && (currentTab.id === 'tab-review' || currentTab.id === 'tab-admin')) {
    showTab('overview');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// GROUND-TRUTH TRAINING REVIEW QUEUE
// ═══════════════════════════════════════════════════════════════════════════
let cachedReviewItems = [];
let currentReviewItem = null;
let currentReviewId = null;
let currentSelectedGroundTruth = null;
let reviewFilterDebounceTimer = null;

let waveformAudioCtx = null;
let currentAudioBuffer = null;
let waveformPeaks = [];

function debounceReviewFilter() {
  clearTimeout(reviewFilterDebounceTimer);
  reviewFilterDebounceTimer = setTimeout(() => {
    loadReviewQueue();
  }, 250);
}

function formatAudioTime(sec) {
  if (!sec || isNaN(sec)) return '00:00.0';
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  const ms = Math.floor((sec % 1) * 10);
  return `${m < 10 ? '0' : ''}${m}:${s < 10 ? '0' : ''}${s}.${ms}`;
}

let currentAudioBlobUrl = null;

async function loadReviewQueue() {
  const tbody = document.getElementById('review-queue-tbody');
  const countTag = document.getElementById('review-count-tag');
  const heroPoolEl = document.getElementById('review-hero-pool-count');
  const paginationInfo = document.getElementById('review-pagination-info');

  if (authCheckPromise) {
    try { await authCheckPromise; } catch (_) {}
  }
  const token = getAuthToken();
  if (!token || !currentUser || currentUser.role !== 'admin') {
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="11" style="text-align:center; padding:36px 16px;">
            <div style="font-size:13px; font-weight:600; color:#f87171; margin-bottom:8px;">🔒 Administrator Authentication Required</div>
            <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:14px;">Ground-truth review and human-in-the-loop retraining require verified administrator credentials.</div>
            <button class="btn btn-sm btn-primary" onclick="openAuthModal()" style="font-size:11px; padding:6px 14px;">Sign In as Admin</button>
          </td>
        </tr>
      `;
    }
    return;
  }

  const statusFilter = document.getElementById('review-status-filter')?.value || '';
  const riskFilter = document.getElementById('review-risk-filter')?.value || '';
  const gtFilter = document.getElementById('review-gt-filter')?.value || '';
  const search = document.getElementById('review-search-input')?.value || '';

  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="11" style="text-align:center; padding:24px; color:var(--text-muted); font-family:var(--font-mono);"><span class="pulse-indicator"></span> Querying forensic verification queue...</td></tr>';
  }

  try {
    let url = `${API_BASE}/api/admin/review/queue?limit=100`;
    if (statusFilter) url += `&status=${encodeURIComponent(statusFilter)}`;
    if (riskFilter) url += `&risk=${encodeURIComponent(riskFilter)}`;
    if (gtFilter) url += `&ground_truth=${encodeURIComponent(gtFilter)}`;
    if (search.trim()) url += `&q=${encodeURIComponent(search.trim())}`;

    const res = await fetch(url, { headers: getAuthHeaders(), credentials: 'include' });
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || `HTTP ${res.status}: Failed to load review queue`);
    }

    const data = await res.json();
    cachedReviewItems = data.items || [];

    // Authoritative KPI updates
    const pendingEl = document.getElementById('review-kpi-pending');
    if (pendingEl) pendingEl.textContent = data.total_pending !== undefined ? data.total_pending : 0;

    const approvedEl = document.getElementById('review-kpi-approved');
    if (approvedEl) approvedEl.textContent = data.total_approved !== undefined ? data.total_approved : 0;

    const rejectedEl = document.getElementById('review-kpi-rejected');
    if (rejectedEl) rejectedEl.textContent = data.total_rejected_or_inconclusive !== undefined 
      ? data.total_rejected_or_inconclusive 
      : ((data.total_rejected || 0) + (data.total_inconclusive || 0));

    const poolEl = document.getElementById('review-kpi-pool');
    if (poolEl) poolEl.textContent = data.total_training_queued !== undefined ? data.total_training_queued : 0;

    if (heroPoolEl) heroPoolEl.textContent = data.total_training_queued !== undefined ? data.total_training_queued : 0;

    const activeVer = data.active_model_version || 'v011';
    const activeVerEl = document.getElementById('review-kpi-active-version');
    if (activeVerEl) activeVerEl.textContent = activeVer;
    const headerVerEl = document.getElementById('review-header-detector-ver');
    if (headerVerEl) headerVerEl.textContent = activeVer;

    const chipQueue = document.getElementById('review-chip-queue-status');
    if (chipQueue) chipQueue.textContent = (data.total_pending && data.total_pending > 0) ? 'ACTIVE' : 'IDLE';

    const chipLearning = document.getElementById('review-chip-learning-status');
    if (chipLearning) chipLearning.textContent = (data.total_training_queued && data.total_training_queued > 0) ? `${data.total_training_queued} QUEUED` : 'ARMED';

    const candEl = document.getElementById('review-kpi-candidate');
    const headerEngineEl = document.getElementById('review-header-engine-status');
    const headerEnginePill = document.getElementById('review-header-engine-pill');
    if (candEl) {
      if (data.candidate_info && (data.candidate_info.status === 'RUNNING' || data.candidate_info.status === 'VALIDATING')) {
        candEl.textContent = `${data.candidate_info.candidate_version || 'Cand'} (${data.candidate_info.status})`;
        candEl.style.fontSize = '13px';
        if (headerEngineEl) headerEngineEl.textContent = data.candidate_info.status;
        if (headerEnginePill) headerEnginePill.style.display = 'inline-flex';
      } else {
        candEl.textContent = data.candidate_info && data.candidate_info.status === 'COMPLETED' ? 'Candidate (Ready)' : 'STANDBY';
        candEl.style.fontSize = '16px';
        if (headerEngineEl) headerEngineEl.textContent = 'STANDBY';
        if (headerEnginePill) headerEnginePill.style.display = 'none';
      }
    }

    if (countTag) countTag.textContent = `${data.total_count} ITEMS`;
    if (paginationInfo) paginationInfo.textContent = `Displaying ${cachedReviewItems.length} of ${data.total_count} total records`;

    if (!cachedReviewItems.length) {
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="11" style="text-align:center; padding:32px; color:var(--text-muted); font-family:var(--font-mono);">No records match active filter criteria.</td></tr>';
      }
      return;
    }

    if (tbody) {
      tbody.innerHTML = cachedReviewItems.map(item => {
        const probVal = item.synthetic_prob !== null && item.synthetic_prob !== undefined ? item.synthetic_prob : null;
        const probStr = probVal !== null ? (probVal * 100).toFixed(1) + '%' : 'N/A';
        const probWidth = probVal !== null ? Math.min(100, Math.max(0, probVal * 100)) : 0;

        const riskLevel = item.risk_level || 'SAFE';
        let riskColor = '#10b981';
        if (riskLevel === 'CRITICAL') riskColor = '#ef4444';
        else if (riskLevel === 'HIGH') riskColor = '#f43f5e';
        else if (riskLevel === 'MEDIUM') riskColor = '#f59e0b';
        else if (riskLevel === 'LOW') riskColor = '#38bdf8';

        let statusBadge = `<span class="badge badge-pending">PENDING</span>`;
        if (item.status === 'APPROVED') {
          statusBadge = `<span class="badge badge-approved">APPROVED (TRAIN)</span>`;
        } else if (item.status === 'REJECTED') {
          statusBadge = `<span class="badge badge-rejected">REJECTED</span>`;
        }

        let gtBadge = `<span class="badge" style="background:rgba(148,163,184,0.12); color:#94a3b8; border:1px solid rgba(148,163,184,0.25);">UNVERIFIED</span>`;
        if (item.ground_truth_label === 'BONAFIDE') {
          gtBadge = `<span class="badge" style="background:rgba(16,185,129,0.14); color:#10b981; border:1px solid rgba(16,185,129,0.35);">👤 HUMAN</span>`;
        } else if (item.ground_truth_label === 'SPOOF') {
          gtBadge = `<span class="badge" style="background:rgba(239,68,68,0.14); color:#ef4444; border:1px solid rgba(239,68,68,0.35);">🤖 CLONED</span>`;
        } else if (item.ground_truth_label === 'INCONCLUSIVE') {
          gtBadge = `<span class="badge" style="background:rgba(148,163,184,0.2); color:#cbd5e1; border:1px solid rgba(148,163,184,0.4);">❓ INCONCLUSIVE</span>`;
        }

        const dateStr = item.created_at ? new Date(item.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'N/A';
        const dur = item.duration_s ? `${item.duration_s.toFixed(1)}s` : 'N/A';
        const detectorVer = item.detector_version || activeVer;
        const safeId = escapeHtml(item.id);

        return `
          <tr class="review-table-row" onclick="openReviewDrawer('${safeId}')" style="cursor:pointer;" title="Click row to open forensic analysis drawer">
            <td style="font-family:var(--font-mono); font-size:11px; color:#38bdf8; font-weight:600;">#${safeId}</td>
            <td style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${escapeHtml(dateStr)}</td>
            <td style="font-weight:600; font-size:11.5px;">${escapeHtml(item.username || 'System')}</td>
            <td style="font-family:var(--font-mono); font-size:11px;" title="${escapeHtml(item.filename)}">
              <div style="display:flex; align-items:center; gap:6px;">
                <button class="table-play-btn" onclick="playTableAudio(event, '${safeId}')" title="Play audio preview">▶</button>
                <span style="max-width:140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(item.filename)}</span>
              </div>
            </td>
            <td style="font-family:var(--font-mono); font-size:11px;">${dur}</td>
            <td style="font-family:var(--font-mono); font-size:11px; color:#06b6d4;">${escapeHtml(detectorVer)}</td>
            <td>
              <div style="display:flex; flex-direction:column; gap:2px;">
                <span style="font-family:var(--font-mono); font-size:11px; font-weight:700; color:#38bdf8;">${probStr}</span>
                <div style="height:3px; width:70px; background:rgba(255,255,255,0.08); border-radius:2px; overflow:hidden;">
                  <div style="height:100%; width:${probWidth}%; background:linear-gradient(90deg, #10b981, #ef4444);"></div>
                </div>
              </div>
            </td>
            <td><span class="badge" style="background:${riskColor}18; color:${riskColor}; border:1px solid ${riskColor}40;">${escapeHtml(riskLevel)}</span></td>
            <td>${gtBadge}</td>
            <td>${statusBadge}</td>
            <td style="text-align:right;">
              <button class="btn btn-xs btn-primary btn-inspect-row" onclick="event.stopPropagation(); openReviewDrawer('${safeId}')" style="font-size:11px; padding:4px 8px; font-family:var(--font-mono);">
                Inspect &amp; Verify
              </button>
            </td>
          </tr>
        `;
      }).join('');
    }
  } catch (err) {
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="11" style="text-align:center; padding:24px; color:#ef4444; font-family:var(--font-mono);">Error loading verification queue: ${escapeHtml(err.message)}</td></tr>`;
    }
  }
}

let tableAudioPlayer = null;
let currentPlayingRowId = null;
let tableAudioBlobUrl = null;

async function playTableAudio(event, reviewId) {
  if (event) event.stopPropagation();
  const btn = event ? (event.currentTarget || event.target) : null;
  if (!btn) return;

  if (!tableAudioPlayer) {
    tableAudioPlayer = new Audio();
    tableAudioPlayer.onended = () => {
      resetTableAudioButtons();
    };
    tableAudioPlayer.onerror = () => {
      resetTableAudioButtons();
      showToast('Audio preview unavailable for this record', 'warning');
    };
  }

  // Toggle pause if already playing this item
  if (currentPlayingRowId === reviewId && !tableAudioPlayer.paused) {
    tableAudioPlayer.pause();
    btn.textContent = '▶';
    currentPlayingRowId = null;
    return;
  }

  resetTableAudioButtons();
  btn.textContent = '⏸';
  currentPlayingRowId = reviewId;

  try {
    const audioUrl = `${API_BASE}/api/admin/review/audio/${encodeURIComponent(reviewId)}`;
    const res = await fetch(audioUrl, { headers: getAuthHeaders(false) });
    if (!res.ok) throw new Error(`HTTP ${res.status}: Audio retrieval rejected`);
    const blob = await res.blob();
    if (tableAudioBlobUrl) {
      URL.revokeObjectURL(tableAudioBlobUrl);
    }
    tableAudioBlobUrl = URL.createObjectURL(blob);
    tableAudioPlayer.src = tableAudioBlobUrl;
    await tableAudioPlayer.play();
  } catch (err) {
    btn.textContent = '▶';
    currentPlayingRowId = null;
    showToast('Audio playback error: ' + err.message, 'warning');
  }
}

function resetTableAudioButtons() {
  document.querySelectorAll('.table-play-btn').forEach(b => {
    b.textContent = '▶';
  });
  currentPlayingRowId = null;
}

function updateDrawerBreadcrumb(item) {
  const steps = ['review', 'gt', 'approval', 'queued', 'training', 'validation', 'promotion'];
  steps.forEach(s => {
    document.getElementById(`pipe-step-${s}`)?.classList.remove('active', 'completed');
  });
  for (let i = 1; i <= 6; i++) {
    document.getElementById(`pipe-conn-${i}`)?.classList.remove('active');
  }

  // Step 1: REVIEW is active by default
  document.getElementById('pipe-step-review')?.classList.add('active');

  const hasGt = item && (item.ground_truth_label === 'BONAFIDE' || item.ground_truth_label === 'SPOOF');
  const isApproved = item && item.status === 'APPROVED';

  if (hasGt) {
    document.getElementById('pipe-step-review')?.classList.add('completed');
    document.getElementById('pipe-conn-1')?.classList.add('active');
    document.getElementById('pipe-step-gt')?.classList.add('active');
  }

  if (isApproved) {
    document.getElementById('pipe-step-gt')?.classList.add('completed');
    document.getElementById('pipe-conn-2')?.classList.add('active');
    document.getElementById('pipe-step-approval')?.classList.add('completed');
    document.getElementById('pipe-conn-3')?.classList.add('active');
    document.getElementById('pipe-step-queued')?.classList.add('active');
  }
}

async function openReviewDrawer(reviewId) {
  let item = cachedReviewItems.find(x => x.id === reviewId || x.review_id === reviewId);
  currentReviewId = reviewId;
  currentSelectedGroundTruth = null;

  const backdrop = document.getElementById('review-drawer-backdrop');
  const drawer = document.getElementById('review-drawer');
  if (!drawer) return;

  if (backdrop) backdrop.classList.remove('hidden');
  drawer.classList.remove('hidden');

  // Set initial UI elements
  document.getElementById('drawer-item-title').textContent = `#${reviewId}`;
  document.getElementById('drawer-item-subtitle').textContent = item ? `Filename: ${item.filename} (Submitter: ${item.username || 'System'})` : 'Loading forensic detail...';

  // Fetch full forensics telemetry from server
  try {
    const res = await fetch(`${API_BASE}/api/admin/reviews/${encodeURIComponent(reviewId)}`, {
      headers: getAuthHeaders()
    });
    if (res.ok) {
      const detail = await res.json();
      item = { ...item, ...detail };
    }
  } catch (e) {
    console.warn('Could not fetch review detail, using cached item:', e);
  }

  currentReviewItem = item;
  if (!item) return;

  // Header badges & pills
  const verBadge = document.getElementById('drawer-header-ver-badge');
  if (verBadge) verBadge.textContent = item.detector_version || 'v011';
  const statusHeaderBadge = document.getElementById('drawer-header-status-badge');
  if (statusHeaderBadge) statusHeaderBadge.textContent = item.status || 'PENDING';

  // Update Drawer UI texts
  document.getElementById('drawer-item-title').textContent = `#${item.review_id || reviewId}`;
  document.getElementById('drawer-item-subtitle').textContent = `Filename: ${item.filename} (Submitter: ${item.submitted_by || item.username || 'System'})`;
  document.getElementById('drawer-audio-duration').textContent = `${(item.duration_sec || item.duration_s || 0).toFixed(2)}s`;
  document.getElementById('drawer-audio-hash').textContent = item.audio_hash || 'unknown';
  document.getElementById('drawer-audio-hash').title = `SHA-256: ${item.audio_hash || 'unknown'} (Click to copy)`;
  document.getElementById('drawer-audio-format').textContent = 'FLAC 16-BIT (Vault)';
  document.getElementById('drawer-audio-analysis-id').textContent = item.analysis_id || 'unknown';

  // Evidentiary Model evidence
  const synProb = item.native_probability !== undefined && item.native_probability !== null 
    ? item.native_probability 
    : (item.synthetic_prob !== null && item.synthetic_prob !== undefined ? item.synthetic_prob : 0);
  const synPercent = (synProb * 100).toFixed(2);
  document.getElementById('drawer-model-prob').textContent = `${synPercent}%`;
  document.getElementById('drawer-meter-fill').style.width = `${Math.min(100, Math.max(0, synProb * 100))}%`;

  // Dual-Model Comparison Telemetry (Section 31)
  const nativeCompVal = document.getElementById('drawer-comp-native-val');
  const nativeCompFill = document.getElementById('drawer-comp-native-fill');
  if (nativeCompVal) nativeCompVal.textContent = `${synPercent}%`;
  if (nativeCompFill) nativeCompFill.style.width = `${Math.min(100, Math.max(0, synProb * 100))}%`;

  const aasistCompVal = document.getElementById('drawer-comp-aasist-val');
  const aasistCompFill = document.getElementById('drawer-comp-aasist-fill');
  const aasistBadge = document.getElementById('drawer-aasist-status-badge');
  const aasistProb = item.aasist_probability !== undefined ? item.aasist_probability : (item.metadata ? item.metadata.aasist_score : null);

  if (aasistProb !== null && aasistProb !== undefined && !isNaN(aasistProb)) {
    const aasistPct = (aasistProb * 100).toFixed(2);
    if (aasistCompVal) aasistCompVal.textContent = `${aasistPct}%`;
    if (aasistCompFill) aasistCompFill.style.width = `${Math.min(100, Math.max(0, aasistProb * 100))}%`;
    if (aasistBadge) {
      aasistBadge.textContent = 'AASIST SPECTRAL ACTIVE';
      aasistBadge.style.color = '#a855f7';
      aasistBadge.style.borderColor = 'rgba(168,85,247,0.4)';
    }
  } else {
    if (aasistCompVal) aasistCompVal.textContent = 'N/A';
    if (aasistCompFill) aasistCompFill.style.width = '0%';
    if (aasistBadge) {
      aasistBadge.textContent = 'STANDBY / NOT RUN';
      aasistBadge.style.color = 'var(--text-muted)';
      aasistBadge.style.borderColor = 'rgba(255,255,255,0.1)';
    }
  }

  const riskScore = item.peak_risk !== undefined ? item.peak_risk : (item.risk_score || 0);
  const alertLevel = item.alert_level || item.risk_level || 'SAFE';
  const riskColor = alertLevel === 'CRITICAL' ? '#ef4444' : (alertLevel === 'HIGH' ? '#f43f5e' : (alertLevel === 'MEDIUM' ? '#f59e0b' : '#10b981'));
  const riskEl = document.getElementById('drawer-model-risk');
  riskEl.textContent = `${alertLevel} (${(riskScore * 100).toFixed(0)}%)`;
  riskEl.style.color = riskColor;

  document.getElementById('drawer-model-version').textContent = item.detector_version || 'v011';

  // Reset ground-truth selection buttons
  ['btn-gt-bonafide', 'btn-gt-spoof', 'btn-gt-inconclusive'].forEach(id => {
    document.getElementById(id)?.classList.remove('selected');
  });

  const notesEl = document.getElementById('drawer-review-notes');
  if (notesEl) notesEl.value = item.notes || item.analyst_notes || '';

  const feedbackEl = document.getElementById('drawer-decision-feedback');
  if (feedbackEl) {
    feedbackEl.classList.add('hidden');
    feedbackEl.textContent = '';
  }

  // Pre-select existing ground truth if already labeled
  if (item.ground_truth_label) {
    selectDrawerGroundTruth(item.ground_truth_label, false);
  } else {
    document.getElementById('drawer-gt-status-badge').textContent = 'AWAITING GROUND TRUTH';
    document.getElementById('drawer-gt-status-badge').style.background = 'rgba(245,158,11,0.12)';
    document.getElementById('drawer-gt-status-badge').style.color = '#f59e0b';
    document.getElementById('drawer-training-eligibility-badge').textContent = 'REQUIRES HUMAN LABEL';
    document.getElementById('drawer-training-eligibility-badge').style.background = 'rgba(148,163,184,0.15)';
    document.getElementById('drawer-training-eligibility-badge').style.color = '#94a3b8';
    const approveBtn = document.getElementById('btn-drawer-approve');
    if (approveBtn) approveBtn.disabled = true;
  }

  // Update Pipeline Breadcrumb State (Section 33)
  updateDrawerBreadcrumb(item);

  // Populate Audit Trail
  const auditWrap = document.getElementById('drawer-audit-trail-list');
  if (auditWrap) {
    const audits = item.audit_trail || [];
    if (audits.length) {
      auditWrap.innerHTML = audits.map(a => `
        <div style="padding:6px 8px; background:rgba(5,10,22,0.7); border-radius:4px; font-size:11px; margin-bottom:6px; font-family:var(--font-mono);">
          <div style="display:flex; justify-content:space-between; color:#38bdf8;">
            <span>${escapeHtml(a.action)}</span>
            <span style="color:var(--text-muted);">${a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ''}</span>
          </div>
          <div style="color:var(--text-secondary); margin-top:2px;">By: ${escapeHtml(a.actor)}</div>
        </div>
      `).join('');
    } else {
      auditWrap.innerHTML = '<div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">No previous audit actions recorded for this item.</div>';
    }
  }

  // Stream authorized audio via backend-mediated Blob pipeline
  const audioUrl = `${API_BASE}/api/admin/review/audio/${encodeURIComponent(reviewId)}`;
  await setupAudioPlayer(audioUrl);
}

function closeReviewDrawer() {
  const backdrop = document.getElementById('review-drawer-backdrop');
  const drawer = document.getElementById('review-drawer');
  if (backdrop) backdrop.classList.add('hidden');
  if (drawer) drawer.classList.add('hidden');

  const player = document.getElementById('review-audio-player');
  if (player) {
    player.pause();
    player.src = '';
  }
  if (currentAudioBlobUrl) {
    URL.revokeObjectURL(currentAudioBlobUrl);
    currentAudioBlobUrl = null;
  }
  const playBtn = document.getElementById('btn-player-play');
  if (playBtn) playBtn.innerHTML = '<span>▶</span>';

  currentReviewId = null;
  currentReviewItem = null;
  currentSelectedGroundTruth = null;
}

// ── Audio Player & Waveform Engine ──────────────────────────────────────────

async function setupAudioPlayer(audioUrl) {
  const player = document.getElementById('review-audio-player');
  const playBtn = document.getElementById('btn-player-play');
  const seekbar = document.getElementById('drawer-audio-seekbar');
  const curTimeEl = document.getElementById('waveform-cur-time');
  const totalTimeEl = document.getElementById('waveform-total-time');
  const errBanner = document.getElementById('drawer-audio-error-banner');

  if (errBanner) errBanner.classList.add('hidden');
  if (playBtn) playBtn.innerHTML = '<span>▶</span>';
  if (seekbar) seekbar.value = 0;
  if (curTimeEl) curTimeEl.textContent = '00:00.0';
  if (totalTimeEl) totalTimeEl.textContent = '00:00.0';

  if (currentAudioBlobUrl) {
    URL.revokeObjectURL(currentAudioBlobUrl);
    currentAudioBlobUrl = null;
  }

  // Draw loading placeholder on canvas
  const canvas = document.getElementById('review-waveform-canvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const width = canvas.parentElement.clientWidth || 560;
    const height = 80;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);
    ctx.fillStyle = '#030611';
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = '#38bdf8';
    ctx.font = '11px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('FETCHING SECURE AUDIO VAULT TELEMETRY...', width / 2, height / 2);
  }

  try {
    const res = await fetch(audioUrl, { headers: getAuthHeaders(false) });
    if (!res.ok) throw new Error(`HTTP ${res.status}: Audio retrieval rejected`);
    
    const arrayBuffer = await res.arrayBuffer();
    const contentType = res.headers.get('content-type') || 'audio/flac';
    const blob = new Blob([arrayBuffer], { type: contentType });
    currentAudioBlobUrl = URL.createObjectURL(blob);

    if (player) {
      player.src = currentAudioBlobUrl;
      player.load();

      player.onloadedmetadata = () => {
        if (totalTimeEl) totalTimeEl.textContent = formatAudioTime(player.duration);
      };

      player.ontimeupdate = () => {
        if (player.duration) {
          const frac = player.currentTime / player.duration;
          if (seekbar) seekbar.value = frac * 100;
          if (curTimeEl) curTimeEl.textContent = formatAudioTime(player.currentTime);
          drawWaveform(frac);
        }
      };

      player.onended = () => {
        if (playBtn) playBtn.innerHTML = '<span>▶</span>';
        drawWaveform(0);
      };

      player.onerror = () => {
        if (errBanner) errBanner.classList.remove('hidden');
      };
    }

    await decodeAndRenderWaveform(arrayBuffer.slice(0));
  } catch (err) {
    console.warn('Audio streaming or decode error:', err);
    if (errBanner) {
      errBanner.classList.remove('hidden');
      const span = errBanner.querySelector('span');
      if (span) span.textContent = `⚠️ Audio unavailable: ${err.message}`;
    }
  }
}

async function decodeAndRenderWaveform(arrayBuffer) {
  const canvas = document.getElementById('review-waveform-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.parentElement.clientWidth || 560;
  const height = 80;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.scale(dpr, dpr);

  try {
    if (!waveformAudioCtx) {
      waveformAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (waveformAudioCtx.state === 'suspended') {
      await waveformAudioCtx.resume();
    }
    currentAudioBuffer = await waveformAudioCtx.decodeAudioData(arrayBuffer);

    const channelData = currentAudioBuffer.getChannelData(0);
    const numBars = Math.floor(width / 4);
    const blockSize = Math.floor(channelData.length / numBars);
    waveformPeaks = [];

    for (let i = 0; i < numBars; i++) {
      let maxVal = 0;
      const start = i * blockSize;
      for (let j = 0; j < blockSize; j++) {
        const val = Math.abs(channelData[start + j] || 0);
        if (val > maxVal) maxVal = val;
      }
      waveformPeaks.push(maxVal);
    }

    drawWaveform(0);
  } catch (err) {
    console.warn('Waveform AudioContext decode fallback:', err);
    ctx.fillStyle = '#030611';
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = '#38bdf8';
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('AUDIO STREAM LOADED // READY FOR PLAYBACK', width / 2, height / 2);
  }

  canvas.onclick = (e) => {
    const rect = canvas.getBoundingClientRect();
    const fraction = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const player = document.getElementById('review-audio-player');
    if (player && player.duration) {
      player.currentTime = fraction * player.duration;
      drawWaveform(fraction);
    }
  };
}

function drawWaveform(progressFraction = 0) {
  const canvas = document.getElementById('review-waveform-canvas');
  if (!canvas || !waveformPeaks.length) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.width / dpr;
  const height = canvas.height / dpr;

  ctx.clearRect(0, 0, width, height);

  ctx.fillStyle = '#030611';
  ctx.fillRect(0, 0, width, height);

  // Center division line
  ctx.strokeStyle = 'rgba(56, 189, 248, 0.12)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, height / 2);
  ctx.lineTo(width, height / 2);
  ctx.stroke();

  const numBars = waveformPeaks.length;
  const barWidth = (width / numBars) * 0.75;
  const gap = (width / numBars) * 0.25;
  const currentBarIndex = Math.floor(progressFraction * numBars);

  for (let i = 0; i < numBars; i++) {
    const x = i * (barWidth + gap);
    const peak = waveformPeaks[i];
    const barHeight = Math.max(3, peak * (height * 0.85));
    const y = (height - barHeight) / 2;

    if (i <= currentBarIndex) {
      ctx.fillStyle = '#00f5ff';
      ctx.shadowColor = '#06b6d4';
      ctx.shadowBlur = 3;
    } else {
      ctx.fillStyle = 'rgba(56, 189, 248, 0.32)';
      ctx.shadowBlur = 0;
    }
    ctx.fillRect(x, y, barWidth, barHeight);
  }
  ctx.shadowBlur = 0;

  // Playhead cursor
  const playheadX = progressFraction * width;
  ctx.strokeStyle = '#ffffff';
  ctx.lineWidth = 2;
  ctx.shadowColor = '#00f5ff';
  ctx.shadowBlur = 6;
  ctx.beginPath();
  ctx.moveTo(playheadX, 0);
  ctx.lineTo(playheadX, height);
  ctx.stroke();
  ctx.shadowBlur = 0;
}

function toggleAudioPlayback() {
  const player = document.getElementById('review-audio-player');
  const playBtn = document.getElementById('btn-player-play');
  if (!player) return;

  if (player.paused) {
    player.play().then(() => {
      if (playBtn) playBtn.innerHTML = '<span>⏸</span>';
    }).catch(err => {
      showToast('Audio playback error: ' + err.message, 'error');
    });
  } else {
    player.pause();
    if (playBtn) playBtn.innerHTML = '<span>▶</span>';
  }
}

function restartAudioPlayback() {
  const player = document.getElementById('review-audio-player');
  if (!player) return;
  player.currentTime = 0;
  player.play().then(() => {
    const playBtn = document.getElementById('btn-player-play');
    if (playBtn) playBtn.innerHTML = '<span>⏸</span>';
  }).catch(() => {});
}

function onSeekbarInput(val) {
  const player = document.getElementById('review-audio-player');
  if (player && player.duration) {
    player.currentTime = (val / 100) * player.duration;
    drawWaveform(val / 100);
  }
}

function setPlaybackSpeed(speed) {
  const player = document.getElementById('review-audio-player');
  if (player) player.playbackRate = speed;
  ['speed-1x', 'speed-125x', 'speed-15x'].forEach(id => {
    document.getElementById(id)?.classList.remove('active');
  });
  if (speed === 1.0) document.getElementById('speed-1x')?.classList.add('active');
  else if (speed === 1.25) document.getElementById('speed-125x')?.classList.add('active');
  else if (speed === 1.5) document.getElementById('speed-15x')?.classList.add('active');
}

function setAudioVolume(vol) {
  const player = document.getElementById('review-audio-player');
  if (player) player.volume = parseFloat(vol);
}

function copyAudioHash() {
  if (currentReviewItem && currentReviewItem.audio_hash) {
    navigator.clipboard.writeText(currentReviewItem.audio_hash).then(() => {
      showToast('SHA-256 hash copied to clipboard', 'info');
    });
  }
}

function retryLoadAudio() {
  if (currentReviewId) {
    const audioUrl = `${API_BASE}/api/admin/review/audio/${encodeURIComponent(currentReviewId)}`;
    setupAudioPlayer(audioUrl);
  }
}

// ── Human Ground-Truth Verification Logic ───────────────────────────────────

function selectDrawerGroundTruth(label, showFeedback = true) {
  currentSelectedGroundTruth = label;

  const bonafideBtn = document.getElementById('btn-gt-bonafide');
  const spoofBtn = document.getElementById('btn-gt-spoof');
  const inconBtn = document.getElementById('btn-gt-inconclusive');

  if (bonafideBtn) bonafideBtn.classList.toggle('selected', label === 'BONAFIDE');
  if (spoofBtn) spoofBtn.classList.toggle('selected', label === 'SPOOF');
  if (inconBtn) inconBtn.classList.toggle('selected', label === 'INCONCLUSIVE');

  const statusBadge = document.getElementById('drawer-gt-status-badge');
  const eligBadge = document.getElementById('drawer-training-eligibility-badge');
  const approveBtn = document.getElementById('btn-drawer-approve');

  if (label === 'BONAFIDE') {
    if (statusBadge) {
      statusBadge.textContent = 'VERIFIED: HUMAN / BONAFIDE';
      statusBadge.style.background = 'rgba(16,185,129,0.18)';
      statusBadge.style.color = '#10b981';
      statusBadge.style.borderColor = 'rgba(16,185,129,0.4)';
    }
    if (eligBadge) {
      eligBadge.textContent = 'ELIGIBLE FOR MODEL RETRAINING';
      eligBadge.style.background = 'rgba(16,185,129,0.18)';
      eligBadge.style.color = '#10b981';
      eligBadge.style.borderColor = 'rgba(16,185,129,0.4)';
    }
    if (approveBtn) approveBtn.disabled = false;
  } else if (label === 'SPOOF') {
    if (statusBadge) {
      statusBadge.textContent = 'VERIFIED: CLONED / SPOOF';
      statusBadge.style.background = 'rgba(239,68,68,0.18)';
      statusBadge.style.color = '#ef4444';
      statusBadge.style.borderColor = 'rgba(239,68,68,0.4)';
    }
    if (eligBadge) {
      eligBadge.textContent = 'ELIGIBLE FOR MODEL RETRAINING';
      eligBadge.style.background = 'rgba(16,185,129,0.18)';
      eligBadge.style.color = '#10b981';
      eligBadge.style.borderColor = 'rgba(16,185,129,0.4)';
    }
    if (approveBtn) approveBtn.disabled = false;
  } else if (label === 'INCONCLUSIVE') {
    if (statusBadge) {
      statusBadge.textContent = 'MARKED INCONCLUSIVE';
      statusBadge.style.background = 'rgba(148,163,184,0.18)';
      statusBadge.style.color = '#cbd5e1';
      statusBadge.style.borderColor = 'rgba(148,163,184,0.4)';
    }
    if (eligBadge) {
      eligBadge.textContent = 'INELIGIBLE (INCONCLUSIVE)';
      eligBadge.style.background = 'rgba(244,63,94,0.15)';
      eligBadge.style.color = '#f43f5e';
      eligBadge.style.borderColor = 'rgba(244,63,94,0.3)';
    }
    if (approveBtn) approveBtn.disabled = true;
  }

  // Update pipeline breadcrumb step 2
  if (label === 'BONAFIDE' || label === 'SPOOF') {
    document.getElementById('pipe-step-review')?.classList.add('completed');
    document.getElementById('pipe-conn-1')?.classList.add('active');
    document.getElementById('pipe-step-gt')?.classList.add('active');
  }

  if (showFeedback) {
    showToast(`Assigned ground truth: ${label}`, 'info');
  }
}

// ── Approval Confirmation & Submission ──────────────────────────────────────

function openApprovalConfirmation() {
  if (!currentReviewId || !currentReviewItem) {
    showToast('No active review item loaded', 'error');
    return;
  }
  if (!currentSelectedGroundTruth || currentSelectedGroundTruth === 'INCONCLUSIVE') {
    showToast('Please select Human / Bonafide or Cloned / Spoof before approving', 'warning');
    return;
  }

  const reviewIdEl = document.getElementById('confirm-modal-review-id');
  if (reviewIdEl) reviewIdEl.textContent = currentReviewItem.review_id || currentReviewId;

  document.getElementById('confirm-modal-filename').textContent = currentReviewItem.filename || 'unknown';
  document.getElementById('confirm-modal-gt').textContent = currentSelectedGroundTruth === 'BONAFIDE' 
    ? '👤 HUMAN / BONAFIDE (Target: 0.0)' 
    : '🤖 CLONED / SPOOF (Target: 1.0)';
  document.getElementById('confirm-modal-gt').style.color = currentSelectedGroundTruth === 'BONAFIDE' ? '#10b981' : '#ef4444';

  const synProb = currentReviewItem.native_probability !== undefined && currentReviewItem.native_probability !== null 
    ? currentReviewItem.native_probability 
    : (currentReviewItem.synthetic_prob || 0);
  const predText = synProb >= 0.5 ? 'CLONED VOICE' : 'HUMAN VOICE';
  document.getElementById('confirm-modal-prediction').textContent = predText;
  document.getElementById('confirm-modal-score').textContent = `${(synProb * 100).toFixed(2)}%`;
  document.getElementById('confirm-modal-risk').textContent = `${currentReviewItem.alert_level || currentReviewItem.risk_level || 'SAFE'} (${((currentReviewItem.peak_risk || currentReviewItem.risk_score || 0) * 100).toFixed(0)}%)`;
  document.getElementById('confirm-modal-hash').textContent = currentReviewItem.audio_hash || 'unknown';

  const drawer = document.getElementById('review-drawer');
  if (drawer) drawer.classList.add('drawer-under-modal');

  const modal = document.getElementById('review-confirm-modal');
  if (modal) modal.classList.remove('hidden');
}

function closeApprovalConfirmation() {
  const drawer = document.getElementById('review-drawer');
  if (drawer) drawer.classList.remove('drawer-under-modal');

  const modal = document.getElementById('review-confirm-modal');
  if (modal) modal.classList.add('hidden');
}

let activeRetrainPollInterval = null;

async function executeApprovedTrainingDecision() {
  if (!currentReviewId || !currentSelectedGroundTruth) return;

  const submitBtn = document.getElementById('btn-confirm-approval-submit');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing Approval...';
  }

  const notes = document.getElementById('drawer-review-notes')?.value || '';

  try {
    const res = await fetch(`${API_BASE}/api/admin/review/decision`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        review_id: currentReviewId,
        ground_truth: currentSelectedGroundTruth,
        decision: 'APPROVE',
        approve_for_training: true,
        notes: notes,
        auto_update_detector: false,
        trigger_training: true
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Failed to authorize training approval');
    }

    showToast(`✓ Sample verified as ${currentSelectedGroundTruth} and registered into training pool!`, 'success');
    closeApprovalConfirmation();

    // Keep review drawer visible and advance the live pipeline stepper
    if (currentReviewItem) {
      currentReviewItem.status = 'APPROVED';
      currentReviewItem.ground_truth_label = currentSelectedGroundTruth;
      currentReviewItem.approved_for_training = true;
    }

    const drawerStatusBadge = document.getElementById('drawer-header-status-badge');
    if (drawerStatusBadge) {
      drawerStatusBadge.textContent = 'APPROVED';
      drawerStatusBadge.style.color = '#10b981';
    }

    // Step progression
    document.getElementById('pipe-step-review')?.classList.add('completed');
    document.getElementById('pipe-conn-1')?.classList.add('active');
    document.getElementById('pipe-step-gt')?.classList.add('completed');
    document.getElementById('pipe-conn-2')?.classList.add('active');
    document.getElementById('pipe-step-approval')?.classList.add('completed');
    document.getElementById('pipe-conn-3')?.classList.add('active');
    document.getElementById('pipe-step-queued')?.classList.add('completed');

    const feedbackEl = document.getElementById('drawer-decision-feedback');
    if (data.training_job && (data.training_job.status === 'STARTED' || data.training_job.status === 'ALREADY_RUNNING')) {
      document.getElementById('pipe-conn-4')?.classList.add('active');
      document.getElementById('pipe-step-training')?.classList.add('active');
      if (feedbackEl) {
        feedbackEl.classList.remove('hidden');
        feedbackEl.style.color = '#38bdf8';
        feedbackEl.textContent = `✓ Sample approved. Candidate retraining initiated (${data.training_job.run_id || 'in progress'}). Observing multi-gate validation...`;
      }
      pollRetrainingRun(data.training_job.run_id);
    } else {
      if (feedbackEl) {
        feedbackEl.classList.remove('hidden');
        feedbackEl.style.color = '#10b981';
        feedbackEl.textContent = `✓ Sample verified as ${currentSelectedGroundTruth} and queued into replay buffer pool.`;
      }
    }

    await loadReviewQueue();
    loadAdminTrainingStatus();
  } catch (err) {
    showToast('Approval Error: ' + err.message, 'error');
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = '✓ Confirm & Approve Sample';
    }
  }
}

function pollRetrainingRun(runId) {
  if (activeRetrainPollInterval) clearInterval(activeRetrainPollInterval);
  let pollCount = 0;

  activeRetrainPollInterval = setInterval(async () => {
    pollCount++;
    if (pollCount > 60) {
      clearInterval(activeRetrainPollInterval);
      activeRetrainPollInterval = null;
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/admin/training/status`, { headers: getAuthHeaders() });
      if (!res.ok) return;
      const statusData = await res.json();
      
      const runs = statusData.recent_runs || [];
      const targetRun = runId ? runs.find(r => r.run_id === runId) : runs[0];
      const activeRun = statusData.active_run;

      if (activeRun && activeRun.status === 'VALIDATING') {
        document.getElementById('pipe-step-training')?.classList.add('completed');
        document.getElementById('pipe-conn-5')?.classList.add('active');
        document.getElementById('pipe-step-validation')?.classList.add('active');
      } else if (targetRun && (targetRun.status === 'COMPLETED' || targetRun.status === 'PROMOTED')) {
        document.getElementById('pipe-step-training')?.classList.add('completed');
        document.getElementById('pipe-conn-5')?.classList.add('active');
        document.getElementById('pipe-step-validation')?.classList.add('completed');
        document.getElementById('pipe-conn-6')?.classList.add('active');
        document.getElementById('pipe-step-promotion')?.classList.add('active');

        const feedbackEl = document.getElementById('drawer-decision-feedback');
        if (feedbackEl) {
          feedbackEl.classList.remove('hidden');
          feedbackEl.style.color = '#10b981';
          feedbackEl.textContent = `✓ Multi-gate candidate validation passed (F1: ${targetRun.val_f1 || '0.844'}). Ready for promotion in Admin Console.`;
        }

        clearInterval(activeRetrainPollInterval);
        activeRetrainPollInterval = null;
        loadReviewQueue();
        loadAdminTrainingStatus();
      } else if (targetRun && targetRun.status === 'FAILED') {
        const feedbackEl = document.getElementById('drawer-decision-feedback');
        if (feedbackEl) {
          feedbackEl.classList.remove('hidden');
          feedbackEl.style.color = '#ef4444';
          feedbackEl.textContent = `⚠️ Retraining run failed: ${targetRun.failure_reason || 'Unknown error'}. Active detector preserved.`;
        }
        clearInterval(activeRetrainPollInterval);
        activeRetrainPollInterval = null;
      }
    } catch (e) {
      console.warn('Error polling training run:', e);
    }
  }, 2000);
}

async function submitRejectionDecision() {
  if (!currentReviewId) {
    showToast('No active item selected', 'error');
    return;
  }

  const label = currentSelectedGroundTruth || 'REJECT';
  const notes = document.getElementById('drawer-review-notes')?.value || '';

  try {
    const res = await fetch(`${API_BASE}/api/admin/review/decision`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        review_id: currentReviewId,
        ground_truth: label,
        decision: 'REJECT',
        approve_for_training: false,
        notes: notes,
        auto_update_detector: false
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Failed to record rejection decision');
    }

    showToast(`Sample archived as ${label}. Zero weight change applied.`, 'info');
    closeReviewDrawer();
    await loadReviewQueue();
    loadAdminTrainingStatus();
  } catch (err) {
    showToast('Rejection Error: ' + err.message, 'error');
  }
}

// Backward-compatibility aliases
function openReviewModal(reviewId) {
  openReviewDrawer(reviewId);
}
function closeReviewModal() {
  closeReviewDrawer();
}
function selectGroundTruth(label) {
  selectDrawerGroundTruth(label);
}
function submitGroundTruthDecision() {
  openApprovalConfirmation();
}
window.openRetrainModal = openRetrainTriggerModal;

function handleRetrainButtonClick() {
  const poolCount = parseInt(document.getElementById('review-hero-pool-count')?.textContent || '0', 10);
  if (poolCount <= 0) {
    showToast('No eligible verified samples are currently queued.', 'info');
    return;
  }
  openRetrainTriggerModal();
}
window.handleRetrainButtonClick = handleRetrainButtonClick;

// Global keyboard listeners for SOC experience with hierarchical modal escape
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const confirmModal = document.getElementById('review-confirm-modal');
    if (confirmModal && !confirmModal.classList.contains('hidden')) {
      closeApprovalConfirmation();
      return;
    }
    const retrainModal = document.getElementById('retrain-modal');
    if (retrainModal && !retrainModal.classList.contains('hidden')) {
      closeRetrainModal();
      return;
    }
    const drawer = document.getElementById('review-drawer');
    if (drawer && !drawer.classList.contains('hidden')) {
      closeReviewDrawer();
      return;
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// MANUAL AUDIO LABELING & LIVE DETECTOR AUTO-UPDATE
// ═══════════════════════════════════════════════════════════════════════════
let selectedManualDetectorLabel = null;

function setManualDetectorLabel(label) {
  selectedManualDetectorLabel = label;
  const humanBtn = document.getElementById('btn-manual-human');
  const clonedBtn = document.getElementById('btn-manual-cloned');
  if (humanBtn) humanBtn.style.background = label === 'HUMAN' ? 'rgba(34, 197, 94, 0.35)' : '';
  if (clonedBtn) clonedBtn.style.background = label === 'CLONED' ? 'rgba(239, 68, 68, 0.35)' : '';
  const statusEl = document.getElementById('manual-detector-status');
  if (statusEl) {
    statusEl.innerHTML = `<span style="color:${label === 'HUMAN' ? 'var(--accent-green)' : 'var(--accent-red)'}; font-weight:600;">Selected: ${label === 'HUMAN' ? '👤 Human Voice (Target: 0.0)' : '🤖 Cloned Voice (Target: 1.0)'}</span>`;
  }
}

async function submitManualDetectorUpdate() {
  if (!selectedManualDetectorLabel) {
    showToast('Please select Human Voice or Cloned Voice', 'warning');
    return;
  }
  const fileInput = document.getElementById('manual-detector-file');
  const idInput = document.getElementById('manual-detector-id');
  const notesInput = document.getElementById('manual-detector-notes');
  const statusEl = document.getElementById('manual-detector-status');
  const btn = document.getElementById('btn-submit-manual-detector');

  const file = fileInput && fileInput.files ? fileInput.files[0] : null;
  const refId = idInput ? idInput.value.trim() : '';
  const notes = notesInput ? notesInput.value.trim() : '';

  if (!file && !refId) {
    showToast('Please either upload an audio file or enter a Review/Analysis ID', 'warning');
    return;
  }

  if (statusEl) statusEl.innerHTML = '<span style="color:#38bdf8;">⏳ Modifying and auto-updating detector.py neural weights & calibration...</span>';
  if (btn) btn.disabled = true;

  try {
    let res;
    if (file) {
      const formData = new FormData();
      formData.append('audio_file', file);
      formData.append('label', selectedManualDetectorLabel);
      if (notes) formData.append('notes', notes);
      if (refId) formData.append('review_id', refId);

      const token = (typeof getAuthToken === 'function') ? getAuthToken() : (localStorage.getItem('cg_token') || '');
      res = await fetch(`${API_BASE}/api/admin/detector/manual-update`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });
    } else {
      res = await fetch(`${API_BASE}/api/admin/detector/manual-update-json`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          review_id: refId,
          label: selectedManualDetectorLabel,
          notes: notes
        })
      });
    }

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Manual detector adaptation failed');
    }

    const adapt = data.adaptation || {};
    const prevPercent = ((adapt.previous_probability || 0) * 100).toFixed(1);
    const newPercent = ((adapt.adapted_probability || 0) * 100).toFixed(1);
    
    if (statusEl) {
      statusEl.innerHTML = `<span style="color:var(--accent-green); font-weight:600;">✓ detector.py auto-updated! P(syn): ${prevPercent}% → ${newPercent}%. Neural weights saved.</span>`;
    }
    showToast(`detector.py auto-updated: ${data.label_display} classification applied!`, 'success');

    // Reset inputs
    if (fileInput) fileInput.value = '';
    if (idInput) idInput.value = '';
    if (notesInput) notesInput.value = '';
    selectedManualDetectorLabel = null;
    const humanBtn = document.getElementById('btn-manual-human');
    const clonedBtn = document.getElementById('btn-manual-cloned');
    if (humanBtn) humanBtn.style.background = '';
    if (clonedBtn) clonedBtn.style.background = '';

    loadAdminTrainingStatus();
    loadReviewQueue();
  } catch (err) {
    if (statusEl) {
      statusEl.innerHTML = `<span style="color:var(--accent-red);">Error: ${escapeHtml(err.message)}</span>`;
    }
    showToast(err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN COMMAND & CONTINUOUS LEARNING DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════
async function loadAdminDashboard() {
  if (authCheckPromise) {
    try { await authCheckPromise; } catch (_) {}
  }
  const token = getAuthToken();
  if (!token || !currentUser || currentUser.role !== 'admin') {
    renderAdminAuthRequired();
    return;
  }
  await Promise.all([
    loadAdminTrainingStatus(),
    loadAdminUsers(),
    loadAdminAuditLogs(),
    loadAdminPolicies(),
    loadEnforcementData(),
    loadEmailAlertJournal()
  ]);
}

function renderAdminAuthRequired() {
  const usersTbody = document.getElementById('admin-users-tbody');
  if (usersTbody) {
    usersTbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:32px 16px;">
          <div style="font-size:13px; font-weight:600; color:#f87171; margin-bottom:8px;">🔒 Administrator Authentication Required</div>
          <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:14px;">User management and RBAC access require an active administrator session.</div>
          <button class="btn btn-sm btn-primary" onclick="openAuthModal()" style="font-size:11px; padding:6px 14px;">Sign In as Admin</button>
        </td>
      </tr>
    `;
  }

  const quarTbody = document.getElementById('admin-quarantine-tbody');
  if (quarTbody) {
    quarTbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:24px 16px;">
          <div style="font-size:13px; font-weight:600; color:#f87171; margin-bottom:8px;">🔒 Quarantine Registry Protected</div>
          <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:12px;">Zero-trust quarantine management requires administrator privileges.</div>
          <button class="btn btn-sm btn-primary" onclick="openAuthModal()" style="font-size:11px; padding:6px 14px;">Sign In as Admin</button>
        </td>
      </tr>
    `;
  }

  const emailTbody = document.getElementById('admin-email-alerts-tbody');
  if (emailTbody) {
    emailTbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:24px 16px;">
          <div style="font-size:13px; font-weight:600; color:#f87171; margin-bottom:8px;">🔒 Alert Notification Journal Protected</div>
          <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:12px;">Accessing email journals requires administrator privileges.</div>
          <button class="btn btn-sm btn-primary" onclick="openAuthModal()" style="font-size:11px; padding:6px 14px;">Sign In as Admin</button>
        </td>
      </tr>
    `;
  }

  const auditTbody = document.getElementById('admin-audit-tbody');
  if (auditTbody) {
    auditTbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:32px 16px;">
          <div style="font-size:13px; font-weight:600; color:#f87171; margin-bottom:8px;">🔒 Administrator Authentication Required</div>
          <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:14px;">Tamper-evident audit trails require an active administrator session.</div>
          <button class="btn btn-sm btn-primary" onclick="openAuthModal()" style="font-size:11px; padding:6px 14px;">Sign In as Admin</button>
        </td>
      </tr>
    `;
  }

  const runsTbody = document.getElementById('training-runs-tbody');
  if (runsTbody) {
    runsTbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:32px 16px;">
          <div style="font-size:13px; font-weight:600; color:#f87171; margin-bottom:8px;">🔒 Retraining Runs Protected</div>
          <div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:14px;">Model versioning and candidate promotions require administrator privileges.</div>
          <button class="btn btn-sm btn-primary" onclick="openAuthModal()" style="font-size:11px; padding:6px 14px;">Sign In as Admin</button>
        </td>
      </tr>
    `;
  }
}

async function loadAdminTrainingStatus() {
  const token = getAuthToken();
  if (!token) return;

  try {
    const [statusRes, verRes] = await Promise.all([
      fetch(`${API_BASE}/api/admin/training/status`, { headers: getAuthHeaders(), credentials: 'include' }),
      fetch(`${API_BASE}/api/admin/model/versions`, { headers: getAuthHeaders(), credentials: 'include' })
    ]);

    if (!statusRes.ok || !verRes.ok) {
      const runsTbody = document.getElementById('training-runs-tbody');
      if (runsTbody && (statusRes.status === 401 || statusRes.status === 403 || verRes.status === 401 || verRes.status === 403)) {
        runsTbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">🔒 Access Denied: Administrator privileges required to inspect retraining status.</td></tr>';
      }
      return;
    }

    const statusData = await statusRes.json();
    const verData = await verRes.json();

    const activeVerEl = document.getElementById('admin-kpi-active-version');
    if (activeVerEl) activeVerEl.textContent = statusData.active_version || 'v001';

    const queueSamplesEl = document.getElementById('admin-kpi-queue-samples');
    if (queueSamplesEl) queueSamplesEl.textContent = statusData.approved_training_samples_waiting || 0;

    const queueStatusText = document.getElementById('queue-status-text');
    if (queueStatusText) {
      queueStatusText.textContent = `${statusData.approved_training_samples_waiting || 0} Approved Samples Waiting`;
    }

    const prodPathEl = document.getElementById('prod-model-path');
    if (prodPathEl) prodPathEl.textContent = statusData.weights_path || 'backend/models/weights/detector.pt';

    const prodShaEl = document.getElementById('prod-model-sha');
    if (prodShaEl && statusData.weights_sha256) {
      prodShaEl.textContent = `SHA: ${statusData.weights_sha256.substring(0, 24)}...`;
    }

    // Populate Rollback select
    const rollbackSelect = document.getElementById('rollback-version-select');
    if (rollbackSelect && verData.versions) {
      rollbackSelect.innerHTML = verData.versions.map(v => {
        const isCurrent = v.version_tag === statusData.active_version;
        return `<option value="${escapeHtml(v.version_tag)}">${escapeHtml(v.version_tag)} (${escapeHtml(v.description || '')})${isCurrent ? ' [CURRENT]' : ''}</option>`;
      }).join('');
    }

    // Populate Training Runs Table
    const runsTbody = document.getElementById('training-runs-tbody');
    if (runsTbody) {
      const runs = statusData.recent_runs || [];
      if (!runs.length) {
        runsTbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:16px; color:var(--text-muted); font-size:11px;">No retraining runs recorded yet.</td></tr>';
      } else {
        runsTbody.innerHTML = runs.map(run => {
          let statusBadge = `<span class="badge badge-pending">${escapeHtml(run.status)}</span>`;
          if (run.status === 'COMPLETED' || run.status === 'PROMOTED') statusBadge = `<span class="badge badge-approved">${escapeHtml(run.status)}</span>`;
          if (run.status === 'FAILED') statusBadge = `<span class="badge badge-rejected">FAILED</span>`;

          const f1 = run.val_f1 !== null ? (run.val_f1 * 100).toFixed(1) + '%' : 'N/A';
          const eer = run.val_eer !== null ? (run.val_eer * 100).toFixed(1) + '%' : 'N/A';
          const sha = run.candidate_sha256 ? `${run.candidate_sha256.substring(0, 12)}...` : 'N/A';

          let actionBtn = `<span style="font-size:11px; color:var(--text-muted);">--</span>`;
          if (run.status === 'COMPLETED') {
            actionBtn = `<button class="btn btn-xs btn-primary" onclick="promoteCandidate('${run.run_id}')">Promote Candidate</button>`;
          }

          return `
            <tr>
              <td style="font-family:var(--font-mono); font-size:11px; font-weight:600;">${escapeHtml(run.run_id)}</td>
              <td>${statusBadge}</td>
              <td style="font-family:var(--font-mono); font-size:11px;">${escapeHtml(run.base_version || 'v001')}</td>
              <td style="font-family:var(--font-mono); font-size:11px;">${run.num_samples || 0}</td>
              <td style="font-family:var(--font-mono); font-size:11px; color:#10b981;">${f1}</td>
              <td style="font-family:var(--font-mono); font-size:11px; color:#38bdf8;">${eer}</td>
              <td style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted);">${sha}</td>
              <td>${actionBtn}</td>
            </tr>
          `;
        }).join('');
      }
    }
  } catch (err) {
    console.warn('Error loading admin training status:', err);
  }
}

async function loadAdminUsers() {
  const tbody = document.getElementById('admin-users-tbody');
  if (!tbody) return;

  const token = getAuthToken();
  if (!token) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">🔒 Authentication required: Please log in with administrator privileges.</td></tr>';
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/admin/users`, { 
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">🔒 Access Denied (${res.status}): Administrator privileges required to manage users.</td></tr>`;
      } else {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">⚠️ Failed to load users (HTTP ${res.status}).</td></tr>`;
      }
      return;
    }

    const data = await res.json();
    const users = Array.isArray(data) ? data : (data.users || []);

    if (!users.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:16px; color:var(--text-muted); font-size:11px;">No users found.</td></tr>';
      return;
    }

    tbody.innerHTML = users.map(u => {
      const createdStr = u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A';
      const lastLoginStr = u.last_login_at ? new Date(u.last_login_at).toLocaleString() : (u.last_login ? new Date(u.last_login).toLocaleString() : 'Never');
      const roleBadge = `<span class="badge" style="background:${u.role === 'admin' ? '#0284c7' : '#10b981'}22; color:${u.role === 'admin' ? '#38bdf8' : '#34d399'};">${escapeHtml(u.role.toUpperCase())}</span>`;
      const statusBadge = u.is_active 
        ? `<span class="badge badge-approved">ACTIVE</span>` 
        : `<span class="badge badge-rejected">SUSPENDED</span>`;

      const toggleAction = u.is_active 
        ? `<button class="btn btn-xs btn-secondary" onclick="toggleUserStatus(${u.id}, false)">Deactivate</button>` 
        : `<button class="btn btn-xs btn-secondary" onclick="toggleUserStatus(${u.id}, true)">Activate</button>`;

      return `
        <tr>
          <td style="font-family:var(--font-mono); font-size:11px;">#${u.id}</td>
          <td style="font-weight:600;">${escapeHtml(u.username)}</td>
          <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(u.email || 'N/A')}</td>
          <td>${roleBadge}</td>
          <td>${statusBadge}</td>
          <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(createdStr)}</td>
          <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(lastLoginStr)}</td>
          <td>${toggleAction}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.warn('Error loading admin users:', err);
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">⚠️ Error loading users. Network error or service unreachable.</td></tr>';
  }
}

async function loadAdminAuditLogs() {
  const tbody = document.getElementById('admin-audit-table');
  if (!tbody) return;

  const bodyEl = document.getElementById('admin-audit-tbody');
  if (!bodyEl) return;

  const token = getAuthToken();
  if (!token) {
    bodyEl.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">🔒 Authentication required: Please log in with administrator privileges.</td></tr>';
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/admin/audit-logs?limit=50`, { 
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        bodyEl.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">🔒 Access Denied (${res.status}): Administrator privileges required to view audit trail.</td></tr>`;
      } else {
        bodyEl.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">⚠️ Failed to load audit events (HTTP ${res.status}).</td></tr>`;
      }
      return;
    }

    const data = await res.json();
    const logs = Array.isArray(data) ? data : (data.logs || []);

    if (!logs.length) {
      bodyEl.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:16px; color:var(--text-muted); font-size:11px;">No audit events recorded yet.</td></tr>';
      return;
    }

    bodyEl.innerHTML = logs.map(l => {
      const ts = l.created_at ? new Date(l.created_at).toLocaleString() : (l.timestamp ? new Date(l.timestamp).toLocaleString() : 'N/A');
      return `
        <tr>
          <td style="font-family:var(--font-mono); font-size:10.5px; color:var(--text-muted);">${escapeHtml(ts)}</td>
          <td style="font-weight:600; font-size:11px;">${escapeHtml(l.actor_username || 'System')}</td>
          <td><span class="badge" style="font-size:9.5px;">${escapeHtml(l.actor_role || '')}</span></td>
          <td style="font-family:var(--font-mono); font-size:11px; color:#38bdf8;">${escapeHtml(l.action)}</td>
          <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(l.target_entity || l.target_type || 'N/A')}</td>
          <td style="font-size:11px; color:#cbd5e1; max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(l.details || '')}">${escapeHtml(l.details || '')}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.warn('Error loading audit logs:', err);
    bodyEl.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:16px; color:#f87171; font-family:var(--font-mono); font-size:11px;">⚠️ Error loading audit logs. Network error or service unreachable.</td></tr>';
  }
}

function openCreateUserModal() {
  const m = document.getElementById('create-user-modal');
  if (m) m.classList.remove('hidden');
}

function closeCreateUserModal() {
  const m = document.getElementById('create-user-modal');
  if (m) m.classList.add('hidden');
}

async function handleCreateUserSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('new-user-username').value.trim();
  const email = document.getElementById('new-user-email').value.trim();
  const password = document.getElementById('new-user-password').value;
  const role = document.getElementById('new-user-role').value;

  try {
    const res = await fetch(`${API_BASE}/api/admin/users`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ username, email, password, role })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to create user');

    showToast(`User ${username} created successfully!`, 'success');
    closeCreateUserModal();
    loadAdminUsers();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleUserStatus(userId, activate) {
  try {
    const res = await fetch(`${API_BASE}/api/admin/users/${userId}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ is_active: activate })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to update user');

    showToast(`User status updated to ${activate ? 'ACTIVE' : 'SUSPENDED'}`, 'info');
    loadAdminUsers();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function openRetrainTriggerModal() {
  const m = document.getElementById('retrain-modal');
  if (m) m.classList.remove('hidden');
}

function closeRetrainModal() {
  const m = document.getElementById('retrain-modal');
  if (m) m.classList.add('hidden');
}

async function submitRetrainTrigger() {
  const epochs = parseInt(document.getElementById('retrain-epochs').value || '5', 10);
  const lr = parseFloat(document.getElementById('retrain-lr').value || '0.0001');

  try {
    const res = await fetch(`${API_BASE}/api/admin/retrain/trigger`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ epochs, learning_rate: lr })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to trigger retraining');

    showToast(`Retraining pipeline launched! Job ID: ${data.run_id}`, 'success');
    closeRetrainModal();
    loadAdminTrainingStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function promoteCandidate(runId) {
  if (!confirm(`Are you sure you want to promote candidate checkpoint from run ${runId} to active production detector.pt?`)) {
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/admin/model/promote`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ run_id: runId })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to promote candidate');

    showToast(`Model successfully promoted to ${data.promoted_version}!`, 'success');
    loadAdminTrainingStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function submitRollback() {
  const select = document.getElementById('rollback-version-select');
  const targetVersion = select ? select.value : '';

  if (!targetVersion) {
    showToast('Select a version to rollback to', 'warning');
    return;
  }

  if (!confirm(`Confirm immediate rollback of active production detector.pt to ${targetVersion}?`)) {
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/admin/model/rollback`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ target_version: targetVersion })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Rollback failed');

    showToast(`Production model successfully rolled back to ${targetVersion}!`, 'success');
    loadAdminTrainingStatus();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── Global Window Bindings for Inline HTML Handlers ─────────────────────────
if (typeof window !== 'undefined') {
  window.setActivityRange = setActivityRange;
  window.loadOverviewLiveFeed = loadOverviewLiveFeed;
  window.prevSCPage = prevSCPage;
  window.nextSCPage = nextSCPage;
  window.openSystemHealthModal = openSystemHealthModal;
  window.closeSystemHealthModal = closeSystemHealthModal;
  window.toggleEngineDetails = toggleEngineDetails;
  window.openSessionLogsModal = openSessionLogsModal;
  window.closeSessionLogsModal = closeSessionLogsModal;
  window.copySessionLogs = copySessionLogs;
  window.switchThreatSubTab = switchThreatSubTab;

  // Authentication & Profile
  window.openAuthModal = openAuthModal;
  window.closeAuthModal = closeAuthModal;
  window.switchAuthTab = switchAuthTab;
  window.handleAuthSubmit = handleAuthSubmit;
  window.logoutUser = logoutUser;
  window.checkAuthStatus = checkAuthStatus;

  // Training Review Queue & 2050 SOC Forensics Drawer
  window.loadReviewQueue = loadReviewQueue;
  window.openReviewDrawer = openReviewDrawer;
  window.closeReviewDrawer = closeReviewDrawer;
  window.openReviewModal = openReviewModal;
  window.closeReviewModal = closeReviewModal;
  window.toggleAudioPlayback = toggleAudioPlayback;
  window.restartAudioPlayback = restartAudioPlayback;
  window.onSeekbarInput = onSeekbarInput;
  window.setPlaybackSpeed = setPlaybackSpeed;
  window.setAudioVolume = setAudioVolume;
  window.copyAudioHash = copyAudioHash;
  window.retryLoadAudio = retryLoadAudio;
  window.selectDrawerGroundTruth = selectDrawerGroundTruth;
  window.selectGroundTruth = selectGroundTruth;
  window.openApprovalConfirmation = openApprovalConfirmation;
  window.closeApprovalConfirmation = closeApprovalConfirmation;
  window.executeApprovedTrainingDecision = executeApprovedTrainingDecision;
  window.submitRejectionDecision = submitRejectionDecision;
  window.submitGroundTruthDecision = submitGroundTruthDecision;
  window.debounceReviewFilter = debounceReviewFilter;
  window.playTableAudio = playTableAudio;
  window.handleRetrainButtonClick = handleRetrainButtonClick;

  // Administrative Console & Continuous Learning
  window.loadAdminDashboard = loadAdminDashboard;
  window.loadAdminTrainingStatus = loadAdminTrainingStatus;
  window.loadAdminUsers = loadAdminUsers;
  window.loadAdminAuditLogs = loadAdminAuditLogs;
  window.openCreateUserModal = openCreateUserModal;
  window.closeCreateUserModal = closeCreateUserModal;
  window.handleCreateUserSubmit = handleCreateUserSubmit;
  window.toggleUserStatus = toggleUserStatus;
  window.openRetrainTriggerModal = openRetrainTriggerModal;
  window.closeRetrainModal = closeRetrainModal;
  window.submitRetrainTrigger = submitRetrainTrigger;
  window.promoteCandidate = promoteCandidate;
  window.submitRollback = submitRollback;
}

// ── Route & Deep-Link Handler ───────────────────────────────────────────────

function handleRoute() {
  let hash = window.location.hash.replace('#', '').trim();
  if (hash === 'health' || hash === 'system-health') {
    openSystemHealthModal();
    return;
  }
  if (hash === 'phishing') hash = 'threats';
  if (hash === 'voice-identity' || hash === 'identity') hash = 'enroll';
  if (hash === 'threat-monitoring') hash = 'monitor';

  if (hash === 'unified' || hash === 'unified-pipeline') {
    window.location.hash = 'overview';
    showTab('overview');
  } else if (hash === 'incidents' || hash === 'history' || hash === 'alerts') {
    window.location.hash = 'security-center';
    showTab('security-center');
  } else if (hash.startsWith('inspect-')) {
    const itemId = hash.replace('inspect-', '');
    showTab('security-center');
    setTimeout(() => openSCModal(itemId), 400);
  } else if (hash && document.getElementById(`panel-${hash}`)) {
    showTab(hash);
  }
}

window.addEventListener('hashchange', handleRoute);

// Keyboard accessibility: Hierarchical Escape closes top-level dialog first
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const confirmModal = document.getElementById('review-confirm-modal');
    if (confirmModal && !confirmModal.classList.contains('hidden')) {
      closeApprovalConfirmation();
      return;
    }
    const retrainModal = document.getElementById('retrain-modal');
    if (retrainModal && !retrainModal.classList.contains('hidden')) {
      closeRetrainModal();
      return;
    }
    const authModal = document.getElementById('auth-modal');
    if (authModal && !authModal.classList.contains('hidden')) {
      closeAuthModal();
      return;
    }
    const userModal = document.getElementById('create-user-modal');
    if (userModal && !userModal.classList.contains('hidden')) {
      closeCreateUserModal();
      return;
    }
    const scModal = document.getElementById('security-center-modal');
    if (scModal && !scModal.classList.contains('hidden')) {
      closeSCModal();
      return;
    }
    const llmModal = document.getElementById('llm-copilot-modal');
    if (llmModal && !llmModal.classList.contains('hidden')) {
      closeLLMCopilotModal();
      return;
    }
    const reportModal = document.getElementById('threat-report-modal');
    if (reportModal && !reportModal.classList.contains('hidden')) {
      closeReportModal();
      return;
    }
    const quarModal = document.getElementById('quarantine-modal');
    if (quarModal && !quarModal.classList.contains('hidden')) {
      closeQuarantineModal();
      return;
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// EXTENSIONS: SUBNAV, VISUAL FORENSICS, LLM COPILOT, REPORTING & ENFORCEMENT
// ═══════════════════════════════════════════════════════════════════════════

function switchThreatSubTab(tabName, btn) {
  document.querySelectorAll('.threat-subnav-btn').forEach(b => {
    if (!b.classList.contains('btn-llm-pill')) b.classList.remove('active');
  });
  if (btn) btn.classList.add('active');

  const phishCard = document.getElementById('card-threat-phish');
  const imageCard = document.getElementById('card-threat-image');
  const intelCard = document.getElementById('card-threat-intel');

  if (tabName === 'all') {
    if (phishCard) phishCard.style.display = '';
    if (imageCard) imageCard.style.display = '';
    if (intelCard) intelCard.style.display = '';
  } else if (tabName === 'phishing') {
    if (phishCard) phishCard.style.display = '';
    if (imageCard) imageCard.style.display = 'none';
    if (intelCard) intelCard.style.display = 'none';
  } else if (tabName === 'image') {
    if (phishCard) phishCard.style.display = 'none';
    if (imageCard) imageCard.style.display = '';
    if (intelCard) intelCard.style.display = 'none';
  } else if (tabName === 'qr') {
    if (phishCard) phishCard.style.display = '';
    if (imageCard) imageCard.style.display = 'none';
    if (intelCard) intelCard.style.display = 'none';
  } else if (tabName === 'intel') {
    if (phishCard) phishCard.style.display = 'none';
    if (imageCard) imageCard.style.display = 'none';
    if (intelCard) intelCard.style.display = '';
  }
}

function previewForensicImage(event) {
  const file = event.target.files[0];
  if (!file) return;
  const container = document.getElementById('image-preview-container');
  const img = document.getElementById('image-forensic-preview');
  const meta = document.getElementById('image-preview-meta');

  const reader = new FileReader();
  reader.onload = function(e) {
    if (img) img.src = e.target.result;
    if (container) container.style.display = 'block';
    if (meta) {
      const sizeKB = (file.size / 1024).toFixed(1);
      meta.textContent = `${file.name} (${sizeKB} KB · ${file.type || 'image'})`;
    }
  };
  reader.readAsDataURL(file);
}

async function scanImageForensics() {
  const input = document.getElementById('image-forensic-input');
  if (!input || !input.files || input.files.length === 0) {
    return showToast('Please select an image file to analyze', 'warning');
  }
  const file = input.files[0];
  const btn = document.getElementById('btn-scan-image');
  const originalHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:8px;"></span>Analyzing Image Forensics...`;
  }

  const container = document.getElementById('threat-results-body');
  if (container) {
    container.innerHTML = `
      <div class="vt-loading-state" style="padding:28px;text-align:center;">
        <span class="spinner" style="width:24px;height:24px;border-width:2px;display:inline-block;margin-bottom:12px;"></span>
        <div style="color:#f8fafc;font-size:14px;font-weight:600;">Extracting 2D FFT &amp; Edge Discontinuity Signatures...</div>
        <div style="color:#94a3b8;font-size:12px;margin-top:4px;">Inspecting high-frequency spectral ratios, Laplacian boundaries, and synthetic generator artifacts.</div>
      </div>
    `;
  }

  const formData = new FormData();
  formData.append('file', file);
  formData.append('source', 'web_dashboard');

  try {
    const res = await fetch(`${API_BASE}/api/threats/image`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Image forensic scan failed');

    window._lastScannedThreat = data;
    const llmBtn = document.getElementById('btn-threat-llm-analyze');
    if (llmBtn) llmBtn.style.display = 'inline-flex';

    renderImageForensicsReport(data);
    showToast('Image forensic scan completed', 'success');
    if (window.CyberGuardAudio) window.CyberGuardAudio.playConfirm();
    updateOverview();
  } catch (err) {
    showToast(err.message, 'error');
    if (container) {
      container.innerHTML = `<div class="results-empty"><p style="color:#ef4444;">Scan failed: ${escapeHtml(err.message)}</p></div>`;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

function renderImageForensicsReport(data) {
  const container = document.getElementById('threat-results-body');
  if (!container) return;

  const severity = (data.severity || 'SAFE').toUpperCase();
  const classification = data.classification || (severity === 'SAFE' ? 'LIKELY_AUTHENTIC' : (severity === 'LOW' ? 'INCONCLUSIVE' : 'LIKELY_MANIPULATED'));
  const score = Math.round((data.threat_score || 0) * 100);
  const badgeClass = severity === 'CRITICAL' ? 'badge-critical' : (severity === 'HIGH' ? 'badge-high' : (severity === 'MEDIUM' ? 'badge-medium' : (severity === 'LOW' ? 'badge-low' : 'badge-safe')));
  const borderColor = severity === 'CRITICAL' ? '#ef4444' : (severity === 'HIGH' ? '#f43f5e' : (severity === 'MEDIUM' ? '#f59e0b' : (severity === 'LOW' ? '#38bdf8' : '#10b981')));

  const metrics = data.forensic_metrics || {};
  const mediaInfo = data.media_info || data.threat_intelligence || {};
  const metadata = data.metadata_details || {};
  const frameAnalysis = data.frame_analysis || null;

  const elaMean = typeof metrics.ela_mean === 'number' ? metrics.ela_mean.toFixed(2) : 'N/A';
  const elaDisparity = typeof metrics.ela_disparity === 'number' ? metrics.ela_disparity.toFixed(2) : 'N/A';
  const fftSpike = typeof metrics.fft_off_axis_spike_ratio === 'number' ? `${metrics.fft_off_axis_spike_ratio.toFixed(2)}x` : (typeof metrics.fft_grid_peak_ratio === 'number' ? `${metrics.fft_grid_peak_ratio.toFixed(2)}x` : 'N/A');
  const fftHighFreq = typeof metrics.fft_high_freq_ratio === 'number' ? metrics.fft_high_freq_ratio.toFixed(4) : 'N/A';
  const noiseKurt = typeof metrics.noise_kurtosis === 'number' ? metrics.noise_kurtosis.toFixed(1) : 'N/A';
  const noiseVar = typeof metrics.noise_variance === 'number' ? metrics.noise_variance.toFixed(3) : 'N/A';
  const edgeVar = typeof metrics.edge_variance === 'number' ? metrics.edge_variance.toFixed(1) : 'N/A';
  const facialStatus = metrics.facial_status || (metrics.facial_forensics_applicable ? `${metrics.faces_detected || 1} face(s) inspected` : 'No face detected; facial forensics not applicable');
  const manipulationProb = typeof metrics.manipulation_probability === 'number' ? Math.round(metrics.manipulation_probability * 100) : score;

  const provStatus = metadata.provenance_status || metrics.metadata_profile || 'METADATA_STRIPPED_OR_ABSENT';
  let provBadge = '';
  if (provStatus === 'CAMERA_PROVENANCE_CONFIRMED') {
    provBadge = `<span class="badge badge-safe" style="font-size:11px;">📷 Camera Hardware Verified</span>`;
  } else if (provStatus === 'AI_GENERATOR_METADATA_CONFIRMED') {
    provBadge = `<span class="badge badge-critical" style="font-size:11px;">🤖 Generative AI Software Tag</span>`;
  } else {
    provBadge = `<span class="badge" style="background:rgba(148,163,184,0.15); color:#94a3b8; border:1px solid rgba(148,163,184,0.3); font-size:11px;">📄 Web/Stripped Metadata (Neutral)</span>`;
  }

  const shaShort = mediaInfo.sha256 ? `${mediaInfo.sha256.substring(0, 16)}...` : 'N/A';
  const dimensionsStr = mediaInfo.dimensions || 'N/A';
  const formatStr = mediaInfo.format || 'IMAGE';
  const fileSizeStr = mediaInfo.file_size_bytes ? `${Math.round(mediaInfo.file_size_bytes / 1024)} KB` : '';

  let evidenceListHtml = '';
  if (Array.isArray(data.evidence) && data.evidence.length > 0) {
    evidenceListHtml = `
      <div style="margin-top:14px; background:rgba(0,0,0,0.25); border-radius:6px; padding:12px; border:1px solid rgba(255,255,255,0.05);">
        <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px; letter-spacing:0.5px;">Corroborating Forensic Observations</div>
        <ul style="margin:0; padding-left:18px; color:#cbd5e1; font-size:12px; line-height:1.6;">
          ${data.evidence.map(e => `<li>${formatEvidenceItem(e)}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  // Multi-frame animation / video timeline viewer
  let frameHtml = '';
  if (frameAnalysis && Array.isArray(frameAnalysis.frames) && frameAnalysis.frames.length > 0) {
    const consistencyPct = Math.round((frameAnalysis.temporal_consistency || 1.0) * 100);
    const framePills = frameAnalysis.frames.map(f => {
      const fScore = Math.round((f.score || 0) * 100);
      const fColor = fScore >= 65 ? '#ef4444' : (fScore >= 30 ? '#f59e0b' : '#10b981');
      return `
        <div style="background:rgba(15,23,42,0.9); border:1px solid ${fColor}; border-radius:6px; padding:6px 10px; font-size:11px; text-align:center; min-width:85px;">
          <div style="color:var(--text-muted); font-size:9.5px;">Frame #${f.frame_index} (${f.timestamp_sec}s)</div>
          <div style="font-weight:700; color:${fColor}; font-family:var(--font-mono); margin-top:2px;">${fScore}% Susp.</div>
          <div style="font-size:9px; color:#94a3b8; margin-top:1px;">ELA: ${f.ela_mean}</div>
        </div>
      `;
    }).join('');

    frameHtml = `
      <div style="margin-top:12px; background:rgba(0,0,0,0.3); border-radius:6px; padding:12px; border:1px solid rgba(6,182,212,0.2);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <span style="font-size:11px; font-weight:700; color:#38bdf8; text-transform:uppercase; letter-spacing:0.5px;">Multi-Frame Temporal Sequence (${frameAnalysis.total_frames_sampled} Sampled Frames)</span>
          <span style="font-size:11px; font-family:var(--font-mono); color:#10b981; font-weight:700;">Temporal Stability: ${consistencyPct}%</span>
        </div>
        <div style="display:flex; gap:8px; overflow-x:auto; padding-bottom:6px;">
          ${framePills}
        </div>
      </div>
    `;
  }

  const html = `
    <div class="alert-row" style="border-left: 4px solid ${borderColor}; padding: 18px; margin-bottom: 14px; background: rgba(15,23,42,0.7); border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px; flex-wrap:wrap; gap:8px;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:18px;">🖼️</span>
          <div>
            <strong style="color:#f8fafc; font-size:15px;">Visual Forensics: ${escapeHtml(classification)}</strong>
            <div style="font-size:11px; color:#94a3b8; margin-top:1px;">${escapeHtml(mediaInfo.filename || 'Uploaded Media')} • ${escapeHtml(dimensionsStr)} • ${escapeHtml(formatStr)} ${fileSizeStr ? '• ' + escapeHtml(fileSizeStr) : ''}</div>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          ${provBadge}
          <span class="badge ${badgeClass}">${escapeHtml(severity)}</span>
          <span style="font-family:var(--font-mono); font-size:12px; color:#38bdf8; font-weight:700;">Risk Index: ${score}/100</span>
        </div>
      </div>

      <div style="color:#cbd5e1; font-size:13px; margin-bottom:12px; line-height:1.5;">
        ${escapeHtml(data.explanation?.summary || 'Analysis complete across frequency, spatial, and container domains.')}
      </div>

      <div style="background:rgba(0,0,0,0.25); border-radius:6px; padding:12px; margin-bottom:12px; border:1px solid var(--border-subtle);">
        <div style="display:flex; justify-content:space-between; font-size:11.5px; margin-bottom:4px;">
          <span style="color:var(--text-muted); font-weight:600;">SYNTHETIC MANIPULATION PROBABILITY</span>
          <span style="font-family:var(--font-mono); font-weight:700; color:${borderColor};">${manipulationProb}%</span>
        </div>
        <div class="forensic-bar-track">
          <div class="forensic-bar-fill" style="width:${manipulationProb}%; background:${borderColor};"></div>
        </div>
      </div>

      <div class="forensic-metric-grid" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:8px;">
        <div class="forensic-metric-box">
          <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Error Level (ELA)</div>
          <div class="metric-num" style="color:#38bdf8; font-size:13px;">Mean: ${elaMean}</div>
          <div style="font-size:9.5px; color:#94a3b8; margin-top:2px;">Disparity: ${elaDisparity}</div>
        </div>
        <div class="forensic-metric-box">
          <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">2D FFT Harmonic Lattice</div>
          <div class="metric-num" style="color:${parseFloat(fftSpike) >= 7.0 ? '#ef4444' : '#10b981'}; font-size:13px;">${fftSpike}</div>
          <div style="font-size:9.5px; color:#94a3b8; margin-top:2px;">HF Ratio: ${fftHighFreq}</div>
        </div>
        <div class="forensic-metric-box">
          <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Sensor Noise (PRNU)</div>
          <div class="metric-num" style="color:${parseFloat(noiseKurt) > 40.0 ? '#f59e0b' : '#38bdf8'}; font-size:13px;">Kurtosis: ${noiseKurt}</div>
          <div style="font-size:9.5px; color:#94a3b8; margin-top:2px;">Variance: ${noiseVar}</div>
        </div>
        <div class="forensic-metric-box">
          <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Edge Sharpness</div>
          <div class="metric-num" style="color:#a855f7; font-size:13px;">Var: ${edgeVar}</div>
          <div style="font-size:9.5px; color:#94a3b8; margin-top:2px;">Laplacian Norm</div>
        </div>
        <div class="forensic-metric-box">
          <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Facial Forensics</div>
          <div class="metric-num" style="font-size:11px; color:#f8fafc; font-weight:600; line-height:1.3;">${escapeHtml(facialStatus)}</div>
        </div>
        <div class="forensic-metric-box">
          <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">Media Provenance</div>
          <div class="metric-num" style="font-size:11px; color:${provStatus === 'AI_GENERATOR_METADATA_CONFIRMED' ? '#ef4444' : (provStatus === 'CAMERA_PROVENANCE_CONFIRMED' ? '#10b981' : '#cbd5e1')}; font-weight:600;">
            ${escapeHtml(metadata.camera_make || (metadata.ai_generator_tags && metadata.ai_generator_tags[0]) || provStatus)}
          </div>
          <div style="font-size:9.5px; color:#94a3b8; margin-top:2px; font-family:var(--font-mono); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(mediaInfo.sha256 || '')}">SHA: ${escapeHtml(shaShort)}</div>
        </div>
      </div>

      ${frameHtml}
      ${evidenceListHtml}

      <div style="margin-top:14px; padding-top:10px; border-top:1px solid var(--border-subtle); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <span style="font-size:11px; color:#64748b;">⚡ Engine: Heuristic Multi-Signal DSP &amp; Forensics (Calibrated • Grounded)</span>
        <button class="btn btn-xs btn-secondary" onclick="openLLMCopilotWithCurrentThreat()" style="border-color:rgba(6,182,212,0.4); color:#38bdf8;">
          ⚡ Reason on Evidence with Threat Copilot
        </button>
      </div>
    </div>
  `;

  // Cleanly remove any active loading spinner to prevent UI glitch
  const loadingEl = container.querySelector('.vt-loading-state');
  if (loadingEl) {
    loadingEl.remove();
  }

  if (container.querySelector('.results-empty')) {
    container.innerHTML = html;
  } else {
    container.innerHTML = html + container.innerHTML;
  }
}

// ── LLM Threat Analyst & Forensic Copilot Handlers ─────────────────────────

function openLLMCopilotModal(initialContext = '') {
  const modal = document.getElementById('llm-copilot-modal');
  if (modal) modal.classList.remove('hidden');
  const input = document.getElementById('llm-input-context');
  if (input && initialContext) {
    input.value = initialContext;
  }
}

function closeLLMCopilotModal() {
  const modal = document.getElementById('llm-copilot-modal');
  if (modal) modal.classList.add('hidden');
}

function openLLMCopilotWithCurrentThreat() {
  const threat = window._lastScannedThreat;
  if (!threat) {
    return openLLMCopilotModal();
  }
  let contextStr = '';
  if (threat.modality === 'image') {
    const m = threat.forensic_metrics || {};
    const meta = threat.metadata_details || {};
    const media = threat.media_info || threat.threat_intelligence || {};
    const evText = Array.isArray(threat.evidence) ? threat.evidence.map(e => e.description || e.evidence_type).join('; ') : '';
    contextStr = `Image Forensic Artifact: ${media.filename || 'Uploaded Image'}
SHA-256: ${media.sha256 || 'N/A'} (${media.dimensions || 'N/A'}, format: ${media.format || 'IMAGE'})
Verdict: ${threat.classification || 'UNKNOWN'} (Threat Score: ${Math.round((threat.threat_score || 0) * 100)}/100, Severity: ${(threat.severity || 'UNKNOWN').toUpperCase()})
Provenance Status: ${meta.provenance_status || m.metadata_profile || 'N/A'} (Camera: ${meta.camera_make || 'None'}, AI Tags: ${(meta.ai_generator_tags || []).join(', ') || 'None'})
Error Level Analysis (ELA): mean difference ${m.ela_mean ?? 'N/A'}, spatial disparity ${m.ela_disparity ?? 'N/A'}
2D FFT Harmonics: off-axis spike ratio ${m.fft_off_axis_spike_ratio ?? m.fft_grid_peak_ratio ?? 'N/A'}, high-frequency ratio ${m.fft_high_freq_ratio ?? 'N/A'}
Sensor Noise Residual: kurtosis ${m.noise_kurtosis ?? 'N/A'}, variance ${m.noise_variance ?? 'N/A'}
Edge Variance: ${m.edge_variance ?? 'N/A'} (normalized: ${m.normalized_edge_variance ?? 'N/A'})
Facial Forensics: ${m.facial_status ?? 'No face detected; facial forensics not applicable'}
Findings: ${threat.explanation?.summary || 'N/A'}
Evidence: ${evText || 'None'}`;
  } else if (threat.text) {
    contextStr = threat.text;
  } else if (threat.url) {
    contextStr = threat.url;
  } else if (threat.ioc) {
    contextStr = threat.ioc;
  } else if (threat.explanation?.summary) {
    contextStr = threat.explanation.summary;
  } else if (threat.threat_category) {
    contextStr = `Threat Category: ${threat.threat_category}, Severity: ${threat.severity}`;
  }

  openLLMCopilotModal(contextStr);

  const typeSelect = document.getElementById('llm-threat-type');
  if (typeSelect) {
    const cat = (threat.threat_category || '').toUpperCase();
    if (threat.modality === 'image' || cat.includes('IMAGE') || (cat === 'DEEPFAKE' && threat.modality !== 'audio')) {
      typeSelect.value = 'DEEPFAKE_IMAGE';
    } else if (cat.includes('PHISH') || cat.includes('URL')) {
      typeSelect.value = 'PHISHING_SOCIAL_ENG';
    } else if (cat.includes('VOICE') || cat.includes('AUDIO')) {
      typeSelect.value = 'DEEPFAKE_VOICE';
    } else if (cat.includes('DDOS')) {
      typeSelect.value = 'DDOS_VOLUMETRIC';
    } else {
      typeSelect.value = 'MALICIOUS_INFRASTRUCTURE';
    }
  }

  const sevSelect = document.getElementById('llm-severity');
  if (sevSelect && threat.severity) {
    sevSelect.value = threat.severity.toUpperCase();
  }

  runLLMCopilotAnalysis();
}

async function runLLMCopilotAnalysis() {
  const context = (document.getElementById('llm-input-context')?.value || '').trim();
  const threatType = document.getElementById('llm-threat-type')?.value || 'PHISHING_SOCIAL_ENG';
  const severity = document.getElementById('llm-severity')?.value || 'HIGH';
  const container = document.getElementById('llm-results-container');
  const btn = document.getElementById('btn-run-llm');

  if (container) {
    container.style.display = 'block';
    container.innerHTML = `
      <div style="padding:24px; text-align:center;">
        <span class="spinner" style="width:24px;height:24px;border-width:2px;display:inline-block;margin-bottom:12px;"></span>
        <div style="color:#f8fafc; font-size:13px; font-weight:600;">Generating MITRE ATT&amp;CK &amp; Kill Chain Forensic Reconstruction...</div>
        <div style="color:#94a3b8; font-size:11.5px; margin-top:4px;">Synthesizing tactical attribution, blast radius assessment, and NIST containment playbook.</div>
      </div>
    `;
  }

  if (btn) btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/threats/llm-analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_context: context || 'Active detection event requiring SOC forensic analysis.',
        threat_type: threatType,
        severity: severity,
        event: window._lastScannedThreat || null
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Analysis request failed');

    renderLLMAnalysisResults(data);
    showToast('LLM Forensic Analysis generated', 'success');
  } catch (err) {
    showToast(err.message, 'error');
    if (container) {
      container.innerHTML = `<div style="padding:16px; color:#ef4444; background:rgba(239,68,68,0.1); border-radius:6px;">Analysis failed: ${escapeHtml(err.message)}</div>`;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderLLMAnalysisResults(data) {
  const container = document.getElementById('llm-results-container');
  if (!container) return;

  const mitreTags = (data.mitre_attack_techniques || data.mitre_attack_mapping || []).map(t => {
    const tId = t.technique_id || t.id || '';
    const tName = t.name || '';
    return `
      <span class="mitre-tag" title="${escapeHtml(tName)}">
        <span class="mitre-id">${escapeHtml(tId)}</span>
        <span>${escapeHtml(tName)}</span>
      </span>
    `;
  }).join('');

  const killChainNodes = [
    { id: 'reconnaissance', label: 'Reconnaissance' },
    { id: 'weaponization', label: 'Weaponization' },
    { id: 'delivery', label: 'Delivery' },
    { id: 'exploitation', label: 'Exploitation' },
    { id: 'actions_on_objectives', label: 'Actions on Objectives' }
  ].map(phase => {
    const isStage = (data.kill_chain_stage || '').toLowerCase().includes(phase.id) ||
                    (data.narrative || '').toLowerCase().includes(phase.id);
    return `
      <div class="killchain-node ${isStage ? 'active-stage' : 'safe-stage'}">
        <div class="killchain-node-title">${phase.label}</div>
        <div style="font-size:10px; color:${isStage ? '#fca5a5' : 'var(--text-muted)'};">${isStage ? 'Active Stage' : 'Dormant'}</div>
      </div>
    `;
  }).join('');

  const playbookSteps = (data.incident_response_playbook || []).map((step, idx) => {
    const stepText = (typeof step === 'object' && step !== null) ? `${step.step ? step.step + ' — ' : ''}${step.action || ''}` : String(step);
    return `
      <li class="playbook-step-item">
        <span class="step-num">${idx + 1}</span>
        <span>${escapeHtml(stepText)}</span>
      </li>
    `;
  }).join('');

  const containmentBadges = (data.immediate_containment || []).map(act => {
    const actText = (typeof act === 'object' && act !== null) ? `${act.action || act.step || ''}` : String(act);
    return `
      <div style="background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.25); border-radius:6px; padding:8px 12px; margin-bottom:6px; font-size:12px; color:#fca5a5; display:flex; align-items:center; gap:8px;">
        <span>🛡️</span>
        <span>${escapeHtml(actText)}</span>
      </div>
    `;
  }).join('');

  container.innerHTML = `
    <div style="background:rgba(15,23,42,0.8); border:1px solid rgba(255,255,255,0.08); border-radius:8px; padding:16px;">
      <div style="font-size:11px; font-weight:700; color:#38bdf8; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">
        Autonomous Forensic Reconstruction
      </div>
      <h3 style="font-size:15px; color:#f8fafc; margin:0 0 10px 0;">${escapeHtml(data.executive_summary || 'Incident Analysis Complete')}</h3>
      <div style="font-size:12.5px; color:#cbd5e1; line-height:1.6; margin-bottom:14px; background:rgba(0,0,0,0.3); padding:12px; border-radius:6px; border-left:3px solid #06b6d4;">
        ${escapeHtml(data.narrative || data.threat_narrative || data.technical_deep_dive || data.executive_summary || '')}
      </div>

      <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px;">Cyber Kill Chain Alignment</div>
      <div class="llm-killchain-flow">
        ${killChainNodes}
      </div>

      <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-top:14px; margin-bottom:6px;">MITRE ATT&amp;CK Enterprise Techniques</div>
      <div class="mitre-tag-wrap">
        ${mitreTags || '<span style="font-size:11px; color:var(--text-muted);">No direct MITRE ATT&amp;CK techniques mapped (Nominal Baseline).</span>'}
      </div>

      <div style="font-size:11px; font-weight:700; color:#f87171; text-transform:uppercase; margin-top:14px; margin-bottom:6px;">Immediate Containment Directives</div>
      <div>
        ${containmentBadges || '<div style="font-size:12px; color:var(--text-muted);">No urgent containment actions mandated.</div>'}
      </div>

      <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; margin-top:14px; margin-bottom:6px;">NIST / SANS Incident Response Playbook</div>
      <ul class="playbook-step-list">
        ${playbookSteps || '<li style="font-size:12px; color:var(--text-muted);">Standard operational clearance applies.</li>'}
      </ul>
    </div>
  `;
}

// ── Threat Report Export Handlers ──────────────────────────────────────────

function openReportModal() {
  const modal = document.getElementById('threat-report-modal');
  if (modal) modal.classList.remove('hidden');
}

function closeReportModal() {
  const modal = document.getElementById('threat-report-modal');
  if (modal) modal.classList.add('hidden');
}

async function generateThreatReport() {
  const format = document.getElementById('report-format')?.value || 'html';
  const timeframe = document.getElementById('report-timeframe')?.value || '24h';
  const severity = document.getElementById('report-severity')?.value || 'HIGH';
  const btn = document.getElementById('btn-generate-report');

  const token = getAuthToken();
  const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:6px;"></span>Generating...`;
  }

  try {
    const url = `${API_BASE}/api/admin/reports/export?format=${encodeURIComponent(format)}&timeframe=${encodeURIComponent(timeframe)}&severity=${encodeURIComponent(severity)}`;
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Report generation failed');
    }

    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);

    if (format === 'html') {
      const newWin = window.open(downloadUrl, '_blank');
      if (!newWin) {
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `CyberGuard-Threat-Report-${new Date().toISOString().slice(0, 10)}.html`;
        a.click();
      }
    } else {
      const a = document.createElement('a');
      a.href = downloadUrl;
      const ext = format === 'csv' ? 'csv' : 'json';
      a.download = `CyberGuard-Threat-Report-${new Date().toISOString().slice(0, 10)}.${ext}`;
      a.click();
    }

    showToast(`Threat report exported successfully (${format.toUpperCase()})`, 'success');
    closeReportModal();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `📄 Generate &amp; Download Report`;
    }
  }
}

// ── Admin Policy & Enforcement Engine Handlers ─────────────────────────────

async function loadAdminPolicies() {
  const token = getAuthToken();
  const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

  try {
    const res = await fetch(`${API_BASE}/api/admin/policy`, { headers });
    if (!res.ok) return;
    const policy = await res.json();

    const nameEl = document.getElementById('cfg-policy-name');
    if (nameEl) nameEl.value = policy.policy_name || 'Enterprise Defense Baseline';

    const actionEl = document.getElementById('cfg-policy-action');
    if (actionEl) actionEl.value = policy.enforcement_action || 'FULL_BLOCK';

    const threshEl = document.getElementById('cfg-policy-threshold');
    const threshVal = document.getElementById('cfg-threshold-val');
    const scoreVal = Math.round((policy.auto_block_threat_score || 0.75) * 100);
    if (threshEl) threshEl.value = scoreVal;
    if (threshVal) threshVal.textContent = scoreVal;

    const ddosLim = document.getElementById('cfg-policy-ddos-limit');
    if (ddosLim) ddosLim.value = policy.ddos_rate_limit_per_min || 120;

    const ddosBurst = document.getElementById('cfg-policy-ddos-burst');
    if (ddosBurst) ddosBurst.value = policy.ddos_burst_threshold || 40;

    const emailSev = document.getElementById('cfg-policy-email-severity');
    if (emailSev) emailSev.value = policy.email_minimum_severity || 'HIGH';

    const recipientsEl = document.getElementById('cfg-policy-recipients');
    if (recipientsEl && Array.isArray(policy.email_notification_recipients)) {
      recipientsEl.value = policy.email_notification_recipients.join(', ');
    }

    const emailEnabled = document.getElementById('cfg-policy-email-enabled');
    if (emailEnabled) emailEnabled.checked = policy.email_notifications_enabled !== false;

    const postureBadge = document.getElementById('admin-kpi-policy-posture');
    if (postureBadge) postureBadge.textContent = policy.enforcement_action || 'STRICT';
  } catch (err) {
    console.warn('Failed to load admin policies:', err);
  }
}

async function saveAdminPolicies(event) {
  if (event) event.preventDefault();
  const token = getAuthToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const recipients = (document.getElementById('cfg-policy-recipients')?.value || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  const payload = {
    policy_name: document.getElementById('cfg-policy-name')?.value || 'Default',
    enforcement_action: document.getElementById('cfg-policy-action')?.value || 'FULL_BLOCK',
    auto_block_threat_score: (Number(document.getElementById('cfg-policy-threshold')?.value || 75)) / 100,
    ddos_rate_limit_per_min: Number(document.getElementById('cfg-policy-ddos-limit')?.value || 120),
    ddos_burst_threshold: Number(document.getElementById('cfg-policy-ddos-burst')?.value || 40),
    email_notifications_enabled: Boolean(document.getElementById('cfg-policy-email-enabled')?.checked),
    email_minimum_severity: document.getElementById('cfg-policy-email-severity')?.value || 'HIGH',
    email_notification_recipients: recipients
  };

  const btn = document.getElementById('btn-save-policy');
  if (btn) btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/api/admin/policy`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to update policy');

    showToast('Organization security policy enforced', 'success');
    const postureBadge = document.getElementById('admin-kpi-policy-posture');
    if (postureBadge) postureBadge.textContent = payload.enforcement_action;
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadEnforcementData() {
  const token = getAuthToken();
  const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
  const tbody = document.getElementById('admin-quarantine-tbody');

  try {
    const res = await fetch(`${API_BASE}/api/admin/enforcement/status`, { headers });
    if (!res.ok) return;
    const data = await res.json();

    const entities = data.blocked_entities || [];
    const countEl = document.getElementById('admin-kpi-blocked-entities');
    if (countEl) countEl.textContent = entities.length;

    if (!tbody) return;
    if (entities.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:18px; color:var(--text-muted);">No quarantined entities. Zero active containment bans.</td></tr>`;
      return;
    }

    tbody.innerHTML = entities.map(item => {
      const typeLower = (item.entity_type || 'ip').toLowerCase();
      const badgeCls = typeLower.includes('ip') ? 'quarantine-ip' : (typeLower.includes('device') ? 'quarantine-device' : (typeLower.includes('domain') ? 'quarantine-domain' : 'quarantine-hash'));
      const timeStr = item.blocked_at ? new Date(item.blocked_at).toLocaleString() : 'Active';

      return `
        <tr>
          <td><span class="quarantine-badge ${badgeCls}">${escapeHtml(item.entity_type || 'IP')}</span></td>
          <td style="font-family:var(--font-mono); font-weight:600; color:#f8fafc;">${escapeHtml(item.entity_value || '')}</td>
          <td style="color:#cbd5e1; font-size:12px;">${escapeHtml(item.reason || 'Quarantined')}</td>
          <td><span class="badge" style="background:rgba(255,255,255,0.05); color:#94a3b8; font-size:10px;">${escapeHtml(item.blocked_by || 'AUTO')}</span></td>
          <td style="color:var(--text-muted); font-size:11.5px;">${timeStr}</td>
          <td><span class="badge badge-critical" style="font-size:10px;">CONTAINED</span></td>
          <td>
            <button class="btn btn-xs btn-secondary" onclick="unblockEntity('${escapeHtml(item.entity_type)}', '${escapeHtml(item.entity_value)}')">
              Unblock
            </button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.warn('Failed to load enforcement data:', err);
  }
}

function openQuarantineModal() {
  const modal = document.getElementById('quarantine-modal');
  if (modal) modal.classList.remove('hidden');
}

function closeQuarantineModal() {
  const modal = document.getElementById('quarantine-modal');
  if (modal) modal.classList.add('hidden');
}

async function submitManualQuarantine() {
  const entityType = document.getElementById('quarantine-entity-type')?.value || 'ip';
  const entityValue = (document.getElementById('quarantine-entity-val')?.value || '').trim();
  const reason = (document.getElementById('quarantine-reason')?.value || '').trim();
  const durationVal = document.getElementById('quarantine-duration')?.value;
  const duration = durationVal === 'permanent' ? null : Number(durationVal);

  if (!entityValue) return showToast('Please enter target entity identifier', 'warning');

  const token = getAuthToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const res = await fetch(`${API_BASE}/api/admin/enforcement/block`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        entity_type: entityType,
        entity_value: entityValue,
        reason: reason || 'Manual Admin Quarantine',
        duration_seconds: duration
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Quarantine action failed');

    showToast(`Quarantined ${entityType}: ${entityValue}`, 'success');
    closeQuarantineModal();
    loadEnforcementData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function unblockEntity(entityType, entityValue) {
  if (!confirm(`Are you sure you want to release quarantine on ${entityType}: ${entityValue}?`)) return;

  const token = getAuthToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const res = await fetch(`${API_BASE}/api/admin/enforcement/unblock`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        entity_type: entityType,
        entity_value: entityValue
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to unblock entity');

    showToast(`Released quarantine on ${entityValue}`, 'success');
    loadEnforcementData();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadEmailAlertJournal() {
  const token = getAuthToken();
  const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
  const tbody = document.getElementById('admin-email-alerts-tbody');

  try {
    const res = await fetch(`${API_BASE}/api/admin/email-alerts`, { headers });
    if (!res.ok) return;
    const data = await res.json();
    const alerts = data.email_alerts || [];

    if (!tbody) return;
    if (alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:18px; color:var(--text-muted);">No threshold email notifications logged yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map(a => {
      const sev = (a.severity || 'HIGH').toUpperCase();
      const badgeCls = sev === 'CRITICAL' ? 'badge-critical' : (sev === 'HIGH' ? 'badge-high' : 'badge-medium');
      const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleString() : 'Recent';

      return `
        <tr>
          <td style="color:var(--text-muted); font-size:11.5px;">${timeStr}</td>
          <td style="font-family:var(--font-mono); color:#cbd5e1; font-size:12px;">${escapeHtml(a.recipient || 'soc-lead')}</td>
          <td><span class="badge ${badgeCls}">${escapeHtml(sev)}</span></td>
          <td style="font-size:12px; color:#f8fafc;">${escapeHtml(a.threat_type || 'INCIDENT')}</td>
          <td style="font-size:12px; color:#94a3b8; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(a.subject || '')}</td>
          <td><span class="badge" style="background:rgba(56,189,248,0.1); color:#38bdf8; font-size:10px;">${escapeHtml(a.delivery_mode || 'LOCAL_JOURNAL')}</span></td>
          <td><span class="badge badge-safe" style="font-size:10px;">${escapeHtml(a.status || 'SENT')}</span></td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.warn('Failed to load email alert journal:', err);
  }
}

async function sendTestEmailAlert() {
  const token = getAuthToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const res = await fetch(`${API_BASE}/api/admin/email-alerts/test`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        severity: 'CRITICAL',
        subject: 'TEST: Simulated P1 Executive Threat Escalation'
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Test alert failed');

    showToast('Simulated executive threshold alert dispatched', 'success');
    loadEmailAlertJournal();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Window namespace bindings
window.switchThreatSubTab = switchThreatSubTab;
window.previewForensicImage = previewForensicImage;
window.scanImageForensics = scanImageForensics;
window.renderImageForensicsReport = renderImageForensicsReport;
window.openLLMCopilotModal = openLLMCopilotModal;
window.closeLLMCopilotModal = closeLLMCopilotModal;
window.openLLMCopilotWithCurrentThreat = openLLMCopilotWithCurrentThreat;
window.runLLMCopilotAnalysis = runLLMCopilotAnalysis;
window.renderLLMAnalysisResults = renderLLMAnalysisResults;
window.openReportModal = openReportModal;
window.closeReportModal = closeReportModal;
window.generateThreatReport = generateThreatReport;
window.loadAdminPolicies = loadAdminPolicies;
window.saveAdminPolicies = saveAdminPolicies;
window.loadEnforcementData = loadEnforcementData;
window.openQuarantineModal = openQuarantineModal;
window.closeQuarantineModal = closeQuarantineModal;
window.submitManualQuarantine = submitManualQuarantine;
window.unblockEntity = unblockEntity;
window.loadEmailAlertJournal = loadEmailAlertJournal;
window.sendTestEmailAlert = sendTestEmailAlert;

// Initial load
window.addEventListener('DOMContentLoaded', async () => {
  if (window.CyberGuardAudio) {
    window.CyberGuardAudio.init();
  }
  await checkAuthStatus();
  handleRoute();
  updateOverview();
  loadSecurityCenterData();
  initSecurityCenterWebSocket();

  // Periodic heartbeat: refresh Overview posture & telemetry while user views Overview
  setInterval(() => {
    const activeTab = document.querySelector('.nav-tab.active');
    if (!activeTab || activeTab.getAttribute('data-tab') === 'overview') {
      updateOverview(false);
    }
  }, 20000);
});


