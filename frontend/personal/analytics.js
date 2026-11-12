/* CyberGuard — Overview analytics
 * One canvas, one honest dataset: every check the workspace has run is bucketed
 * by time and severity, with mean confidence drawn over it. No external chart
 * library, no invented numbers.
 */
(() => {
  "use strict";

  const canvas = document.getElementById("personalAnalyticsChart");
  const panel = document.getElementById("personalAnalytics");
  if (!canvas || !panel) return;

  const $ = (sel, root = document) => root.querySelector(sel);
  const historyKey = "cyberguard_personal_history";
  const tokenKey = "cyberguard_token";

  const palette = {
    critical: "#B3261E",
    high: "#E6812F",
    medium: "#C9E265",
    low: "#4E9A6A",
    line: "#14532D",
    grid: "#E3EDE0",
    axis: "#6B8272",
    frame: "#14321F"
  };

  const state = { range: "ALL", records: [], hover: null, progress: 0, ready: false };

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function readLocal() {
    try {
      const raw = JSON.parse(localStorage.getItem(historyKey) || "[]");
      if (!Array.isArray(raw)) return [];
      return raw.map(item => {
        const at = new Date(item.at || Date.now()).getTime();
        const level = String(item.level || "unknown");
        const severity =
          level === "danger" ? 2 : level === "warning" ? 1 : level === "safe" ? 0 : 0;
        return {
          at,
          severity,
          confidence: null,
          label: item.verdict || item.type || "Check",
          type: String(item.type || "Check")
        };
      }).filter(r => Number.isFinite(r.at));
    } catch {
      return [];
    }
  }

  function token() {
    try {
      return String(localStorage.getItem(tokenKey) || "").trim();
    } catch {
      return "";
    }
  }

  async function readRemote() {
    if (!token()) return [];
    try {
      const res = await fetch("/api/incidents/events?limit=200", {
        headers: { Authorization: `Bearer ${token()}` },
        credentials: "same-origin"
      });
      if (!res.ok) return [];
      const data = await res.json();
      if (!Array.isArray(data)) return [];
      return data.map(ev => {
        const sev = String(ev.severity || "").toLowerCase();
        const at = ev.timestamp ? Number(ev.timestamp) * 1000 : Date.now();
        const conf = Number(
          ev.confidence ?? ev.score ?? ev.explanation?.confidence ?? NaN
        );
        return {
          at,
          severity: /critical/.test(sev) ? 3 : /high/.test(sev) ? 2 : /medium/.test(sev) ? 1 : 0,
          confidence: Number.isFinite(conf) ? Math.min(100, conf <= 1 ? conf * 100 : conf) : null,
          label: ev.classification || ev.threat_category || "Check",
          type: String(ev.threat_category || ev.classification || "Check")
        };
      }).filter(r => Number.isFinite(r.at));
    } catch {
      return [];
    }
  }

  function mergeRecords(local, remote) {
    const seen = new Set();
    const out = [];
    for (const r of [...remote, ...local]) {
      const key = `${r.at}|${r.label}|${r.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(r);
    }
    return out.sort((a, b) => a.at - b.at);
  }

  function rangeStart(range) {
    if (range === "24H") return Date.now() - 24 * 3600 * 1000;
    if (range === "7D") return Date.now() - 7 * 24 * 3600 * 1000;
    return 0;
  }

  function buckets(records) {
    const start = rangeStart(state.range);
    const rows = records.filter(r => r.at >= start);
    if (!rows.length) return { rows, points: [] };

    const end = Date.now();
    const span = Math.max(end - Math.min(start === 0 ? rows[0].at : start, end), 60_000);
    const count = state.range === "24H" ? 8 : state.range === "7D" ? 7 : 8;
    const size = span / count;

    const points = Array.from({ length: count }, (_, i) => ({
      from: end - span + i * size,
      to: end - span + (i + 1) * size,
      critical: 0, high: 0, medium: 0, low: 0, total: 0, confidence: []
    }));

    rows.forEach(r => {
      let idx = Math.floor((r.at - (end - span)) / size);
      idx = Math.max(0, Math.min(count - 1, idx));
      const p = points[idx];
      if (r.severity === 3) p.critical += 1;
      else if (r.severity === 2) p.high += 1;
      else if (r.severity === 1) p.medium += 1;
      else p.low += 1;
      p.total += 1;
      if (r.confidence != null) p.confidence.push(r.confidence);
    });

    return { rows, points };
  }

  function mean(nums) {
    return nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : null;
  }

  function shortLabel(point, index, count) {
    if (state.range === "7D") {
      return new Date(point.from).toLocaleDateString(undefined, { weekday: "short" });
    }
    if (state.range === "24H") {
      return new Date(point.from).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    }
    if (index === 0) return "earliest";
    if (index === count - 1) return "now";
    const d = new Date(point.from);
    return d.toLocaleDateString(undefined, { day: "2-digit", month: "short" });
  }

  function draw() {
    const rect = canvas.getBoundingClientRect();
    if (!rect.width) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(rect.width * dpr);
    canvas.height = Math.round(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, rect.width, rect.height);

    const W = rect.width;
    const H = rect.height;
    const padL = 34, padR = 40, padT = 16, padB = 26;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;

    const { points } = buckets(state.records);
    const maxTotal = Math.max(1, ...points.map(p => p.total));
    const niceMax = Math.max(4, Math.ceil(maxTotal / 4) * 4);

    // horizontal grid + count axis
    ctx.font = "500 10px 'DM Sans', system-ui, sans-serif";
    ctx.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const y = padT + (plotH / 4) * i;
      ctx.strokeStyle = palette.grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, y + 0.5);
      ctx.lineTo(W - padR, y + 0.5);
      ctx.stroke();
      ctx.fillStyle = palette.axis;
      ctx.textAlign = "right";
      ctx.fillText(String(Math.round(niceMax - (niceMax / 4) * i)), padL - 8, y);
    }

    if (!points.length) {
      ctx.fillStyle = palette.axis;
      ctx.textAlign = "center";
      ctx.font = "500 12px 'DM Sans', system-ui, sans-serif";
      ctx.fillText("No checks recorded in this period yet", padL + plotW / 2, padT + plotH / 2);
      return;
    }

    const slot = plotW / points.length;
    const barW = Math.min(46, slot * 0.52);
    const scale = v => (v / niceMax) * plotH;

    const ease = state.progress;

    points.forEach((p, i) => {
      const cx = padL + slot * i + slot / 2;
      let baseY = padT + plotH;
      const parts = [
        [p.low, palette.low],
        [p.medium, palette.medium],
        [p.high, palette.high],
        [p.critical, palette.critical]
      ];
      parts.forEach(([value, color]) => {
        if (!value) return;
        const h = scale(value) * ease;
        ctx.fillStyle = color;
        const r = Math.min(4, barW / 2, h / 2);
        ctx.beginPath();
        ctx.moveTo(cx - barW / 2, baseY);
        ctx.lineTo(cx - barW / 2, baseY - h + r);
        ctx.quadraticCurveTo(cx - barW / 2, baseY - h, cx - barW / 2 + r, baseY - h);
        ctx.lineTo(cx + barW / 2 - r, baseY - h);
        ctx.quadraticCurveTo(cx + barW / 2, baseY - h, cx + barW / 2, baseY - h + r);
        ctx.lineTo(cx + barW / 2, baseY);
        ctx.closePath();
        ctx.fill();
        baseY -= h;
      });

      ctx.fillStyle = palette.axis;
      ctx.textAlign = "center";
      ctx.font = "500 10px 'DM Sans', system-ui, sans-serif";
      const label = shortLabel(p, i, points.length);
      if (points.length <= 8 || i % 2 === 0) {
        ctx.fillText(label, cx, padT + plotH + 14);
      }
    });

    // mean confidence line (right axis, 0–100)
    const confPoints = points
      .map((p, i) => ({ v: mean(p.confidence), x: padL + slot * i + slot / 2 }))
      .filter(p => p.v != null);
    if (confPoints.length > 1) {
      const yFor = v => padT + plotH - (Math.min(100, Math.max(0, v)) / 100) * plotH * ease;
      ctx.strokeStyle = palette.line;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.setLineDash([6, 5]);
      ctx.beginPath();
      confPoints.forEach((p, i) => {
        const y = yFor(p.v);
        if (i === 0) ctx.moveTo(p.x, y);
        else {
          const prev = confPoints[i - 1];
          const midX = (prev.x + p.x) / 2;
          ctx.bezierCurveTo(midX, yFor(prev.v), midX, y, p.x, y);
        }
      });
      ctx.stroke();
      ctx.setLineDash([]);

      confPoints.forEach(p => {
        const y = yFor(p.v);
        ctx.beginPath();
        ctx.fillStyle = "#FFFFFF";
        ctx.strokeStyle = palette.line;
        ctx.lineWidth = 2;
        ctx.arc(p.x, y, 3.4, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
      });

      const last = confPoints[confPoints.length - 1];
      ctx.fillStyle = palette.line;
      ctx.textAlign = "left";
      ctx.font = "600 10px 'DM Sans', system-ui, sans-serif";
      ctx.fillText(`${Math.round(last.v)}%`, Math.min(W - padR + 6, W - 26), yFor(last.v));
    }

    // hover crosshair
    if (state.hover != null && points[state.hover]) {
      const i = state.hover;
      const x = padL + slot * i + slot / 2;
      ctx.strokeStyle = "rgba(20,50,31,0.18)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, padT);
      ctx.lineTo(x, padT + plotH);
      ctx.stroke();
    }
  }

  function renderParams(rows, points) {
    const holder = $("#personalParamRows");
    if (!holder) return;
    if (!rows.length) {
      holder.innerHTML = '<p class="param-empty">Run your first check to populate this panel.</p>';
      return;
    }

    const flagged = rows.filter(r => r.severity >= 2).length;
    const withConf = rows.map(r => r.confidence).filter(v => v != null);
    const avgConf = mean(withConf);
    const vectors = [...new Set(rows.map(r => r.type).filter(Boolean))];
    const total = rows.length;

    const params = [
      { label: "Checks analysed", value: String(total), meter: 1 },
      { label: "Threats flagged", value: String(flagged), meter: total ? flagged / total : 0, tone: "warn" },
      {
        label: "Average confidence",
        value: avgConf == null ? "—" : `${Math.round(avgConf)}%`,
        meter: avgConf == null ? 0 : avgConf / 100
      },
      { label: "Detection vectors", value: `${vectors.length}`, meter: Math.min(1, vectors.length / 5) }
    ];

    holder.innerHTML = params.map(p => `
      <div class="param-row">
        <div class="param-top"><span>${p.label}</span><b class="${p.tone || ""}">${p.value}</b></div>
        <div class="param-track"><i class="${p.tone || ""}" style="width:${Math.max(4, Math.round(p.meter * 100))}%"></i></div>
      </div>
    `).join("");

    const foot = $("#personalAnalyticsFoot");
    if (foot) {
      const bucketsUsed = points.filter(p => p.total).length;
      foot.textContent = `${total} check${total === 1 ? "" : "s"} across ${bucketsUsed} active interval${bucketsUsed === 1 ? "" : "s"} · ${state.range === "ALL" ? "all time" : state.range.toLowerCase()}`;
    }
  }

  async function renderEngines() {
    const holder = $("#engineList");
    if (!holder) return;
    const rows = [];
    try {
      const res = await fetch("/api/health", { credentials: "same-origin" });
      const h = await res.json();
      rows.push({ label: "Backend service", ok: h.status === "ok" });
      rows.push({ label: "Threat database", ok: h.database === "connected" });
      rows.push({ label: "Neural detector", ok: h.detector_ready === true });
      rows.push({ label: "VirusTotal intel", ok: h.threat_intel?.virustotal_configured === true });
      rows.push({ label: "URLhaus feed", ok: h.threat_intel?.urlhaus_configured === true });
    } catch {
      rows.push({ label: "Backend service", ok: false });
    }
    holder.innerHTML = rows.map(r => `
      <span class="engine-chip ${r.ok ? "on" : "off"}"><i></i>${r.label}</span>
    `).join("");
  }

  function tooltipFor(point, clientX) {
    let tip = $("#analyticsTip");
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "analyticsTip";
      tip.className = "analytics-tip";
      $(".analytics-canvas").appendChild(tip);
    }
    const conf = mean(point.confidence);
    tip.innerHTML = `
      <b>${new Date(point.from).toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</b>
      <span><i style="background:${palette.critical}"></i>Critical ${point.critical}</span>
      <span><i style="background:${palette.high}"></i>High ${point.high}</span>
      <span><i style="background:${palette.medium}"></i>Medium ${point.medium}</span>
      <span><i style="background:${palette.low}"></i>Low / safe ${point.low}</span>
      ${conf == null ? "" : `<span class="tip-mean">Mean confidence ${Math.round(conf)}%</span>`}
    `;
    const box = canvas.parentElement.getBoundingClientRect();
    const left = Math.max(8, Math.min(clientX - box.left - 70, box.width - 150));
    tip.style.left = `${left}px`;
    tip.style.opacity = "1";
  }

  function hideTip() {
    const tip = $("#analyticsTip");
    if (tip) tip.style.opacity = "0";
  }

  function animate() {
    if (reduceMotion) {
      state.progress = 1;
      draw();
      return;
    }
    const start = performance.now();
    const step = now => {
      const t = Math.min(1, (now - start) / 620);
      state.progress = 1 - Math.pow(1 - t, 3);
      draw();
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  async function refresh() {
    const [local, remote] = await Promise.all([Promise.resolve(readLocal()), readRemote()]);
    state.records = mergeRecords(local, remote);
    const { rows, points } = buckets(state.records);
    renderParams(rows, points);
    animate();
    state.ready = true;
    renderEngines();
  }

  panel.addEventListener("click", event => {
    const pill = event.target.closest(".range-pill");
    if (!pill) return;
    $$(".range-pill", panel).forEach(el => el.classList.toggle("active", el === pill));
    state.range = pill.dataset.range || "ALL";
    refresh();
  });

  function $$(sel, root = document) {
    return [...root.querySelectorAll(sel)];
  }

  canvas.addEventListener("mousemove", event => {
    const rect = canvas.getBoundingClientRect();
    const { points } = buckets(state.records);
    if (!points.length) return;
    const slot = (rect.width - 74) / points.length;
    const idx = Math.floor((event.clientX - rect.left - 34) / slot);
    state.hover = idx >= 0 && idx < points.length ? idx : null;
    if (state.hover != null) tooltipFor(points[state.hover], event.clientX);
    else hideTip();
    draw();
  });

  canvas.addEventListener("mouseleave", () => {
    state.hover = null;
    hideTip();
    draw();
  });

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (!state.ready) return;
      state.progress = 1;
      draw();
    }, 140);
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refresh();
  });

  refresh();
  window.addEventListener("storage", event => {
    if (event.key === historyKey) refresh();
  });

  // Refresh the panel after a check is saved from another tab or the same page.
  window.addEventListener("cyberguard:activity", () => refresh());
})();
