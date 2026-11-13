/* CyberGuard workspace — monitoring, incidents, alerts, voice identity, health.
 * Every value on these pages comes from the backend or the local scan history.
 * Nothing is simulated.
 */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const STORAGE_API = "cyberguard_api_base";
  const STORAGE_TOKEN = "cyberguard_token";
  const STORAGE_HISTORY = "cyberguard_personal_history";

  function apiBase() {
    try {
      const saved = (localStorage.getItem(STORAGE_API) || "").trim();
      if (saved) {
        const cleanSaved = saved.replace(/\/+$/, "");
        if (typeof location !== "undefined" && location.protocol === "https:" && (cleanSaved.startsWith("http://127.0.0.1") || cleanSaved.startsWith("http://localhost"))) {
          const tunnel = (localStorage.getItem("cyberguard_custom_tunnel") || "").trim();
          if (tunnel) return tunnel.replace(/\/+$/, "");
          const cfg = window.__CYBERGUARD_PERSONAL_CONFIG__ || {};
          if (cfg.tunnel_url) return cfg.tunnel_url.replace(/\/+$/, "");
        }
        return cleanSaved;
      }
      const tunnel = (localStorage.getItem("cyberguard_custom_tunnel") || "").trim();
      if (tunnel) return tunnel.replace(/\/+$/, "");
    } catch {}
    const cfg = window.__CYBERGUARD_PERSONAL_CONFIG__ || {};
    if (cfg.api_base) return cfg.api_base.replace(/\/+$/, "");
    if (typeof location !== "undefined" && location.protocol === "https:") {
      return (cfg.tunnel_url || "https://fax-heat-harris-sufficient.trycloudflare.com").replace(/\/+$/, "");
    }
    return "";
  }

  function token() {
    try {
      return String(localStorage.getItem(STORAGE_TOKEN) || "").trim();
    } catch {
      return "";
    }
  }

  function signedIn() {
    return Boolean(token());
  }

  function headers(extra = {}) {
    const t = token();
    return t
      ? { Authorization: `Bearer ${t}`, "X-Session-Token": t, ...extra }
      : { ...extra };
  }

  async function api(path, options = {}) {
    const res = await fetch(apiBase() + path, {
      ...options,
      headers: headers(options.headers || {}),
      credentials: "include"
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { message: text.slice(0, 400) };
    }
    if (!res.ok) {
      const err = new Error(data.detail || data.message || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  const esc = value =>
    String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const fmtTime = value => {
    if (!value) return "—";
    const ms = typeof value === "number" ? (value < 1e12 ? value * 1000 : value) : Date.parse(value);
    if (!Number.isFinite(ms)) return "—";
    return new Date(ms).toLocaleString(undefined, {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit"
    });
  };

  const relTime = ts => {
    const ms = typeof ts === "number" ? (ts < 1e12 ? ts * 1000 : ts) : Date.parse(ts);
    if (!Number.isFinite(ms)) return "";
    const diff = Math.max(0, Date.now() - ms) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  };

  const sevClass = value => {
    const s = String(value || "").toLowerCase();
    if (/critical/.test(s)) return "critical";
    if (/high/.test(s)) return "high";
    if (/medium/.test(s)) return "medium";
    if (/low|safe|info/.test(s)) return "low";
    return "offline";
  };

  function empty(title, message) {
    return `<div class="ops-empty"><b>${esc(title)}</b>${esc(message)}</div>`;
  }

  function gate(message) {
    return `<div class="ops-gate">
      <h3>Sign in to continue</h3>
      <p>${esc(message)}</p>
      <button class="ops-btn primary" type="button" data-open-auth>Sign in</button>
    </div>`;
  }

  function openAuth() {
    const btn = $("#authBtn");
    if (btn) btn.click();
  }

  document.addEventListener("click", event => {
    if (event.target.closest("[data-open-auth]")) openAuth();
  });

  function localHistory() {
    try {
      const list = JSON.parse(localStorage.getItem(STORAGE_HISTORY) || "[]");
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  /* ── Overview: protection strip ───────────────────────────────────────── */
  async function loadOverview() {
    const history = localHistory();
    const localHigh = history.filter(h => h.level === "danger").length;

    let summary = null;
    let health = null;
    try {
      summary = await api("/api/incidents/dashboard/summary");
    } catch {}
    try {
      health = await api("/api/health");
    } catch {}

    const checks = summary && !summary.requires_authentication
      ? summary.total_events_analyzed ?? 0
      : history.length;
    const findings = summary && !summary.requires_authentication
      ? summary.high_critical_threats ?? 0
      : localHigh;

    let meanConf = null;
    if (summary && !summary.requires_authentication) {
      try {
        const events = await api("/api/incidents/events?limit=100");
        const values = (Array.isArray(events) ? events : [])
          .map(e => Number(e.confidence))
          .filter(v => Number.isFinite(v))
          .map(v => (v <= 1 ? v * 100 : v));
        if (values.length) meanConf = values.reduce((a, b) => a + b, 0) / values.length;
      } catch {}
    }

    const engines = health
      ? [
          health.status === "ok",
          health.database === "connected",
          health.detector_ready === true,
          health.threat_intel?.virustotal_configured === true,
          health.threat_intel?.urlhaus_configured === true
        ].filter(Boolean).length
      : null;

    const set = (id, value, cls) => {
      const el = $(`#${id}`);
      if (!el) return;
      el.textContent = value;
      if (cls !== undefined) el.className = cls;
    };

    set("statChecks", checks);
    set("statFindings", findings, findings > 0 ? "warn" : "");
    set("statConfidence", meanConf == null ? "—" : `${Math.round(meanConf)}%`);
    set("statEngines", engines == null ? "—" : `${engines}/5`, engines === 5 ? "ok" : engines === 0 ? "danger" : "");

    let posture = "Normal monitoring";
    let cls = "";
    const critical = summary && !summary.requires_authentication ? summary.critical_threats ?? 0 : 0;
    const open = summary && !summary.requires_authentication ? summary.open_incidents ?? 0 : 0;
    if (critical > 0) {
      posture = `Critical attention · ${critical} critical`;
      cls = "is-danger";
    } else if (findings > 0) {
      posture = `Elevated watch · ${findings} high-risk`;
      cls = "is-warning";
    } else if (open > 0) {
      posture = `${open} open incident${open === 1 ? "" : "s"}`;
      cls = "is-warning";
    } else if (!health) {
      posture = "Backend unreachable";
      cls = "is-danger";
    }
    const postureEl = $("#statPosture");
    if (postureEl) {
      postureEl.textContent = posture;
      postureEl.className = cls;
    }
  }

  /* ── Live monitoring ──────────────────────────────────────────────────── */
  const monitor = { sev: "ALL", events: [], timer: null };

  function renderMonitorFeed() {
    const holder = $("#monitorFeed");
    if (!holder) return;

    if (!signedIn()) {
      holder.innerHTML = gate("Threat events are scoped to an account. Sign in to see your telemetry.");
      return;
    }
    const events = monitor.events.filter(ev => {
      const cls = sevClass(ev.severity);
      if (monitor.sev === "ALL") return true;
      if (monitor.sev === "HIGH") return cls === "critical" || cls === "high";
      if (monitor.sev === "MEDIUM") return cls === "medium";
      return cls === "low";
    });

    if (!events.length) {
      holder.innerHTML = empty("No events in this view", "Run a check, or choose a different severity filter.");
      return;
    }

    holder.innerHTML = `<div class="feed-list">${events.map(ev => {
      const cls = sevClass(ev.severity);
      const title = ev.classification || ev.threat_category || "Threat event";
      const summary = ev.explanation?.summary || ev.details?.summary || ev.source || "Analysed by CyberGuard";
      return `<div class="feed-item">
        <span class="feed-dot ${cls === "critical" || cls === "high" ? cls : ""}"></span>
        <div class="feed-copy">
          <b>${esc(String(title).replace(/_/g, " "))}</b>
          <span title="${esc(summary)}">${esc(summary)}</span>
        </div>
        <span class="feed-time">${esc(relTime(ev.timestamp))}</span>
      </div>`;
    }).join("")}</div>`;
  }

  async function loadMonitoring() {
    let summary = null;
    try {
      summary = await api("/api/incidents/dashboard/summary");
    } catch {}

    const tiles = $("#monitorTiles");
    if (tiles) {
      if (!signedIn() || !summary || summary.requires_authentication) {
        tiles.innerHTML = "";
      } else {
        const data = [
          ["Events analysed", summary.total_events_analyzed ?? 0, "All checks in your scope", ""],
          ["High & critical", summary.high_critical_threats ?? 0, "Require a look", "is-warn"],
          ["Open incidents", summary.open_incidents ?? 0, "Not yet resolved", ""],
          ["Critical threats", summary.critical_threats ?? 0, "Priority containment", "is-warn"]
        ];
        tiles.innerHTML = data.map(([label, value, note, cls]) =>
          `<div class="ops-tile ${cls}"><span>${esc(label)}</span><b>${esc(value)}</b><small>${esc(note)}</small></div>`
        ).join("");
      }
    }

    if (signedIn()) {
      try {
        const events = await api("/api/incidents/events?limit=60");
        monitor.events = Array.isArray(events) ? events : [];
      } catch {
        monitor.events = [];
      }
    } else {
      monitor.events = [];
    }
    renderMonitorFeed();
  }

  /* ── Incidents ────────────────────────────────────────────────────────── */
  const nextStatus = status => {
    const s = String(status || "").toUpperCase();
    if (s === "NEW") return ["INVESTIGATING", "Start review"];
    if (s === "INVESTIGATING") return ["CONTAINED", "Mark contained"];
    if (s === "CONTAINED") return ["RESOLVED", "Resolve"];
    return null;
  };

  async function loadIncidents() {
    const holder = $("#incidentsTable");
    if (!holder) return;
    if (!signedIn()) {
      holder.innerHTML = gate("Incident records are private to the signed-in account.");
      return;
    }
    holder.innerHTML = '<div class="ops-empty">Loading incidents…</div>';
    let rows = [];
    try {
      const data = await api("/api/incidents/?limit=50");
      rows = Array.isArray(data) ? data : [];
    } catch (err) {
      holder.innerHTML = empty("Could not load incidents", err.message);
      return;
    }
    if (!rows.length) {
      holder.innerHTML = empty("No incidents yet", "Correlated findings will appear here when a check raises one.");
      return;
    }

    holder.innerHTML = `<div class="ops-table-wrap"><table class="ops-table">
      <thead><tr>
        <th>Incident</th><th>Category</th><th>Severity</th><th>Status</th><th>First seen</th><th>Action</th>
      </tr></thead>
      <tbody>${rows.map(inc => {
        const ev = Array.isArray(inc.events) && inc.events.length ? inc.events[0] : {};
        const severity = inc.severity || inc.risk_level || ev.severity || "UNKNOWN";
        const sev = sevClass(severity);
        const category = inc.category || inc.threat_category || ev.threat_category || "Security event";
        const status = String(inc.status || "").toUpperCase();
        const step = nextStatus(status);
        return `<tr>
          <td><b>${esc(inc.incident_id || inc.id || "—")}</b></td>
          <td>${esc(String(category).replace(/_/g, " "))}</td>
          <td><span class="ops-chip ${sev}">${esc(severity)}</span></td>
          <td><span class="ops-chip ${status === "RESOLVED" ? "safe" : "medium"}">${esc(status || "NEW")}</span></td>
          <td>${esc(fmtTime(inc.first_seen || inc.created_at || ev.timestamp))}</td>
          <td>${step
            ? `<button class="ops-btn small" data-incident="${esc(inc.incident_id || inc.id)}" data-status="${step[0]}">${step[1]}</button>`
            : '<span class="ops-chip safe">Closed</span>'}</td>
        </tr>`;
      }).join("")}</tbody>
    </table></div>`;
  }

  document.addEventListener("click", async event => {
    const btn = event.target.closest("[data-incident]");
    if (!btn) return;
    btn.disabled = true;
    try {
      await api(`/api/incidents/${encodeURIComponent(btn.dataset.incident)}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: btn.dataset.status })
      });
      await loadIncidents();
      await loadOverview();
    } catch (err) {
      btn.disabled = false;
      alert(err.message || "Could not update the incident.");
    }
  });

  /* ── Alerts ───────────────────────────────────────────────────────────── */
  async function loadAlerts() {
    const holder = $("#alertsList");
    const delivery = $("#deliveryList");
    if (!holder) return;

    if (!signedIn()) {
      holder.innerHTML = gate("Alerts are private to the signed-in account.");
      if (delivery) delivery.innerHTML = "";
      return;
    }

    holder.innerHTML = '<div class="ops-empty">Loading alerts…</div>';
    try {
      const data = await api("/api/alerts/recent?limit=40");
      const alerts = Array.isArray(data.alerts) ? data.alerts : [];
      holder.innerHTML = alerts.length
        ? `<div class="feed-list">${alerts.map(a => {
            const cls = sevClass(a.severity);
            return `<div class="feed-item">
              <span class="feed-dot ${cls === "critical" || cls === "high" ? cls : ""}"></span>
              <div class="feed-copy">
                <b>${esc(a.title || a.message || a.threat_title || "Security alert")}</b>
                <span>${esc(a.session_id ? `Session ${a.session_id}` : a.category || "Detection engine")}</span>
              </div>
              <span class="feed-time">${esc(relTime(a.timestamp || a.created_at))}</span>
            </div>`;
          }).join("")}</div>`
        : empty("No alerts raised", "Alerts appear here when a detection crosses the configured threshold.");
    } catch (err) {
      holder.innerHTML = empty("Could not load alerts", err.message);
    }

    if (!delivery) return;
    try {
      const data = await api("/api/alerts/delivery-history?limit=25");
      const rows = Array.isArray(data.delivery_history) ? data.delivery_history : [];
      delivery.innerHTML = rows.length
        ? `<div class="ops-table-wrap"><table class="ops-table">
            <thead><tr><th>Recipient</th><th>Subject</th><th>Status</th><th>Sent</th></tr></thead>
            <tbody>${rows.map(r => `<tr>
              <td>${esc(r.recipient || "—")}</td>
              <td>${esc(r.subject || r.threat_title || "Security alert")}</td>
              <td><span class="ops-chip ${/sent|delivered|success/i.test(String(r.status)) ? "safe" : "medium"}">${esc(r.status || "queued")}</span></td>
              <td>${esc(fmtTime(r.timestamp || r.sent_at || r.created_at))}</td>
            </tr>`).join("")}</tbody>
          </table></div>`
        : empty("No email notifications yet", "Only HIGH and CRITICAL findings trigger an email, and only to a verified address.");
    } catch (err) {
      delivery.innerHTML = empty("Delivery record unavailable", err.message);
    }
  }

  /* ── Voice identity ───────────────────────────────────────────────────── */
  async function loadIdentity() {
    const holder = $("#speakerList");
    if (!holder) return;
    if (!signedIn()) {
      holder.innerHTML = gate("Voice profiles are private to the signed-in account.");
      return;
    }
    holder.innerHTML = '<div class="ops-empty">Loading voice profiles…</div>';
    try {
      const rows = await api("/api/speakers");
      const list = Array.isArray(rows) ? rows : [];
      holder.innerHTML = list.length
        ? `<div class="ops-table-wrap"><table class="ops-table">
            <thead><tr><th>Name</th><th>Role</th><th class="num">Samples</th><th>Enrolled</th><th>Action</th></tr></thead>
            <tbody>${list.map(sp => `<tr>
              <td><b>${esc(sp.name)}</b></td>
              <td>${esc(sp.role || sp.organization || "—")}</td>
              <td class="num">${esc(sp.num_samples ?? 0)}</td>
              <td>${esc(fmtTime(sp.created_at))}</td>
              <td><button class="ops-btn small" data-speaker="${esc(sp.speaker_id)}">Remove</button></td>
            </tr>`).join("")}</tbody>
          </table></div>`
        : empty("No voices enrolled", "Add three or more samples of a trusted speaker to create a profile.");
    } catch (err) {
      holder.innerHTML = empty("Could not load voice profiles", err.message);
    }
  }

  document.addEventListener("click", async event => {
    const btn = event.target.closest("[data-speaker]");
    if (!btn) return;
    if (!confirm("Remove this voice profile? This cannot be undone.")) return;
    btn.disabled = true;
    try {
      await api(`/api/speakers/${encodeURIComponent(btn.dataset.speaker)}`, { method: "DELETE" });
      await loadIdentity();
    } catch (err) {
      btn.disabled = false;
      alert(err.message || "Could not remove the profile.");
    }
  });

  function wireEnroll() {
    const form = $("#enrollForm");
    if (!form || form.dataset.wired) return;
    form.dataset.wired = "1";
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (!signedIn()) {
        openAuth();
        return;
      }
      const name = $("#enrollName").value.trim();
      const files = $("#enrollSamples").files;
      if (!name || !files.length) return;
      const btn = $("#enrollSubmit");
      btn.disabled = true;
      btn.textContent = "Enrolling…";
      try {
        const body = new FormData();
        body.append("name", name);
        [...files].forEach(file => body.append("files", file));
        await api("/api/speakers/enroll", { method: "POST", body });
        form.reset();
        await loadIdentity();
      } catch (err) {
        alert(err.message || "Enrolment failed.");
      } finally {
        btn.disabled = false;
        btn.textContent = "Enrol voice";
      }
    });
  }

  /* ── System health ────────────────────────────────────────────────────── */
  function kv(label, value, cls = "") {
    return `<div class="kv"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`;
  }

  async function loadHealth() {
    const grid = $("#healthGrid");
    if (!grid) return;
    grid.innerHTML = '<div class="ops-empty">Checking services…</div>';
    const blocks = [];

    try {
      const h = await api("/api/health");
      blocks.push(`<div class="health-block"><h3>Backend</h3>
        ${kv("Service", h.service || "CyberGuard", "good")}
        ${kv("Version", h.version || "—")}
        ${kv("Environment", h.environment || h.backend || "—")}
        ${kv("Database", h.database === "connected" ? "Connected" : String(h.database || "unknown"), h.database === "connected" ? "good" : "bad")}
      </div>`);
      blocks.push(`<div class="health-block"><h3>Detection engines</h3>
        ${kv("Neural detector", h.detector_ready ? "Ready" : "Standby", h.detector_ready ? "good" : "")}
        ${kv("VirusTotal", h.threat_intel?.virustotal_configured ? "Configured" : "Not configured", h.threat_intel?.virustotal_configured ? "good" : "")}
        ${kv("URLhaus", h.threat_intel?.urlhaus_configured ? "Configured" : "Not configured", h.threat_intel?.urlhaus_configured ? "good" : "")}
      </div>`);
    } catch (err) {
      grid.innerHTML = empty("Backend unreachable", err.message);
      return;
    }

    try {
      const status = await api("/api/config/status");
      const caps = status.capabilities || {};
      blocks.push(`<div class="health-block"><h3>Models &amp; pipeline</h3>
        ${kv("Pipeline", status.status || "operational", "good")}
        ${kv("Detector", status.active_detector_version || status.detector_version || "—")}
        ${kv("Detector mode", status.detector_mode || "—")}
        ${kv("Neural weights", status.neural_detector_ready ? "Ready" : "Standby", status.neural_detector_ready ? "good" : "")}
        ${kv("Wav2Vec2", status.wav2vec2_available ? "Available" : "Unavailable", status.wav2vec2_available ? "good" : "")}
        ${kv("ECAPA voice", status.ecapa_available ? "Available" : "Unavailable", status.ecapa_available ? "good" : "")}
        ${kv("Vision forensics", caps.vision_forensics || caps.image_forensics || "verified")}
      </div>`);
    } catch {}

    try {
      const sync = await api("/api/sync/status");
      blocks.push(`<div class="health-block"><h3>Data sync</h3>
        ${kv("Mode", sync.mode || "—")}
        ${kv("Cloud database", sync.cloud_connected ? "Connected" : "Offline", sync.cloud_connected ? "good" : "bad")}
        ${kv("Local database", sync.local_connected ? "Connected" : "Offline", sync.local_connected ? "good" : "bad")}
        ${kv("Last sync", fmtTime(sync.last_sync_timestamp))}
      </div>`);
    } catch {}

    grid.innerHTML = blocks.join("");
    const stamp = $("#healthStamp");
    if (stamp) stamp.textContent = `Checked ${new Date().toLocaleTimeString()}`;
  }

  /* ── Wiring ───────────────────────────────────────────────────────────── */
  const loaders = {
    monitoring: loadMonitoring,
    incidents: loadIncidents,
    alerts: loadAlerts,
    identity: loadIdentity,
    health: loadHealth
  };

  function currentPage() {
    return (location.hash || "#home").replace("#", "") || "home";
  }

  function activate(page) {
    if (page === "home") loadOverview();
    const loader = loaders[page];
    if (loader) loader();
    wireEnroll();
  }

  window.addEventListener("hashchange", () => activate(currentPage()));

  const buttons = {
    monitorRefreshBtn: loadMonitoring,
    incidentsRefreshBtn: loadIncidents,
    alertsRefreshBtn: loadAlerts,
    identityRefreshBtn: loadIdentity,
    healthRefreshBtn: loadHealth
  };
  Object.entries(buttons).forEach(([id, fn]) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("click", () => fn());
  });

  const filter = $("#monitorFilter");
  if (filter) {
    filter.addEventListener("click", event => {
      const btn = event.target.closest("button[data-sev]");
      if (!btn) return;
      $$("button", filter).forEach(b => b.classList.toggle("active", b === btn));
      monitor.sev = btn.dataset.sev;
      renderMonitorFeed();
    });
  }

  if (document.getElementById("page-monitoring")) {
    monitor.timer = setInterval(() => {
      if (currentPage() === "monitoring" && !document.hidden) loadMonitoring();
    }, 20000);
  }

  // Refresh account-scoped views after sign-in.
  const authBtn = $("#authBtn");
  if (authBtn) {
    authBtn.addEventListener("click", () => {
      setTimeout(() => activate(currentPage()), 1200);
    });
  }

  window.addEventListener("cyberguard:activity", () => {
    if (currentPage() === "home") loadOverview();
  });

  const start = () => {
    activate(currentPage());
    loadOverview();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
