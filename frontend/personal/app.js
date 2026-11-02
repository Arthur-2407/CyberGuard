(() => {
  "use strict";

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const CONFIG = window.__CYBERGUARD_PERSONAL_CONFIG__ || {};
  const STORAGE_API = "cyberguard_api_base";
  const STORAGE_HISTORY = "cyberguard_personal_history";
  const STORAGE_TOKEN = "cyberguard_token";

  const knownEndpoints = {
    health: ["/api/health", "/health"],
    url: ["/api/threats/url"],
    file: ["/api/threats/unified"],
    image: ["/api/threats/image"],
    qr: ["/api/threats/qr"],
    audio: ["/api/threats/deepfake"],
    auth_me: "/api/auth/me",
    auth_login: "/api/auth/login",
    auth_register: "/api/auth/register",
    auth_logout: "/api/auth/logout",
    user_events: "/api/incidents/events?limit=30"
  };

  const state = {
    apiBase: "",
    health: "checking",
    currentUser: null,
    selectedFile: null,
    selectedImage: null,
    selectedAudio: null,
    imageMode: "image",
    activeMediaTab: "image"
  };

  const activeRequests = new Set();
  const safeParse = (value, fallback) => { try { return JSON.parse(value) ?? fallback; } catch { return fallback; } };
  const getHistory = () => safeParse(localStorage.getItem(STORAGE_HISTORY), []);
  const setHistory = items => { try { localStorage.setItem(STORAGE_HISTORY, JSON.stringify(items.slice(0, 40))); } catch {} };
  const normalizeBase = value => String(value || "").trim().replace(/\/+$/, "");

  // Resolve backend origin using verified precedence across local and deployed environments
  function getBase() {
    const params = new URLSearchParams(location.search);
    const query = params.get("api_base") || params.get("backend_url");
    if (query) {
      const clean = normalizeBase(query);
      try { localStorage.setItem(STORAGE_API, clean); } catch {}
      return clean;
    }

    // 1. Saved custom override in personal settings
    try {
      const saved = localStorage.getItem(STORAGE_API);
      if (saved && saved.trim()) return normalizeBase(saved);
      const legacy = localStorage.getItem("cyberguard_personal_api_base");
      if (legacy && legacy.trim()) return normalizeBase(legacy);
    } catch {}

    // 2. Localhost / Loopback: ALWAYS use local port/origin (never default to remote cloud)
    if (typeof location !== "undefined" && (location.hostname === "localhost" || location.hostname === "127.0.0.1" || location.hostname === "0.0.0.0")) {
      const port = (location.port && location.port !== "") ? location.port : "3000";
      return (location.port === "3000" || location.port === "8000") ? "" : `http://127.0.0.1:${port}`;
    }

    // 3. Vercel deployment: relative requests proxied by vercel.json
    if (typeof location !== "undefined" && location.hostname.includes("vercel.app")) {
      return "";
    }

    // 4. Custom Cloudflare Tunnel or explicit connection mode
    try {
      const custom = localStorage.getItem("cyberguard_custom_tunnel");
      if (custom && custom.trim()) return normalizeBase(custom);
      const mode = localStorage.getItem("cyberguard_connection_mode");
      if (mode === "hybrid") {
        const active = localStorage.getItem("cyberguard_hybrid_active_base");
        if (active && active.trim()) return normalizeBase(active);
      }
    } catch {}

    if (CONFIG.api_base) return normalizeBase(CONFIG.api_base);
    return "https://cyberguard-backend-8rbz.onrender.com";
  }

  state.apiBase = getBase();
  const apiUrl = path => state.apiBase + path;

  function getAuthToken() {
    try {
      let token = localStorage.getItem(STORAGE_TOKEN) || localStorage.getItem("cg_token") || sessionStorage.getItem(STORAGE_TOKEN) || "";
      return String(token).trim().replace(/^Bearer\s+/i, "").replace(/^["']|["']$/g, "");
    } catch { return ""; }
  }

  function setAuthToken(token) {
    try {
      if (token) {
        localStorage.setItem(STORAGE_TOKEN, token);
      } else {
        localStorage.removeItem(STORAGE_TOKEN);
        localStorage.removeItem("cg_token");
        sessionStorage.removeItem(STORAGE_TOKEN);
      }
    } catch {}
  }

  function sharedAuthHeaders() {
    const token = getAuthToken();
    return token ? { Authorization: "Bearer " + token, "X-Session-Token": token } : {};
  }

  async function request(path, options = {}) {
    const controller = new AbortController();
    activeRequests.add(controller);
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 60000);
    try {
      const response = await fetch(apiUrl(path), {
        ...options,
        headers: { ...sharedAuthHeaders(), ...(options.headers || {}) },
        signal: controller.signal,
        credentials: "include"
      });
      const text = await response.text();
      let data;
      try { data = text ? JSON.parse(text) : {}; } catch { data = { message: text.slice(0, 500) }; }

      if (!response.ok) {
        // If unauthorized and not an auth submission, sync logout state
        if (response.status === 401 && !path.includes("/api/auth/login") && !path.includes("/api/auth/register")) {
          if (state.currentUser) {
            handleSessionExpired();
          }
        }
        const err = new Error(data.detail || data.message || data.error || ("Request failed (" + response.status + ")"));
        err.status = response.status;
        err.data = data;
        throw err;
      }
      return data;
    } finally {
      clearTimeout(timeout);
      activeRequests.delete(controller);
    }
  }

  function toast(message, type = "info") {
    const el = $("#toast");
    if (!el) return;
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => el.classList.remove("show"), 3200);
  }

  function setConnection(status, detail) {
    state.health = status;
    const pill = $("#connectionState"), settings = $("#settingsConnection"), title = $("#overviewStatus"), sub = $("#overviewSubstatus"), tag = $("#statusTag");
    if (pill) {
      pill.classList.toggle("online", status === "online");
      pill.classList.toggle("offline", status === "offline");
      const span = pill.querySelector("span");
      if (span) span.textContent = status === "online" ? "Backend connected" : status === "offline" ? "Backend unavailable" : "Checking connection";
    }
    if (settings) {
      settings.textContent = status === "online" ? "Connected" : status === "offline" ? "Unavailable" : "Checking";
    }
    if (title) {
      title.textContent = status === "online" ? "CyberGuard is connected" : status === "offline" ? "Could not reach CyberGuard" : "Checking your connection";
    }
    if (sub) {
      sub.textContent = detail || (status === "online" ? "Live backend connection confirmed." : "Results will be available when a backend can be reached.");
    }
    if (tag) {
      tag.textContent = status === "online" ? "CONNECTED" : status === "offline" ? "OFFLINE" : "CONNECTING";
    }
  }

  async function checkHealth() {
    setConnection("checking", "Testing backend reachability...");
    let lastError;
    const progressTimer = setTimeout(() => {
      if (state.health === "checking") {
        setConnection("checking", "Waking up cloud backend instance (this may take a few moments)...");
      }
    }, 2500);

    for (const path of knownEndpoints.health) {
      try {
        const data = await request(path, { method: "GET", timeoutMs: 8000 });
        clearTimeout(progressTimer);
        const envLabel = data.backend || (data.status === "ok" ? "active" : "connected");
        setConnection("online", `Live CyberGuard backend confirmed (${envLabel}).`);
        return data;
      } catch (e) {
        lastError = e;
        if (e.status && e.status !== 404 && e.status !== 405) break;
      }
    }
    clearTimeout(progressTimer);
    setConnection("offline", lastError ? "Connection check failed: " + lastError.message : "No health endpoint responded.");
    return null;
  }

  // Authentication Management
  async function checkAuth() {
    try {
      const user = await request(knownEndpoints.auth_me, { method: "GET" });
      if (user && user.username) {
        state.currentUser = user;
        updateAuthUI();
        loadUserActivity();
        return user;
      }
    } catch (_) {}
    state.currentUser = null;
    updateAuthUI();
    renderLocalHistory();
    return null;
  }

  function updateAuthUI() {
    const btnText = $("#authBtnText");
    const authBtn = $("#authBtn");
    const pill = $("#authPill");
    const settingsDesc = $("#settingsAccountDesc");
    const settingsBtn = $("#settingsAuthActionBtn");

    if (state.currentUser) {
      const u = state.currentUser;
      const roleStr = (u.role || "user").toUpperCase();
      if (btnText) btnText.textContent = `${u.username} (${roleStr})`;
      if (authBtn) {
        authBtn.classList.add("logged-in");
        authBtn.setAttribute("title", `Signed in as ${u.username}. Click to view account or sign out.`);
      }
      if (settingsDesc) settingsDesc.textContent = `Signed in as ${u.username} (${u.email || "No email"}). Connected to tenant database.`;
      if (settingsBtn) {
        settingsBtn.textContent = "Account & Sign Out";
        settingsBtn.style.color = "#b91c1c";
      }
    } else {
      if (btnText) btnText.textContent = "Sign In";
      if (authBtn) {
        authBtn.classList.remove("logged-in");
        authBtn.setAttribute("title", "Sign in to your CyberGuard account");
      }
      if (settingsDesc) settingsDesc.textContent = "Sign in to sync your verified scan records with your CyberGuard account.";
      if (settingsBtn) {
        settingsBtn.textContent = "Sign In";
        settingsBtn.style.color = "";
      }
    }
  }

  function openAuthModal(initialTab = "login") {
    const modal = $("#authModal");
    if (!modal) return;
    const formView = $("#authFormView");
    const profileView = $("#authProfileView");
    const errAlert = $("#authErrorMsg");
    if (errAlert) { errAlert.textContent = ""; errAlert.classList.remove("show"); }

    if (state.currentUser) {
      if (formView) formView.style.display = "none";
      if (profileView) profileView.style.display = "block";
      const u = state.currentUser;
      $("#profileUsername").textContent = u.username || "-";
      $("#profileEmail").textContent = u.email || "-";
      $("#profileRole").textContent = (u.role || "user").toUpperCase();
      $("#profileSpace").textContent = u.db_path || `user_${u.id}.db`;
    } else {
      if (formView) formView.style.display = "block";
      if (profileView) profileView.style.display = "none";
      switchAuthTab(initialTab);
    }
    modal.classList.add("open");
  }

  function closeAuthModal() {
    const modal = $("#authModal");
    if (modal) modal.classList.remove("open");
  }

  function switchAuthTab(tab) {
    const tabLog = $("#tabLogin");
    const tabReg = $("#tabRegister");
    const logForm = $("#loginForm");
    const regForm = $("#registerForm");
    const title = $("#modalTitle");
    const subtitle = $("#modalSubtitle");
    const errAlert = $("#authErrorMsg");
    if (errAlert) { errAlert.textContent = ""; errAlert.classList.remove("show"); }

    if (tab === "register") {
      tabLog?.classList.remove("active");
      tabReg?.classList.add("active");
      if (logForm) logForm.style.display = "none";
      if (regForm) regForm.style.display = "grid";
      if (title) title.textContent = "Create an Account";
      if (subtitle) subtitle.textContent = "Create your isolated personal security space.";
    } else {
      tabReg?.classList.remove("active");
      tabLog?.classList.add("active");
      if (regForm) regForm.style.display = "none";
      if (logForm) logForm.style.display = "grid";
      if (title) title.textContent = "Sign In to CyberGuard";
      if (subtitle) subtitle.textContent = "Access your isolated personal security space.";
    }
  }

  async function handleLoginSubmit(e) {
    e.preventDefault();
    const username = $("#loginUsername")?.value.trim();
    const password = $("#loginPassword")?.value;
    const submitBtn = $("#loginSubmitBtn");
    const errAlert = $("#authErrorMsg");

    if (!username || !password) {
      if (errAlert) { errAlert.textContent = "Please provide both username and password."; errAlert.classList.add("show"); }
      return;
    }

    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = "<span>Signing in…</span>"; }
    try {
      const res = await request(knownEndpoints.auth_login, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      if (res && res.token) {
        setAuthToken(res.token);
        state.currentUser = res.user || { username };
        updateAuthUI();
        closeAuthModal();
        toast(`Signed in successfully as ${state.currentUser.username}`);
        loadUserActivity();
        checkHealth();
      }
    } catch (err) {
      if (errAlert) {
        errAlert.textContent = err.message || "Failed to sign in. Verify your credentials.";
        errAlert.classList.add("show");
      }
    } finally {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = "<span>Sign In</span>"; }
    }
  }

  async function handleRegisterSubmit(e) {
    e.preventDefault();
    const username = $("#regUsername")?.value.trim();
    const email = $("#regEmail")?.value.trim();
    const password = $("#regPassword")?.value;
    const submitBtn = $("#regSubmitBtn");
    const errAlert = $("#authErrorMsg");

    if (!username || !password || !email) {
      if (errAlert) { errAlert.textContent = "All fields are required."; errAlert.classList.add("show"); }
      return;
    }

    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = "<span>Creating account…</span>"; }
    try {
      const res = await request(knownEndpoints.auth_register, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password })
      });
      if (res && (res.token || res.user)) {
        if (res.token) setAuthToken(res.token);
        state.currentUser = res.user || { username, email };
        updateAuthUI();
        closeAuthModal();
        toast(`Account created! Welcome, ${state.currentUser.username}`);
        loadUserActivity();
        checkHealth();
      }
    } catch (err) {
      if (errAlert) {
        errAlert.textContent = err.message || "Failed to create account. Choose a different username.";
        errAlert.classList.add("show");
      }
    } finally {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = "<span>Create Account</span>"; }
    }
  }

  async function handleLogout() {
    try {
      await request(knownEndpoints.auth_logout, { method: "POST" });
    } catch (_) {}
    setAuthToken(null);
    state.currentUser = null;
    updateAuthUI();
    closeAuthModal();
    toast("Signed out successfully.");
    renderLocalHistory();
    checkHealth();
  }

  function handleSessionExpired() {
    setAuthToken(null);
    state.currentUser = null;
    updateAuthUI();
    toast("Session expired. Please sign in again.", "warning");
    renderLocalHistory();
  }

  // Forensic Result Formatting
  function safeText(value) {
    return String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function summarize(data) {
    const obj = (data && typeof data === "object") ? (data.event || data) : { result: data };
    const candidates = [
      obj.classification,
      obj.severity,
      obj.threat_category,
      obj.verdict,
      obj.status,
      obj.threat_level,
      obj.risk_level,
      data.summary?.classification,
      data.summary?.category
    ];
    const raw = candidates.find(v => typeof v === "string") || "";
    const s = raw.toLowerCase();
    const scoreVal = obj.confidence ?? obj.risk_score ?? data.summary?.total_processing_ms;

    let level = "safe", heading = "Safe to proceed";
    if (/malicious|danger|critical|high|cloned|scam|phish/.test(s)) {
      level = "danger";
      heading = "High risk detected";
    } else if (/suspicious|warning|medium|uncertain|manipulated|review/.test(s)) {
      level = "warning";
      heading = "Suspicious activity detected";
    } else if (/safe|clean|benign|authentic|low/.test(s)) {
      level = "safe";
      heading = "No known threat detected";
    } else {
      level = "unknown";
      heading = "Analysis completed";
    }

    const explanationObj = obj.explanation || {};
    const summaryText = (typeof explanationObj === "string" ? explanationObj : (explanationObj.summary || explanationObj.reasoning)) ||
      obj.summary || obj.message || obj.detail || "Analysis concluded successfully.";

    const reasoningText = (typeof explanationObj === "object" && explanationObj.reasoning && explanationObj.reasoning !== summaryText) ?
      explanationObj.reasoning : "";

    const actions = Array.isArray(obj.recommended_actions) ? obj.recommended_actions : [];
    const evidenceList = Array.isArray(obj.evidence) ? obj.evidence.map(e => e.description || e.evidence_type || JSON.stringify(e)) : [];

    return {
      level,
      heading,
      badgeText: raw ? raw.replace(/_/g, " ").toUpperCase() : (level === "safe" ? "VERIFIED SAFE" : "THREAT DETECTED"),
      summary: summaryText,
      reasoning: reasoningText,
      actions,
      evidence: evidenceList,
      score: (typeof scoreVal === "number" && scoreVal <= 1.0) ? Math.round(scoreVal * 100) + "% confidence" : ""
    };
  }

  function renderResult(target, data, label, targetName = "") {
    const s = summarize(data);

    let actionsHtml = "";
    if (s.actions.length > 0) {
      actionsHtml = `
        <div class="result-section">
          <div class="result-section-title">Recommended Safety Steps</div>
          <ul class="actions-list">
            ${s.actions.map(act => `<li>${safeText(act)}</li>`).join("")}
          </ul>
        </div>
      `;
    }

    let evidenceHtml = "";
    if (s.evidence.length > 0) {
      evidenceHtml = `
        <div class="result-section">
          <div class="result-section-title">Forensic Indicators & Evidence</div>
          <div class="evidence-pill-wrap">
            ${s.evidence.map(ev => `<span class="evidence-pill">${safeText(ev)}</span>`).join("")}
          </div>
        </div>
      `;
    }

    target.innerHTML = `
      <div class="result-card ${s.level}">
        <div class="result-heading-wrap">
          <div class="result-top">
            <span class="result-dot"></span>
            <strong>${safeText(s.heading)}</strong>
          </div>
          <span class="verdict-badge ${s.level}">${safeText(s.badgeText)}</span>
        </div>
        <p><strong>Summary:</strong> ${safeText(s.summary)}</p>
        ${s.reasoning ? `<p style="margin-top:6px; color:#55635c;"><strong>Forensic Details:</strong> ${safeText(s.reasoning)}</p>` : ""}
        ${s.score ? `<div class="result-meta">${safeText(s.score)}</div>` : ""}
        ${actionsHtml}
        ${evidenceHtml}
        <details>
          <summary>Inspect raw forensic artifact response</summary>
          <pre>${safeText(JSON.stringify(data, null, 2))}</pre>
        </details>
      </div>
    `;

    saveActivity(label, s.heading, s.level, targetName);
  }

  function renderError(target, error) {
    target.innerHTML = `
      <div class="result-card unknown">
        <div class="result-top">
          <span class="result-dot"></span>
          <strong>Unable to complete check</strong>
        </div>
        <p>${safeText(error.message || "The CyberGuard backend service could not process this request.")}<br><br>
        Please verify that the backend is running, reachable, and has permission to analyze this artifact.</p>
      </div>
    `;
  }

  function saveActivity(type, verdict, level, target = "") {
    const list = getHistory();
    list.unshift({ id: Date.now(), type, verdict, level, target, at: new Date().toISOString() });
    setHistory(list);
    if (!state.currentUser) {
      renderLocalHistory();
    }
  }

  function getHistoryIcon(type = "") {
    const t = String(type).toLowerCase();
    if (t.includes("link") || t.includes("url")) {
      return `<div class="history-icon mint"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div>`;
    }
    if (t.includes("file")) {
      return `<div class="history-icon purple"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></div>`;
    }
    if (t.includes("voice") || t.includes("audio")) {
      return `<div class="history-icon purple"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg></div>`;
    }
    return `<div class="history-icon purple"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg></div>`;
  }

  function getHistoryBadge(level, verdict) {
    const isSafe = level === "safe";
    const isDanger = level === "danger";
    const isWarning = level === "warning";
    const prefix = isSafe ? "✓ " : isDanger ? "✕ " : isWarning ? "⚠ " : "";
    const text = verdict || (isSafe ? "Safe" : isDanger ? "Threat detected" : "Caution");
    return `<span class="history-badge ${level}">${prefix}${safeText(text)}</span>`;
  }

  function renderLocalHistory() {
    const list = getHistory();
    const markup = list.length
      ? list.map(item => `
        <div class="history-row">
          ${getHistoryIcon(item.type)}
          <div class="history-copy">
            <b>${safeText(item.type)}</b>
            <span>${safeText(item.target || item.summary || item.verdict || "Check completed")}</span>
          </div>
          ${getHistoryBadge(item.level, item.verdict)}
          <time>${safeText(new Date(item.at).toLocaleDateString())}</time>
        </div>
      `).join("")
      : '<div class="empty-state"><span class="empty-icon">◷</span><b>No activity yet</b><p>Checks you perform in this browser will appear here.</p></div>';

    const recent = list.length
      ? list.slice(0, 3).map(item => `
        <div class="history-row">
          ${getHistoryIcon(item.type)}
          <div class="history-copy">
            <b>${safeText(item.type)}</b>
            <span>${safeText(item.target || item.summary || item.verdict || "Check completed")}</span>
          </div>
          ${getHistoryBadge(item.level, item.verdict)}
          <time>${safeText(new Date(item.at).toLocaleDateString())}</time>
        </div>
      `).join("")
      : '<div class="empty-state"><span class="empty-icon">◷</span><b>No checks yet</b><p>Your recent scans will appear here after you run your first check.</p></div>';

    const actList = $("#activityList");
    const recList = $("#recentList");
    if (actList) actList.innerHTML = markup;
    if (recList) recList.innerHTML = recent;
  }

  async function loadUserActivity() {
    if (!state.currentUser) {
      renderLocalHistory();
      return;
    }
    try {
      const events = await request(knownEndpoints.user_events, { method: "GET" });
      if (Array.isArray(events) && events.length > 0) {
        const markup = events.map(ev => {
          const sev = (ev.severity || "SAFE").toLowerCase();
          const level = /critical|high/.test(sev) ? "danger" : (sev === "medium" ? "warning" : "safe");
          const ts = ev.timestamp ? new Date(ev.timestamp * 1000).toLocaleDateString() : "Recent";
          const cat = (ev.threat_category || "Security Check").replace(/_/g, " ");
          const summary = ev.explanation?.summary || ev.classification || "Check completed";
          const verdict = ev.classification || (level === "safe" ? "Safe" : "Threat detected");
          return `
            <div class="history-row">
              ${getHistoryIcon(cat)}
              <div class="history-copy">
                <b>${safeText(cat)}</b>
                <span>${safeText(summary)}</span>
              </div>
              ${getHistoryBadge(level, verdict)}
              <time>${safeText(ts)}</time>
            </div>
          `;
        }).join("");

        const recent = events.slice(0, 3).map(ev => {
          const sev = (ev.severity || "SAFE").toLowerCase();
          const level = /critical|high/.test(sev) ? "danger" : (sev === "medium" ? "warning" : "safe");
          const ts = ev.timestamp ? new Date(ev.timestamp * 1000).toLocaleDateString() : "Recent";
          const cat = (ev.threat_category || "Security Check").replace(/_/g, " ");
          const summary = ev.explanation?.summary || ev.classification || "Check completed";
          const verdict = ev.classification || (level === "safe" ? "Safe" : "Threat detected");
          return `
            <div class="history-row">
              ${getHistoryIcon(cat)}
              <div class="history-copy">
                <b>${safeText(cat)}</b>
                <span>${safeText(summary)}</span>
              </div>
              ${getHistoryBadge(level, verdict)}
              <time>${safeText(ts)}</time>
            </div>
          `;
        }).join("");

        const actList = $("#activityList");
        const recList = $("#recentList");
        if (actList) actList.innerHTML = markup;
        if (recList) recList.innerHTML = recent;
        return;
      }
    } catch (_) {}
    renderLocalHistory();
  }
  // Navigation and deep-linking
  function navigate() {
    const raw = (location.hash || "#home").slice(1);
    const active = ["home", "link", "file", "media", "activity", "settings"].includes(raw) ? raw : "home";

    $$(".page").forEach(el => el.classList.toggle("active", el.id === "page-" + active));
    $$(".nav-link[data-page]").forEach(el => el.classList.toggle("active", el.dataset.page === active));

    const titles = {
      home: "Overview",
      link: "Check a link",
      file: "Check a file",
      media: "Image & voice",
      activity: "My activity",
      settings: "Settings"
    };

    const crumb = $("#crumbCurrent");
    if (crumb) crumb.textContent = titles[active] || "Overview";

    const sidebar = $("#sidebar");
    if (sidebar) sidebar.classList.remove("open");

    if (active === "activity") {
      loadUserActivity();
    }
  }

  async function postForm(paths, form, target, label, targetName = "") {
    target.innerHTML = `
      <div class="result-card unknown">
        <div class="result-top">
          <span class="result-dot"></span>
          <strong>Analyzing artifact…</strong>
        </div>
        <p>Connecting to CyberGuard security engines. Please hold on…</p>
      </div>
    `;
    let last;
    for (const path of paths) {
      try {
        const data = await request(path, { method: "POST", body: form });
        renderResult(target, data, label, targetName);
        return;
      } catch (e) {
        last = e;
        if (e.status !== 404 && e.status !== 405) break;
      }
    }
    renderError(target, last || new Error("Endpoint returned an unexpected error."));
  }

  async function postFile(paths, file, target, label) {
    target.innerHTML = `
      <div class="result-card unknown">
        <div class="result-top">
          <span class="result-dot"></span>
          <strong>Analyzing ${safeText(file.name)}…</strong>
        </div>
        <p>Running multi-modal threat forensics. Please wait for completion…</p>
      </div>
    `;
    let last;
    for (const path of paths) {
      try {
        const form = new FormData();
        form.append("file", file);
        form.append("source", "personal_frontend");
        const data = await request(path, { method: "POST", body: form });
        renderResult(target, data, label, file ? file.name : "File");
        return;
      } catch (e) {
        last = e;
        if (e.status !== 404 && e.status !== 405) break;
      }
    }
    renderError(target, last || new Error("Endpoint returned an unexpected error."));
  }

  // Event Listeners Initialization
  function initEvents() {
    // URL scan
    $("#scanUrlBtn")?.addEventListener("click", () => {
      const input = $("#urlInput");
      const value = input ? input.value.trim() : "";
      const target = $("#urlResult");
      if (!/^https?:\/\//i.test(value)) {
        toast("Enter a complete link starting with http:// or https://");
        input?.focus();
        return;
      }
      const form = new FormData();
      form.append("url", value);
      form.append("source", "personal_frontend");
      postForm(knownEndpoints.url, form, target, "Link check", value);
    });

    // File scan
    $("#fileInput")?.addEventListener("change", e => {
      state.selectedFile = e.target.files[0] || null;
      const fn = $("#fileName");
      if (fn) fn.textContent = state.selectedFile ? state.selectedFile.name + " • " + Math.round(state.selectedFile.size / 1024) + " KB" : "No file selected";
      const btn = $("#scanFileBtn");
      if (btn) btn.disabled = !state.selectedFile;
    });

    $("#scanFileBtn")?.addEventListener("click", () => {
      if (state.selectedFile) {
        postFile(knownEndpoints.file, state.selectedFile, $("#fileResult"), "File scan");
      }
    });

    // Image scan
    $("#imageInput")?.addEventListener("change", e => {
      state.selectedImage = e.target.files[0] || null;
      const fn = $("#imageName");
      if (fn) fn.textContent = state.selectedImage ? state.selectedImage.name : "No image selected";
      const btn = $("#scanImageBtn");
      if (btn) btn.disabled = !state.selectedImage;
    });

    $("#scanImageBtn")?.addEventListener("click", () => {
      if (state.selectedImage) {
        const endpoint = state.imageMode === "qr" ? knownEndpoints.qr : knownEndpoints.image;
        const label = state.imageMode === "qr" ? "QR code check" : "Image forensics";
        postFile(endpoint, state.selectedImage, $("#imageResult"), label);
      }
    });

    // Image Mode Toggle (Image Forensics vs QR code)
    // Fixed: uses $$ querySelectorAll to prevent TypeError
    $$(".mode-button").forEach(btn => {
      btn.addEventListener("click", () => {
        state.imageMode = btn.dataset.imageMode;
        $$(".mode-button").forEach(b => b.classList.toggle("active", b === btn));
        const title = $("#imageUploadTitle");
        const help = $("#imageUploadHelp");
        const scanBtn = $("#scanImageBtn");
        if (title) title.textContent = state.imageMode === "qr" ? "Choose a QR code image" : "Choose an image to inspect";
        if (help) help.textContent = state.imageMode === "qr" ? "We’ll decode the QR code and assess its destination." : "Look for signs of image manipulation or synthetic content.";
        if (scanBtn) scanBtn.innerHTML = state.imageMode === "qr" ? "Check QR code <b>→</b>" : "Inspect image <b>→</b>";
      });
    });

    // Audio scan
    $("#audioInput")?.addEventListener("change", e => {
      state.selectedAudio = e.target.files[0] || null;
      const fn = $("#audioName");
      if (fn) fn.textContent = state.selectedAudio ? state.selectedAudio.name : "No audio selected";
      const btn = $("#scanAudioBtn");
      if (btn) btn.disabled = !state.selectedAudio;
    });

    $("#scanAudioBtn")?.addEventListener("click", () => {
      if (state.selectedAudio) {
        postFile(knownEndpoints.audio, state.selectedAudio, $("#audioResult"), "Voice analysis");
      }
    });

    // Media Tabs Toggle (Image / QR vs Voice)
    $$(".media-tab").forEach(btn => {
      btn.addEventListener("click", () => {
        const mode = btn.dataset.media;
        state.activeMediaTab = mode;
        $$(".media-tab").forEach(b => b.classList.toggle("active", b === btn));
        const imgP = $("#imagePanel");
        const audP = $("#audioPanel");
        if (imgP) imgP.classList.toggle("hidden", mode !== "image");
        if (audP) audP.classList.toggle("hidden", mode !== "audio");
      });
    });

    // Quick-check cards: handle voice card click to pre-select audio tab
    $$(".tool-card[data-select-media]").forEach(card => {
      card.addEventListener("click", () => {
        const targetMedia = card.dataset.selectMedia;
        if (targetMedia) {
          state.activeMediaTab = targetMedia;
          $$(".media-tab").forEach(b => b.classList.toggle("active", b.dataset.media === targetMedia));
          const imgP = $("#imagePanel");
          const audP = $("#audioPanel");
          if (imgP) imgP.classList.toggle("hidden", targetMedia !== "image");
          if (audP) audP.classList.toggle("hidden", targetMedia !== "audio");
        }
      });
    });

    // Mobile navigation & Refresh
    $("#mobileMenu")?.addEventListener("click", () => $("#sidebar")?.classList.toggle("open"));
    $("#refreshBtn")?.addEventListener("click", () => {
      checkHealth();
      checkAuth();
      toast("Refreshing backend connection.");
    });

    $("#clearActivityBtn")?.addEventListener("click", () => {
      if (confirm("Clear local activity stored in this browser session?")) {
        setHistory([]);
        renderLocalHistory();
        toast("Local check activity cleared.");
      }
    });

    // Settings panel actions
    const apiInput = $("#apiBaseInput");
    if (apiInput) apiInput.value = state.apiBase;

    $("#saveApiBtn")?.addEventListener("click", () => {
      const val = normalizeBase($("#apiBaseInput")?.value);
      if (val && !/^https?:\/\//i.test(val)) {
        toast("Please enter a valid HTTP/HTTPS address.");
        return;
      }
      try { localStorage.setItem(STORAGE_API, val); } catch {}
      state.apiBase = val;
      checkHealth();
      toast("Backend address saved.");
    });

    $("#resetApiBtn")?.addEventListener("click", () => {
      try { localStorage.removeItem(STORAGE_API); } catch {}
      state.apiBase = getBase();
      if (apiInput) apiInput.value = state.apiBase;
      checkHealth();
      toast("Default backend address restored.");
    });

    $("#testApiBtn")?.addEventListener("click", () => {
      checkHealth();
      toast("Testing connection to backend…");
    });

    // Auth trigger buttons
    $("#authBtn")?.addEventListener("click", () => openAuthModal("login"));
    $("#settingsAuthActionBtn")?.addEventListener("click", () => openAuthModal(state.currentUser ? "profile" : "login"));
    $("#modalCloseBtn")?.addEventListener("click", closeAuthModal);
    $("#authModal")?.addEventListener("click", e => { if (e.target === $("#authModal")) closeAuthModal(); });

    $("#tabLogin")?.addEventListener("click", () => switchAuthTab("login"));
    $("#tabRegister")?.addEventListener("click", () => switchAuthTab("register"));
    $("#loginForm")?.addEventListener("submit", handleLoginSubmit);
    $("#registerForm")?.addEventListener("submit", handleRegisterSubmit);
    $("#logoutBtn")?.addEventListener("click", handleLogout);

    // Drag and drop setup
    [["fileDrop", "fileInput"], ["imageDrop", "imageInput"]].forEach(([zoneId, inputId]) => {
      const zone = $("#" + zoneId);
      const input = $("#" + inputId);
      if (!zone || !input) return;
      ["dragenter", "dragover"].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.add("dragging"); }));
      ["dragleave", "drop"].forEach(ev => zone.addEventListener(ev, e => { e.preventDefault(); zone.classList.remove("dragging"); }));
      zone.addEventListener("drop", e => {
        if (e.dataTransfer && e.dataTransfer.files.length) {
          input.files = e.dataTransfer.files;
          input.dispatchEvent(new Event("change"));
        }
      });
    });

    window.addEventListener("hashchange", navigate);
  }

  // Quick preset connection helpers
  function bindPresets() {
    $("#presetLocalBtn")?.addEventListener("click", () => {
      const localUrl = "http://127.0.0.1:3000";
      const apiInput = $("#apiBaseInput");
      if (apiInput) apiInput.value = localUrl;
      try { localStorage.setItem(STORAGE_API, localUrl); } catch {}
      state.apiBase = localUrl;
      checkHealth();
      toast("Switched to Local Backend (port 3000).");
    });

    $("#presetCloudBtn")?.addEventListener("click", () => {
      const cloudUrl = "https://cyberguard-backend-8rbz.onrender.com";
      const apiInput = $("#apiBaseInput");
      if (apiInput) apiInput.value = cloudUrl;
      try { localStorage.setItem(STORAGE_API, cloudUrl); } catch {}
      state.apiBase = cloudUrl;
      checkHealth();
      toast("Switched to Cloud Render Backend.");
    });

    $("#presetTunnelBtn")?.addEventListener("click", () => {
      const saved = localStorage.getItem("cyberguard_custom_tunnel") || prompt("Enter active Cloudflare Tunnel URL (e.g. https://...trycloudflare.com):");
      if (saved && saved.trim()) {
        const clean = normalizeBase(saved);
        try {
          localStorage.setItem("cyberguard_custom_tunnel", clean);
          localStorage.setItem(STORAGE_API, clean);
        } catch {}
        const apiInput = $("#apiBaseInput");
        if (apiInput) apiInput.value = clean;
        state.apiBase = clean;
        checkHealth();
        toast("Connected to Cloudflare Tunnel.");
      }
    });
  }

  // Execution Entrypoint
  function initApp() {
    initEvents();
    bindPresets();
    navigate();
    checkAuth();
    checkHealth();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initApp);
  } else {
    initApp();
  }

  // Resource lifecycle cleanup: abort in-flight browser requests on page navigation
  window.addEventListener("pagehide", () => {
    for (const controller of activeRequests) {
      try { controller.abort(); } catch {}
    }
    activeRequests.clear();
    if (toast.timer) clearTimeout(toast.timer);
  });
})();
