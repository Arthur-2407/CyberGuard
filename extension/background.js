/**
 * CyberGuard Browser Shield — Manifest V3 Background Service Worker
 *
 * Capabilities:
 * - Real-time navigation monitoring (normal & user-authorized InPrivate/incognito tabs)
 * - Defensive URL normalization (punycode, IP-literal, lookalike detection)
 * - Persistent local blocklist enforced via chrome.declarativeNetRequest
 * - Pre-request redirection to safe interstitial warning page (blocked.html)
 * - Asynchronous CyberGuard SOC backend integration with offline fallback
 * - Privacy-preserving telemetry (zero collection of passwords, forms, or cookies)
 */

const DEFAULT_BACKEND_URL = "http://127.0.0.1:3000";
const VERIFICATION_RULE_ID_OFFSET = 1000;

// Default high-confidence verified phishing & malicious test indicators
const DEFAULT_BLOCKED_DOMAINS = [
  {
    domain: "testsafebrowsing.appspot.com",
    reason: "Google SafeBrowsing Synthetic Test Indicator",
    threat: "MALICIOUS_PHISHING",
    source: "Verified Security Baseline",
    addedAt: Date.now()
  },
  {
    domain: "malware.wicar.org",
    reason: "WICAR Verified Malware Test Site",
    threat: "MALWARE_DISTRIBUTION",
    source: "Verified Security Baseline",
    addedAt: Date.now()
  },
  {
    domain: "phishing-test.cyberguard.local",
    reason: "CyberGuard Synthetic Phishing Simulation Domain",
    threat: "PHISHING_CREDENTIAL_HARVESTING",
    source: "CyberGuard Test Engine",
    addedAt: Date.now()
  }
];

// In-memory cache for recent URL verdicts to prevent request loops
const _verdictCache = new Map();
const VERDICT_CACHE_TTL_MS = 60000; // 1 minute

// ── State Initialization ──────────────────────────────────────────────────────
async function initStorage() {
  const data = await chrome.storage.local.get([
    "backendUrl",
    "shieldEnabled",
    "blockedDomains",
    "whitelistedDomains",
    "stats"
  ]);

  const updates = {};
  if (!data.backendUrl) updates.backendUrl = DEFAULT_BACKEND_URL;
  if (data.shieldEnabled === undefined) updates.shieldEnabled = true;
  if (!data.blockedDomains) updates.blockedDomains = DEFAULT_BLOCKED_DOMAINS;
  if (!data.whitelistedDomains) updates.whitelistedDomains = [];
  if (!data.stats) updates.stats = { scannedUrls: 0, blockedThreats: 0, lastSync: null };

  if (Object.keys(updates).length > 0) {
    await chrome.storage.local.set(updates);
  }

  await updateDeclarativeNetRules();
  await checkBackendStatus();
  await checkIncognitoPermission();
}

// ── Incognito / InPrivate Permission Inspection ──────────────────────────────
async function checkIncognitoPermission() {
  const isAllowed = await chrome.extension.isAllowedIncognitoAccess();
  await chrome.storage.local.set({ incognitoAllowed: isAllowed });
  return isAllowed;
}

// ── URL Normalization & Feature Extraction ────────────────────────────────────
function normalizeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const protocol = parsed.protocol.toLowerCase();

    // Ignore browser internal schemes
    if (["chrome:", "chrome-extension:", "edge:", "about:", "view-source:", "data:", "blob:"].includes(protocol)) {
      return null;
    }

    const hostname = parsed.hostname.toLowerCase().trim();
    // Path without credentials
    const cleanPath = parsed.pathname;

    // Detect IP-literal hosts (e.g. http://192.168.1.1 or [::1])
    const isIpLiteral = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith("[");

    // Detect Punycode / IDN homoglyphs (e.g. xn--pple-43d.com)
    const isPunycode = hostname.includes("xn--");

    // Detect suspicious deep subdomain nesting
    const parts = hostname.split(".");
    const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;

    return {
      raw: rawUrl,
      protocol,
      hostname,
      cleanPath,
      isIpLiteral,
      isPunycode,
      subdomainCount,
      search: parsed.search
    };
  } catch (_) {
    return null;
  }
}

// ── DeclarativeNetRequest Rule Synchronization ───────────────────────────────
async function updateDeclarativeNetRules() {
  const { blockedDomains = [], whitelistedDomains = [], shieldEnabled = true } =
    await chrome.storage.local.get(["blockedDomains", "whitelistedDomains", "shieldEnabled"]);

  const whitelistSet = new Set(whitelistedDomains.map(d => d.toLowerCase()));

  // Remove existing dynamic rules
  const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
  const existingRuleIds = existingRules.map(r => r.id);

  if (!shieldEnabled) {
    if (existingRuleIds.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existingRuleIds,
        addRules: []
      });
    }
    return;
  }

  // Filter out any domains currently whitelisted
  const activeBlocked = blockedDomains.filter(item => !whitelistSet.has(item.domain.toLowerCase()));

  const newRules = activeBlocked.map((item, index) => {
    const ruleId = VERIFICATION_RULE_ID_OFFSET + index + 1;
    const interstitialUrl = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent("http://" + item.domain)}&domain=${encodeURIComponent(item.domain)}&reason=${encodeURIComponent(item.reason)}&threat=${encodeURIComponent(item.threat || "MALICIOUS")}&source=${encodeURIComponent(item.source || "CyberGuard Blocklist")}`
    );

    return {
      id: ruleId,
      priority: 1,
      action: {
        type: "redirect",
        redirect: {
          url: interstitialUrl
        }
      },
      condition: {
        urlFilter: `||${item.domain}`,
        resourceTypes: ["main_frame"]
      }
    };
  });

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existingRuleIds,
    addRules: newRules
  });
}

// ── Local Rule Assessment ────────────────────────────────────────────────────
async function checkLocalBlocklist(hostname) {
  const { blockedDomains = [], whitelistedDomains = [] } =
    await chrome.storage.local.get(["blockedDomains", "whitelistedDomains"]);

  const lowerHost = hostname.toLowerCase();

  // Check whitelist override
  if (whitelistedDomains.some(d => lowerHost === d.toLowerCase() || lowerHost.endsWith("." + d.toLowerCase()))) {
    return { blocked: false, whitelisted: true };
  }

  // Check blocklist
  const match = blockedDomains.find(item => {
    const target = item.domain.toLowerCase();
    return lowerHost === target || lowerHost.endsWith("." + target);
  });

  if (match) {
    return { blocked: true, rule: match };
  }

  return { blocked: false };
}

// ── Backend Live Inspection ──────────────────────────────────────────────────
async function inspectUrlWithBackend(normalized) {
  const { backendUrl = DEFAULT_BACKEND_URL } = await chrome.storage.local.get("backendUrl");

  // Check cache first
  const cacheKey = normalized.hostname + normalized.cleanPath;
  const cached = _verdictCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp < VERDICT_CACHE_TTL_MS)) {
    return cached.result;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const payload = {
      url: normalized.raw,
      domain: normalized.hostname,
      source: "cyberguard_browser_extension",
      include_intel: true
    };

    const res = await fetch(`${backendUrl}/api/threats/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      const isMalicious = data.severity === "CRITICAL" || data.severity === "HIGH" ||
        (data.risk_score && data.risk_score >= 0.75) ||
        data.threat_category === "PHISHING_CREDENTIAL_HARVESTING" ||
        data.threat_category === "MALICIOUS_DOMAIN";

      const result = {
        checked: true,
        isMalicious,
        riskScore: data.risk_score || 0.0,
        severity: data.severity || "LOW",
        category: data.threat_category || "UNKNOWN",
        reason: data.explanation?.summary || data.narrative || "Identified as a malicious destination by CyberGuard Threat Intelligence.",
        virustotal: data.threat_intelligence?.virustotal,
        urlhaus: data.threat_intelligence?.urlhaus,
        source: "CyberGuard SOC AI Engine"
      };

      _verdictCache.set(cacheKey, { timestamp: Date.now(), result });
      return result;
    }
  } catch (err) {
    // Backend offline or timeout
  }

  return { checked: false, offline: true };
}

// ── Heuristic URL Risk Scorer (Offline Resilience) ───────────────────────────
function evaluateOfflineHeuristic(normalized) {
  let score = 0.0;
  const reasons = [];

  // IP literal host check
  if (normalized.isIpLiteral) {
    score += 0.45;
    reasons.push("IP-literal host instead of domain name");
  }

  // Homoglyph / Punycode
  if (normalized.isPunycode) {
    score += 0.40;
    reasons.push("Internationalized domain name (punycode) lookalike indicator");
  }

  // Deceptive subdomains
  const host = normalized.hostname;
  const popularBrands = ["paypal", "apple", "google", "microsoft", "netflix", "chase", "bankofamerica", "wellsfargo", "amazon", "binance", "coinbase"];
  for (const brand of popularBrands) {
    if (host.includes(brand) && !host.endsWith("." + brand + ".com") && host !== brand + ".com") {
      score += 0.50;
      reasons.push(`Brand impersonation / lookalike keyword: ${brand}`);
      break;
    }
  }

  // Suspicious security urgency keywords in path or host
  const suspiciousKeywords = ["login-verify", "secure-account", "update-banking", "recover-wallet", "confirm-identity", "auth-session"];
  for (const kw of suspiciousKeywords) {
    if (host.includes(kw) || normalized.cleanPath.includes(kw)) {
      score += 0.35;
      reasons.push(`High-risk credential phishing keyword pattern: ${kw}`);
      break;
    }
  }

  if (normalized.subdomainCount >= 3) {
    score += 0.20;
    reasons.push("Deeply nested subdomain structure");
  }

  const isSuspicious = score >= 0.70;
  return {
    score: Math.min(score, 1.0),
    isSuspicious,
    reasons
  };
}

// ── Background Health Probe ──────────────────────────────────────────────────
async function checkBackendStatus() {
  const { backendUrl = DEFAULT_BACKEND_URL } = await chrome.storage.local.get("backendUrl");
  let status = "OFFLINE";
  let version = null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${backendUrl}/health`, { signal: controller.signal });
    clearTimeout(timeout);
    if (res.ok) {
      const data = await res.json();
      status = "ONLINE";
      version = data.version || "1.0.0";
    }
  } catch (_) {
    status = "OFFLINE";
  }

  await chrome.storage.local.set({ backendStatus: status, backendVersion: version });
  return status;
}

// ── Navigation Interception & Real-Time Protection ───────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only process top-level navigations
  const normalized = normalizeUrl(details.url);
  if (!normalized) return;

  const { shieldEnabled = true } = await chrome.storage.local.get("shieldEnabled");
  if (!shieldEnabled) return;

  // 1. Check local persistent blocklist
  const localCheck = await checkLocalBlocklist(normalized.hostname);
  if (localCheck.blocked) {
    const item = localCheck.rule;
    const interstitial = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(details.url)}&domain=${encodeURIComponent(normalized.hostname)}&reason=${encodeURIComponent(item.reason)}&threat=${encodeURIComponent(item.threat || "MALICIOUS")}&source=${encodeURIComponent(item.source || "CyberGuard Blocklist")}`
    );
    chrome.tabs.update(details.tabId, { url: interstitial });
    recordThreatBlocked(normalized.hostname, item.reason);
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;
  const normalized = normalizeUrl(tab.url);
  if (!normalized) return;

  // Don't analyze extension's own blocked.html
  if (tab.url.startsWith(chrome.runtime.getURL(""))) return;

  const { shieldEnabled = true } = await chrome.storage.local.get("shieldEnabled");
  if (!shieldEnabled) return;

  // Update telemetry scanned count
  incrementScannedCount();

  // Check if whitelisted
  const localCheck = await checkLocalBlocklist(normalized.hostname);
  if (localCheck.whitelisted || localCheck.blocked) return;

  // 2. Perform Live Threat Inspection with CyberGuard Backend
  const backendVerdict = await inspectUrlWithBackend(normalized);
  if (backendVerdict.checked && backendVerdict.isMalicious) {
    // Add to persistent blocklist
    await addDomainToBlocklist({
      domain: normalized.hostname,
      reason: backendVerdict.reason,
      threat: backendVerdict.category,
      source: backendVerdict.source,
      addedAt: Date.now()
    });

    // Update rules & redirect
    await updateDeclarativeNetRules();
    const interstitial = chrome.runtime.getURL(
      `blocked.html?url=${encodeURIComponent(tab.url)}&domain=${encodeURIComponent(normalized.hostname)}&reason=${encodeURIComponent(backendVerdict.reason)}&threat=${encodeURIComponent(backendVerdict.category)}&source=${encodeURIComponent(backendVerdict.source)}`
    );
    chrome.tabs.update(tabId, { url: interstitial });
    recordThreatBlocked(normalized.hostname, backendVerdict.reason);
    return;
  }

  // 3. If backend is offline, run offline heuristic evaluation
  if (backendVerdict.offline) {
    const offlineEval = evaluateOfflineHeuristic(normalized);
    if (offlineEval.isSuspicious) {
      await addDomainToBlocklist({
        domain: normalized.hostname,
        reason: offlineEval.reasons.join("; "),
        threat: "HEURISTIC_SUSPECTED_PHISHING",
        source: "CyberGuard Offline Heuristic",
        addedAt: Date.now()
      });
      await updateDeclarativeNetRules();
      const interstitial = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(tab.url)}&domain=${encodeURIComponent(normalized.hostname)}&reason=${encodeURIComponent(offlineEval.reasons.join("; "))}&threat=HEURISTIC_SUSPECTED_PHISHING&source=CyberGuard+Offline+Heuristic`
      );
      chrome.tabs.update(tabId, { url: interstitial });
      recordThreatBlocked(normalized.hostname, offlineEval.reasons.join("; "));
    }
  }
});

// ── Helper: Blocklist & Telemetry Mutators ────────────────────────────────────
async function addDomainToBlocklist(entry) {
  const { blockedDomains = [] } = await chrome.storage.local.get("blockedDomains");
  const exists = blockedDomains.some(b => b.domain.toLowerCase() === entry.domain.toLowerCase());
  if (!exists) {
    const updated = [entry, ...blockedDomains];
    await chrome.storage.local.set({ blockedDomains: updated });
  }
}

async function recordThreatBlocked(domain, reason) {
  const { stats = { scannedUrls: 0, blockedThreats: 0 } } = await chrome.storage.local.get("stats");
  stats.blockedThreats = (stats.blockedThreats || 0) + 1;
  await chrome.storage.local.set({ stats });

  // Update badge
  chrome.action.setBadgeText({ text: String(stats.blockedThreats) });
  chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
}

async function incrementScannedCount() {
  const { stats = { scannedUrls: 0, blockedThreats: 0 } } = await chrome.storage.local.get("stats");
  stats.scannedUrls = (stats.scannedUrls || 0) + 1;
  await chrome.storage.local.set({ stats });
}

// ── Message Listener for Popup & Interstitial Communication ───────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "CHECK_BACKEND_STATUS") {
    checkBackendStatus().then(status => sendResponse({ status }));
    return true;
  }
  if (request.type === "CHECK_INCOGNITO_STATUS") {
    checkIncognitoPermission().then(allowed => sendResponse({ allowed }));
    return true;
  }
  if (request.type === "UNBLOCK_DOMAIN") {
    handleUnblockDomain(request.domain, request.temporary).then(res => sendResponse(res));
    return true;
  }
  if (request.type === "RESCAN_URL") {
    const normalized = normalizeUrl(request.url);
    if (!normalized) {
      sendResponse({ error: "Invalid URL" });
      return;
    }
    inspectUrlWithBackend(normalized).then(verdict => {
      sendResponse({ verdict });
    });
    return true;
  }
});

async function handleUnblockDomain(domain, temporary = false) {
  const lower = domain.toLowerCase();
  const { blockedDomains = [], whitelistedDomains = [] } =
    await chrome.storage.local.get(["blockedDomains", "whitelistedDomains"]);

  const filtered = blockedDomains.filter(b => b.domain.toLowerCase() !== lower);
  const updatedWhitelist = Array.from(new Set([...whitelistedDomains, lower]));

  await chrome.storage.local.set({
    blockedDomains: filtered,
    whitelistedDomains: updatedWhitelist
  });

  await updateDeclarativeNetRules();
  return { success: true };
}

// ── Periodic Alarms: Status check & Blocklist Refresh ────────────────────────
chrome.alarms.create("CYBERGUARD_HEARTBEAT", { periodInMinutes: 2 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "CYBERGUARD_HEARTBEAT") {
    checkBackendStatus();
    checkIncognitoPermission();
  }
});

// Initialization
chrome.runtime.onInstalled.addListener(initStorage);
chrome.runtime.onStartup.addListener(initStorage);
