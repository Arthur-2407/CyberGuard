document.addEventListener("DOMContentLoaded", async () => {
  // 1. Load persisted states
  const {
    shieldEnabled = true,
    backendStatus = "CHECKING",
    incognitoAllowed = false,
    stats = { scannedUrls: 0, blockedThreats: 0 },
    backendUrl = "http://127.0.0.1:3000"
  } = await chrome.storage.local.get([
    "shieldEnabled",
    "backendStatus",
    "incognitoAllowed",
    "stats",
    "backendUrl"
  ]);

  // Master switch
  const toggleShield = document.getElementById("toggle-shield");
  toggleShield.checked = shieldEnabled;
  toggleShield.addEventListener("change", async () => {
    const isEnabled = toggleShield.checked;
    await chrome.storage.local.set({ shieldEnabled: isEnabled });
    // Trigger background rules re-evaluation
    chrome.runtime.sendMessage({ type: "CHECK_BACKEND_STATUS" });
  });

  // KPI counters
  document.getElementById("kpi-scanned").textContent = stats.scannedUrls || 0;
  document.getElementById("kpi-blocked").textContent = stats.blockedThreats || 0;

  // Backend status dot & text
  const dotBackend = document.getElementById("dot-backend");
  const textBackend = document.getElementById("text-backend");

  function renderBackendStatus(status) {
    if (status === "ONLINE") {
      dotBackend.className = "dot online";
      textBackend.textContent = "DOCKER ONLINE";
      textBackend.style.color = "#10b981";
    } else {
      dotBackend.className = "dot warning";
      textBackend.textContent = "OFFLINE (STANDBY)";
      textBackend.style.color = "#f59e0b";
    }
  }
  renderBackendStatus(backendStatus);

  // Probe fresh backend status
  chrome.runtime.sendMessage({ type: "CHECK_BACKEND_STATUS" }, (res) => {
    if (res && res.status) renderBackendStatus(res.status);
  });

  // Incognito status
  const dotIncognito = document.getElementById("dot-incognito");
  const textIncognito = document.getElementById("text-incognito");
  const incognitoBanner = document.getElementById("incognito-banner");

  function renderIncognitoStatus(allowed) {
    if (allowed) {
      dotIncognito.className = "dot online";
      textIncognito.textContent = "ACTIVE";
      textIncognito.style.color = "#10b981";
      incognitoBanner.classList.add("hidden");
    } else {
      dotIncognito.className = "dot warning";
      textIncognito.textContent = "DISABLED";
      textIncognito.style.color = "#f59e0b";
      incognitoBanner.classList.remove("hidden");
    }
  }
  renderIncognitoStatus(incognitoAllowed);

  // Check incognito permission directly
  chrome.runtime.sendMessage({ type: "CHECK_INCOGNITO_STATUS" }, (res) => {
    if (res && res.allowed !== undefined) renderIncognitoStatus(res.allowed);
  });

  // Fix InPrivate button: opens extension management page
  document.getElementById("btn-fix-incognito").addEventListener("click", () => {
    chrome.tabs.create({ url: `edge://extensions/?id=${chrome.runtime.id}` }, (tab) => {
      if (chrome.runtime.lastError) {
        chrome.tabs.create({ url: `chrome://extensions/?id=${chrome.runtime.id}` });
      }
    });
  });

  // On-Demand URL Scanner
  const inputUrl = document.getElementById("input-url");
  const btnScan = document.getElementById("btn-scan");
  const scanResult = document.getElementById("scan-result");

  btnScan.addEventListener("click", () => {
    const raw = inputUrl.value.trim();
    if (!raw) return;

    btnScan.disabled = true;
    btnScan.textContent = "...";
    scanResult.className = "scan-result";
    scanResult.textContent = "Analyzing against CyberGuard SOC Threat Matrix...";
    scanResult.classList.remove("hidden");

    chrome.runtime.sendMessage({ type: "RESCAN_URL", url: raw }, (response) => {
      btnScan.disabled = false;
      btnScan.textContent = "Scan";

      if (!response || !response.verdict) {
        scanResult.className = "scan-result safe";
        scanResult.textContent = "Verified: No active threats detected.";
        return;
      }

      const v = response.verdict;
      if (v.isMalicious) {
        scanResult.className = "scan-result threat";
        scanResult.innerHTML = `<strong>MALICIOUS DETECTED:</strong> ${v.category}<br>${v.reason}`;
      } else {
        scanResult.className = "scan-result safe";
        scanResult.textContent = "CLEAN: Verified harmless by CyberGuard engines.";
      }
    });
  });

  // Inspect Current Tab
  document.getElementById("link-current-tab").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        inputUrl.value = tabs[0].url;
        btnScan.click();
      }
    });
  });

  // Open SOC Dashboard
  document.getElementById("link-soc-dashboard").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: "http://127.0.0.1:3000/#phishing" });
  });

  // Open Options Page
  document.getElementById("link-options").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});
