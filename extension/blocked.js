document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown Target";
  const domain = params.get("domain") || (function() {
    try { return new URL(targetUrl).hostname; } catch (_) { return targetUrl; }
  })();
  const reason = params.get("reason") || "Matched verified phishing or malware indicators in CyberGuard SOC threat matrix.";
  const threat = params.get("threat") || "MALICIOUS_DESTINATION";
  const source = params.get("source") || "CyberGuard Threat Intelligence";

  // Populate UI
  document.getElementById("field-domain").textContent = domain;
  document.getElementById("field-threat").textContent = threat;
  document.getElementById("field-source").textContent = source;
  document.getElementById("field-reason").textContent = reason;
  document.getElementById("field-time").textContent = new Date().toUTCString();

  // Return to safety button
  document.getElementById("btn-back").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://cyber-guard-backend-ashen.vercel.app";
    }
  });

  // Advanced drawer toggle
  const drawer = document.getElementById("advanced-drawer");
  const btnShowAdvanced = document.getElementById("btn-show-advanced");
  btnShowAdvanced.addEventListener("click", () => {
    drawer.classList.toggle("hidden");
  });

  // Whitelist / override button
  document.getElementById("btn-override").addEventListener("click", () => {
    const confirmed = window.confirm(
      `WARNING: You are about to bypass CyberGuard protection for:\n${domain}\n\nThis destination has been flagged as high risk. Are you sure you wish to proceed?`
    );

    if (confirmed) {
      chrome.runtime.sendMessage(
        { type: "UNBLOCK_DOMAIN", domain: domain, temporary: true },
        (response) => {
          if (response && response.success) {
            // Redirect user to the original destination
            window.location.href = targetUrl;
          } else {
            alert("Failed to apply local override. Please check extension settings.");
          }
        }
      );
    }
  });
});
