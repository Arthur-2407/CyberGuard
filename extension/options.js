document.addEventListener("DOMContentLoaded", async () => {
  const backendInput = document.getElementById("cfg-backend-url");
  const saveBtn = document.getElementById("btn-save-backend");
  const saveStatus = document.getElementById("save-status");
  const blockedTbody = document.querySelector("#table-blocked tbody");
  const whitelistTbody = document.querySelector("#table-whitelist tbody");

  const {
    backendUrl = "http://127.0.0.1:3000",
    blockedDomains = [],
    whitelistedDomains = []
  } = await chrome.storage.local.get(["backendUrl", "blockedDomains", "whitelistedDomains"]);

  backendInput.value = backendUrl;

  // Save backend URL
  saveBtn.addEventListener("click", async () => {
    const raw = backendInput.value.trim().replace(/\/+$/, "");
    if (!raw) return;
    await chrome.storage.local.set({ backendUrl: raw });
    saveStatus.textContent = "Saved successfully!";
    setTimeout(() => { saveStatus.textContent = ""; }, 2500);
    chrome.runtime.sendMessage({ type: "CHECK_BACKEND_STATUS" });
  });

  // Render blocked domains
  function renderBlocked() {
    blockedTbody.innerHTML = "";
    if (blockedDomains.length === 0) {
      blockedTbody.innerHTML = "<tr><td colspan='4' style='color:#64748b;text-align:center;'>No blocked domains recorded.</td></tr>";
      return;
    }
    blockedDomains.forEach((item, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="color:#f87171;font-weight:600;">${item.domain}</td>
        <td>${item.threat || "MALICIOUS"}</td>
        <td style="color:#94a3b8;">${item.reason || "Policy block"}</td>
        <td><button class="btn-table-del" data-idx="${idx}">Remove</button></td>
      `;
      blockedTbody.appendChild(tr);
    });

    blockedTbody.querySelectorAll(".btn-table-del").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const idx = parseInt(e.target.dataset.idx, 10);
        blockedDomains.splice(idx, 1);
        await chrome.storage.local.set({ blockedDomains });
        renderBlocked();
      });
    });
  }
  renderBlocked();

  // Render whitelist
  function renderWhitelist() {
    whitelistTbody.innerHTML = "";
    if (whitelistedDomains.length === 0) {
      whitelistTbody.innerHTML = "<tr><td colspan='2' style='color:#64748b;text-align:center;'>No whitelist overrides recorded.</td></tr>";
      return;
    }
    whitelistedDomains.forEach((domain, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="color:#38bdf8;font-weight:600;">${domain}</td>
        <td><button class="btn-table-del" data-idx="${idx}">Revoke</button></td>
      `;
      whitelistTbody.appendChild(tr);
    });

    whitelistTbody.querySelectorAll(".btn-table-del").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const idx = parseInt(e.target.dataset.idx, 10);
        whitelistedDomains.splice(idx, 1);
        await chrome.storage.local.set({ whitelistedDomains });
        renderWhitelist();
      });
    });
  }
  renderWhitelist();
});
