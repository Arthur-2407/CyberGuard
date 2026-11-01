(() => {
  "use strict";
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const CONFIG = window.__CYBERGUARD_PERSONAL_CONFIG__ || {};
  const STORAGE_API = "cyberguard_api_base";
  const STORAGE_HISTORY = "cyberguard_personal_history";
  const knownEndpoints = {
    health: ["/health", "/health/"],
    url: ["/api/threats/url", "/api/threats/phishing"],
    file: ["/api/threats/unified"],
    image: ["/api/threats/image"],
    qr: ["/api/threats/qr"],
    audio: ["/api/threats/deepfake"]
  };
  const state = { apiBase: "", health: "checking", selectedFile: null, selectedImage: null, selectedAudio: null, imageMode: "image" };
  const safeParse = (value, fallback) => { try { return JSON.parse(value) ?? fallback; } catch { return fallback; } };
  const getHistory = () => safeParse(localStorage.getItem(STORAGE_HISTORY), []);
  const setHistory = items => { try { localStorage.setItem(STORAGE_HISTORY, JSON.stringify(items.slice(0,30))); } catch {} };
  const normalizeBase = value => String(value || "").trim().replace(/\/+$/, "");
  function getBase() {
    const params = new URLSearchParams(location.search);
    const query = params.get("api_base") || params.get("backend_url");
    if (query) {
      const clean = normalizeBase(query);
      try { localStorage.setItem(STORAGE_API, clean); } catch {}
      return clean;
    }
    try {
      // Read the same local/cloud/hybrid mode and endpoint keys as the SOC console.
      const mode = localStorage.getItem("cyberguard_connection_mode");
      if (mode === "local") {
        const port = localStorage.getItem("cyberguard_local_port") || "3000";
        return "http://127.0.0.1:" + port;
      }
      if (mode === "hybrid") {
        const active = localStorage.getItem("cyberguard_hybrid_active_base");
        if (active) return normalizeBase(active);
        if (location.hostname.includes("vercel.app")) return "";
        return "https://cyberguard-backend-8rbz.onrender.com";
      }
      if (mode === "deployed") {
        const custom = localStorage.getItem("cyberguard_custom_tunnel");
        if (custom && custom.trim()) return normalizeBase(custom);
        if (location.hostname.includes("vercel.app")) return "";
        return "https://cyberguard-backend-8rbz.onrender.com";
      }
      const saved = localStorage.getItem(STORAGE_API);
      if (saved) return normalizeBase(saved);
      // Read the previous consumer-only key during migration, then use the shared key going forward.
      const legacy = localStorage.getItem("cyberguard_personal_api_base");
      if (legacy) return normalizeBase(legacy);
    } catch {}
    if (CONFIG.api_base) return normalizeBase(CONFIG.api_base);
    if (location.hostname === "localhost" || location.hostname === "127.0.0.1" || location.hostname === "0.0.0.0") {
      return location.port === "3000" ? "" : "http://127.0.0.1:3000";
    }
    // The existing Vercel proxy rewrites /api and /health to the deployed backend.
    if (location.hostname.includes("vercel.app")) return "";
    // GitHub Pages and other static hosts call the same deployed FastAPI backend as the SOC UI.
    return "https://cyberguard-backend-8rbz.onrender.com";
  }
  state.apiBase = getBase();
  const apiUrl = path => state.apiBase + path;
  function sharedAuthHeaders() {
    try {
      let token = localStorage.getItem("cyberguard_token") || localStorage.getItem("cg_token") || sessionStorage.getItem("cyberguard_token") || "";
      token = String(token).trim().replace(/^Bearer\s+/i, "").replace(/^["']|["']$/g, "");
      return token ? { Authorization: "Bearer " + token, "X-Session-Token": token } : {};
    } catch { return {}; }
  }
  async function request(path, options={}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);
    try {
      const response = await fetch(apiUrl(path), {...options, headers: {...sharedAuthHeaders(), ...(options.headers || {})}, signal: controller.signal, credentials: "include"});
      const text = await response.text();
      let data; try { data = text ? JSON.parse(text) : {}; } catch { data = { message: text.slice(0,500) }; }
      if (!response.ok) { const err = new Error(data.detail || data.message || data.error || ("Request failed ("+response.status+")")); err.status=response.status; err.data=data; throw err; }
      return data;
    } finally { clearTimeout(timeout); }
  }
  function toast(message) { const el=$("#toast"); el.textContent=message; el.classList.add("show"); clearTimeout(toast.timer); toast.timer=setTimeout(()=>el.classList.remove("show"),2800); }
  function setConnection(status, detail) {
    state.health=status;
    const pill=$("#connectionState"), settings=$("#settingsConnection"), title=$("#overviewStatus"), sub=$("#overviewSubstatus"), tag=$("#statusTag");
    pill.classList.toggle("online",status==="online"); pill.classList.toggle("offline",status==="offline");
    pill.querySelector("span").textContent=status==="online"?"Backend connected":status==="offline"?"Backend unavailable":"Checking connection";
    settings.textContent=status==="online"?"Connected":status==="offline"?"Unavailable":"Checking";
    title.textContent=status==="online"?"CyberGuard is connected":status==="offline"?"Could not reach CyberGuard":"Checking your connection";
    sub.textContent=detail || (status==="online"?"Live backend connection confirmed.":"Results will be available when a backend can be reached.");
    tag.textContent=status==="online"?"CONNECTED":status==="offline"?"OFFLINE":"CONNECTING";
  }
  async function checkHealth() {
    setConnection("checking");
    let lastError;
    for (const path of knownEndpoints.health) {
      try { const data=await request(path,{method:"GET"}); setConnection("online", "The backend health endpoint responded successfully."); return data; }
      catch(e) { lastError=e; if (e.status && e.status!==404 && e.status!==405) break; }
    }
    setConnection("offline", lastError ? "Connection check failed: "+lastError.message : "No health endpoint responded.");
    return null;
  }
  function safeText(value) { return String(value ?? "").replace(/[&<>"']/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
  function summarize(data) {
    const obj = data && typeof data==="object" ? data : {result:data};
    const candidates=[obj.verdict,obj.status,obj.severity,obj.threat_level,obj.risk_level,obj.threat_category,obj.classification,obj.label,obj.result?.verdict,obj.result?.status,obj.result?.severity,obj.result?.threat_category,obj.result?.label];
    const raw=candidates.find(v=>typeof v==="string") || "";
    const s=raw.toLowerCase();
    const numeric=[obj.risk_score,obj.score,obj.result?.risk_score,obj.result?.score].find(v=>typeof v==="number");
    let level="unknown", heading="Analysis completed";
    if (/malicious|danger|critical|high|infected|phish|unsafe|synthetic|cloned/.test(s)) {level="danger";heading="Potential risk detected";}
    else if (/suspicious|warning|medium|uncertain|review/.test(s)) {level="warning";heading="Needs a closer look";}
    else if (/safe|clean|benign|low.?risk|legitimate|authentic/.test(s)) {level="safe";heading="No known threat reported";}
    else if (numeric!==undefined) {heading="Analysis completed";}
    const summary=[obj.message,obj.detail,obj.explanation_summary,obj.explanation,obj.summary,obj.result?.message,obj.result?.explanation_summary,obj.result?.explanation].find(v=>typeof v==="string" && v.trim());
    return {level,heading,summary:summary || "The service returned a response. Review the details below; this interface will not infer a safe or dangerous verdict when the backend does not provide one.",numeric};
  }
  function renderResult(target,data,label) {
    const s=summarize(data), score=s.numeric!==undefined?"Risk score: "+s.numeric:"";
    target.innerHTML='<div class="result-card '+s.level+'"><div class="result-top"><span class="result-dot"></span><strong>'+safeText(s.heading)+'</strong></div><p>'+safeText(s.summary)+'</p>'+(score?'<div class="result-meta">'+safeText(score)+'</div>':'')+'<details><summary>View response details</summary><pre>'+safeText(JSON.stringify(data,null,2))+'</pre></details></div>';
    saveActivity(label,s.heading,s.level);
  }
  function renderError(target,error) {
    target.innerHTML='<div class="result-card unknown"><div class="result-top"><span class="result-dot"></span><strong>Could not complete the check</strong></div><p>'+safeText(error.message)+'<br><br>Confirm the backend URL, network access, CORS settings and endpoint availability, then try again. No scan result has been assumed.</p></div>';
  }
  function saveActivity(type,verdict,level) {
    const list=getHistory(); list.unshift({id:Date.now(),type,verdict,level,at:new Date().toISOString()}); setHistory(list); renderHistory();
  }
  function renderHistory() {
    const list=getHistory();
    const markup=list.length?list.map(item=>'<div class="history-row"><div class="history-mark '+safeText(item.level)+'">●</div><div class="history-copy"><b>'+safeText(item.type)+'</b><span>'+safeText(item.verdict)+'</span></div><time>'+safeText(new Date(item.at).toLocaleString())+'</time></div>').join(""):'<div class="empty-state"><span class="empty-icon">◷</span><b>No activity to show</b><p>Checks you run from this browser will be listed here.</p></div>';
    const recent=list.length?list.slice(0,3).map(item=>'<div class="history-row"><div class="history-mark '+safeText(item.level)+'">●</div><div class="history-copy"><b>'+safeText(item.type)+'</b><span>'+safeText(item.verdict)+'</span></div><time>'+safeText(new Date(item.at).toLocaleDateString())+'</time></div>').join(""):'<div class="empty-state"><span class="empty-icon">◷</span><b>No checks yet</b><p>Your recent scans will appear here after you run your first check.</p></div>';
    $("#activityList").innerHTML=markup; $("#recentList").innerHTML=recent;
  }
  function navigate() {
    const page=(location.hash||"#home").slice(1);
    const valid=["home","link","file","media","activity","settings"], active=valid.includes(page)?page:"home";
    $$(".page").forEach(el=>el.classList.toggle("active",el.id==="page-"+active));
    $$(".nav-link[data-page]").forEach(el=>el.classList.toggle("active",el.dataset.page===active));
    $("#crumbCurrent").textContent=({home:"Overview",link:"Check a link",file:"Check a file",media:"Image & voice",activity:"My activity",settings:"Settings"})[active];
    $("#sidebar").classList.remove("open");
    if(active==="activity")renderHistory();
  }
  async function postForm(paths,form,target,label) {
    target.innerHTML='<div class="result-card unknown"><div class="result-top"><span class="result-dot"></span><strong>Checking…</strong></div><p>Sending your request to CyberGuard. Please wait for the service response.</p></div>';
    let last;
    for(const path of paths) {
      try { const data=await request(path,{method:"POST",body:form}); renderResult(target,data,label); return; }
      catch(e) { last=e; if(e.status!==404 && e.status!==405)break; }
    }
    renderError(target,last||new Error("No compatible endpoint was found."));
  }
  async function postFile(paths,file,target,label) {
    target.innerHTML='<div class="result-card unknown"><div class="result-top"><span class="result-dot"></span><strong>Uploading for analysis…</strong></div><p>Waiting for the connected service to finish.</p></div>';
    let last;
    for(const path of paths) {
      try { const form=new FormData(); form.append("file",file); form.append("source","personal_frontend"); const data=await request(path,{method:"POST",body:form}); renderResult(target,data,label); return; }
      catch(e) { last=e; if(e.status!==404 && e.status!==405)break; }
    }
    renderError(target,last||new Error("No compatible upload endpoint was found."));
  }
  $("#scanUrlBtn").addEventListener("click",()=>{
    const value=$("#urlInput").value.trim(), target=$("#urlResult");
    if(!/^https?:\/\//i.test(value)){toast("Enter a complete link starting with http:// or https://.");$("#urlInput").focus();return;}
    const form=new FormData(); form.append("url",value); form.append("source","personal_frontend"); postForm(knownEndpoints.url,form,target,"Link check");
  });
  $("#fileInput").addEventListener("change",e=>{state.selectedFile=e.target.files[0]||null;$("#fileName").textContent=state.selectedFile?state.selectedFile.name+" • "+Math.round(state.selectedFile.size/1024)+" KB":"No file selected";$("#scanFileBtn").disabled=!state.selectedFile;});
  $("#scanFileBtn").addEventListener("click",()=>state.selectedFile&&postFile(knownEndpoints.file,state.selectedFile,$("#fileResult"),"File scan"));
  $("#imageInput").addEventListener("change",e=>{state.selectedImage=e.target.files[0]||null;$("#imageName").textContent=state.selectedImage?state.selectedImage.name:"No image selected";$("#scanImageBtn").disabled=!state.selectedImage;});
  $("#scanImageBtn").addEventListener("click",()=>state.selectedImage&&postFile(state.imageMode==="qr"?knownEndpoints.qr:knownEndpoints.image,state.selectedImage,$("#imageResult"),state.imageMode==="qr"?"QR code check":"Image forensics"));
  $(".mode-button").forEach(btn=>btn.addEventListener("click",()=>{state.imageMode=btn.dataset.imageMode;$(".mode-button").forEach(b=>b.classList.toggle("active",b===btn));$("#imageUploadTitle").textContent=state.imageMode==="qr"?"Choose a QR code image":"Choose an image to inspect";$("#imageUploadHelp").textContent=state.imageMode==="qr"?"We’ll decode the QR code and assess its destination.":"Look for signs of image manipulation or synthetic content.";$("#scanImageBtn").innerHTML=state.imageMode==="qr"?"Check QR code <b>→</b>":"Inspect image <b>→</b>";}));
  $("#audioInput").addEventListener("change",e=>{state.selectedAudio=e.target.files[0]||null;$("#audioName").textContent=state.selectedAudio?state.selectedAudio.name:"No audio selected";$("#scanAudioBtn").disabled=!state.selectedAudio;});
  $("#scanAudioBtn").addEventListener("click",()=>state.selectedAudio&&postFile(knownEndpoints.audio,state.selectedAudio,$("#audioResult"),"Voice analysis"));
  $$(".media-tab").forEach(btn=>btn.addEventListener("click",()=>{$$(".media-tab").forEach(b=>b.classList.toggle("active",b===btn));$("#imagePanel").classList.toggle("hidden",btn.dataset.media!=="image");$("#audioPanel").classList.toggle("hidden",btn.dataset.media!=="audio");}));
  $("#mobileMenu").addEventListener("click",()=>$("#sidebar").classList.toggle("open"));
  $("#refreshBtn").addEventListener("click",()=>{checkHealth();toast("Refreshing backend connection.");});
  $("#clearActivityBtn").addEventListener("click",()=>{if(confirm("Clear the activity stored in this browser?")){setHistory([]);renderHistory();toast("Local activity cleared.");}});
  $("#apiBaseInput").value=state.apiBase;
  $("#saveApiBtn").addEventListener("click",()=>{const value=normalizeBase($("#apiBaseInput").value);if(value&&!/^https:\/\//i.test(value)&&!/^http:\/\/localhost(?::\d+)?$/i.test(value)&&!/^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(value)){toast("Use HTTPS for remote backends.");return;}try{localStorage.setItem(STORAGE_API,value);}catch{}state.apiBase=value;checkHealth();toast("Backend address saved in this browser.");});
  $("#resetApiBtn").addEventListener("click",()=>{try{localStorage.removeItem(STORAGE_API);}catch{}state.apiBase=normalizeBase(CONFIG.api_base||"");$("#apiBaseInput").value=state.apiBase;checkHealth();toast("Default backend setting restored.");});
  $("#testApiBtn").addEventListener("click",checkHealth);
  window.addEventListener("hashchange",navigate);
  // Drag-and-drop helpers
  [["fileDrop","fileInput"],["imageDrop","imageInput"]].forEach(([zoneId,inputId])=>{const zone=$("#"+zoneId),input=$("#"+inputId);["dragenter","dragover"].forEach(ev=>zone.addEventListener(ev,e=>{e.preventDefault();zone.classList.add("dragging");}));["dragleave","drop"].forEach(ev=>zone.addEventListener(ev,e=>{e.preventDefault();zone.classList.remove("dragging");}));zone.addEventListener("drop",e=>{if(e.dataTransfer.files.length){input.files=e.dataTransfer.files;input.dispatchEvent(new Event("change"));}});});
  renderHistory(); navigate(); checkHealth();
})();