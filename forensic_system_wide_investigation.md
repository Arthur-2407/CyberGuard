# CyberGuard System-Wide Forensic Investigation & Architectural Audit Report

**Date:** November 5, 2026  
**Local Project Working Directory:** `D:\BPUT`  
**Git Branch Baseline:** `forensic-pipeline-repair` (Commit `2668015`)  
**Target Architecture:** Resource-Efficient, On-Demand Lazy-Loading Architecture for 8 GB RAM / Intel i5 Host  

---

## 1. Executive Summary

A comprehensive, non-destructive audit of the CyberGuard cybersecurity and forensic intelligence platform was conducted across all local source trees, configuration layers, model inventories, database schemas, frontend presentation engines, and test asset directories (including `D:\BPUT\New folder`).

The audit successfully traced the root causes of the four anomalies identified in user screenshots:
1. **Malware Lab Shannon Entropy Discrepancy (`0.00 / 8.00` vs `PE64 Entropy: 6.50 / 8.0`)**: Caused by an omitted top-level `file_metadata` dictionary in `coordinator.py`'s response payload, leading `frontend/app.js` to evaluate `meta.entropy` as `undefined` (defaulting to 0.00).
2. **Malware Lab Scan Latency (6100 ms vs 28 ms individual scanner execution)**: Caused by unbounded synchronous/blocking OSINT queries and 5–6 second network timeouts in `asyncio.gather` for unconfigured or rate-limited external threat-intelligence lookups, whose durations were omitted from the engine breakdown table.
3. **Model-vs-Heuristic Forensic Conflict & Information Density**: The visual detector (`MobileNetV3_ForensicVisionDetector`) reported nominal synthetic indicators ($p=0.0175 \approx 0.02$) while spatial noise kurtosis ($90.8$) and 2D FFT harmonics ($3.03\times$) triggered heuristic anomaly thresholds ($0.56$). The UI presented all 8 matrix metrics simultaneously without a prominent first-level classification or an expandable deep-dive modal.
4. **System Health `SpeechBrain ECAPA-TDNN` Displayed as `OFFLINE`**: The model weights (`embedding_model.ckpt`, `classifier.ckpt`, `hyperparams.yaml`) exist and load successfully on disk. However, because eager loading at boot was omitted to save RAM, `is_ecapa_available()` returned `False` (in-memory state), which the frontend mapped directly to `OFFLINE` rather than `AVAILABLE_ON_DISK`.

---

## 2. Test Asset Inventory (`D:\BPUT\New folder`)

Every file located in the provided test folder was statically analyzed (SHA-256, magic bytes, byte length, and pipeline mapping):

| Filename | Size (Bytes) | Size (Display) | Format / Magic | SHA-256 Hash | Target Pipeline | Corresponding Reference Sample |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `demo (1).exe` | 389,352 | 380.2 KB | PE32+ (Windows 64-bit GUI `MZ`) | `9fb082fc5e414036cdab981ad81f1dbc1a90d21c27a2d74537a753abe1203d3a` | Malware Lab Multi-Engine Scan | **Screenshot 1 (`kryptex-setup-latest-v5.exe`)** |
| `demo (1).png` | 2,011,482 | 1964.3 KB | PNG (`89 50 4E 47`) | `36e70dbb678732ca5c2460ae3109c0460f714d5edb0ef7970eebd88e03d5f279` | AI Media Forensics (Image) | **Screenshot 2 & 3 (`CyberGuard Neon...png`)** |
| `demo (2).exe` | 62,458,440 | 59.5 MB | PE32 (Windows 32-bit `MZ`) | `d41f38da09cd4d0a6fc1ef58dda5ebd4fb7aac27d8937a1dc312ed2d51de1b9c` | Malware Lab Multi-Engine Scan | Large Executable Package |
| `demo (1).jpg` | 793,948 | 775.3 KB | JPEG (`FF D8 FF E1`, Exif) | `a4b79f997e52dbfd8558debdd506970e56cd7d73854c57807ddbd823e2a31127` | AI Media Forensics (Image) | Camera / Image Sample 1 |
| `demo (2).jpg` | 2,258,524 | 2205.6 KB | JPEG (`FF D8 FF E1`, Exif) | `8d163b3babc0c4f2dbde1a9238ae8b8456a8bb47d922265fa236d5f55ddaf31e` | AI Media Forensics (Image) | High-Resolution Image Sample 2 |
| `demo (1).mp3` | 2,241,350 | 2188.8 KB | MPEG Audio (`49 44 33`, ID3v2) | `459f85a72ba53455c097b8242f97860e796f2c1d987340761feb986ffe85c4fe` | Voice Cloning & Biometrics | Audio Speech Stream 1 |
| `demo (2).mp3` | 1,457,452 | 1423.3 KB | MPEG Audio (`49 44 33`, ID3v2) | `0e2ff842f96d6b408fb6112a3e11f05bc8982cc1bec9e5d4e135b56a628a6633` | Voice Cloning & Biometrics | Audio Speech Stream 2 |
| `demo (2).png` | 8,151 | 8.0 KB | PNG (`89 50 4E 47`) | `9f3fc48b54136732bd8fe87a9da3658f0f2ba75d7c39487c66885b0b30317191` | QR Forensics / Payload Decoder | Synthetic Payload / QR Code Image |
| `demo.mp4` | 59,700,776 | 56.9 MB | MP4 ISO Base Media (`ftypmp42`) | `fe63f4fb3cc76657016d686ff91d2c7ac4ca60ff1479d33f6c01e0e032ff99a6` | Video & Temporal Forensics | Multi-Modal Deepfake Video Sample |

*Safety Protocol Adherence:* No untrusted binaries (`demo (1).exe`, `demo (2).exe`) were directly executed; all tests are conducted via strictly static parsing, ClamAV scanning, YARA pattern matching, and structural header parsing.

---

## 3. End-to-End Pipeline Wiring & Connection Mapping

The audit traced the complete pipeline architecture from UI interactions to backend endpoints, inference engines, and persistent databases:

```
[ Frontend: Web Browser (Chrome) / CyberGuard Desktop / Mobile ]
                                │
   ┌────────────────────────────┼────────────────────────────┐
   ▼                            ▼                            ▼
/api/malware/scan       /api/media/analyze           /api/config/status
   │                            │                            │
   ▼                            ▼                            ▼
[ Malware Coordinator ]   [ Deepfake Coordinator ]    [ System Health & Diagnostics ]
 ├── FileFormatAnalyzer    ├── ImageForensicsEngine     ├── Service Registry Lifecycle
 ├── ClamAVScanner         ├── VideoForensicsEngine     ├── Model On-Disk Availability
 ├── YaraScanner           ├── VisionDeepfakeDetector   ├── Engine Readiness Probes
 ├── Threat Intel Hub      ├── C2PAProvenanceEngine     └── Active Resource Scheduler
 └── VerdictEngine         ├── CorrelationEngine
                           └── QwenService (LLM)
```

### Detailed Pipeline Inventory

1. **Malware Analysis Subsystem (`/api/malware/upload`, `/api/malware/scan`, `/api/malware/scan-path`)**:
   - *Intake:* Validates file boundary ($<1\text{ GB}$), generates scan UUID and SHA-256.
   - *Execution:* Concurrently triggers `FileFormatAnalyzer` (Shannon entropy, PE headers, ZIP bomb safeguards), `ClamAVScanner` (daemon / CLI `clamscan` / builtin core), and `YaraScanner` (native `yara-python` with 6 rules).
   - *Threat Intel:* Non-blocking lookups to VirusTotal, URLhaus, and live OSINT scrapers by hash.
   - *Output:* Aggregates findings into `MalwareVerdictResult`, builds `ThreatEvent`, and stores record in `MalwareScanStore`.

2. **AI Media Forensics (`/api/media/analyze`, `/api/media/video/analyze`)**:
   - *Image Pipeline:* EXIF metadata parsing, 2D FFT spectral harmonics (high-frequency artifact spikes), Error Level Analysis (ELA disparity), Noise Residual kurtosis & variance, facial boundary seam tracking, C2PA cryptographic signature verification, and `MobileNetV3_ForensicVisionDetector` inference.
   - *Video Pipeline:* FFprobe metadata extraction, adaptive keyframe sampling via FFmpeg, per-frame visual forensics, temporal variance & jitter index calculation, and audio track separation.
   - *Grounding & Correlation:* Evaluates evidence using Noisy-OR Bayesian fusion. Explicitly disallows unqualified "AUTHENTIC" claims without valid cryptographic C2PA or sensor PRNU signatures.

3. **Voice Cloning & Speaker Biometrics (`/ws/audio`, `/api/enroll`, `/api/verify`)**:
   - *Acoustic Deepfake Detection:* Dual CNN-BiLSTM with WebRTC VAD and Wav2Vec 2.0 acoustic features.
   - *Speaker Verification:* SpeechBrain ECAPA-TDNN 192-dimensional embedding extraction and cosine centroid distance checking against enrolled speaker profiles.

4. **Threat Intelligence & SOC Enclave (`/api/threats/search`, `/api/threats/correlate`)**:
   - VirusTotal v3 API feed, Abuse.ch URLhaus malware feed, domain reputation checking, and strict isolation shield.

5. **LLM Forensic Copilot (`/api/llm/explain`, `/api/copilot/chat`)**:
   - Single primary generative model: `Qwen3.5-4B-Q4_K_M.gguf` running via `llama_cpp` (1024/2048 context window, bounded CPU memory). Generates contextual narratives grounded in backend evidence.

---

## 4. Root Cause Analysis of Reported Deficiencies

### 4.1 Malware Lab Shannon Entropy Discrepancy
- **Defect:** Shannon Entropy Radar displayed `0.00 / 8.00`, whereas the engine breakdown table reported `Detected format: PE64, Entropy: 6.50 / 8.0 (NORMAL)`.
- **Root Cause:** In `backend/analysis/malware/coordinator.py`, the returned `report` dictionary omitted `"file_metadata"` at the top level:
  ```python
  # coordinator.py lines 308-318:
  report = {
      "scan_id": scan_id,
      "verdict": verdict_res.to_dict(),
      "event": threat_event,
      "filename": filename,
      "sha256": file_inspection.sha256,
      "size_bytes": file_inspection.size_bytes,
      "status": verdict_res.verdict,
      "processing_time_ms": round(verdict_res.total_processing_ms, 1),
  }
  ```
  In `frontend/app.js` line 34866:
  ```javascript
  const meta = report.file_metadata || {};
  const entropy = meta.entropy !== undefined ? Number(meta.entropy) : 0.0;
  ```
  `meta` was empty, so `entropy` fell back to `0.0`, while the multi-engine table pulled the formatted string from `verdict.engines`.
- **Remediation:**
  1. Add `report["file_metadata"] = file_inspection.to_dict()` and `report["file_inspection"] = file_inspection.to_dict()` in `coordinator.py`.
  2. Update `frontend/app.js` to inspect `report.file_metadata || report.file_inspection || report.verdict?.file_metadata || {}`.

### 4.2 Malware Scan Latency & Timing Transparency
- **Defect:** Scan latency reported `6100 ms`, while individual local scanners completed in under $30\text{ ms}$ combined.
- **Root Cause:**
  1. `_query_osint()` invoked synchronous DuckDuckGo search methods directly on the event loop without timeout bounds.
  2. `_query_vt()` and `_query_urlhaus()` waited up to 5–6 seconds on network timeouts when credentials or network were unreachable.
  3. The breakdown table only displayed ClamAV, YARA, and Structural Entropy rows, hiding the $6000\text{ ms}$ threat-intelligence network wait.
- **Remediation:**
  1. Bound external threat intel lookups with a strict, non-blocking 1.5s timeout.
  2. Add dedicated rows in the multi-engine table for VirusTotal, URLhaus, and OSINT with real measured latencies.
  3. Ensure all external operations are executed asynchronously via `asyncio.to_thread` or async HTTP clients.

### 4.3 Image Forensics Classification Prominence & "More Details" Modal
- **Defect:** The UI presented all eight forensic matrix dimensions at equal visual hierarchy. Conflicting evidence between the neural classifier ($p=0.02$) and spatial noise kurtosis ($90.8$) was confusing to parse.
- **Remediation:**
  1. Introduce a prominent first-level **Primary Verdict Badge**:
     - `AI-GENERATED`
     - `MANIPULATED`
     - `DEEPFAKE`
     - `ORIGINAL-LIKE — ORIGIN UNVERIFIED`
     - `INCONCLUSIVE — ELEVATED RISK`
     - `ANALYSIS FAILED`
  2. Explain signal contradictions directly in the summary (e.g., *"Neural vision classifier found no strong synthetic indicators ($p=0.02$), while spatial noise ($90.8$) and frequency analysis identified anomalies. The available evidence is conflicting; final classification remains inconclusive."*).
  3. Implement an accessible **More Details** modal with structured expandable sections:
     - Section A: General Analysis
     - Section B: AI Model Analysis
     - Section C: Traditional Image Forensics
     - Section D: Video Analysis
     - Section E: Provenance & C2PA
     - Section F: Risk and Evidence
     - Section G: Execution Manifest

### 4.4 Unnatural Slash-Separated Wording
- **Defect:** Widespread presentation strings using slash syntax: `INCONCLUSIVE / ELEVATED CAUTION`, `CLEAN / NO MATCH`, `// CALIBRATED MULTI-SIGNAL FORENSICS`, `NO_DETECTION / SAFE`, etc.
- **Remediation:** Replace with natural, professional technical language:
  - `INCONCLUSIVE / ELEVATED CAUTION` $\rightarrow$ `INCONCLUSIVE — ELEVATED RISK`
  - `CLEAN / NO MATCH` $\rightarrow$ `NO THREAT FOUND`
  - `// CALIBRATED MULTI-SIGNAL FORENSICS & EVIDENCE CORRELATION` $\rightarrow$ `MULTI-SIGNAL FORENSIC ANALYSIS`
  - `NO_DETECTION / SAFE` $\rightarrow$ `NO DETECTION`
  - Preserve all technical slashes in MIME types, URLs, routes, regex, and file paths.

### 4.5 System Health & ECAPA-TDNN Lifecycle Reporting
- **Defect:** `SpeechBrain ECAPA-TDNN Speaker Biometrics` showed `OFFLINE`.
- **Root Cause:** `is_ecapa_available()` in `speaker_extractor.py` returned `_ECAPA_AVAILABLE`, which was only `True` if `_load_ecapa()` had loaded the model into active RAM. In a lazy-loading design, the model is on disk and loaded on demand. The frontend interpreted `ecapa_available: false` as `OFFLINE`.
- **Remediation:**
  1. Distinguish between on-disk availability and active in-memory state.
  2. Implement lifecycle states in the backend: `AVAILABLE_ON_DISK`, `READY_IN_MEMORY`, `ACTIVE`, `IDLE`, `UNAVAILABLE`.
  3. When files exist in `backend/models/weights/ecapa_tdnn/`, report status as `AVAILABLE ON DISK — READY TO LOAD`.

---

## 5. Model Inventory & Host Hardware Assessment

**Host Environment:**
- Memory: 8 GB Physical RAM
- CPU: Intel Core i5 10th Generation
- GPU: Intel Integrated Graphics (CPU inference only)
- Storage: High-speed SSD

**Model Inventory on Disk:**

| Model Component | File Location | File Size | Memory Footprint (Active) | Startup State | Loading Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Qwen3.5-4B-Q4_K_M** | `backend/models/weights/qwen3.5/Qwen3.5-4B-Q4_K_M.gguf` | 2.55 GB | $\approx 2.7\text{ GB}$ (Resident) | On Disk | On-Demand (Lazy) with 5m Idle TTL |
| **MobileNetV3 Vision Detector** | `backend/models/weights/vision_detector.pt` | 4.14 MB | $\approx 45\text{ MB}$ | On Disk | On-Demand (Lazy) when image analyzed |
| **AASIST Audio Anti-Spoofing** | `backend/models/weights/aasist/AASIST.pth` | 1.28 MB | $\approx 35\text{ MB}$ | On Disk | On-Demand (Lazy) for voice streams |
| **ECAPA-TDNN Speaker Model** | `backend/models/weights/ecapa_tdnn/` (5 files) | 88.9 MB | $\approx 180\text{ MB}$ | On Disk | On-Demand (Lazy) for speaker verify |
| **CNN-BiLSTM Voice Detector** | `backend/models/weights/detector.pt` | 35.8 MB | $\approx 60\text{ MB}$ | On Disk | On-Demand (Lazy) for voice streams |

**Resource Budgeting Rule:** If all models were loaded simultaneously at boot, host RAM consumption would exceed $3.5\text{ GB}$ (over 45% of total system RAM). Under lazy loading:
- Startup RAM: $\approx 180\text{ MB}$ (Python runtime + FastAPI + SQLite).
- Peak single-task RAM: $<3.0\text{ GB}$ during Qwen inference; $<350\text{ MB}$ during image/voice forensics.
- Idle eviction releases memory after configurable timeout ($300\text{s}$).

---

## 6. Implementation Priorities & Phased Action Plan

1. **Step 1 — Malware Lab Pipeline & Latency Repair:**
   - Update `coordinator.py` to include `file_metadata` and per-engine timing breakdowns.
   - Guard external threat-intelligence queries with strict async timeouts.
   - Synchronize Shannon entropy radar and engine breakdown metrics in `frontend/app.js`.

2. **Step 2 — Forensic Correlation & Visual Presentation Overhaul:**
   - Add first-level primary classification badge to media forensics.
   - Refine correlation engine to generate contextual explanations when neural and heuristic signals diverge.
   - Implement the accessible 7-section **More Details** modal.

3. **Step 3 — Professional Language & Slash Removal:**
   - Sanitize all user-facing presentation strings across dashboard, malware lab, forensics, voice, and system health.

4. **Step 4 — Unified Lazy-Loading Architecture & Service Registry:**
   - Implement `ModelRegistry` in `backend/services/model_registry.py` with thread-safe lazy loading, active request tracking, idle eviction timer, and explicit lifecycle states (`AVAILABLE_ON_DISK`, `READY_IN_MEMORY`, etc.).
   - Connect ECAPA-TDNN, Vision Detector, Voice Detector, and Qwen to the registry.

5. **Step 5 — System Diagnostics Panel Update:**
   - Update `/api/config/status` and System Health UI to reflect genuine on-disk and in-memory states.

6. **Step 6 — Live Verification in Google Chrome & Comprehensive Testing:**
   - Launch application on port 3000.
   - Execute Chrome browser automation to test Malware Lab, Image Forensics, Video Forensics, More Details popup, and System Health.
   - Verify regression suites and record exact test evidence.
