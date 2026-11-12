# CyberGuard Image Forensics Pipeline: Forensic Investigation, Root-Cause Analysis, Repair & Validation Audit

**Document Identifier:** `CG-AUDIT-2026-FORENSICS-01`  
**Date:** November 7, 2026  
**Local Project Repository:** `D:\BPUT`  
**Git Branch Baseline:** `main` (Tracking `origin/main`)  
**Investigation Scope:** End-to-End Image Forensics, Neural Detection, DSP Signal Analysis, Face Biometrics, Provenance, and Forensic Dashboard Presentation  
**Status:** Verification Passed (100% Automated Test Suite Green)

---

## 1. Executive Summary

A comprehensive, evidence-driven, non-destructive investigation and engineering repair was conducted on the CyberGuard Image & Media Forensics pipeline. The audit was triggered by forensic discrepancies identified in real-world analysis outputs (specifically against a 66×64 portrait image asset, `demo (2).png`, submitted via the dashboard).

### Key Findings at a Glance:
1. **Face Detection Failure (`No face detected` despite visible face):**  
   *Root Cause:* In `backend/analysis/forensics/image_forensics.py`, OpenCV Haar cascade detection enforced a hard minimum face size constraint `min_face = max(48, int(min_side * 0.08))`. In small-resolution inputs (such as 66×64), the visible face occupies $29\times 29$ pixels ($< 48\text{ px}$), causing zero detections and falsely claiming that no face existed.
2. **AI Generation Contradiction (`98.4% Authentic` Neural Vision vs `70% DETECTED` Matrix):**  
   *Root Cause:* In `backend/models/vision_detector.py`, the active MobileNetV3 neural classifier correctly predicted $p_{\text{synthetic}} = 0.0161$ (1.6% synthetic, 98.4% authentic). However, `backend/analysis/forensics/correlation_engine.py` completely decoupled the matrix score from the evaluated neural model, deriving `ai_generation` from classical 2D FFT harmonics and spatial noise kurtosis. Because bilinear upsampling of a 66×64 asset to 256×256 artificially created interpolation lattice spikes ($2.50\times$) and high-frequency roll-off (HF ratio 0.0078), the heuristic rule falsely flagged `ai_gen_outcome = "DETECTED"` and forced `ai_generation_score = max(threat_score, 0.70) = 0.70` (70%).
3. **Manipulation Semantics Discrepancy (`68% — INCONCLUSIVE`):**  
   *Root Cause:* Error Level Analysis (ELA) indicated uniform compression across blocks ($\text{mean} = 2.30$, $\text{disparity} = 1.11$, nominal status). However, an uncalibrated threshold `ela_disp >= 0.30` in the correlation engine mapped raw block variance directly into an inconclusive verdict and score clamp without clarifying that $1.11$ reflects natural content variance rather than splicing.
4. **Statistical Inconsistency in Noise Analysis (`Kurtosis 28.7 described as Gaussian-consistent`):**  
   *Root Cause:* Conventional Pearson kurtosis for a Gaussian distribution is $\approx 3.0$ (excess kurtosis $\approx 0.0$). A kurtosis of $28.7$ represents a strongly leptokurtic distribution. In compact assets ($66\times 64$), edge transitions across small image patches inflate residual kurtosis. The dashboard UI unconditionally rendered `GAUSSIAN SENSOR` whenever noise status was nominal, falsely asserting Gaussian statistics for a heavy-tailed residual.
5. **Conflicting Risk Labels (`INCONCLUSIVE - ELEVATED RISK` alongside `LOW` Badges):**  
   *Root Cause:* In `frontend/app.js`, `primaryVerdictTitle` was statically hardcoded to `'INCONCLUSIVE — ELEVATED RISK'` for all inconclusive outcomes regardless of whether the calculated `severity` was `LOW` ($< 50/100$) or `MEDIUM`/`HIGH`.
6. **Sensor Hardware Provenance (`Digital Optical Profile`):**  
   *Root Cause:* When EXIF metadata was stripped or absent, `frontend/app.js` rendered a placeholder string `'Digital Optical Profile'` instead of explicitly stating that hardware sensor metadata was absent.
7. **Calibration Ambiguity (`Calibrated 8-Point Matrix` vs `(Uncalibrated)`):**  
   *Root Cause:* The UI title claimed a calibrated matrix while the subtitle disclosed uncalibrated heuristic fusion.

All root causes were resolved without discarding existing CyberGuard architecture or compromising backward compatibility. The full test suite (40 unit, integration, and forensic tests) is green.

---

## 2. Forensic Discrepancies Matrix & Root Causes

| Defect Observed | Source in Codebase | Mechanism of Failure | Corrective Implementation |
| :--- | :--- | :--- | :--- |
| **No face detected** | `image_forensics.py` (L695–L708) | `min_face` clamped to $\ge 48\text{ px}$. A $29\times 29\text{ px}$ face in a $66\times 64$ asset was ignored. | Scaled `min_face = max(16, int(min_side * 0.15))` for compact inputs ($<120\text{ px}$). Detected face preserved ($[19, 9, 29, 29]$) with status `FACE_DETECTED` and confidence $0.88$. Biometric warping forensics conditionally gated on resolution baseline ($44\text{ px}$). |
| **Dimension Mismatch (150×150 vs 66×64)** | `deepfake_coordinator.py` & `app.js` | Source image physically $66\times 64\text{ px}$, but internal processing dimensions (FFT 256×256, Neural 224×224, ELA 66×64) and display thumbnails were untracked. | Structured dimensions: `original_dimensions` ($66\times 64$), `analysis_dimensions` ($66\times 64$), and `detector_dimensions` (`neural_vision: [224, 224]`, `fft: [256, 256]`, `ela: [66, 64]`, `face: [66, 64]`). |
| **Contradictory AI Gen (98.4% Auth vs 70% DETECTED)** | `correlation_engine.py` (L70–L85, L270–L285) | Neural inference ($p_{\text{synthetic}}=0.0161$) was ignored. Upsampled FFT grid resonance triggered heuristic anomaly rule, clamping score to $0.70$. | Evidence-aware fusion: when neural vision model evaluates $p_{\text{synthetic}}$, `ai_generation_score` reflects model prediction ($0.02$) and status `NOT_DETECTED`. Resolution roll-off recognized as physical Nyquist limit. |
| **Manipulation 68% — INCONCLUSIVE** | `correlation_engine.py` (L87–L94, L287–L294) | Normal spatial variance in small blocks triggered `ela_disp >= 0.30`, and score was clamped to $0.60–0.68$. | Explicit semantics: uniform ELA response ($\text{mean}=2.30$, $\text{status}=\text{NOMINAL}$) produces `NO_EVIDENCE_DETECTED` (or bounded low inconclusive where appropriate). |
| **Kurtosis 28.7 as "Gaussian-consistent"** | `image_forensics.py` & `app.js` (L29068) | UI pill rendered `GAUSSIAN SENSOR` for any nominal status. Non-Gaussian leptokurtosis from high edge density was mislabeled. | Excess kurtosis explicitly computed ($\text{excess} = 25.7$). Status labeled `COMPACT_EDGE_KURTOSIS` / `LEPTOKURTIC RESIDUAL`. UI pill renders `EDGE RESIDUAL (COMPACT)`. |
| **ELEVATED RISK with LOW badge** | `frontend/app.js` (L28675–L28695, L28215–L28228) | Title hardcoded to `'INCONCLUSIVE — ELEVATED RISK'`. | Unified risk mapping: score $< 50$ / `LOW` severity renders `INCONCLUSIVE — LOW ANOMALY PROFILE` with cyan `#38bdf8` `LOW` badge and matching banner. |
| **"Digital Optical Profile" sensor tag** | `frontend/app.js` (L28831) | Placeholder string injected when `camera_make` was null. | Accurately renders `No Hardware Sensor EXIF`. |
| **"Calibrated 8-Point Matrix" ambiguity** | `frontend/app.js` (L28370) | Heading claimed calibrated while subtitle stated uncalibrated. | Heading standardized to `8-Point Forensic Multi-Signal Matrix`, subtitle: `Calibration: Heuristic Multi-Signal Fusion (Uncalibrated)`. |
| **Missing C2PA treated as negative proof** | `c2pa_provenance.py` & `correlation_engine.py` | Missing provenance risked contributing to suspicion. | Explicit neutral status: `MISSING_PROVENANCE` / `NO_CREDENTIALS_PRESENT` yields 0% provenance score but 0.0 penalty contribution. |

---

## 3. Architecture & Traceability Map

```
[ FRONTEND: Web SOC / Desktop Client ]
  │
  ├─ previewForensicMedia() ── Reset stale state (window._lastForensicData = null)
  │
  ▼ POST /api/threats/image (UploadFile multipart/form-data)
[ BACKEND API LAYER: routes_threats.py ]
  │
  ├─ Raw Bytes Intake & SHA-256 Hashing: 9f3fc48b54136732bd8fe87a9da3658f0f2ba75d7c39487c66885b0b30317191
  │
  ▼
[ ORCHESTRATION LAYER: DeepfakeCoordinator._analyze_image() ]
  │
  ├── 1. Container & EXIF Metadata Extraction (_extract_image_metadata)
  │      Original dimensions: 66x64, Format: PNG, Mode: RGBA
  │      EXIF: Absent (Web/chat asset container profile)
  │
  ├── 2. C2PA Cryptographic Provenance Engine (c2pa_engine.analyze)
  │      Status: MISSING_PROVENANCE (Neutral, 0.0 contribution)
  │
  ├── 3. DSP Forensic Signal Engine (ImageForensicsEngine.analyze)
  │      ├── ELA (Quality 95, 4x4 spatial blocks): Mean=2.30, Disparity=1.11 [NOMINAL]
  │      ├── 2D FFT (256x256 Hann-windowed): High-Freq Ratio=0.0078, Spike=2.50x
  │      │     Asset dimension check: min(66, 64) < 128px
  │      │     Status: NOMINAL (Roll-off reflects physical Nyquist resolution)
  │      ├── Sensor Noise Residual (3x3 median filter, Sobel edge mask):
  │      │     Variance=61.844, Kurtosis=28.7, Excess Kurtosis=25.7
  │      │     Status: NOMINAL (Substatus: COMPACT_EDGE_KURTOSIS)
  │      ├── Edge Sharpness & Seams: Laplacian variance 3376.1 [NOMINAL ACUTANCE]
  │      └── Face Detection & Biometric Warping:
  │             Haar Cascade (scale 1.05, minNeighbors 3, minSize 16x16)
  │             Detected 1 face: [ymin=0.141, xmin=0.288, ymax=0.594, xmax=0.727]
  │             Box pixels: [19, 9, 29, 29] (Face dimension: 29px < 44px baseline)
  │             Status: FACE_DETECTED, facial_forensics_applicable: False
  │
  ├── 4. Neural Vision Deepfake Detector (VisionDeepfakeDetector.predict)
  │      Architecture: MobileNetV3_ForensicVisionDetector
  │      Weights Checkpoint: backend/models/weights/vision_detector.pt (verified SHA-256)
  │      Preprocessing: 224x224 RGB, ImageNet normalization ([0.485, 0.456, 0.406])
  │      Inference Output: Synthetic Logit/Softmax p=0.0161, Authentic=0.9839
  │      Predicted Class: AUTHENTIC, Confidence=0.94
  │
  └── 5. Evidence Correlation & Decision Engine (ForensicCorrelationEngine.correlate_image)
         ├── Evaluated Neural Score: p_synthetic = 0.0161
         ├── Matrix Grounding: ai_generation = NOT_DETECTED (0.02)
         ├── Manipulation Grounding: image_manipulation = NO_EVIDENCE_DETECTED (0.00)
         ├── Face Manipulation: NOT_APPLICABLE (Face present, compact resolution)
         ├── Modality Gating: Video Stability / AV Sync = NOT_APPLICABLE
         ├── Grounding Status: BENIGN_UNVERIFIED_ORIGIN
         └── Composite Threat Score: 0.25 (RiskLevel.SAFE, LIKELY_AUTHENTIC)
```

---

## 4. Detailed Component Audits

### 4.1 Image Preprocessing & Dimensions Tracing
- **Observation:** The user noted that the asset was 150×150 whereas the dashboard reported 66×64.
- **Verification:** Inspection of the original uploaded file `media_1794045724927_61538e53.png` and repo asset `demo (2).png` confirmed both are physically $66\times 64$ pixels with identical pixel values ($\text{diff} = 0.0$). The $150\times 150$ reference originated from frontend CSS thumbnail containers and avatar presentation boundaries.
- **Correction:** The backend payload now returns explicit dimensional separation:
  ```json
  {
    "dimensions": "66x64",
    "original_dimensions": "66x64",
    "original_width": 66,
    "original_height": 64,
    "analysis_dimensions": "66x64",
    "detector_dimensions": {
      "neural_vision": [224, 224],
      "fft": [256, 256],
      "ela": [66, 64],
      "face": [66, 64]
    }
  }
  ```

### 4.2 Face Detection Status Model
- **Observation:** The dashboard reported `"No face detected; facial boundary and warping forensics not applicable"` on an image with a visible portrait.
- **Verification:** OpenCV Haar cascades (`haarcascade_frontalface_alt2.xml` and `default.xml`) were constrained by `min_face = max(48, ...)`. Since the face occupies $29\times 29\text{ px}$, it was discarded.
- **Status Model Defined:**
  - `FACE_DETECTED`: Valid human face localized; bounding box and confidence preserved.
  - `NO_FACE_DETECTED`: No candidate face found after scale and anthropomorphic checks.
  - `LOW_CONFIDENCE`: Candidate detected but failed bilateral symmetry or chromatic checks.
  - `INSUFFICIENT_RESOLUTION`: Image or face region $< 16\text{ px}$.
  - `DETECTOR_UNAVAILABLE`: Cascade model weights absent from disk.
  - `DETECTION_ERROR`: Exception during image decoding or cascade inference.
- **Biometric Gating:** When face dimension $< 44\text{ px}$, warping/seam analysis is marked `NOT_APPLICABLE` with the reason `"compact face resolution: 29px < 44px baseline"`, eliminating false splicing penalties while preserving face localization.

### 4.3 Neural AI Vision Classifier Audit
- **Architecture:** `MobileNetV3_ForensicVisionDetector` based on `models.mobilenet_v3_small` with custom classification head (`Linear(576, 128) -> Hardswish -> Dropout(0.2) -> Linear(128, 2)`).
- **Weights File:** `backend/models/weights/vision_detector.pt` ($4,137,447\text{ bytes}$, verified SHA-256 `4435b38208daaaafd72ca2f51d9682e5300777d60fd9ad34fa233ce444c8a36f`).
- **Class Mapping:** Output tensor shape $[1, 2]$:
  - Index 0: `AUTHENTIC` ($p = 0.9839 \rightarrow 98.4\%$)
  - Index 1: `SYNTHETIC_DEEPFAKE` ($p = 0.0161 \rightarrow 1.6\%$)
- **Score Calibration:** Softmax probabilities are explicitly reported as uncalibrated model scores. The matrix title was updated to reflect `Heuristic Multi-Signal Fusion (Uncalibrated)`.

### 4.4 2D FFT Frequency Analysis Audit
- **Calculation:** 2D FFT with 2D Hann windowing centered at $(128, 128)$.
- **Roll-Off vs Latent Diffusion:** In low-resolution images ($66\times 64$), bilinear resizing to $256\times 256$ introduces periodic grid harmonics ($2.50\times$) and high-frequency attenuation ($\text{HF ratio} = 0.0078$).
- **Correction:** When $\min(w, h) < 128$, the engine notes:
  `"2D FFT frequency spectrum evaluated across native compact asset (66x64). High-frequency roll-off reflects physical resolution boundaries rather than latent diffusion upsampling."`
  and assigns $\text{severity} = 0.0$ and `fft_status = "NOMINAL"`.

### 4.5 Noise Residual Statistics Audit
- **Mathematics:**
  $$\text{Kurtosis} = \frac{\frac{1}{N}\sum (x - \bar{x})^4}{\left(\frac{1}{N}\sum (x - \bar{x})^2\right)^2}, \quad \text{Excess Kurtosis} = \text{Kurtosis} - 3.0$$
- **Finding:** A kurtosis of $28.7$ gives an excess kurtosis of $+25.7$, which is leptokurtic. High edge density on small image patches causes large residuals. Mislabeled as Gaussian in previous versions.
- **Correction:** The system now reports:
  `"Sensor noise residual exhibits elevated kurtosis (28.7, excess: 25.7, variance: 61.844) attributable to high edge density on compact (66x64) asset; non-Gaussian/leptokurtic, consistent with compressed web portraits."`
  The UI pill renders `EDGE RESIDUAL (COMPACT)`.

### 4.6 C2PA Provenance & Content Credentials Audit
- **Engine:** `backend/analysis/forensics/c2pa_provenance.py` inspecting JUMBF boxes, PNG chunks (`caDI`, `caDO`, `c2pa`), and ISO-BMFF UUIDs.
- **Semantics:** Missing manifests are mapped to `MISSING_PROVENANCE` / `NO_CREDENTIALS_PRESENT`. In compliance with C2PA standards, missing credentials are treated neutrally (0% score, 0.0 suspicion contribution).

---

## 5. Automated Test Results & Verification

All automated tests executed cleanly in the project's virtual environment (`d:\BPUT\venv\Scripts\python.exe`):

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\BPUT, configfile: pytest.ini
collected 40 items

tests/test_image_forensics_pipeline.py::test_authentic_photo_classified_likely_authentic PASSED [  2%]
tests/test_image_forensics_pipeline.py::test_generative_ai_metadata_detection PASSED [  5%]
tests/test_image_forensics_pipeline.py::test_content_based_synthetic_image_detection PASSED [  7%]
tests/test_image_forensics_pipeline.py::test_animated_gif_multi_frame_extraction PASSED [ 10%]
tests/test_image_forensics_pipeline.py::test_llm_analyst_authentic_media_grounding PASSED [ 12%]
tests/test_image_forensics_pipeline.py::test_llm_analyst_suspicious_media_playbook PASSED [ 15%]
tests/test_image_forensics_pipeline.py::test_ai_generated_image_with_diffusion_noise_kurtosis PASSED [ 17%]
tests/test_image_forensics_pipeline.py::test_camera_exif_grounding_preserves_safe PASSED [ 20%]
tests/test_image_forensics_pipeline.py::test_high_res_smartphone_photo_with_sharp_edges_is_authentic PASSED [ 22%]
tests/test_image_forensics_pipeline.py::test_configurable_thresholds_honored PASSED [ 25%]
tests/test_media_forensics_subsystem.py::TestC2PAProvenanceEngine::test_missing_provenance PASSED [ 27%]
tests/test_media_forensics_subsystem.py::TestC2PAProvenanceEngine::test_synthetic_ai_claimed_manifest PASSED [ 30%]
tests/test_media_forensics_subsystem.py::TestC2PAProvenanceEngine::test_hardware_provenance_manifest PASSED [ 32%]
tests/test_media_forensics_subsystem.py::TestImageForensicsEngine::test_frequency_domain_analysis PASSED [ 35%]
tests/test_media_forensics_subsystem.py::TestImageForensicsEngine::test_ela_disparity_and_heatmap_generation PASSED [ 37%]
tests/test_media_forensics_subsystem.py::TestImageForensicsEngine::test_prnu_sensor_noise_kurtosis PASSED [ 40%]
tests/test_media_forensics_subsystem.py::TestVideoForensicsEngine::test_video_metadata_and_keyframe_sampling PASSED [ 42%]
tests/test_media_forensics_subsystem.py::TestCalibratedCorrelationEngine::test_strict_grounding_web_stripped_returns_benign_unverified PASSED [ 45%]
tests/test_media_forensics_subsystem.py::TestCalibratedCorrelationEngine::test_grounded_camera_provenance PASSED [ 47%]
tests/test_media_forensics_subsystem.py::TestCalibratedCorrelationEngine::test_noise_flattening_not_masked_by_camera_exif PASSED [ 50%]
tests/test_media_forensics_subsystem.py::TestCalibratedCorrelationEngine::test_synthetic_ai_detection_elevation PASSED [ 52%]
tests/test_media_forensics_subsystem.py::TestForensicsAPIEndpoints::test_post_image_forensics_endpoint PASSED [ 55%]
tests/test_media_forensics_subsystem.py::TestForensicsAPIEndpoints::test_post_video_forensics_endpoint PASSED [ 57%]
tests/test_media_forensics_subsystem.py::TestForensicsAPIEndpoints::test_get_nonexistent_report_returns_404 PASSED [ 60%]
tests/test_media_forensics_subsystem.py::TestDatabasePersistence::test_forensic_columns_persisted_and_rehydrated PASSED [ 62%]
tests/test_forensic_pipeline_reconciliation.py::test_compact_portrait_regression_sample PASSED [ 65%]
tests/test_forensic_pipeline_reconciliation.py::test_face_detection_status_model PASSED [ 67%]
tests/test_forensic_pipeline_reconciliation.py::test_kurtosis_mathematical_consistency PASSED [ 70%]
tests/test_forensic_pipeline_reconciliation.py::test_c2pa_missing_provenance_is_neutral PASSED [ 72%]
tests/test_forensic_pipeline_reconciliation.py::test_neural_vision_detector_readiness_and_class_mapping PASSED [ 75%]
tests/test_forensic_integrity_audit.py::test_noisy_or_scoring_and_attribution_trace PASSED [ 77%]
tests/test_forensic_integrity_audit.py::test_vision_deepfake_detector_state_machine PASSED [ 80%]
tests/test_forensic_integrity_audit.py::test_video_audio_visual_synchronization_qualification PASSED [ 82%]
tests/test_forensic_integrity_audit.py::test_c2pa_unverified_manifest_status PASSED [ 85%]
tests/test_forensic_integrity_audit.py::test_exif_camera_claim_does_not_damp_suspicion PASSED [ 87%]
tests/test_forensic_integrity_audit.py::test_neural_vision_detector_ready_and_inference PASSED [ 90%]
tests/test_forensic_integrity_audit.py::test_qwen_primary_llm_service_manifest_and_execution PASSED [ 92%]
tests/test_forensic_integrity_audit.py::test_real_phone_photo_regression_no_face_no_false_positive PASSED [ 95%]
tests/test_forensic_integrity_audit.py::test_video_pipeline_authenticity_and_matrix_contract PASSED [ 97%]
tests/test_forensic_integrity_audit.py::test_screen_recording_presentation_dynamics_and_neural_aggregation PASSED [100%]

======================== 40 passed in 95.86s ========================
```

---

## 6. Files Modified & Added

1. `backend/analysis/forensics/image_forensics.py`:
   - Added low-resolution adaptive face detection ($16\text{ px}$ minimum face size for $\min(w, h) < 120$).
   - Implemented face detection status model (`FACE_DETECTED`, `NO_FACE_DETECTED`, `INSUFFICIENT_RESOLUTION`, etc.).
   - Gated biometric warping checks on face resolution baseline ($44\text{ px}$).
   - Added physical Nyquist frequency roll-off baseline handling for compact assets ($< 128\text{ px}$).
   - Added `COMPACT_EDGE_KURTOSIS` noise profile to prevent false Gaussian claims.
2. `backend/analysis/forensics/correlation_engine.py`:
   - Connected evaluated neural vision probability directly to `ai_generation_score`.
   - Reconciled `ai_gen_outcome` and `image_manipulation` outcome mappings.
   - Updated inconclusive reasoning and summary generation to distinguish low-anomaly profile ($< 50$) from elevated risk ($\ge 50$).
   - Added support for `FACE_DETECTED_INSUFFICIENT_RESOLUTION` and `NO_CREDENTIALS_PRESENT`.
3. `backend/analysis/deepfake_coordinator.py`:
   - Added explicit `original_dimensions`, `analysis_dimensions`, and `detector_dimensions` tracking in `threat_intelligence` and `forensic_metrics`.
4. `frontend/app.js`:
   - Fixed `primaryVerdictTitle` and banner to display `INCONCLUSIVE — LOW ANOMALY PROFILE` with cyan `#38bdf8` `LOW` badge when score $< 50$.
   - Replaced `'Digital Optical Profile'` placeholder with `No Hardware Sensor EXIF`.
   - Updated noise status pill to render `EDGE RESIDUAL (COMPACT)` and `LEPTOKURTIC RESIDUAL`.
   - Updated facial biometrics pill to render `RESOLUTION COMPACT` instead of `NOT APPLICABLE` when a face is detected.
   - Standardized matrix title to `8-Point Forensic Multi-Signal Matrix`.
   - Cleared stale state (`_lastForensicData = null`) upon new file selection.
5. `tests/test_forensic_pipeline_reconciliation.py`:
   - Added regression test suite verifying the sample portrait asset, face detection status model, kurtosis mathematics, and C2PA neutrality.

---

## 7. Operational Guidelines for Analysts

1. **Interpreting Compact Assets ($< 128\text{ px}$):**  
   Low-resolution assets cannot provide reliable high-frequency sensor noise or biometric seam warping evidence due to downsampling roll-off. Treat compact assets as `INSUFFICIENT_RESOLUTION` for biometrics rather than concluding no face was present.
2. **Provenance Reality:**  
   The absence of C2PA Content Credentials or EXIF camera tags is routine for web, chat, and screenshot media. Absence of provenance is never proof of AI generation or tampering.
3. **Neural Classifier vs Heuristics:**  
   When the MobileNetV3 neural classifier is active, its prediction reflects direct feature inspection for diffusion and GAN synthesis markers. Heuristic frequency roll-off from small images must not override a verified nominal neural profile.

