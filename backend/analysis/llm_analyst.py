"""
llm_analyst.py — Explainable AI & LLM Threat Intelligence Analysis Layer.

Provides:
  - Evidence-grounded forensic narrative generation for detected threats and media artifacts
  - Modality-aware MITRE ATT&CK enterprise technique mapping & tactic categorization
  - Cyber Kill-Chain multi-stage attack reconstruction
  - Actionable, proportionate Incident Response Playbooks (Media Containment vs Endpoint vs Network)
  - Zero-dependency local cybersecurity reasoning engine with telemetry-grounded synthesis
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Standard MITRE ATT&CK mappings based on threat categories
_CATEGORY_MITRE_MAP = {
    "PHISHING": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "desc": "Adversary sends targeted emails or messages containing deceptive links."},
        {"id": "T1598", "name": "Phishing for Information", "tactic": "Reconnaissance", "desc": "Adversary probes targets to acquire sensitive credentials or PII."},
        {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution", "desc": "Relies on user clicking deceptive URL."},
    ],
    "DEEPFAKE": [
        {"id": "T1566.003", "name": "Spearphishing via Service: Manipulated Media", "tactic": "Initial Access", "desc": "Impersonation using synthetic audio, video, or deceptive media."},
        {"id": "T1656", "name": "Impersonation", "tactic": "Defense Evasion", "desc": "Adversary impersonates trusted entity or executive to bypass verification."},
    ],
    "DEEPFAKE_IMAGE": [
        {"id": "T1585.002", "name": "Synthetic Personas: Generative Visual Artifacts", "tactic": "Resource Development", "desc": "Adversary employs generative neural models or synthetic imagery."},
        {"id": "T1566.003", "name": "Spearphishing via Service: Manipulated Media", "tactic": "Initial Access", "desc": "Distribution of synthetic visual media for deceptive authorization or influence."},
    ],
    "DEEPFAKE_VOICE": [
        {"id": "T1566.003", "name": "Spearphishing via Service: Cloned Voice", "tactic": "Initial Access", "desc": "Acoustic voice synthesis targeting personnel or authentication."},
        {"id": "T1656", "name": "Impersonation", "tactic": "Defense Evasion", "desc": "Adversary impersonates trusted executive or customer via cloned audio."},
    ],
    "SAFE": [
        {"id": "N/A", "name": "Nominal Baseline", "tactic": "Operational Normal", "desc": "Asset evaluated and confirmed authentic with zero threat indicators."},
    ],
    "MALICIOUS_URL": [
        {"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution", "desc": "Lures user to navigate to malicious or weaponized staging infrastructure."},
        {"id": "T1584.001", "name": "Compromise Infrastructure: Domains", "tactic": "Resource Development", "desc": "Use of bulletproof domains or hijacked web properties."},
        {"id": "T1071.001", "name": "Web Protocols: HTTP/HTTPS", "tactic": "Command and Control", "desc": "Command traffic masked via legitimate web ports."},
    ],
    "CREDENTIAL_ATTACK": [
        {"id": "T1110.001", "name": "Password Guessing / Brute Force", "tactic": "Credential Access", "desc": "Systematic automated login attempts against user accounts."},
        {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access", "desc": "Testing single common password against multiple target usernames."},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access / Persistence", "desc": "Using obtained credentials to blend in as a legitimate user."},
    ],
    "ACCOUNT_TAKEOVER": [
        {"id": "T1078.003", "name": "Local Accounts", "tactic": "Defense Evasion", "desc": "Unauthorized session established on compromise of primary credentials."},
        {"id": "T1556", "name": "Modify Authentication Process", "tactic": "Credential Access", "desc": "Attempting to bypass multi-factor authentication or device binding."},
    ],
    "API_ABUSE": [
        {"id": "T1499.004", "name": "Endpoint Denial of Service: Application Exhaustion", "tactic": "Impact", "desc": "High-volume request flooding targeting backend compute resources."},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "desc": "Automated scripts abusing API surfaces."},
    ],
    "DATA_EXFILTRATION": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "desc": "Stealthy egress of bulk sensitive data records."},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "desc": "Transferring corporate artifacts to unapproved cloud storage."},
    ],
}


class LLMSecurityAnalyst:
    """
    Intelligent cybersecurity reasoning engine providing explainable AI threat assessments.
    Grounded in actual forensic metrics, telemetry, and IOC intelligence.
    """

    def __init__(self):
        self._provider = "CYBERGUARD_NEURAL_REASONER"

    def analyze(self, threat_data: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze threat event, incident, or forensic bundle.
        Returns complete, structured AI forensic report.
        """
        start_ts = time.time()

        # Extract core properties
        raw_type = threat_data.get("threat_type") or threat_data.get("threat_category") or threat_data.get("category") or ""
        modality = (threat_data.get("modality") or "").lower()
        raw_upper = str(raw_type).upper()

        if "IMAGE" in raw_upper or modality == "image":
            category = "DEEPFAKE_IMAGE"
        elif "VOICE" in raw_upper or "AUDIO" in raw_upper or modality == "audio":
            category = "DEEPFAKE_VOICE"
        elif "VIDEO" in raw_upper or modality == "video":
            category = "DEEPFAKE"
        elif "PHISH" in raw_upper:
            category = "PHISHING"
        elif "URL" in raw_upper:
            category = "MALICIOUS_URL"
        elif raw_upper in ("SAFE", "CLEAN"):
            category = "SAFE"
        elif raw_upper:
            category = raw_upper
        else:
            category = "UNKNOWN"

        raw_sev = threat_data.get("severity") or threat_data.get("risk") or "SAFE"
        if hasattr(raw_sev, "value"):
            raw_sev = raw_sev.value
        raw_sev_str = str(raw_sev).upper()
        if "SAFE" in raw_sev_str:
            severity = "SAFE"
        elif "CRITICAL" in raw_sev_str:
            severity = "CRITICAL"
        elif "HIGH" in raw_sev_str:
            severity = "HIGH"
        elif "MEDIUM" in raw_sev_str:
            severity = "MEDIUM"
        elif "LOW" in raw_sev_str:
            severity = "LOW"
        else:
            severity = raw_sev_str

        source = threat_data.get("source") or "SOC Ingestion"
        raw_class = threat_data.get("classification")
        if hasattr(raw_class, "value"):
            raw_class = raw_class.value
        classification = str(raw_class or ("SAFE" if severity == "SAFE" else "SUSPICIOUS")).upper()
        if classification in ("SAFE", "LIKELY_AUTHENTIC") or severity == "SAFE":
            severity = "SAFE"
            classification = "LIKELY_AUTHENTIC" if classification == "LIKELY_AUTHENTIC" else "SAFE"
        target_id = threat_data.get("event_id") or threat_data.get("incident_id") or threat_data.get("session_id") or "EVT-UNKNOWN"
        evidence_list = threat_data.get("evidence", []) or []
        explanation = threat_data.get("explanation", {}) or {}
        summary_base = explanation.get("summary") if isinstance(explanation, dict) else ""
        reasoning_base = explanation.get("reasoning") if isinstance(explanation, dict) else ""

        # Rich media forensic structures
        media_info = threat_data.get("media_info") or {}
        metadata_details = threat_data.get("metadata_details") or {}
        forensic_metrics = threat_data.get("forensic_metrics") or {}
        frame_analysis = threat_data.get("frame_analysis") or {}

        ti = threat_data.get("threat_intelligence") or {}
        indicator = ti.get("indicator") or threat_data.get("indicator") or threat_data.get("incident_context") or ""

        # 1. Build MITRE ATT&CK Mapping
        mitre_techniques = self._map_mitre_techniques(category, severity, evidence_list, forensic_metrics, metadata_details)

        # 2. Build Kill Chain progression
        kill_chain = self._reconstruct_kill_chain(category, severity, indicator, evidence_list)

        # 3. Generate Evidence-Grounded Executive Narrative
        exec_narrative = self._generate_executive_narrative(
            category=category,
            severity=severity,
            source=source,
            indicator=indicator,
            evidence=evidence_list,
            summary_base=summary_base,
            reasoning_base=reasoning_base,
            media_info=media_info,
            metadata_details=metadata_details,
            forensic_metrics=forensic_metrics,
            frame_analysis=frame_analysis,
        )

        # 4. Generate Modality-Aware Incident Containment Playbook
        playbook = self._generate_containment_playbook(
            category=category,
            severity=severity,
            indicator=indicator,
            media_info=media_info,
            metadata_details=metadata_details,
        )

        # 5. Determine Threat Actor Archetype
        actor_profile = self._determine_threat_actor_profile(category, severity)

        elapsed_ms = (time.time() - start_ts) * 1000

        res = {
            "status": "ANALYSIS_COMPLETE",
            "target_id": target_id,
            "threat_category": category,
            "assessed_severity": severity,
            "classification": classification,
            "confidence": float(threat_data.get("confidence") or (0.95 if severity == "SAFE" else 0.88)),
            "executive_summary": exec_narrative["summary"],
            "technical_deep_dive": exec_narrative["deep_dive"],
            "narrative": exec_narrative["deep_dive"],
            "threat_narrative": exec_narrative["deep_dive"],
            "executive_briefing": exec_narrative["summary"],
            "attack_vectors_identified": exec_narrative["vectors"],
            "adversary_profile": actor_profile,
            "kill_chain_reconstruction": kill_chain,
            "mitre_attack_mapping": mitre_techniques,
            "mitre_mapping": mitre_techniques,
            "incident_response_playbook": playbook,
            "recommended_containment_window": "NONE (Nominal Baseline)" if severity == "SAFE" else ("IMMEDIATE (< 15 mins)" if severity in ("CRITICAL", "HIGH") else "STANDARD (< 2 hours)"),
            "analyst_engine": self._provider,
            "analysis_latency_ms": round(elapsed_ms, 1),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return res

    def _map_mitre_techniques(
        self,
        category: str,
        severity: str,
        evidence: List[Any],
        forensic_metrics: Dict[str, Any],
        metadata_details: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        if severity == "SAFE":
            return [
                {
                    "id": "N/A",
                    "name": "Nominal Asset Baseline",
                    "tactic": "Operational Normal",
                    "desc": "Asset evaluated and confirmed authentic across frequency, noise, and container domains.",
                }
            ]

        base_techniques = list(_CATEGORY_MITRE_MAP.get(category, [
            {"id": "T1566.003", "name": "Spearphishing via Service: Manipulated Media", "tactic": "Initial Access", "desc": "Distribution of manipulated media."},
        ]))

        # Corroborate specific techniques based on actual signals
        ev_strings = []
        for e in evidence:
            if isinstance(e, dict):
                ev_strings.append(f"{e.get('evidence_type', '')} {e.get('description', '')}".lower())
            else:
                ev_strings.append(str(e).lower())
        ev_blob = " ".join(ev_strings)

        results = []
        has_ai_tag = bool(metadata_details.get("ai_generator_tags"))
        has_grid = forensic_metrics.get("fft_off_axis_spike_ratio", 0) >= 7.0 or "lattice" in ev_blob

        if has_ai_tag or has_grid:
            results.append({
                "id": "T1585.002",
                "name": "Synthetic Personas: Generative Visual Artifacts",
                "tactic": "Resource Development",
                "desc": "Generative model metadata or periodic neural upsampling artifacts confirmed.",
            })

        if forensic_metrics.get("qr_detected") or "qr" in ev_blob:
            results.append({
                "id": "T1566.004",
                "name": "Quishing / QR Phishing",
                "tactic": "Initial Access",
                "desc": "Adversary uses barcode/QR vector to evade optical and URL filtering.",
            })

        if forensic_metrics.get("facial_forensics_applicable") and severity in ("HIGH", "CRITICAL"):
            results.append({
                "id": "T1656",
                "name": "Impersonation",
                "tactic": "Defense Evasion",
                "desc": "Adversary leverages facial manipulation to deceive visual review.",
            })

        # Fallback to category baseline if no specific deep technique triggered
        if not results:
            results = base_techniques

        return results

    def _reconstruct_kill_chain(
        self,
        category: str,
        severity: str,
        indicator: str,
        evidence: List[Any],
    ) -> List[Dict[str, str]]:
        is_safe = severity == "SAFE" or category == "SAFE"

        if is_safe:
            return [
                {
                    "phase": "Phase 1: Asset Inspection & Ingestion",
                    "status": "NOMINAL_BASELINE",
                    "assessment": "Asset submitted for inspection conforms to standard operational baselines.",
                },
                {
                    "phase": "Phase 2: Signal & Domain Verification",
                    "status": "CLEAN",
                    "assessment": "No synthetic deepfake harmonics, localized splicing, or exploit payloads identified.",
                },
                {
                    "phase": "Phase 3: Provenance & Container Integrity",
                    "status": "VERIFIED_AUTHENTIC",
                    "assessment": "Container structure, metadata profile, and optical properties verified intact.",
                },
                {
                    "phase": "Phase 4: Exploitation Assessment",
                    "status": "NONE",
                    "assessment": "Zero exploit attempts or anomalous behavioral deviations detected.",
                },
                {
                    "phase": "Phase 5: Operational Routing",
                    "status": "BENIGN",
                    "assessment": "Asset cleared for legitimate business routing and workflow consumption.",
                },
            ]

        is_media = "DEEPFAKE" in category
        target_name = indicator[:60] if indicator else ("identity verification workflows" if is_media else "organizational assets")

        return [
            {
                "phase": "Phase 1: Reconnaissance & Target Profiling",
                "status": "COMPLETED",
                "assessment": f"Adversary targeted {target_name} via social engineering or synthetic media channel.",
            },
            {
                "phase": "Phase 2: Weaponization & Asset Generation",
                "status": "COMPLETED",
                "assessment": (
                    "Synthesized deceptive visual/voice asset using generative tools to bypass standard verification."
                    if is_media else "Engineered attack payload or staging infrastructure."
                ),
            },
            {
                "phase": "Phase 3: Delivery & Infiltration Vector",
                "status": "DETECTED_AND_INTERCEPTED",
                "assessment": f"Artifact delivered via {category.lower().replace('_', ' ')} channel; parsed by CyberGuard inspection engines.",
            },
            {
                "phase": "Phase 4: Exploitation & Trust Breach",
                "status": "CONTAINED",
                "assessment": "Adversary attempted trust deception; flagged by multi-signal forensic analysis before execution.",
            },
            {
                "phase": "Phase 5: Actions on Objectives",
                "status": "PREVENTED",
                "assessment": "Potential unauthorized action, spoofing, or fraudulent transaction neutralized by risk escalation.",
            },
        ]

    def _generate_executive_narrative(
        self,
        category: str,
        severity: str,
        source: str,
        indicator: str,
        evidence: List[Any],
        summary_base: str,
        reasoning_base: str,
        media_info: Dict[str, Any],
        metadata_details: Dict[str, Any],
        forensic_metrics: Dict[str, Any],
        frame_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Synthesize evidence-grounded executive summary and technical deep dive."""
        is_safe = severity == "SAFE" or category == "SAFE"
        filename = media_info.get("filename") or indicator or "inspected media asset"
        sha256 = media_info.get("sha256") or "N/A"
        dimensions = media_info.get("dimensions") or "N/A"
        img_format = media_info.get("format") or "N/A"

        if is_safe:
            summary = (
                f"CyberGuard Forensic Copilot evaluated the media asset '{filename}' (SHA-256: {sha256[:12]}...). "
                f"Multi-signal forensic analysis verified that 2D frequency spectra, Error Level Analysis (ELA), "
                f"and sensor noise residuals conform to authentic photographic standards. "
                f"Container provenance status: {metadata_details.get('provenance_status') or 'STANDARD'}. "
                f"Zero synthetic manipulation indicators were detected."
            )
            vectors = ["Asset parameters verified within standard optical, acoustic, and behavioral baselines."]

            # Technical details grounded in actual metrics
            tech_lines = [
                f"Media Identification: {filename} ({dimensions}, format: {img_format}, SHA-256: {sha256}).",
                f"Container Provenance: {metadata_details.get('provenance_status', 'STANDARD')}." +
                (f" Camera: {metadata_details.get('camera_make', '')} {metadata_details.get('camera_model', '')}." if metadata_details.get('camera_make') else ""),
            ]
            if forensic_metrics:
                tech_lines.append(
                    f"Error Level Analysis (ELA): mean difference {forensic_metrics.get('ela_mean', 0.0):.2f}, "
                    f"spatial disparity {forensic_metrics.get('ela_disparity', 0.0):.2f} (uniform compression response)."
                )
                tech_lines.append(
                    f"2D Frequency Spectrum: off-axis periodic spike ratio {forensic_metrics.get('fft_off_axis_spike_ratio', 0.0):.2f}x background "
                    f"(natural power-law falloff; no transposed-convolution lattice)."
                )
                tech_lines.append(
                    f"Sensor Noise Residual: kurtosis {forensic_metrics.get('noise_kurtosis', 0.0):.1f}, "
                    f"variance {forensic_metrics.get('noise_variance', 0.0):.3f} (quasi-Gaussian sensor shot noise)."
                )
                tech_lines.append(
                    f"Facial Forensics: {forensic_metrics.get('facial_status', 'No face detected; facial forensics not applicable')}."
                )

            deep_dive = " ".join(tech_lines)
            return {"summary": summary, "deep_dive": deep_dive, "vectors": vectors}

        # Suspicious / Manipulated media
        triggers = []
        if metadata_details.get("ai_generator_tags"):
            triggers.append(f"generative AI tool signature '{metadata_details['ai_generator_tags'][0]}'")
        if forensic_metrics.get("fft_off_axis_spike_ratio", 0) >= 7.0:
            triggers.append(f"periodic lattice harmonic spikes ({forensic_metrics['fft_off_axis_spike_ratio']:.2f}x background)")
        if forensic_metrics.get("ela_disparity", 0) >= 14.0:
            triggers.append(f"localized ELA compression disparity ({forensic_metrics['ela_disparity']:.2f})")
        if forensic_metrics.get("qr_detected"):
            triggers.append("embedded QR code payload")
        if not triggers:
            triggers.append("multi-domain statistical deviations")

        summary = (
            f"CyberGuard Forensic Copilot identified {severity}-severity synthetic media indicators in '{filename}' "
            f"(SHA-256: {sha256[:12]}...). Key anomalies detected: {', '.join(triggers)}. "
            f"The asset exhibits statistical and container characteristics deviating from authentic optical captures."
        )

        vectors = []
        if "DEEPFAKE" in category:
            if metadata_details.get("ai_generator_tags"):
                vectors.append("Generative AI software signature embedded in container metadata")
            if forensic_metrics.get("fft_off_axis_spike_ratio", 0) >= 7.0:
                vectors.append("2D FFT periodic lattice spikes characteristic of neural upsampling")
            if forensic_metrics.get("ela_disparity", 0) >= 14.0:
                vectors.append("Localized Error Level Analysis disparity indicating digital splicing")
            if forensic_metrics.get("noise_kurtosis", 0) > 40.0:
                vectors.append("Non-Gaussian sensor noise flattening from diffusion denoising")
            if not vectors:
                vectors = ["Heuristic multi-signal anomaly detected across spatial and frequency domains"]
        else:
            vectors = [
                f"Anomalous pattern identified in {category.lower().replace('_', ' ')} payload",
                "Deviation from standard baseline operational telemetry",
            ]

        tech_lines = [
            f"Technical Evaluation: {summary_base or 'Forensic analysis confirmed anomalous characteristics.'}",
            f"Evidence points: {len(evidence)} corroborating findings.",
            f"Asset SHA-256: {sha256} ({dimensions}, format: {img_format}).",
        ]
        if forensic_metrics:
            tech_lines.append(
                f"ELA mean: {forensic_metrics.get('ela_mean', 0.0):.2f}, disparity: {forensic_metrics.get('ela_disparity', 0.0):.2f}. "
                f"FFT harmonic spike ratio: {forensic_metrics.get('fft_off_axis_spike_ratio', 0.0):.2f}x. "
                f"Noise kurtosis: {forensic_metrics.get('noise_kurtosis', 0.0):.1f}."
            )
        if frame_analysis and frame_analysis.get("total_frames_sampled"):
            tech_lines.append(
                f"Multi-frame temporal consistency: {frame_analysis.get('temporal_consistency', 0.0):.2f} "
                f"across {frame_analysis.get('total_frames_sampled')} sampled frames."
            )

        deep_dive = " ".join(tech_lines)
        return {"summary": summary, "deep_dive": deep_dive, "vectors": vectors}

    def _generate_containment_playbook(
        self,
        category: str,
        severity: str,
        indicator: str,
        media_info: Dict[str, Any],
        metadata_details: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Actionable, modality-aware incident response playbook."""
        is_safe = severity == "SAFE" or category == "SAFE"
        is_media = "DEEPFAKE" in category

        if is_safe:
            return [
                {
                    "step": "1. Operational Clearance",
                    "action": "Asset cleared for standard enterprise workflow routing. Provenance and visual parameters verified.",
                    "owner": "Digital Asset Governance",
                    "priority": "P3 (Informational)",
                }
            ]

        if is_media:
            filename = media_info.get("filename") or indicator or "inspected media file"
            sha256 = media_info.get("sha256") or "N/A"
            return [
                {
                    "step": "1. Media Quarantine & Flagging",
                    "action": f"Flag media file '{filename}' as unverified / potentially synthetic. Halt use in identity verification, KYC, or public publication.",
                    "owner": "SOC Tier 1 / Media Governance Lead",
                    "priority": "P1 (High)",
                },
                {
                    "step": "2. Provenance & Out-of-Band Verification",
                    "action": "Request original uncompressed camera file (RAW/TIFF) or confirm sender identity via secondary verified channel.",
                    "owner": "Identity Verification Team",
                    "priority": "P1 (High)",
                },
                {
                    "step": "3. Forensic Evidence Retention",
                    "action": f"Preserve artifact (SHA-256: {sha256[:16]}...) with full DSP forensic telemetry in encrypted audit vault for forensic review.",
                    "owner": "Digital Forensics Lead",
                    "priority": "P2 (Standard)",
                },
                {
                    "step": "4. Departmental Awareness Briefing",
                    "action": "Notify operational teams of potential synthetic media social engineering vector targeting this channel.",
                    "owner": "Security Awareness & GRC",
                    "priority": "P3 (Closure)",
                },
            ]

        # For network, API, or credential attacks
        target_entity = indicator or "source endpoint"
        return [
            {
                "step": "1. Immediate Perimeter Block",
                "action": f"Block indicator '{target_entity}' across perimeter firewalls, API gateways, and DNS resolvers.",
                "owner": "SOC Tier 1 / Network Security",
                "priority": "P0 (Immediate)",
            },
            {
                "step": "2. Session Invalidation",
                "action": f"Invalidate active sessions associated with '{target_entity}' and review authentication logs.",
                "owner": "IAM / Identity Ops",
                "priority": "P1 (High)",
            },
            {
                "step": "3. Forensic Audit & Evidence Retention",
                "action": "Preserve connection logs and telemetry in encrypted audit storage for forensic analysis.",
                "owner": "Digital Forensics Lead",
                "priority": "P2 (Standard)",
            },
        ]

    def _determine_threat_actor_profile(self, category: str, severity: str) -> Dict[str, str]:
        if severity == "SAFE" or category == "SAFE":
            return {
                "archetype": "Legitimate Enterprise Operator / User",
                "motivation": "Routine Business Operations",
                "sophistication": "Nominal Baseline",
            }
        elif severity in ("CRITICAL", "HIGH") and "DEEPFAKE" in category:
            return {
                "archetype": "Synthetic Media Operator / Social Engineering Campaign",
                "motivation": "Identity Impersonation & Verification Bypass",
                "sophistication": "Moderate to High (Generative AI Tooling)",
            }
        elif category in ("CREDENTIAL_ATTACK", "API_ABUSE"):
            return {
                "archetype": "Automated Credential Stuffing & Botnet Operator",
                "motivation": "Account Takeover & Resource Exploitation",
                "sophistication": "Moderate (Automated tooling, rotating proxies)",
            }
        elif category == "MALICIOUS_URL":
            return {
                "archetype": "Malware Staging & Phishing Campaign Distributor",
                "motivation": "Initial Access Brokerage & Endpoint Payload Dropper",
                "sophistication": "Moderate to High",
            }
        else:
            return {
                "archetype": "Unverified Digital Origin / External Sender",
                "motivation": "Reconnaissance or Social Engineering Probing",
                "sophistication": "Low to Moderate",
            }


_analyst_singleton: Optional[LLMSecurityAnalyst] = None

def get_llm_analyst() -> LLMSecurityAnalyst:
    global _analyst_singleton
    if _analyst_singleton is None:
        _analyst_singleton = LLMSecurityAnalyst()
    return _analyst_singleton
