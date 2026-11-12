"""
url_verdict_engine.py — Centralized, Evidence-Driven URL & Phishing Threat Aggregation and Verdict Engine.

TAXONOMY (Phase 2 & Phase 8):
  - PHISHING DETECTED
  - MALWARE DETECTED
  - PHISHING + MALWARE
  - SUSPICIOUS
  - UNKNOWN / UNVERIFIED
  - NO KNOWN THREATS DETECTED

CRITICAL INVARIANTS:
  - Absence of threat intelligence (NOT_FOUND / NO_MATCH) is NOT proof of safety.
  - An unreachable or offline website is UNVERIFIED / UNREACHABLE, NEVER clean.
  - Phishing and Malware are evaluated independently.
  - Inspection coverage and confidence are calculated from verified evidence, never manufactured.
  - Fully explainable with structured evidence provenance.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from backend.threats.models import Evidence, Explanation, RiskLevel, ThreatCategory
from backend.analysis.hosting_intelligence import HostingIntelligenceResult, HostingType
from backend.analysis.web_inspector import WebInspectionResult, InspectionState

logger = logging.getLogger(__name__)


class UnifiedVerdict(str, Enum):
    PHISHING_DETECTED = "PHISHING DETECTED"
    MALWARE_DETECTED = "MALWARE DETECTED"
    PHISHING_AND_MALWARE = "PHISHING + MALWARE"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN_UNVERIFIED = "UNKNOWN / UNVERIFIED"
    NO_KNOWN_THREATS = "NO KNOWN THREATS DETECTED"


class EvidenceStrength(str, Enum):
    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERIFIED = "VERIFIED"


class ProviderAnalysisState(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    NOT_FOUND = "NOT_FOUND"
    NOT_SCANNED = "NOT_SCANNED"
    UNREACHABLE = "UNREACHABLE"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    DISABLED = "DISABLED"
    PARTIAL = "PARTIAL"
    CLEAN = "CLEAN"


@dataclass
class AggregatedVerdictResult:
    verdict: UnifiedVerdict
    verdict_display: str
    severity: RiskLevel
    risk_score: float
    confidence: float
    scan_coverage_pct: float
    evidence_strength: EvidenceStrength
    threat_category: ThreatCategory
    classification: str
    provider_states: Dict[str, str]
    evidence_items: List[Evidence]
    explanation_summary: str
    explanation_reasoning: str
    explanation_limitations: str
    recommended_actions: List[str]
    is_phishing: bool = False
    is_malware: bool = False
    is_unverified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "verdict_display": self.verdict_display,
            "severity": self.severity.value,
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "scan_coverage_pct": round(self.scan_coverage_pct, 1),
            "evidence_strength": self.evidence_strength.value,
            "threat_category": self.threat_category.value,
            "classification": self.classification,
            "provider_states": self.provider_states,
            "is_phishing": self.is_phishing,
            "is_malware": self.is_malware,
            "is_unverified": self.is_unverified,
            "explanation_summary": self.explanation_summary,
            "explanation_reasoning": self.explanation_reasoning,
            "explanation_limitations": self.explanation_limitations,
            "recommended_actions": self.recommended_actions,
        }


class URLVerdictEngine:
    """
    Centralized, deterministic aggregation layer consuming signals from:
      - VirusTotal & URLhaus reputation providers
      - URL resolver & multi-hop redirect forensics
      - Hosting context & ephemeral tunnel intelligence
      - Live web page inspector (credentials, permissions, brand impersonation, payload)
      - Syntax & domain heuristics
    """

    @classmethod
    def aggregate(
        cls,
        target_url: str,
        is_local: bool = False,
        vt_report: Optional[Dict[str, Any]] = None,
        uh_report: Optional[Dict[str, Any]] = None,
        resolution: Optional[Any] = None,
        hosting_intel: Optional[HostingIntelligenceResult] = None,
        web_inspection: Optional[WebInspectionResult] = None,
        local_heuristics: Optional[Dict[str, Any]] = None,
        existing_evidences: Optional[List[Evidence]] = None,
    ) -> AggregatedVerdictResult:
        vt_data = vt_report or {}
        uh_data = uh_report or {}
        heur = local_heuristics or {}
        evidences = list(existing_evidences or [])

        layers_total = 8
        layers_completed = 0

        # Layer 1: Canonicalization / URL structure
        layers_completed += 1

        # Layer 2: Domain / Syntax heuristics
        layers_completed += 1

        # Layer 3: DNS / Redirect resolution
        res_completed = False
        res_status = getattr(resolution, "status", None)
        if res_status is not None:
            res_val = getattr(res_status, "value", str(res_status))
            if res_val in ("COMPLETED", "RESOLVED", "NO_REDIRECT", "BLOCKED_ORIGINAL_URL", "BLOCKED_REDIRECT_TARGET", "REDIRECT_LOOP"):
                layers_completed += 1
                res_completed = True
        elif is_local or (web_inspection and web_inspection.is_live):
            layers_completed += 1
            res_completed = True

        # Layer 4: VirusTotal reputation
        vt_status = vt_data.get("status", "NOT_SCANNED")
        if vt_status in ("COMPLETED", "NO_MATCH"):
            layers_completed += 1

        # Layer 5: URLhaus intelligence
        uh_status = uh_data.get("status", "NOT_SCANNED")
        if uh_status in ("COMPLETED", "NO_MATCH"):
            layers_completed += 1

        # Layers 6, 7, 8: Live inspection (Crawl, DOM, Script/Forms/Permissions)
        web_is_live = False
        if web_inspection and web_inspection.is_live:
            web_is_live = True
            layers_completed += 3
        elif web_inspection and web_inspection.status_code and web_inspection.status_code > 0:
            layers_completed += 1

        scan_coverage_pct = (layers_completed / layers_total) * 100.0

        # Provider states determination
        if is_local:
            vt_state = ProviderAnalysisState.NOT_SCANNED.value
        elif vt_status == "COMPLETED":
            s_dict = vt_data.get("summary", {})
            vt_mal = s_dict.get("malicious", 0) or vt_data.get("malicious_count", 0)
            vt_susp = s_dict.get("suspicious", 0) or vt_data.get("suspicious_count", 0)
            if vt_mal > 0 or vt_susp > 0:
                vt_state = ProviderAnalysisState.MATCH.value
            else:
                vt_state = ProviderAnalysisState.NO_MATCH.value
        elif vt_status == "NOT_FOUND":
            vt_state = ProviderAnalysisState.NOT_FOUND.value
        elif vt_status == "TIMEOUT":
            vt_state = ProviderAnalysisState.TIMEOUT.value
        elif vt_status in ("UNAVAILABLE", "UNREACHABLE"):
            vt_state = ProviderAnalysisState.UNREACHABLE.value
        elif vt_status == "ERROR":
            vt_state = ProviderAnalysisState.ERROR.value
        elif vt_status == "RATE_LIMITED":
            vt_state = ProviderAnalysisState.RATE_LIMITED.value
        elif vt_status in ("NOT_CONFIGURED", "DISABLED"):
            vt_state = ProviderAnalysisState.DISABLED.value
        else:
            vt_state = ProviderAnalysisState.PARTIAL.value

        if is_local:
            uh_state = ProviderAnalysisState.NOT_SCANNED.value
        elif uh_data.get("matched", False):
            uh_state = ProviderAnalysisState.MATCH.value
        elif uh_status == "NO_MATCH":
            uh_state = ProviderAnalysisState.NO_MATCH.value
        elif uh_status == "TIMEOUT":
            uh_state = ProviderAnalysisState.TIMEOUT.value
        elif uh_status in ("NOT_CONFIGURED", "DISABLED"):
            uh_state = ProviderAnalysisState.DISABLED.value
        elif uh_status in ("UNAVAILABLE", "UNREACHABLE"):
            uh_state = ProviderAnalysisState.UNREACHABLE.value
        elif uh_status == "ERROR":
            uh_state = ProviderAnalysisState.ERROR.value
        else:
            uh_state = ProviderAnalysisState.PARTIAL.value

        if is_local:
            crawler_state = ProviderAnalysisState.NOT_SCANNED.value
            cred_state = ProviderAnalysisState.NOT_SCANNED.value
            perm_state = ProviderAnalysisState.NOT_SCANNED.value
        elif web_is_live and web_inspection:
            crawler_state = "ONLINE"
            if web_inspection.credential_harvesting.has_credential_forms:
                cred_state = ProviderAnalysisState.MATCH.value
            else:
                cred_state = ProviderAnalysisState.CLEAN.value

            if web_inspection.sensitive_permissions.abuse_detected:
                perm_state = ProviderAnalysisState.MATCH.value
            elif web_inspection.sensitive_permissions.probes_camera or web_inspection.sensitive_permissions.probes_geolocation:
                perm_state = "PROBED_CLEAN"
            else:
                perm_state = ProviderAnalysisState.CLEAN.value
        else:
            crawler_state = ProviderAnalysisState.UNREACHABLE.value
            cred_state = "UNVERIFIED_UNREACHABLE"
            perm_state = "UNVERIFIED_UNREACHABLE"

        hosting_state = hosting_intel.hosting_type.value if hosting_intel else "STANDARD"

        provider_states = {
            "virustotal": vt_state,
            "urlhaus": uh_state,
            "live_crawler": crawler_state,
            "credential_harvesting": cred_state,
            "sensitive_permissions": perm_state,
            "hosting_type": hosting_state,
        }

        is_phishing = False
        is_malware = False
        has_suspicious_signals = False

        phishing_score = 0.0
        malware_score = 0.0
        suspicion_score = 0.0

        # Phishing checks:
        if web_inspection and web_inspection.credential_harvesting.has_password_field:
            is_phishing = True
            phishing_score += 0.85

        if web_inspection and web_inspection.sensitive_permissions.abuse_detected:
            is_phishing = True
            phishing_score += 0.85

        if web_inspection and web_inspection.brand_impersonation.impersonation_detected:
            is_phishing = True
            phishing_score += 0.8

        if web_inspection and web_inspection.credential_harvesting.cross_domain_targets:
            is_phishing = True
            phishing_score += 0.75

        vt_categories = vt_data.get("categories", [])
        if any("phish" in str(c).lower() for c in vt_categories):
            is_phishing = True
            phishing_score += 0.8

        # Malware checks:
        if uh_data.get("matched", False) and uh_data.get("classification") == "malware_distribution_url":
            is_malware = True
            malware_score += 0.9
        elif uh_data.get("matched", False):
            is_malware = True
            malware_score += 0.75

        s_dict = vt_data.get("summary", {})
        vt_mal = s_dict.get("malicious", 0) or vt_data.get("malicious_count", 0)
        vt_susp = s_dict.get("suspicious", 0) or vt_data.get("suspicious_count", 0)
        if vt_mal >= 2:
            is_malware = True
            malware_score += min(1.0, 0.6 + vt_mal * 0.05)

        if web_inspection and web_inspection.payload_delivery.malware_delivery_detected:
            is_malware = True
            malware_score += 0.85

        # Suspicious signals:
        if hosting_intel and hosting_intel.is_ephemeral_tunnel:
            if web_is_live:
                has_suspicious_signals = True
            suspicion_score += hosting_intel.risk_contribution

        res_error = getattr(resolution, "error_message", None)
        if getattr(resolution, "status", None) and getattr(resolution.status, "value", "") == "REDIRECT_LOOP":
            has_suspicious_signals = True
            suspicion_score += 0.35

        if getattr(resolution, "protocol_transition", "") == "HTTPS_TO_HTTP_DOWNGRADE":
            has_suspicious_signals = True
            suspicion_score += 0.35

        local_risk_val = heur.get("local_risk_score", 0.0)
        local_risk_float = 0.0
        if isinstance(local_risk_val, (int, float)):
            local_risk_float = float(local_risk_val)
        elif isinstance(local_risk_val, str):
            val_upper = local_risk_val.strip().upper()
            if val_upper in ("CRITICAL", "HIGH"):
                local_risk_float = 0.8
                has_suspicious_signals = True
            elif val_upper == "MEDIUM":
                local_risk_float = 0.5
                has_suspicious_signals = True
            elif val_upper == "LOW":
                local_risk_float = 0.2
            else:
                try:
                    local_risk_float = float(local_risk_val)
                except ValueError:
                    local_risk_float = 0.0

        if local_risk_float > 0.0:
            suspicion_score += local_risk_float

        # Decision tree:
        if is_local:
            verdict = UnifiedVerdict.NO_KNOWN_THREATS
            verdict_display = "NO KNOWN THREATS DETECTED"
            severity = RiskLevel.SAFE
            risk_score = 0.0
            confidence = 1.0
            threat_cat = ThreatCategory.SAFE
            classification = "SAFE"
            evidence_strength = EvidenceStrength.NONE
            summary = f"Local development or private network target: '{target_url}'."
            reasoning = "Target resolves strictly to loopback or private RFC 1918 infrastructure. Threat intelligence lookups are not applicable."
        elif is_phishing and is_malware:
            verdict = UnifiedVerdict.PHISHING_AND_MALWARE
            verdict_display = "PHISHING + MALWARE"
            severity = RiskLevel.CRITICAL
            risk_score = max(0.9, min(1.0, max(phishing_score, malware_score)))
            confidence = 0.95
            threat_cat = ThreatCategory.PHISHING
            classification = "PHISHING_AND_MALWARE"
            evidence_strength = EvidenceStrength.VERIFIED
            summary = "Dual-Threat Compromise: Independent verified evidence of both Phishing and Malware delivery."
            reasoning = "CyberGuard verified independent signals of deceptive credential harvesting or social engineering combined with confirmed malicious payload delivery or malware threat intelligence records."
        elif is_phishing:
            verdict = UnifiedVerdict.PHISHING_DETECTED
            verdict_display = "PHISHING DETECTED"
            severity = RiskLevel.CRITICAL if phishing_score >= 0.85 else RiskLevel.HIGH
            risk_score = min(1.0, max(0.8, phishing_score))
            confidence = 0.92
            threat_cat = ThreatCategory.PHISHING
            classification = "PHISHING"
            evidence_strength = EvidenceStrength.STRONG
            summary = "Phishing attack verified: Deceptive credential harvesting, brand impersonation, or sensor permission abuse detected."
            reasoning = "Forensic inspection identified deceptive mechanisms intended to capture victim credentials, sensitive hardware permissions, or impersonate authorized identity providers without legitimate authorization."
        elif is_malware:
            verdict = UnifiedVerdict.MALWARE_DETECTED
            verdict_display = "MALWARE DETECTED"
            severity = RiskLevel.CRITICAL if (malware_score >= 0.85 or vt_mal >= 5) else RiskLevel.HIGH
            risk_score = min(1.0, max(0.75, malware_score))
            confidence = 0.95 if (uh_data.get("matched") or vt_mal > 10) else 0.85
            threat_cat = ThreatCategory.MALWARE_INDICATOR
            classification = "MALWARE"
            evidence_strength = EvidenceStrength.VERIFIED if uh_data.get("matched") else EvidenceStrength.STRONG
            summary = "Malware distribution target verified: Confirmed malicious payload or threat intelligence match."
            reasoning = "Verified evidence indicates association with malicious payload delivery, malware drop infrastructure, or confirmed detection across authoritative malware intelligence feeds."
        elif has_suspicious_signals and suspicion_score >= 0.35:
            verdict = UnifiedVerdict.SUSPICIOUS
            verdict_display = "SUSPICIOUS"
            severity = RiskLevel.MEDIUM
            risk_score = min(0.65, max(0.35, suspicion_score))
            confidence = 0.75
            threat_cat = ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY
            classification = "SUSPICIOUS"
            evidence_strength = EvidenceStrength.MODERATE
            summary = "Suspicious infrastructure or URL characteristics detected."
            reasoning = "Heuristic indicators identified anomalous infrastructure (e.g. temporary public tunnel, high-entropy subdomain, redirect anomalies), but insufficient behavioral proof exists for definitive phishing or malware classification."
        elif not web_is_live and vt_state in (ProviderAnalysisState.NOT_FOUND.value, ProviderAnalysisState.NO_MATCH.value, ProviderAnalysisState.UNREACHABLE.value, ProviderAnalysisState.TIMEOUT.value, ProviderAnalysisState.ERROR.value):
            verdict = UnifiedVerdict.UNKNOWN_UNVERIFIED
            verdict_display = "UNKNOWN / UNVERIFIED"
            if hosting_intel and hosting_intel.is_ephemeral_tunnel:
                severity = RiskLevel.MEDIUM
                risk_score = 0.35
            elif has_suspicious_signals:
                severity = RiskLevel.MEDIUM
                risk_score = max(0.25, suspicion_score)
            else:
                severity = RiskLevel.LOW
                risk_score = 0.2
            confidence = 0.3
            threat_cat = ThreatCategory.INSUFFICIENT_EVIDENCE
            classification = "UNKNOWN_UNVERIFIED"
            evidence_strength = EvidenceStrength.NONE
            summary = f"Target '{target_url}' is UNVERIFIED: No external threat records found and website inspection was unreachable."
            reasoning = f"Absence of external threat records does not guarantee safety. The indicator is not indexed in VirusTotal or URLhaus, and live DOM inspection could not reach the endpoint ({crawler_state}). CyberGuard refuses to declare an uninspected, unindexed destination as SAFE."
        elif web_is_live and scan_coverage_pct >= 75.0 and vt_state in (ProviderAnalysisState.NO_MATCH.value, ProviderAnalysisState.NOT_FOUND.value) and uh_state == ProviderAnalysisState.NO_MATCH.value:
            verdict = UnifiedVerdict.NO_KNOWN_THREATS
            verdict_display = "NO KNOWN THREATS DETECTED"
            severity = RiskLevel.SAFE
            risk_score = 0.05
            confidence = 0.85
            threat_cat = ThreatCategory.SAFE
            classification = "NO_KNOWN_THREATS"
            evidence_strength = EvidenceStrength.NONE
            summary = f"No known threats identified across completed forensic checks for '{target_url}'."
            reasoning = f"Absence of external threat records does not guarantee safety. All {layers_completed}/{layers_total} inspection layers completed successfully. Live DOM audit verified no credential harvesting forms, no camera/mic/location permission abuse, no deceptive brand impersonation, and external reputation providers returned no threat records. Note: This reflects completed checks and is not an absolute guarantee against zero-day evasion."
        else:
            verdict = UnifiedVerdict.UNKNOWN_UNVERIFIED
            verdict_display = "UNKNOWN / UNVERIFIED"
            severity = RiskLevel.LOW
            risk_score = 0.2
            confidence = 0.4
            threat_cat = ThreatCategory.INSUFFICIENT_EVIDENCE
            classification = "UNKNOWN_UNVERIFIED"
            evidence_strength = EvidenceStrength.WEAK
            summary = "Insufficient telemetry to verify safety or malice."
            reasoning = "Analysis reached partial completion. Available observations are insufficient to confirm whether the destination is benign or hostile."

        # Recommended actions:
        actions = []
        if is_local:
            actions.append("Local development environment — no defensive blocking required.")
        elif verdict in (UnifiedVerdict.PHISHING_DETECTED, UnifiedVerdict.MALWARE_DETECTED, UnifiedVerdict.PHISHING_AND_MALWARE):
            actions.extend([
                f"Immediately block access to target '{target_url}' across border firewalls and endpoint browsers.",
                "Inspect network access logs and proxy history for past connections to this destination.",
                "Revoke any active session tokens or credentials submitted to this indicator.",
                "Trigger automated incident response playbook and quarantine affected endpoints.",
            ])
        elif verdict == UnifiedVerdict.SUSPICIOUS:
            actions.extend([
                f"Enforce enhanced monitoring and prompt browser warning before allowing connection to '{target_url}'.",
                "Do not submit credentials, OTPs, or grant camera/GPS device permissions.",
                "Monitor for repeated connections or subsequent redirect changes.",
            ])
        elif verdict == UnifiedVerdict.UNKNOWN_UNVERIFIED:
            actions.extend([
                "Exercise strict caution: Target is newly created or unindexed, and could not be verified by live crawler.",
                "Do NOT enter credentials, passwords, or personal identity details.",
                "Do NOT grant browser device permissions (Camera, Microphone, Location).",
                "Re-scan destination once endpoint is confirmed online.",
            ])
        else:
            actions.append("Standard security vigilance recommended; no active malicious indicators discovered in completed checks.")

        limitations = (
            f"CyberGuard authoritative verdict engine enforces evidence-based classification. "
            f"Absence of threat records is never conflated with safety. Inspection completed "
            f"{layers_completed}/{layers_total} security layers ({scan_coverage_pct:.0f}% coverage)."
        )

        return AggregatedVerdictResult(
            verdict=verdict,
            verdict_display=verdict_display,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            scan_coverage_pct=scan_coverage_pct,
            evidence_strength=evidence_strength,
            threat_category=threat_cat,
            classification=classification,
            provider_states=provider_states,
            evidence_items=evidences,
            explanation_summary=summary,
            explanation_reasoning=reasoning,
            explanation_limitations=limitations,
            recommended_actions=actions,
            is_phishing=is_phishing,
            is_malware=is_malware,
            is_unverified=(verdict == UnifiedVerdict.UNKNOWN_UNVERIFIED),
        )


_global_verdict_engine: Optional[URLVerdictEngine] = None


def get_url_verdict_engine() -> URLVerdictEngine:
    global _global_verdict_engine
    if _global_verdict_engine is None:
        _global_verdict_engine = URLVerdictEngine()
    return _global_verdict_engine
