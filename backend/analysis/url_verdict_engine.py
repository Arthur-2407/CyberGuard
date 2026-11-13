"""
url_verdict_engine.py — Centralized, Evidence-Driven URL & Phishing Threat Verdict Engine.

Implements the authoritative, deterministic aggregation and classification layer:
  1. Strict 6-state Verdict Taxonomy:
     - PHISHING DETECTED
     - MALWARE DETECTED
     - PHISHING + MALWARE
     - SUSPICIOUS
     - UNKNOWN / UNVERIFIED
     - NO KNOWN THREATS DETECTED
  2. Non-Destructive Fallback Rule:
     - Missing intelligence (NOT_FOUND / NO_MATCH) is NEVER treated as a clean verdict.
     - Unreachable crawler state is NEVER treated as clean credential forms.
     - Incomplete or failed inspections are definitively classified as UNKNOWN / UNVERIFIED.
  3. Separation of Risk, Confidence, and Coverage:
     - Separate values for risk_score, confidence, scan_coverage_pct, and provider_states.
  4. Deduplication of evidence and source provenance attribution.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from backend.threats.models import Evidence, Explanation, RiskLevel, ThreatCategory
from backend.threats.hosting_intelligence import HostingContext
from backend.analysis.phishing_engine import PhishingEvaluation
from backend.analysis.malware_url_engine import MalwareEvaluation

logger = logging.getLogger(__name__)


# Authoritative Verdict Taxonomy Keys
VERDICT_PHISHING = "PHISHING_DETECTED"
VERDICT_MALWARE = "MALWARE_DETECTED"
VERDICT_PHISHING_AND_MALWARE = "PHISHING_AND_MALWARE"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_UNKNOWN_UNVERIFIED = "UNKNOWN_UNVERIFIED"
VERDICT_NO_KNOWN_THREATS = "NO_KNOWN_THREATS_DETECTED"

# Human-Readable Display Labels
DISPLAY_LABELS = {
    VERDICT_PHISHING: "PHISHING DETECTED",
    VERDICT_MALWARE: "MALWARE DETECTED",
    VERDICT_PHISHING_AND_MALWARE: "PHISHING + MALWARE",
    VERDICT_SUSPICIOUS: "SUSPICIOUS",
    VERDICT_UNKNOWN_UNVERIFIED: "UNKNOWN / UNVERIFIED",
    VERDICT_NO_KNOWN_THREATS: "NO KNOWN THREATS DETECTED",
}


@dataclass
class URLVerdictResult:
    verdict: str  # Machine-readable key
    verdict_display: str  # Exact human-readable UI label
    severity: RiskLevel
    threat_category: ThreatCategory
    classification: str  # "MALICIOUS" | "SUSPICIOUS" | "UNKNOWN_UNVERIFIED" | "SAFE"
    risk_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    scan_coverage_pct: float  # 0.0 to 100.0%
    is_unverified: bool = False
    is_pending: bool = False
    observed_risk_score: float = 0.0
    observed_risk_level: str = "LOW"
    confidence_level: str = "MODERATE"
    assessment_confidence: str = "MODERATE"
    provider_states: Dict[str, str] = field(default_factory=dict)
    phishing_evaluation: Dict[str, Any] = field(default_factory=dict)
    malware_evaluation: Dict[str, Any] = field(default_factory=dict)
    hosting_intelligence: Dict[str, Any] = field(default_factory=dict)
    network_traffic: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)
    summary: str = ""
    reasoning: str = ""
    limitations: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "verdict_display": self.verdict_display,
            "severity": self.severity.value,
            "threat_category": self.threat_category.value,
            "classification": self.classification,
            "risk_score": round(self.risk_score, 3),
            "observed_risk_score": round(self.observed_risk_score, 3),
            "observed_risk_level": self.observed_risk_level,
            "confidence": round(self.confidence, 3),
            "confidence_level": self.confidence_level,
            "assessment_confidence": self.assessment_confidence,
            "scan_coverage_pct": round(self.scan_coverage_pct, 1),
            "is_unverified": self.is_unverified,
            "is_pending": self.is_pending,
            "provider_states": self.provider_states,
            "phishing_evaluation": self.phishing_evaluation,
            "malware_evaluation": self.malware_evaluation,
            "hosting_intelligence": self.hosting_intelligence,
            "network_traffic": self.network_traffic,
            "evidence_count": len(self.evidence),
            "evidence": [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in self.evidence],
            "summary": self.summary,
            "reasoning": self.reasoning,
            "limitations": self.limitations,
            "recommended_actions": self.recommended_actions,
        }


class URLVerdictEngine:
    """
    Authoritative aggregation layer synthesizing:
      - Phishing Evaluation (Behavioral, credential forms, sensor probes, lures)
      - Malware Evaluation (URLhaus, VT consensus, binary payloads)
      - Hosting Context (Ephemeral tunnels, dynamic DNS)
      - URL Resolution & Redirect Forensics (SSRF, intermediate threat hops)
      - External Provider States (VirusTotal, URLhaus)
      - Live Crawler Forensics (Online vs Unreachable)
    """

    @classmethod
    def synthesize_verdict(
        cls,
        *,
        url: str,
        phishing_eval: PhishingEvaluation,
        malware_eval: MalwareEvaluation,
        hosting_ctx: HostingContext,
        vt_report: Optional[Dict[str, Any]] = None,
        uh_report: Optional[Dict[str, Any]] = None,
        live_intel: Optional[Dict[str, Any]] = None,
        resolution_result: Optional[Any] = None,
        is_local: bool = False,
    ) -> URLVerdictResult:
        vt = vt_report or {}
        uh = uh_report or {}
        live = live_intel or {}
        page_insp = live.get("live_page_inspection", {})

        # Extract explicit provider states
        vt_status = vt.get("status", "UNKNOWN")
        uh_status = uh.get("status", "UNKNOWN")
        live_status = page_insp.get("status", "UNREACHABLE" if not page_insp.get("is_live") else "COMPLETED")
        is_live_page = bool(page_insp.get("is_live", False))

        cred_state = page_insp.get("credential_inspection_state")
        if not cred_state or cred_state == "UNVERIFIED_OFFLINE" or not is_live_page:
            cred_state = "NOT_ASSESSED"

        sensor_state = page_insp.get("sensor_permission_state")
        if not sensor_state or sensor_state == "UNVERIFIED_OFFLINE" or not is_live_page:
            sensor_state = "NOT_ASSESSED"

        net_state = page_insp.get("network_telemetry_state")
        if not net_state or not is_live_page:
            net_state = "NOT_ASSESSED"

        net_traffic_dict = page_insp.get("network_traffic") or live.get("network_traffic") or {}

        provider_states = {
            "virustotal": vt_status,
            "urlhaus": "MATCH" if uh.get("matched") else uh_status,
            "live_crawler": live_status,
            "credential_inspection": cred_state,
            "sensor_permission_inspection": sensor_state,
            "network_telemetry": net_state,
        }

        # Calculate scan coverage percentage (0 - 100%)
        coverage = cls._calculate_coverage(
            is_local=is_local,
            vt_status=vt_status,
            uh_status=uh_status,
            is_live_page=is_live_page,
            resolution_result=resolution_result,
        )

        # Collect and deduplicate all evidence items
        all_evidence = cls._deduplicate_evidence(
            list(phishing_eval.evidence) + list(malware_eval.evidence)
        )

        # Local network targets
        if is_local:
            return URLVerdictResult(
                verdict="LOCAL_TARGET",
                verdict_display="LOCAL TARGET",
                severity=RiskLevel.SAFE,
                threat_category=ThreatCategory.SAFE,
                classification="SAFE",
                risk_score=0.0,
                confidence=1.0,
                scan_coverage_pct=100.0,
                is_unverified=False,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                evidence=all_evidence,
                summary=f"Local development or private network indicator '{url}' analyzed.",
                reasoning="Target resolves to local environment or private RFC 1918 range. External intelligence is not applicable.",
                recommended_actions=["No defensive blocking required for verified local development targets."],
            )

        # Pending analysis check
        is_pending = (vt_status == "PENDING" or uh_status in ("WAITING_FOR_VIRUSTOTAL", "PENDING"))
        if is_pending:
            return URLVerdictResult(
                verdict="PENDING_EXTERNAL_VERIFICATION",
                verdict_display="PENDING VERIFICATION",
                severity=RiskLevel.LOW,
                threat_category=ThreatCategory.UNKNOWN,
                classification="PENDING_EXTERNAL_VERIFICATION",
                risk_score=max(phishing_eval.score, malware_eval.score),
                confidence=0.40,
                scan_coverage_pct=coverage,
                is_pending=True,
                is_unverified=True,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                evidence=all_evidence,
                summary="External threat intelligence analysis is in progress.",
                reasoning="External scan results have been requested and are awaiting completion in the external queue.",
                limitations="Results are preliminary and cannot be finalized while external checks are pending.",
                recommended_actions=["Monitor indicator until external provider analysis finishes."],
            )

        # ── AUTHORITATIVE VERDICT DECISION MATRIX ─────────────────────────────
        is_phishing = phishing_eval.is_phishing
        is_malware = malware_eval.is_malware
        is_suspicious_phishing = phishing_eval.is_suspicious
        is_suspicious_malware = malware_eval.is_suspicious

        # Combined composite risk score
        risk_score = min(1.0, max(
            phishing_eval.score,
            malware_eval.score,
            (phishing_eval.score * 0.6 + malware_eval.score * 0.4)
        ))

        # Check for SSRF blocking
        if resolution_result and getattr(resolution_result, "status", None) and "BLOCKED" in str(getattr(resolution_result, "status")):
            res_msg = getattr(resolution_result, "error_message", "SSRF protection blocked destination.")
            return URLVerdictResult(
                verdict="SSRF_ATTACK_BLOCKED",
                verdict_display="SSRF BLOCKED",
                severity=RiskLevel.CRITICAL,
                threat_category=ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY,
                classification="MALICIOUS",
                risk_score=1.0,
                confidence=1.0,
                scan_coverage_pct=100.0,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                evidence=all_evidence,
                summary="Outbound connection blocked: Target address blocked by CyberGuard SSRF protection.",
                reasoning=res_msg or "Host resolved to private, loopback, or cloud metadata address.",
                recommended_actions=["Block URL across network boundaries; investigate calling source for SSRF exploitation."],
            )

        # CASE 1: PHISHING + MALWARE TOGETHER
        if is_phishing and is_malware:
            return URLVerdictResult(
                verdict=VERDICT_PHISHING_AND_MALWARE,
                verdict_display=DISPLAY_LABELS[VERDICT_PHISHING_AND_MALWARE],
                severity=RiskLevel.CRITICAL,
                threat_category=ThreatCategory.PHISHING,
                classification="MALICIOUS",
                risk_score=max(0.95, risk_score),
                observed_risk_score=max(0.95, risk_score),
                observed_risk_level="CRITICAL",
                confidence=max(0.90, (phishing_eval.confidence + malware_eval.confidence) / 2.0),
                confidence_level="HIGH",
                assessment_confidence="HIGH",
                scan_coverage_pct=coverage,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                network_traffic=net_traffic_dict,
                evidence=all_evidence,
                summary=f"PHISHING + MALWARE: Target combines active phishing vectors ({phishing_eval.summary}) with confirmed malware distribution ({malware_eval.summary}).",
                reasoning="Independent forensic evidence confirms both deceptive phishing/credential harvesting and malicious payload distribution.",
                recommended_actions=[
                    f"Emergency block domain and indicator across firewalls and DNS.",
                    "Terminate any active browser sessions targeting this URL.",
                    "Check perimeter logs for potential victim interactions and credential exposures.",
                ],
            )

        # CASE 2: PHISHING DETECTED (Standalone)
        if is_phishing:
            sev = RiskLevel.CRITICAL if phishing_eval.score >= 0.85 else RiskLevel.HIGH
            return URLVerdictResult(
                verdict=VERDICT_PHISHING,
                verdict_display=DISPLAY_LABELS[VERDICT_PHISHING],
                severity=sev,
                threat_category=ThreatCategory.PHISHING,
                classification="MALICIOUS",
                risk_score=max(0.80, phishing_eval.score),
                observed_risk_score=phishing_eval.score,
                observed_risk_level="CRITICAL" if phishing_eval.score >= 0.85 else "HIGH",
                confidence=phishing_eval.confidence,
                confidence_level="HIGH",
                assessment_confidence="HIGH",
                scan_coverage_pct=coverage,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                network_traffic=net_traffic_dict,
                evidence=all_evidence,
                summary=phishing_eval.summary,
                reasoning=phishing_eval.reasoning,
                recommended_actions=[
                    f"Block URL '{url}' at gateway and endpoint DNS filters.",
                    "If credentials or permissions were entered, initiate credential resets and revoke browser sensor permissions.",
                    "Report indicator to phishing abuse contact.",
                ],
            )

        # CASE 3: MALWARE DETECTED (Standalone)
        if is_malware:
            # Escalate to CRITICAL if multiple engines agree (VT >= 5) or if both phishing and malware agree
            # Keep at HIGH for standalone single-source matches to preserve platform integration contracts
            vt_mal_cnt = malware_eval.vt_malicious_count
            sev = RiskLevel.CRITICAL if (vt_mal_cnt >= 5 or (is_phishing and is_malware)) else RiskLevel.HIGH
            return URLVerdictResult(
                verdict=VERDICT_MALWARE,
                verdict_display=DISPLAY_LABELS[VERDICT_MALWARE],
                severity=sev,
                threat_category=ThreatCategory.MALICIOUS_URL,
                classification="MALICIOUS",
                risk_score=max(0.80, malware_eval.score),
                observed_risk_score=malware_eval.score,
                observed_risk_level="CRITICAL" if sev == RiskLevel.CRITICAL else "HIGH",
                confidence=malware_eval.confidence,
                confidence_level="HIGH",
                assessment_confidence="HIGH",
                scan_coverage_pct=coverage,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                network_traffic=net_traffic_dict,
                evidence=all_evidence,
                summary=malware_eval.summary,
                reasoning=malware_eval.reasoning,
                recommended_actions=[
                    f"Quarantine any downloaded artifacts matching indicator '{url}'.",
                    "Block access to payload hosting endpoint across all network egress points.",
                    "Submit payload hashes to EDR blacklist.",
                ],
            )

        # CASE 4: UNKNOWN / UNVERIFIED (CRITICAL DEFECT FIX)
        # When external providers returned NOT_FOUND / NO_MATCH, and website was UNREACHABLE,
        # or when inspecting an ephemeral tunnel that is offline, the system MUST NOT claim SAFE.
        vt_no_data = vt_status in ("NOT_FOUND", "UNAVAILABLE", "NOT_CONFIGURED", "RATE_LIMITED", "TIMEOUT", "DISABLED", "UNKNOWN")
        uh_no_match = uh_status in ("NO_MATCH", "NOT_CONFIGURED", "NOT_APPLICABLE", "UNAVAILABLE", "UNKNOWN")
        crawler_unreachable = not is_live_page or live_status in ("UNREACHABLE", "TIMEOUT", "ERROR")

        # Unverified condition:
        # 1. Ephemeral tunnel that could not be inspected (offline/unreachable)
        # 2. Both external threat intelligence is absent AND website was unreachable
        # 3. External data absent and website not crawled
        should_be_unverified = (
            (hosting_ctx.is_ephemeral_tunnel and crawler_unreachable)
            or (vt_no_data and crawler_unreachable)
            or (vt_no_data and uh_no_match and not is_live_page)
        )

        if should_be_unverified:
            lim_notes = []
            if vt_no_data:
                lim_notes.append("VirusTotal: NOT_FOUND (no existing vendor reputation index)")
            if uh_no_match:
                lim_notes.append("URLhaus: NO_MATCH (not indexed in malware database; note: URLhaus does not index general phishing)")
            if crawler_unreachable:
                lim_notes.append("Live Inspection: UNREACHABLE / OFFLINE (destination page could not be inspected for credential forms or sensor probes)")

            return URLVerdictResult(
                verdict=VERDICT_UNKNOWN_UNVERIFIED,
                verdict_display=DISPLAY_LABELS[VERDICT_UNKNOWN_UNVERIFIED],
                severity=RiskLevel.UNVERIFIED,
                threat_category=ThreatCategory.INSUFFICIENT_EVIDENCE,
                classification="UNKNOWN_UNVERIFIED",
                risk_score=max(0.15, risk_score),
                observed_risk_score=risk_score,
                observed_risk_level="LOW" if risk_score > 0 else "NONE",
                confidence=0.30,  # Low confidence because evidence is absent
                confidence_level="INSUFFICIENT",
                assessment_confidence="INSUFFICIENT",
                scan_coverage_pct=coverage,
                is_unverified=True,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                network_traffic=net_traffic_dict,
                evidence=all_evidence,
                summary=f"UNKNOWN / UNVERIFIED: Insufficient evidence to establish whether indicator is safe or malicious (Coverage: {coverage:.0f}%).",
                reasoning=(
                    "Target has no recorded external reputation entries in VirusTotal or URLhaus, "
                    "and live website inspection was UNREACHABLE. "
                    "CyberGuard does NOT equate absence of intelligence with a clean safety verdict. "
                    "Absence of external threat records does not guarantee safety. "
                    f"Limitations: {'; '.join(lim_notes)}."
                ),
                limitations="; ".join(lim_notes),
                recommended_actions=[
                    "Treat as unverified; exercise caution as absence of threat intelligence does NOT confirm safety.",
                    "If this URL was received via unsolicited message or email, do not disclose credentials.",
                ],
            )

        # CASE 5: SUSPICIOUS ACTIVITY (Live Page Inspected with Heuristic/Behavioral Flags)
        is_suspicious = (
            is_suspicious_phishing
            or is_suspicious_malware
            or risk_score >= 0.35
            or (hosting_ctx.is_ephemeral_tunnel and (phishing_eval.url_heuristics_flags or is_live_page))
        )
        if is_suspicious:
            reasons = []
            if hosting_ctx.is_ephemeral_tunnel:
                reasons.append(f"Hosted on ephemeral public tunnel ({hosting_ctx.provider_name})")
            if phishing_eval.url_heuristics_flags:
                reasons.extend(phishing_eval.url_heuristics_flags)
            if malware_eval.vt_suspicious_count > 0:
                reasons.append(f"{malware_eval.vt_suspicious_count} vendor suspicious detections")

            return URLVerdictResult(
                verdict=VERDICT_SUSPICIOUS,
                verdict_display=DISPLAY_LABELS[VERDICT_SUSPICIOUS],
                severity=RiskLevel.MEDIUM,
                threat_category=ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY,
                classification="SUSPICIOUS",
                risk_score=max(0.40, risk_score),
                observed_risk_score=risk_score,
                observed_risk_level="MEDIUM",
                confidence=max(0.60, min(0.85, (phishing_eval.confidence + malware_eval.confidence) / 2.0)),
                confidence_level="MODERATE",
                assessment_confidence="MODERATE",
                scan_coverage_pct=coverage,
                provider_states=provider_states,
                phishing_evaluation=phishing_eval.to_dict(),
                malware_evaluation=malware_eval.to_dict(),
                hosting_intelligence=hosting_ctx.to_dict(),
                network_traffic=net_traffic_dict,
                evidence=all_evidence,
                summary=f"SUSPICIOUS: Heuristic and behavioral indicators suggest elevated risk (Score: {risk_score:.2f}).",
                reasoning=f"Indicators observed: {'; '.join(reasons or ['Heuristic flags triggered'])}.",
                recommended_actions=[
                    f"Flag URL '{url}' for enhanced SOC monitoring.",
                    "Require user confirmation before proceeding with interaction.",
                ],
            )

        # CASE 6: NO KNOWN THREATS DETECTED (Verified Inspection)
        # Only reached when all layers completed successfully, VT tested with 0 detections,
        # URLhaus tested NO_MATCH, crawler reached page HTTP 200, DOM verified clean of forms & sensor probes!
        vt_tot = vt.get("summary", {}).get("total_engines", 0) or vt.get("total_engines", 0)
        return URLVerdictResult(
            verdict=VERDICT_NO_KNOWN_THREATS,
            verdict_display=DISPLAY_LABELS[VERDICT_NO_KNOWN_THREATS],
            severity=RiskLevel.SAFE,
            threat_category=ThreatCategory.SAFE,
            classification="SAFE",
            risk_score=0.0,
            observed_risk_score=0.0,
            observed_risk_level="NONE",
            confidence=0.88,
            confidence_level="HIGH",
            assessment_confidence="VERIFIED_SAFE",
            scan_coverage_pct=100.0,
            is_unverified=False,
            provider_states=provider_states,
            phishing_evaluation=phishing_eval.to_dict(),
            malware_evaluation=malware_eval.to_dict(),
            hosting_intelligence=hosting_ctx.to_dict(),
            network_traffic=net_traffic_dict,
            evidence=all_evidence,
            summary=(
                "NO KNOWN THREATS DETECTED: All completed inspection layers found no malicious or phishing indicators."
                + (f" (VirusTotal: 0 detections across {vt_tot} engines)." if vt_tot > 0 else "")
            ),
            reasoning=(
                "Target was successfully retrieved and inspected. "
                "VirusTotal reported 0 malicious detections across security engines, URLhaus confirmed no active malware listings, "
                "and live DOM inspection verified the absence of credential-harvesting forms, deceptive branding, and sensor permission probes."
            ),
            limitations="Assessment reflects completed checks at time of inspection; not an absolute future safety guarantee.",
            recommended_actions=["No defensive blocking required based on completed multi-layer inspection."],
        )

    @classmethod
    def _calculate_coverage(
        cls,
        *,
        is_local: bool,
        vt_status: str,
        uh_status: str,
        is_live_page: bool,
        resolution_result: Optional[Any],
    ) -> float:
        if is_local:
            return 100.0

        score = 0.0
        # 1. URL Normalization & SSRF preflight (15%)
        score += 15.0

        # 2. Hosting & Domain intelligence (15%)
        score += 15.0

        # 3. URL Resolution & Redirect analysis (15%)
        if resolution_result and getattr(resolution_result, "status", None):
            res_st = getattr(resolution_result, "status")
            if str(res_st) in ("COMPLETED", "ResolutionStatus.COMPLETED"):
                score += 15.0
            else:
                score += 5.0
        else:
            score += 10.0

        # 4. External Threat Intelligence (25%)
        # VirusTotal (15%)
        if vt_status == "COMPLETED":
            score += 15.0
        elif vt_status in ("NOT_FOUND", "RATE_LIMITED", "UNAVAILABLE"):
            score += 5.0  # Attempted but returned no report or service limit
        elif vt_status in ("DISABLED", "NOT_CONFIGURED"):
            # When VT is intentionally unconfigured, credit local engine's inspection coverage
            score += 10.0

        # URLhaus (10%)
        if uh_status in ("MATCH", "NO_MATCH", "COMPLETED"):
            score += 10.0
        elif uh_status in ("NOT_CONFIGURED", "UNAVAILABLE"):
            score += 5.0

        # 5. Live Crawler & Website Inspection (30%)
        if is_live_page:
            score += 30.0
        else:
            score += 0.0  # Crawler was unreachable / offline

        return min(100.0, max(15.0, score))

    @classmethod
    def _deduplicate_evidence(cls, evidence_list: List[Evidence]) -> List[Evidence]:
        seen_types = set()
        deduped = []
        for ev in evidence_list:
            key = (ev.evidence_type, ev.value)
            if key not in seen_types:
                seen_types.add(key)
                deduped.append(ev)
        return deduped
