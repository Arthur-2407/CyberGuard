"""
correlation.py — Cross-Provider Threat Intelligence Correlation Engine for CyberGuard.

Correlates normalized results from VirusTotal and URLhaus to produce a single,
provenance-preserving combined assessment.

KEY DESIGN PRINCIPLES:
- NOT a majority-vote algorithm. Each provider's evidence is preserved separately.
- Disagreements are SHOWN explicitly, never hidden or averaged away.
- Provider absence (NO_MATCH) does NOT mean the IOC is safe.
- "VERIFIED" is never used — instead: CORROBORATED / SINGLE_PROVIDER / CONFLICTING / etc.
- Every evidence item carries its source (VirusTotal / URLhaus / CyberGuard).

Correlation Status Taxonomy:
  CORROBORATED         — Both providers independently match the same IOC.
  PARTIALLY_CORROBORATED — Both match but at different scopes (e.g. exact URL vs host-level).
  SINGLE_PROVIDER      — One provider matched; other has NO_MATCH or NOT_APPLICABLE.
  CONFLICTING          — Providers return materially different classifications.
  NO_MATCH             — Neither provider returned a matching record.
  INSUFFICIENT_DATA    — Both providers UNAVAILABLE / ERROR / TIMEOUT.
  PROVIDER_UNAVAILABLE — One unavailable, other has data (available evidence preserved).
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Any, List, Optional


class CorrelationStatus(str, Enum):
    CORROBORATED = "CORROBORATED"
    PARTIALLY_CORROBORATED = "PARTIALLY_CORROBORATED"
    SINGLE_PROVIDER = "SINGLE_PROVIDER"
    CONFLICTING = "CONFLICTING"
    NO_MATCH = "NO_MATCH"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PENDING = "PENDING"
    RELATED_EVIDENCE = "RELATED_EVIDENCE"



# Provider statuses that represent "no actionable intelligence" (not errors)
_NO_MATCH_STATUSES = frozenset({
    "NO_MATCH", "NOT_FOUND", "NOT_APPLICABLE",
})

# Provider statuses that represent unavailability / errors
_UNAVAILABLE_STATUSES = frozenset({
    "UNAVAILABLE", "TIMEOUT", "ERROR", "NOT_CONFIGURED",
    "AUTHENTICATION_FAILED", "FORBIDDEN", "RATE_LIMITED",
    "INITIALIZING",
})

# Provider statuses that represent successful data
_COMPLETED_STATUSES = frozenset({"COMPLETED"})


def _is_completed(result: Dict[str, Any]) -> bool:
    if result.get("status") not in _COMPLETED_STATUSES:
        return False
    if "matched" in result and result["matched"] is not None:
        return bool(result["matched"])
    mal = result.get("malicious_count", 0) or result.get("summary", {}).get("malicious", 0)
    susp = result.get("suspicious_count", 0) or result.get("summary", {}).get("suspicious", 0)
    return bool(mal > 0 or susp > 0)


def _is_no_match(result: Dict[str, Any]) -> bool:
    status = result.get("status")
    if status in _NO_MATCH_STATUSES:
        return True
    if status in _COMPLETED_STATUSES:
        if "matched" in result and result["matched"] is not None:
            return not bool(result["matched"])
        mal = result.get("malicious_count", 0) or result.get("summary", {}).get("malicious", 0)
        susp = result.get("suspicious_count", 0) or result.get("summary", {}).get("suspicious", 0)
        return bool(mal == 0 and susp == 0)
    return False


def _is_unavailable(result: Dict[str, Any]) -> bool:
    return result.get("status") in _UNAVAILABLE_STATUSES


class ThreatIntelCorrelationEngine:
    """
    Produces a single, traceable correlation result from two normalized provider results.
    Does NOT make risk decisions — those belong to CyberGuard's existing risk engine.
    """

    def correlate(
        self,
        vt_result: Dict[str, Any],
        urlhaus_result: Dict[str, Any],
        ioc_info: Dict[str, Any],
        associated_iocs: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """
        Correlate VirusTotal and URLhaus results for a single IOC,
        with optional scope-aware handling of associated threat indicators.

        Returns a CorrelationResult dict containing:
          status, agreement, conflicts, corroborating_evidence,
          provider_gaps, freshness, summary, provider_statuses,
          related_intelligence
        """
        vt_matched = _is_completed(vt_result)
        uh_matched = _is_completed(urlhaus_result)
        vt_unavailable = _is_unavailable(vt_result)
        uh_unavailable = _is_unavailable(urlhaus_result)
        vt_no_match = _is_no_match(vt_result)
        uh_no_match = _is_no_match(urlhaus_result)

        indicator = ioc_info.get("indicator", vt_result.get("indicator", ""))
        indicator_type = ioc_info.get("category", vt_result.get("indicator_type", "unknown"))

        # Inspect associated IOCs for related threat intelligence
        all_associated = associated_iocs or ioc_info.get("associated_iocs") or []
        related_threat_iocs: List[Dict[str, Any]] = []
        for item in all_associated:
            val = item.get("value") if isinstance(item, dict) else getattr(item, "value", "")
            scp = item.get("scope") if isinstance(item, dict) else getattr(item, "scope", "")
            rel = item.get("relationship") if isinstance(item, dict) else getattr(item, "relationship", "")
            threat = item.get("threat") if isinstance(item, dict) else getattr(item, "threat", "")
            uh_id = item.get("urlhaus_record_id") if isinstance(item, dict) else getattr(item, "urlhaus_record_id", None)
            rep_url = item.get("provider_report_url") if isinstance(item, dict) else getattr(item, "provider_report_url", None)
            intel = item.get("intelligence") if isinstance(item, dict) else getattr(item, "intelligence", {})
            vt_intel = intel.get("virustotal", {}) if isinstance(intel, dict) else {}
            uh_intel = intel.get("urlhaus", {}) if isinstance(intel, dict) else {}

            is_threat = (
                scp == "URLHAUS_RECORDED_MALWARE_URL"
                or rel == "RECORDED_MALWARE_URL"
                or bool(threat)
                or (isinstance(uh_intel, dict) and uh_intel.get("matched"))
                or (isinstance(vt_intel, dict) and (vt_intel.get("malicious", 0) > 0 or vt_intel.get("positives", 0) > 0))
            )
            if is_threat and val:
                related_threat_iocs.append({
                    "indicator": val,
                    "scope": scp or "URLHAUS_RECORDED_MALWARE_URL",
                    "threat": threat or "malware_download",
                    "source": item.get("source") if isinstance(item, dict) else getattr(item, "source", "URLhaus"),
                    "urlhaus_record_id": uh_id,
                    "provider_report_url": rep_url,
                    "virustotal_malicious": vt_intel.get("malicious", 0) if isinstance(vt_intel, dict) else 0,
                    "virustotal_total": vt_intel.get("total_engines", 0) if isinstance(vt_intel, dict) else 0,
                })

        corroborating_evidence: List[Dict[str, Any]] = []
        conflicts: List[str] = []
        provider_gaps: List[str] = []


        # --- DETERMINE CORRELATION STATUS ---

        vt_st = vt_result.get("status")
        uh_st = urlhaus_result.get("status")
        if vt_st in ("PENDING", "QUEUED", "ANALYZING", "SUBMITTED") or uh_st in ("PENDING", "WAITING_FOR_VIRUSTOTAL", "WAITING"):
            status = CorrelationStatus.PENDING
            agreement = False
            summary = (
                "External threat intelligence verification is currently pending. "
                "VirusTotal is analyzing and URLhaus is awaiting VirusTotal completion. "
                "Final correlated assessment cannot be issued until external providers reach a terminal state."
            )
            provider_gaps.append(f"VirusTotal: {vt_st or 'PENDING'} (results awaiting completion).")
            provider_gaps.append(f"URLhaus: {uh_st or 'WAITING_FOR_VIRUSTOTAL'}.")

        elif vt_unavailable and uh_unavailable:
            status = CorrelationStatus.INSUFFICIENT_DATA
            agreement = False
            summary = (
                "Both VirusTotal and URLhaus were unavailable or could not be queried. "
                "No external intelligence is available for this IOC. "
                "CyberGuard local analysis should be considered separately."
            )
            provider_gaps.append(f"VirusTotal: {vt_result.get('status', 'UNAVAILABLE')}")
            provider_gaps.append(f"URLhaus: {urlhaus_result.get('status', 'UNAVAILABLE')}")

        elif vt_unavailable and (uh_matched or uh_no_match):
            status = CorrelationStatus.PROVIDER_UNAVAILABLE
            agreement = False
            provider_gaps.append(f"VirusTotal: {vt_result.get('status', 'UNAVAILABLE')} — could not be queried.")
            if uh_matched:
                corroborating_evidence.extend(urlhaus_result.get("evidence", []))
                summary = (
                    f"VirusTotal was unavailable ({vt_result.get('status', 'UNAVAILABLE')}). "
                    f"URLhaus returned matching intelligence for this IOC (scope: {urlhaus_result.get('match_scope', 'unknown')}). "
                    "Assessment is based solely on URLhaus evidence."
                )
            else:
                summary = (
                    f"VirusTotal was unavailable ({vt_result.get('status', 'UNAVAILABLE')}). "
                    "URLhaus returned no matching record. No external intelligence available."
                )

        elif uh_unavailable and (vt_matched or vt_no_match):
            status = CorrelationStatus.PROVIDER_UNAVAILABLE
            agreement = False
            provider_gaps.append(f"URLhaus: {urlhaus_result.get('status', 'UNAVAILABLE')} — could not be queried.")
            if vt_matched:
                vt_evidence = self._extract_vt_evidence(vt_result)
                corroborating_evidence.extend(vt_evidence)
                summary = (
                    f"URLhaus was unavailable ({urlhaus_result.get('status', 'UNAVAILABLE')}). "
                    "VirusTotal returned matching intelligence. Assessment is based solely on VirusTotal evidence."
                )
            else:
                summary = (
                    f"URLhaus was unavailable ({urlhaus_result.get('status', 'UNAVAILABLE')}). "
                    "VirusTotal returned no matching record. No external intelligence available."
                )

        elif vt_matched and uh_matched:
            # Both providers returned matching intelligence — determine scope
            vt_scope = "exact"
            uh_scope = urlhaus_result.get("match_scope", "UNKNOWN")

            if uh_scope in ("HOST_LEVEL",):
                # VT found exact match; URLhaus found host-level evidence only
                status = CorrelationStatus.PARTIALLY_CORROBORATED
                agreement = True
                summary = (
                    f"VirusTotal provided exact-match intelligence for this IOC. "
                    f"URLhaus provided supporting HOST-LEVEL evidence (not an exact URL match). "
                    f"Providers partially corroborate each other — different scopes of evidence."
                )
            else:
                # Both have direct/exact match evidence
                status = CorrelationStatus.CORROBORATED
                agreement = True
                summary = (
                    f"Both VirusTotal and URLhaus independently returned matching intelligence for this IOC. "
                    f"Providers corroborate each other: VirusTotal ({vt_result.get('summary', {}).get('malicious', 0)} malicious engine(s)) "
                    f"and URLhaus (classification: {urlhaus_result.get('classification', 'malware_url')}). "
                    f"This is corroborated external intelligence."
                )

            # Collect evidence from both providers
            vt_evidence = self._extract_vt_evidence(vt_result)
            corroborating_evidence.extend(vt_evidence)
            corroborating_evidence.extend(urlhaus_result.get("evidence", []))

        elif vt_matched and (uh_no_match or uh_unavailable):
            # VT found something; URLhaus did not match or is not applicable
            status = CorrelationStatus.SINGLE_PROVIDER
            agreement = False
            vt_evidence = self._extract_vt_evidence(vt_result)
            corroborating_evidence.extend(vt_evidence)

            uh_reason = urlhaus_result.get("status", "NO_MATCH")
            if uh_reason == "NOT_APPLICABLE":
                provider_gaps.append(
                    f"URLhaus: NOT_APPLICABLE for this IOC type "
                    f"({urlhaus_result.get('limitations', [''])[0] if urlhaus_result.get('limitations') else 'unsupported IOC type'})."
                )
                summary = (
                    "Only VirusTotal provided matching intelligence. "
                    "URLhaus lookup was not applicable for this IOC type. "
                    "Single-provider intelligence only."
                )
            else:
                provider_gaps.append(
                    f"URLhaus: {uh_reason} — no matching malware-distribution record found. "
                    "This does not confirm the IOC is safe."
                )
                summary = (
                    "Only VirusTotal returned matching intelligence. "
                    "URLhaus returned no matching record for this IOC. "
                    "Note: URLhaus focuses specifically on malware-distribution URLs — "
                    "absence of a URLhaus record does not contradict VirusTotal findings."
                )

        elif uh_matched and (vt_no_match or vt_unavailable):
            # URLhaus found something; VT did not match
            status = CorrelationStatus.SINGLE_PROVIDER
            agreement = False
            corroborating_evidence.extend(urlhaus_result.get("evidence", []))

            if vt_no_match:
                # This is a genuine disagreement: VT clean, URLhaus malware
                # URLhaus focuses on malware-distribution; VT is broader reputation
                # This MAY be a conflict or just scope difference — flag it
                vt_malicious = vt_result.get("summary", {}).get("malicious", 0)
                if vt_malicious == 0:
                    # VT returned data but no malicious detections; URLhaus disagrees
                    status = CorrelationStatus.CONFLICTING
                    conflicts.append(
                        f"VirusTotal: {vt_malicious} malicious engine detection(s) — not classified as malicious. "
                        f"URLhaus: classified as '{urlhaus_result.get('classification', 'malware')}' "
                        f"(scope: {urlhaus_result.get('match_scope', 'unknown')}). "
                        "Providers differ in corpus, methodology, and scope. "
                        "URLhaus focuses on malware-distribution URLs specifically; "
                        "VirusTotal uses broader multi-engine reputation scoring."
                    )
                    summary = (
                        "VirusTotal returned no malicious detections while URLhaus reports matching malware intelligence. "
                        "This is a provider disagreement — the providers have different methodologies and corpuses. "
                        "URLhaus focuses specifically on malware-distribution URLs. "
                        "Both findings are preserved for review."
                    )
                else:
                    # VT had some malicious; URLhaus corroborates
                    status = CorrelationStatus.CORROBORATED
                    agreement = True
                    vt_evidence = self._extract_vt_evidence(vt_result)
                    corroborating_evidence.extend(vt_evidence)
                    summary = (
                        "Both providers returned matching intelligence. "
                        f"VirusTotal: {vt_malicious} malicious engine detection(s). "
                        f"URLhaus: {urlhaus_result.get('classification', 'malware')} match."
                    )
            else:
                provider_gaps.append(f"VirusTotal: {vt_result.get('status', 'UNAVAILABLE')}")
                summary = (
                    "URLhaus returned matching malware intelligence. "
                    f"VirusTotal was unavailable ({vt_result.get('status', 'UNAVAILABLE')}). "
                    "Assessment is based solely on URLhaus evidence."
                )

        elif vt_no_match and uh_no_match:
            if related_threat_iocs:
                status = CorrelationStatus.RELATED_EVIDENCE
                agreement = True
                rel_primary = related_threat_iocs[0]
                summary = (
                    f"Primary IOC '{indicator}': Neither VirusTotal nor URLhaus returned a direct matching record. "
                    f"However, related threat intelligence was discovered: landing resource references "
                    f"{rel_primary.get('source', 'URLhaus')} tracked indicator '{rel_primary['indicator']}' "
                    f"(threat: {rel_primary.get('threat', 'malware_download')}"
                    + (f", VirusTotal: {rel_primary['virustotal_malicious']} malicious engines" if rel_primary.get('virustotal_malicious', 0) > 0 else "")
                    + "). Evidence is scoped to the related indicator."
                )
                provider_gaps.append("Primary IOC: NO_MATCH from VirusTotal and URLhaus.")
                provider_gaps.append(
                    f"Related Intelligence: Confirmed threat record for associated IOC '{rel_primary['indicator']}'."
                )
            else:
                status = CorrelationStatus.NO_MATCH
                agreement = True
                summary = (
                    "Neither VirusTotal nor URLhaus returned a matching record for this IOC. "
                    "Absence of external intelligence does NOT establish that the IOC is safe. "
                    "CyberGuard local analysis should be considered separately."
                )
                provider_gaps.append("VirusTotal: NO_MATCH — not in current dataset.")
                provider_gaps.append(
                    "URLhaus: NO_MATCH — not in malware-distribution URL database. "
                    "Note: URLhaus focuses specifically on malware-distribution URLs."
                )

        else:
            # Edge case: mixed states not covered above
            status = CorrelationStatus.INSUFFICIENT_DATA
            agreement = False
            summary = (
                f"Insufficient data to perform meaningful correlation. "
                f"VirusTotal status: {vt_result.get('status', 'UNKNOWN')}. "
                f"URLhaus status: {urlhaus_result.get('status', 'UNKNOWN')}."
            )

        # --- BUILD FRESHNESS ---
        freshness: Dict[str, Any] = {}
        vt_timeline = vt_result.get("timeline", {})
        if vt_timeline.get("last_analysis"):
            freshness["virustotal_last_analysis"] = vt_timeline["last_analysis"]
        if urlhaus_result.get("date_added"):
            freshness["urlhaus_date_added"] = urlhaus_result["date_added"]
        if urlhaus_result.get("last_seen_online"):
            freshness["urlhaus_last_seen_online"] = urlhaus_result["last_seen_online"]

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": status.value,
            "primary_status": (CorrelationStatus.NO_MATCH.value if (vt_no_match and uh_no_match) else status.value),
            "related_intelligence": {
                "has_related_threat": bool(related_threat_iocs),
                "related_threats": related_threat_iocs,
                "correlation_scope": "RELATED_IOC" if related_threat_iocs else "PRIMARY_IOC",
            },
            "agreement": agreement,
            "conflicts": conflicts,
            "corroborating_evidence": corroborating_evidence,
            "provider_gaps": provider_gaps,
            "freshness": freshness,
            "summary": summary,
            "provider_statuses": {
                "virustotal": vt_result.get("status", "UNKNOWN"),
                "urlhaus": urlhaus_result.get("status", "UNKNOWN"),
            },
        }


    def _extract_vt_evidence(self, vt_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract VT intelligence as normalized evidence items with source provenance."""
        evidence = []
        summary = vt_result.get("summary", {})
        malicious = summary.get("malicious", 0)
        suspicious = summary.get("suspicious", 0)
        total = summary.get("total_engines", 0)

        if malicious > 0 or suspicious > 0:
            evidence.append({
                "source": "VirusTotal",
                "evidence_type": "multi_engine_detection",
                "indicator": vt_result.get("indicator", ""),
                "scope": f"EXACT_{(vt_result.get('indicator_type') or 'indicator').upper()}",
                "description": (
                    f"VirusTotal: {malicious} malicious and {suspicious} suspicious detection(s) "
                    f"out of {total} security engine(s)."
                ),
                "actual_value": f"{malicious}/{total} malicious",
                "timestamp": vt_result.get("timeline", {}).get("last_analysis"),
                "relevance": "DIRECT_MATCH",
            })

        categories = vt_result.get("categories", [])
        if categories:
            cat_str = ", ".join(
                f"{c.get('provider', '?')}: {c.get('category', '?')}"
                for c in categories[:5]
            )
            evidence.append({
                "source": "VirusTotal",
                "evidence_type": "category_classification",
                "indicator": vt_result.get("indicator", ""),
                "scope": f"EXACT_{(vt_result.get('indicator_type') or 'indicator').upper()}",
                "description": f"VirusTotal category classifications: {cat_str}",
                "actual_value": cat_str,
                "timestamp": vt_result.get("timeline", {}).get("last_analysis"),
                "relevance": "SUPPORTING",
            })

        return evidence
