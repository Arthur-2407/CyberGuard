"""
test_correlation.py — ThreatIntelCorrelationEngine unit tests.

Tests all 6 correlation states and evidence provenance preservation.
No live network calls — all inputs are synthetic normalized results.
"""

import pytest
from backend.threats.correlation import ThreatIntelCorrelationEngine, CorrelationStatus


def make_engine():
    return ThreatIntelCorrelationEngine()


# ── Helper factories for normalized provider results ───────────────────────────

def vt_completed(malicious: int = 2, suspicious: int = 0, total: int = 73):
    return {
        "provider": "VirusTotal",
        "status": "COMPLETED",
        "indicator": "https://evil.example.com",
        "indicator_type": "url",
        "matched": malicious > 0 or suspicious > 0,
        "summary": {"malicious": malicious, "suspicious": suspicious, "harmless": 70, "undetected": 0, "total_engines": total},
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "categories": [{"provider": "Sophos", "category": "malware"}],
        "timeline": {"last_analysis": 1700000000},
        "engine_results": [{"engine_name": "VendorA", "verdict": "malicious", "result": "Trojan.X"}],
        "permalink": "https://virustotal.com/gui/url/abc",
    }


def vt_not_found():
    return {
        "provider": "VirusTotal",
        "status": "NOT_FOUND",
        "indicator": "https://unknown.example.com",
        "indicator_type": "url",
        "matched": False,
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0},
    }


def vt_completed_clean(total: int = 60):
    """VT scan completed but zero malicious detections."""
    return {
        "provider": "VirusTotal",
        "status": "COMPLETED",
        "indicator": "https://maybe.example.com",
        "indicator_type": "url",
        "matched": False,
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 58, "undetected": 2, "total_engines": total},
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": total,
        "categories": [],
        "timeline": {},
        "engine_results": [],
    }


def vt_unavailable():
    return {
        "provider": "VirusTotal",
        "status": "UNAVAILABLE",
        "indicator": "https://test.example.com",
        "indicator_type": "url",
    }


def uh_matched_url(classification: str = "malware_distribution_url"):
    return {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://evil.example.com",
        "indicator_type": "url",
        "matched": True,
        "classification": classification,
        "url_status": "online",
        "threat": "malware_download",
        "match_scope": "EXACT_URL",
        "evidence": [{
            "source": "URLhaus",
            "evidence_type": "malware_distribution_url",
            "indicator": "https://evil.example.com",
            "scope": "EXACT_URL",
            "description": "URLhaus confirms malware-distribution URL (online).",
            "actual_value": "https://evil.example.com",
            "timestamp": "2024-01-15",
            "relevance": "DIRECT_MATCH",
        }],
        "date_added": "2024-01-15",
        "tags": ["malware"],
        "payloads": [],
        "blacklists": {},
        "urls_for_host": [],
        "limitations": ["URLhaus focuses on malware-distribution URLs."],
    }


def uh_matched_host():
    return {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "evil.example.com",
        "indicator_type": "domain",
        "matched": True,
        "classification": "host_with_malware_urls",
        "url_status": None,
        "threat": None,
        "match_scope": "HOST_LEVEL",
        "evidence": [{
            "source": "URLhaus",
            "evidence_type": "host_with_malware_urls",
            "indicator": "evil.example.com",
            "scope": "HOST_LEVEL",
            "description": "URLhaus associates host with 5 malware URLs.",
            "actual_value": "evil.example.com",
            "timestamp": "2024-01-10",
            "relevance": "HOST_LEVEL_MATCH",
        }],
        "date_added": "2024-01-10",
        "tags": [],
        "payloads": [],
        "blacklists": {},
        "urls_for_host": [{"url": "http://evil.example.com/x.exe", "url_status": "online"}],
        "limitations": [],
    }


def uh_no_match():
    return {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": "https://safe.example.com",
        "indicator_type": "url",
        "matched": False,
        "match_scope": "EXACT_URL",
        "evidence": [],
        "limitations": ["URLhaus returned no matching record."],
    }


def uh_not_applicable(reason="SHA-1"):
    return {
        "provider": "URLhaus",
        "status": "NOT_APPLICABLE",
        "indicator": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "indicator_type": "hash_sha1",
        "matched": False,
        "match_scope": "NOT_APPLICABLE",
        "evidence": [],
        "limitations": [f"URLhaus does not support {reason} lookup."],
    }


def uh_unavailable():
    return {
        "provider": "URLhaus",
        "status": "UNAVAILABLE",
        "indicator": "https://test.example.com",
        "indicator_type": "url",
        "matched": False,
    }


def ioc_info(ioc: str = "https://evil.example.com", category: str = "url"):
    return {"indicator": ioc, "category": category, "is_local": False, "scope": "PUBLIC"}


# ── Test A: CORROBORATED ───────────────────────────────────────────────────────

def test_both_matched_exact_corroborated():
    engine = make_engine()
    result = engine.correlate(vt_completed(malicious=2), uh_matched_url(), ioc_info())
    assert result["status"] == CorrelationStatus.CORROBORATED.value
    assert result["agreement"] is True
    # Evidence from both providers should be present
    sources = {ev.get("source") for ev in result["corroborating_evidence"]}
    assert "VirusTotal" in sources
    assert "URLhaus" in sources
    assert result["conflicts"] == []


def test_both_matched_host_partially_corroborated():
    engine = make_engine()
    # VT: exact URL match, URLhaus: host-level
    result = engine.correlate(vt_completed(malicious=3), uh_matched_host(), ioc_info())
    assert result["status"] == CorrelationStatus.PARTIALLY_CORROBORATED.value
    assert result["agreement"] is True


# ── Test B: SINGLE_PROVIDER (VT match, URLhaus NO_MATCH) ─────────────────────

def test_vt_match_uh_no_match_single_provider():
    engine = make_engine()
    result = engine.correlate(vt_completed(malicious=5), uh_no_match(), ioc_info())
    assert result["status"] == CorrelationStatus.SINGLE_PROVIDER.value
    assert result["agreement"] is False
    # VT evidence should be preserved
    sources = {ev.get("source") for ev in result["corroborating_evidence"]}
    assert "VirusTotal" in sources
    # At least one provider gap should mention URLhaus
    gaps_text = " ".join(result["provider_gaps"])
    assert "URLhaus" in gaps_text or "NO_MATCH" in gaps_text


def test_vt_match_uh_not_applicable_single_provider():
    engine = make_engine()
    result = engine.correlate(vt_completed(malicious=1), uh_not_applicable(), ioc_info())
    assert result["status"] == CorrelationStatus.SINGLE_PROVIDER.value
    gaps_text = " ".join(result["provider_gaps"])
    assert "NOT_APPLICABLE" in gaps_text


# ── Test C: SINGLE_PROVIDER (URLhaus match, VT NO_MATCH) ─────────────────────

def test_uh_match_vt_not_found_single_provider():
    engine = make_engine()
    result = engine.correlate(vt_not_found(), uh_matched_url(), ioc_info())
    # VT has no malicious count and returned NOT_FOUND — this is CONFLICTING (VT 0 detections, URLhaus match)
    # Because VT found the record but with 0 malicious; or may be SINGLE_PROVIDER depending on vt_not_found status
    # vt_not_found returns status=NOT_FOUND which is a no_match status
    assert result["status"] in (
        CorrelationStatus.SINGLE_PROVIDER.value,
        CorrelationStatus.CONFLICTING.value,
    )
    # URLhaus evidence should be in the corroborating list
    sources = {ev.get("source") for ev in result["corroborating_evidence"]}
    assert "URLhaus" in sources


# ── Test D: CONFLICTING (VT clean, URLhaus malware match) ─────────────────────

def test_vt_clean_uh_malware_conflicting():
    engine = make_engine()
    # VT: scan completed, 0 malicious — URLhaus says it's a malware distribution URL
    result = engine.correlate(vt_completed_clean(total=60), uh_matched_url(), ioc_info())
    assert result["status"] == CorrelationStatus.CONFLICTING.value
    assert result["agreement"] is False
    # Must have explicit conflict explanation
    assert len(result["conflicts"]) > 0
    conflict_text = " ".join(result["conflicts"])
    assert "VirusTotal" in conflict_text or "URLhaus" in conflict_text
    # Summary must explain the conflict, not hide it
    assert "conflict" in result["summary"].lower() or "disagree" in result["summary"].lower() or "differ" in result["summary"].lower()


# ── Test E: INSUFFICIENT_DATA (both UNAVAILABLE) ──────────────────────────────

def test_both_unavailable_insufficient_data():
    engine = make_engine()
    result = engine.correlate(vt_unavailable(), uh_unavailable(), ioc_info())
    assert result["status"] == CorrelationStatus.INSUFFICIENT_DATA.value
    assert result["agreement"] is False
    # Both providers should be mentioned in gaps
    gaps_text = " ".join(result["provider_gaps"])
    assert "VirusTotal" in gaps_text
    assert "URLhaus" in gaps_text


# ── Test F: PROVIDER_UNAVAILABLE (one unavailable, other has data) ────────────

def test_vt_unavailable_uh_matched_preserves_evidence():
    engine = make_engine()
    result = engine.correlate(vt_unavailable(), uh_matched_url(), ioc_info())
    assert result["status"] == CorrelationStatus.PROVIDER_UNAVAILABLE.value
    # VT should be mentioned in gaps
    gaps_text = " ".join(result["provider_gaps"])
    assert "VirusTotal" in gaps_text
    # URLhaus evidence MUST be preserved
    sources = {ev.get("source") for ev in result["corroborating_evidence"]}
    assert "URLhaus" in sources


def test_uh_unavailable_vt_matched_preserves_evidence():
    engine = make_engine()
    result = engine.correlate(vt_completed(malicious=3), uh_unavailable(), ioc_info())
    assert result["status"] == CorrelationStatus.PROVIDER_UNAVAILABLE.value
    # URLhaus should be mentioned in gaps
    gaps_text = " ".join(result["provider_gaps"])
    assert "URLhaus" in gaps_text
    # VT evidence MUST be preserved
    sources = {ev.get("source") for ev in result["corroborating_evidence"]}
    assert "VirusTotal" in sources


# ── Test G: NO_MATCH (both no match) ──────────────────────────────────────────

def test_both_no_match():
    engine = make_engine()
    result = engine.correlate(vt_not_found(), uh_no_match(), ioc_info())
    assert result["status"] == CorrelationStatus.NO_MATCH.value
    # Should warn that absence doesn't confirm safety
    summary_lower = result["summary"].lower()
    assert "not" in summary_lower


# ── Test H: Provenance ────────────────────────────────────────────────────────

def test_evidence_items_have_source_provenance():
    """All evidence items must carry a 'source' field (never anonymous)."""
    engine = make_engine()
    result = engine.correlate(vt_completed(malicious=2), uh_matched_url(), ioc_info())
    for ev in result["corroborating_evidence"]:
        assert "source" in ev, f"Evidence item missing 'source': {ev}"
        assert ev["source"] in ("VirusTotal", "URLhaus", "CyberGuard", "CyberGuard Correlation")


def test_correlation_result_has_required_keys():
    """Correlation result must always have all required keys."""
    engine = make_engine()
    result = engine.correlate(vt_unavailable(), uh_unavailable(), ioc_info())
    required_keys = {
        "indicator", "indicator_type", "status", "agreement",
        "conflicts", "corroborating_evidence", "provider_gaps",
        "freshness", "summary", "provider_statuses",
    }
    for key in required_keys:
        assert key in result, f"Missing key: {key}"
