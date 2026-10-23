"""
test_qr_pipeline.py - Exhaustive verification test matrix for the QR -> URL -> Threat Intel pipeline.
"""
import pytest
import io
import asyncio
from unittest.mock import patch, AsyncMock
from PIL import Image
import qrcode

from backend.config import get_settings
from backend.analysis.qr_analyzer import QRAnalyzer
from backend.analysis.url_analyzer import URLAnalyzer
from backend.threats.models import ThreatCategory, RiskLevel
from backend.threats.virustotal import VirusTotalProvider
from backend.threats.urlhaus import URLhausProvider
from backend.threats.correlation import CorrelationStatus


@pytest.fixture
def qr_analyzer():
    settings = get_settings()
    return QRAnalyzer(settings)


@pytest.fixture
def url_analyzer():
    settings = get_settings()
    return URLAnalyzer(settings)


def _make_qr_image_bytes(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue()


# ── TEST 1: User's exact test fixture decoding ─────────────────────────────────
@pytest.mark.asyncio
async def test_user_test_fixture_exact_payload(qr_analyzer):
    """Verify that the user's actual QR fixture decodes to https://q.me-qr.com/kyla2f1y."""
    with open("tests/fixtures/user_test_qr.png", "rb") as f:
        img_bytes = f.read()

    event = await qr_analyzer.analyze(img_bytes)
    assert event.modality == "image/qr"
    ti = event.threat_intelligence
    assert ti is not None
    assert ti["qr_metadata"]["qr_status"] == "DECODED"
    assert ti["qr_metadata"]["decoded_payload"] == "https://q.me-qr.com/kyla2f1y"
    assert ti["qr_metadata"]["content_type"] == "URL"
    assert event.classification != "QR_DECODE_FAILED"


# ── TEST 2: Non-QR image produces QR_DECODE_FAILED (NEVER SAFE) ────────────────
@pytest.mark.asyncio
async def test_non_qr_image_fails_safely(qr_analyzer):
    """An image without a QR code must return QR_DECODE_FAILED, never a false SAFE verdict."""
    blank_img = Image.new("RGB", (150, 150), color="white")
    buf = io.BytesIO()
    blank_img.save(buf, format="PNG")

    event = await qr_analyzer.analyze(buf.getvalue())
    assert event.classification == "QR_DECODE_FAILED"
    assert event.threat_category == ThreatCategory.UNKNOWN
    assert "No QR code" in event.explanation.summary


# ── TEST 3: Plain text QR payload routed to PhishingAnalyzer ───────────────────
@pytest.mark.asyncio
async def test_plain_text_qr_payloads(qr_analyzer):
    """Plain text QR codes must not be labeled as MALICIOUS_URL."""
    # Benign text
    benign_bytes = _make_qr_image_bytes("Office WiFi password is cyberguard2026")
    event_benign = await qr_analyzer.analyze(benign_bytes)
    assert event_benign.modality == "image/qr"
    assert event_benign.classification == "SAFE"
    assert event_benign.threat_category == ThreatCategory.SAFE
    assert "plain text" in event_benign.explanation.summary.lower()

    # Phishing text
    phish_bytes = _make_qr_image_bytes("URGENT: Your bank account is locked. Verify your credentials immediately.")
    event_phish = await qr_analyzer.analyze(phish_bytes)
    assert event_phish.modality == "image/qr"
    assert event_phish.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert event_phish.threat_category == ThreatCategory.PHISHING


# ── TEST 4: VirusTotal PENDING state blocks final SAFE verdict ─────────────────
@pytest.mark.asyncio
async def test_vt_pending_state_produces_pending_verification(qr_analyzer):
    """When VirusTotal analysis is pending, verdict MUST NOT be finalized as SAFE."""
    mock_pending_vt = {
        "status": "PENDING",
        "provider": "VirusTotal",
        "indicator": "https://suspicious-pending-scan.com/drop",
        "indicator_type": "url",
        "message": "URL was submitted to VirusTotal for analysis (results pending in external queue).",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0},
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": ""
    }

    qr_bytes = _make_qr_image_bytes("https://suspicious-pending-scan.com/drop")

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_pending_vt)):
        event = await qr_analyzer.analyze(qr_bytes)

    # Must be PENDING_EXTERNAL_VERIFICATION, not SAFE!
    assert event.classification == "PENDING_EXTERNAL_VERIFICATION"
    assert event.threat_category != ThreatCategory.MALICIOUS_URL
    ti = event.threat_intelligence
    assert ti["is_pending"] is True
    assert ti["can_finalize"] is False
    assert ti["providers"]["virustotal"]["status"] == "PENDING"
    assert ti["providers"]["urlhaus"]["status"] == "WAITING_FOR_VIRUSTOTAL"
    assert ti["correlation"]["status"] == "PENDING"
    assert "results pending" in event.explanation.summary


# ── TEST 5: VT Malicious + URLhaus Matched -> CORROBORATED ─────────────────────
@pytest.mark.asyncio
async def test_vt_malicious_and_urlhaus_matched_corroborated(qr_analyzer):
    """When both VT and URLhaus independently detect malware, report CORROBORATED."""
    mock_vt = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://malware-drop-site.org/malware.exe",
        "indicator_type": "url",
        "summary": {"malicious": 8, "suspicious": 2, "harmless": 0, "undetected": 60, "total_engines": 70},
        "malicious_count": 8,
        "suspicious_count": 2,
        "total_engines": 70,
        "engine_results": [{"engine_name": "Kaspersky", "verdict": "malicious", "result": "Trojan.Generic", "method": "blacklist"}],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "https://virustotal.com/gui/url/mock"
    }

    mock_uh = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://malware-drop-site.org/malware.exe",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "exe",
        "tags": ["AgentTesla", "payload_delivery"],
        "evidence": [{"evidence_type": "urlhaus_malware", "actual_value": "AgentTesla", "description": "URLhaus malware drop"}],
        "match_scope": "EXACT_URL",
        "limitations": [],
    }

    qr_bytes = _make_qr_image_bytes("https://malware-drop-site.org/malware.exe")

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_vt)):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh)):
            event = await qr_analyzer.analyze(qr_bytes)

    assert event.severity == RiskLevel.CRITICAL
    assert event.threat_category == ThreatCategory.MALICIOUS_URL
    assert event.classification == "MALICIOUS"
    ti = event.threat_intelligence
    assert ti["correlation"]["status"] == CorrelationStatus.CORROBORATED.value
    assert ti["providers"]["virustotal"]["matched"] is True
    assert ti["providers"]["urlhaus"]["matched"] is True


# ── TEST 6: Single Provider — VT Malicious + URLhaus No Match ─────────────────
@pytest.mark.asyncio
async def test_vt_malicious_urlhaus_no_match_single_provider(qr_analyzer):
    """When only VirusTotal detects malware, report SINGLE_PROVIDER and preserve evidence."""
    mock_vt = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://phishing-site-example.com/login",
        "indicator_type": "url",
        "summary": {"malicious": 3, "suspicious": 1, "harmless": 20, "undetected": 46, "total_engines": 70},
        "malicious_count": 3,
        "suspicious_count": 1,
        "total_engines": 70,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": ""
    }

    mock_uh = {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": "https://phishing-site-example.com/login",
        "indicator_type": "url",
        "matched": False,
        "classification": None,
        "evidence": [],
        "match_scope": "EXACT_URL",
        "limitations": ["Not indexed by URLhaus."],
    }

    qr_bytes = _make_qr_image_bytes("https://phishing-site-example.com/login")

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_vt)):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh)):
            event = await qr_analyzer.analyze(qr_bytes)

    assert event.severity == RiskLevel.HIGH
    assert event.threat_category == ThreatCategory.MALICIOUS_URL
    ti = event.threat_intelligence
    assert ti["correlation"]["status"] == CorrelationStatus.SINGLE_PROVIDER.value
    assert ti["providers"]["virustotal"]["matched"] is True
    assert ti["providers"]["urlhaus"]["matched"] is False


# ── TEST 7: Single Provider — VT No Match + URLhaus Confirmed Malware ─────────
@pytest.mark.asyncio
async def test_vt_clean_urlhaus_malware_escalates_risk(qr_analyzer):
    """When URLhaus confirms active malware even if VT is clean, risk escalates from SAFE."""
    mock_vt = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://brand-new-stealer.xyz/payload.bin",
        "indicator_type": "url",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 40, "undetected": 30, "total_engines": 70},
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 70,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": ""
    }

    mock_uh = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://brand-new-stealer.xyz/payload.bin",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "RedLineStealer",
        "tags": ["RedLineStealer"],
        "evidence": [{"evidence_type": "urlhaus_malware", "actual_value": "RedLineStealer", "description": "Active RedLine stealer drop"}],
        "match_scope": "EXACT_URL",
        "limitations": [],
    }

    qr_bytes = _make_qr_image_bytes("https://brand-new-stealer.xyz/payload.bin")

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_vt)):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh)):
            event = await qr_analyzer.analyze(qr_bytes)

    # Must NOT be SAFE! URLhaus confirmed malware escalates risk.
    assert event.severity in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    assert event.threat_category == ThreatCategory.MALICIOUS_URL


# ── TEST 8: Provider Failure Isolation ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_provider_failure_isolation_vt_fails_uh_succeeds(qr_analyzer):
    """If VirusTotal fails, URLhaus still runs and threat evidence survives."""
    mock_vt_err = {
        "status": "UNAVAILABLE",
        "provider": "VirusTotal",
        "indicator": "https://test-provider-isolation.com/file",
        "indicator_type": "url",
        "message": "Connection timed out."
    }

    mock_uh = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://test-provider-isolation.com/file",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "dropper",
        "tags": ["dropper"],
        "evidence": [{"evidence_type": "urlhaus_malware", "actual_value": "dropper", "description": "Active dropper"}],
        "match_scope": "EXACT_URL",
        "limitations": [],
    }

    qr_bytes = _make_qr_image_bytes("https://test-provider-isolation.com/file")

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_vt_err)):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh)):
            event = await qr_analyzer.analyze(qr_bytes)

    assert event.severity in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    ti = event.threat_intelligence
    assert ti["providers"]["virustotal"]["status"] == "UNAVAILABLE"
    assert ti["providers"]["urlhaus"]["matched"] is True


# ── TEST 9: Both Providers Unavailable -> INSUFFICIENT_DATA (No Fake Safe) ────
@pytest.mark.asyncio
async def test_both_providers_unavailable_insufficient_data(qr_analyzer):
    """When both external providers are down, report INSUFFICIENT_DATA and do not claim safe from absence."""
    mock_vt_err = {"status": "UNAVAILABLE", "provider": "VirusTotal", "indicator": "https://example.com/test", "indicator_type": "url"}
    mock_uh_err = {"status": "UNAVAILABLE", "provider": "URLhaus", "indicator": "https://example.com/test", "indicator_type": "url", "matched": False, "evidence": []}

    qr_bytes = _make_qr_image_bytes("https://example.com/test")

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_vt_err)):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh_err)):
            event = await qr_analyzer.analyze(qr_bytes)

    ti = event.threat_intelligence
    assert ti["correlation"]["status"] == CorrelationStatus.INSUFFICIENT_DATA.value


# ── TEST 10: Equivalence between Manual URL and QR URL ─────────────────────────
@pytest.mark.asyncio
async def test_manual_url_and_qr_url_produce_identical_verdicts(url_analyzer, qr_analyzer):
    """QR URL analysis must produce the exact same classification and risk as manual URL input."""
    test_url = "https://example.com/consistent-test-url"
    qr_bytes = _make_qr_image_bytes(test_url)

    mock_vt = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": test_url,
        "indicator_type": "url",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 20, "total_engines": 70},
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": ""
    }
    mock_uh = {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": test_url,
        "indicator_type": "url",
        "matched": False,
        "classification": None,
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_vt)):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh)):
            url_event = await url_analyzer.analyze(test_url)
            qr_event = await qr_analyzer.analyze(qr_bytes)

    assert url_event.threat_category == qr_event.threat_category == ThreatCategory.SAFE
    assert url_event.severity == qr_event.severity == RiskLevel.SAFE
    assert url_event.classification == qr_event.classification == "SAFE"
    assert url_event.threat_intelligence["correlation"]["status"] == qr_event.threat_intelligence["correlation"]["status"]


# ── TEST 11: Concurrency and Isolation between Different QR Images ────────────
@pytest.mark.asyncio
async def test_concurrency_and_payload_isolation(qr_analyzer):
    """Multiple concurrent QR analyses must remain completely isolated without cross-contamination."""
    qr_bytes_1 = _make_qr_image_bytes("https://site-alpha.com/page1")
    qr_bytes_2 = _make_qr_image_bytes("https://site-beta.com/page2")

    mock_vt1 = {"status": "COMPLETED", "provider": "VirusTotal", "indicator": "https://site-alpha.com/page1", "indicator_type": "url", "summary": {"malicious": 0, "total_engines": 70}, "engine_results": []}
    mock_vt2 = {"status": "COMPLETED", "provider": "VirusTotal", "indicator": "https://site-beta.com/page2", "indicator_type": "url", "summary": {"malicious": 6, "total_engines": 70}, "malicious_count": 6, "engine_results": []}
    mock_uh = {"provider": "URLhaus", "status": "NO_MATCH", "matched": False, "evidence": []}

    async def mock_vt_side_effect(u):
        return mock_vt1 if "site-alpha" in u else mock_vt2

    with patch.object(VirusTotalProvider, "get_url_report", side_effect=mock_vt_side_effect):
        with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=mock_uh)):
            ev1, ev2 = await asyncio.gather(
                qr_analyzer.analyze(qr_bytes_1, correlation_id="cid-alpha"),
                qr_analyzer.analyze(qr_bytes_2, correlation_id="cid-beta"),
            )

    assert ev1.correlation_id == "cid-alpha"
    assert ev1.severity == RiskLevel.SAFE
    assert ev1.threat_intelligence["qr_metadata"]["decoded_payload"] == "https://site-alpha.com/page1"

    assert ev2.correlation_id == "cid-beta"
    assert ev2.severity == RiskLevel.CRITICAL
    assert ev2.threat_intelligence["qr_metadata"]["decoded_payload"] == "https://site-beta.com/page2"
