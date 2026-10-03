"""
test_url_resolution_forensics.py — Comprehensive Unit & Forensic Tests for Safe URL Resolution.

Covers:
  - Exact user case regression (q.me-qr.com -> URLhaus report -> tracked malware URL)
  - Multi-hop redirect tracking with HTTP status codes and Location headers
  - SSRF protection (localhost, RFC1918 private IPs, cloud metadata 169.254.169.254)
  - Redirect loop detection
  - Maximum redirect depth enforcement
  - Protocol downgrade detection (HTTPS -> HTTP)
  - Meta-refresh navigation tracking
  - Canonical URL and OpenGraph URL isolation (no field overwrites)
  - Provider report URL vs. URLhaus recorded malware URL disambiguation
  - Safe HTML metadata parsing (no execution of remote scripts)
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from backend.analysis.url_resolver import (
    SafeURLResolver,
    SSRFValidator,
    SafeHTMLMetadataParser,
    ResolutionStatus,
    ResolutionResult,
    RedirectHop,
    PageMetadata,
    AssociatedIOC,
)
from backend.analysis.url_analyzer import URLAnalyzer
from backend.threats.models import RiskLevel, ThreatCategory


# ── 1. SSRF VALIDATOR TESTS ───────────────────────────────────────────────────

def test_ssrf_blocks_loopback_and_private_ips():
    """Verify SSRF validator blocks localhost, 127.0.0.1, RFC1918, and link-local."""
    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("http://127.0.0.1:8080/admin")
    assert not safe
    assert is_ssrf
    assert "Loopback" in reason or "blocked" in reason

    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("http://192.168.1.1/")
    assert not safe
    assert is_ssrf
    assert "Private" in reason or "blocked" in reason

    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("http://10.0.0.1/status")
    assert not safe
    assert is_ssrf

    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("http://localhost:3000/")
    assert not safe
    assert is_ssrf
    assert "Blocked hostname" in reason or "blocked" in reason


def test_ssrf_blocks_cloud_metadata_endpoints():
    """Verify SSRF validator blocks AWS/GCP/Azure metadata IP 169.254.169.254."""
    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("http://169.254.169.254/latest/meta-data/")
    assert not safe
    assert is_ssrf
    assert "metadata" in reason.lower() or "blocked" in reason.lower()

    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("http://metadata.google.internal/computeMetadata/v1/")
    assert not safe
    assert is_ssrf


def test_ssrf_blocks_internal_tlds():
    """Verify SSRF validator blocks .local, .internal, .localhost TLDs."""
    for bad_domain in ["server.local", "db.internal", "app.localhost"]:
        safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url(f"http://{bad_domain}/api")
        assert not safe
        assert is_ssrf
        assert "Internal TLD" in reason or "Blocked" in reason


def test_ssrf_allows_public_ip_and_domain():
    """Verify SSRF validator allows legitimate public IPs."""
    # 8.8.8.8 is Google Public DNS
    safe, is_ssrf, reason, scheme, host, port = SSRFValidator.validate_url("https://8.8.8.8/dns-query")
    assert safe
    assert not is_ssrf
    assert reason == ""


# ── 2. HTML METADATA PARSER SAFETY ───────────────────────────────────────────

def test_safe_html_parser_extracts_metadata_without_execution():
    """Verify HTML parser extracts title, canonical, og:url, and referenced IOCs without script execution."""
    sample_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>URLhaus | http://42.179.116.166:55253/i</title>
        <link rel="canonical" href="https://urlhaus.abuse.ch/url/3923115/" />
        <meta property="og:url" content="https://urlhaus.abuse.ch/url/3923115/" />
        <script>alert("malicious script should never execute");</script>
    </head>
    <body>
        <p>Database record for malware distribution URL.</p>
        <a href="https://urlhaus.abuse.ch/url/3923115/">Report Details</a>
    </body>
    </html>
    """
    parser = SafeHTMLMetadataParser("https://urlhaus.abuse.ch/url/3923115/")
    parser.feed(sample_html)

    assert parser.title == "URLhaus | http://42.179.116.166:55253/i"
    assert parser.canonical_url == "https://urlhaus.abuse.ch/url/3923115/"
    assert parser.og_url == "https://urlhaus.abuse.ch/url/3923115/"
    # Check that referenced URLs extracted the URLhaus report link and the title URL
    assert "https://urlhaus.abuse.ch/url/3923115/" in parser.referenced_urls
    assert "http://42.179.116.166:55253/i" in parser.referenced_urls


def test_safe_html_parser_meta_refresh_detection():
    """Verify HTML parser detects <meta http-equiv='refresh'> navigation safely."""
    html_with_refresh = """
    <html>
    <head>
        <meta http-equiv="refresh" content="2; url=https://target.com/landing">
    </head>
    </html>
    """
    parser = SafeHTMLMetadataParser("https://source.com/")
    parser.feed(html_with_refresh)

    assert parser.meta_refresh_target == "https://target.com/landing"


# ── 3. REDIRECT CHAIN & RESOLUTION ENGINE TESTS ──────────────────────────────

@pytest.mark.asyncio
async def test_redirect_loop_detection():
    """Verify resolver detects redirect loops (A -> B -> A) and halts with REDIRECT_LOOP."""
    resolver = SafeURLResolver()

    # Simulate response for hop 1: url_a -> 302 to url_b
    # Hop 2: url_b -> 302 to url_a
    url_a = "http://loop-test-a.org/"
    url_b = "http://loop-test-b.org/"

    # Mock SSRFValidator to treat both as valid public hostnames
    with patch.object(SSRFValidator, "validate_url", return_value=(True, False, "", "http", "mock", 80)):
        mock_resp_a = MagicMock()
        mock_resp_a.status_code = 302
        mock_resp_a.headers = {"location": url_b, "content-type": "text/html"}
        mock_resp_a.text = "Redirecting"

        mock_resp_b = MagicMock()
        mock_resp_b.status_code = 302
        mock_resp_b.headers = {"location": url_a, "content-type": "text/html"}
        mock_resp_b.text = "Redirecting"

        def mock_get(url, **kwargs):
            return mock_resp_a if url == url_a else mock_resp_b

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get):
            res = await resolver.resolve(url_a)

    assert res.status == ResolutionStatus.REDIRECT_LOOP
    assert "Redirect loop detected" in (res.error_message or "")
    assert res.redirect_count >= 1


@pytest.mark.asyncio
async def test_redirect_limit_exceeded():
    """Verify resolver halts when maximum redirect depth is reached without infinite recursion."""
    resolver = SafeURLResolver(max_hops=3)

    with patch.object(SSRFValidator, "validate_url", return_value=(True, False, "", "http", "mock", 80)):
        def mock_get(url, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 302
            # Always redirect to next number
            curr = int(url.split("/")[-1] or "0")
            mock_resp.headers = {"location": f"http://infinite-chain.org/{curr + 1}", "content-type": "text/html"}
            mock_resp.text = "Redirecting"
            return mock_resp

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get):
            res = await resolver.resolve("http://infinite-chain.org/0")

    assert res.status == ResolutionStatus.REDIRECT_LIMIT
    assert res.redirect_count == 3
    assert "Maximum redirect depth exceeded" in (res.error_message or "")


@pytest.mark.asyncio
async def test_blocked_redirect_target_ssrf():
    """Verify resolver stops immediately if an intermediate redirect attempts SSRF."""
    resolver = SafeURLResolver()

    url_initial = "http://public-entry.org/jump"
    url_evil_target = "http://127.0.0.1:8000/internal-admin"

    # Step 1: Initial URL passes SSRF
    # Step 2: Redirect to evil target fails SSRF with is_ssrf=True
    def mock_validate(target_url):
        if "127.0.0.1" in target_url:
            return False, True, "Loopback address blocked: 127.0.0.1", "http", "127.0.0.1", 8000
        return True, False, "", "http", "public-entry.org", 80

    with patch.object(SSRFValidator, "validate_url", side_effect=mock_validate):
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"location": url_evil_target, "content-type": "text/html"}
        mock_resp.text = "Redirecting"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await resolver.resolve(url_initial)

    assert res.status == ResolutionStatus.BLOCKED_REDIRECT_TARGET
    assert "blocked by SSRF protection" in (res.error_message or "")
    assert res.terminal_url == url_evil_target


@pytest.mark.asyncio
async def test_protocol_downgrade_recording():
    """Verify HTTPS to HTTP transition is explicitly captured as HTTPS_TO_HTTP_DOWNGRADE."""
    resolver = SafeURLResolver()

    url_https = "https://secure-source.org/login"
    url_http = "http://insecure-dest.org/login"

    with patch.object(SSRFValidator, "validate_url", return_value=(True, False, "", "http", "mock", 80)):
        mock_redirect = MagicMock()
        mock_redirect.status_code = 301
        mock_redirect.headers = {"location": url_http, "content-type": "text/html"}
        mock_redirect.text = "Moved"

        mock_terminal = MagicMock()
        mock_terminal.status_code = 200
        mock_terminal.headers = {"content-type": "text/html"}
        mock_terminal.text = "<html><title>Insecure Login</title></html>"

        def mock_get(url, **kwargs):
            return mock_redirect if url == url_https else mock_terminal

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get):
            res = await resolver.resolve(url_https)

    assert res.protocol_transition == "HTTPS_TO_HTTP_DOWNGRADE"
    assert res.redirect_count == 1
    assert res.redirect_chain[0].status_code == 301
    assert res.terminal_status_code == 200


# ── 4. FORENSIC DISAMBIGUATION & REGRESSION TESTS ───────────────────────────

@pytest.mark.asyncio
async def test_urlhaus_report_vs_malware_url_separation():
    """
    REGRESSION & AUDIT TEST:
    Verify that when terminal page is a URLhaus report:
      1. original_url is preserved
      2. terminal_url is preserved as the report page
      3. provider_report_url is set to the report page
      4. recorded_malware_url is set to the tracked malware URL
      5. Neither overwrites the other!
    """
    resolver = SafeURLResolver()

    orig_url = "https://q.me-qr.com/kyla2f1y"
    term_report_url = "https://urlhaus.abuse.ch/url/3923115/"
    tracked_malware = "http://42.179.116.166:55253/i"

    report_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>URLhaus | {tracked_malware}</title>
        <link rel="canonical" href="{term_report_url}" />
    </head>
    <body>
        <h1>URLhaus Database</h1>
        <p>Malware URL: {tracked_malware}</p>
        <a href="{term_report_url}">Record #3923115</a>
    </body>
    </html>
    """

    with patch.object(SSRFValidator, "validate_url", return_value=(True, False, "", "https", "mock", 443)):
        mock_hop1 = MagicMock()
        mock_hop1.status_code = 301
        mock_hop1.headers = {"location": term_report_url, "content-type": "text/html"}
        mock_hop1.text = "Redirect"

        mock_terminal = MagicMock()
        mock_terminal.status_code = 200
        mock_terminal.headers = {"content-type": "text/html"}
        mock_terminal.text = report_html

        def mock_get(url, **kwargs):
            return mock_hop1 if url == orig_url else mock_terminal

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get):
            res = await resolver.resolve(orig_url)

    # Core Forensic Invariants:
    assert res.original_url == orig_url
    assert res.terminal_url == term_report_url
    assert res.terminal_status_code == 200
    assert res.provider_report_url == term_report_url
    assert res.recorded_malware_url == tracked_malware

    # Disambiguation Guarantee:
    assert res.terminal_url != res.recorded_malware_url
    assert res.provider_report_url != res.recorded_malware_url
    assert res.page_metadata.title == f"URLhaus | {tracked_malware}"

    # Verify Associated IOCs
    ioc_values = [ioc.value for ioc in res.associated_iocs]
    assert tracked_malware in ioc_values
    malware_ioc = next(ioc for ioc in res.associated_iocs if ioc.value == tracked_malware)
    assert malware_ioc.scope == "URLHAUS_RECORDED_MALWARE_URL"
    assert malware_ioc.associated_host == "42.179.116.166"


@pytest.mark.asyncio
async def test_url_analyzer_full_forensic_pipeline_enrichment():
    """
    Test URLAnalyzer with the exact scenario:
    The landing page documents URLhaus record #3923115 with tracked malware http://42.179.116.166:55253/i.
    URLAnalyzer queries URLhaus for URLID 3923115, enriches associated IOC,
    and classifies the event as HIGH/MALICIOUS with zero field overwrites.
    """
    analyzer = URLAnalyzer()

    orig_url = "https://q.me-qr.com/kyla2f1y"
    term_report_url = "https://urlhaus.abuse.ch/url/3923115/"
    tracked_malware = "http://42.179.116.166:55253/i"

    mock_res = ResolutionResult(
        original_url=orig_url,
        terminal_url=term_report_url,
        status=ResolutionStatus.COMPLETED,
        redirect_count=1,
        redirect_chain=[
            RedirectHop(
                hop=1,
                from_url=orig_url,
                to_url=term_report_url,
                status_code=301,
                redirect_type="HTTP",
                location_header=term_report_url,
            )
        ],
        terminal_status_code=200,
        page_metadata=PageMetadata(
            title=f"URLhaus | {tracked_malware}",
            canonical_url=term_report_url,
            referenced_urls=[term_report_url, tracked_malware],
        ),
        provider_report_url=term_report_url,
        recorded_malware_url=tracked_malware,
        associated_iocs=[
            AssociatedIOC(
                value=tracked_malware,
                type="URL",
                source="URLhaus",
                relationship="RECORDED_MALWARE_URL",
                scope="URLHAUS_RECORDED_MALWARE_URL",
                associated_host="42.179.116.166",
                urlhaus_record_id="3923115",
                provider_report_url=term_report_url,
            )
        ],
    )

    mock_urlid_data = {
        "id": "3923115",
        "url": tracked_malware,
        "recorded_malware_url": tracked_malware,
        "matched": True,
        "url_status": "offline",
        "host": "42.179.116.166",
        "threat": "malware_download",
        "tags": ["Mozi", "elf"],
        "payloads": [{"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
    }

    mock_uh_resp = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": tracked_malware,
        "matched": True,
        "threat": "malware_download",
        "url_status": "offline",
        "match_scope": "URLHAUS_RECORDED_MALWARE_URL",
    }

    mock_vt_orig = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": orig_url,
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 20, "total_engines": 70},
        "engine_results": [],
    }

    with patch.object(analyzer.resolver, "resolve", AsyncMock(return_value=mock_res)):
        with patch.object(analyzer.vt_provider, "get_url_report", AsyncMock(return_value=mock_vt_orig)):
            with patch.object(analyzer.urlhaus_provider, "lookup_urlid", AsyncMock(return_value=mock_urlid_data)):
                with patch.object(analyzer.urlhaus_provider, "lookup_url", AsyncMock(return_value=mock_uh_resp)):
                    event = await analyzer.analyze(orig_url)

    # Risk Engine Verdict:
    assert event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert event.classification == "MALICIOUS"

    # Threat Intelligence Payload Field Non-Collision:
    ti = event.threat_intelligence
    assert ti["original_url"] == orig_url
    assert ti["terminal_url"] == term_report_url
    assert ti["final_url"] == term_report_url  # Backward compatibility field
    assert ti["provider_report_url"] == term_report_url
    assert ti["recorded_malware_url"] == tracked_malware
    assert ti["urlhaus_recorded_malware_url"] == tracked_malware

    # Resolution object in payload:
    assert ti["resolution"]["status"] == "COMPLETED"
    assert ti["resolution"]["terminal_status_code"] == 200
    assert len(ti["resolution"]["redirect_chain"]) == 1

    # Associated IOCs intact:
    assert len(ti["associated_iocs"]) >= 1
    ioc0 = ti["associated_iocs"][0]
    assert ioc0["value"] == tracked_malware
    assert ioc0["scope"] == "URLHAUS_RECORDED_MALWARE_URL"
    assert ioc0["threat"] == "malware_download"
    assert ioc0["associated_host"] == "42.179.116.166"


@pytest.mark.asyncio
async def test_me_qr_landing_page_associated_threat_provenance():
    """
    Forensic Regression Test: User Observed Case.
    Primary URL: https://q.me-qr.com/kyla2f1y
    Redirects to Terminal URL: https://qr1.me-qr.com/kyla2f1y (HTTP 200)
    Landing page contains reference to URLhaus report: https://urlhaus.abuse.ch/url/3923115/
    URLhaus report identifies recorded malware URL: http://42.179.116.166:55253/i

    Verifies:
      1. Primary IOC retains its own identity (clean VT 0/92, URLhaus NO_MATCH).
      2. Providers map is NOT contaminated: providers['urlhaus']['matched'] is False for primary.
      3. Associated IOC has its own scope ('URLHAUS_RECORDED_MALWARE_URL') and VT (3/93).
      4. Correlation status is 'RELATED_EVIDENCE' (no contradiction between NO_MATCH and matched).
      5. Assessment narrative accurately distinguishes landing-page reference from network redirect.
      6. Performance timers capture all stages: resolution_ms, virustotal_ms, urlhaus_ms, correlation_ms.
    """
    analyzer = URLAnalyzer()

    orig_url = "https://q.me-qr.com/kyla2f1y"
    term_url = "https://qr1.me-qr.com/kyla2f1y"
    report_page = "https://urlhaus.abuse.ch/url/3923115/"
    recorded_malware = "http://42.179.116.166:55253/i"

    mock_res = ResolutionResult(
        original_url=orig_url,
        terminal_url=term_url,
        status=ResolutionStatus.COMPLETED,
        redirect_count=1,
        redirect_chain=[
            RedirectHop(
                hop=1,
                from_url=orig_url,
                to_url=term_url,
                status_code=301,
                redirect_type="HTTP",
            )
        ],
        terminal_status_code=200,
        page_metadata=PageMetadata(
            title="Giant QR Code Generator | View QR code",
            canonical_url="https://me-qr.com/page/blog/how-many-unique-qr-codes-are-possible",
            referenced_urls=[report_page],
        ),
        provider_report_url=report_page,
        recorded_malware_url=recorded_malware,
        associated_iocs=[
            AssociatedIOC(
                value=recorded_malware,
                type="URL",
                source="URLhaus",
                relationship="RECORDED_MALWARE_URL",
                scope="URLHAUS_RECORDED_MALWARE_URL",
                associated_host="42.179.116.166",
                urlhaus_record_id="3923115",
                provider_report_url=report_page,
            )
        ],
    )

    mock_vt_primary = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": orig_url,
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 58, "undetected": 34, "total_engines": 92},
        "engine_results": [],
    }

    mock_uh_primary = {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": orig_url,
        "matched": False,
        "message": "URL not found in URLhaus database",
    }

    mock_urlid_data = {
        "id": "3923115",
        "url": recorded_malware,
        "recorded_malware_url": recorded_malware,
        "matched": True,
        "url_status": "online",
        "host": "42.179.116.166",
        "threat": "malware_download",
        "tags": ["Mozi", "elf"],
        "payloads": [{"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
    }

    mock_vt_recorded = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": recorded_malware,
        "summary": {"malicious": 3, "suspicious": 0, "harmless": 50, "undetected": 40, "total_engines": 93},
        "engine_results": [],
    }

    async def mock_get_url_report(target_url):
        if target_url == recorded_malware:
            return mock_vt_recorded
        return mock_vt_primary

    with patch.object(analyzer.resolver, "resolve", AsyncMock(return_value=mock_res)):
        with patch.object(analyzer.vt_provider, "get_url_report", side_effect=mock_get_url_report):
            with patch.object(analyzer.urlhaus_provider, "lookup_urlid", AsyncMock(return_value=mock_urlid_data)):
                with patch.object(analyzer.urlhaus_provider, "lookup_url", AsyncMock(return_value=mock_uh_primary)):
                    event = await analyzer.analyze(orig_url)

    ti = event.threat_intelligence

    # 1. Identity preservation
    assert ti["original_url"] == orig_url
    assert ti["terminal_url"] == term_url
    assert ti["provider_report_url"] == report_page
    assert ti["recorded_malware_url"] == recorded_malware

    # 2. Primary IOC Provider Scoping
    providers = ti["providers"]
    assert providers["virustotal"]["malicious"] == 0
    assert providers["virustotal"]["scope"] == "PRIMARY_IOC"
    assert providers["urlhaus"]["matched"] is False
    assert providers["urlhaus"]["status"] == "NO_MATCH"
    assert providers["urlhaus"]["scope"] == "PRIMARY_IOC"

    # 3. Related Intelligence Scoping
    assert "related_intelligence" in providers
    related = providers["related_intelligence"]
    assert related["scope"] == "URLHAUS_RECORDED_MALWARE_URL"
    assert related["urlhaus"]["threat"] == "malware_download"
    assert related["urlhaus"]["status"] == "online"
    assert related["virustotal"]["malicious"] == 3
    assert related["virustotal"]["total_engines"] == 93

    # 4. Correlation Status: RELATED_EVIDENCE (not NO_MATCH contradiction!)
    corr = ti["correlation"]
    assert corr["status"] == "RELATED_EVIDENCE"
    assert corr["primary_status"] == "NO_MATCH"
    assert "related_intelligence" in corr

    # 5. Narrative truthfulness: does NOT claim resolved via redirect to URLhaus
    reasoning = event.explanation.reasoning
    assert "contained a reference to URLhaus database record" in reasoning
    assert "resolved via redirect to a URLhaus database report" not in reasoning
    assert "no direct provider detections" in reasoning

    # 6. Performance breakdown includes resolution_ms
    perf = ti["performance"]
    assert "resolution_ms" in perf
    assert "virustotal_ms" in perf
    assert "urlhaus_ms" in perf
    assert "correlation_ms" in perf
    assert "total_ms" in perf

