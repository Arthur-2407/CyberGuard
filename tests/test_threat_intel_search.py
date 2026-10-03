import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from backend.config import Settings, VirusTotalConfig, get_settings
from backend.threats.ioc_classifier import IOCClassifier, IOCType, IOCScope
from backend.threats.virustotal import VirusTotalProvider
from backend.threats.models import RiskLevel, ThreatCategory
from backend.main import app


def test_ioc_classifier_hashes():
    # MD5 (32 hex)
    md5 = "e80b5017098950fc58aad83c8c14978e"
    res = IOCClassifier.classify(md5)
    assert res["is_supported"] is True
    assert res["category"] == "hash"
    assert res["hash_type"] == "MD5"
    assert res["scope"] == "PUBLIC"
    assert res["is_local"] is False

    # SHA-1 (40 hex)
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    res = IOCClassifier.classify(sha1)
    assert res["is_supported"] is True
    assert res["category"] == "hash"
    assert res["hash_type"] == "SHA-1"

    # SHA-256 (64 hex)
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res = IOCClassifier.classify(sha256)
    assert res["is_supported"] is True
    assert res["category"] == "hash"
    assert res["hash_type"] == "SHA-256"


def test_ioc_classifier_urls():
    # Public URL
    pub = "https://www.google.com/search?q=cyberguard"
    res = IOCClassifier.classify(pub)
    assert res["is_supported"] is True
    assert res["category"] == "url"
    assert res["is_local"] is False
    assert res["scope"] == "PUBLIC"

    # Localhost URL (http://localhost:3000/)
    loc = "http://localhost:3000/"
    res = IOCClassifier.classify(loc)
    assert res["is_supported"] is True
    assert res["category"] == "url"
    assert res["is_local"] is True
    assert res["scope"] == "LOCAL_OR_PRIVATE"

    # Loopback IP URL
    loc_ip = "http://127.0.0.1:8000/api"
    res = IOCClassifier.classify(loc_ip)
    assert res["is_local"] is True

    # Private RFC 1918 URL
    priv_url = "http://192.168.1.100/admin"
    res = IOCClassifier.classify(priv_url)
    assert res["is_local"] is True
    assert res["scope"] == "LOCAL_OR_PRIVATE"


def test_ioc_classifier_ips():
    # Public IPv4
    res = IOCClassifier.classify("8.8.8.8")
    assert res["is_supported"] is True
    assert res["category"] == "ip"
    assert res["is_local"] is False

    # Private IPv4
    res = IOCClassifier.classify("10.0.0.1")
    assert res["is_supported"] is True
    assert res["category"] == "ip"
    assert res["is_local"] is True

    # Loopback IPv4
    res = IOCClassifier.classify("127.0.0.1")
    assert res["is_local"] is True


def test_ioc_classifier_domains():
    # Public domain
    res = IOCClassifier.classify("github.com")
    assert res["is_supported"] is True
    assert res["category"] == "domain"
    assert res["is_local"] is False

    # Local domain
    res = IOCClassifier.classify("server.local")
    assert res["is_supported"] is True
    assert res["category"] == "domain"
    assert res["is_local"] is True

    # Localhost domain
    res = IOCClassifier.classify("localhost")
    assert res["is_local"] is True


def test_ioc_classifier_invalid():
    res = IOCClassifier.classify("")
    assert res["is_supported"] is False

    res = IOCClassifier.classify("invalid target with spaces")
    assert res["is_supported"] is False


@pytest.mark.asyncio
async def test_search_localhost_does_not_call_virustotal():
    """Verify that http://localhost:3000/ does not trigger external VirusTotal lookups and is safe."""
    client = TestClient(app)
    resp = client.get("/api/threats/search?ioc=http://localhost:3000/")
    assert resp.status_code == 200

    data = resp.json()
    assert data["severity"] == "SAFE"
    assert data["classification"] == "SAFE"

    ti = data.get("threat_intelligence")
    assert ti is not None
    assert ti["is_local"] is True
    assert ti["status"] == "NOT_APPLICABLE"
    assert "LOCAL / PRIVATE TARGET" in ti["message"]
    assert ti["summary"]["malicious"] == 0


@pytest.mark.asyncio
async def test_search_public_url_mocked_completed():
    """Verify public URL search normalization and engine results rendering."""
    client = TestClient(app)

    mock_report = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://example.com",
        "indicator_type": "url",
        "summary": {
            "malicious": 2,
            "suspicious": 1,
            "harmless": 65,
            "undetected": 5,
            "timeout": 0,
            "total_engines": 73
        },
        "reputation": 10,
        "categories": [
            {"provider": "BitDefender", "category": "technology"}
        ],
        "category_names": ["technology"],
        "engine_results": [
            {"engine_name": "VendorA", "verdict": "malicious", "result": "phishing", "method": "blacklist"},
            {"engine_name": "VendorB", "verdict": "suspicious", "result": "suspicious", "method": "heuristic"},
            {"engine_name": "VendorC", "verdict": "harmless", "result": "clean", "method": "blacklist"}
        ],
        "timeline": {
            "first_submission": 1600000000,
            "last_analysis": 1700000000
        },
        "technical_details": {
            "url": "https://example.com",
            "final_url": "https://example.com/",
            "http_response_code": 200
        },
        "permalink": "https://www.virustotal.com/gui/url/mock_id",
        "malicious_count": 2,
        "suspicious_count": 1,
        "harmless_count": 65,
        "undetected_count": 5,
        "total_engines": 73
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_report)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            resp = client.get("/api/threats/search?ioc=https://example.com")
            assert resp.status_code == 200
            data = resp.json()

            # Malicious count is 2 -> severity HIGH
            assert data["severity"] == "HIGH"
            ti = data["threat_intelligence"]
            assert ti["status"] == "COMPLETED"
            assert ti["summary"]["malicious"] == 2
            assert len(ti["engine_results"]) == 3
            assert ti["permalink"] == "https://www.virustotal.com/gui/url/mock_id"

            # Check that evidence list contains proper objects with string descriptions
            for ev in data["evidence"]:
                assert isinstance(ev["description"], str)
                assert "[object" not in ev["description"]


@pytest.mark.asyncio
async def test_search_not_found_returns_structured_report():
    """Verify that a 404 NOT_FOUND from VirusTotal does not raise an HTTP 500 error."""
    client = TestClient(app)

    mock_not_found = {
        "status": "NOT_FOUND",
        "provider": "VirusTotal",
        "indicator": "https://unknown-site-12345.org",
        "indicator_type": "url",
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=mock_not_found)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            resp = client.get("/api/threats/search?ioc=https://unknown-site-12345.org")
            assert resp.status_code == 200
            data = resp.json()

            ti = data["threat_intelligence"]
            assert ti["status"] == "NOT_FOUND"
            assert "NO VIRUSTOTAL REPORT FOUND" in ti["message"]
            assert data["severity"] == "SAFE"


# ── URLhaus and Correlation Pipeline Integration Tests ─────────────────────────

from backend.threats.urlhaus import URLhausProvider
from backend.threats.correlation import CorrelationStatus


def test_urlhaus_status_endpoint():
    """Verify GET /api/threats/urlhaus/status returns structured status response."""
    client = TestClient(app)
    mock_status = {
        "provider": "URLhaus",
        "status": "READY",
        "configured": True,
        "enabled": True,
        "message": "URLhaus malware-URL intelligence operational.",
    }
    with patch.object(URLhausProvider, "check_status", AsyncMock(return_value=mock_status)):
        resp = client.get("/api/threats/urlhaus/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "URLhaus"
        assert data["status"] == "READY"
        assert data["configured"] is True


@pytest.mark.asyncio
async def test_provider_order_execution():
    """Controlled test proving VirusTotal completes before URLhaus starts."""
    client = TestClient(app)
    call_order = []

    async def mock_vt_call(*args, **kwargs):
        call_order.append("VT_START")
        import asyncio
        await asyncio.sleep(0.01)
        call_order.append("VT_END")
        return {
            "status": "COMPLETED",
            "provider": "VirusTotal",
            "indicator": "order-test-threat.com",
            "indicator_type": "domain",
            "summary": {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 0, "total_engines": 61},
            "malicious_count": 1,
            "total_engines": 61,
            "engine_results": [],
            "categories": [],
            "timeline": {},
            "technical_details": {},
            "permalink": "",
        }

    async def mock_uh_call(*args, **kwargs):
        call_order.append("UH_START")
        import asyncio
        await asyncio.sleep(0.01)
        call_order.append("UH_END")
        return {
            "provider": "URLhaus",
            "status": "NO_MATCH",
            "indicator": "order-test-threat.com",
            "indicator_type": "domain",
            "matched": False,
            "match_scope": "NO_MATCH",
            "evidence": [],
        }

    with patch.object(VirusTotalProvider, "get_domain_report", side_effect=mock_vt_call):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_host", side_effect=mock_uh_call):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=order-test-threat.com")
                    assert resp.status_code == 200
                    # Verify VT completed before URLhaus started
                    assert call_order == ["VT_START", "VT_END", "UH_START", "UH_END"]


@pytest.mark.asyncio
async def test_vt_fails_urlhaus_still_executes():
    """If VirusTotal fails, URLhaus still runs and threat assessment survives."""
    client = TestClient(app)
    uh_mock_report = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://badware.com/drop",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "malware_download",
        "match_scope": "EXACT_URL",
        "evidence": [{
            "source": "URLhaus",
            "evidence_type": "malware_distribution_url",
            "description": "URLhaus confirmed malware drop",
            "actual_value": "https://badware.com/drop",
        }],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(side_effect=Exception("VT Network Outage"))):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=uh_mock_report)):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://badware.com/drop")
                    assert resp.status_code == 200
                    data = resp.json()
                    ti = data["threat_intelligence"]
                    assert ti["providers"]["virustotal"]["status"] == "UNAVAILABLE"
                    assert ti["providers"]["urlhaus"]["matched"] is True
                    # CyberGuard still flags the risk from URLhaus evidence
                    assert data["severity"] != "SAFE"


@pytest.mark.asyncio
async def test_vt_succeeds_urlhaus_fails():
    """If URLhaus fails, VirusTotal results are retained and correlation engine completes."""
    client = TestClient(app)
    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://phish.org",
        "indicator_type": "url",
        "summary": {"malicious": 6, "suspicious": 1, "harmless": 50, "undetected": 0, "total_engines": 57},
        "malicious_count": 6,
        "suspicious_count": 1,
        "total_engines": 57,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "https://virustotal.com/gui/url/phish",
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(side_effect=Exception("URLhaus 500"))):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://phish.org")
                    assert resp.status_code == 200
                    data = resp.json()
                    ti = data["threat_intelligence"]
                    assert ti["providers"]["virustotal"]["status"] == "COMPLETED"
                    assert ti["providers"]["virustotal"]["matched"] is True
                    assert ti["providers"]["urlhaus"]["status"] == "ERROR"
                    assert data["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_both_no_match_correlation():
    """When both providers find no match, status is NO_MATCH and not falsely marked SAFE."""
    client = TestClient(app)
    vt_mock = {
        "status": "NOT_FOUND",
        "provider": "VirusTotal",
        "indicator": "https://fresh-domain-999.xyz",
        "indicator_type": "url",
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 0,
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0},
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": "https://fresh-domain-999.xyz",
        "indicator_type": "url",
        "matched": False,
        "match_scope": "NO_MATCH",
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=uh_mock)):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://fresh-domain-999.xyz")
                    assert resp.status_code == 200
                    data = resp.json()
                    ti = data["threat_intelligence"]
                    assert ti["correlation"]["status"] == "NO_MATCH"
                    assert "Absence of external threat records does not guarantee safety" in data["explanation"]["reasoning"]


@pytest.mark.asyncio
async def test_corroborated_correlation():
    """When both providers return matching malicious intelligence, status is CORROBORATED."""
    client = TestClient(app)
    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://confirmed-malware-drop.com/exe",
        "indicator_type": "url",
        "summary": {"malicious": 8, "suspicious": 2, "harmless": 40, "undetected": 0, "total_engines": 50},
        "malicious_count": 8,
        "suspicious_count": 2,
        "total_engines": 50,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "https://virustotal.com/gui/url/exe",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://confirmed-malware-drop.com/exe",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "malware_download",
        "match_scope": "EXACT_URL",
        "evidence": [{
            "source": "URLhaus",
            "evidence_type": "malware_distribution_url",
            "description": "URLhaus confirms online malware distribution point.",
            "actual_value": "https://confirmed-malware-drop.com/exe",
        }],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=uh_mock)):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://confirmed-malware-drop.com/exe")
                    assert resp.status_code == 200
                    data = resp.json()
                    ti = data["threat_intelligence"]
                    assert ti["correlation"]["status"] == "CORROBORATED"
                    assert data["severity"] == "CRITICAL"
                    # Check provider provenance
                    assert "VirusTotal" in ti["correlated_assessment"]["provenance"]
                    assert "URLhaus" in ti["correlated_assessment"]["provenance"]


@pytest.mark.asyncio
async def test_single_provider_correlation():
    """When only one provider has matching threat intelligence, status is SINGLE_PROVIDER."""
    client = TestClient(app)
    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://brand-new-phish.net",
        "indicator_type": "url",
        "summary": {"malicious": 4, "suspicious": 1, "harmless": 55, "undetected": 0, "total_engines": 60},
        "malicious_count": 4,
        "suspicious_count": 1,
        "total_engines": 60,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": "https://brand-new-phish.net",
        "indicator_type": "url",
        "matched": False,
        "match_scope": "NO_MATCH",
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=uh_mock)):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://brand-new-phish.net")
                    assert resp.status_code == 200
                    data = resp.json()
                    ti = data["threat_intelligence"]
                    assert ti["correlation"]["status"] == "SINGLE_PROVIDER"
                    assert ti["providers"]["virustotal"]["matched"] is True
                    assert ti["providers"]["urlhaus"]["matched"] is False


@pytest.mark.asyncio
async def test_conflicting_correlation():
    """When providers materially disagree (VT zero malicious, URLhaus active malware), status is CONFLICTING."""
    client = TestClient(app)
    vt_clean = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://stealth-malware.org/loader",
        "indicator_type": "url",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 65, "undetected": 0, "total_engines": 65},
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines": 65,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }
    uh_malware = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://stealth-malware.org/loader",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "malware_download",
        "match_scope": "EXACT_URL",
        "evidence": [{
            "source": "URLhaus",
            "evidence_type": "malware_distribution_url",
            "description": "URLhaus confirmed malware loader URL",
            "actual_value": "https://stealth-malware.org/loader",
        }],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=vt_clean)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=uh_malware)):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://stealth-malware.org/loader")
                    assert resp.status_code == 200
                    data = resp.json()
                    ti = data["threat_intelligence"]
                    assert ti["correlation"]["status"] == "CONFLICTING"
                    assert len(ti["correlation"]["conflicts"]) > 0
                    # Risk is not marked safe when URLhaus has confirmed malware
                    assert data["severity"] != "SAFE"


@pytest.mark.asyncio
async def test_ioc_routing_sha256():
    """Verify SHA-256 hash routes to lookup_payload_sha256."""
    client = TestClient(app)
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": sha256,
        "indicator_type": "hash",
        "summary": {"malicious": 10, "suspicious": 0, "harmless": 40, "undetected": 0, "total_engines": 50},
        "malicious_count": 10,
        "total_engines": 50,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": sha256,
        "indicator_type": "hash",
        "matched": True,
        "classification": "payload",
        "match_scope": "EXACT_HASH",
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_file_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_payload_sha256", AsyncMock(return_value=uh_mock)) as mock_sha:
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get(f"/api/threats/search?ioc={sha256}")
                    assert resp.status_code == 200
                    mock_sha.assert_called_once_with(sha256)


@pytest.mark.asyncio
async def test_ioc_routing_md5():
    """Verify MD5 hash routes to lookup_payload_md5."""
    client = TestClient(app)
    md5 = "e80b5017098950fc58aad83c8c14978e"

    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": md5,
        "indicator_type": "hash",
        "summary": {"malicious": 5, "suspicious": 0, "harmless": 45, "undetected": 0, "total_engines": 50},
        "malicious_count": 5,
        "total_engines": 50,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": md5,
        "indicator_type": "hash",
        "matched": True,
        "classification": "payload",
        "match_scope": "EXACT_HASH",
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_file_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_payload_md5", AsyncMock(return_value=uh_mock)) as mock_md5:
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get(f"/api/threats/search?ioc={md5}")
                    assert resp.status_code == 200
                    mock_md5.assert_called_once_with(md5)


@pytest.mark.asyncio
async def test_ioc_routing_sha1_not_applicable():
    """Verify SHA-1 hash is marked NOT_APPLICABLE for URLhaus since URLhaus does not support SHA-1."""
    client = TestClient(app)
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": sha1,
        "indicator_type": "hash",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 0, "total_engines": 50},
        "malicious_count": 0,
        "total_engines": 50,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }

    with patch.object(VirusTotalProvider, "get_file_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "is_configured", True):
                resp = client.get(f"/api/threats/search?ioc={sha1}")
                assert resp.status_code == 200
                data = resp.json()
                ti = data["threat_intelligence"]
                assert ti["urlhaus"]["status"] == "NOT_APPLICABLE"
                assert ti["urlhaus"]["match_scope"] == "NOT_APPLICABLE"


@pytest.mark.asyncio
async def test_ioc_routing_domain():
    """Verify domain routes to URLhaus lookup_host with indicator_type='domain'."""
    client = TestClient(app)
    domain = "suspicious-domain-test.xyz"

    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": domain,
        "indicator_type": "domain",
        "summary": {"malicious": 1, "suspicious": 0, "harmless": 50, "undetected": 0, "total_engines": 51},
        "malicious_count": 1,
        "total_engines": 51,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": domain,
        "indicator_type": "domain",
        "matched": True,
        "classification": "host_with_malware_urls",
        "match_scope": "HOST_LEVEL",
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_domain_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_host", AsyncMock(return_value=uh_mock)) as mock_host:
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get(f"/api/threats/search?ioc={domain}")
                    assert resp.status_code == 200
                    mock_host.assert_called_once_with(domain, indicator_type="domain")


@pytest.mark.asyncio
async def test_ioc_routing_ip():
    """Verify IP routes to URLhaus lookup_host with indicator_type='ip'."""
    client = TestClient(app)
    ip = "93.184.216.34"

    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": ip,
        "indicator_type": "ip",
        "summary": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 0, "total_engines": 50},
        "malicious_count": 0,
        "total_engines": 50,
        "engine_results": [],
        "categories": [],
        "timeline": {},
        "technical_details": {},
        "permalink": "",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "NO_MATCH",
        "indicator": ip,
        "indicator_type": "ip",
        "matched": False,
        "match_scope": "NO_MATCH",
        "evidence": [],
    }

    with patch.object(VirusTotalProvider, "get_ip_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_host", AsyncMock(return_value=uh_mock)) as mock_host:
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get(f"/api/threats/search?ioc={ip}")
                    assert resp.status_code == 200
                    mock_host.assert_called_once_with(ip, indicator_type="ip")


@pytest.mark.asyncio
async def test_backward_compatibility_and_structure():
    """Verify that both legacy fields and new multi-provider fields are structurally complete."""
    client = TestClient(app)
    vt_mock = {
        "status": "COMPLETED",
        "provider": "VirusTotal",
        "indicator": "https://example.com/compat-check",
        "indicator_type": "url",
        "summary": {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 0, "total_engines": 63},
        "malicious_count": 2,
        "suspicious_count": 1,
        "total_engines": 63,
        "reputation": 5,
        "engine_results": [{"engine_name": "Vendor1", "verdict": "malicious", "result": "trojan"}],
        "categories": [{"provider": "Vendor1", "category": "malware"}],
        "timeline": {"first_seen": 1600000000},
        "technical_details": {"ip": "1.2.3.4"},
        "permalink": "https://virustotal.com/gui/url/compat",
    }
    uh_mock = {
        "provider": "URLhaus",
        "status": "COMPLETED",
        "indicator": "https://example.com/compat-check",
        "indicator_type": "url",
        "matched": True,
        "classification": "malware_distribution_url",
        "url_status": "online",
        "threat": "malware_download",
        "match_scope": "EXACT_URL",
        "evidence": [{
            "source": "URLhaus",
            "evidence_type": "malware_distribution_url",
            "description": "URLhaus online malware URL",
            "actual_value": "https://example.com/compat-check",
        }],
    }

    with patch.object(VirusTotalProvider, "get_url_report", AsyncMock(return_value=vt_mock)):
        with patch.object(VirusTotalProvider, "is_configured", True):
            with patch.object(URLhausProvider, "lookup_url", AsyncMock(return_value=uh_mock)):
                with patch.object(URLhausProvider, "is_configured", True):
                    resp = client.get("/api/threats/search?ioc=https://example.com/compat-check")
                    assert resp.status_code == 200
                    data = resp.json()

                    # 1. Top-level ThreatEvent contract
                    assert "event_id" in data
                    assert "severity" in data
                    assert "classification" in data
                    assert "evidence" in data
                    assert "explanation" in data
                    assert "recommended_actions" in data
                    assert "detector" in data
                    assert "threat_intelligence" in data

                    ti = data["threat_intelligence"]

                    # 2. Legacy backwards-compatible fields
                    legacy_fields = [
                        "provider", "status", "indicator", "indicator_type",
                        "summary", "engine_results", "categories", "timeline",
                        "technical_details", "permalink", "cyberguard_local",
                        "correlated_assessment", "recommended_actions"
                    ]
                    for field in legacy_fields:
                        assert field in ti, f"Missing legacy field: {field}"

                    # 3. New multi-provider fields
                    new_fields = ["providers", "correlation", "urlhaus", "performance", "analysis_id"]
                    for field in new_fields:
                        assert field in ti, f"Missing new multi-provider field: {field}"

                    # 4. Providers sub-structure
                    assert "virustotal" in ti["providers"]
                    assert "urlhaus" in ti["providers"]

                    # 5. Correlation sub-structure
                    assert "status" in ti["correlation"]
                    assert "agreement" in ti["correlation"]
                    assert "conflicts" in ti["correlation"]
                    assert "corroborating_evidence" in ti["correlation"]
                    assert "provider_gaps" in ti["correlation"]


@pytest.mark.asyncio
async def test_pipeline_status_endpoint():
    """Verify that GET /api/threats/pipeline/status returns health for both providers."""
    client = TestClient(app)
    mock_vt = {"provider": "VirusTotal", "status": "READY", "configured": True, "enabled": True}
    mock_uh = {"provider": "URLhaus", "status": "READY", "configured": True, "enabled": True}

    with patch("backend.threats.virustotal.VirusTotalProvider.check_status", AsyncMock(return_value=mock_vt)):
        with patch("backend.threats.urlhaus.URLhausProvider.check_status", AsyncMock(return_value=mock_uh)):
            resp = client.get("/api/threats/pipeline/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "READY"
            assert data["pipeline_active"] is True
            assert data["virustotal"]["status"] == "READY"
            assert data["urlhaus"]["status"] == "READY"


@pytest.mark.asyncio
async def test_config_status_includes_threat_intel_pipeline():
    """Verify that GET /api/config/status includes live provider and pipeline health."""
    client = TestClient(app)
    mock_vt = {"provider": "VirusTotal", "status": "READY"}
    mock_uh = {"provider": "URLhaus", "status": "READY"}

    with patch("backend.threats.virustotal.VirusTotalProvider.check_status", AsyncMock(return_value=mock_vt)):
        with patch("backend.threats.urlhaus.URLhausProvider.check_status", AsyncMock(return_value=mock_uh)):
            resp = client.get("/api/config/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["virustotal_status"] == "READY"
            assert data["urlhaus_status"] == "READY"
            assert data["threat_intel_active"] is True


