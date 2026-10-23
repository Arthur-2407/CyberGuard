import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from backend.config import Settings, VirusTotalConfig, URLhausConfig
from backend.threats.enclave import (
    ThreatIntelEnclave,
    threat_enclave_context,
    async_threat_enclave_context,
    PHISHING_AND_URL_SCOPE,
)
from backend.threats.virustotal import VirusTotalProvider
from backend.threats.urlhaus import URLhausProvider
from backend.analysis.unified_pipeline import UnifiedThreatPipeline
from fastapi.testclient import TestClient
from backend.main import app


@pytest.fixture(autouse=True)
def reset_enclave_state():
    enclave = ThreatIntelEnclave.get_instance()
    enclave.reset_metrics()
    VirusTotalProvider.clear_report_cache()
    URLhausProvider.clear_report_cache()
    yield
    enclave.reset_metrics()
    VirusTotalProvider.clear_report_cache()
    URLhausProvider.clear_report_cache()


def create_test_settings():
    settings = Settings()
    settings.virustotal = VirusTotalConfig(
        enabled=True,
        timeout_sec=5,
        cache_enabled=True,
        cache_ttl_sec=3600.0,
        isolated_enclave_only=True,
        api_key="valid_test_api_key_64_characters_mocked_for_unit_tests_0123456789a",
    )
    settings.urlhaus = URLhausConfig(
        enabled=True,
        timeout_sec=5,
        cache_enabled=True,
        cache_ttl_sec=3600.0,
        isolated_enclave_only=True,
        auth_key="valid_urlhaus_test_auth_key",
    )
    return settings


@pytest.mark.asyncio
async def test_virustotal_isolated_when_outside_phishing_tab():
    """Verify that calling VirusTotal from outside the Phishing & URL tab is blocked to save tokens."""
    settings = create_test_settings()
    provider = VirusTotalProvider(settings)

    # Explicitly set an unauthorized context (e.g. voice_analysis or overview)
    with threat_enclave_context("voice_analysis"):
        res = await provider.get_url_report("https://malicious-test.example/phish")
        assert res.get("status") == "ISOLATED_ENCLAVE_RESTRICTED"
        assert res.get("enclave_isolated") is True
        assert "Phishing & URL tab" in res.get("message")

    enclave = ThreatIntelEnclave.get_instance()
    metrics = enclave.get_metrics()
    assert metrics["enclave_blocks"] >= 1
    assert metrics["tokens_saved"] >= 1


@pytest.mark.asyncio
async def test_urlhaus_isolated_when_outside_phishing_tab():
    """Verify that calling URLhaus from outside the Phishing & URL tab is blocked to save tokens."""
    settings = create_test_settings()
    provider = URLhausProvider(settings)

    with threat_enclave_context("training_review"):
        res = await provider.lookup_url("https://malware-drop.example/payload.exe")
        assert res.get("status") == "ISOLATED_ENCLAVE_RESTRICTED"
        assert res.get("enclave_isolated") is True
        assert "Phishing & URL tab" in res.get("message")

    enclave = ThreatIntelEnclave.get_instance()
    metrics = enclave.get_metrics()
    assert metrics["enclave_blocks"] >= 1
    assert metrics["tokens_saved"] >= 1


@pytest.mark.asyncio
async def test_virustotal_report_caching_conserves_tokens():
    """Verify that repeat queries for the same indicator return from cache with zero API tokens consumed."""
    settings = create_test_settings()
    provider = VirusTotalProvider(settings)

    mock_resp = {
        "status": "SUCCESS",
        "data": {
            "id": "mock_id",
            "attributes": {
                "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 40},
                "last_analysis_results": {},
            }
        }
    }

    with threat_enclave_context(PHISHING_AND_URL_SCOPE):
        with patch.object(provider, "_make_request", AsyncMock(return_value=mock_resp)) as mock_make:
            # 1. First lookup — cache miss, dispatches API request
            res1 = await provider.get_url_report("https://repeat-threat.com/login")
            assert res1.get("status") == "COMPLETED"
            assert res1.get("malicious_count") == 12
            assert res1.get("cached") is not True
            assert mock_make.call_count == 1

            # 2. Second lookup — cache HIT, zero external calls made
            res2 = await provider.get_url_report("https://repeat-threat.com/login")
            assert res2.get("status") == "COMPLETED"
            assert res2.get("cached") is True
            assert res2.get("tokens_saved") == 1
            # Call count remains 1!
            assert mock_make.call_count == 1

            # 3. Third lookup with different casing — still cache HIT!
            res3 = await provider.get_url_report("HTTPS://REPEAT-THREAT.COM/LOGIN")
            assert res3.get("status") == "COMPLETED"
            assert res3.get("cached") is True
            assert mock_make.call_count == 1

    enclave = ThreatIntelEnclave.get_instance()
    metrics = enclave.get_metrics()
    assert metrics["cache_hits"] >= 2
    assert metrics["tokens_saved"] >= 2


@pytest.mark.asyncio
async def test_urlhaus_report_caching_conserves_tokens():
    """Verify URLhaus report caching prevents redundant token usage for URLs and hosts."""
    settings = create_test_settings()
    provider = URLhausProvider(settings)

    mock_raw = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "date_added": "2026-10-18 00:00:00 UTC",
    }

    with threat_enclave_context(PHISHING_AND_URL_SCOPE):
        with patch.object(provider, "_post", AsyncMock(return_value=mock_raw)) as mock_post:
            res1 = await provider.lookup_url("http://known-malware.org/bad.exe")
            assert res1.get("status") == "COMPLETED"
            assert res1.get("cached") is not True
            assert mock_post.call_count == 1

            res2 = await provider.lookup_url("http://known-malware.org/bad.exe")
            assert res2.get("status") == "COMPLETED"
            assert res2.get("cached") is True
            assert mock_post.call_count == 1


@pytest.mark.asyncio
async def test_request_deduplication_coalesces_concurrent_requests():
    """Verify that simultaneous requests for the same indicator are coalesced into 1 API call."""
    settings = create_test_settings()
    provider = VirusTotalProvider(settings)

    mock_resp = {
        "status": "SUCCESS",
        "data": {
            "id": "mock_coalesce",
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 50},
                "last_analysis_results": {},
            }
        }
    }

    async def slow_make_request(*args, **kwargs):
        await asyncio.sleep(0.05)
        return mock_resp

    with threat_enclave_context(PHISHING_AND_URL_SCOPE):
        with patch.object(provider, "_make_request", side_effect=slow_make_request) as mock_make:
            # Fire 3 concurrent lookups for the identical target
            t1 = asyncio.create_task(provider.get_url_report("https://concurrent-target.org/"))
            t2 = asyncio.create_task(provider.get_url_report("https://concurrent-target.org/"))
            t3 = asyncio.create_task(provider.get_url_report("https://concurrent-target.org/"))

            r1, r2, r3 = await asyncio.gather(t1, t2, t3)
            assert r1.get("status") == "COMPLETED"
            assert r2.get("status") == "COMPLETED"
            assert r3.get("status") == "COMPLETED"
            # Exactly 1 outbound network call was made!
            assert mock_make.call_count == 1

    enclave = ThreatIntelEnclave.get_instance()
    metrics = enclave.get_metrics()
    assert metrics["dedup_hits"] >= 1 or metrics["cache_hits"] >= 1


def test_api_threats_enclave_metrics_endpoint():
    """Verify that the FastAPI router scopes /api/threats to the enclave and provides metrics."""
    client = TestClient(app)
    resp = client.get("/api/threats/enclave/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["isolated_enclave"] is True
    assert "tokens_saved" in data
    assert "cache_hits" in data
    assert "total_requests" in data


def test_pipeline_status_includes_enclave_telemetry():
    """Verify that /api/threats/pipeline/status includes enclave token savings information."""
    client = TestClient(app)
    resp = client.get("/api/threats/pipeline/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "enclave" in data
    assert data["enclave"]["isolated_enclave"] is True
    assert data["enclave"]["target_workspace"] == "Phishing & URL Workspace"


@pytest.mark.asyncio
async def test_unified_pipeline_file_hash_skipped_outside_phishing():
    """Verify that uploading general files to unified pipeline skips VT hash check when not in Phishing tab."""
    settings = create_test_settings()
    pipeline = UnifiedThreatPipeline(settings)

    # Calling with source="audio_file" outside phishing tab
    with threat_enclave_context("voice_analysis"):
        with patch.object(VirusTotalProvider, "get_file_report", AsyncMock()) as mock_vt_file:
            res = await pipeline.analyze(
                file_bytes=b"fake_audio_bytes_header_test",
                filename="speech_sample.wav",
                source="voice_analysis"
            )
            # Must NOT call VT get_file_report!
            assert mock_vt_file.call_count == 0

    enclave = ThreatIntelEnclave.get_instance()
    assert enclave.get_metrics()["enclave_blocks"] >= 1


def test_header_scope_enforces_enclave_boundary():
    """Verify that passing an unauthorized scope via X-Threat-Scope header blocks provider lookup."""
    client = TestClient(app)
    # When X-Threat-Scope indicates an unauthorized scope, external queries are restricted to save tokens
    resp = client.get("/api/threats/search?ioc=8.8.8.8", headers={"X-Threat-Scope": "voice_analysis"})
    assert resp.status_code == 200
    data = resp.json()
    threat_intel = data.get("threat_intelligence") or {}
    providers = threat_intel.get("providers") or {}
    vt = providers.get("virustotal") or {}
    uh = providers.get("urlhaus") or {}
    assert vt.get("status") == "ISOLATED_ENCLAVE_RESTRICTED"
    assert uh.get("status") == "ISOLATED_ENCLAVE_RESTRICTED"


