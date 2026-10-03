import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from backend.config import Settings, VirusTotalConfig
from backend.threats.virustotal import VirusTotalProvider
from backend.analysis.url_analyzer import URLAnalyzer
from backend.threats.models import RiskLevel, ThreatCategory


def create_test_settings(enabled: bool = True, api_key: str = "valid_mock_key_64_characters_long_0123456789abcdef0123456789abcdef01") -> Settings:
    settings = Settings()
    settings.virustotal = VirusTotalConfig(
        enabled=enabled,
        timeout_sec=5,
        poll_interval_sec=5,
        max_file_size_bytes=33554432,
        cache_enabled=True,
        api_key=api_key
    )
    return settings


@pytest.mark.asyncio
async def test_vt_status_not_configured_when_disabled():
    settings = create_test_settings(enabled=False, api_key="some_key")
    provider = VirusTotalProvider(settings)
    assert not provider.is_configured

    status = await provider.check_status(force_refresh=True)
    assert status["status"] == "NOT_CONFIGURED"
    assert status["configured"] is False
    assert status["enabled"] is False


@pytest.mark.asyncio
async def test_vt_status_not_configured_when_key_empty():
    settings = create_test_settings(enabled=True, api_key="")
    provider = VirusTotalProvider(settings)
    assert not provider.is_configured

    status = await provider.check_status(force_refresh=True)
    assert status["status"] == "NOT_CONFIGURED"
    assert status["configured"] is False
    assert "VIRUSTOTAL_API_KEY is missing" in status["message"]


@pytest.mark.asyncio
async def test_vt_status_ready_mocked():
    settings = create_test_settings(enabled=True, api_key="mock_key")
    provider = VirusTotalProvider(settings)
    assert provider.is_configured

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"id": "test_user"}}

    with patch.object(httpx.AsyncClient, "request", AsyncMock(return_value=mock_resp)):
        status = await provider.check_status(force_refresh=True)
        assert status["status"] == "READY"
        assert status["configured"] is True


@pytest.mark.asyncio
async def test_vt_status_authentication_failed_mocked():
    settings = create_test_settings(enabled=True, api_key="invalid_key")
    provider = VirusTotalProvider(settings)

    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch.object(httpx.AsyncClient, "request", AsyncMock(return_value=mock_resp)):
        status = await provider.check_status(force_refresh=True)
        assert status["status"] == "AUTHENTICATION_FAILED"
        assert "authentication failed" in status["message"].lower()


@pytest.mark.asyncio
async def test_vt_status_forbidden_mocked():
    settings = create_test_settings(enabled=True, api_key="forbidden_key")
    provider = VirusTotalProvider(settings)

    mock_resp = MagicMock()
    mock_resp.status_code = 403

    with patch.object(httpx.AsyncClient, "request", AsyncMock(return_value=mock_resp)):
        status = await provider.check_status(force_refresh=True)
        assert status["status"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_vt_status_rate_limited_mocked():
    settings = create_test_settings(enabled=True, api_key="rate_limited_key")
    provider = VirusTotalProvider(settings)

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch.object(httpx.AsyncClient, "request", AsyncMock(return_value=mock_resp)):
        status = await provider.check_status(force_refresh=True)
        assert status["status"] == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_vt_status_unavailable_mocked():
    settings = create_test_settings(enabled=True, api_key="mock_key")
    provider = VirusTotalProvider(settings)

    with patch.object(httpx.AsyncClient, "request", AsyncMock(side_effect=httpx.ConnectError("Connection refused"))):
        status = await provider.check_status(force_refresh=True)
        assert status["status"] == "UNAVAILABLE"


@pytest.mark.asyncio
async def test_vt_cached_status_preserves_quota():
    settings = create_test_settings(enabled=True, api_key="mock_key")
    provider = VirusTotalProvider(settings)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"id": "test_user"}}

    mock_request = AsyncMock(return_value=mock_resp)
    with patch.object(httpx.AsyncClient, "request", mock_request):
        status1 = await provider.check_status(force_refresh=True)
        assert status1["status"] == "READY"
        assert mock_request.call_count == 1

        # Second call without force_refresh uses cache
        status2 = await provider.check_status(force_refresh=False)
        assert status2["status"] == "READY"
        assert mock_request.call_count == 1


@pytest.mark.asyncio
async def test_local_url_analysis_fallback_when_vt_disabled():
    """Verify local heuristic analysis continues working even when VirusTotal is not configured."""
    settings = create_test_settings(enabled=False, api_key="")
    analyzer = URLAnalyzer(settings)

    # Safe URL
    event_safe = await analyzer.analyze("https://www.google.com/search?q=test")
    assert event_safe.severity == RiskLevel.SAFE

    # Suspicious IP URL
    event_sus = await analyzer.analyze("http://192.168.1.100/login/secure/verify")
    assert event_sus.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert event_sus.threat_category == ThreatCategory.MALICIOUS_URL
