"""
test_urlhaus.py — URLhausProvider unit tests.

Tests provider initialization, configuration states, status check responses,
IOC-type routing, and normalization logic.
All live network calls are mocked via unittest.mock.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from backend.config import Settings, URLhausConfig
from backend.threats.urlhaus import URLhausProvider, get_urlhaus_provider


def make_uh_settings(enabled: bool = True, auth_key: str = "test-urlhaus-auth-key-abc123"):
    settings = Settings()
    settings.urlhaus = URLhausConfig(
        enabled=enabled,
        timeout_sec=5,
        cache_enabled=True,
        auth_key=auth_key,
    )
    return settings


def make_provider(enabled: bool = True, auth_key: str = "test-urlhaus-auth-key-abc123"):
    URLhausProvider._cached_status = None
    URLhausProvider._status_cache_time = 0.0
    settings = make_uh_settings(enabled=enabled, auth_key=auth_key)
    return URLhausProvider(settings)


# ── is_configured ──────────────────────────────────────────────────────────────

def test_is_configured_with_key():
    p = make_provider(enabled=True, auth_key="somekey")
    assert p.is_configured is True


def test_is_configured_without_key():
    p = make_provider(enabled=True, auth_key="")
    assert p.is_configured is False


def test_is_configured_disabled():
    p = make_provider(enabled=False, auth_key="somekey")
    assert p.is_configured is False


# ── check_status ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_status_not_configured_when_disabled():
    p = make_provider(enabled=False, auth_key="somekey")
    status = await p.check_status(force_refresh=True)
    assert status["status"] == "NOT_CONFIGURED"
    assert status["enabled"] is False


@pytest.mark.asyncio
async def test_status_not_configured_when_key_empty():
    p = make_provider(enabled=True, auth_key="")
    status = await p.check_status(force_refresh=True)
    assert status["status"] == "NOT_CONFIGURED"
    assert "URLHAUS_AUTH_KEY" in status["message"]


@pytest.mark.asyncio
async def test_status_ready_when_ok():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "ok", "urls": []}

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)):
        status = await p.check_status(force_refresh=True)
        assert status["status"] == "READY"
        assert status["configured"] is True


@pytest.mark.asyncio
async def test_status_authentication_failed():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)):
        status = await p.check_status(force_refresh=True)
        assert status["status"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_status_rate_limited():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=mock_resp)):
        status = await p.check_status(force_refresh=True)
        assert status["status"] == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_status_timeout():
    p = make_provider()
    with patch.object(httpx.AsyncClient, "get", AsyncMock(side_effect=httpx.TimeoutException("Timeout"))):
        status = await p.check_status(force_refresh=True)
        assert status["status"] == "TIMEOUT"


@pytest.mark.asyncio
async def test_status_unavailable_on_network_error():
    p = make_provider()
    with patch.object(httpx.AsyncClient, "get", AsyncMock(side_effect=httpx.ConnectError("refused"))):
        status = await p.check_status(force_refresh=True)
        assert status["status"] == "UNAVAILABLE"


@pytest.mark.asyncio
async def test_status_cached():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "ok"}

    mock_get = AsyncMock(return_value=mock_resp)
    with patch.object(httpx.AsyncClient, "get", mock_get):
        s1 = await p.check_status(force_refresh=True)
        assert s1["status"] == "READY"
        assert mock_get.call_count == 1

        # Second call without force_refresh uses cached result
        s2 = await p.check_status(force_refresh=False)
        assert s2["status"] == "READY"
        assert mock_get.call_count == 1  # No additional network call


# ── IOC Type Routing ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lookup_url_calls_url_endpoint():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "is_listed", "url_status": "online", "threat": "malware_download"}
    mock_resp.raise_for_status = MagicMock()

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)) as mock_post:
        result = await p.lookup_url("https://evil.example.com/malware.exe")
        # Must have called /url/ endpoint
        call_url = mock_post.call_args[0][0]
        assert "/url/" in call_url
        assert result["indicator"] == "https://evil.example.com/malware.exe"
        assert result["indicator_type"] == "url"
        assert result["matched"] is True
        assert result["status"] == "COMPLETED"
        assert result["match_scope"] == "EXACT_URL"


@pytest.mark.asyncio
async def test_lookup_host_domain_calls_host_endpoint():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "is_listed",
        "urls": [{"url": "http://evil.com/pay.exe", "url_status": "online", "date_added": "2024-01-01", "threat": "malware_download"}]
    }
    mock_resp.raise_for_status = MagicMock()

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)) as mock_post:
        result = await p.lookup_host("evil.com", indicator_type="domain")
        call_url = mock_post.call_args[0][0]
        assert "/host/" in call_url
        assert result["indicator_type"] == "domain"
        assert result["matched"] is True
        assert result["match_scope"] == "HOST_LEVEL"
        assert result["classification"] == "host_with_malware_urls"


@pytest.mark.asyncio
async def test_lookup_host_ip_calls_host_endpoint():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "is_listed", "urls": []}
    mock_resp.raise_for_status = MagicMock()

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)) as mock_post:
        result = await p.lookup_host("192.168.1.100", indicator_type="ip")
        call_url = mock_post.call_args[0][0]
        assert "/host/" in call_url
        assert result["indicator_type"] == "ip"


@pytest.mark.asyncio
async def test_lookup_payload_sha256_calls_payload_endpoint():
    p = make_provider()
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "ok", "md5_hash": "abc", "sha256_hash": sha256, "urls": []}
    mock_resp.raise_for_status = MagicMock()

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)) as mock_post:
        result = await p.lookup_payload_sha256(sha256)
        call_url = mock_post.call_args[0][0]
        assert "/payload/" in call_url
        assert result["indicator_type"] == "hash_sha256"
        assert result["matched"] is True
        assert result["match_scope"] == "EXACT_HASH"


@pytest.mark.asyncio
async def test_lookup_payload_md5_calls_payload_endpoint():
    p = make_provider()
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "ok", "md5_hash": md5, "urls": []}
    mock_resp.raise_for_status = MagicMock()

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)) as mock_post:
        result = await p.lookup_payload_md5(md5)
        call_url = mock_post.call_args[0][0]
        assert "/payload/" in call_url
        assert result["indicator_type"] == "hash_md5"


def test_sha1_returns_not_applicable():
    """URLhaus has no SHA-1 payload lookup — must return NOT_APPLICABLE without any network call."""
    p = make_provider()
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    result = p.lookup_sha1_not_applicable(sha1)
    assert result["status"] == "NOT_APPLICABLE"
    assert result["matched"] is False
    assert result["indicator_type"] == "hash_sha1"
    assert result["match_scope"] == "NOT_APPLICABLE"
    # Verify the limitation message explains WHY
    lim = " ".join(result.get("limitations", []))
    assert "SHA-1" in lim or "sha1" in lim.lower() or "SHA256" in lim or "MD5" in lim


# ── No-match normalization ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_url_no_match():
    p = make_provider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "no_results"}
    mock_resp.raise_for_status = MagicMock()

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)):
        result = await p.lookup_url("https://safe.example.com")
        assert result["status"] == "NO_MATCH"
        assert result["matched"] is False
        assert result["match_scope"] == "EXACT_URL"
        # Limitations should explain this doesn't confirm safety
        lim_text = " ".join(result.get("limitations", []))
        assert "NOT" in lim_text.upper() or "does not" in lim_text.lower()


@pytest.mark.asyncio
async def test_not_configured_returns_structured_result():
    """Provider that is not configured must return a structured NOT_CONFIGURED result (not raise)."""
    p = make_provider(enabled=True, auth_key="")
    result = await p.lookup_url("https://example.com")
    assert result["status"] == "NOT_CONFIGURED"
    assert result["matched"] is False
    assert result["indicator"] == "https://example.com"


# ── Singleton factory ──────────────────────────────────────────────────────────

def test_singleton_returns_same_instance():
    """get_urlhaus_provider() returns the same singleton when called multiple times."""
    import backend.threats.urlhaus as uh_module
    uh_module._provider_singleton = None
    settings = make_uh_settings()
    p1 = get_urlhaus_provider(settings)
    p2 = get_urlhaus_provider()
    assert p1 is p2
