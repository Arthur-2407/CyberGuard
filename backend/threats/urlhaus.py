"""
urlhaus.py — URLhaus Community API Provider for CyberGuard.

URLhaus (by abuse.ch) is a malware-distribution URL intelligence platform.
This provider implements the correct documented API operations for each IOC type:

  URL       → POST /v1/url/              (exact URL lookup)
  Domain/IP → POST /v1/host/            (host-level intelligence)
  SHA-256   → POST /v1/payload/         (sha256_hash= parameter)
  MD5       → POST /v1/payload/         (md5_hash= parameter)
  SHA-1     → NOT_APPLICABLE            (URLhaus has no SHA-1 payload lookup)

Auth: HTTP header "Auth-Key: <key>" — key is loaded from URLHAUS_AUTH_KEY env var.
No keys are ever logged, returned in API responses, or stored in source.

URLhaus focuses on malware-distribution URLs. A NO_MATCH result does NOT mean
the IOC is safe — it means URLhaus has no matching record for that indicator.
"""

import httpx
import logging
import time
from typing import Dict, Any, Optional, List

from backend.config import get_settings

logger = logging.getLogger(__name__)

# URLhaus base URL for Community API v1
_URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausError(Exception):
    pass


class URLhausProvider:
    """
    Provider for URLhaus Community API.

    Implements the sequential second-stage intelligence lookup after VirusTotal.
    Each IOC type is routed to the correct documented URLhaus operation.
    Provider-specific results are normalized into a common schema before
    being passed to the correlation engine — VirusTotal never sees URLhaus
    raw fields and vice versa.
    """

    _cached_status: Optional[Dict[str, Any]] = None
    _status_cache_time: float = 0.0
    _CACHE_TTL_SEC: float = 300.0

    def __init__(self, config=None):
        self.config = config or get_settings()
        self.uh_config = self.config.urlhaus
        # Auth-Key sourced from config (which reads env) — never from source code
        self._auth_key = self.uh_config.auth_key
        self.timeout = self.uh_config.timeout_sec

    @property
    def is_configured(self) -> bool:
        """True only if URLhaus is enabled AND an auth key is present."""
        return self.uh_config.enabled and bool(self._auth_key)

    def _get_headers(self) -> Dict[str, str]:
        """Build auth headers. Auth-Key is never logged."""
        return {
            "Auth-Key": self._auth_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

    async def check_status(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Verify URLhaus API credentials and connectivity.
        Uses /v1/urls/recent/?limit=1 as a lightweight probe (GET with Auth-Key).
        Results are cached for CACHE_TTL_SEC to avoid quota waste.
        """
        if not self.uh_config.enabled:
            return {
                "provider": "URLhaus",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "enabled": False,
                "message": "URLhaus integration is disabled in configuration.",
            }

        if not bool(self._auth_key):
            return {
                "provider": "URLhaus",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "enabled": True,
                "message": "URLhaus Auth-Key is missing. Set URLHAUS_AUTH_KEY in environment.",
            }

        now = time.time()
        cached = URLhausProvider._cached_status
        cached_st = cached.get("status") if cached else None
        # Cache healthy/permanent auth failures for CACHE_TTL_SEC; transient/timeout errors cooldown for 30s
        ttl = URLhausProvider._CACHE_TTL_SEC if cached_st in ("READY", "AUTHENTICATION_FAILED") else 30.0
        if (
            not force_refresh
            and cached
            and (now - URLhausProvider._status_cache_time < ttl)
        ):
            return dict(cached)

        # Probe with a minimal recent URLs request (Auth-Key validated here, bounded probe timeout)
        try:
            async with httpx.AsyncClient(timeout=min(self.timeout, 4.0)) as client:
                resp = await client.get(
                    f"{_URLHAUS_BASE}/urls/recent/limit/1/",
                    headers=self._get_headers(),
                )

                if resp.status_code == 401 or resp.status_code == 403:
                    status_obj = {
                        "provider": "URLhaus",
                        "status": "AUTHENTICATION_FAILED",
                        "configured": True,
                        "enabled": True,
                        "message": "URLhaus authentication failed. Configured Auth-Key was rejected.",
                    }
                elif resp.status_code == 429:
                    status_obj = {
                        "provider": "URLhaus",
                        "status": "RATE_LIMITED",
                        "configured": True,
                        "enabled": True,
                        "message": "URLhaus API rate limit reached.",
                    }
                elif resp.status_code >= 500:
                    status_obj = {
                        "provider": "URLhaus",
                        "status": "UNAVAILABLE",
                        "configured": True,
                        "enabled": True,
                        "message": "URLhaus service returned a server error.",
                    }
                else:
                    data = resp.json()
                    qs = data.get("query_status", "")
                    if qs in ("ok", "no_results"):
                        status_obj = {
                            "provider": "URLhaus",
                            "status": "READY",
                            "configured": True,
                            "enabled": True,
                            "message": "URLhaus malware-URL intelligence is operational.",
                        }
                    else:
                        status_obj = {
                            "provider": "URLhaus",
                            "status": "DEGRADED",
                            "configured": True,
                            "enabled": True,
                            "message": f"URLhaus returned unexpected status: {qs}",
                        }

        except httpx.TimeoutException:
            logger.warning("provider=urlhaus status=TIMEOUT reason=status_check_timeout")
            status_obj = {
                "provider": "URLhaus",
                "status": "TIMEOUT",
                "configured": True,
                "enabled": True,
                "message": "URLhaus status check timed out.",
            }
        except httpx.RequestError as e:
            logger.warning(f"provider=urlhaus status=UNAVAILABLE reason=NETWORK_ERROR error={e}")
            status_obj = {
                "provider": "URLhaus",
                "status": "UNAVAILABLE",
                "configured": True,
                "enabled": True,
                "message": "URLhaus external service could not be reached.",
            }
        except Exception as e:
            logger.error(f"provider=urlhaus status=ERROR error={e}")
            status_obj = {
                "provider": "URLhaus",
                "status": "ERROR",
                "configured": True,
                "enabled": True,
                "message": f"Unexpected error during URLhaus status check.",
            }

        URLhausProvider._cached_status = status_obj
        URLhausProvider._status_cache_time = time.time()
        return dict(status_obj)

    def _not_applicable_result(self, indicator: str, indicator_type: str, reason: str) -> Dict[str, Any]:
        """Return a normalized NOT_APPLICABLE result for unsupported IOC types."""
        return {
            "provider": "URLhaus",
            "status": "NOT_APPLICABLE",
            "indicator": indicator,
            "indicator_type": indicator_type,
            "matched": False,
            "classification": None,
            "url_status": None,
            "threat": None,
            "date_added": None,
            "last_seen_online": None,
            "host": None,
            "tags": [],
            "payloads": [],
            "blacklists": {},
            "urls_for_host": [],
            "evidence": [],
            "external_reference": None,
            "match_scope": "NOT_APPLICABLE",
            "limitations": [reason],
            "error": None,
        }

    def _not_configured_result(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Return a normalized NOT_CONFIGURED result."""
        return {
            "provider": "URLhaus",
            "status": "NOT_CONFIGURED",
            "indicator": indicator,
            "indicator_type": indicator_type,
            "matched": False,
            "classification": None,
            "url_status": None,
            "threat": None,
            "date_added": None,
            "last_seen_online": None,
            "host": None,
            "tags": [],
            "payloads": [],
            "blacklists": {},
            "urls_for_host": [],
            "evidence": [],
            "external_reference": None,
            "match_scope": "NOT_APPLICABLE",
            "limitations": ["URLhaus Auth-Key not configured. Set URLHAUS_AUTH_KEY in environment."],
            "error": None,
        }

    async def _post(self, endpoint: str, form_data: Dict[str, str]) -> Dict[str, Any]:
        """
        Execute an authenticated POST request to the URLhaus API.
        Returns a dict containing either the JSON response (with status=SUCCESS)
        or an error/status dict. Auth headers are never logged.
        """
        url = f"{_URLHAUS_BASE}{endpoint}"
        headers = self._get_headers()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, data=form_data, headers=headers)

                if resp.status_code in (401, 403):
                    logger.error(
                        f"provider=urlhaus status=AUTHENTICATION_FAILED http_status={resp.status_code}"
                    )
                    URLhausProvider._cached_status = {
                        "provider": "URLhaus",
                        "status": "AUTHENTICATION_FAILED",
                        "configured": True,
                        "enabled": True,
                        "message": "URLhaus authentication failed.",
                    }
                    URLhausProvider._status_cache_time = time.time()
                    return {"_internal_status": "AUTHENTICATION_FAILED"}

                if resp.status_code == 429:
                    logger.warning("provider=urlhaus status=RATE_LIMITED http_status=429")
                    return {"_internal_status": "RATE_LIMITED"}

                if resp.status_code >= 500:
                    logger.error(f"provider=urlhaus status=UNAVAILABLE http_status={resp.status_code}")
                    return {"_internal_status": "UNAVAILABLE"}

                resp.raise_for_status()
                data = resp.json()
                data["_internal_status"] = "SUCCESS"
                return data

        except httpx.TimeoutException:
            logger.warning("provider=urlhaus status=TIMEOUT reason=request_timeout")
            return {"_internal_status": "TIMEOUT"}
        except httpx.RequestError as e:
            logger.warning(f"provider=urlhaus status=UNAVAILABLE reason=NETWORK_ERROR error={e}")
            return {"_internal_status": "UNAVAILABLE"}
        except Exception as e:
            logger.error(f"provider=urlhaus status=ERROR error={e}")
            return {"_internal_status": "ERROR"}

    def _normalize_url_result(
        self, raw: Dict[str, Any], url: str
    ) -> Dict[str, Any]:
        """
        Normalize a /v1/url/ response into the canonical URLhaus provider result.
        query_status values: is_listed / no_results / http_post_expected / ...
        """
        int_status = raw.get("_internal_status", "SUCCESS")
        if int_status != "SUCCESS":
            return self._error_result(url, "url", int_status)

        qs = raw.get("query_status", "")

        if qs == "no_results":
            return {
                "provider": "URLhaus",
                "status": "NO_MATCH",
                "indicator": url,
                "indicator_type": "url",
                "matched": False,
                "classification": None,
                "url_status": None,
                "threat": None,
                "date_added": None,
                "last_seen_online": None,
                "host": None,
                "tags": [],
                "payloads": [],
                "blacklists": {},
                "urls_for_host": [],
                "evidence": [],
                "external_reference": None,
                "match_scope": "EXACT_URL",
                "limitations": [
                    "URLhaus returned no matching record for this URL. "
                    "This does NOT confirm the URL is safe — URLhaus focuses specifically on "
                    "malware-distribution URLs and may not have indexed this indicator."
                ],
                "error": None,
            }

        if qs not in ("is_listed", "ok"):
            return self._error_result(url, "url", f"UNEXPECTED_STATUS:{qs}")

        # Build normalized evidence list
        payloads_raw = raw.get("payloads") or []
        payloads_normalized = []
        for p in payloads_raw:
            if isinstance(p, dict):
                payloads_normalized.append({
                    "file_type": p.get("file_type"),
                    "filename": p.get("filename"),
                    "signature": p.get("signature"),
                    "md5_hash": p.get("md5_hash"),
                    "sha256_hash": p.get("sha256_hash"),
                    "first_seen": p.get("firstseen"),
                    "last_seen": p.get("lastseen"),
                })

        evidence = [
            {
                "source": "URLhaus",
                "evidence_type": "malware_distribution_url",
                "indicator": url,
                "scope": "EXACT_URL",
                "description": (
                    f"URLhaus confirms this URL is a known malware-distribution site. "
                    f"Threat: {raw.get('threat', 'malware_download')}. "
                    f"URL status: {raw.get('url_status', 'unknown')}."
                ),
                "actual_value": raw.get("url", url),
                "timestamp": raw.get("date_added"),
                "relevance": "DIRECT_MATCH",
            }
        ]

        blacklists = raw.get("blacklists") or {}
        if isinstance(blacklists, dict) and any(
            v not in ("not listed", None, "") for v in blacklists.values()
        ):
            evidence.append({
                "source": "URLhaus",
                "evidence_type": "blacklist_membership",
                "indicator": url,
                "scope": "EXACT_URL",
                "description": f"URLhaus blacklist data: {blacklists}",
                "actual_value": str(blacklists),
                "timestamp": raw.get("date_added"),
                "relevance": "SUPPORTING",
            })

        return {
            "provider": "URLhaus",
            "status": "COMPLETED",
            "indicator": url,
            "indicator_type": "url",
            "matched": True,
            "classification": "malware_distribution_url",
            "url_status": raw.get("url_status"),
            "threat": raw.get("threat"),
            "date_added": raw.get("date_added"),
            "last_seen_online": raw.get("last_online"),
            "host": raw.get("host"),
            "tags": raw.get("tags") or [],
            "payloads": payloads_normalized,
            "blacklists": blacklists if isinstance(blacklists, dict) else {},
            "urls_for_host": [],
            "evidence": evidence,
            "external_reference": raw.get("urlhaus_reference"),
            "match_scope": "EXACT_URL",
            "limitations": [
                "URLhaus focuses on malware-distribution URLs. "
                "A match indicates historical or active malware activity, "
                "not necessarily a phishing threat."
            ],
            "error": None,
        }

    def _normalize_host_result(
        self, raw: Dict[str, Any], host: str, indicator_type: str
    ) -> Dict[str, Any]:
        """
        Normalize a /v1/host/ response into the canonical URLhaus provider result.
        indicator_type is "domain" or "ip".
        """
        int_status = raw.get("_internal_status", "SUCCESS")
        if int_status != "SUCCESS":
            return self._error_result(host, indicator_type, int_status)

        qs = raw.get("query_status", "")

        if qs in ("no_results", "is_not_listed"):
            return {
                "provider": "URLhaus",
                "status": "NO_MATCH",
                "indicator": host,
                "indicator_type": indicator_type,
                "matched": False,
                "classification": None,
                "url_status": None,
                "threat": None,
                "date_added": None,
                "last_seen_online": None,
                "host": host,
                "tags": [],
                "payloads": [],
                "blacklists": {},
                "urls_for_host": [],
                "evidence": [],
                "external_reference": None,
                "match_scope": "HOST_LEVEL",
                "limitations": [
                    f"URLhaus returned no matching record for host '{host}'. "
                    "This does NOT confirm the host is safe."
                ],
                "error": None,
            }

        if qs not in ("is_listed", "ok"):
            return self._error_result(host, indicator_type, f"UNEXPECTED_STATUS:{qs}")

        urls_raw = raw.get("urls") or []
        urls_for_host = []
        for u in urls_raw:
            if isinstance(u, dict):
                urls_for_host.append({
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "date_added": u.get("date_added"),
                    "threat": u.get("threat"),
                    "urlhaus_reference": u.get("urlhaus_reference"),
                })

        active_urls = [u for u in urls_for_host if u.get("url_status") == "online"]

        evidence = [
            {
                "source": "URLhaus",
                "evidence_type": "host_with_malware_urls",
                "indicator": host,
                "scope": "HOST_LEVEL",
                "description": (
                    f"URLhaus associates host '{host}' with {len(urls_for_host)} malware-distribution URL(s), "
                    f"of which {len(active_urls)} are currently active (online)."
                ),
                "actual_value": host,
                "timestamp": raw.get("date_added"),
                "relevance": "HOST_LEVEL_MATCH",
            }
        ]

        return {
            "provider": "URLhaus",
            "status": "COMPLETED",
            "indicator": host,
            "indicator_type": indicator_type,
            "matched": True,
            "classification": "host_with_malware_urls",
            "url_status": None,
            "threat": None,
            "date_added": raw.get("date_added"),
            "last_seen_online": None,
            "host": host,
            "tags": raw.get("tags") or [],
            "payloads": [],
            "blacklists": {},
            "urls_for_host": urls_for_host,
            "evidence": evidence,
            "external_reference": raw.get("urlhaus_reference"),
            "match_scope": "HOST_LEVEL",
            "limitations": [
                f"This is HOST-LEVEL evidence, not URL-level. "
                f"URLhaus reports {len(urls_for_host)} malware URL(s) associated with this host. "
                "Individual URLs on this host are NOT all assumed malicious."
            ],
            "error": None,
        }

    def _normalize_payload_result(
        self, raw: Dict[str, Any], file_hash: str, hash_type: str
    ) -> Dict[str, Any]:
        """
        Normalize a /v1/payload/ response into the canonical URLhaus provider result.
        hash_type is 'sha256' or 'md5'.
        indicator_type will be 'hash_sha256' or 'hash_md5'.
        """
        indicator_type = f"hash_{hash_type}"
        int_status = raw.get("_internal_status", "SUCCESS")
        if int_status != "SUCCESS":
            return self._error_result(file_hash, indicator_type, int_status)

        qs = raw.get("query_status", "")

        if qs in ("no_results", "is_not_listed"):
            return {
                "provider": "URLhaus",
                "status": "NO_MATCH",
                "indicator": file_hash,
                "indicator_type": indicator_type,
                "matched": False,
                "classification": None,
                "url_status": None,
                "threat": None,
                "date_added": None,
                "last_seen_online": None,
                "host": None,
                "tags": [],
                "payloads": [],
                "blacklists": {},
                "urls_for_host": [],
                "evidence": [],
                "external_reference": None,
                "match_scope": "EXACT_HASH",
                "limitations": [
                    f"URLhaus returned no matching payload record for this {hash_type.upper()} hash. "
                    "This does NOT confirm the file is safe."
                ],
                "error": None,
            }

        if qs != "ok":
            return self._error_result(file_hash, indicator_type, f"UNEXPECTED_STATUS:{qs}")

        # URLhaus payload response fields
        urls_raw = raw.get("urls") or []
        urls_for_payload = []
        for u in urls_raw:
            if isinstance(u, dict):
                urls_for_payload.append({
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "filename": u.get("filename"),
                    "date_added": u.get("date_added"),
                    "urlhaus_reference": u.get("urlhaus_reference"),
                })

        evidence = [
            {
                "source": "URLhaus",
                "evidence_type": "malware_payload",
                "indicator": file_hash,
                "scope": "EXACT_HASH",
                "description": (
                    f"URLhaus payload intelligence: {hash_type.upper()} hash matches a known malware payload. "
                    f"File type: {raw.get('file_type', 'unknown')}. "
                    f"Associated with {len(urls_for_payload)} URLhaus URL record(s)."
                ),
                "actual_value": file_hash,
                "timestamp": raw.get("firstseen"),
                "relevance": "DIRECT_MATCH",
            }
        ]

        return {
            "provider": "URLhaus",
            "status": "COMPLETED",
            "indicator": file_hash,
            "indicator_type": indicator_type,
            "matched": True,
            "classification": "malware_payload",
            "url_status": None,
            "threat": raw.get("signature"),
            "date_added": raw.get("firstseen"),
            "last_seen_online": raw.get("lastseen"),
            "host": None,
            "tags": [],
            "payloads": [{
                "file_type": raw.get("file_type"),
                "md5_hash": raw.get("md5_hash"),
                "sha256_hash": raw.get("sha256_hash"),
                "signature": raw.get("signature"),
                "file_size": raw.get("file_size"),
                "urls_count": len(urls_for_payload),
            }],
            "blacklists": {},
            "urls_for_host": urls_for_payload,
            "evidence": evidence,
            "external_reference": raw.get("urlhaus_reference"),
            "match_scope": "EXACT_HASH",
            "limitations": [
                "URLhaus payload intelligence is based on malware samples it has collected. "
                "Hash correlation is exact-match only."
            ],
            "error": None,
        }

    def _error_result(self, indicator: str, indicator_type: str, internal_status: str) -> Dict[str, Any]:
        """Build a provider error result preserving the internal status."""
        status_map = {
            "AUTHENTICATION_FAILED": "AUTHENTICATION_FAILED",
            "RATE_LIMITED": "RATE_LIMITED",
            "TIMEOUT": "TIMEOUT",
            "UNAVAILABLE": "UNAVAILABLE",
            "ERROR": "ERROR",
        }
        mapped = status_map.get(internal_status, "ERROR")
        msg_map = {
            "AUTHENTICATION_FAILED": "URLhaus Auth-Key was rejected.",
            "RATE_LIMITED": "URLhaus API rate limit reached. Please retry later.",
            "TIMEOUT": "URLhaus request timed out.",
            "UNAVAILABLE": "URLhaus service could not be reached.",
            "ERROR": f"URLhaus query failed with status: {internal_status}",
        }
        return {
            "provider": "URLhaus",
            "status": mapped,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "matched": False,
            "classification": None,
            "url_status": None,
            "threat": None,
            "date_added": None,
            "last_seen_online": None,
            "host": None,
            "tags": [],
            "payloads": [],
            "blacklists": {},
            "urls_for_host": [],
            "evidence": [],
            "external_reference": None,
            "match_scope": "NOT_APPLICABLE",
            "limitations": [],
            "error": msg_map.get(mapped, f"Status: {internal_status}"),
        }

    # ── Public IOC-type-specific lookup methods ────────────────────────────────

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Lookup a URL in URLhaus malware-distribution URL database.
        Documented operation: POST /v1/url/ with form field url=<url>
        """
        if not self.is_configured:
            return self._not_configured_result(url, "url")

        logger.info(f"provider=urlhaus operation=lookup_url indicator_type=url")
        raw = await self._post("/url/", {"url": url})
        return self._normalize_url_result(raw, url)

    async def lookup_urlid(self, urlid: str) -> Dict[str, Any]:
        """
        Lookup a URLhaus database record by URLhaus ID.
        Documented operation: POST /v1/urlid/ with form field urlid=<urlid>
        Retrieves the exact recorded malware URL and intelligence described by the report.
        """
        if not self.is_configured:
            return self._not_configured_result(urlid, "urlhaus_id")

        logger.info(f"provider=urlhaus operation=lookup_urlid urlid={urlid}")
        raw = await self._post("/urlid/", {"urlid": str(urlid)})
        int_status = raw.get("_internal_status", "SUCCESS")
        if int_status != "SUCCESS":
            return self._error_result(urlid, "urlhaus_id", int_status)

        qs = raw.get("query_status", "")
        if qs == "no_results":
            return {
                "provider": "URLhaus",
                "status": "NO_MATCH",
                "indicator": urlid,
                "indicator_type": "urlhaus_id",
                "matched": False,
                "classification": None,
                "url_status": None,
                "threat": None,
                "date_added": None,
                "last_seen_online": None,
                "host": None,
                "tags": [],
                "payloads": [],
                "blacklists": {},
                "urls_for_host": [],
                "evidence": [],
                "external_reference": None,
                "match_scope": "URLHAUS_RECORDED_MALWARE_URL",
                "limitations": [f"URLhaus record ID {urlid} not found."],
                "error": None,
            }

        recorded_url = raw.get("url")
        payloads_raw = raw.get("payloads") or []
        payloads_normalized = []
        for p in payloads_raw:
            if isinstance(p, dict):
                payloads_normalized.append({
                    "file_type": p.get("file_type"),
                    "filename": p.get("filename"),
                    "signature": p.get("signature"),
                    "md5_hash": p.get("response_md5") or p.get("md5_hash"),
                    "sha256_hash": p.get("response_sha256") or p.get("sha256_hash"),
                    "first_seen": p.get("firstseen"),
                    "last_seen": p.get("lastseen"),
                })

        evidence = [
            {
                "source": "URLhaus",
                "evidence_type": "urlhaus_recorded_malware_url",
                "indicator": recorded_url,
                "scope": "URLHAUS_RECORDED_MALWARE_URL",
                "description": (
                    f"URLhaus database record #{urlid} documents recorded malware URL: {recorded_url}. "
                    f"Threat: {raw.get('threat', 'malware_download')}. "
                    f"URL status: {raw.get('url_status', 'unknown')}."
                ),
                "actual_value": recorded_url,
                "timestamp": raw.get("date_added"),
                "relevance": "RECORDED_MALWARE_URL",
            }
        ]

        return {
            "provider": "URLhaus",
            "status": "COMPLETED",
            "indicator": recorded_url,
            "indicator_type": "url",
            "matched": True,
            "classification": "malware_distribution_url",
            "url_status": raw.get("url_status"),
            "threat": raw.get("threat"),
            "date_added": raw.get("date_added"),
            "last_seen_online": raw.get("last_online"),
            "host": raw.get("host"),
            "tags": raw.get("tags") or [],
            "payloads": payloads_normalized,
            "blacklists": raw.get("blacklists") if isinstance(raw.get("blacklists"), dict) else {},
            "urls_for_host": [],
            "evidence": evidence,
            "external_reference": raw.get("urlhaus_reference"),
            "urlhaus_record_id": str(raw.get("id") or urlid),
            "recorded_malware_url": recorded_url,
            "match_scope": "URLHAUS_RECORDED_MALWARE_URL",
            "limitations": [
                "URLhaus record documents a tracked malware URL. "
                "The report page itself is not malware; the recorded URL is the malware distribution target."
            ],
            "error": None,
        }


    async def lookup_host(self, host: str, indicator_type: str = "domain") -> Dict[str, Any]:
        """
        Lookup a host (domain or IP) in URLhaus host intelligence.
        Documented operation: POST /v1/host/ with form field host=<host>
        Returns HOST-LEVEL evidence — not URL-level.
        """
        if not self.is_configured:
            return self._not_configured_result(host, indicator_type)

        logger.info(f"provider=urlhaus operation=lookup_host indicator_type={indicator_type}")
        raw = await self._post("/host/", {"host": host})
        return self._normalize_host_result(raw, host, indicator_type)

    async def lookup_payload_sha256(self, sha256_hash: str) -> Dict[str, Any]:
        """
        Lookup a SHA-256 hash in URLhaus payload database.
        Documented operation: POST /v1/payload/ with sha256_hash=<hash>
        """
        if not self.is_configured:
            return self._not_configured_result(sha256_hash, "hash_sha256")

        logger.info(f"provider=urlhaus operation=lookup_payload_sha256 indicator_type=hash_sha256")
        raw = await self._post("/payload/", {"sha256_hash": sha256_hash})
        return self._normalize_payload_result(raw, sha256_hash, "sha256")

    async def lookup_payload_md5(self, md5_hash: str) -> Dict[str, Any]:
        """
        Lookup an MD5 hash in URLhaus payload database.
        Documented operation: POST /v1/payload/ with md5_hash=<hash>
        """
        if not self.is_configured:
            return self._not_configured_result(md5_hash, "hash_md5")

        logger.info(f"provider=urlhaus operation=lookup_payload_md5 indicator_type=hash_md5")
        raw = await self._post("/payload/", {"md5_hash": md5_hash})
        return self._normalize_payload_result(raw, md5_hash, "md5")

    def lookup_sha1_not_applicable(self, sha1_hash: str) -> Dict[str, Any]:
        """
        URLhaus payload API does NOT support SHA-1 hash lookup.
        Returns NOT_APPLICABLE without making any network request.
        This is a legitimate, documented limitation.
        """
        return self._not_applicable_result(
            sha1_hash,
            "hash_sha1",
            "URLhaus payload API supports SHA-256 and MD5 hash lookups only. "
            "SHA-1 hash lookup is not available in the current URLhaus Community API. "
            "No URLhaus request was performed.",
        )


# ── Singleton factory ──────────────────────────────────────────────────────────
_provider_singleton: Optional[URLhausProvider] = None


def get_urlhaus_provider(settings=None) -> URLhausProvider:
    """Return the application-wide URLhausProvider singleton."""
    global _provider_singleton
    if _provider_singleton is None or settings is not None:
        _provider_singleton = URLhausProvider(settings)
    return _provider_singleton


async def init_urlhaus_pipeline(config=None) -> Dict[str, Any]:
    """Warm up and verify URLhaus pipeline connectivity."""
    provider = get_urlhaus_provider(config)
    return await provider.check_status(force_refresh=True)
