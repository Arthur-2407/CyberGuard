import httpx
import logging
import asyncio
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import base64

from backend.config import get_settings

logger = logging.getLogger(__name__)


class VirusTotalError(Exception):
    pass


class VirusTotalProvider:
    """
    Provider for VirusTotal Threat Intelligence API (v3).
    Handles API interactions, authentication, rate limits, timeouts, and report normalization.
    """
    _cached_status: Optional[Dict[str, Any]] = None
    _status_cache_time: float = 0.0
    _CACHE_TTL_SEC: float = 300.0

    def __init__(self, config=None):
        self.config = config or get_settings()
        self.vt_config = self.config.virustotal
        self.api_key = self.vt_config.api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.timeout = self.vt_config.timeout_sec

    @property
    def is_configured(self) -> bool:
        return self.vt_config.enabled and bool(self.api_key)

    async def check_status(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Verify VirusTotal API credentials and capability state.
        Uses a lightweight authenticated endpoint (/users/current) and caches results
        to respect rate limits.
        """
        if not self.vt_config.enabled:
            return {
                "provider": "VirusTotal",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "enabled": False,
                "message": "VirusTotal integration is disabled in configuration."
            }

        if not bool(self.api_key):
            return {
                "provider": "VirusTotal",
                "status": "NOT_CONFIGURED",
                "configured": False,
                "enabled": True,
                "message": "External intelligence provider is not configured. VIRUSTOTAL_API_KEY is missing."
            }

        now = time.time()
        cached = VirusTotalProvider._cached_status
        cached_st = cached.get("status") if cached else None
        # Only cache healthy or permanent auth failures for the long TTL; transient errors expire in 10s to allow quick auto-recovery
        ttl = VirusTotalProvider._CACHE_TTL_SEC if cached_st in ("READY", "AUTHENTICATION_FAILED", "FORBIDDEN") else 10.0
        if not force_refresh and cached and (now - VirusTotalProvider._status_cache_time < ttl):
            return dict(cached)

        res = await self._make_request("GET", "/users/current")
        st = res.get("status")

        if st == "SUCCESS":
            status_obj = {
                "provider": "VirusTotal",
                "status": "READY",
                "configured": True,
                "enabled": True,
                "message": "VirusTotal intelligence is operational."
            }
        elif st == "UNAUTHORIZED":
            status_obj = {
                "provider": "VirusTotal",
                "status": "AUTHENTICATION_FAILED",
                "configured": True,
                "enabled": True,
                "message": "VirusTotal authentication failed. Configured credentials were rejected."
            }
        elif st == "FORBIDDEN":
            status_obj = {
                "provider": "VirusTotal",
                "status": "FORBIDDEN",
                "configured": True,
                "enabled": True,
                "message": "VirusTotal operation forbidden with current credentials."
            }
        elif st == "RATE_LIMITED":
            status_obj = {
                "provider": "VirusTotal",
                "status": "RATE_LIMITED",
                "configured": True,
                "enabled": True,
                "message": "VirusTotal API request quota has been reached."
            }
        elif st in ("UNAVAILABLE", "TIMEOUT"):
            status_obj = {
                "provider": "VirusTotal",
                "status": "UNAVAILABLE",
                "configured": True,
                "enabled": True,
                "message": "VirusTotal external service could not be reached or request timed out."
            }
        else:
            status_obj = {
                "provider": "VirusTotal",
                "status": "DEGRADED",
                "configured": True,
                "enabled": True,
                "message": f"VirusTotal provider returned unexpected status: {st}"
            }

        VirusTotalProvider._cached_status = status_obj
        VirusTotalProvider._status_cache_time = now
        return dict(status_obj)

    def _get_headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        if not self.is_configured:
            return {"status": "NOT_CONFIGURED"}

        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()

        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(method, url, headers=headers, **kwargs)

                if response.status_code == 401:
                    logger.error("provider=virustotal status=AUTHENTICATION_FAILED http_status=401 reason=UNAUTHORIZED")
                    VirusTotalProvider._cached_status = {
                        "provider": "VirusTotal",
                        "status": "AUTHENTICATION_FAILED",
                        "configured": True,
                        "enabled": True,
                        "message": "VirusTotal authentication failed. Configured credentials were rejected."
                    }
                    VirusTotalProvider._status_cache_time = time.time()
                    return {"status": "UNAUTHORIZED"}
                elif response.status_code == 403:
                    logger.error("provider=virustotal status=FORBIDDEN http_status=403 reason=FORBIDDEN")
                    VirusTotalProvider._cached_status = {
                        "provider": "VirusTotal",
                        "status": "FORBIDDEN",
                        "configured": True,
                        "enabled": True,
                        "message": "VirusTotal operation forbidden with current credentials."
                    }
                    VirusTotalProvider._status_cache_time = time.time()
                    return {"status": "FORBIDDEN"}
                elif response.status_code == 429:
                    logger.warning("provider=virustotal status=RATE_LIMITED http_status=429 reason=QUOTA_EXCEEDED")
                    VirusTotalProvider._cached_status = {
                        "provider": "VirusTotal",
                        "status": "RATE_LIMITED",
                        "configured": True,
                        "enabled": True,
                        "message": "VirusTotal API request quota has been reached."
                    }
                    VirusTotalProvider._status_cache_time = time.time()
                    return {"status": "RATE_LIMITED"}
                elif response.status_code == 404:
                    return {"status": "NOT_FOUND"}
                elif response.status_code >= 500:
                    logger.error(f"provider=virustotal status=UNAVAILABLE http_status={response.status_code}")
                    return {"status": "UNAVAILABLE"}

                response.raise_for_status()
                data = response.json()
                data["status"] = "SUCCESS"
                VirusTotalProvider._cached_status = {
                    "provider": "VirusTotal",
                    "status": "READY",
                    "configured": True,
                    "enabled": True,
                    "message": "VirusTotal intelligence is operational."
                }
                VirusTotalProvider._status_cache_time = time.time()
                return data

        except httpx.TimeoutException:
            logger.error("provider=virustotal status=UNAVAILABLE reason=TIMEOUT")
            return {"status": "TIMEOUT"}
        except httpx.RequestError as e:
            logger.error(f"provider=virustotal status=UNAVAILABLE reason=NETWORK_ERROR error={e}")
            return {"status": "UNAVAILABLE"}
        except Exception as e:
            logger.error(f"provider=virustotal status=FAILED error={e}")
            return {"status": "FAILED"}

    def _generate_gui_permalink(self, indicator: str, indicator_type: str, item_id: Optional[str] = None) -> str:
        """Construct canonical VirusTotal web GUI link for human analysts."""
        if indicator_type == "url":
            target_id = item_id or base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"https://www.virustotal.com/gui/url/{target_id}"
        elif indicator_type in ("hash", "file"):
            return f"https://www.virustotal.com/gui/file/{indicator.lower()}"
        elif indicator_type == "domain":
            return f"https://www.virustotal.com/gui/domain/{indicator.lower()}"
        elif indicator_type in ("ip", "ipv4", "ipv6"):
            return f"https://www.virustotal.com/gui/ip-address/{indicator}"
        return ""

    def _normalize_report(self, raw_data: Dict[str, Any], indicator: str, indicator_type: str) -> Dict[str, Any]:
        """
        Normalize VirusTotal API v3 response into a rich, structured CyberGuard schema.
        Preserves legacy fields (malicious_count, suspicious_count, etc.) for backward compatibility.
        """
        status = raw_data.get("status", "FAILED")
        if status != "SUCCESS":
            return {
                "status": status,
                "provider": "VirusTotal",
                "indicator": indicator,
                "indicator_type": indicator_type,
            }

        try:
            data_block = raw_data.get("data", {})
            item_id = data_block.get("id")
            attrs = data_block.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            raw_engines = attrs.get("last_analysis_results", {})
            raw_categories = attrs.get("categories", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            timeout = stats.get("timeout", 0)
            total_engines = sum(stats.values()) if stats else len(raw_engines)

            # Security engine results
            engine_results: List[Dict[str, Any]] = []
            for eng_name, eng_val in raw_engines.items():
                if isinstance(eng_val, dict):
                    engine_results.append({
                        "engine_name": eng_val.get("engine_name") or eng_name,
                        "verdict": eng_val.get("category", "undetected"),
                        "result": eng_val.get("result") or "clean",
                        "method": eng_val.get("method", ""),
                    })

            # Sort engine results: malicious first, then suspicious, harmless, undetected
            def _verdict_rank(item: Dict[str, Any]) -> int:
                v = (item.get("verdict") or "").lower()
                if v == "malicious": return 0
                if v == "suspicious": return 1
                if v == "harmless": return 2
                return 3

            engine_results.sort(key=_verdict_rank)

            # Categories by provider
            categories_list: List[Dict[str, str]] = []
            if isinstance(raw_categories, dict):
                for prov, cat in raw_categories.items():
                    categories_list.append({
                        "provider": str(prov),
                        "category": str(cat),
                    })

            # Timeline
            timeline = {
                "first_seen": attrs.get("first_seen_date") or attrs.get("first_submission_date"),
                "first_submission": attrs.get("first_submission_date"),
                "last_submission": attrs.get("last_submission_date"),
                "last_analysis": attrs.get("last_analysis_date"),
                "last_modification": attrs.get("last_modification_date"),
                "creation_date": attrs.get("creation_date"),
            }

            # Technical details
            technical_details: Dict[str, Any] = {}
            if indicator_type == "url":
                technical_details = {
                    "url": attrs.get("url") or indicator,
                    "final_url": attrs.get("last_final_url"),
                    "http_response_code": attrs.get("last_http_response_code"),
                    "threat_names": attrs.get("threat_names", []),
                    "title": attrs.get("title"),
                }
            elif indicator_type == "domain":
                technical_details = {
                    "domain": indicator,
                    "registrar": attrs.get("registrar"),
                    "tld": attrs.get("tld"),
                    "creation_date": attrs.get("creation_date"),
                    "whois_date": attrs.get("whois_date"),
                }
            elif indicator_type in ("ip", "ipv4", "ipv6"):
                technical_details = {
                    "ip_address": indicator,
                    "asn": attrs.get("asn"),
                    "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"),
                    "continent": attrs.get("continent"),
                    "network": attrs.get("network"),
                }
            elif indicator_type in ("hash", "file"):
                technical_details = {
                    "md5": attrs.get("md5"),
                    "sha1": attrs.get("sha1"),
                    "sha256": attrs.get("sha256") or (indicator if len(indicator) == 64 else None),
                    "file_size": attrs.get("size"),
                    "type_description": attrs.get("type_description"),
                    "type_extension": attrs.get("type_extension"),
                    "meaningful_name": attrs.get("meaningful_name"),
                }

            gui_permalink = self._generate_gui_permalink(indicator, indicator_type, item_id)
            api_link = data_block.get("links", {}).get("self")

            return {
                "status": "COMPLETED",
                "provider": "VirusTotal",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "summary": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": timeout,
                    "total_engines": total_engines,
                },
                "reputation": attrs.get("reputation"),
                "categories": categories_list,
                "category_names": list(raw_categories.values()) if isinstance(raw_categories, dict) else [],
                "engine_results": engine_results,
                "timeline": timeline,
                "technical_details": technical_details,
                "permalink": gui_permalink or api_link,
                "api_link": api_link,
                # Backward-compatibility legacy fields
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": total_engines,
            }
        except Exception as e:
            logger.error(f"Failed to normalize VirusTotal report: {e}")
            return {
                "status": "FAILED",
                "provider": "VirusTotal",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "message": f"Normalization failed: {str(e)}",
            }

    async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Retrieve a file report using its hash (SHA-256, SHA-1, or MD5)."""
        res = await self._make_request("GET", f"/files/{file_hash}")
        return self._normalize_report(res, indicator=file_hash, indicator_type="hash")

    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """Retrieve a URL report."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        res = await self._make_request("GET", f"/urls/{url_id}")
        return self._normalize_report(res, indicator=url, indicator_type="url")

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Retrieve a domain report."""
        res = await self._make_request("GET", f"/domains/{domain}")
        return self._normalize_report(res, indicator=domain, indicator_type="domain")

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Retrieve an IP address report."""
        res = await self._make_request("GET", f"/ip_addresses/{ip}")
        return self._normalize_report(res, indicator=ip, indicator_type="ip")

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Submit a URL for scanning. Returns an analysis ID which can be polled."""
        res = await self._make_request("POST", "/urls", data={"url": url})
        if res.get("status") != "SUCCESS":
            return {"status": res.get("status")}

        analysis_id = res.get("data", {}).get("id")
        return {
            "status": "SUBMITTED",
            "analysis_id": analysis_id
        }

    async def scan_file(self, file_bytes: bytes, filename: str = "upload.dat") -> Dict[str, Any]:
        """Submit a file for scanning (max 32MB standard)."""
        if len(file_bytes) > self.vt_config.max_file_size_bytes:
            return {"status": "NOT_SUPPORTED_BY_VIRUSTOTAL_CONFIGURATION"}

        files = {"file": (filename, file_bytes)}
        res = await self._make_request("POST", "/files", files=files)

        if res.get("status") != "SUCCESS":
            return {"status": res.get("status")}

        analysis_id = res.get("data", {}).get("id")
        return {
            "status": "SUBMITTED",
            "analysis_id": analysis_id
        }

    async def get_analysis_report(self, analysis_id: str) -> Dict[str, Any]:
        """Retrieve the status of a pending analysis."""
        res = await self._make_request("GET", f"/analyses/{analysis_id}")
        if res.get("status") != "SUCCESS":
            return {"status": res.get("status")}

        status = res.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            stats = res.get("data", {}).get("attributes", {}).get("stats", {})
            return {
                "status": "COMPLETED",
                "provider": "VirusTotal",
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "harmless_count": stats.get("harmless", 0),
                "undetected_count": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0
            }
        elif status == "queued":
            return {"status": "QUEUED"}
        else:
            return {"status": "ANALYZING"}

    async def poll_analysis(self, analysis_id: str, timeout_sec: float = 4.0, interval_sec: float = 1.0) -> Dict[str, Any]:
        """Poll a pending analysis ID until completion or timeout."""
        start = time.time()
        while time.time() - start < timeout_sec:
            rep = await self.get_analysis_report(analysis_id)
            if rep.get("status") == "COMPLETED":
                return rep
            elif rep.get("status") not in ("QUEUED", "ANALYZING"):
                return rep
            await asyncio.sleep(interval_sec)
        return {"status": "PENDING", "analysis_id": analysis_id}


_provider_singleton: Optional[VirusTotalProvider] = None


def get_virustotal_provider(settings=None) -> VirusTotalProvider:
    """Return the application-wide VirusTotalProvider singleton."""
    global _provider_singleton
    if _provider_singleton is None or settings is not None:
        _provider_singleton = VirusTotalProvider(settings)
    return _provider_singleton


async def init_virustotal_pipeline(config=None) -> Dict[str, Any]:
    """Warm up and verify VirusTotal pipeline connectivity."""
    provider = get_virustotal_provider(config)
    return await provider.check_status(force_refresh=True)
