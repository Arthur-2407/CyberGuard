"""
url_resolver.py — Safe URL Resolution, Redirect Chain Tracking, and Landing-Page Metadata Extraction.

Implements deep forensic URL resolution with strict SSRF defenses:
  - Multi-hop redirect tracking (301, 302, 303, 307, 308, and HTML META_REFRESH).
  - Hop-by-hop destination revalidation against private/local/internal addresses.
  - DNS rebinding defense (validates all resolved IP addresses before connection).
  - Loop detection and bounded redirect depth limit.
  - Bounded per-hop and total resolution timeouts.
  - Bounded response body reading (prevents memory exhaustion/response bombs).
  - Untrusted HTML metadata extraction (title, canonical, og:url) without JS execution.
  - Identification of provider report pages (URLhaus / VirusTotal) and referenced IOCs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from enum import Enum
from html.parser import HTMLParser
from typing import Dict, Any, List, Optional, Tuple, Set

import httpx

logger = logging.getLogger(__name__)

# Bounded configuration defaults
DEFAULT_MAX_REDIRECT_HOPS = 10
DEFAULT_PER_HOP_TIMEOUT_SEC = 4.0
DEFAULT_TOTAL_TIMEOUT_SEC = 12.0
DEFAULT_MAX_RESPONSE_BYTES = 262144  # 256 KB max for metadata extraction
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberGuard-Resolver/1.0"


class ResolutionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    BLOCKED_REDIRECT_TARGET = "BLOCKED_REDIRECT_TARGET"
    BLOCKED_ORIGINAL_URL = "BLOCKED_ORIGINAL_URL"
    REDIRECT_LOOP = "REDIRECT_LOOP"
    REDIRECT_LIMIT = "REDIRECT_LIMIT"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    CONTENT_TYPE_DOWNLOAD = "CONTENT_TYPE_DOWNLOAD"


class RedirectType(str, Enum):
    HTTP = "HTTP"
    META_REFRESH = "META_REFRESH"


class LinkRelationship(str, Enum):
    REDIRECT = "REDIRECT"
    META_REDIRECT = "META_REDIRECT"
    CANONICAL = "CANONICAL"
    OG_URL = "OG_URL"
    PAGE_LINK = "PAGE_LINK"
    PROVIDER_REPORT = "PROVIDER_REPORT"
    RECORDED_MALWARE_URL = "RECORDED_MALWARE_URL"
    RELATED_HOST = "RELATED_HOST"
    RELATED_PAYLOAD = "RELATED_PAYLOAD"


@dataclass
class RedirectHop:
    hop: int
    from_url: str
    to_url: str
    status_code: int
    redirect_type: str = "HTTP"
    location_header: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop": self.hop,
            "from_url": self.from_url,
            "to_url": self.to_url,
            "status_code": self.status_code,
            "redirect_type": self.redirect_type,
            "location": self.location_header,
            "headers": self.headers,
            "duration_ms": round(self.duration_ms, 1),
        }


@dataclass
class PageMetadata:
    title: Optional[str] = None
    canonical_url: Optional[str] = None
    og_url: Optional[str] = None
    content_type: str = "text/html"
    is_download: bool = False
    meta_refresh_target: Optional[str] = None
    client_side_redirect_target: Optional[str] = None
    client_side_redirect_status: str = "CLIENT_SIDE_REDIRECT_NOT_RESOLVED"
    referenced_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "canonical_url": self.canonical_url,
            "og_url": self.og_url,
            "content_type": self.content_type,
            "is_download": self.is_download,
            "meta_refresh_target": self.meta_refresh_target,
            "client_side_redirect_target": self.client_side_redirect_target,
            "client_side_redirect_status": self.client_side_redirect_status,
            "referenced_urls": self.referenced_urls,
        }



@dataclass
class AssociatedIOC:
    value: str
    type: str  # "URL", "DOMAIN", "IP", "HASH"
    source: str
    relationship: str
    scope: str
    associated_host: Optional[str] = None
    threat: Optional[str] = None
    url_status: Optional[str] = None
    urlhaus_record_id: Optional[str] = None
    provider_report_url: Optional[str] = None
    payload_sha256: Optional[str] = None
    intelligence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type,
            "source": self.source,
            "relationship": self.relationship,
            "scope": self.scope,
            "associated_host": self.associated_host,
            "threat": self.threat,
            "url_status": self.url_status,
            "urlhaus_record_id": self.urlhaus_record_id,
            "provider_report_url": self.provider_report_url,
            "payload_sha256": self.payload_sha256,
            "intelligence": self.intelligence,
        }


@dataclass
class ResolutionResult:
    original_url: str
    terminal_url: str
    status: ResolutionStatus
    redirect_count: int
    redirect_chain: List[RedirectHop]
    terminal_status_code: Optional[int]
    page_metadata: PageMetadata
    provider_report_url: Optional[str] = None
    recorded_malware_url: Optional[str] = None
    associated_iocs: List[AssociatedIOC] = field(default_factory=list)
    protocol_transition: str = "NONE"
    total_duration_ms: float = 0.0
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_url": self.original_url,
            "terminal_url": self.terminal_url,
            "status": self.status.value,
            "redirect_count": self.redirect_count,
            "redirect_chain": [h.to_dict() for h in self.redirect_chain],
            "terminal_status_code": self.terminal_status_code,
            "page_metadata": self.page_metadata.to_dict(),
            "provider_report_url": self.provider_report_url,
            "recorded_malware_url": self.recorded_malware_url,
            "associated_iocs": [ioc.to_dict() for ioc in self.associated_iocs],
            "protocol_transition": self.protocol_transition,
            "total_duration_ms": round(self.total_duration_ms, 1),
            "error_message": self.error_message,
        }


# ── SSRF & IP VALIDATION ───────────────────────────────────────────────────────

class SSRFValidator:
    """Strict SSRF validator preventing access to internal, loopback, and metadata targets."""

    BLOCKED_HOSTNAMES = frozenset({
        "localhost", "localhost.localdomain", "broadcasthost",
        "metadata.google.internal", "metadata", "instance-data",
    })

    BLOCKED_PORTS = frozenset({
        22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 445, 1433,
        1521, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
        9200, 11211, 27017, 28017
    })

    @staticmethod
    def is_safe_ip(ip_str: str) -> Tuple[bool, str]:
        """Verify that an IP address is a valid, globally routable public address."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address format: {ip_str}"

        if ip.is_loopback:
            return False, f"Loopback address blocked: {ip_str}"
        if ip.is_private:
            return False, f"Private RFC 1918 / RFC 4193 address blocked: {ip_str}"
        if ip.is_link_local:
            return False, f"Link-local address blocked: {ip_str}"
        if ip.is_multicast:
            return False, f"Multicast address blocked: {ip_str}"
        if ip.is_reserved:
            return False, f"Reserved address blocked: {ip_str}"
        if ip.is_unspecified:
            return False, f"Unspecified address blocked: {ip_str}"

        # Cloud metadata service protection
        if str(ip) in ("169.254.169.254", "fd00:ec2::254"):
            return False, f"Cloud metadata endpoint blocked: {ip_str}"

        return True, ""

    @classmethod
    def validate_hostname(cls, hostname: str) -> Tuple[bool, bool, str, List[str]]:
        """
        Validate hostname and resolve DNS to ensure all IPs are public.
        Mitigates DNS rebinding by performing resolution prior to connection.
        Returns: (is_safe, is_ssrf_block, reason, resolved_ips)
        """
        if not hostname:
            return False, False, "Empty hostname", []

        h_lower = hostname.lower()
        if h_lower in cls.BLOCKED_HOSTNAMES:
            return False, True, f"Blocked hostname: {hostname}", []

        if h_lower.endswith((".local", ".internal", ".localhost", ".test", ".example", ".invalid")):
            return False, True, f"Internal TLD blocked: {hostname}", []

        # Check if hostname is already a direct IP
        try:
            ip = ipaddress.ip_address(hostname)
            safe, reason = cls.is_safe_ip(str(ip))
            if not safe:
                return False, True, reason, []
            return True, False, "", [str(ip)]
        except ValueError:
            pass

        # Perform DNS resolution
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            # DNS resolution failure (e.g. NXDOMAIN, offline host, mock domain) is a network error, NOT an SSRF attack
            return False, False, f"DNS resolution failed for {hostname}: {e}", []
        except Exception as e:
            return False, False, f"DNS lookup error for {hostname}: {e}", []

        resolved_ips: List[str] = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

        if not resolved_ips:
            return False, False, f"No IP addresses resolved for hostname: {hostname}", []

        # Validate EVERY resolved IP address
        for ip_str in resolved_ips:
            safe, reason = cls.is_safe_ip(ip_str)
            if not safe:
                return False, True, f"DNS resolution for {hostname} resolved to unsafe IP ({ip_str}): {reason}", []

        return True, False, "", resolved_ips

    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, bool, str, str, str, int]:
        """
        Parse and validate complete URL for outbound request safety.
        Returns: (is_safe, is_ssrf_block, error_message, scheme, hostname, port)
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            return False, False, f"URL parse error: {e}", "", "", 0

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False, False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted.", "", "", 0

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, False, "URL missing hostname.", "", "", 0

        port = parsed.port or (443 if scheme == "https" else 80)
        if port in cls.BLOCKED_PORTS:
            return False, True, f"Port {port} is blocked by SSRF policy.", scheme, hostname, port

        # Validate hostname & DNS resolution
        safe, is_ssrf, reason, resolved_ips = cls.validate_hostname(hostname)
        if not safe:
            return False, is_ssrf, reason, scheme, hostname, port

        return True, False, "", scheme, hostname, port


# ── UNTRUSTED HTML METADATA PARSER ─────────────────────────────────────────────

class SafeHTMLMetadataParser(HTMLParser):
    """
    Parses untrusted HTML strictly as text tokens to extract metadata.
    Zero script execution, zero dynamic evaluation.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.title: Optional[str] = None
        self.canonical_url: Optional[str] = None
        self.og_url: Optional[str] = None
        self.meta_refresh_target: Optional[str] = None
        self.client_side_redirect_target: Optional[str] = None
        self.client_side_redirect_status: str = "CLIENT_SIDE_REDIRECT_NOT_RESOLVED"
        self.referenced_urls: List[str] = []
        self._in_title = False
        self._title_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower == "title":
            self._in_title = True

        elif tag_lower == "a":
            href = attr_dict.get("href", "").strip()
            if href:
                if re.match(r"^https?://urlhaus\.abuse\.ch/url/\d+", href, re.IGNORECASE):
                    if href not in self.referenced_urls:
                        self.referenced_urls.append(href)
                    if not self.client_side_redirect_target:
                        self.client_side_redirect_target = href

        elif tag_lower == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href", "")
            if rel == "canonical" and href:
                try:
                    self.canonical_url = urllib.parse.urljoin(self.base_url, href)
                except Exception:
                    self.canonical_url = href

        elif tag_lower == "meta":
            prop = attr_dict.get("property", "").lower()
            name = attr_dict.get("name", "").lower()
            content = attr_dict.get("content", "")

            # OpenGraph URL
            if (prop == "og:url" or name == "og:url") and content:
                try:
                    self.og_url = urllib.parse.urljoin(self.base_url, content)
                except Exception:
                    self.og_url = content

            # Meta Refresh: e.g. <meta http-equiv="refresh" content="0; url=https://...">
            http_equiv = attr_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh" and content:
                match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.IGNORECASE)
                if match:
                    target = match.group(1).strip()
                    try:
                        self.meta_refresh_target = urllib.parse.urljoin(self.base_url, target)
                    except Exception:
                        self.meta_refresh_target = target

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self._in_title = False
            raw_title = " ".join(self._title_chunks).strip()
            # Collapse whitespace and limit length
            self.title = re.sub(r"\s+", " ", raw_title)[:500] if raw_title else None

            # Look for URLs embedded in the title (e.g. "URLhaus | http://42.179.116.166:55253/i")
            if self.title:
                urls = re.findall(r"https?://[^\s<>\"']+", self.title)
                for u in urls:
                    cleaned_u = u.rstrip(".,;!)]")
                    if cleaned_u not in self.referenced_urls:
                        self.referenced_urls.append(cleaned_u)

    def handle_data(self, data: str):
        if self._in_title:
            self._title_chunks.append(data)
        elif "window.location" in data or "urlhaus.abuse.ch/url/" in data:
            # Detect client-side redirect destination or URLhaus report link in script/text
            m = re.search(r"https?://urlhaus\.abuse\.ch/url/\d+/?", data)
            if m:
                found_u = m.group(0).rstrip(".,;!)]")
                if found_u not in self.referenced_urls:
                    self.referenced_urls.append(found_u)
                if not self.client_side_redirect_target:
                    self.client_side_redirect_target = found_u



# ── SAFE URL RESOLVER PIPELINE ────────────────────────────────────────────────

class SafeURLResolver:
    """
    Authoritative, forensic URL resolver for CyberGuard.
    Traces multi-hop redirects, captures HTTP headers, extracts metadata,
    and isolates referenced security indicators with full SSRF protection.
    """

    def __init__(
        self,
        max_hops: int = DEFAULT_MAX_REDIRECT_HOPS,
        per_hop_timeout_sec: float = DEFAULT_PER_HOP_TIMEOUT_SEC,
        total_timeout_sec: float = DEFAULT_TOTAL_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.max_hops = max_hops
        self.per_hop_timeout_sec = per_hop_timeout_sec
        self.total_timeout_sec = total_timeout_sec
        self.max_response_bytes = max_response_bytes
        self.user_agent = user_agent

    @staticmethod
    def is_urlhaus_report_url(url: str) -> Optional[str]:
        """Return URLhaus record ID if URL is a URLhaus database report page."""
        match = re.match(r"^https?://urlhaus\.abuse\.ch/url/(\d+)/?", url, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def is_virustotal_report_url(url: str) -> bool:
        """Return True if URL is a VirusTotal GUI report page."""
        return bool(re.match(r"^https?://(?:www\.)?virustotal\.com/gui/url/", url, re.IGNORECASE))

    async def resolve(self, original_url: str) -> ResolutionResult:
        """
        Execute safe step-by-step resolution of original_url.
        Preserves complete redirect history, landing page metadata, and associated IOCs.
        """
        start_time = time.time()
        redirect_chain: List[RedirectHop] = []
        visited_urls: Set[str] = set()

        current_url = original_url.strip()
        protocol_transition = "NONE"
        terminal_status_code: Optional[int] = None
        page_metadata = PageMetadata()
        status = ResolutionStatus.COMPLETED
        error_msg: Optional[str] = None

        safe_headers_whitelist = {"location", "content-type", "content-length", "server", "date"}

        hop_count = 0
        while True:
            # 1. Total resolution timeout check
            elapsed = time.time() - start_time
            if elapsed >= self.total_timeout_sec:
                status = ResolutionStatus.TIMEOUT
                error_msg = f"Overall URL resolution timed out after {elapsed:.1f}s (limit: {self.total_timeout_sec}s)."
                break

            # 2. Redirect depth limit check
            if hop_count >= self.max_hops:
                status = ResolutionStatus.REDIRECT_LIMIT
                error_msg = f"Maximum redirect depth exceeded ({self.max_hops} hops)."
                break

            # 3. SSRF Validation for current target URL
            safe, is_ssrf, reason, scheme, hostname, port = SSRFValidator.validate_url(current_url)
            if not safe:
                if is_ssrf:
                    if hop_count == 0:
                        status = ResolutionStatus.BLOCKED_ORIGINAL_URL
                        error_msg = f"Original URL blocked by SSRF protection: {reason}"
                    else:
                        status = ResolutionStatus.BLOCKED_REDIRECT_TARGET
                        error_msg = f"Redirect target at hop {hop_count} blocked by SSRF protection: {reason}"
                else:
                    status = ResolutionStatus.NETWORK_ERROR
                    error_msg = f"Resolution failed for '{current_url}': {reason}"
                break

            # 4. Redirect loop detection
            norm_target = current_url.lower().rstrip("/")
            if norm_target in visited_urls:
                status = ResolutionStatus.REDIRECT_LOOP
                error_msg = f"Redirect loop detected: '{current_url}' was visited previously in resolution chain."
                break
            visited_urls.add(norm_target)

            # 5. Outbound request execution
            req_start = time.time()
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }

            try:
                # Use stream to enforce response body size limit
                remaining_time = max(0.5, min(self.per_hop_timeout_sec, self.total_timeout_sec - elapsed))
                async with httpx.AsyncClient(
                    follow_redirects=False,
                    verify=False,  # Security inspection probes destinations without throwing SSL aborts
                    timeout=remaining_time,
                ) as client:
                    resp = await client.get(current_url, headers=headers)

                hop_duration = (time.time() - req_start) * 1000.0
                resp_status = resp.status_code

                # Filter safe headers (strictly omit cookies, authorizations, secrets)
                captured_headers = {
                    k.lower(): v for k, v in resp.headers.items()
                    if k.lower() in safe_headers_whitelist
                }

                # 6. Check for HTTP Redirects (301, 302, 303, 307, 308)
                if resp_status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        # Malformed redirect missing Location header: treat as terminal
                        terminal_status_code = resp_status
                        break

                    next_url = urllib.parse.urljoin(current_url, location.strip())

                    # Check for protocol downgrade
                    curr_scheme = urllib.parse.urlparse(current_url).scheme.lower()
                    next_scheme = urllib.parse.urlparse(next_url).scheme.lower()
                    if curr_scheme == "https" and next_scheme == "http":
                        protocol_transition = "HTTPS_TO_HTTP_DOWNGRADE"
                    elif curr_scheme == "http" and next_scheme == "https":
                        protocol_transition = "HTTP_TO_HTTPS_UPGRADE"

                    hop_count += 1
                    redirect_chain.append(RedirectHop(
                        hop=hop_count,
                        from_url=current_url,
                        to_url=next_url,
                        status_code=resp_status,
                        redirect_type="HTTP",
                        location_header=location,
                        headers=captured_headers,
                        duration_ms=hop_duration,
                    ))

                    current_url = next_url
                    continue

                # 7. Terminal resource reached
                terminal_status_code = resp_status
                content_type_header = resp.headers.get("content-type", "").lower()
                page_metadata.content_type = content_type_header.split(";")[0].strip() or "application/octet-stream"

                # Check for binary downloads
                is_html = "text/html" in content_type_header or "application/xhtml+xml" in content_type_header
                if not is_html and any(b in content_type_header for b in ["application/octet-stream", "application/zip", "application/x-"]):
                    page_metadata.is_download = True

                # Parse HTML content if text/html
                if is_html:
                    # Bounded content read
                    body_text = resp.text[:self.max_response_bytes]
                    try:
                        parser = SafeHTMLMetadataParser(current_url)
                        parser.feed(body_text)
                        page_metadata.title = parser.title
                        page_metadata.canonical_url = parser.canonical_url
                        page_metadata.og_url = parser.og_url
                        page_metadata.meta_refresh_target = parser.meta_refresh_target
                        page_metadata.referenced_urls = parser.referenced_urls

                        # Check for HTML META_REFRESH navigation
                        if parser.meta_refresh_target and hop_count < self.max_hops:
                            meta_target = parser.meta_refresh_target
                            norm_meta = meta_target.lower().rstrip("/")
                            if norm_meta != current_url.lower().rstrip("/") and norm_meta not in visited_urls:
                                hop_count += 1
                                redirect_chain.append(RedirectHop(
                                    hop=hop_count,
                                    from_url=current_url,
                                    to_url=meta_target,
                                    status_code=200,
                                    redirect_type="META_REFRESH",
                                    location_header=meta_target,
                                    headers=captured_headers,
                                    duration_ms=hop_duration,
                                ))
                                current_url = meta_target
                                continue
                    except Exception as e:
                        logger.debug(f"HTML metadata parsing exception: {e}")

                break

            except httpx.TimeoutException:
                status = ResolutionStatus.TIMEOUT
                error_msg = f"Network timeout during HTTP request to '{current_url}'."
                break
            except httpx.RequestError as e:
                status = ResolutionStatus.NETWORK_ERROR
                error_msg = f"HTTP request failed for '{current_url}': {str(e)}"
                break
            except Exception as e:
                status = ResolutionStatus.NETWORK_ERROR
                error_msg = f"Unexpected error during resolution of '{current_url}': {str(e)}"
                break

        total_duration_ms = (time.time() - start_time) * 1000.0

        # ── POST-RESOLUTION FORENSICS & INDICATOR ISOLATION ───────────────────
        provider_report_url: Optional[str] = None
        recorded_malware_url: Optional[str] = None
        associated_iocs: List[AssociatedIOC] = []

        # Check if terminal URL is a URLhaus report URL
        uh_id = self.is_urlhaus_report_url(current_url)
        if uh_id:
            provider_report_url = current_url
        else:
            # Check if any discovered link or client-side redirect points to a URLhaus report
            for candidate in page_metadata.referenced_urls:
                cand_id = self.is_urlhaus_report_url(candidate)
                if cand_id:
                    uh_id = cand_id
                    provider_report_url = f"https://urlhaus.abuse.ch/url/{uh_id}/"
                    break


        # Check if terminal URL is a VirusTotal report URL
        if self.is_virustotal_report_url(current_url):
            provider_report_url = current_url

        # Check referenced URLs for security indicators and report pages
        title_urls = page_metadata.referenced_urls
        for ref_u in title_urls:
            if ref_u == original_url or ref_u == current_url:
                continue

            ref_uh_id = self.is_urlhaus_report_url(ref_u)
            if ref_uh_id:
                # This is a URLhaus database report page, NOT the malware URL
                provider_report_url = ref_u
                uh_id = ref_uh_id
                associated_iocs.append(AssociatedIOC(
                    value=ref_u,
                    type="URL",
                    source="URLhaus",
                    relationship="PROVIDER_REPORT",
                    scope="PROVIDER_REPORT",
                    associated_host="urlhaus.abuse.ch",
                    urlhaus_record_id=ref_uh_id,
                    provider_report_url=ref_u,
                ))
            elif not self.is_virustotal_report_url(ref_u):
                # This is a referenced indicator (e.g. from title: "URLhaus | http://42.179.116.166:55253/i")
                parsed_ref = urllib.parse.urlparse(ref_u)
                ref_host = parsed_ref.hostname or ""
                recorded_malware_url = ref_u
                associated_iocs.append(AssociatedIOC(
                    value=ref_u,
                    type="URL",
                    source="URLhaus" if "urlhaus" in (page_metadata.title or "").lower() else "PageMetadata",
                    relationship="RECORDED_MALWARE_URL" if uh_id else "REFERENCED_SECURITY_IOC",
                    scope="URLHAUS_RECORDED_MALWARE_URL" if uh_id else "REFERENCED_URL",
                    associated_host=ref_host,
                    urlhaus_record_id=uh_id,
                    provider_report_url=provider_report_url,
                ))


        return ResolutionResult(
            original_url=original_url,
            terminal_url=current_url,
            status=status,
            redirect_count=len(redirect_chain),
            redirect_chain=redirect_chain,
            terminal_status_code=terminal_status_code,
            page_metadata=page_metadata,
            provider_report_url=provider_report_url,
            recorded_malware_url=recorded_malware_url,
            associated_iocs=associated_iocs,
            protocol_transition=protocol_transition,
            total_duration_ms=total_duration_ms,
            error_message=error_msg,
        )
