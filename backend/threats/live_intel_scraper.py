"""
live_intel_scraper.py — Live Real-Time Web Intelligence & Deep Crawler Forensics Engine.

Integrates:
  - DuckDuckGo Search (duckduckgo_search / ddgs) for real-time web OSINT
  - Trafilatura for robust text, metadata, and body extraction without clutter
  - Playwright & BeautifulSoup4 for dynamic DOM rendering, credential form extraction,
    and sensitive sensor probe detection (Camera, Mic, GPS)
  - Crawl4AI for deep web scraping and markdown synthesis
  - Qwen LLM for grounded, multi-vector threat synthesis alongside VirusTotal & URLhaus

Explicit analysis state guarantees:
  - UNREACHABLE / OFFLINE is NEVER converted into CLEAN / NO FORMS.
  - Sensor permission probing (Camera, Mic, GPS) is identified and attributed.
  - SSRF protection prevents probing private/loopback/metadata endpoints.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import logging
import os
import re
import socket
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

from backend.threats.network_telemetry import (
    NetworkTrafficIntelligenceEngine, NetworkRequestRecord, NetworkTrafficReport
)

logger = logging.getLogger(__name__)


def classify_network_failure(exc: Exception, url: str) -> Tuple[str, str]:
    """
    Classifies network and crawler errors into granular diagnostics (Phase 10.1):
      - DNS_RESOLUTION_FAILED
      - CONNECTION_REFUSED
      - CONNECTION_TIMEOUT
      - TLS_HANDSHAKE_FAILED
      - NETWORK_POLICY_BLOCKED
      - NAVIGATION_TIMEOUT
      - BROWSER_INITIALIZATION_FAILED
      - HTTP_REQUEST_FAILED
    """
    err_str = str(exc).lower()
    exc_type = type(exc).__name__

    if "getaddrinfo failed" in err_str or "gaierror" in err_str or "err_name_not_resolved" in err_str or "nosuchhost" in err_str:
        return ("DNS_RESOLUTION_FAILED", f"DNS resolution failed: Hostname could not be resolved ({exc_type}: {exc})")
    if "connectionrefused" in err_str or "10061" in err_str or "refused" in err_str or "err_connection_refused" in err_str:
        return ("CONNECTION_REFUSED", f"TCP connection actively refused by target port ({exc_type}: {exc})")
    if "timeout" in err_str or "timed out" in err_str or "err_connection_timed_out" in err_str:
        return ("CONNECTION_TIMEOUT", f"Connection or read timed out ({exc_type}: {exc})")
    if "ssl" in err_str or "certificate" in err_str or "handshake" in err_str or "err_ssl_" in err_str or "err_cert_" in err_str:
        return ("TLS_HANDSHAKE_FAILED", f"TLS negotiation failed ({exc_type}: {exc})")
    if "err_blocked_by_client" in err_str or "network_access_denied" in err_str or "ssrf" in err_str:
        return ("NETWORK_POLICY_BLOCKED", f"Network policy or SSRF security rule blocked connection ({exc_type}: {exc})")
    if "navigation timeout" in err_str or "timeout" in exc_type.lower():
        return ("NAVIGATION_TIMEOUT", f"Browser navigation exceeded timeout boundary ({exc_type}: {exc})")
    if "executable doesn't exist" in err_str or ("browser" in err_str and "launch" in err_str):
        return ("BROWSER_INITIALIZATION_FAILED", f"Browser automation initialization failed ({exc_type}: {exc})")
    return ("HTTP_REQUEST_FAILED", f"HTTP network request failed: {exc_type} - {exc}")



# Sensitive browser sensor and device permission API signatures (CamPhish, TrackUrl, etc.)
SENSOR_PATTERNS = {
    "GPS_GEOLOCATION": [
        r"navigator\.geolocation\.getCurrentPosition",
        r"navigator\.geolocation\.watchPosition",
        r"navigator\.geolocation",
    ],
    "CAMERA_MICROPHONE": [
        r"navigator\.mediaDevices\.getUserMedia",
        r"navigator\.getUserMedia",
        r"webkitGetUserMedia",
        r"mozGetUserMedia",
        r"video\s*:\s*true",
        r"audio\s*:\s*true",
    ],
    "NOTIFICATIONS": [
        r"Notification\.requestPermission",
    ],
}

# Deceptive lures commonly combined with sensor/permission theft
DECEPTIVE_LURE_PATTERNS = [
    r"(?i)\b(online\s*meeting|join\s*meeting|video\s*conference|meeting\s*room)\b",
    r"(?i)\b(camera\s*test|webcam\s*test|mic\s*test|audio\s*test)\b",
    r"(?i)\b(live\s*stream|live\s*youtube\s*tv|youtube\s*live|watch\s*live)\b",
    r"(?i)\b(festival\s*wishing|festival\s*greeting|greeting\s*card|happy\s*festival)\b",
    r"(?i)\b(verify\s*your\s*age|age\s*verification|prove\s*you\s*are\s*human)\b",
]

# Exfiltration script endpoints
EXFILTRATION_PATTERNS = [
    r"(?i)(?:action|href|url|endpoint)[\s=:\'\"\`]+[^\'\"]*(?:post\.php|login\.php|location\.php|grab\.php|log\.php|submit\.php)",
    r"https?://(?:api\.)?telegram\.org/bot",
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks",
    r"https?://webhook\.site",
]


class LiveIntelScraper:
    """
    Centralized Real-Time Web Intelligence & Forensic Crawler for CyberGuard.
    """

    @staticmethod
    def is_anti_bot_challenge(status_code: int, html_content: str) -> bool:
        low = (html_content or "").lower()
        if "cf-browser-verification" in low or "challenge-running" in low or "turnstile" in low:
            return True
        if ("cloudflare" in low or "ray id" in low) and (
            "just a moment..." in low or "attention required" in low or "checking your browser" in low
        ):
            return True
        if status_code in (403, 503) and ("cloudflare" in low or "ddos" in low or "challenge" in low or "bot" in low):
            return True
        return False

    @staticmethod
    def search_duckduckgo_osint(query: str, max_results: int = 4) -> List[Dict[str, str]]:
        """
        Query DuckDuckGo for live OSINT threat intelligence, news, and security forums.
        """
        results: List[Dict[str, str]] = []
        try:
            try:
                from duckduckgo_search import DDGS
                with DDGS() as ddgs:
                    raw_res = list(ddgs.text(query, max_results=max_results))
                    for r in raw_res:
                        results.append({
                            "title": r.get("title", ""),
                            "link": r.get("href") or r.get("link", ""),
                            "snippet": r.get("body") or r.get("snippet", ""),
                        })
            except ImportError:
                import urllib.request
                import json
                enc_q = urllib.parse.quote(query)
                req = urllib.request.Request(
                    f"https://html.duckduckgo.com/html/?q={enc_q}",
                    headers={"User-Agent": "CyberGuard-SOC-Auditor/2.0"}
                )
                with urllib.request.urlopen(req, timeout=3.5) as resp:
                    html_data = resp.read().decode("utf-8", errors="ignore")
                    matches = re.findall(r'<a class="result__snippet[^>]*>(.*?)</a>', html_data)
                    for m in matches[:max_results]:
                        clean = re.sub(r'<[^>]+>', '', m).strip()
                        if clean:
                            results.append({
                                "title": f"DuckDuckGo OSINT: {query[:30]}",
                                "link": f"https://duckduckgo.com/?q={enc_q}",
                                "snippet": clean[:250],
                            })
        except Exception as e:
            logger.debug(f"DuckDuckGo OSINT search notice for '{query}': {e}")
        return results

    @staticmethod
    def extract_with_trafilatura(html_content: str) -> Dict[str, Any]:
        """
        Extract clean text and structured metadata using Trafilatura.
        """
        res = {"clean_text": "", "title": "", "author": "", "date": ""}
        if not html_content:
            return res
        try:
            import trafilatura
            text = trafilatura.extract(html_content, include_comments=False, include_tables=False)
            res["clean_text"] = text or ""
            metadata = trafilatura.extract_metadata(html_content)
            if metadata:
                res["title"] = metadata.title or ""
                res["author"] = metadata.author or ""
                res["date"] = metadata.date or ""
        except Exception as exc:
            logger.debug(f"Trafilatura extraction notice: {exc}")
            clean_str = re.sub(r'<[^>]+>', ' ', html_content)
            res["clean_text"] = ' '.join(clean_str.split())[:1000]
        return res

    @staticmethod
    def inspect_dom_with_bs4(html_content: str, base_url: str = "") -> Dict[str, Any]:
        """
        Parse HTML with BeautifulSoup to detect:
          - Credential harvesting forms (password, OTP, PIN, token, card inputs)
          - External form action targets & PHP exfiltration endpoints
          - Sensitive sensor permissions (Camera, Mic, GPS)
          - Deceptive social engineering lures (fake meetings, greeting traps)
        """
        inspection: Dict[str, Any] = {
            "title": "",
            "meta_description": "",
            "has_credential_forms": False,
            "has_password_field": False,
            "has_otp_or_pin_field": False,
            "credential_input_count": 0,
            "has_sensor_probes": False,
            "probed_sensors": [],
            "social_engineering_lures": [],
            "form_actions": [],
            "external_scripts": [],
            "suspicious_indicators": [],
        }

        if not html_content:
            return inspection

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, "html.parser")

            if soup.title and soup.title.string:
                inspection["title"] = soup.title.string.strip()

            meta_desc = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
            if meta_desc and meta_desc.get("content"):
                inspection["meta_description"] = str(meta_desc.get("content")).strip()

            base_domain = urllib.parse.urlparse(base_url).netloc.lower() if base_url else ""

            # 1. Forms & Form Actions
            forms = soup.find_all("form")
            for f in forms:
                action = f.get("action", "")
                if action:
                    inspection["form_actions"].append(action)
                    if base_domain:
                        act_parsed = urllib.parse.urlparse(action)
                        if act_parsed.netloc and act_parsed.netloc.lower() != base_domain:
                            inspection["suspicious_indicators"].append(
                                f"Form target points to external domain: {act_parsed.netloc}"
                            )

            # 2. Input Fields
            inputs = soup.find_all("input")
            cred_count = 0
            for inp in inputs:
                itype = (inp.get("type") or "").lower()
                iname = (inp.get("name") or "").lower()
                iid = (inp.get("id") or "").lower()
                ihint = f"{iname} {iid}"

                if itype == "password" or "pass" in ihint:
                    inspection["has_password_field"] = True
                    inspection["has_credential_forms"] = True
                    cred_count += 1

                if any(k in ihint for k in ["otp", "pin", "token", "ssn", "cvv", "card"]):
                    inspection["has_otp_or_pin_field"] = True
                    inspection["has_credential_forms"] = True
                    cred_count += 1

            inspection["credential_input_count"] = cred_count

            if inspection["has_password_field"]:
                inspection["suspicious_indicators"].append("Target page contains password input field (Potential credential harvester)")
            if inspection["has_otp_or_pin_field"]:
                inspection["suspicious_indicators"].append("Target page probes for OTP/PIN/Financial identity values")

            # 3. Sensitive Browser Sensor Probes (Camera, Mic, GPS)
            raw_text = html_content
            for sensor_name, patterns in SENSOR_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, raw_text):
                        if sensor_name not in inspection["probed_sensors"]:
                            inspection["probed_sensors"].append(sensor_name)
                            inspection["has_sensor_probes"] = True
                            inspection["suspicious_indicators"].append(
                                f"Page scripts probe sensitive hardware sensors: {sensor_name}"
                            )
                        break

            # 4. Deceptive Social Engineering Lures
            full_text_sample = ((inspection["title"] or "") + " " + soup.get_text()[:4000]).lower()
            for lure_pat in DECEPTIVE_LURE_PATTERNS:
                m = re.search(lure_pat, full_text_sample)
                if m:
                    lure_str = m.group(0).strip()
                    if lure_str not in inspection["social_engineering_lures"]:
                        inspection["social_engineering_lures"].append(lure_str)
                        inspection["suspicious_indicators"].append(
                            f"Deceptive social engineering lure detected: '{lure_str}'"
                        )

            # 5. External script sources
            scripts = soup.find_all("script", src=True)
            for s in scripts[:8]:
                src = s.get("src", "")
                if src:
                    inspection["external_scripts"].append(src)

        except Exception as exc:
            logger.debug(f"BeautifulSoup DOM inspection notice: {exc}")

        return inspection

    @staticmethod
    def _is_safe_target_url(url: str) -> bool:
        """SSRF validator to reject loopback, internal, and cloud metadata targets."""
        try:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or "").lower()
            if not host:
                return False
            if host in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
                return False
            if host.endswith(".local") or host.endswith(".internal"):
                return False
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return False
                if str(ip) == "169.254.169.254":
                    return False
            except ValueError:
                pass
            return True
        except Exception:
            return False

    @staticmethod
    async def inspect_live_page(url: str, timeout_sec: float = 6.0) -> Dict[str, Any]:
        """
        Inspect live page via Playwright with fast fallback to HTTP + Trafilatura + BeautifulSoup.
        Explicitly tracks inspection states (UNREACHABLE, COMPLETED, SSRF_BLOCKED, ANTI_BOT_CHALLENGE).
        Guarantees that unreachable crawler states are NEVER reported as clean forms (Defect C fix).
        """
        page_intel: Dict[str, Any] = {
            "url": url,
            "status": "UNREACHABLE",
            "status_code": 0,
            "title": "",
            "meta_description": "",
            "clean_body_text": "",
            "failure_reason": None,
            "dom_inspection": {
                "has_credential_forms": False,
                "has_password_field": False,
                "has_otp_or_pin_field": False,
                "credential_input_count": 0,
                "has_sensor_probes": False,
                "probed_sensors": [],
                "social_engineering_lures": [],
                "form_actions": [],
                "external_scripts": [],
                "suspicious_indicators": [],
            },
            "crawl4ai_markdown": None,
            "rendering_engine": "HTTP+BS4",
            "is_live": False,
            "credential_inspection_state": "NOT_ASSESSED",
            "sensor_permission_state": "NOT_ASSESSED",
            "network_telemetry_state": "NOT_ASSESSED",
            "network_traffic": None,
        }

        # SSRF Pre-flight validation
        if not LiveIntelScraper._is_safe_target_url(url):
            page_intel["status"] = "SSRF_BLOCKED"
            page_intel["error"] = "Target points to private, loopback, or metadata network address."
            page_intel["failure_reason"] = "Outbound connection blocked: Target address blocked by CyberGuard SSRF protection."
            page_intel["credential_inspection_state"] = "NOT_ASSESSED"
            page_intel["sensor_permission_state"] = "NOT_ASSESSED"
            page_intel["network_telemetry_state"] = "NOT_ASSESSED"
            return page_intel

        # 1. Fast HTTP + Trafilatura + BeautifulSoup evaluation
        html_content = ""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout_sec, follow_redirects=True, verify=False) as client:
                resp = await client.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberGuard/2.0 Security Auditor"}
                )
                page_intel["status_code"] = resp.status_code
                html_content = resp.text

                # Anti-bot challenge detection (Cloudflare / Turnstile)
                is_cf_challenge = LiveIntelScraper.is_anti_bot_challenge(resp.status_code, html_content)
                if is_cf_challenge:
                    page_intel["status"] = "ANTI_BOT_CHALLENGE"
                    page_intel["failure_reason"] = "Cloudflare anti-bot challenge or Turnstile verification gate encountered."
                    page_intel["is_live"] = False
                    page_intel["credential_inspection_state"] = "NOT_ASSESSED"
                    page_intel["sensor_permission_state"] = "NOT_ASSESSED"
                    page_intel["network_telemetry_state"] = "NOT_ASSESSED"
                    page_intel["network_traffic"] = {
                        "total_requests": 1,
                        "total_responses": 1,
                        "failed_requests": 0,
                        "unique_destinations": [urllib.parse.urlparse(url).netloc],
                        "requests_sample": [{"url": url, "method": "GET", "status_code": resp.status_code}],
                        "destinations": {},
                        "suspicious_requests": [],
                        "exfiltration_events": [],
                        "sensor_probes_observed": [],
                        "traffic_patterns_detected": ["Anti-bot challenge gate encountered; content inspection inconclusive."],
                        "network_risk_score": 0.0,
                        "summary": "Anti-bot challenge prevented automated crawler inspection.",
                        "state": "ANTI_BOT_CHALLENGE",
                    }
                    return page_intel

                page_intel["is_live"] = (resp.status_code < 400)
                if resp.status_code < 400:
                    page_intel["status"] = "COMPLETED"
                else:
                    page_intel["status"] = f"HTTP_{resp.status_code}"
                    page_intel["failure_reason"] = f"HTTP server returned error status code {resp.status_code}"
        except Exception as exc:
            fail_code, fail_msg = classify_network_failure(exc, url)
            logger.debug(f"HTTP live fetch notice for {url}: {fail_code} - {fail_msg}")
            page_intel["status"] = fail_code
            page_intel["failure_reason"] = fail_msg
            page_intel["is_live"] = False
            page_intel["credential_inspection_state"] = "NOT_ASSESSED"
            page_intel["sensor_permission_state"] = "NOT_ASSESSED"
            page_intel["network_telemetry_state"] = "NOT_ASSESSED"
            page_intel["network_traffic"] = {
                "total_requests": 0,
                "total_responses": 0,
                "failed_requests": 1,
                "unique_destinations": [],
                "requests_sample": [],
                "destinations": {},
                "suspicious_requests": [],
                "exfiltration_events": [],
                "sensor_probes_observed": [],
                "traffic_patterns_detected": [],
                "network_risk_score": 0.0,
                "summary": f"Target unreachable: {fail_msg}",
                "state": "NOT_ASSESSED",
            }
            return page_intel

        if html_content and page_intel["is_live"]:
            dom = LiveIntelScraper.inspect_dom_with_bs4(html_content, base_url=url)
            traf = LiveIntelScraper.extract_with_trafilatura(html_content)
            page_intel["title"] = dom.get("title") or traf.get("title") or ""
            page_intel["meta_description"] = dom.get("meta_description") or ""
            page_intel["clean_body_text"] = traf.get("clean_text") or ""
            page_intel["dom_inspection"] = dom

            # Set explicit states based on verified inspection
            if dom.get("has_credential_forms"):
                page_intel["credential_inspection_state"] = "HARVESTING_DETECTED"
            else:
                page_intel["credential_inspection_state"] = "CLEAN_NO_FORMS"

            if dom.get("has_sensor_probes"):
                page_intel["sensor_permission_state"] = "PERMISSION_PROBE_DETECTED"
            else:
                page_intel["sensor_permission_state"] = "CLEAN_NO_PROBES"

        # 2. Dynamic Playwright rendering if dynamic scripts, credential forms, or sensor probes exist
        need_dynamic = (
            page_intel["is_live"]
            and (
                page_intel["dom_inspection"].get("has_credential_forms")
                or page_intel["dom_inspection"].get("has_sensor_probes")
                or not page_intel["clean_body_text"]
                or "trycloudflare.com" in url
            )
        )
        if need_dynamic:
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    # Strictly DENY all permissions during inspection (never grant camera, microphone, geolocation)
                    context = await browser.new_context(
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberGuard/2.0 Security Auditor",
                        permissions=[],
                        ignore_https_errors=True,
                    )
                    page = await context.new_page()

                    dynamic_requests: List[NetworkRequestRecord] = [
                        NetworkRequestRecord(url=url, method="GET", resource_type="document")
                    ]

                    def on_req(req):
                        try:
                            dynamic_requests.append(NetworkRequestRecord(
                                url=req.url,
                                method=req.method,
                                resource_type=req.resource_type,
                            ))
                        except Exception:
                            pass

                    def on_resp(res):
                        try:
                            for r in reversed(dynamic_requests):
                                if r.url == res.url:
                                    r.status_code = res.status
                                    r.status_text = res.status_text
                                    break
                        except Exception:
                            pass

                    page.on("request", on_req)
                    page.on("response", on_resp)

                    # Sensitive sensor probe instrumentation script (intercepts without granting access)
                    init_script = """
                    window.__cyberguard_telemetry = { sensor_probes: [] };
                    if (navigator.geolocation) {
                        navigator.geolocation.getCurrentPosition = function(s, e) {
                            window.__cyberguard_telemetry.sensor_probes.push({
                                api: 'navigator.geolocation.getCurrentPosition',
                                sensor: 'GEOLOCATION',
                                timestamp: Date.now()
                            });
                            if (e) e({ code: 1, message: 'Permission denied by CyberGuard Sandbox' });
                        };
                        navigator.geolocation.watchPosition = function(s, e) {
                            window.__cyberguard_telemetry.sensor_probes.push({
                                api: 'navigator.geolocation.watchPosition',
                                sensor: 'GEOLOCATION',
                                timestamp: Date.now()
                            });
                            if (e) e({ code: 1, message: 'Permission denied by CyberGuard Sandbox' });
                            return 1;
                        };
                    }
                    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
                        navigator.mediaDevices.getUserMedia = function(c) {
                            var types = [];
                            if (c && c.video) types.push('CAMERA');
                            if (c && c.audio) types.push('MICROPHONE');
                            window.__cyberguard_telemetry.sensor_probes.push({
                                api: 'navigator.mediaDevices.getUserMedia',
                                sensor: types.join('_') || 'CAMERA_MICROPHONE',
                                timestamp: Date.now()
                            });
                            return Promise.reject(new DOMException('Permission denied by CyberGuard Sandbox', 'NotAllowedError'));
                        };
                    }
                    if (window.Notification && Notification.requestPermission) {
                        Notification.requestPermission = function() {
                            window.__cyberguard_telemetry.sensor_probes.push({
                                api: 'Notification.requestPermission',
                                sensor: 'NOTIFICATIONS',
                                timestamp: Date.now()
                            });
                            return Promise.resolve('denied');
                        };
                    }
                    """
                    await page.add_init_script(init_script)

                    await page.goto(url, timeout=int(timeout_sec * 1000), wait_until="domcontentloaded")
                    dyn_title = await page.title()
                    dyn_html = await page.content()

                    telemetry_data = await page.evaluate("() => window.__cyberguard_telemetry || { sensor_probes: [] }")
                    await browser.close()

                    if dyn_title and not page_intel["title"]:
                        page_intel["title"] = dyn_title
                    if dyn_html:
                        dyn_dom = LiveIntelScraper.inspect_dom_with_bs4(dyn_html, base_url=url)
                        probes_from_js = telemetry_data.get("sensor_probes", [])
                        for pr in probes_from_js:
                            s_name = pr.get("sensor")
                            if s_name and s_name not in dyn_dom["probed_sensors"]:
                                dyn_dom["probed_sensors"].append(s_name)
                                dyn_dom["has_sensor_probes"] = True

                        page_intel["dom_inspection"].update(dyn_dom)
                        page_intel["rendering_engine"] = "Playwright Chromium + BS4"
                        if dyn_dom.get("has_credential_forms"):
                            page_intel["credential_inspection_state"] = "HARVESTING_DETECTED"
                        if dyn_dom.get("has_sensor_probes"):
                            page_intel["sensor_permission_state"] = "PERMISSION_PROBE_DETECTED"

                    # Traffic intelligence from Playwright session
                    traffic_rep = NetworkTrafficIntelligenceEngine.analyze_traffic(
                        base_url=url,
                        requests=dynamic_requests,
                        sensor_probes=telemetry_data.get("sensor_probes", []),
                        is_ephemeral_tunnel=("trycloudflare.com" in url or "ngrok" in url),
                    )
                    page_intel["network_traffic"] = traffic_rep.to_dict()
                    page_intel["network_telemetry_state"] = "EXFILTRATION_DETECTED" if traffic_rep.exfiltration_events else "CLEAN_TRAFFIC"
            except Exception as pw_err:
                logger.debug(f"Playwright dynamic rendering notice for {url}: {pw_err}")

        # Baseline network traffic report if Playwright was not launched
        if not page_intel.get("network_traffic") and page_intel["is_live"]:
            baseline_traffic = NetworkTrafficIntelligenceEngine.analyze_traffic(
                base_url=url,
                requests=[NetworkRequestRecord(url=url, method="GET", resource_type="document", status_code=page_intel["status_code"])],
                sensor_probes=[{"sensor": s} for s in page_intel["dom_inspection"].get("probed_sensors", [])],
                is_ephemeral_tunnel=("trycloudflare.com" in url or "ngrok" in url),
            )
            page_intel["network_traffic"] = baseline_traffic.to_dict()
            page_intel["network_telemetry_state"] = "EXFILTRATION_DETECTED" if baseline_traffic.exfiltration_events else "CLEAN_TRAFFIC"

        # 3. Deep crawling via Crawl4AI if content is substantial
        if page_intel["is_live"]:
            try:
                from crawl4ai import AsyncWebCrawler
                async with AsyncWebCrawler(verbose=False) as crawler:
                    res = await asyncio.wait_for(crawler.arun(url=url), timeout=timeout_sec)
                    if res and res.markdown:
                        page_intel["crawl4ai_markdown"] = res.markdown[:1200]
            except Exception as c4_err:
                logger.debug(f"Crawl4AI execution notice for {url}: {c4_err}")

        return page_intel

    @classmethod
    async def analyze_indicator_full(
        cls,
        indicator: str,
        category: str = "url",
        vt_report: Optional[Dict[str, Any]] = None,
        uh_report: Optional[Dict[str, Any]] = None,
        context_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main sequential execution:
          1. DuckDuckGo live OSINT web search
          2. Trafilatura clean extraction + BeautifulSoup credential form audit (if URL)
          3. Playwright headless inspection (if dynamic content)
          4. Crawl4AI markdown extraction (if applicable)
          5. Grounded Qwen LLM synthesis alongside VirusTotal & URLhaus
        """
        start_time = asyncio.get_event_loop().time()
        meta = context_metadata or {}
        is_url = category in ("url", "embedded_url") or indicator.startswith("http://") or indicator.startswith("https://")
        is_hash = category in ("hash", "apk_hash", "file_hash") or (len(indicator) in (32, 40, 64) and re.match(r'^[a-fA-F0-9]+$', indicator))
        is_package = category in ("package", "app_package") or meta.get("package_name")

        # Early check: local, loopback, or private indicator check (prevents SSRF and local false positives)
        is_local_ind = False
        if is_url:
            parsed = urllib.parse.urlparse(indicator)
            hostname = parsed.hostname or ""
            if hostname.lower() in ("localhost", "127.0.0.1", "::1") or hostname.lower().endswith(".local") or hostname.lower().endswith(".internal"):
                is_local_ind = True
            else:
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_reserved:
                        is_local_ind = True
                except ValueError:
                    pass
        if is_local_ind or meta.get("is_local") or meta.get("scope") == "LOCAL_OR_PRIVATE":
            return {
                "status": "NOT_APPLICABLE",
                "indicator": indicator,
                "category": category,
                "url_sha256": hashlib.sha256(indicator.encode("utf-8")).hexdigest() if is_url else None,
                "message": "Live web scraper not applicable to local development or private indicators.",
                "osint": {"engine": "DuckDuckGo Search", "hits_count": 0, "results": []},
                "live_page_inspection": {
                    "is_live": False,
                    "status": "NOT_APPLICABLE",
                    "rendering_engine": "HTTP+BS4",
                    "credential_inspection_state": "NOT_APPLICABLE",
                    "sensor_permission_state": "NOT_APPLICABLE",
                },
                "qwen_llm_synthesis": {"executive_briefing": None, "containment_recommendations": []}
            }

        # Check for explicit test fixture injection (for deterministic offline testing)
        if meta.get("mock_live_page"):
            mock_data = meta["mock_live_page"]
            return {
                "status": "COMPLETED",
                "indicator": indicator,
                "category": category,
                "url_sha256": hashlib.sha256(indicator.encode("utf-8")).hexdigest() if is_url else None,
                "osint": meta.get("mock_osint", {"engine": "DuckDuckGo Search", "hits_count": 0, "results": []}),
                "live_page_inspection": mock_data,
                "qwen_llm_synthesis": {
                    "executive_briefing": "Mocked test fixture analysis completed.",
                    "containment_recommendations": []
                }
            }

        # 1. Real-time DuckDuckGo OSINT & 2. Live Page Inspection executed concurrently with bounded timeouts
        search_query = indicator
        if is_package:
            search_query = f"{meta.get('app_name', '')} {meta.get('package_name', indicator)} android malware threat"
        elif is_hash:
            search_query = f"{indicator} virustotal malware hash report"
        elif is_url:
            parsed = urllib.parse.urlparse(indicator)
            search_query = f'"{parsed.netloc}" phishing scam fraud'

        async def _fetch_osint():
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(cls.search_duckduckgo_osint, search_query.strip(), 3),
                    timeout=4.0
                )
            except Exception as e:
                logger.debug(f"DuckDuckGo OSINT notice: {e}")
                return []

        async def _fetch_page():
            if is_url:
                try:
                    return await asyncio.wait_for(
                        cls.inspect_live_page(indicator, timeout_sec=4.0),
                        timeout=5.0
                    )
                except Exception as e:
                    logger.debug(f"Live page inspection notice: {e}")
            return {
                "is_live": False,
                "status": "UNREACHABLE",
                "status_code": 0,
                "failure_reason": "Live inspection could not reach target host.",
                "dom_inspection": {},
                "rendering_engine": "HTTP+BS4",
                "credential_inspection_state": "NOT_ASSESSED",
                "sensor_permission_state": "NOT_ASSESSED",
                "network_telemetry_state": "NOT_ASSESSED",
                "network_traffic": {
                    "total_requests": 0,
                    "total_responses": 0,
                    "failed_requests": 1,
                    "unique_destinations": [],
                    "requests_sample": [],
                    "destinations": {},
                    "suspicious_requests": [],
                    "exfiltration_events": [],
                    "sensor_probes_observed": [],
                    "traffic_patterns_detected": [],
                    "network_risk_score": 0.0,
                    "summary": "Target unreachable; no live network traffic recorded.",
                    "state": "NOT_ASSESSED",
                },
            }

        ddg_hits, page_data = await asyncio.gather(_fetch_osint(), _fetch_page())

        # 3. Compute Cryptographic URL Hash
        url_sha256 = None
        if is_url:
            url_sha256 = hashlib.sha256(indicator.strip().encode("utf-8")).hexdigest()

        # 4. Synthesize with Cybersecurity Reasoning Engine (fast deterministic baseline)
        qwen_briefing = None
        qwen_recommendations: List[str] = []
        try:
            from backend.analysis.llm_analyst import get_llm_analyst
            analyst = get_llm_analyst()

            llm_payload = {
                "source": "live_web_threat_scraper",
                "indicator": indicator,
                "category": category,
                "url_sha256": url_sha256,
                "osint_search_hits": ddg_hits,
                "page_title": page_data.get("title", ""),
                "page_description": page_data.get("meta_description", ""),
                "credential_probe_detected": page_data.get("dom_inspection", {}).get("has_credential_forms", False),
                "sensor_probe_detected": page_data.get("dom_inspection", {}).get("has_sensor_probes", False),
                "suspicious_indicators": page_data.get("dom_inspection", {}).get("suspicious_indicators", []),
                "extracted_body": page_data.get("clean_body_text", "")[:350],
                "virustotal": vt_report or {},
                "urlhaus": uh_report or {},
                "threat_context": meta,
            }
            res = analyst.analyze(llm_payload, use_neural=False)
            qwen_briefing = res.get("executive_briefing") or res.get("executive_summary")
            qwen_recommendations = (
                res.get("incident_response_playbook", {}).get("immediate_containment")
                or res.get("immediate_containment")
                or []
            )
        except Exception as llm_err:
            logger.debug(f"LLM live synthesis notice: {llm_err}")

        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000.0

        dom_insp = page_data.get("dom_inspection", {})
        is_live_flag = page_data.get("is_live", False)

        return {
            "status": "COMPLETED",
            "indicator": indicator,
            "category": category,
            "url_sha256": url_sha256,
            "duration_ms": round(duration_ms, 2),
            "osint": {
                "engine": "DuckDuckGo Search",
                "query": search_query,
                "hits_count": len(ddg_hits),
                "results": ddg_hits,
            },
            "live_page_inspection": {
                "is_live": is_live_flag,
                "status": page_data.get("status", "COMPLETED" if is_live_flag else "UNREACHABLE"),
                "status_code": page_data.get("status_code", 0),
                "title": page_data.get("title", ""),
                "clean_text_snippet": (page_data.get("clean_body_text", "")[:250]),
                "rendering_engine": page_data.get("rendering_engine", "HTTP+BS4"),
                "has_credential_forms": dom_insp.get("has_credential_forms", False),
                "has_password_field": dom_insp.get("has_password_field", False),
                "has_otp_or_pin_field": dom_insp.get("has_otp_or_pin_field", False),
                "has_sensor_probes": dom_insp.get("has_sensor_probes", False),
                "probed_sensors": dom_insp.get("probed_sensors", []),
                "social_engineering_lures": dom_insp.get("social_engineering_lures", []),
                "suspicious_indicators": dom_insp.get("suspicious_indicators", []),
                "form_actions": dom_insp.get("form_actions", []),
                "crawl4ai_markdown_snippet": (page_data.get("crawl4ai_markdown", "")[:250]) if page_data.get("crawl4ai_markdown") else None,
                "failure_reason": page_data.get("failure_reason"),
                "credential_inspection_state": page_data.get(
                    "credential_inspection_state",
                    ("HARVESTING_DETECTED" if dom_insp.get("has_credential_forms") else ("CLEAN_NO_FORMS" if is_live_flag else "NOT_ASSESSED"))
                ),
                "sensor_permission_state": page_data.get(
                    "sensor_permission_state",
                    ("PERMISSION_PROBE_DETECTED" if dom_insp.get("has_sensor_probes") else ("CLEAN_NO_PROBES" if is_live_flag else "NOT_ASSESSED"))
                ),
                "network_telemetry_state": page_data.get("network_telemetry_state", ("CLEAN_TRAFFIC" if is_live_flag else "NOT_ASSESSED")),
                "network_traffic": page_data.get("network_traffic") or {
                    "total_requests": 0,
                    "total_responses": 0,
                    "failed_requests": 0 if is_live_flag else 1,
                    "unique_destinations": [],
                    "requests_sample": [],
                    "destinations": {},
                    "suspicious_requests": [],
                    "exfiltration_events": [],
                    "sensor_probes_observed": [],
                    "traffic_patterns_detected": [],
                    "network_risk_score": 0.0,
                    "summary": "Live inspection completed with zero additional network requests." if is_live_flag else "Target unreachable; no live network traffic recorded.",
                    "state": "CLEAN_TRAFFIC" if is_live_flag else "NOT_ASSESSED",
                },
            },
            "qwen_llm_synthesis": {
                "model": "Qwen3.5-4B-Q4_K_M",
                "executive_briefing": qwen_briefing,
                "containment_recommendations": qwen_recommendations,
            },
        }


_global_scraper: Optional[LiveIntelScraper] = None


def get_live_intel_scraper() -> LiveIntelScraper:
    global _global_scraper
    if _global_scraper is None:
        _global_scraper = LiveIntelScraper()
    return _global_scraper
