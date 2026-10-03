import time
import urllib.parse
import logging
import uuid
import copy
from typing import List, Dict, Any, Optional

from backend.config import get_settings
from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel, IncidentStatus
)
from backend.threats.virustotal import get_virustotal_provider
from backend.threats.urlhaus import get_urlhaus_provider
from backend.threats.correlation import ThreatIntelCorrelationEngine, CorrelationStatus
from backend.analysis.url_resolver import (
    SafeURLResolver, ResolutionResult, ResolutionStatus, AssociatedIOC, PageMetadata, RedirectHop
)

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """
    Authoritative URL Threat Intelligence Analyzer for CyberGuard.

    Executes a multi-stage sequential verification pipeline:
      1. URL Normalization & Local / Private network detection
      2. Safe Step-by-Step URL Resolution & Redirect Forensics (strict SSRF protection)
      3. CyberGuard Local Heuristics
      4. VirusTotal Multi-Engine Intelligence (Provider 1, terminal state awaited/polled)
      5. Landing-Page & Provider Report Disambiguation (URLhaus Record & Associated Threat IOCs)
      6. URLhaus Malware URL Intelligence (Provider 2, executed after VT terminal state)
      7. Cross-Provider Correlation (Scope-aware matching)
      8. CyberGuard Authoritative Risk Engine & Final Verdict Gate
      9. Structured Threat Intelligence Payload generation (Zero field overwrites, full backward compatibility)
    """

    def __init__(self, config=None):
        self.config = config or get_settings()
        self.vt_provider = get_virustotal_provider(self.config)
        self.urlhaus_provider = get_urlhaus_provider(self.config)
        self.correlation_engine = ThreatIntelCorrelationEngine()
        self.resolver = SafeURLResolver()

    async def analyze(
        self,
        url: str,
        source: str = "url_submission",
        correlation_id: str = None,
        poll_vt: bool = True,
        max_vt_poll_sec: float = 4.0,
        local_only: bool = False,
    ) -> ThreatEvent:
        start_time = time.time()
        analysis_id = correlation_id or str(uuid.uuid4())
        evidences: List[Evidence] = []
        local_risk_score = 0.0

        # ── STAGE 1: Normalization & Local/Private Target Classification ──────
        try:
            parsed_url = urllib.parse.urlparse(url)
            hostname = (parsed_url.hostname or "").lower()
            path = parsed_url.path or ""
            scheme = (parsed_url.scheme or "http").lower()
            port = parsed_url.port
            canonical_url = urllib.parse.urlunparse((
                scheme,
                f"{hostname}:{port}" if port and port not in (80, 443) else hostname,
                path,
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment,
            ))
        except Exception as e:
            canonical_url = url
            hostname = ""
            path = ""

        is_local = self._is_local_or_private(hostname)
        logger.info(f"analysis_id={analysis_id} stage=URL_NORMALIZATION status=COMPLETED canonical_url={canonical_url} is_local={is_local}")

        # ── STAGE 2: Safe Step-by-Step URL Resolution & Redirect Chain ────────
        res_start = time.time()
        resolution: Optional[ResolutionResult] = None
        if not is_local and not local_only:
            try:
                resolution = await self.resolver.resolve(canonical_url)
                logger.info(
                    f"analysis_id={analysis_id} stage=URL_RESOLUTION status={resolution.status.value} "
                    f"hops={resolution.redirect_count} terminal={resolution.terminal_url} "
                    f"http_status={resolution.terminal_status_code}"
                )
            except Exception as e:
                logger.error(f"analysis_id={analysis_id} stage=URL_RESOLUTION status=ERROR error={e}")
                resolution = ResolutionResult(
                    original_url=canonical_url,
                    terminal_url=canonical_url,
                    status=ResolutionStatus.NETWORK_ERROR,
                    redirect_count=0,
                    redirect_chain=[],
                    terminal_status_code=None,
                    page_metadata=PageMetadata(),
                    error_message=str(e),
                )
        res_duration_ms = (time.time() - res_start) * 1000.0

        # SSRF / Redirect security checks
        if resolution and resolution.status == ResolutionStatus.BLOCKED_ORIGINAL_URL:
            # Original URL blocked by SSRF validation
            evidences.append(Evidence(
                evidence_type="ssrf_blocked_url",
                description=resolution.error_message or "Original URL blocked by SSRF protection.",
                value=canonical_url,
                severity_contribution=1.0,
                source="CyberGuardResolver"
            ))
            return self._build_event(
                url=canonical_url,
                source=source,
                correlation_id=analysis_id,
                severity=RiskLevel.CRITICAL,
                local_risk_score=1.0,
                is_pending=False,
                evidences=evidences,
                vt_report={"status": "NOT_APPLICABLE", "provider": "VirusTotal", "indicator": canonical_url, "summary": {"malicious": 0, "total_engines": 0}},
                uh_report={"status": "NOT_APPLICABLE", "provider": "URLhaus", "indicator": canonical_url, "matched": False},
                correlation={"status": "NOT_APPLICABLE"},
                is_local=False,
                start_time=start_time,
                timings={"local_ms": 0.0, "vt_ms": 0.0, "uh_ms": 0.0, "corr_ms": 0.0, "resolution_ms": res_duration_ms},
                threat_cat=ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY,
                classification="MALICIOUS",
                resolution=resolution,
                custom_summary="Outbound connection blocked: Target address blocked by CyberGuard SSRF protection.",
                custom_reasoning=resolution.error_message or "Host resolved to internal, loopback, or cloud metadata address.",
            )

        if resolution and resolution.status == ResolutionStatus.BLOCKED_REDIRECT_TARGET:
            # Redirect target was private/internal (SSRF attack in redirect chain)
            evidences.append(Evidence(
                evidence_type="ssrf_blocked_redirect",
                description=resolution.error_message or "Redirect target attempted to access internal/private destination (SSRF attack blocked).",
                value=resolution.terminal_url,
                severity_contribution=1.0,
                source="CyberGuardResolver"
            ))
            local_risk_score = 1.0

        elif resolution and resolution.status == ResolutionStatus.REDIRECT_LOOP:
            evidences.append(Evidence(
                evidence_type="redirect_loop",
                description=resolution.error_message or "Redirect loop detected in URL resolution chain.",
                value=f"hops={resolution.redirect_count}",
                severity_contribution=0.3,
                source="CyberGuardResolver"
            ))
            local_risk_score = max(local_risk_score, 0.4)

        if resolution and resolution.redirect_count > 0:
            hops_str = " -> ".join([f"{h.from_url} ({h.status_code})" for h in resolution.redirect_chain]) + f" -> {resolution.terminal_url}"
            evidences.append(Evidence(
                evidence_type="redirect_chain",
                description=f"URL resolved through {resolution.redirect_count} redirect hop(s): {hops_str}",
                value=f"hops={resolution.redirect_count}",
                severity_contribution=0.1 if resolution.redirect_count > 2 else 0.0,
                source="CyberGuardResolver"
            ))

        if resolution and resolution.protocol_transition == "HTTPS_TO_HTTP_DOWNGRADE":
            evidences.append(Evidence(
                evidence_type="protocol_downgrade",
                description="Redirect chain downgraded secure HTTPS connection to unencrypted HTTP.",
                value=resolution.terminal_url,
                severity_contribution=0.25,
                source="CyberGuardResolver"
            ))
            local_risk_score = max(local_risk_score, 0.35)

        # ── STAGE 3: Local CyberGuard URL Heuristic Analysis ───────────────────
        heuristics_start = time.time()
        try:
            # Rule 1: IP address as hostname
            if self._is_ip_address(hostname):
                evidences.append(Evidence(
                    evidence_type="ip_hostname",
                    description="URL uses an IP address instead of a domain name.",
                    value=hostname,
                    severity_contribution=0.4,
                    source="CyberGuard"
                ))
                local_risk_score += 0.4

            # Rule 2: Suspicious TLDs
            if hostname.endswith((".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq")):
                evidences.append(Evidence(
                    evidence_type="suspicious_tld",
                    description="Domain uses a TLD commonly associated with spam/phishing.",
                    value=hostname.split('.')[-1],
                    severity_contribution=0.3,
                    source="CyberGuard"
                ))
                local_risk_score += 0.3

            # Rule 3: Unusually long URL
            if len(url) > 100:
                evidences.append(Evidence(
                    evidence_type="long_url",
                    description="URL is unusually long, potentially obfuscating malicious payloads.",
                    value=f"length={len(url)}",
                    severity_contribution=0.1,
                    source="CyberGuard"
                ))
                local_risk_score += 0.1

            # Rule 4: Suspicious keywords in path/hostname
            suspicious_keywords = ["login", "verify", "secure", "account", "update", "bank", "credential"]
            found_keywords = [kw for kw in suspicious_keywords if kw in hostname or kw in path.lower()]
            if found_keywords:
                evidences.append(Evidence(
                    evidence_type="suspicious_keywords",
                    description="URL contains keywords often used in phishing to impersonate login portals.",
                    value=",".join(found_keywords),
                    severity_contribution=0.3,
                    source="CyberGuard"
                ))
                local_risk_score += 0.3

            # Rule 5: Multiple subdomains
            if len(hostname.split(".")) > 4:
                evidences.append(Evidence(
                    evidence_type="excessive_subdomains",
                    description="Domain has an excessive number of subdomains, a common look-alike domain tactic.",
                    value=hostname,
                    severity_contribution=0.2,
                    source="CyberGuard"
                ))
                local_risk_score += 0.2

        except Exception as e:
            evidences.append(Evidence(
                evidence_type="parse_error",
                description="Failed to parse URL, potentially malformed or obfuscated.",
                value=str(e),
                severity_contribution=0.1,
                source="CyberGuard"
            ))
            local_risk_score += 0.1

        local_heuristics_ms = (time.time() - heuristics_start) * 1000.0

        # Local severity calculation
        local_risk_score = min(local_risk_score, 1.0)
        if local_risk_score >= 0.8:
            local_risk = RiskLevel.CRITICAL
        elif local_risk_score >= 0.6:
            local_risk = RiskLevel.HIGH
        elif local_risk_score >= 0.35:
            local_risk = RiskLevel.MEDIUM
        elif local_risk_score > 0.0:
            local_risk = RiskLevel.LOW
        else:
            local_risk = RiskLevel.SAFE

        logger.info(f"analysis_id={analysis_id} stage=LOCAL_HEURISTICS status=COMPLETED risk_score={local_risk_score:.2f} local_risk={local_risk.value} duration_ms={local_heuristics_ms:.1f}")

        # If local-only mode requested or indicator is local private target
        if local_only or is_local:
            vt_report = {
                "status": "NOT_APPLICABLE",
                "provider": "VirusTotal",
                "indicator": canonical_url,
                "indicator_type": "url",
                "message": "LOCAL / PRIVATE TARGET: External threat intelligence (VirusTotal) is not applicable to local development servers or internal private networks. No external request performed.",
                "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "total_engines": 0},
                "engine_results": [],
                "categories": [],
                "timeline": {},
                "technical_details": {"scope": "LOCAL_OR_PRIVATE"},
                "permalink": ""
            }
            uh_report = {
                "status": "NOT_APPLICABLE",
                "provider": "URLhaus",
                "indicator": canonical_url,
                "indicator_type": "url",
                "matched": False,
                "classification": None,
                "evidence": [],
                "limitations": ["LOCAL / PRIVATE TARGET: URLhaus public threat intelligence does not apply to private addresses."],
            }
            correlation = self.correlation_engine.correlate(vt_report, uh_report, {"indicator": canonical_url, "category": "url"})
            return self._build_event(
                url=canonical_url,
                source=source,
                correlation_id=analysis_id,
                severity=local_risk,
                local_risk_score=local_risk_score,
                is_pending=False,
                evidences=evidences,
                vt_report=vt_report,
                uh_report=uh_report,
                correlation=correlation,
                is_local=is_local,
                start_time=start_time,
                timings={"local_ms": local_heuristics_ms, "vt_ms": 0.0, "uh_ms": 0.0, "corr_ms": 0.0, "resolution_ms": res_duration_ms},
                resolution=resolution,
            )

        # ── STAGE 4: VirusTotal Intelligence (Provider 1) ──────────────────────
        vt_start = time.time()
        logger.info(f"analysis_id={analysis_id} stage=VIRUSTOTAL status=QUERYING")

        if not self.vt_provider.is_configured:
            vt_report = {
                "status": "NOT_CONFIGURED",
                "provider": "VirusTotal",
                "indicator": canonical_url,
                "indicator_type": "url",
                "message": "VirusTotal provider is not configured. Server-side VIRUSTOTAL_API_KEY is missing or disabled in configuration.",
                "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "total_engines": 0},
                "engine_results": [],
                "categories": [],
                "timeline": {},
                "technical_details": {},
                "permalink": ""
            }
        else:
            try:
                vt_report = await self.vt_provider.get_url_report(canonical_url)
                if vt_report.get("status") == "NOT_FOUND":
                    # URL not found in VT dataset — submit for scanning
                    logger.info(f"analysis_id={analysis_id} stage=VIRUSTOTAL status=NOT_FOUND action=SUBMIT_SCAN")
                    scan_res = await self.vt_provider.scan_url(canonical_url)
                    analysis_id_vt = scan_res.get("analysis_id")

                    if scan_res.get("status") == "SUBMITTED" and analysis_id_vt and poll_vt:
                        logger.info(f"analysis_id={analysis_id} stage=VIRUSTOTAL status=POLLING analysis_id={analysis_id_vt}")
                        poll_res = await self.vt_provider.poll_analysis(analysis_id_vt, timeout_sec=max_vt_poll_sec)
                        if poll_res.get("status") == "COMPLETED":
                            vt_report = await self.vt_provider.get_url_report(canonical_url)
                        else:
                            vt_report = {
                                "status": "PENDING",
                                "provider": "VirusTotal",
                                "indicator": canonical_url,
                                "indicator_type": "url",
                                "analysis_id": analysis_id_vt,
                                "message": "URL was submitted to VirusTotal for analysis (results pending in external queue).",
                                "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "total_engines": 0},
                                "engine_results": [],
                                "categories": [],
                                "timeline": {},
                                "technical_details": {},
                                "permalink": self.vt_provider._generate_gui_permalink(canonical_url, "url")
                            }
                    else:
                        vt_report = {
                            "status": "PENDING" if scan_res.get("status") == "SUBMITTED" else "NOT_FOUND",
                            "provider": "VirusTotal",
                            "indicator": canonical_url,
                            "indicator_type": "url",
                            "analysis_id": analysis_id_vt,
                            "message": "URL was submitted to VirusTotal for analysis (results pending in external queue)." if scan_res.get("status") == "SUBMITTED" else "Indicator was not found in VirusTotal dataset.",
                            "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "total_engines": 0},
                            "engine_results": [],
                            "categories": [],
                            "timeline": {},
                            "technical_details": {},
                            "permalink": self.vt_provider._generate_gui_permalink(canonical_url, "url")
                        }
            except Exception as e:
                logger.error(f"analysis_id={analysis_id} stage=VIRUSTOTAL status=ERROR error={e}")
                vt_report = {
                    "status": "UNAVAILABLE",
                    "provider": "VirusTotal",
                    "indicator": canonical_url,
                    "indicator_type": "url",
                    "message": f"External intelligence query failed: {str(e)}",
                    "summary": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0, "total_engines": 0},
                    "engine_results": [],
                    "permalink": ""
                }

        vt_duration_ms = (time.time() - vt_start) * 1000.0
        vt_status = vt_report.get("status", "UNKNOWN")
        logger.info(f"analysis_id={analysis_id} stage=VIRUSTOTAL status={vt_status} duration_ms={vt_duration_ms:.1f}")

        # ── STAGE 5: Landing-Page & Provider Report Disambiguation & IOCs ─────
        # Identify if resolution or VirusTotal reached a provider report URL (e.g. URLhaus report)
        terminal_url = resolution.terminal_url if resolution else canonical_url
        terminal_status_code = resolution.terminal_status_code if resolution else None
        provider_report_url = resolution.provider_report_url if resolution else None
        recorded_malware_url = resolution.recorded_malware_url if resolution else None
        associated_iocs = list(resolution.associated_iocs) if resolution else []

        # Check VirusTotal technical details for URLhaus report URL
        vt_final_url = vt_report.get("technical_details", {}).get("final_url") or ""
        vt_title = vt_report.get("technical_details", {}).get("title") or ""

        # Check if VT final_url is a URLhaus report URL
        uh_id_vt = self.resolver.is_urlhaus_report_url(vt_final_url)
        uh_id_res = self.resolver.is_urlhaus_report_url(terminal_url)
        uh_id_cand = self.resolver.is_urlhaus_report_url(provider_report_url or "")
        uh_id = uh_id_cand or uh_id_res or uh_id_vt

        if uh_id:
            provider_report_url = f"https://urlhaus.abuse.ch/url/{uh_id}/"
            # Authoritative query to URLhaus for record details by ID
            try:
                uh_rec = await self.urlhaus_provider.lookup_urlid(uh_id)
                if uh_rec.get("matched"):
                    rec_malware_u = uh_rec.get("recorded_malware_url")
                    rec_host = uh_rec.get("host")
                    if rec_malware_u:
                        recorded_malware_url = rec_malware_u

                        # Check if already present in associated_iocs
                        existing = [ioc for ioc in associated_iocs if ioc.value == rec_malware_u]
                        payloads = uh_rec.get("payloads", [])
                        sha256 = payloads[0].get("sha256_hash") if payloads else None
                        if existing:
                            existing[0].intelligence["urlhaus"] = uh_rec
                            existing[0].threat = uh_rec.get("threat") or existing[0].threat
                            existing[0].url_status = uh_rec.get("url_status") or existing[0].url_status
                            existing[0].urlhaus_record_id = uh_id
                            existing[0].provider_report_url = provider_report_url
                            if sha256:
                                existing[0].payload_sha256 = sha256
                        else:
                            associated_iocs.append(AssociatedIOC(
                                value=rec_malware_u,
                                type="URL",
                                source="URLhaus",
                                relationship="RECORDED_MALWARE_URL",
                                scope="URLHAUS_RECORDED_MALWARE_URL",
                                associated_host=rec_host,
                                threat=uh_rec.get("threat"),
                                url_status=uh_rec.get("url_status"),
                                urlhaus_record_id=uh_id,
                                provider_report_url=provider_report_url,
                                payload_sha256=sha256,
                                intelligence={"urlhaus": uh_rec},
                            ))

                        # Also add host-level associated IOC if not already present
                        if rec_host and not any(ioc.value == rec_host for ioc in associated_iocs):
                            associated_iocs.append(AssociatedIOC(
                                value=rec_host,
                                type="IP" if self._is_ip_address(rec_host) else "DOMAIN",
                                source="URLhaus",
                                relationship="RELATED_HOST",
                                scope="HOST_LEVEL",
                                associated_host=rec_host,
                                threat=uh_rec.get("threat"),
                                urlhaus_record_id=uh_id,
                                provider_report_url=provider_report_url,
                            ))
            except Exception as e:
                logger.error(f"URLhaus urlid lookup failed: {e}")

        # Check if page title contains "URLhaus | <malware_url>" and extract recorded malware URL
        page_title = (resolution.page_metadata.title if resolution else "") or vt_title or ""
        if "urlhaus" in page_title.lower() and not recorded_malware_url:
            m_title = urllib.parse.unquote(page_title)
            import re
            m_url = re.search(r"https?://[^\s<>\"']+", m_title)
            if m_url and not self.resolver.is_urlhaus_report_url(m_url.group(0)):
                recorded_malware_url = m_url.group(0).rstrip(".,;!)]")
                if not any(ioc.value == recorded_malware_url for ioc in associated_iocs):
                    p_ref = urllib.parse.urlparse(recorded_malware_url)
                    associated_iocs.append(AssociatedIOC(
                        value=recorded_malware_url,
                        type="URL",
                        source="PageMetadata",
                        relationship="RECORDED_MALWARE_URL",
                        scope="URLHAUS_RECORDED_MALWARE_URL",
                        associated_host=p_ref.hostname or "",
                        provider_report_url=provider_report_url,
                    ))

        # Enrich the recorded malware URL through VirusTotal if found
        if recorded_malware_url and self.vt_provider.is_configured:
            try:
                rec_vt = await self.vt_provider.get_url_report(recorded_malware_url)
                if rec_vt.get("status") == "COMPLETED":
                    rec_mal = rec_vt.get("summary", {}).get("malicious", 0)
                    rec_susp = rec_vt.get("summary", {}).get("suspicious", 0)
                    rec_tot = rec_vt.get("summary", {}).get("total_engines", 0)
                    for ioc in associated_iocs:
                        if ioc.value == recorded_malware_url:
                            ioc.intelligence["virustotal"] = {
                                "status": "COMPLETED",
                                "malicious": rec_mal,
                                "suspicious": rec_susp,
                                "total_engines": rec_tot,
                                "permalink": rec_vt.get("permalink", ""),
                            }
            except Exception as e:
                logger.debug(f"VT lookup for recorded malware URL failed: {e}")

        # ── STAGE 6: URLhaus Intelligence (Provider 2 — Enforce Order) ────────
        uh_start = time.time()
        logger.info(f"analysis_id={analysis_id} stage=URLHAUS status=QUERYING")

        if vt_status == "PENDING":
            logger.info(f"analysis_id={analysis_id} stage=URLHAUS status=WAITING_FOR_VIRUSTOTAL")
            uh_report = {
                "provider": "URLhaus",
                "status": "WAITING_FOR_VIRUSTOTAL",
                "indicator": canonical_url,
                "indicator_type": "url",
                "matched": False,
                "classification": None,
                "evidence": [],
                "limitations": ["URLhaus query is waiting for VirusTotal to reach a terminal state before executing."],
                "error": None,
            }
        elif not self.urlhaus_provider.is_configured:
            uh_report = {
                "provider": "URLhaus",
                "status": "NOT_CONFIGURED",
                "indicator": canonical_url,
                "indicator_type": "url",
                "matched": False,
                "classification": None,
                "evidence": [],
                "limitations": ["URLhaus Auth-Key not configured. Set URLHAUS_AUTH_KEY in environment."],
                "error": None,
            }
        else:
            try:
                # Query original URL in URLhaus
                uh_report = await self.urlhaus_provider.lookup_url(canonical_url)

                # If original didn't match, and terminal URL is different and not a report page:
                if not uh_report.get("matched") and terminal_url != canonical_url and not uh_id_res:
                    term_uh = await self.urlhaus_provider.lookup_url(terminal_url)
                    if term_uh.get("matched"):
                        uh_report = term_uh
            except Exception as e:
                logger.error(f"analysis_id={analysis_id} stage=URLHAUS status=ERROR error={e}")
                uh_report = {
                    "provider": "URLhaus",
                    "status": "ERROR",
                    "indicator": canonical_url,
                    "indicator_type": "url",
                    "matched": False,
                    "classification": None,
                    "evidence": [],
                    "limitations": [],
                    "error": str(e),
                }

        uh_duration_ms = (time.time() - uh_start) * 1000.0
        uh_status = uh_report.get("status", "UNKNOWN")
        logger.info(f"analysis_id={analysis_id} stage=URLHAUS status={uh_status} matched={uh_report.get('matched', False)} duration_ms={uh_duration_ms:.1f}")

        # ── STAGE 7: Cross-Provider Correlation ───────────────────────────────
        corr_start = time.time()
        logger.info(f"analysis_id={analysis_id} stage=CORRELATION status=COMPUTING")

        correlation = self.correlation_engine.correlate(
            vt_report,
            uh_report,
            {"indicator": canonical_url, "category": "url"},
            associated_iocs=associated_iocs,
        )
        corr_duration_ms = (time.time() - corr_start) * 1000.0
        logger.info(f"analysis_id={analysis_id} stage=CORRELATION status={correlation.get('status')} duration_ms={corr_duration_ms:.1f}")

        # ── STAGE 8: CyberGuard Authoritative Risk Engine & Final Verdict Gate ─
        is_pending = (vt_status == "PENDING") or (uh_status == "WAITING_FOR_VIRUSTOTAL")
        custom_summary: Optional[str] = None
        custom_reasoning: Optional[str] = None

        if is_pending:
            final_severity = local_risk
            classification = "PENDING_EXTERNAL_VERIFICATION"
            threat_cat = ThreatCategory.UNKNOWN
        else:
            risk_level = local_risk

            # VirusTotal contribution for scanned URL
            if vt_status == "COMPLETED":
                summary_dict = vt_report.get("summary", {})
                malicious = summary_dict.get("malicious", 0) or vt_report.get("malicious_count", 0)
                suspicious = summary_dict.get("suspicious", 0) or vt_report.get("suspicious_count", 0)

                if malicious >= 5:
                    risk_level = RiskLevel.CRITICAL
                elif malicious >= 1:
                    risk_level = self._max_risk(risk_level, RiskLevel.HIGH)
                elif suspicious >= 2:
                    risk_level = self._max_risk(risk_level, RiskLevel.MEDIUM)
                elif suspicious >= 1:
                    risk_level = self._max_risk(risk_level, RiskLevel.LOW)

            # URLhaus direct contribution for scanned URL
            if uh_report.get("matched", False):
                if risk_level in (RiskLevel.SAFE, RiskLevel.LOW):
                    risk_level = RiskLevel.MEDIUM
                if uh_report.get("classification") == "malware_distribution_url":
                    risk_level = self._max_risk(risk_level, RiskLevel.HIGH)

            # Forensics: Associated Threat IOC evaluation (URLhaus recorded malware URL)
            has_associated_malware = False
            for ioc in associated_iocs:
                if ioc.scope == "URLHAUS_RECORDED_MALWARE_URL":
                    ioc_uh = ioc.intelligence.get("urlhaus", {})
                    ioc_vt = ioc.intelligence.get("virustotal", {})
                    vt_mal = ioc_vt.get("malicious", 0)
                    if ioc_uh.get("matched") or vt_mal > 0 or ioc.threat or ioc.urlhaus_record_id:
                        has_associated_malware = True
                        evidences.append(Evidence(
                            evidence_type="urlhaus_recorded_malware_url",
                            description=(
                                f"Landing resource/report references URLhaus-tracked malware URL: '{ioc.value}'. "
                                f"Threat: {ioc.threat or 'malware_download'}. URL status: {ioc.url_status or 'tracked'}."
                            ),
                            value=ioc.value,
                            severity_contribution=0.85,
                            confidence=0.95,
                            source="URLhaus"
                        ))

            if has_associated_malware:
                # Elevate risk: URL resolves or references intelligence documenting active malware target
                risk_level = self._max_risk(risk_level, RiskLevel.HIGH)
                ioc_threat_str = (ioc.threat if 'ioc' in locals() and ioc else None) or "malware_download"
                is_direct_report_resolution = bool(
                    terminal_url and provider_report_url and terminal_url.rstrip("/").lower() == provider_report_url.rstrip("/").lower()
                )
                if is_direct_report_resolution:
                    custom_summary = (
                        f"The submitted URL resolved via redirect to a URLhaus database report ({provider_report_url}). "
                        f"The report documents an active malware-distribution target ({recorded_malware_url}). "
                        "CyberGuard distinguishes the terminal report page from the recorded malware URL, "
                        "and flags the submitted link due to its direct resolution to malware tracking intelligence."
                    )
                    custom_reasoning = (
                        f"Resolution followed {resolution.redirect_count if resolution else 0} redirect hop(s) terminating at URLhaus database record #{uh_id}. "
                        f"The URLhaus database tracks active malware URL '{recorded_malware_url}' (threat: {ioc_threat_str}). "
                        "A successful HTTP 200 response from the URLhaus report page indicates successful retrieval of the research page, "
                        "NOT that the referenced malware URL is harmless."
                    )
                else:
                    custom_summary = (
                        f"The submitted URL resolved via redirect to landing page ({terminal_url}), "
                        f"which references a URLhaus database report ({provider_report_url}). "
                        f"The report documents an active malware-distribution target ({recorded_malware_url}). "
                        "CyberGuard distinguishes the primary URL and landing page from the referenced threat IOC, "
                        "and evaluates elevated risk based on association with tracked malware intelligence."
                    )
                    custom_reasoning = (
                        f"Network resolution reached landing page '{terminal_url}' (HTTP {terminal_status_code or 200}), "
                        f"which contained a reference to URLhaus database record #{uh_id}. "
                        f"The URLhaus database tracks active malware URL '{recorded_malware_url}' (threat: {ioc_threat_str}). "
                        f"Primary IOC '{canonical_url}' has no direct provider detections, but risk is elevated "
                        f"due to association with tracked malware distribution."
                    )


            # SSRF blocked redirect target check
            if resolution and resolution.status == ResolutionStatus.BLOCKED_REDIRECT_TARGET:
                risk_level = RiskLevel.CRITICAL
                custom_summary = "Outbound resolution blocked: URL redirected to an internal, private, or loopback destination (SSRF attack blocked)."
                custom_reasoning = resolution.error_message or "A redirect in the resolution chain targeted an RFC 1918 private address or loopback interface."

            final_severity = risk_level
            threat_cat = ThreatCategory.MALICIOUS_URL if final_severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) else (
                ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY if final_severity == RiskLevel.MEDIUM else ThreatCategory.SAFE
            )
            classification = (
                "MALICIOUS" if final_severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                else ("SUSPICIOUS" if final_severity == RiskLevel.MEDIUM else "SAFE")
            )

        # Append external evidence items
        if vt_status == "COMPLETED":
            tot = vt_report.get("summary", {}).get("total_engines", 0) or vt_report.get("total_engines", 0)
            mal = vt_report.get("summary", {}).get("malicious", 0) or vt_report.get("malicious_count", 0)
            susp = vt_report.get("summary", {}).get("suspicious", 0) or vt_report.get("suspicious_count", 0)
            if tot > 0:
                evidences.append(Evidence(
                    evidence_type="vt_url_reputation",
                    description=f"VirusTotal: {mal} malicious, {susp} suspicious out of {tot} security engines.",
                    value=vt_report.get("permalink", canonical_url),
                    severity_contribution=min(1.0, (mal * 0.1) + (susp * 0.05)),
                    confidence=0.95 if tot > 20 else 0.8,
                    source="VirusTotal"
                ))

        for uh_ev in uh_report.get("evidence", []):
            if isinstance(uh_ev, dict):
                evidences.append(Evidence(
                    evidence_type=uh_ev.get("evidence_type", "urlhaus_intelligence"),
                    description=uh_ev.get("description", "URLhaus intelligence."),
                    value=uh_ev.get("actual_value"),
                    severity_contribution=0.2 if uh_report.get("classification") == "malware_distribution_url" else 0.1,
                    confidence=0.85,
                    source="URLhaus"
                ))

        timings = {
            "local_ms": round(local_heuristics_ms, 1),
            "vt_ms": round(vt_duration_ms, 1),
            "uh_ms": round(uh_duration_ms, 1),
            "corr_ms": round(corr_duration_ms, 1),
            "resolution_ms": round(res_duration_ms, 1),
        }

        return self._build_event(
            url=canonical_url,
            source=source,
            correlation_id=analysis_id,
            severity=final_severity,
            local_risk_score=local_risk_score,
            is_pending=is_pending,
            evidences=evidences,
            vt_report=vt_report,
            uh_report=uh_report,
            correlation=correlation,
            is_local=False,
            start_time=start_time,
            timings=timings,
            threat_cat=threat_cat,
            classification=classification,
            resolution=resolution,
            terminal_url=terminal_url,
            terminal_status_code=terminal_status_code,
            provider_report_url=provider_report_url,
            recorded_malware_url=recorded_malware_url,
            associated_iocs=associated_iocs,
            custom_summary=custom_summary,
            custom_reasoning=custom_reasoning,
        )

    def _build_event(
        self,
        *,
        url: str,
        source: str,
        correlation_id: str,
        severity: RiskLevel,
        local_risk_score: float,
        is_pending: bool,
        evidences: List[Evidence],
        vt_report: Dict[str, Any],
        uh_report: Dict[str, Any],
        correlation: Dict[str, Any],
        is_local: bool,
        start_time: float,
        timings: Dict[str, float],
        threat_cat: Optional[ThreatCategory] = None,
        classification: Optional[str] = None,
        resolution: Optional[ResolutionResult] = None,
        terminal_url: Optional[str] = None,
        terminal_status_code: Optional[int] = None,
        provider_report_url: Optional[str] = None,
        recorded_malware_url: Optional[str] = None,
        associated_iocs: Optional[List[AssociatedIOC]] = None,
        custom_summary: Optional[str] = None,
        custom_reasoning: Optional[str] = None,
    ) -> ThreatEvent:
        total_duration_ms = (time.time() - start_time) * 1000.0
        timings["total_ms"] = round(total_duration_ms, 1)

        vt_status = vt_report.get("status", "UNKNOWN")
        uh_status = uh_report.get("status", "UNKNOWN")
        corr_status = correlation.get("status", "UNKNOWN")

        if threat_cat is None:
            threat_cat = ThreatCategory.MALICIOUS_URL if severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) else ThreatCategory.SAFE
        if classification is None:
            classification = "MALICIOUS" if severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) else ("SUSPICIOUS" if severity == RiskLevel.MEDIUM else "SAFE")

        # Dynamic Explanation
        if custom_summary and custom_reasoning:
            summary = custom_summary
            reasoning = custom_reasoning
            limitations = None
        elif is_pending:
            summary = f"URL analysis preliminary local score {local_risk_score:.2f}. URL was submitted to VirusTotal for analysis (results pending)."
            reasoning = "External threat intelligence analysis is in progress. A final verified assessment cannot be finalized while external results are pending."
            limitations = "External threat intelligence verification is pending. This is a PRELIMINARY result, NOT a final verified SAFE verdict."
        elif is_local:
            summary = f"Local development indicator '{url}' analyzed."
            reasoning = "Target address points to the local CyberGuard development environment or a private RFC 1918 network. External threat intelligence reputation is not applicable. Local heuristic analysis completed."
            limitations = "External intelligence providers not applicable for private networks."
        elif corr_status == CorrelationStatus.CORROBORATED.value:
            summary = "URL security analysis complete. VirusTotal and URLhaus both returned corroborating threat intelligence."
            reasoning = correlation.get("summary", "Threat corroborated by multiple independent security providers.")
            limitations = None
        elif corr_status == CorrelationStatus.SINGLE_PROVIDER.value:
            active = "VirusTotal" if vt_report.get("matched") or vt_status == "COMPLETED" else "URLhaus"
            summary = f"URL security analysis complete. Single-provider intelligence from {active}."
            reasoning = correlation.get("summary", f"Only {active} provided matching threat intelligence.")
            limitations = "Threat intelligence confirmed by single provider only."
        elif corr_status == CorrelationStatus.NO_MATCH.value:
            tot = vt_report.get("summary", {}).get("total_engines", 0) or vt_report.get("total_engines", 0)
            term_code = terminal_status_code if terminal_status_code is not None else 200
            summary = f"URL analysis completed with local risk score {local_risk_score:.2f}." + (f" VirusTotal reported 0 malicious detections out of {tot} engines." if tot > 0 else "")
            reasoning = (
                f"Target URL retrieved with HTTP status {term_code}. "
                "Neither VirusTotal nor URLhaus returned an active malware record for this URL. "
                "Note: A successful HTTP 200 response indicates successful network retrieval only; "
                "absence of external threat intelligence records does not confirm safety. CyberGuard local heuristics applied."
            )
            limitations = "Absence of external threat records does not guarantee safety."
        elif vt_status == "COMPLETED":
            tot = vt_report.get("summary", {}).get("total_engines", 0) or vt_report.get("total_engines", 0)
            mal = vt_report.get("summary", {}).get("malicious", 0) or vt_report.get("malicious_count", 0)
            summary = f"URL analysis completed. VirusTotal reported {mal} malicious detections out of {tot} security engines."
            reasoning = f"External threat intelligence analyzed across {tot} security engines."
            limitations = None
        else:
            summary = f"URL analysis completed with risk score {local_risk_score:.2f}."
            reasoning = "Heuristic indicators evaluated. External threat intelligence providers were unavailable or unconfigured."
            limitations = "External intelligence unavailable."

        # Recommended actions
        recommended_actions: List[str] = []
        if is_local:
            recommended_actions.append("Local development target — no defensive blocking required.")
        elif severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            target_to_block = recorded_malware_url or terminal_url or url
            recommended_actions.extend([
                f"Block access to indicator '{target_to_block}' across network and endpoints.",
                "Inspect associated access logs and active sessions for signs of compromise.",
                "Report indicator to internal incident response and escalate priority.",
            ])
            if corr_status == CorrelationStatus.CORROBORATED.value:
                recommended_actions.append("Intelligence is CORROBORATED by multiple providers — high confidence in threat assessment.")
        elif severity == RiskLevel.MEDIUM:
            recommended_actions.extend([
                f"Flag URL '{url}' for enhanced monitoring.",
                "Verify traffic origins and prompt user confirmation before interaction.",
            ])
        elif is_pending:
            recommended_actions.append("External verification pending. Monitor indicator until external analysis finishes.")
        else:
            recommended_actions.append("No defensive action required based on available intelligence.")

        # Structured Technical Details for UI and API consumers
        resolved_term_url = terminal_url or url
        raw_tech = copy.deepcopy(vt_report.get("technical_details", {}))

        # Backward compatible mapping (legacy consumers)
        raw_tech["url"] = url
        raw_tech["final_url"] = resolved_term_url
        if terminal_status_code is not None:
            raw_tech["http_response_code"] = terminal_status_code

        # Add explicit, distinct forensic fields
        raw_tech["original_url"] = url
        raw_tech["terminal_url"] = resolved_term_url
        if terminal_status_code is not None:
            raw_tech["terminal_http_status"] = terminal_status_code
        if resolution:
            raw_tech["redirect_hops"] = resolution.redirect_count
            if resolution.redirect_chain:
                hops_str = " -> ".join([f"Hop {h.hop}: {h.from_url} ({h.status_code})" for h in resolution.redirect_chain]) + f" -> {resolved_term_url}"
                raw_tech["redirect_chain_summary"] = hops_str
            if resolution.page_metadata.title:
                raw_tech["title"] = resolution.page_metadata.title
            if resolution.page_metadata.canonical_url:
                raw_tech["canonical_url"] = resolution.page_metadata.canonical_url
            if resolution.page_metadata.og_url:
                raw_tech["og_url"] = resolution.page_metadata.og_url

        if provider_report_url:
            raw_tech["provider_report_url"] = provider_report_url
        if recorded_malware_url:
            raw_tech["urlhaus_recorded_malware_url"] = recorded_malware_url

        # Structured Threat Intelligence Payload
        threat_intel_payload: Dict[str, Any] = {
            "provider": "VirusTotal",
            "status": vt_status,
            "indicator": url,
            "indicator_type": "url",
            "original_url": url,
            "terminal_url": resolved_term_url,
            "final_url": resolved_term_url,
            "resolved_terminal_url": resolved_term_url,
            "provider_report_url": provider_report_url,
            "recorded_malware_url": recorded_malware_url,
            "urlhaus_recorded_malware_url": recorded_malware_url,
            "resolution": resolution.to_dict() if resolution else None,
            "redirect_chain": [h.to_dict() for h in resolution.redirect_chain] if resolution else [],
            "redirect_count": resolution.redirect_count if resolution else 0,
            "page_metadata": resolution.page_metadata.to_dict() if resolution else None,
            "associated_iocs": [ioc.to_dict() for ioc in (associated_iocs or [])],
            "is_local": is_local,
            "message": vt_report.get("message") or ("VirusTotal intelligence operational." if vt_status == "COMPLETED" else f"Status: {vt_status}"),
            "summary": vt_report.get("summary", {
                "malicious": vt_report.get("malicious_count", 0),
                "suspicious": vt_report.get("suspicious_count", 0),
                "harmless": vt_report.get("harmless_count", 0),
                "undetected": vt_report.get("undetected_count", 0),
                "timeout": 0,
                "total_engines": vt_report.get("total_engines", 0),
            }),
            "reputation": vt_report.get("reputation"),
            "categories": vt_report.get("categories", []),
            "category_names": vt_report.get("category_names", []),
            "timeline": vt_report.get("timeline", {}),
            "technical_details": raw_tech,
            "engine_results": vt_report.get("engine_results", []),
            "permalink": vt_report.get("permalink", ""),
            "cyberguard_local": {
                "risk_level": local_risk_score,
                "is_local": is_local,
                "evidence": [
                    {
                        "evidence_type": ev.evidence_type,
                        "description": ev.description,
                        "value": ev.value,
                        "severity_contribution": ev.severity_contribution,
                        "source": ev.source
                    }
                    for ev in evidences if ev.source == "CyberGuard"
                ]
            },
            "correlated_assessment": {
                "final_risk": severity.value,
                "scope": "ASSOCIATED_THREAT_INTELLIGENCE" if recorded_malware_url else "PRIMARY_IOC",
                "risk_source": (
                    "Associated URLhaus Malware Intelligence" if recorded_malware_url
                    else ("VirusTotal" if vt_status == "COMPLETED" and (vt_report.get("summary", {}).get("malicious", 0) > 0) else "CyberGuard Heuristics")
                ),
                "risk_contributions": [
                    {
                        "source": ev.source,
                        "type": ev.evidence_type,
                        "description": ev.description,
                        "contribution": ev.severity_contribution,
                        "target_ioc": ev.value,
                    }
                    for ev in evidences if ev.severity_contribution > 0
                ],
                "provenance": (
                    "Source: CyberGuard Resolver + VirusTotal + URLhaus"
                    if recorded_malware_url or corr_status in (CorrelationStatus.CORROBORATED.value, CorrelationStatus.SINGLE_PROVIDER.value, CorrelationStatus.RELATED_EVIDENCE.value)
                    else "Source: CyberGuard"
                ),
                "reasoning": reasoning,
            },
            "correlation": correlation,
            "urlhaus": uh_report,
            "providers": {
                "virustotal": {
                    "status": vt_status,
                    "scope": "PRIMARY_IOC",
                    "matched": (vt_status == "COMPLETED" and ((vt_report.get("summary", {}).get("malicious", 0) > 0) or (vt_report.get("malicious_count", 0) > 0))),
                    "malicious": vt_report.get("summary", {}).get("malicious", 0) or vt_report.get("malicious_count", 0),
                    "suspicious": vt_report.get("summary", {}).get("suspicious", 0) or vt_report.get("suspicious_count", 0),
                    "total_engines": vt_report.get("summary", {}).get("total_engines", 0) or vt_report.get("total_engines", 0),
                    "permalink": vt_report.get("permalink", ""),
                },
                "urlhaus": {
                    "status": uh_status,
                    "scope": "PRIMARY_IOC",
                    "matched": uh_report.get("matched", False),
                    "classification": uh_report.get("classification"),
                    "match_scope": uh_report.get("match_scope", "PRIMARY_IOC"),
                    "url_status": uh_report.get("url_status"),
                    "threat": uh_report.get("threat"),
                    "external_reference": uh_report.get("external_reference"),
                },
                "related_intelligence": {
                    "has_related_threat": bool(recorded_malware_url or provider_report_url),
                    "recorded_malware_url": recorded_malware_url,
                    "provider_report_url": provider_report_url,
                    "scope": "URLHAUS_RECORDED_MALWARE_URL" if recorded_malware_url else "PROVIDER_REPORT",
                    "threat": getattr(next((ioc for ioc in (associated_iocs or []) if ioc.value == recorded_malware_url), None), "threat", None) or uh_report.get("threat"),
                    "url_status": getattr(next((ioc for ioc in (associated_iocs or []) if ioc.value == recorded_malware_url), None), "url_status", None) or uh_report.get("url_status"),
                    "urlhaus": {
                        "url": recorded_malware_url,
                        "threat": getattr(next((ioc for ioc in (associated_iocs or []) if ioc.value == recorded_malware_url), None), "threat", None) or uh_report.get("threat"),
                        "status": getattr(next((ioc for ioc in (associated_iocs or []) if ioc.value == recorded_malware_url), None), "url_status", None) or uh_report.get("url_status"),
                        "provider_report_url": provider_report_url,
                    } if (recorded_malware_url or provider_report_url) else None,
                    "virustotal": next(
                        (ioc.intelligence.get("virustotal") for ioc in (associated_iocs or []) if ioc.value == recorded_malware_url and ioc.intelligence.get("virustotal")),
                        None
                    ),
                }
            },
            "performance": {
                "total_ms": timings.get("total_ms", 0.0),
                "virustotal_ms": timings.get("vt_ms", 0.0),
                "urlhaus_ms": timings.get("uh_ms", 0.0),
                "correlation_ms": timings.get("corr_ms", 0.0),
                "resolution_ms": timings.get("resolution_ms", 0.0),
                "local_heuristics_ms": timings.get("local_ms", 0.0),
            },
            "is_pending": is_pending,
            "can_finalize": not is_pending,
        }

        return ThreatEvent(
            source=source,
            source_type="url",
            modality="text",
            threat_category=threat_cat,
            severity=severity,
            confidence=0.95 if evidences else 1.0,
            classification=classification,
            evidence=evidences,
            explanation=Explanation(
                summary=summary,
                reasoning=reasoning,
                limitations=limitations,
            ),
            recommended_actions=recommended_actions,
            affected_asset=url,
            detector="URLThreatIntelPipeline",
            processing_time_ms=total_duration_ms,
            correlation_id=correlation_id,
            threat_intelligence=threat_intel_payload,
        )


    def _is_ip_address(self, hostname: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _is_local_or_private(self, hostname: str) -> bool:
        import ipaddress
        if not hostname:
            return False
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        if hostname.endswith(".local") or hostname.endswith(".internal"):
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False

    def _max_risk(self, r1: RiskLevel, r2: RiskLevel) -> RiskLevel:
        ranks = {RiskLevel.SAFE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
        return r1 if ranks.get(r1, 0) >= ranks.get(r2, 0) else r2
