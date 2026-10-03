from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from typing import List, Optional, Dict, Any
import time
import copy
import logging
import uuid

from backend.config import get_settings
from backend.analysis.phishing_analyzer import PhishingAnalyzer
from backend.analysis.url_analyzer import URLAnalyzer
from backend.analysis.qr_analyzer import QRAnalyzer
from backend.analysis.deepfake_coordinator import DeepfakeCoordinator
from backend.analysis.anomaly_detector import AnomalyDetector
from backend.threats.models import ThreatEvent, Explanation, RiskLevel, ThreatCategory, Evidence
from backend.threats.ioc_classifier import IOCClassifier, IOCType, IOCScope
from backend.threats.virustotal import get_virustotal_provider
from backend.threats.urlhaus import get_urlhaus_provider
from backend.threats.correlation import ThreatIntelCorrelationEngine, CorrelationStatus

# We use the main app's singletons
from backend.analysis.unified_pipeline import UnifiedThreatPipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threats", tags=["Threat Analysis"])

_correlation_engine = ThreatIntelCorrelationEngine()


def _get_dependencies():
    settings = get_settings()
    from backend.main import get_app_incident_manager
    incident_manager = get_app_incident_manager()
    return settings, incident_manager


def _broadcast_threat_event(event: ThreatEvent):
    try:
        from backend.main import get_app_ws_notifier
        ws_notifier = get_app_ws_notifier()
        if ws_notifier and hasattr(ws_notifier, "broadcast_raw"):
            import asyncio
            payload = {
                "type": "threat_event",
                "event": event.model_dump() if hasattr(event, "model_dump") else event.dict()
            }
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(ws_notifier.broadcast_raw(payload))
            except RuntimeError:
                pass
    except Exception as exc:
        logger.debug(f"Threat event broadcast skipped: {exc}")


@router.post("/unified")
async def analyze_unified(
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    ioc: Optional[str] = Form(None),
    speaker_id: Optional[str] = Form(None),
    source: str = Form("unified_api"),
    correlation_id: Optional[str] = Form(None),
):
    """
    Unified Non-Destructive Threat Analysis Endpoint.
    Ingests any threat artifact (file, text, URL, IOC) across all pipelines,
    correlates findings, creates/updates incidents, and dispatches alerts.
    """
    settings = get_settings()
    from backend.main import get_app_detector, get_app_incident_manager, get_app_alert_manager
    detector = get_app_detector()
    incident_manager = get_app_incident_manager()
    alert_manager = get_app_alert_manager()

    pipeline = UnifiedThreatPipeline(
        config=settings,
        detector=detector,
        incident_manager=incident_manager,
        alert_manager=alert_manager,
    )

    file_bytes = None
    filename = None
    if file is not None:
        file_bytes = await file.read()
        filename = file.filename

    result = await pipeline.analyze(
        file_bytes=file_bytes,
        filename=filename,
        text=text,
        url=url,
        ioc=ioc,
        speaker_id=speaker_id,
        source=source,
        correlation_id=correlation_id,
    )
    if isinstance(result, dict) and "event" in result and isinstance(result["event"], ThreatEvent):
        _broadcast_threat_event(result["event"])
    return result


@router.post("/phishing", response_model=ThreatEvent)
async def analyze_phishing(
    text: str = Form(...),
    source: str = Form("api_submission"),
    correlation_id: Optional[str] = Form(None)
):
    settings, incident_manager = _get_dependencies()
    if not getattr(settings.cyberguard, "phishing_analysis_enabled", True):
        raise HTTPException(status_code=400, detail="Phishing analysis is disabled.")

    analyzer = PhishingAnalyzer(settings)
    event = analyzer.analyze(text, source=source, correlation_id=correlation_id)

    if incident_manager:
        incident_manager.process_event(event)

    _broadcast_threat_event(event)
    return event


@router.post("/url", response_model=ThreatEvent)
async def analyze_url(
    url: str = Form(...),
    source: str = Form("api_submission"),
    correlation_id: Optional[str] = Form(None)
):
    settings, incident_manager = _get_dependencies()
    if not getattr(settings.cyberguard, "url_analysis_enabled", True):
        raise HTTPException(status_code=400, detail="URL analysis is disabled.")

    analyzer = URLAnalyzer(settings)
    event = await analyzer.analyze(url, source=source, correlation_id=correlation_id)

    if incident_manager:
        incident_manager.process_event(event)

    _broadcast_threat_event(event)
    return event


@router.post("/qr", response_model=ThreatEvent)
async def analyze_qr(
    file: UploadFile = File(...),
    source: str = Form("api_submission"),
    correlation_id: Optional[str] = Form(None)
):
    settings, incident_manager = _get_dependencies()
    if not getattr(settings.cyberguard, "qr_analysis_enabled", True):
        raise HTTPException(status_code=400, detail="QR analysis is disabled.")

    content = await file.read()
    analyzer = QRAnalyzer(settings)
    event = await analyzer.analyze(content, source=source, correlation_id=correlation_id)

    if incident_manager:
        incident_manager.process_event(event)

    _broadcast_threat_event(event)
    return event


@router.post("/deepfake", response_model=ThreatEvent)
async def analyze_deepfake(
    file: UploadFile = File(...),
    source: str = Form("api_submission"),
    correlation_id: Optional[str] = Form(None)
):
    settings, incident_manager = _get_dependencies()
    from backend.main import get_app_detector
    voice_detector = get_app_detector()

    coordinator = DeepfakeCoordinator(settings, voice_detector)
    content = await file.read()

    event = coordinator.analyze(
        media_bytes=content,
        filename=file.filename,
        source=source,
        correlation_id=correlation_id
    )

    if incident_manager:
        incident_manager.process_event(event)

    _broadcast_threat_event(event)
    return event


@router.post("/events", response_model=ThreatEvent)
async def ingest_event(
    event_data: dict,
    source: str = "log_ingestion",
    correlation_id: Optional[str] = None
):
    settings, incident_manager = _get_dependencies()
    if not getattr(settings.cyberguard, "technical_anomaly_enabled", True):
        raise HTTPException(status_code=400, detail="Anomaly detection is disabled.")

    analyzer = AnomalyDetector(settings)
    event = analyzer.analyze(event_data, source=source, correlation_id=correlation_id)

    if incident_manager:
        incident_manager.process_event(event)

    _broadcast_threat_event(event)
    return event


@router.get("/virustotal/status")
async def virustotal_status(force_refresh: bool = False):
    """Return real-time VirusTotal provider capability and health state using shared singleton."""
    settings, _ = _get_dependencies()
    provider = get_virustotal_provider(settings)
    return await provider.check_status(force_refresh=force_refresh)


@router.get("/urlhaus/status")
async def urlhaus_status(force_refresh: bool = False):
    """Return real-time URLhaus provider capability and health state using shared singleton."""
    settings, _ = _get_dependencies()
    provider = get_urlhaus_provider(settings)
    return await provider.check_status(force_refresh=force_refresh)


@router.get("/pipeline/status")
async def threat_intel_pipeline_status(force_refresh: bool = False):
    """Return real-time status of the entire Threat Intelligence pipeline (VT + URLhaus)."""
    settings, _ = _get_dependencies()
    vt_provider = get_virustotal_provider(settings)
    uh_provider = get_urlhaus_provider(settings)
    vt_status = await vt_provider.check_status(force_refresh=force_refresh)
    uh_status = await uh_provider.check_status(force_refresh=force_refresh)
    is_active = (vt_status.get("status") == "READY") and (uh_status.get("status") == "READY")
    return {
        "status": "READY" if is_active else ("DEGRADED" if (vt_status.get("status") == "READY" or uh_status.get("status") == "READY") else "OFFLINE"),
        "pipeline_active": is_active,
        "virustotal": vt_status,
        "urlhaus": uh_status,
    }


# ── URLhaus IOC-Type Router ────────────────────────────────────────────────────

async def _run_urlhaus_lookup(
    urlhaus_provider,
    category: str,
    ioc_type: str,
    canonical_ioc: str,
    is_local: bool,
) -> Dict[str, Any]:
    """
    Route the IOC to the correct URLhaus operation based on its type.
    This is the SECOND stage in the sequential VT → URLhaus pipeline.

    Routing:
      url         → lookup_url()
      domain      → lookup_host()
      ip          → lookup_host()
      hash_sha256 → lookup_payload_sha256()
      hash_md5    → lookup_payload_md5()
      hash_sha1   → NOT_APPLICABLE (documented limitation)
      local IOC   → NOT_APPLICABLE (no public intel for private addresses)
    """
    if is_local:
        return {
            "provider": "URLhaus",
            "status": "NOT_APPLICABLE",
            "indicator": canonical_ioc,
            "indicator_type": category,
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
            "limitations": [
                "LOCAL / PRIVATE TARGET: URLhaus public threat intelligence does not apply "
                "to local development servers or private RFC 1918 networks."
            ],
            "error": None,
        }

    if not urlhaus_provider.is_configured:
        return {
            "provider": "URLhaus",
            "status": "NOT_CONFIGURED",
            "indicator": canonical_ioc,
            "indicator_type": category,
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
            "limitations": [
                "URLhaus Auth-Key not configured. Set URLHAUS_AUTH_KEY in environment."
            ],
            "error": None,
        }

    try:
        if category == "url":
            return await urlhaus_provider.lookup_url(canonical_ioc)
        elif category == "domain":
            return await urlhaus_provider.lookup_host(canonical_ioc, indicator_type="domain")
        elif category == "ip":
            return await urlhaus_provider.lookup_host(canonical_ioc, indicator_type="ip")
        elif category == "hash":
            if ioc_type == "hash_sha256":
                return await urlhaus_provider.lookup_payload_sha256(canonical_ioc)
            elif ioc_type == "hash_md5":
                return await urlhaus_provider.lookup_payload_md5(canonical_ioc)
            else:
                # SHA-1 or unknown hash type — URLhaus does not support SHA-1
                return urlhaus_provider.lookup_sha1_not_applicable(canonical_ioc)
        else:
            return {
                "provider": "URLhaus",
                "status": "NOT_APPLICABLE",
                "indicator": canonical_ioc,
                "indicator_type": category,
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
                "limitations": [f"URLhaus has no documented lookup for IOC category '{category}'."],
                "error": None,
            }
    except Exception as e:
        logger.error(f"provider=urlhaus status=ERROR error={e}")
        return {
            "provider": "URLhaus",
            "status": "ERROR",
            "indicator": canonical_ioc,
            "indicator_type": category,
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
            "error": str(e),
        }


@router.get("/search", response_model=ThreatEvent)
async def threat_intelligence_search(
    ioc: str,
    correlation_id: Optional[str] = None
):
    """
    Sequential Two-Provider Threat Intelligence Search.

    Pipeline: IOC → VirusTotal → URLhaus → Correlation → CyberGuard Risk Engine → Report

    Safely differentiates public IOCs from local/private environments.
    Returns a single combined report with provider provenance preserved.
    URLhaus results are only queried AFTER VirusTotal reaches a terminal state.
    """
    analysis_id = str(uuid.uuid4())
    start_time = time.time()
    settings, incident_manager = _get_dependencies()
    vt_provider = get_virustotal_provider(settings)
    uh_provider = get_urlhaus_provider(settings)

    # ── STEP 1: IOC Classification (existing logic, unchanged) ─────────────────
    ioc_info = IOCClassifier.classify(ioc)
    if not ioc_info.get("is_supported"):
        raise HTTPException(status_code=400, detail=ioc_info.get("message", "Invalid IOC indicator."))

    canonical_ioc = ioc_info["indicator"]
    category = ioc_info["category"]
    ioc_type = ioc_info.get("ioc_type", category)
    is_local = ioc_info["is_local"]
    scope = ioc_info["scope"]

    logger.info(
        f"analysis_id={analysis_id} ioc_type={category} scope={scope} stage=STARTED"
    )

    # ── STEP 2: Local CyberGuard Analysis (existing logic, unchanged) ──────────
    local_evidences: List[Evidence] = []
    local_risk: RiskLevel = RiskLevel.SAFE
    url_ti: Optional[Dict[str, Any]] = None

    if is_local:
        local_evidences.append(Evidence(
            evidence_type="local_private_indicator",
            description=f"Indicator '{canonical_ioc}' resolves to a local development environment or private network.",
            value=canonical_ioc,
            severity_contribution=0.0,
            confidence=1.0,
            source="CyberGuard"
        ))
        local_risk = RiskLevel.SAFE
    elif category == "url":
        try:
            local_settings = copy.deepcopy(settings)
            local_settings.virustotal.enabled = False
            local_analyzer = URLAnalyzer(local_settings)
            local_event = await local_analyzer.analyze(canonical_ioc, source="local_heuristics")
            local_evidences.extend([
                ev for ev in local_event.evidence
                if not ev.evidence_type.startswith("vt_")
            ])
            local_risk = local_event.severity
            url_ti = local_event.threat_intelligence
        except Exception as err:
            logger.warning(f"Local URL heuristic analysis error: {err}")
    elif category == "ip":
        local_evidences.append(Evidence(
            evidence_type="public_ip_indicator",
            description=f"Public IPv{ioc_info.get('ip_version', 4)} address target submitted for threat analysis.",
            value=canonical_ioc,
            severity_contribution=0.0,
            source="CyberGuard"
        ))
    elif category == "hash":
        local_evidences.append(Evidence(
            evidence_type="hash_indicator",
            description=f"Cryptographic hash ({ioc_info.get('hash_type', 'Hash')}) submitted for malware reputation analysis.",
            value=canonical_ioc,
            severity_contribution=0.0,
            source="CyberGuard"
        ))
    elif category == "domain":
        local_evidences.append(Evidence(
            evidence_type="domain_indicator",
            description=f"Public domain name '{canonical_ioc}' submitted for threat intelligence reputation lookup.",
            value=canonical_ioc,
            severity_contribution=0.0,
            source="CyberGuard"
        ))

    # ── STEP 3: VirusTotal (awaited to terminal state — FIRST provider) ────────
    vt_report: Dict[str, Any] = {}
    vt_stage_start = time.time()

    logger.info(f"analysis_id={analysis_id} ioc_type={category} stage=VIRUSTOTAL status=QUERYING")

    if is_local:
        vt_report = {
            "status": "NOT_APPLICABLE",
            "provider": "VirusTotal",
            "indicator": canonical_ioc,
            "indicator_type": category,
            "message": (
                "LOCAL / PRIVATE TARGET: External threat intelligence (VirusTotal) is not applicable to "
                "local development servers or internal private networks. No external request performed."
            ),
            "summary": {
                "malicious": 0, "suspicious": 0, "harmless": 0,
                "undetected": 0, "timeout": 0, "total_engines": 0
            },
            "engine_results": [],
            "categories": [],
            "category_names": [],
            "timeline": {},
            "technical_details": {
                "indicator": canonical_ioc,
                "scope": "LOCAL_OR_PRIVATE",
                "environment": "Internal / Development",
            },
            "permalink": ""
        }
    elif not vt_provider.is_configured:
        vt_report = {
            "status": "NOT_CONFIGURED",
            "provider": "VirusTotal",
            "indicator": canonical_ioc,
            "indicator_type": category,
            "message": "External intelligence provider is not configured. Server-side VIRUSTOTAL_API_KEY is missing or disabled in configuration.",
            "summary": {
                "malicious": 0, "suspicious": 0, "harmless": 0,
                "undetected": 0, "timeout": 0, "total_engines": 0
            },
            "engine_results": [],
            "categories": [],
            "category_names": [],
            "timeline": {},
            "technical_details": {},
            "permalink": ""
        }
    else:
        try:
            if category == "hash":
                vt_report = await vt_provider.get_file_report(canonical_ioc)
            elif category == "ip":
                vt_report = await vt_provider.get_ip_report(canonical_ioc)
            elif category == "url":
                vt_report = await vt_provider.get_url_report(canonical_ioc)
            else:
                vt_report = await vt_provider.get_domain_report(canonical_ioc)
        except Exception as e:
            logger.error(f"analysis_id={analysis_id} provider=virustotal stage=VIRUSTOTAL status=ERROR error={e}")
            vt_report = {
                "status": "UNAVAILABLE",
                "provider": "VirusTotal",
                "indicator": canonical_ioc,
                "indicator_type": category,
                "message": f"External intelligence query failed: {str(e)}"
            }

        vt_st = vt_report.get("status")
        if vt_st == "NOT_FOUND":
            vt_report["message"] = (
                "NO VIRUSTOTAL REPORT FOUND: The indicator was not found in the available VirusTotal dataset. "
                "This does NOT confirm that the indicator is safe."
            )
        elif vt_st == "UNAUTHORIZED":
            vt_report["status"] = "AUTHENTICATION_FAILED"
            vt_report["message"] = "VirusTotal authentication failed. The configured server API key was rejected."
        elif vt_st == "FORBIDDEN":
            vt_report["message"] = "VirusTotal operation forbidden with current API privileges."
        elif vt_st == "RATE_LIMITED":
            vt_report["message"] = "VirusTotal API request rate limit or quota exceeded. Please retry later."
        elif vt_st in ("UNAVAILABLE", "TIMEOUT"):
            vt_report["message"] = "External VirusTotal service could not be reached or request timed out."

    vt_duration_ms = (time.time() - vt_stage_start) * 1000
    logger.info(
        f"analysis_id={analysis_id} ioc_type={category} stage=VIRUSTOTAL "
        f"status={vt_report.get('status', 'UNKNOWN')} duration_ms={vt_duration_ms:.0f}"
    )

    # ── STEP 4: URLhaus (SECOND provider — only after VT reaches terminal state) ─
    uh_stage_start = time.time()

    logger.info(f"analysis_id={analysis_id} ioc_type={category} stage=URLHAUS status=QUERYING")

    uh_report = await _run_urlhaus_lookup(
        uh_provider, category, ioc_type, canonical_ioc, is_local
    )

    uh_duration_ms = (time.time() - uh_stage_start) * 1000
    logger.info(
        f"analysis_id={analysis_id} ioc_type={category} stage=URLHAUS "
        f"status={uh_report.get('status', 'UNKNOWN')} "
        f"matched={uh_report.get('matched', False)} duration_ms={uh_duration_ms:.0f}"
    )

    # ── STEP 5: Correlation (only after BOTH providers reach terminal state) ────
    corr_start = time.time()

    vt_status_initial = vt_report.get("status")
    init_mal = vt_report.get("malicious_count", 0) if vt_status_initial == "COMPLETED" else 0
    init_susp = vt_report.get("suspicious_count", 0) if vt_status_initial == "COMPLETED" else 0
    if not init_mal and vt_status_initial == "COMPLETED":
        s_dict = vt_report.get("summary", {})
        init_mal = s_dict.get("malicious", 0)
        init_susp = s_dict.get("suspicious", 0)
    if "matched" not in vt_report:
        vt_report["matched"] = (vt_status_initial == "COMPLETED" and (init_mal > 0 or init_susp > 0))

    logger.info(f"analysis_id={analysis_id} ioc_type={category} stage=CORRELATION status=COMPUTING")

    correlation = _correlation_engine.correlate(vt_report, uh_report, ioc_info)

    corr_duration_ms = (time.time() - corr_start) * 1000
    logger.info(
        f"analysis_id={analysis_id} ioc_type={category} stage=CORRELATION "
        f"status={correlation['status']} duration_ms={corr_duration_ms:.0f}"
    )

    # ── STEP 6: Assessment & Risk Engine (existing logic, extended with URLhaus evidence) ─
    vt_status = vt_report.get("status")
    malicious = vt_report.get("malicious_count", 0) if vt_status == "COMPLETED" else 0
    suspicious = vt_report.get("suspicious_count", 0) if vt_status == "COMPLETED" else 0
    total_engines = vt_report.get("total_engines", 0) if vt_status == "COMPLETED" else 0

    # If vt_report uses summary dict structure (new format)
    if not malicious and vt_status == "COMPLETED":
        summary_dict = vt_report.get("summary", {})
        malicious = summary_dict.get("malicious", 0)
        suspicious = summary_dict.get("suspicious", 0)
        total_engines = summary_dict.get("total_engines", 0)

    # Risk determination — existing CyberGuard risk engine logic (unchanged)
    risk_level = RiskLevel.SAFE
    if is_local:
        risk_level = local_risk
    elif vt_status == "COMPLETED":
        if malicious >= 5:
            risk_level = RiskLevel.CRITICAL
        elif malicious >= 1:
            risk_level = RiskLevel.HIGH
        elif suspicious >= 2:
            risk_level = RiskLevel.MEDIUM
        elif suspicious >= 1:
            risk_level = RiskLevel.LOW
        else:
            risk_level = local_risk
    else:
        risk_level = local_risk

    # URLhaus evidence can escalate risk if VT has no match but URLhaus confirms malware
    uh_matched = uh_report.get("matched", False)
    if (
        uh_matched
        and risk_level in (RiskLevel.SAFE, RiskLevel.LOW)
        and correlation["status"] in (
            CorrelationStatus.CORROBORATED.value,
            CorrelationStatus.CONFLICTING.value,
            CorrelationStatus.SINGLE_PROVIDER.value,
            CorrelationStatus.PROVIDER_UNAVAILABLE.value,
        )
    ):
        # URLhaus confirms malware activity — escalate to at least MEDIUM
        # (risk engine contribution, not hardcoded detection)
        if risk_level == RiskLevel.SAFE:
            risk_level = RiskLevel.MEDIUM
        # Note: we do NOT blindly set CRITICAL; URLhaus alone doesn't override VT clean verdict

    # URL forensics: If URL resolution identified an associated malware URL, elevate risk
    if url_ti and url_ti.get("recorded_malware_url"):
        risk_level = RiskLevel.HIGH if risk_level != RiskLevel.CRITICAL else risk_level

    # Combined evidence list (local + VT + URLhaus)
    combined_evidences: List[Evidence] = list(local_evidences)

    # VT evidence
    if vt_status == "COMPLETED" and total_engines > 0:
        vt_contrib = min(1.0, (malicious * 0.1) + (suspicious * 0.05))
        combined_evidences.append(Evidence(
            evidence_type=f"vt_{category}_reputation",
            description=f"VirusTotal: {malicious} malicious, {suspicious} suspicious out of {total_engines} engines.",
            value=vt_report.get("permalink", ""),
            severity_contribution=vt_contrib,
            confidence=0.95 if total_engines > 20 else 0.8,
            source="VirusTotal"
        ))

    # URLhaus evidence (with source provenance)
    for uh_ev in uh_report.get("evidence", []):
        if isinstance(uh_ev, dict):
            combined_evidences.append(Evidence(
                evidence_type=uh_ev.get("evidence_type", "urlhaus_intelligence"),
                description=uh_ev.get("description", "URLhaus intelligence."),
                value=uh_ev.get("actual_value"),
                severity_contribution=0.15 if uh_report.get("classification") == "malware_distribution_url" else 0.08,
                confidence=0.85,
                source="URLhaus"
            ))

    # Correlation evidence items
    for corr_ev in correlation.get("corroborating_evidence", []):
        # Avoid duplicate evidence (corr engine may include VT/URLhaus evidence already added)
        if isinstance(corr_ev, dict) and corr_ev.get("source") not in ("VirusTotal", "URLhaus"):
            combined_evidences.append(Evidence(
                evidence_type=corr_ev.get("evidence_type", "correlation_evidence"),
                description=corr_ev.get("description", "Cross-provider correlation."),
                value=corr_ev.get("actual_value"),
                severity_contribution=0.0,
                confidence=0.9,
                source=corr_ev.get("source", "CyberGuard Correlation")
            ))

    # ── STEP 7: Provenance + Explanation ──────────────────────────────────────
    corr_status = correlation["status"]

    if is_local:
        provenance = "Source: CyberGuard (Local Analysis)"
        summary_text = f"Local development indicator '{canonical_ioc}' analyzed."
        reasoning_text = (
            "Target address points to the local CyberGuard development environment or a private RFC 1918 network. "
            "External threat intelligence reputation is not applicable. Local heuristic analysis completed."
        )
    elif corr_status == CorrelationStatus.CORROBORATED.value:
        provenance = "Source: CyberGuard + VirusTotal + URLhaus"
        summary_text = (
            f"Threat intelligence search completed for {category}. "
            f"VirusTotal and URLhaus both returned corroborating intelligence."
        )
        reasoning_text = correlation.get("summary", "Corroborated by both providers.")
    elif corr_status == CorrelationStatus.PARTIALLY_CORROBORATED.value:
        provenance = "Source: CyberGuard + VirusTotal + URLhaus"
        summary_text = f"Partial corroboration: providers returned intelligence at different scopes."
        reasoning_text = correlation.get("summary", "Partially corroborated.")
    elif corr_status == CorrelationStatus.CONFLICTING.value:
        provenance = "Source: CyberGuard + VirusTotal + URLhaus (CONFLICTING)"
        summary_text = f"Provider findings conflict. Review both results carefully."
        reasoning_text = correlation.get("summary", "Providers returned conflicting findings.")
    elif corr_status == CorrelationStatus.SINGLE_PROVIDER.value:
        active_provider = "VirusTotal" if vt_report.get("matched") or vt_status == "COMPLETED" else "URLhaus"
        provenance = f"Source: CyberGuard + {active_provider}"
        summary_text = f"Single-provider intelligence: only {active_provider} returned matching data."
        reasoning_text = correlation.get("summary", f"Only {active_provider} provided intelligence.")
    elif vt_status == "COMPLETED":
        provenance = "Source: CyberGuard + VirusTotal" if local_evidences else "Source: VirusTotal"
        summary_text = (
            f"Threat intelligence search completed for {category}. "
            f"VirusTotal reported {malicious} malicious and {suspicious} suspicious engine detections out of {total_engines} engines."
        )
        reasoning_text = (
            f"External threat intelligence correlated across {total_engines} security vendors. "
            + (f"{malicious} vendors flagged this indicator as malicious. " if malicious > 0 else "No vendors flagged malicious. ")
            + (f"Local CyberGuard heuristics identified {len(local_evidences)} indicators." if local_evidences else "")
        )
    elif vt_status == "NOT_FOUND":
        provenance = "Source: CyberGuard"
        summary_text = f"No external intelligence report found for {canonical_ioc}."
        reasoning_text = (
            "The indicator is not present in the current VirusTotal or URLhaus dataset. "
            "Absence of external threat records does not guarantee safety. CyberGuard local heuristics applied."
        )
    else:
        provenance = "Source: CyberGuard"
        summary_text = f"External intelligence providers unavailable or not configured."
        reasoning_text = vt_report.get("message", "External provider lookup could not be completed.")

    # ── STEP 8: Recommended Actions ───────────────────────────────────────────
    recommended_actions: List[str] = []
    if is_local:
        recommended_actions.append("Local development target - no defensive blocking required.")
    elif risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        recommended_actions.extend([
            f"Block access to {category} '{canonical_ioc}' across network and endpoints.",
            "Inspect associated access logs and active sessions for signs of compromise.",
            "Report indicator to internal incident response and escalate priority.",
        ])
        if corr_status == CorrelationStatus.CORROBORATED.value:
            recommended_actions.append(
                "Intelligence is CORROBORATED by multiple providers — high confidence in threat assessment."
            )
    elif risk_level == RiskLevel.MEDIUM:
        recommended_actions.extend([
            f"Flag {category} '{canonical_ioc}' for enhanced monitoring.",
            "Verify traffic origins and prompt user confirmation before interaction.",
        ])
    elif corr_status == CorrelationStatus.NO_MATCH.value:
        recommended_actions.append(
            "Exercise standard vigilance; indicator has not been indexed by external threat intelligence providers."
        )
    elif corr_status == CorrelationStatus.CONFLICTING.value:
        recommended_actions.append(
            "Provider findings conflict. Manual review recommended before taking defensive action."
        )
    else:
        recommended_actions.append("No defensive action required based on available intelligence.")

    # ── STEP 9: Threat Category ────────────────────────────────────────────────
    if category == "hash":
        threat_cat = ThreatCategory.MALWARE_INDICATOR if risk_level != RiskLevel.SAFE else ThreatCategory.SAFE
    else:
        threat_cat = ThreatCategory.MALICIOUS_URL if risk_level != RiskLevel.SAFE else ThreatCategory.SAFE

    classification = (
        "MALICIOUS" if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        else ("SUSPICIOUS" if risk_level == RiskLevel.MEDIUM else "SAFE")
    )

    # ── STEP 10: Build Combined Threat Intelligence Payload ───────────────────
    # All existing fields preserved (backward-compatible).
    # New fields: providers, correlation, urlhaus.
    threat_intel_payload: Dict[str, Any] = {
        # ── Existing fields (preserved unchanged) ──
        "provider": "VirusTotal",  # Legacy: primary provider label
        "status": vt_status,
        "indicator": canonical_ioc,
        "indicator_type": category,
        "original_url": (url_ti.get("original_url") if url_ti else canonical_ioc) if category == "url" else None,
        "terminal_url": url_ti.get("terminal_url") if url_ti else None,
        "final_url": (url_ti.get("terminal_url") or url_ti.get("final_url")) if url_ti else None,
        "provider_report_url": url_ti.get("provider_report_url") if url_ti else None,
        "recorded_malware_url": url_ti.get("recorded_malware_url") if url_ti else None,
        "urlhaus_recorded_malware_url": url_ti.get("urlhaus_recorded_malware_url") if url_ti else None,
        "resolution": url_ti.get("resolution") if url_ti else None,
        "redirect_chain": url_ti.get("redirect_chain", []) if url_ti else [],
        "redirect_count": url_ti.get("redirect_count", 0) if url_ti else 0,
        "page_metadata": url_ti.get("page_metadata") if url_ti else None,
        "associated_iocs": url_ti.get("associated_iocs", []) if url_ti else [],
        "ioc_classification": ioc_info.get("ioc_type"),
        "scope": scope,
        "is_local": is_local,
        "message": vt_report.get("message") or (
            "VirusTotal intelligence operational." if vt_status == "COMPLETED"
            else f"Status: {vt_status}"
        ),
        "summary": vt_report.get("summary", {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": vt_report.get("harmless_count", 0),
            "undetected": vt_report.get("undetected_count", 0),
            "timeout": 0,
            "total_engines": total_engines,
        }),
        "reputation": vt_report.get("reputation"),
        "categories": vt_report.get("categories", []),
        "category_names": vt_report.get("category_names", []),
        "timeline": vt_report.get("timeline", {}),
        "technical_details": vt_report.get("technical_details", {}),
        "engine_results": vt_report.get("engine_results", []),
        "permalink": vt_report.get("permalink", ""),
        "cyberguard_local": {
            "risk_level": local_risk.value,
            "is_local": is_local,
            "evidence": [
                {
                    "evidence_type": ev.evidence_type,
                    "description": ev.description,
                    "value": ev.value,
                    "severity_contribution": ev.severity_contribution,
                    "source": ev.source
                }
                for ev in local_evidences
            ]
        },
        "correlated_assessment": {
            "overall_severity": risk_level.value,
            "provenance": provenance,
            "reasoning": reasoning_text,
        },
        "recommended_actions": recommended_actions,

        # ── New fields (backward-compatible additions) ──
        "analysis_id": analysis_id,
        "providers": {
            "virustotal": {
                "status": vt_report.get("status", "UNKNOWN"),
                "matched": (
                    vt_status == "COMPLETED"
                    and (malicious > 0 or suspicious > 0)
                ),
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total_engines,
                "permalink": vt_report.get("permalink", ""),
            },
            "urlhaus": {
                "status": uh_report.get("status", "UNKNOWN"),
                "matched": uh_report.get("matched", False),
                "classification": uh_report.get("classification"),
                "match_scope": uh_report.get("match_scope", "NOT_APPLICABLE"),
                "url_status": uh_report.get("url_status"),
                "threat": uh_report.get("threat"),
                "external_reference": uh_report.get("external_reference"),
            },
        },
        "correlation": {
            "status": correlation["status"],
            "agreement": correlation["agreement"],
            "conflicts": correlation.get("conflicts", []),
            "corroborating_evidence": correlation.get("corroborating_evidence", []),
            "provider_gaps": correlation.get("provider_gaps", []),
            "freshness": correlation.get("freshness", {}),
            "summary": correlation.get("summary", ""),
        },
        "urlhaus": uh_report,
        "performance": {
            "virustotal_ms": round(vt_duration_ms),
            "urlhaus_ms": round(uh_duration_ms),
            "correlation_ms": round(corr_duration_ms),
            "total_ms": round((time.time() - start_time) * 1000),
        },
    }

    total_duration_ms = (time.time() - start_time) * 1000
    logger.info(
        f"analysis_id={analysis_id} ioc_type={category} stage=COMPLETED "
        f"correlation_status={corr_status} risk={risk_level.value} "
        f"total_ms={total_duration_ms:.0f}"
    )

    event = ThreatEvent(
        source="Threat Intelligence Search",
        source_type="ioc_search",
        modality="text",
        threat_category=threat_cat,
        severity=risk_level,
        confidence=0.95 if (vt_status == "COMPLETED" and total_engines > 20) else (0.9 if is_local else 0.7),
        classification=classification,
        evidence=combined_evidences,
        explanation=Explanation(
            summary=summary_text,
            reasoning=reasoning_text,
            limitations=(
                "External reputation data provided by VirusTotal API v3 and URLhaus Community API. "
                "Provider provenance preserved. URLhaus focuses on malware-distribution URLs — "
                "NO_MATCH from URLhaus does not confirm an indicator is safe."
            )
        ),
        recommended_actions=recommended_actions,
        detector="CyberGuard + VirusTotalProvider + URLhausProvider",
        processing_time_ms=total_duration_ms,
        correlation_id=correlation_id,
        threat_intelligence=threat_intel_payload
    )

    if incident_manager and risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        try:
            incident_manager.process_event(event)
        except Exception as e:
            logger.warning(f"Failed to record incident: {e}")

    _broadcast_threat_event(event)
    return event
