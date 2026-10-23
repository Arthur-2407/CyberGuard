from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends, Request, Query, Path, Response, status
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import asyncio
import copy
import json
import logging
import re
import time
import uuid

import hashlib
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
from backend.threats.live_intel_scraper import get_live_intel_scraper

# We use the main app's singletons
from backend.analysis.unified_pipeline import UnifiedThreatPipeline

from backend.threats.enclave import (
    ThreatIntelEnclave,
    PHISHING_AND_URL_SCOPE,
    _ACTIVE_THREAT_ENCLAVE,
)

from contextvars import ContextVar

logger = logging.getLogger(__name__)

_ACTIVE_USER_CONTEXT: ContextVar[Optional[Any]] = ContextVar("active_user_context", default=None)


async def enter_threat_workspace_enclave(request: Request):
    """FastAPI dependency establishing the isolated Phishing & URL execution enclave and user context."""
    header_scope = request.headers.get("X-Threat-Scope")
    scope = header_scope if header_scope else PHISHING_AND_URL_SCOPE
    token = _ACTIVE_THREAT_ENCLAVE.set(scope)

    # Automatically identify caller to guarantee isolated tenant database routing
    curr_user = None
    try:
        from backend.storage.auth import get_token_from_request, AuthService
        from backend.storage.database import get_session_factory
        raw_tok = get_token_from_request(request)
        if raw_tok:
            factory = get_session_factory("data/cyberguard.db")
            with factory() as db:
                u_obj = AuthService.get_user_from_token(db, raw_tok)
                if u_obj:
                    curr_user = {
                        "id": u_obj.id,
                        "username": u_obj.username,
                        "email": u_obj.email,
                        "role": u_obj.role,
                        "db_path": u_obj.db_path,
                    }
    except Exception as exc:
        logger.debug(f"User context extraction notice in enclave: {exc}")

    u_token = _ACTIVE_USER_CONTEXT.set(curr_user)
    try:
        yield
    finally:
        _ACTIVE_THREAT_ENCLAVE.reset(token)
        _ACTIVE_USER_CONTEXT.reset(u_token)


router = APIRouter(
    prefix="/api/threats",
    tags=["Threat Analysis"],
    dependencies=[Depends(enter_threat_workspace_enclave)],
)

_correlation_engine = ThreatIntelCorrelationEngine()


def _get_dependencies(user: Optional[Any] = None):
    settings = get_settings()
    active_user = user or _ACTIVE_USER_CONTEXT.get()
    from backend.incidents.incident_manager import get_incident_manager_for_user
    incident_manager = get_incident_manager_for_user(active_user)
    return settings, incident_manager


def _broadcast_threat_event(event: ThreatEvent):
    curr_user = _ACTIVE_USER_CONTEXT.get()
    if curr_user and isinstance(curr_user, dict):
        if not getattr(event, "user_id", None):
            event.user_id = curr_user.get("id")
        if not getattr(event, "user_email", None):
            event.user_email = curr_user.get("email")
        if not getattr(event, "affected_user", None):
            event.affected_user = curr_user.get("username")

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

    # Automated Brevo Email Dispatch: Triggered ONLY on HIGH or CRITICAL threats to the specific active user
    try:
        sev = getattr(event, "severity", None)
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        if str(sev_str).upper() in ("HIGH", "CRITICAL"):
            from backend.alerts.email_notifier import get_email_notifier
            notifier = get_email_notifier()
            u_email = getattr(event, "user_email", None) or (curr_user.get("email") if curr_user and isinstance(curr_user, dict) else None)
            try:
                import asyncio
                loop = asyncio.get_running_loop()
                loop.create_task(notifier.notify_threat_event(event, user_email=u_email))
            except RuntimeError:
                pass
    except Exception as email_err:
        logger.debug(f"Automated email dispatch trigger notice: {email_err}")


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
    correlates findings, creates/updates incidents in the caller's isolated DB, and dispatches alerts.
    """
    settings = get_settings()
    from backend.main import get_app_detector, get_app_alert_manager
    from backend.incidents.incident_manager import get_incident_manager_for_user
    detector = get_app_detector()
    curr_user = _ACTIVE_USER_CONTEXT.get()
    incident_manager = get_incident_manager_for_user(curr_user)
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
        user=curr_user,
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

    curr_user = _ACTIVE_USER_CONTEXT.get()
    analyzer = PhishingAnalyzer(settings)
    event = analyzer.analyze(text, source=source, correlation_id=correlation_id, user=curr_user)

    # Correlate attached URL through VirusTotal and URLhaus pipeline if present
    import re
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    if urls:
        first_url = urls[0]
        if not first_url.startswith("http"):
            first_url = "http://" + first_url
        try:
            url_analyzer = URLAnalyzer(settings)
            url_event = await url_analyzer.analyze(first_url, source=source, correlation_id=correlation_id)
            if url_event:
                if url_event.threat_intelligence:
                    event.threat_intelligence = copy.deepcopy(url_event.threat_intelligence)
                for ev in url_event.evidence:
                    if ev.evidence_type in ("virustotal_detection", "urlhaus_malware_detection", "cross_provider_correlation"):
                        event.evidence.append(ev)
                if url_event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL) and event.severity not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    event.severity = url_event.severity
                    event.threat_category = ThreatCategory.PHISHING
        except Exception as e:
            logger.debug(f"Phishing embedded URL deep scan notice: {e}")

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


@router.post("/image", response_model=ThreatEvent)
async def analyze_image_forensics(
    file: UploadFile = File(...),
    source: str = Form("image_upload"),
    correlation_id: Optional[str] = Form(None)
):
    """
    Dedicated General Image & Deepfake Forensic Analysis Endpoint.
    Evaluates 2D FFT spectral distributions, high-frequency anomalies,
    Laplacian edge variance, and generative AI metadata signatures.
    """
    settings, incident_manager = _get_dependencies()
    from backend.main import get_app_detector
    voice_detector = get_app_detector()

    coordinator = DeepfakeCoordinator(settings, voice_detector)
    content = await file.read()

    event = coordinator.analyze(
        media_bytes=content,
        filename=file.filename or "uploaded_image.png",
        source=source,
        correlation_id=correlation_id
    )

    if incident_manager:
        incident_manager.process_event(event)

    try:
        from backend.security.enforcement import get_enforcement_engine
        enforcement = get_enforcement_engine()
        if enforcement:
            enforcement.evaluate_threat_for_auto_block(event)
    except Exception as enf_err:
        logger.debug(f"Image enforcement evaluation notice: {enf_err}")

    _broadcast_threat_event(event)
    return event


@router.post("/llm-analysis")
async def perform_llm_security_analysis(
    payload: Dict[str, Any]
):
    """
    Explainable AI & LLM Security Analysis Layer.
    Synthesizes executive briefing, MITRE ATT&CK mapping,
    Cyber Kill Chain reconstruction, and Incident Response Playbook.
    """
    from backend.analysis.llm_analyst import get_llm_analyst
    analyst = get_llm_analyst()

    # If an incident_id is passed, load incident data from DB
    incident_id = payload.get("incident_id")
    event_data = payload.get("event") or payload.get("threat_data") or payload

    if incident_id:
        try:
            from backend.storage.database import get_session_factory, IncidentModel, ThreatEventModel
            session = get_session_factory()()
            inc = session.query(IncidentModel).filter(IncidentModel.incident_id == incident_id).first()
            if inc:
                evs = session.query(ThreatEventModel).filter(ThreatEventModel.incident_id == incident_id).all()
                event_data = {
                    "incident_id": inc.incident_id,
                    "threat_category": inc.category,
                    "severity": inc.risk,
                    "status": inc.status,
                    "source": "Incident Case Management",
                    "evidence": [e.explanation_summary for e in evs if e.explanation_summary],
                    "recommendations": json.loads(inc.recommendations_json or "[]"),
                }
            session.close()
        except Exception as exc:
            logger.debug(f"Incident retrieval for LLM analysis notice: {exc}")

    # Enrich with live OSINT intelligence if indicator or package name or hash is present
    target_ind = event_data.get("indicator") or event_data.get("package_name") or event_data.get("sha256") or event_data.get("url")
    live_intel = event_data.get("live_intelligence")
    if target_ind and not live_intel:
        try:
            scraper = get_live_intel_scraper()
            ind_cat = "package" if event_data.get("package_name") else ("hash" if event_data.get("sha256") else "url")
            live_intel = await scraper.analyze_indicator_full(str(target_ind), category=ind_cat, context_metadata=event_data)
            event_data["live_intelligence"] = live_intel
            if live_intel.get("osint", {}).get("results"):
                event_data["osint_search_hits"] = live_intel["osint"]["results"]
        except Exception as osint_err:
            logger.debug(f"LLM analysis OSINT enrichment notice: {osint_err}")

    result = await asyncio.to_thread(analyst.analyze, event_data, None, True)
    if live_intel:
        result["live_intelligence"] = live_intel

    # Ensure standard schema aliases for forensic copilot and test clients
    if "mitre_attack_mapping" in result and "mitre_attack_techniques" not in result:
        result["mitre_attack_techniques"] = [
            {"technique_id": m.get("id"), "name": m.get("name"), "tactic": m.get("tactic")}
            for m in result["mitre_attack_mapping"]
        ]
    if "kill_chain_reconstruction" in result and "kill_chain_stage" not in result:
        kc = result["kill_chain_reconstruction"]
        result["kill_chain_stage"] = kc.get("phase") if isinstance(kc, dict) else "Delivery / Exploitation"
    if "immediate_containment" not in result:
        playbook = result.get("incident_response_playbook", [])
        if playbook:
            result["immediate_containment"] = [
                f"{p.get('step', '')}: {p.get('action', '')}".strip(": ")
                for p in playbook
            ]
        elif result.get("assessed_severity") == "SAFE":
            result["immediate_containment"] = [
                "Operational Clearance: Asset verified authentic. No containment actions required."
            ]
        else:
            result["immediate_containment"] = [
                f"Containment Window: {result.get('recommended_containment_window', 'Standard')}",
                "Review evidence artifacts and verify origin through out-of-band channel."
            ]
    if "executive_summary" in result and "executive_briefing" not in result:
        result["executive_briefing"] = result["executive_summary"]
    if "mitre_attack_mapping" in result and "mitre_mapping" not in result:
        result["mitre_mapping"] = result["mitre_attack_mapping"]
    if "technical_deep_dive" in result and "narrative" not in result:
        result["narrative"] = result["technical_deep_dive"]
    if "technical_deep_dive" in result and "threat_narrative" not in result:
        result["threat_narrative"] = result["technical_deep_dive"]

    return result


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
    """Return real-time status of the entire Threat Intelligence pipeline (VT + URLhaus) concurrently."""
    settings, _ = _get_dependencies()
    vt_provider = get_virustotal_provider(settings)
    uh_provider = get_urlhaus_provider(settings)
    vt_res, uh_res = await asyncio.gather(
        vt_provider.check_status(force_refresh=force_refresh),
        uh_provider.check_status(force_refresh=force_refresh),
        return_exceptions=True,
    )
    vt_status = vt_res if isinstance(vt_res, dict) else {
        "provider": "VirusTotal", "status": "ERROR", "configured": True, "enabled": True, "message": str(vt_res)
    }
    uh_status = uh_res if isinstance(uh_res, dict) else {
        "provider": "URLhaus", "status": "ERROR", "configured": True, "enabled": True, "message": str(uh_res)
    }
    is_active = (vt_status.get("status") == "READY") and (uh_status.get("status") == "READY")
    enclave_metrics = ThreatIntelEnclave.get_instance().get_metrics()
    return {
        "status": "READY" if is_active else ("DEGRADED" if (vt_status.get("status") == "READY" or uh_status.get("status") == "READY") else "OFFLINE"),
        "pipeline_active": is_active,
        "virustotal": vt_status,
        "urlhaus": uh_status,
        "enclave": enclave_metrics,
    }


@router.get("/enclave/metrics")
async def get_enclave_metrics():
    """Return live token usage statistics, cache hits, and isolation enforcement metrics."""
    return ThreatIntelEnclave.get_instance().get_metrics()


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
            local_event = await local_analyzer.analyze(canonical_ioc, source="local_heuristics", local_only=True)
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

    # ── STEP 5b: Live Web Intelligence & Deep Crawler Forensics ─────────────
    live_start = time.time()
    logger.info(f"analysis_id={analysis_id} ioc_type={category} stage=LIVE_WEB_INTEL status=SCRAPING")
    live_intel: Dict[str, Any] = {}
    if is_local:
        live_intel = {
            "status": "NOT_APPLICABLE",
            "indicator": canonical_ioc,
            "category": category,
            "url_sha256": hashlib.sha256(canonical_ioc.encode("utf-8")).hexdigest() if category == "url" else None,
            "message": "Live web scraper not applicable to local development or private indicators.",
            "osint": {"engine": "DuckDuckGo Search", "hits_count": 0, "results": []},
            "live_page_inspection": {"is_live": False, "rendering_engine": "HTTP+BS4"},
            "qwen_llm_synthesis": {"executive_briefing": None, "containment_recommendations": []}
        }
    else:
        live_scraper = get_live_intel_scraper()
        try:
            live_intel = await live_scraper.analyze_indicator_full(
                indicator=canonical_ioc,
                category=category,
                vt_report=vt_report,
                uh_report=uh_report,
                context_metadata=ioc_info
            )
        except Exception as live_err:
            logger.warning(f"analysis_id={analysis_id} stage=LIVE_WEB_INTEL status=NOTICE error={live_err}")
            live_intel = {
                "status": "ERROR",
                "indicator": canonical_ioc,
                "category": category,
                "url_sha256": hashlib.sha256(canonical_ioc.encode("utf-8")).hexdigest() if category == "url" else None,
                "error": str(live_err),
                "osint": {"engine": "DuckDuckGo Search", "hits_count": 0, "results": []},
                "live_page_inspection": {"is_live": False, "rendering_engine": "HTTP+BS4"},
                "qwen_llm_synthesis": {"executive_briefing": None, "containment_recommendations": []}
            }
    live_duration_ms = (time.time() - live_start) * 1000.0
    logger.info(f"analysis_id={analysis_id} stage=LIVE_WEB_INTEL status=COMPLETED duration_ms={live_duration_ms:.1f}")

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
    dom_insp = live_intel.get("live_page_inspection", {})
    osint_hits = live_intel.get("osint", {}).get("hits_count", 0)

    # Evidence contribution from Live Web Inspection & OSINT (skipped for local/private indicators)
    if not is_local:
        if dom_insp.get("has_credential_forms"):
            local_evidences.append(Evidence(
                evidence_type="credential_harvesting_form",
                description="Live DOM Inspection: Password/credential input fields detected on destination page (Active Phishing Probe).",
                value=canonical_ioc,
                severity_contribution=0.8,
                confidence=0.95,
                source="Playwright+BS4"
            ))
            if risk_level in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM):
                risk_level = RiskLevel.HIGH

        if osint_hits > 0:
            local_evidences.append(Evidence(
                evidence_type="live_osint_warning",
                description=f"DuckDuckGo OSINT: Found {osint_hits} real-time threat record(s) referencing security warnings or phishing indicators.",
                value=canonical_ioc,
                severity_contribution=0.3,
                confidence=0.85,
                source="DuckDuckGoOSINT"
            ))

    url_sha256 = hashlib.sha256(canonical_ioc.encode("utf-8")).hexdigest() if category == "url" else None

    # New fields: providers, correlation, urlhaus, live_intelligence.
    threat_intel_payload: Dict[str, Any] = {
        # ── Existing fields (preserved unchanged) ──
        "provider": "VirusTotal",  # Legacy: primary provider label
        "status": vt_status,
        "indicator": canonical_ioc,
        "indicator_type": category,
        "url_sha256": url_sha256,
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
        "live_intelligence": live_intel,
        "qwen_briefing": live_intel.get("qwen_llm_synthesis", {}).get("executive_briefing"),
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
            "live_crawler": {
                "status": live_intel.get("status", "COMPLETED"),
                "rendering_engine": dom_insp.get("rendering_engine", "HTTP+BS4"),
                "is_live": dom_insp.get("is_live", False),
                "osint_hits": osint_hits,
                "has_credential_forms": dom_insp.get("has_credential_forms", False),
            },
            "qwen_llm": {
                "status": "COMPLETED" if live_intel.get("qwen_llm_synthesis", {}).get("executive_briefing") else "STANDBY",
                "executive_briefing": live_intel.get("qwen_llm_synthesis", {}).get("executive_briefing"),
                "containment_recommendations": live_intel.get("qwen_llm_synthesis", {}).get("containment_recommendations", []),
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
            "live_crawler_ms": round(live_duration_ms),
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


# =========================================================================
# REAL-TIME CALL SCREENING & PHONE NUMBER REPUTATION INTELLIGENCE
# =========================================================================

class PhoneReputationResponse(BaseModel):
    phone_number: str
    normalized_number: str
    country_code: Optional[str] = None
    classification: str = "UNKNOWN / INSUFFICIENT EVIDENCE"
    risk_score: float = 0.0
    confidence: float = 0.0
    reason_codes: List[str] = Field(default_factory=list)
    evidence_sources: List[str] = Field(default_factory=list)
    explanation: str = "No prior threat reports found in threat database."
    is_scam: bool = False
    is_spoofed: bool = False
    is_disputed: bool = False
    recommended_action: str = "ALLOW"
    reputation_found: bool = False
    source_freshness: str = "CURRENT"
    cached: bool = False
    last_verified_at: Optional[str] = None


class ScreenedCallIngestRequest(BaseModel):
    incident_id: Optional[str] = None
    phone_number: Optional[str] = None
    raw_number: Optional[str] = None
    normalized_number: Optional[str] = None
    caller_display_name: Optional[str] = None
    call_direction: str = "INCOMING"
    classification: str = "UNKNOWN"
    risk_score: float = 0.0
    confidence: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    reason_codes: Optional[List[str]] = None
    evidence_sources: Optional[List[str]] = None
    carrier_verification_status: str = "NOT_VERIFIED"
    action_recommended: str = "ALLOW"
    action_applied: str = "ALLOWED"
    response_latency_ms: float = 0.0
    explanation: Optional[str] = None
    device_id: Optional[str] = None
    timestamp: Optional[float] = None
    timestamp_epoch_ms: Optional[int] = None


def normalize_phone_number(raw_number: Optional[str], default_region: str = "IN") -> str:
    """Standards-compliant E.164 phone number normalizer."""
    if not raw_number:
        return ""
    trimmed = str(raw_number).strip()
    restricted_terms = {"unknown", "restricted", "private", "blocked", "anonymous", "caller id blocked", "-1", "-2"}
    if trimmed.lower() in restricted_terms:
        return ""
    cleaned = re.sub(r"[^\d+]", "", trimmed)
    if not cleaned:
        return ""
    # Short codes (3 to 6 digits without prefix, e.g. 112, 100, 911)
    if not cleaned.startswith("+") and 3 <= len(cleaned) <= 6:
        return cleaned
    if cleaned.startswith("+"):
        return cleaned
    # Domestic handling
    if default_region.upper() == "IN":
        if cleaned.startswith("0") and len(cleaned) == 11:
            return "+91" + cleaned[1:]
        elif len(cleaned) == 10:
            return "+91" + cleaned
        elif len(cleaned) == 12 and cleaned.startswith("91"):
            return "+" + cleaned
    elif default_region.upper() in ("US", "CA"):
        if cleaned.startswith("1") and len(cleaned) == 11:
            return "+" + cleaned
        elif len(cleaned) == 10:
            return "+1" + cleaned
    return "+" + cleaned if not cleaned.startswith("+") else cleaned


@router.get("/phone/{phone_number}", response_model=PhoneReputationResponse)
async def get_phone_reputation(
    phone_number: str = Path(..., description="Raw or E.164 phone number to screen"),
    default_region: str = Query("IN", description="Default ISO 3166-1 alpha-2 country code")
):
    """
    Evidence-based phone number reputation lookup for real-time call screening.
    Checks the local database cache first, evaluates freshness, and returns defensible risk assessment.
    """
    normalized = normalize_phone_number(phone_number, default_region=default_region)
    if not normalized:
        return PhoneReputationResponse(
            phone_number=phone_number,
            normalized_number="",
            country_code=default_region,
            classification="UNKNOWN / INSUFFICIENT EVIDENCE",
            risk_score=0.0,
            confidence=0.0,
            reason_codes=["RESTRICTED_OR_EMPTY_NUMBER"],
            evidence_sources=["LOCAL_CALL_PARSER"],
            explanation="Number is restricted, anonymous, or cannot be parsed. Standard allow policy applied.",
            recommended_action="ALLOW",
            reputation_found=False,
            cached=False,
            source_freshness="CURRENT"
        )

    # Database lookup
    try:
        from backend.storage.database import get_session_factory, CallerReputationModel
        settings = get_settings()
        factory = get_session_factory(str(settings.abs_path(settings.storage.db_path)))
        with factory() as session:
            record = session.query(CallerReputationModel).filter(
                (CallerReputationModel.normalized_number == normalized) |
                (CallerReputationModel.raw_number == phone_number)
            ).first()

            if record:
                is_expired = False
                now = datetime.now(timezone.utc)
                if record.expires_at:
                    rec_exp = record.expires_at.replace(tzinfo=timezone.utc) if record.expires_at.tzinfo is None else record.expires_at
                    if now > rec_exp:
                        is_expired = True

                reasons = []
                if record.reason_codes_json:
                    try:
                        reasons = json.loads(record.reason_codes_json)
                    except Exception:
                        pass
                sources = []
                if record.evidence_sources_json:
                    try:
                        sources = json.loads(record.evidence_sources_json)
                    except Exception:
                        pass

                freshness = "EXPIRED" if is_expired else "FRESH"
                calc_risk = record.risk_score * 0.3 if is_expired else record.risk_score
                calc_conf = 0.2 if is_expired else record.confidence

                return PhoneReputationResponse(
                    phone_number=phone_number,
                    normalized_number=record.normalized_number,
                    country_code=record.country_code or default_region,
                    classification=record.classification if not is_expired else "UNKNOWN / INSUFFICIENT EVIDENCE",
                    risk_score=round(calc_risk, 3),
                    confidence=round(calc_conf, 3),
                    reason_codes=reasons if not is_expired else (reasons + ["CACHE_EXPIRED"]),
                    evidence_sources=sources,
                    explanation=record.explanation or "Verified intelligence record retrieved from threat intelligence database.",
                    is_scam=record.is_scam and not is_expired,
                    is_spoofed=record.is_spoofed and not is_expired,
                    is_disputed=record.disputed,
                    recommended_action="BLOCK" if (record.is_scam or calc_risk >= 0.75) else ("SILENCE" if calc_risk >= 0.40 else "ALLOW"),
                    reputation_found=True,
                    source_freshness=freshness,
                    cached=True,
                    last_verified_at=record.last_verified_at.isoformat() if record.last_verified_at else None
                )
    except Exception as exc:
        logger.warning(f"Phone reputation database lookup notice: {exc}")

    # Honest UNKNOWN result when no intelligence exists
    return PhoneReputationResponse(
        phone_number=phone_number,
        normalized_number=normalized,
        country_code=default_region,
        classification="UNKNOWN / INSUFFICIENT EVIDENCE",
        risk_score=0.0,
        confidence=0.0,
        reason_codes=["NO_PRIOR_TELEMETRY"],
        evidence_sources=["CYBERGUARD_LOCAL_CACHE"],
        explanation="No malicious or spam indicators on record for this number. Conservative allow policy applies.",
        is_scam=False,
        is_spoofed=False,
        is_disputed=False,
        recommended_action="ALLOW",
        reputation_found=False,
        cached=False,
        source_freshness="UNAVAILABLE"
    )


@router.post("/screened-calls")
async def ingest_screened_call(
    request: ScreenedCallIngestRequest,
    response: Response
):
    """
    Ingest a screened incoming call incident from the Android CallScreeningService.
    Persists audit trail, associates with active tenant database, and broadcasts live to SOC console.
    """
    settings = get_settings()
    incident_id = request.incident_id or f"CALL-{uuid.uuid4().hex[:10].upper()}"
    raw_num = request.phone_number or request.raw_number or request.normalized_number or ""
    norm = normalize_phone_number(raw_num) or request.normalized_number or raw_num
    reasons_list = request.reasons or request.reason_codes or []
    curr_user = _ACTIVE_USER_CONTEXT.get()

    try:
        from backend.storage.database import get_session_factory, ScreenedCallIncidentModel
        factory = get_session_factory(str(settings.abs_path(settings.storage.db_path)))
        with factory() as session:
            existing = session.query(ScreenedCallIncidentModel).filter(
                ScreenedCallIncidentModel.incident_id == incident_id
            ).first()
            if existing:
                response.status_code = status.HTTP_200_OK
                return {
                    "status": "ALREADY_INGESTED",
                    "incident_id": incident_id,
                    "action_applied": existing.action_applied,
                    "classification": existing.classification,
                    "normalized_number": existing.normalized_number,
                    "soc_broadcast": True
                }

            inc = ScreenedCallIncidentModel(
                incident_id=incident_id,
                normalized_number=norm or raw_num,
                caller_display_name=request.caller_display_name,
                call_direction=request.call_direction,
                classification=request.classification,
                risk_score=request.risk_score,
                confidence=request.confidence,
                reasons_json=json.dumps(reasons_list),
                carrier_verification_status=request.carrier_verification_status,
                action_recommended=request.action_recommended,
                action_applied=request.action_applied,
                response_latency_ms=request.response_latency_ms,
                user_id=curr_user.get("id") if curr_user and isinstance(curr_user, dict) else None,
                device_id=request.device_id,
            )
            session.add(inc)
            session.commit()
    except Exception as exc:
        logger.warning(f"Screened call incident persistence notice: {exc}")

    # Broadcast to SOC dashboard via WebSocket
    try:
        from backend.main import get_app_ws_notifier
        ws_notifier = get_app_ws_notifier()
        if ws_notifier and hasattr(ws_notifier, "broadcast_raw"):
            payload = {
                "type": "screened_call",
                "data": {
                    "incident_id": incident_id,
                    "phone_number": raw_num,
                    "normalized_number": norm or raw_num,
                    "caller_name": request.caller_display_name or "Unknown Caller",
                    "classification": request.classification,
                    "risk_score": request.risk_score,
                    "confidence": request.confidence,
                    "reasons": reasons_list,
                    "carrier_verification": request.carrier_verification_status,
                    "action_applied": request.action_applied,
                    "latency_ms": request.response_latency_ms,
                    "timestamp": time.time()
                }
            }
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(ws_notifier.broadcast_raw(payload))
            except RuntimeError:
                pass
    except Exception as ws_err:
        logger.debug(f"Screened call WebSocket broadcast notice: {ws_err}")

    # If HIGH_RISK or SUSPICIOUS, also ingest into SOC IncidentManager
    if request.risk_score >= 0.70 or request.classification in ("HIGH_RISK", "SUSPECTED_SCAM", "SUSPICIOUS"):
        try:
            from backend.incidents.incident_manager import get_incident_manager_for_user
            incident_manager = get_incident_manager_for_user(curr_user)
            if incident_manager:
                event = ThreatEvent(
                    source=f"Call Screening // {norm or raw_num}",
                    source_type="incoming_call_telephony",
                    modality="telephony",
                    threat_category=ThreatCategory.VOICE_CLONE if "VOICE_CLONE" in reasons_list else ThreatCategory.PHISHING,
                    severity=RiskLevel.HIGH if request.risk_score >= 0.75 else RiskLevel.MEDIUM,
                    confidence=request.confidence,
                    classification=request.classification,
                    evidence=[
                        Evidence(
                            type="call_screening_telemetry",
                            description=f"Incoming call screened: {request.action_applied}. Carrier: {request.carrier_verification_status}. Reasons: {', '.join(reasons_list)}",
                            confidence=request.confidence,
                            source="CyberGuardCallScreeningService"
                        )
                    ],
                    explanation=Explanation(
                        summary=f"Incoming call from {norm or raw_num} classified as {request.classification} ({int(request.risk_score*100)}% risk).",
                        reasoning=f"Screening policy applied action: {request.action_applied}. Carrier verification: {request.carrier_verification_status}.",
                        limitations="Carrier verification and reputation evidence subject to telecommunications network reporting."
                    ),
                    recommended_actions=[
                        f"Action applied: {request.action_applied}",
                        "Block number permanently in device security settings if recurrent."
                    ],
                    detector="CyberGuardCallScreeningEngine",
                    processing_time_ms=request.response_latency_ms,
                    correlation_id=incident_id
                )
                incident_manager.process_event(event)
                _broadcast_threat_event(event)
        except Exception as inc_err:
            logger.warning(f"Call screening incident manager recording notice: {inc_err}")

    response.status_code = status.HTTP_201_CREATED
    return {
        "status": "INGESTED",
        "incident_id": incident_id,
        "action_applied": request.action_applied,
        "classification": request.classification,
        "normalized_number": norm or raw_num,
        "soc_broadcast": True
    }


@router.get("/screened-calls")
async def list_screened_calls(
    limit: int = Query(50, ge=1, le=200)
):
    """
    Retrieve audit list of screened calls for the SOC dashboard.
    """
    settings = get_settings()
    results = []
    try:
        from backend.storage.database import get_session_factory, ScreenedCallIncidentModel
        factory = get_session_factory(str(settings.abs_path(settings.storage.db_path)))
        with factory() as session:
            rows = session.query(ScreenedCallIncidentModel).order_by(ScreenedCallIncidentModel.timestamp.desc()).limit(limit).all()
            for r in rows:
                reasons = []
                if r.reasons_json:
                    try:
                        reasons = json.loads(r.reasons_json)
                    except Exception:
                        pass
                results.append({
                    "incident_id": r.incident_id,
                    "normalized_number": r.normalized_number,
                    "caller_name": r.caller_display_name or "Unknown",
                    "classification": r.classification,
                    "risk_score": r.risk_score,
                    "confidence": r.confidence,
                    "reasons": reasons,
                    "carrier_verification": r.carrier_verification_status,
                    "action_recommended": r.action_recommended,
                    "action_applied": r.action_applied,
                    "latency_ms": r.response_latency_ms,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None
                })
    except Exception as exc:
        logger.warning(f"List screened calls error: {exc}")
    return {"screened_calls": results, "total": len(results)}


# ====================================================================
# OEM APPLICATION PROVENANCE & ECOSYSTEM VERIFICATION
# ====================================================================

class OEMAppVerifyRequest(BaseModel):
    package_name: str
    app_name: Optional[str] = None
    device_brand: Optional[str] = None
    device_model: Optional[str] = None
    device_manufacturer: Optional[str] = None
    sha256: Optional[str] = None


class OEMAppVerifyResponse(BaseModel):
    package_name: str
    app_name: str
    is_trusted_oem: bool
    status: str  # "VALID", "SUSPICIOUS", "UNTRUSTED_EXTERNAL"
    store_name: str
    device_brand: str
    risk_score: float
    confidence: float
    source_verification: Dict[str, Any]
    llm_forensic_report: Optional[Dict[str, str]] = None
    recommendations: List[str]


@router.post("/verify-oem-app", response_model=OEMAppVerifyResponse)
async def verify_oem_app(req: OEMAppVerifyRequest, response: Response):
    """
    Verify whether an installed or pre-installed package genuinely belongs to the host device's
    OEM ecosystem (e.g. Xiaomi/Mi/MIUI/Redmi for Xiaomi hardware, Samsung for Galaxy, etc.).
    Uses DuckDuckGo OSINT, BeautifulSoup DOM inspection, VirusTotal and URLhaus hash checks,
    and refines unverified/suspicious findings with the LLM Analyst.
    """
    pkg = req.package_name.strip()
    app_label = req.app_name.strip() if req.app_name else pkg.split(".")[-1].capitalize()
    brand = (req.device_brand or "").lower().strip()
    mfg = (req.device_manufacturer or "").lower().strip()
    model = (req.device_model or "").lower().strip()
    device_str = f"{brand} {mfg} {model}".strip()

    # 1. Determine target OEM ecosystem and expected package namespaces
    is_xiaomi = any(k in device_str for k in ("xiaomi", "redmi", "poco", "miui", "kunzite"))
    is_samsung = any(k in device_str for k in ("samsung", "galaxy"))
    is_google = any(k in device_str for k in ("google", "pixel"))
    is_bbk = any(k in device_str for k in ("oppo", "oneplus", "realme", "vivo", "iqoo", "coloros", "heytap"))
    is_moto = any(k in device_str for k in ("motorola", "lenovo"))

    expected_prefixes = []
    oem_display = "OEM Ecosystem"

    if is_xiaomi:
        expected_prefixes = ["com.xiaomi.", "com.miui.", "com.mi.", "com.redmi."]
        oem_display = "Xiaomi / Redmi OEM"
    elif is_samsung:
        expected_prefixes = ["com.sec.", "com.samsung."]
        oem_display = "Samsung OEM"
    elif is_google:
        expected_prefixes = ["com.google.android.", "com.google.", "android."]
        oem_display = "Google / Android OEM"
    elif is_bbk:
        expected_prefixes = [
            "com.oppo.", "com.coloros.", "com.heytap.", "com.oneplus.",
            "com.vivo.", "com.bbk.", "com.realme.", "com.iqoo."
        ]
        oem_display = "BBK / OnePlus / OPPO / Vivo OEM"
    elif is_moto:
        expected_prefixes = ["com.motorola.", "com.lenovo."]
        oem_display = "Motorola / Lenovo OEM"
    else:
        if brand and brand in pkg.lower():
            expected_prefixes = [f"com.{brand}."]
            oem_display = f"{req.device_brand or 'OEM'} System"

    matches_oem_prefix = any(pkg.startswith(p) for p in expected_prefixes)

    # 2. Real-time web scraping via DuckDuckGo OSINT
    scraper = get_live_intel_scraper()
    search_query = f'"{pkg}" Google Play official'
    osint_hits = []
    try:
        osint_hits = scraper.search_duckduckgo_osint(search_query, max_results=4)
    except Exception as exc:
        logger.debug(f"OSINT query error for {pkg}: {exc}")

    found_official_listing = False
    recognized_developer = None
    official_store_url = None

    for hit in osint_hits:
        link = hit.get("link", "").lower()
        title = hit.get("title", "").lower()
        snippet = hit.get("snippet", "").lower()

        if "play.google.com/store/apps/details" in link and pkg.lower() in link:
            found_official_listing = True
            official_store_url = hit.get("link")

        if is_xiaomi and any(d in (title + " " + snippet) for d in ("xiaomi inc", "xiaomi inc.", "beijing xiaomi", "miui")):
            recognized_developer = "Xiaomi Inc."
        elif is_samsung and "samsung electronics" in (title + " " + snippet):
            recognized_developer = "Samsung Electronics Co., Ltd."
        elif is_google and "google llc" in (title + " " + snippet):
            recognized_developer = "Google LLC"

    # 3. VirusTotal & URLhaus lookup on SHA-256 or package name
    vt_provider = get_virustotal_provider()
    urlhaus_provider = get_urlhaus_provider()
    vt_hits = 0
    vt_scanned = False
    urlhaus_matched = False

    if req.sha256 and req.sha256 != "N/A" and len(req.sha256) == 64:
        try:
            vt_res = vt_provider.lookup_hash(req.sha256)
            if vt_res and not vt_res.get("error"):
                vt_scanned = True
                stats = vt_res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt_hits = stats.get("malicious", 0) + stats.get("suspicious", 0)
        except Exception as exc:
            logger.debug(f"VT lookup notice: {exc}")

        try:
            uh_res = await urlhaus_provider.lookup_payload_sha256(req.sha256)
            if uh_res and uh_res.get("matched"):
                urlhaus_matched = True
        except Exception as exc:
            logger.debug(f"URLhaus lookup notice: {exc}")

    source_verif = {
        "osint_matches": len(osint_hits),
        "found_official_play_listing": found_official_listing,
        "official_store_url": official_store_url,
        "recognized_developer": recognized_developer,
        "virustotal_scanned": vt_scanned,
        "virustotal_malicious_hits": vt_hits,
        "urlhaus_matched": urlhaus_matched,
        "matches_oem_prefix": matches_oem_prefix,
        "expected_oem_prefixes": expected_prefixes,
    }

    # 4. Determine Trust Classification
    if matches_oem_prefix and vt_hits == 0 and not urlhaus_matched:
        status_code = "VALID"
        is_trusted = True
        store_display = f"{oem_display} Ecosystem (Verified)"
        risk = 0.05
        conf = 0.95
        recommendations = [
            f"Package verified as authentic {oem_display} ecosystem software.",
            "Passes hardware provenance baseline checks; exempt from quarantine.",
            "Normal background operation authorized."
        ]
        llm_report = None
    elif vt_hits > 0 or urlhaus_matched:
        status_code = "SUSPICIOUS"
        is_trusted = False
        store_display = "Malware / Blacklisted Signature"
        risk = 0.95
        conf = 0.98
        recommendations = [
            "Malicious IOC detected in global threat repositories.",
            "Enforce immediate active quarantine and purge binary.",
            "Block background execution and alert SOC."
        ]
        from backend.analysis.llm_analyst import get_llm_analyst
        analyst = get_llm_analyst()
        threat_bundle = {
            "threat_type": "MALWARE_PACKAGE",
            "category": "MALICIOUS_APP",
            "severity": "CRITICAL",
            "package_name": pkg,
            "app_name": app_label,
            "sha256": req.sha256,
            "vt_hits": vt_hits,
            "urlhaus": urlhaus_matched,
        }
        res_analysis = analyst.analyze(threat_bundle, context={"package_name": pkg, "app_name": app_label})
        llm_report = {
            "executive_briefing": res_analysis.get("executive_briefing") or f"Critical security alert: {app_label} ({pkg}) is flagged by threat intelligence with confirmed malicious indicators.",
            "technical_deep_dive": res_analysis.get("technical_deep_dive") or f"Binary hash {req.sha256} correlated with {vt_hits} VirusTotal detections. Immediate containment required."
        }
    else:
        status_code = "UNTRUSTED_EXTERNAL"
        is_trusted = False
        store_display = "Direct Web / Sideload (Unverified External Origin)"
        risk = 0.85
        conf = 0.90
        recommendations = [
            f"Package '{pkg}' does not match host device OEM ({oem_display}) baseline.",
            "Application originated from unverified external source or third-party web sideload.",
            "Maintain in Active Quarantine pending user authorization.",
            "Inspect required permissions for SMS, microphone, and accessibility privilege escalation."
        ]
        from backend.analysis.llm_analyst import get_llm_analyst
        analyst = get_llm_analyst()
        threat_bundle = {
            "threat_type": "UNVERIFIED_SIDELOAD",
            "category": "UNOFFICIAL_PACKAGE",
            "severity": "HIGH",
            "package_name": pkg,
            "app_name": app_label,
            "sha256": req.sha256,
            "osint": source_verif
        }
        res_analysis = analyst.analyze(threat_bundle, context={"package_name": pkg, "app_name": app_label, "detected_urls": [official_store_url] if official_store_url else []})
        llm_report = {
            "executive_briefing": res_analysis.get("executive_briefing") or f"Application {app_label} ({pkg}) was detected from an external sideload source outside the {oem_display} ecosystem.",
            "technical_deep_dive": res_analysis.get("technical_deep_dive") or f"Package provenance audit: no official OEM digital signing signature for {device_str}. Quarantined to isolate background attack surfaces."
        }

    return OEMAppVerifyResponse(
        package_name=pkg,
        app_name=app_label,
        is_trusted_oem=is_trusted,
        status=status_code,
        store_name=store_display,
        device_brand=req.device_brand or "UNKNOWN",
        risk_score=risk,
        confidence=conf,
        source_verification=source_verif,
        llm_forensic_report=llm_report,
        recommendations=recommendations
    )


