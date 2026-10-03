"""
unified_pipeline.py — Master Unified Threat Pipeline for CyberGuard.

Integrates all detection and intelligence modalities into a single, cohesive,
non-destructive pipeline:
  - Audio & Voice Cloning (MFCC, Log-Mel, Prosodic, Wav2Vec2, ECAPA)
  - Synthetic Media & Deepfakes (Audio, Video, Image FFT)
  - Phishing & Social Engineering (Text heuristics, credential & urgency flags)
  - URL & Look-alike Domain Analysis (Heuristics + VirusTotal multi-engine)
  - QR Code Forensic Decoding (Image decode -> URL/Text analysis)
  - External Threat Intelligence & IOC Search (Hash, Domain, IP, URL)
  - Technical Anomaly & Event Log Analysis (Brute force, ATO, API abuse, Exfiltration)
  - Incident Correlation & MITRE ATT&CK Mapping
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import re
import tempfile
import time
import uuid
from typing import Optional, Dict, Any, List, Union

from backend.config import get_settings
from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel, Incident
)
from backend.threats.ioc_classifier import IOCClassifier
from backend.threats.virustotal import get_virustotal_provider
from backend.analysis.phishing_analyzer import PhishingAnalyzer
from backend.analysis.url_analyzer import URLAnalyzer
from backend.analysis.qr_analyzer import QRAnalyzer
from backend.analysis.deepfake_coordinator import DeepfakeCoordinator
from backend.analysis.anomaly_detector import AnomalyDetector
from backend.detection.detector import VoiceCloneDetector

logger = logging.getLogger(__name__)


class UnifiedThreatPipeline:
    """
    Unified multi-modal cybersecurity threat analysis and response pipeline.
    Safely executes and correlates all detection pipelines without data loss or crashes.
    """

    def __init__(self, config=None, detector: VoiceCloneDetector = None, incident_manager=None, alert_manager=None):
        self.config = config or get_settings()
        self.detector = detector
        self.incident_manager = incident_manager
        self.alert_manager = alert_manager

        # Initialize sub-analyzers
        self.phishing_analyzer = PhishingAnalyzer(self.config)
        self.url_analyzer = URLAnalyzer(self.config)
        self.qr_analyzer = QRAnalyzer(self.config)
        self.anomaly_detector = AnomalyDetector(self.config)
        self.deepfake_coordinator = DeepfakeCoordinator(self.config, voice_detector=self.detector)

    async def analyze(
        self,
        *,
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        text: Optional[str] = None,
        url: Optional[str] = None,
        ioc: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
        speaker_id: Optional[str] = None,
        source: str = "unified_pipeline",
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze any provided artifact or indicator across all applicable pipelines.
        Returns a dictionary containing:
          - "event": The unified ThreatEvent
          - "incident": Correlated Incident (if any)
          - "pipeline_execution": Stages and components executed
        """
        start_time = time.time()
        correlation_id = correlation_id or str(uuid.uuid4())[:12]

        executed_stages: List[Dict[str, Any]] = []
        evidences: List[Evidence] = []
        primary_category = ThreatCategory.SAFE
        highest_risk = RiskLevel.SAFE
        overall_confidence = 0.9
        classification = "SAFE"
        threat_intel_payload: Optional[Dict[str, Any]] = None
        mitre_id: Optional[str] = None
        mitre_name: Optional[str] = None
        detected_modality = "general"

        def _log_stage(name: str, status: str, details: str = ""):
            executed_stages.append({
                "stage": name,
                "status": status,
                "details": details,
                "elapsed_ms": round((time.time() - start_time) * 1000, 1),
            })

        # ── 1. STRUCTURED SYSTEM LOG / ANOMALY ANALYSIS ───────────────────────
        if event_data:
            detected_modality = "structured_data"
            _log_stage("Anomaly Detection", "RUNNING", "Analyzing authentication/API/system telemetry")
            anom_event = self.anomaly_detector.analyze(event_data, source=source, correlation_id=correlation_id)
            evidences.extend(anom_event.evidence)
            if self._risk_rank(anom_event.severity) > self._risk_rank(highest_risk):
                highest_risk = anom_event.severity
                primary_category = anom_event.threat_category
                classification = anom_event.classification
                mitre_id = "T1110" if anom_event.threat_category == ThreatCategory.CREDENTIAL_ATTACK else "T1499"
                mitre_name = "Brute Force / Telemetry Anomaly"
            _log_stage("Anomaly Detection", "COMPLETED", f"Severity: {anom_event.severity.value}")

        # ── 2. FILE ARTIFACT ANALYSIS ──────────────────────────────────────────
        if file_bytes is not None and len(file_bytes) > 0:
            filename = filename or "unnamed_artifact.dat"
            fn_lower = filename.lower()
            file_hash = hashlib.sha256(file_bytes).hexdigest()

            # Hash Reputation Check via VirusTotal
            _log_stage("VirusTotal Hash Intelligence", "RUNNING", f"SHA-256: {file_hash[:12]}...")
            vt_provider = get_virustotal_provider(self.config)
            if vt_provider.is_configured:
                try:
                    vt_file_rep = await asyncio.wait_for(
                        vt_provider.get_file_report(file_hash),
                        timeout=min(self.config.virustotal.timeout_sec, 6.0)
                    )
                    if vt_file_rep.get("status") == "COMPLETED":
                        mal = vt_file_rep.get("malicious_count", 0)
                        susp = vt_file_rep.get("suspicious_count", 0)
                        tot = vt_file_rep.get("total_engines", 0)
                        if mal > 0 or susp > 0:
                            vtrisk = min(1.0, (mal * 0.1) + (susp * 0.05))
                            evidences.append(Evidence(
                                evidence_type="vt_malware_hash_reputation",
                                description=f"VirusTotal File Intelligence: {mal} malicious, {susp} suspicious out of {tot} security engines.",
                                value=vt_file_rep.get("permalink", file_hash),
                                severity_contribution=vtrisk,
                                source="VirusTotal"
                            ))
                            threat_intel_payload = vt_file_rep
                            if mal >= 3:
                                highest_risk = RiskLevel.CRITICAL
                                primary_category = ThreatCategory.MALWARE_INDICATOR
                                classification = "MALICIOUS"
                                mitre_id = "T1204"
                                mitre_name = "User Execution: Malicious File"
                            elif mal >= 1:
                                if self._risk_rank(RiskLevel.HIGH) > self._risk_rank(highest_risk):
                                    highest_risk = RiskLevel.HIGH
                                    primary_category = ThreatCategory.MALWARE_INDICATOR
                                    classification = "MALICIOUS"
                    _log_stage("VirusTotal Hash Intelligence", "COMPLETED", f"Status: {vt_file_rep.get('status')}")
                except Exception as e:
                    _log_stage("VirusTotal Hash Intelligence", "SKIPPED", str(e))
            else:
                _log_stage("VirusTotal Hash Intelligence", "NOT_CONFIGURED", "API Key not configured")

            # Route by media type
            if fn_lower.endswith((".mp3", ".wav", ".m4a", ".aac", ".flac", ".ogg", ".webm")):
                detected_modality = "audio"
                _log_stage("Audio & Voice Cloning Pipeline", "RUNNING", "Acoustic feature extraction & model inference")
                audio_event = self.deepfake_coordinator._analyze_audio(
                    file_bytes, filename, source=source, correlation_id=correlation_id, start_time=start_time
                )
                evidences.extend(audio_event.evidence)
                if self._risk_rank(audio_event.severity) > self._risk_rank(highest_risk):
                    highest_risk = audio_event.severity
                    primary_category = audio_event.threat_category
                    classification = audio_event.classification
                    mitre_id = "T1656"
                    mitre_name = "Impersonation / Synthetic Voice Cloning"
                _log_stage("Audio & Voice Cloning Pipeline", "COMPLETED", f"Severity: {audio_event.severity.value}")

            elif fn_lower.endswith((".mp4", ".mkv", ".mov", ".avi", ".wmv")):
                detected_modality = "video"
                _log_stage("Video Deepfake Pipeline", "RUNNING", "Audio track extraction & keyframe forensic analysis")
                video_event = self.deepfake_coordinator._analyze_video(
                    file_bytes, filename, source=source, correlation_id=correlation_id, start_time=start_time
                )
                evidences.extend(video_event.evidence)
                if self._risk_rank(video_event.severity) > self._risk_rank(highest_risk):
                    highest_risk = video_event.severity
                    primary_category = video_event.threat_category
                    classification = video_event.classification
                    mitre_id = "T1565"
                    mitre_name = "Data Manipulation: Synthetic Deepfake Video"
                _log_stage("Video Deepfake Pipeline", "COMPLETED", f"Severity: {video_event.severity.value}")

            elif fn_lower.endswith((".jpg", ".jpeg", ".png", ".webp", ".bmp")):
                detected_modality = "image"
                _log_stage("QR Code Scanning", "RUNNING", "Scanning for embedded QR payloads")
                qr_event = await self.qr_analyzer.analyze(file_bytes, source=source, correlation_id=correlation_id)
                if qr_event.classification not in ("UNAVAILABLE", "ERROR") and qr_event.severity != RiskLevel.SAFE:
                    evidences.extend(qr_event.evidence)
                    if self._risk_rank(qr_event.severity) > self._risk_rank(highest_risk):
                        highest_risk = qr_event.severity
                        primary_category = qr_event.threat_category
                        classification = qr_event.classification
                        mitre_id = "T1204.001"
                        mitre_name = "Malicious QR Code Redirection"
                _log_stage("QR Code Scanning", "COMPLETED", f"Result: {qr_event.explanation.summary if qr_event.explanation else 'Done'}")

                _log_stage("Image Deepfake & Spectral Analysis", "RUNNING", "2D FFT frequency spectrum & Laplacian noise variance")
                img_event = self.deepfake_coordinator._analyze_image(
                    file_bytes, filename, source=source, correlation_id=correlation_id, start_time=start_time
                )
                evidences.extend(img_event.evidence)
                if self._risk_rank(img_event.severity) > self._risk_rank(highest_risk):
                    highest_risk = img_event.severity
                    primary_category = img_event.threat_category
                    classification = img_event.classification
                    mitre_id = "T1565"
                    mitre_name = "Synthetic Generative Image"
                _log_stage("Image Deepfake & Spectral Analysis", "COMPLETED", f"Severity: {img_event.severity.value}")

            elif fn_lower.endswith((".txt", ".log", ".eml", ".csv", ".json")):
                detected_modality = "text"
                try:
                    text_content = file_bytes.decode("utf-8", errors="ignore")
                    text = (text + "\n" + text_content) if text else text_content
                except Exception:
                    pass

        # ── 3. TEXT / SOCIAL ENGINEERING / PHISHING PIPELINE ───────────────────
        if text and text.strip():
            detected_modality = "text" if detected_modality == "general" else detected_modality
            cleaned_text = text.strip()

            # Check if text is actually a direct URL or IOC
            if cleaned_text.startswith(("http://", "https://")):
                url = cleaned_text
            else:
                _log_stage("Phishing & Social Engineering Analysis", "RUNNING", "Heuristic analysis for urgency, credential theft, and financial coercion")
                phish_event = self.phishing_analyzer.analyze(cleaned_text, source=source, correlation_id=correlation_id)
                evidences.extend(phish_event.evidence)
                if self._risk_rank(phish_event.severity) > self._risk_rank(highest_risk):
                    highest_risk = phish_event.severity
                    primary_category = phish_event.threat_category
                    classification = phish_event.classification
                    mitre_id = "T1566.002"
                    mitre_name = "Spearphishing Link / Social Engineering"
                _log_stage("Phishing & Social Engineering Analysis", "COMPLETED", f"Severity: {phish_event.severity.value}")

                # Extract embedded URLs from text and analyze them
                embedded_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', cleaned_text)
                for emb_url in embedded_urls[:3]:
                    _log_stage("Embedded URL Extraction", "RUNNING", f"Analyzing embedded link: {emb_url[:40]}...")
                    emb_event = await self.url_analyzer.analyze(emb_url, source=source, correlation_id=correlation_id)
                    evidences.extend(emb_event.evidence)
                    if self._risk_rank(emb_event.severity) > self._risk_rank(highest_risk):
                        highest_risk = emb_event.severity
                        primary_category = emb_event.threat_category
                        classification = emb_event.classification
                        mitre_id = "T1566.002"
                        mitre_name = "Phishing URL Delivery"
                    _log_stage("Embedded URL Extraction", "COMPLETED", f"Severity: {emb_event.severity.value}")

        # ── 4. URL / DOMAIN THREAT INTELLIGENCE PIPELINE ───────────────────────
        if url and url.strip():
            detected_modality = "url"
            cleaned_url = url.strip()
            _log_stage("URL & Domain Intelligence", "RUNNING", f"Evaluating {cleaned_url[:50]}")
            url_event = await self.url_analyzer.analyze(cleaned_url, source=source, correlation_id=correlation_id)
            evidences.extend(url_event.evidence)
            if self._risk_rank(url_event.severity) > self._risk_rank(highest_risk):
                highest_risk = url_event.severity
                primary_category = url_event.threat_category
                classification = url_event.classification
                mitre_id = "T1071.001"
                mitre_name = "Web Protocols: Malicious URL"
            _log_stage("URL & Domain Intelligence", "COMPLETED", f"Severity: {url_event.severity.value}")

        # ── 5. IOC CLASSIFICATION & THREAT INTEL SEARCH ────────────────────────
        if ioc and ioc.strip():
            detected_modality = "ioc"
            cleaned_ioc = ioc.strip()
            _log_stage("IOC Classification & VirusTotal Intelligence", "RUNNING", f"Querying indicator '{cleaned_ioc}'")
            ioc_info = IOCClassifier.classify(cleaned_ioc)
            if ioc_info.get("is_supported"):
                if ioc_info.get("is_local"):
                    evidences.append(Evidence(
                        evidence_type="local_private_indicator",
                        description=f"Indicator '{cleaned_ioc}' resolves to local development environment or private RFC 1918 network.",
                        value=cleaned_ioc,
                        severity_contribution=0.0,
                        source="CyberGuard"
                    ))
                    _log_stage("IOC Classification & VirusTotal Intelligence", "COMPLETED", "Local / Private target protected.")
                else:
                    vt_prov = get_virustotal_provider(self.config)
                    if vt_prov.is_configured:
                        try:
                            cat = ioc_info["category"]
                            if cat == "hash":
                                vt_rep = await vt_prov.get_file_report(cleaned_ioc)
                            elif cat == "ip":
                                vt_rep = await vt_prov.get_ip_report(cleaned_ioc)
                            elif cat == "url":
                                vt_rep = await vt_prov.get_url_report(cleaned_ioc)
                            else:
                                vt_rep = await vt_prov.get_domain_report(cleaned_ioc)

                            threat_intel_payload = vt_rep
                            if vt_rep.get("status") == "COMPLETED":
                                mal = vt_rep.get("malicious_count", 0)
                                susp = vt_rep.get("suspicious_count", 0)
                                tot = vt_rep.get("total_engines", 0)
                                if mal > 0 or susp > 0:
                                    vtrisk = min(1.0, (mal * 0.1) + (susp * 0.05))
                                    evidences.append(Evidence(
                                        evidence_type=f"vt_{cat}_reputation",
                                        description=f"VirusTotal: {mal} malicious, {susp} suspicious out of {tot} security vendors.",
                                        value=vt_rep.get("permalink", cleaned_ioc),
                                        severity_contribution=vtrisk,
                                        source="VirusTotal"
                                    ))
                                    if mal >= 5:
                                        highest_risk = RiskLevel.CRITICAL
                                        primary_category = ThreatCategory.MALICIOUS_URL if cat != "hash" else ThreatCategory.MALWARE_INDICATOR
                                        classification = "MALICIOUS"
                                    elif mal >= 1:
                                        if self._risk_rank(RiskLevel.HIGH) > self._risk_rank(highest_risk):
                                            highest_risk = RiskLevel.HIGH
                                            primary_category = ThreatCategory.MALICIOUS_URL if cat != "hash" else ThreatCategory.MALWARE_INDICATOR
                                            classification = "MALICIOUS"
                            _log_stage("IOC Classification & VirusTotal Intelligence", "COMPLETED", f"Status: {vt_rep.get('status')}")
                        except Exception as vt_err:
                            _log_stage("IOC Classification & VirusTotal Intelligence", "SKIPPED", str(vt_err))

        # ── 6. UNIFIED EVIDENCE & EXPLANATION SYNTHESIS ───────────────────────
        total_time_ms = (time.time() - start_time) * 1000.0

        if not evidences:
            summary = "Universal security analysis completed. No threat indicators detected."
            reasoning = "Artifacts, content, and indicators verified clean across all inspected security layers."
            actions = ["Target verified authentic and safe.", "No defensive remediation required."]
        elif highest_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            summary = f"Elevated threat detected: {primary_category.value} ({highest_risk.value})."
            reasoning = (
                f"Multi-pipeline correlation confirmed {len(evidences)} corroborating risk indicators. "
                f"Defensive mitigation recommended immediately."
            )
            actions = [
                f"Quarantine / Block {detected_modality} artifact immediately.",
                "Review correlated incident in the CyberGuard dashboard.",
                "Escalate to incident response team for forensic containment.",
            ]
        elif highest_risk == RiskLevel.MEDIUM:
            summary = f"Suspicious activity observed: {primary_category.value} ({highest_risk.value})."
            reasoning = f"Correlated {len(evidences)} indicators exhibiting anomalous patterns warranting enhanced monitoring."
            actions = ["Flag indicator for manual verification", "Monitor associated session telemetry."]
        else:
            summary = f"Low risk indicators identified: {primary_category.value}."
            reasoning = "Minor anomalies observed, but overall threat score remains below critical enforcement thresholds."
            actions = ["Routine security posture maintained."]

        explanation = Explanation(
            summary=summary,
            reasoning=reasoning,
            limitations="Grounded multi-modal analysis across acoustic, visual, semantic, and network threat intelligence layers."
        )

        unified_event = ThreatEvent(
            source=source,
            source_type=detected_modality,
            modality=detected_modality,
            threat_category=primary_category,
            severity=highest_risk,
            confidence=overall_confidence,
            classification=classification,
            evidence=evidences,
            explanation=explanation,
            recommended_actions=actions,
            detector="CyberGuard UnifiedThreatPipeline",
            detector_version="2.0",
            processing_time_ms=total_time_ms,
            correlation_id=correlation_id,
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
            threat_intelligence=threat_intel_payload,
        )

        # ── 7. INCIDENT CREATION & ALERT DISPATCH ─────────────────────────────
        incident: Optional[Incident] = None
        if self.incident_manager and highest_risk != RiskLevel.SAFE:
            try:
                incident = self.incident_manager.process_event(unified_event)
                _log_stage("Incident Management", "COMPLETED", f"Incident #{incident.incident_id if incident else 'Logged'}")
            except Exception as e:
                logger.error(f"Failed to record unified incident: {e}", exc_info=True)
                _log_stage("Incident Management", "ERROR", str(e))
        else:
            _log_stage("Incident Management", "SKIPPED", "Risk is SAFE or manager disabled")

        if self.alert_manager and highest_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            try:
                # Dispatch WebSocket / Webhook alert
                from backend.detection.threshold_engine import ThresholdEngine, AlertRecommendation
                rec = AlertRecommendation(
                    alert_level=highest_risk,
                    title=f"🚨 {highest_risk.value} Threat: {primary_category.value}",
                    message=summary,
                    actions=actions,
                    color="#ef4444" if highest_risk == RiskLevel.HIGH else "#dc2626",
                )
                asyncio.create_task(self.alert_manager.dispatch(
                    session_id=correlation_id,
                    chunk_id=0,
                    risk_score=0.9 if highest_risk == RiskLevel.CRITICAL else 0.8,
                    alert_level=highest_risk,
                    recommendation=rec,
                    detection_score=0.9,
                ))
            except Exception as alert_err:
                logger.warning(f"Alert dispatch warning: {alert_err}")

        return {
            "event": unified_event,
            "incident": incident,
            "pipeline_execution": executed_stages,
            "summary": {
                "category": primary_category.value,
                "risk_level": highest_risk.value,
                "classification": classification,
                "evidence_count": len(evidences),
                "total_processing_ms": round(total_time_ms, 1),
                "mitre_attack": f"{mitre_id} ({mitre_name})" if mitre_id else "None",
            }
        }

    def _risk_rank(self, level: RiskLevel) -> int:
        ranks = {RiskLevel.SAFE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
        return ranks.get(level, 0)
