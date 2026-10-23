import time
import io
import urllib.parse
import logging
import uuid
from typing import List, Optional

from backend.threats.models import (
    ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel
)
from backend.analysis.url_analyzer import URLAnalyzer
from backend.analysis.phishing_analyzer import PhishingAnalyzer

logger = logging.getLogger(__name__)


class QRAnalyzer:
    """Analyzes QR codes for embedded malicious payloads (URLs, phishing text)."""

    def __init__(self, config=None):
        self.config = config
        self.url_analyzer = URLAnalyzer(config)
        self.phishing_analyzer = PhishingAnalyzer(config)
        self.capability_status = "READY"
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
            self._Image = Image
            self._decode = decode
        except ImportError:
            self.capability_status = "UNAVAILABLE"

    async def analyze(
        self,
        image_bytes: bytes,
        source: str = "qr_submission",
        correlation_id: str = None
    ) -> ThreatEvent:
        start_time = time.time()
        analysis_id = correlation_id or str(uuid.uuid4())

        logger.info(f"analysis_id={analysis_id} stage=QR_DECODE status=STARTED")

        if self.capability_status != "READY":
            logger.warning(f"analysis_id={analysis_id} stage=QR_DECODE status=UNAVAILABLE")
            return self._build_unavailable_event(source, analysis_id, start_time)

        if not image_bytes or len(image_bytes) == 0:
            logger.warning(f"analysis_id={analysis_id} stage=QR_DECODE status=FAILED error=EMPTY_IMAGE")
            return self._build_decode_failed_event(source, "Empty image data provided.", analysis_id, start_time)

        if len(image_bytes) > 25 * 1024 * 1024:
            logger.warning(f"analysis_id={analysis_id} stage=QR_DECODE status=FAILED error=IMAGE_TOO_LARGE")
            return self._build_decode_failed_event(source, "Image exceeds maximum allowed size (25MB).", analysis_id, start_time)

        try:
            image = self._Image.open(io.BytesIO(image_bytes))
            decoded_objects = self._decode(image)

            # Preprocessing fallbacks if direct decode finds nothing
            if not decoded_objects:
                try:
                    gray = image.convert("L")
                    decoded_objects = self._decode(gray)
                except Exception:
                    pass

            if not decoded_objects:
                for angle in (90, 180, 270):
                    try:
                        rot = image.rotate(angle, expand=True)
                        decoded_objects = self._decode(rot)
                        if decoded_objects:
                            break
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"analysis_id={analysis_id} stage=QR_DECODE status=ERROR error={e}")
            return self._build_error_event(source, str(e), analysis_id, start_time)

        if not decoded_objects:
            logger.info(f"analysis_id={analysis_id} stage=QR_DECODE status=NO_QR_FOUND")
            return self._build_decode_failed_event(source, "No QR code could be decoded from the uploaded image.", analysis_id, start_time)

        # Extract all decoded payloads
        decoded_texts: List[str] = []
        for obj in decoded_objects:
            try:
                txt = obj.data.decode("utf-8", errors="replace").strip()
                if txt and txt not in decoded_texts:
                    decoded_texts.append(txt)
            except Exception:
                pass

        if not decoded_texts:
            return self._build_decode_failed_event(source, "QR code contained unreadable or empty binary data.", analysis_id, start_time)

        primary_payload = decoded_texts[0]
        qr_duration_ms = (time.time() - start_time) * 1000.0
        logger.info(f"analysis_id={analysis_id} stage=QR_DECODE status=COMPLETED duration_ms={qr_duration_ms:.1f} count={len(decoded_texts)}")

        # ── Check if payload is a URL ──────────────────────────────────────────
        parsed = urllib.parse.urlparse(primary_payload)
        is_url = parsed.scheme in ["http", "https"]

        if is_url:
            logger.info(f"analysis_id={analysis_id} stage=URL_CLASSIFICATION status=COMPLETED is_url=True url={primary_payload}")

            # Route to shared URL analysis pipeline
            url_event = await self.url_analyzer.analyze(
                primary_payload,
                source=source,
                correlation_id=analysis_id,
            )

            # Adapt the event for QR origin
            url_event.modality = "image/qr"
            url_event.explanation.summary = f"QR Code contained a URL ({primary_payload}). {url_event.explanation.summary}"

            # If multiple QR codes exist in the image, record them in evidence
            if len(decoded_texts) > 1:
                url_event.evidence.append(Evidence(
                    evidence_type="multiple_qr_codes",
                    description=f"Image contained {len(decoded_texts)} distinct QR codes. Analyzed primary URL.",
                    value="; ".join(decoded_texts),
                    severity_contribution=0.0,
                    source="QRAnalyzer"
                ))

            # Enrich threat_intelligence with QR metadata
            if url_event.threat_intelligence is not None:
                url_event.threat_intelligence["qr_metadata"] = {
                    "qr_status": "DECODED",
                    "decoded_payload": primary_payload,
                    "content_type": "URL",
                    "additional_payloads": decoded_texts[1:] if len(decoded_texts) > 1 else [],
                    "analysis_id": analysis_id,
                    "decode_time_ms": round(qr_duration_ms, 1),
                }
                if "performance" in url_event.threat_intelligence and isinstance(url_event.threat_intelligence["performance"], dict):
                    url_event.threat_intelligence["performance"]["qr_decode_ms"] = round(qr_duration_ms, 1)
                    url_event.threat_intelligence["performance"]["total_ms"] = round(
                        url_event.threat_intelligence["performance"].get("total_ms", 0.0) + qr_duration_ms, 1
                    )

            return url_event


        # ── Non-URL Payload: analyze text content with PhishingAnalyzer ────────
        logger.info(f"analysis_id={analysis_id} stage=URL_CLASSIFICATION status=COMPLETED is_url=False type=TEXT")
        text_event = self.phishing_analyzer.analyze(
            primary_payload,
            source=source,
            correlation_id=analysis_id
        )

        text_event.modality = "image/qr"
        if text_event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            text_event.explanation.summary = f"QR Code contained text payload with suspicious phishing indicators: {primary_payload[:60]}"
            text_event.threat_category = ThreatCategory.PHISHING
        else:
            text_event.severity = RiskLevel.SAFE
            text_event.classification = "SAFE"
            text_event.threat_category = ThreatCategory.SAFE
            text_event.explanation.summary = f"QR payload is plain text: {primary_payload[:60]}"
            text_event.explanation.reasoning = "No malicious or phishing keywords detected in plain-text QR payload."

        text_event.threat_intelligence = {
            "provider": "CyberGuard",
            "status": "COMPLETED",
            "indicator": primary_payload[:80],
            "indicator_type": "text",
            "is_local": False,
            "qr_metadata": {
                "qr_status": "DECODED",
                "decoded_payload": primary_payload,
                "content_type": "TEXT",
                "additional_payloads": decoded_texts[1:] if len(decoded_texts) > 1 else [],
                "analysis_id": analysis_id,
                "decode_time_ms": round(qr_duration_ms, 1),
            },
            "summary": {"malicious": 1 if text_event.severity != RiskLevel.SAFE else 0, "total_engines": 1},
            "correlated_assessment": {
                "final_risk": text_event.severity.value,
                "provenance": "Source: CyberGuard Heuristic Analyzer",
                "reasoning": text_event.explanation.reasoning if text_event.explanation else "",
            },
            "performance": {"qr_decode_ms": round(qr_duration_ms, 1), "total_ms": round((time.time() - start_time) * 1000.0, 1)},
        }

        return text_event

    def _build_decode_failed_event(self, source, summary, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="qr",
            modality="image/qr",
            threat_category=ThreatCategory.UNKNOWN,
            severity=RiskLevel.SAFE,
            classification="QR_DECODE_FAILED",
            explanation=Explanation(
                summary=summary,
                reasoning="The uploaded image could not be decoded as a valid QR code. No URL or threat analysis was performed.",
                limitations="Unable to parse QR matrix from image bytes."
            ),
            detector="QRAnalyzer",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id,
            threat_intelligence={
                "provider": "CyberGuard",
                "status": "QR_DECODE_FAILED",
                "indicator": "N/A",
                "indicator_type": "qr",
                "qr_metadata": {
                    "qr_status": "QR_DECODE_FAILED",
                    "error": summary,
                }
            }
        )

    def _build_unavailable_event(self, source, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="qr",
            modality="image/qr",
            threat_category=ThreatCategory.UNKNOWN,
            severity=RiskLevel.SAFE,
            classification="UNAVAILABLE",
            explanation=Explanation(
                summary="QR scanning capability is not installed.",
                reasoning="Missing Pillow or pyzbar dependencies.",
            ),
            capability_status="UNAVAILABLE",
            detector="QRAnalyzer",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id
        )

    def _build_error_event(self, source, error_msg, correlation_id, start_time) -> ThreatEvent:
        return ThreatEvent(
            source=source,
            source_type="qr",
            modality="image/qr",
            threat_category=ThreatCategory.UNKNOWN,
            severity=RiskLevel.LOW,
            classification="ERROR",
            evidence=[Evidence(
                evidence_type="qr_decode_error",
                description="Failed to decode QR image.",
                value=error_msg,
                source="QRAnalyzer"
            )],
            explanation=Explanation(
                summary="Error occurred while trying to decode QR code.",
                reasoning=error_msg
            ),
            detector="QRAnalyzer",
            processing_time_ms=(time.time() - start_time) * 1000.0,
            correlation_id=correlation_id
        )
