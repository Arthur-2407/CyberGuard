"""
tests/test_notification_dispatcher_and_verdict.py
Verification test suite for:
  1. Centralized ThreatNotificationDispatcher severity gating (LOW/MEDIUM vs HIGH/CRITICAL).
  2. Durable Outbox deduplication and audit history.
  3. Malware Lab VerdictEngine handling of provider failures (VT ERROR/TIMEOUT -> PARTIAL_SCAN).
  4. Threat Intel Search status polling endpoint (/api/threats/search/status/{analysis_id}).
"""

import pytest
import uuid
import time
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.alerts.notification_dispatcher import get_notification_dispatcher
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation
from backend.analysis.malware.file_analyzer import FileFormatAnalyzer
from backend.analysis.malware.clamav_scanner import ClamAVScanResult
from backend.analysis.malware.yara_scanner import YaraScanResult
from backend.analysis.malware.verdict_engine import MalwareVerdictEngine
from backend.api.routes_threats import _THREAT_SEARCH_CACHE


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.mark.asyncio
async def test_dispatcher_severity_gating_low_and_medium():
    dispatcher = get_notification_dispatcher()
    
    # LOW risk event
    low_event = ThreatEvent(
        event_id=str(uuid.uuid4()),
        source="test_suite",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.SAFE,
        classification="BENIGN_DOMAIN",
        severity=RiskLevel.LOW,
        confidence=0.9,
        explanation=Explanation(
            summary="Low risk domain",
            reasoning="Benign test"
        ),
        user_id=1,
        user_email="low_user@example.com"
    )
    
    result = await dispatcher.dispatch_threat_event(low_event)
    assert result["status"] == "skipped"
    assert "SEVERITY_BELOW_THRESHOLD" in result["reason"]
    assert result["severity"] == "LOW"
    assert result["gated"] is True

    # MEDIUM risk event
    med_event = ThreatEvent(
        event_id=str(uuid.uuid4()),
        source="test_suite",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.SUSPICIOUS_NETWORK_ACTIVITY,
        classification="SUSPICIOUS_ACTIVITY",
        severity=RiskLevel.MEDIUM,
        confidence=0.8,
        explanation=Explanation(
            summary="Medium risk domain",
            reasoning="Suspicious test"
        ),
        user_id=1,
        user_email="med_user@example.com"
    )
    
    result_med = await dispatcher.dispatch_threat_event(med_event)
    assert result_med["status"] == "skipped"
    assert "SEVERITY_BELOW_THRESHOLD" in result_med["reason"]
    assert result_med["severity"] == "MEDIUM"
    assert result_med["gated"] is True


@pytest.mark.asyncio
async def test_dispatcher_severity_gating_high_and_critical():
    dispatcher = get_notification_dispatcher()
    unique_ioc = f"http://malware-{uuid.uuid4().hex[:8]}.com/payload.exe"
    
    high_event = ThreatEvent(
        event_id=str(uuid.uuid4()),
        source="threat_intelligence",
        source_type="ioc_search",
        modality="url",
        threat_category=ThreatCategory.MALICIOUS_URL,
        classification="MALWARE_URL_DETECTED",
        severity=RiskLevel.HIGH,
        confidence=0.95,
        explanation=Explanation(
            summary="High severity malware payload detected",
            reasoning="Verified active C2 beacon"
        ),
        user_id=1,
        user_email="soc_analyst_high@example.com"
    )
    
    with patch("backend.alerts.email_notifier.EmailNotifier.notify_threat_event", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = {"status": "sent", "delivery_status": "PROVIDER_ACCEPTED"}
        result = await dispatcher.dispatch_threat_event(high_event)
        assert result["status"] == "queued"
        assert result["severity"] == "HIGH"
        assert result["eligible"] is True
        assert "outbox_id" in result


@pytest.mark.asyncio
async def test_dispatcher_deduplication_cooldown():
    dispatcher = get_notification_dispatcher()
    unique_ioc = f"http://repeat-c2-{uuid.uuid4().hex[:8]}.com/bot.exe"
    
    event1 = ThreatEvent(
        event_id=str(uuid.uuid4()),
        source="threat_intelligence",
        source_type="ioc_search",
        modality="url",
        threat_category=ThreatCategory.MALICIOUS_URL,
        classification="CRITICAL_C2_BEACON",
        severity=RiskLevel.CRITICAL,
        confidence=0.99,
        explanation=Explanation(
            summary=f"Critical ransomware download from {unique_ioc}",
            reasoning="Matched high-confidence signature"
        ),
        user_id=1,
        user_email="admin_dedup@example.com"
    )
    
    with patch("backend.alerts.email_notifier.EmailNotifier.notify_threat_event", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = {"status": "sent", "delivery_status": "PROVIDER_ACCEPTED"}
        res1 = await dispatcher.dispatch_threat_event(event1)
        assert res1["status"] == "queued"

        # Second submission of identical alert within cooldown window
        event2 = ThreatEvent(
            event_id=str(uuid.uuid4()),
            source="threat_intelligence",
            source_type="ioc_search",
            modality="url",
            threat_category=ThreatCategory.MALICIOUS_URL,
            classification="CRITICAL_C2_BEACON",
            severity=RiskLevel.CRITICAL,
            confidence=0.99,
            explanation=Explanation(
                summary=f"Critical ransomware download from {unique_ioc}",
                reasoning="Matched high-confidence signature"
            ),
            user_id=1,
            user_email="admin_dedup@example.com"
        )
        res2 = await dispatcher.dispatch_threat_event(event2)
        assert res2["status"] == "skipped"
        assert res2["reason"] == "DUPLICATE_ALERT_COOLDOWN_ACTIVE"


def test_dispatcher_outbox_audit_history():
    dispatcher = get_notification_dispatcher()
    history = dispatcher.get_audit_history(limit=50)
    assert isinstance(history, list)
    if history:
        rec = history[0]
        assert "alert_id" in rec
        assert "severity" in rec
        assert "status" in rec
        assert "timestamp" in rec


def test_verdict_engine_with_vt_error_not_reported_as_safe():
    """
    Ensure when VirusTotal returns ERROR or TIMEOUT, the engine verdict is PARTIAL_SCAN
    with risk_score >= 0.35 and is NOT falsely reported as SAFE or NO_DETECTION.
    """
    engine = MalwareVerdictEngine()
    analyzer = FileFormatAnalyzer()
    file_insp = analyzer.analyze(b"Normal clean documentation file content.", filename="doc.txt")

    clamav_res = ClamAVScanResult(
        engine="ClamAV",
        available=True,
        status="NO_DETECTION"
    )
    yara_res = YaraScanResult(
        engine="YARA",
        available=True,
        status="NO_DETECTION"
    )
    vt_report = {
        "status": "ERROR",
        "configured": True,
        "message": "VirusTotal API connection timeout or quota exceeded",
        "elapsed_ms": 5000.0
    }

    verdict = engine.correlate(
        file_inspection=file_insp,
        clamav_result=clamav_res,
        yara_result=yara_res,
        vt_report=vt_report
    )

    assert verdict.scan_coverage == "PARTIAL"
    assert "VirusTotal Multi-Scanner Reputation" in verdict.missing_engines
    assert verdict.verdict == "PARTIAL_SCAN"
    assert verdict.risk_score >= 0.35
    assert verdict.risk_score != 0.05
    vt_summary = next(e for e in verdict.engines if "VirusTotal" in e.name)
    assert vt_summary.status == "ERROR"
    assert "timeout" in vt_summary.details.lower() or "quota" in vt_summary.details.lower()


def test_threat_search_status_endpoint_cache_retrieval(client):
    test_id = f"test-analysis-{uuid.uuid4().hex}"
    mock_event = ThreatEvent(
        event_id=test_id,
        source="threat_intelligence",
        source_type="ioc_search",
        modality="url",
        threat_category=ThreatCategory.MALICIOUS_URL,
        classification="CONFIRMED_MALICIOUS_IOC",
        severity=RiskLevel.CRITICAL,
        confidence=0.99,
        explanation=Explanation(
            summary="Critical threat IOC confirmed",
            reasoning="Corroborated by VirusTotal and URLhaus"
        ),
        threat_score=0.95,
        correlation_id=test_id
    )
    _THREAT_SEARCH_CACHE[test_id] = mock_event
    
    resp = client.get(f"/api/threats/search/status/{test_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_id"] == test_id
    assert data["severity"] == "CRITICAL"
    assert data["classification"] == "CONFIRMED_MALICIOUS_IOC"
