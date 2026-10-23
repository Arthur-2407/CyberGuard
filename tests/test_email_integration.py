"""
test_email_integration.py — Comprehensive Unit & Integration Test Suite for Brevo Email Alerts.

Covers:
  - Missing and invalid credentials
  - Invalid sender/recipient email validation
  - Mocked HTTP 201 successful dispatch & Message-ID extraction
  - Mocked HTTP 401 unauthorized & IP restriction errors
  - Mocked HTTP 429 rate limiting
  - Mocked HTTP 500 transient error with bounded retries
  - Network timeout resilience
  - Secret redaction (guaranteed no API key leaks)
  - Policy gating (enabled/disabled, severity thresholds)
  - Duplicate alert suppression
  - Daily zero-cost usage cap (250/day limit)
  - Relational database persistence (email_alert_records)
  - Admin RBAC enforcement & test alert endpoint
"""

import asyncio
import datetime
import json
import os
import unittest.mock as mock
import pytest
import httpx
from fastapi.testclient import TestClient

from backend.alerts.brevo_client import BrevoEmailClient, BrevoSendResult
from backend.alerts.email_notifier import EmailNotifier, get_email_notifier
from backend.config import get_settings, reload_settings
from backend.main import app
from backend.storage.database import init_db, get_session_factory, EmailAlertRecordModel, UserModel
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def admin_headers(client):
    """Authenticate as default admin and return bearer token header."""
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "admin", "password": "Admin@CyberGuard2026!"},
    )
    assert resp.status_code == 200
    token = resp.json().get("token") or resp.json().get("access_token")
    return {"Authorization": f"Bearer {token}"}



# ── 1. Brevo Client Offline Unit Tests ────────────────────────────────────────

@pytest.mark.asyncio
async def test_brevo_missing_api_key():
    client = BrevoEmailClient(api_key="", default_sender_email="soc@cyberguard.local")
    res = await client.send_alert_email(
        recipient="analyst@cyberguard.local",
        subject="Test Alert",
        html_content="<p>test</p>",
        plain_text_content="test",
    )
    assert res.success is False
    assert res.delivery_status == "CONFIGURATION_REQUIRED"
    assert "Missing Brevo API key" in res.error_message


@pytest.mark.asyncio
async def test_brevo_invalid_sender_email():
    client = BrevoEmailClient(api_key="mock-key-123", default_sender_email="not-an-email")
    res = await client.send_alert_email(
        recipient="analyst@cyberguard.local",
        subject="Test Alert",
        html_content="<p>test</p>",
        plain_text_content="test",
    )
    assert res.success is False
    assert res.delivery_status == "CONFIGURATION_REQUIRED"
    assert "Invalid or missing sender" in res.error_message


@pytest.mark.asyncio
async def test_brevo_invalid_recipient_email():
    client = BrevoEmailClient(api_key="mock-key-123", default_sender_email="soc@cyberguard.local")
    res = await client.send_alert_email(
        recipient="bad-recipient-format",
        subject="Test Alert",
        html_content="<p>test</p>",
        plain_text_content="test",
    )
    assert res.success is False
    assert res.delivery_status == "SEND_FAILED"
    assert "Invalid recipient email" in res.error_message


@pytest.mark.asyncio
async def test_brevo_successful_mocked_201():
    fake_key = "xkeysib-mock-123456789"
    client = BrevoEmailClient(api_key=fake_key, default_sender_email="soc@cyberguard.local")

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"messageId": "<202610091200.brevo-uuid@smtp-relay.brevo.com>"}

    with mock.patch("httpx.AsyncClient.post", new_callable=mock.AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await client.send_alert_email(
            recipient="admin@cyberguard.local",
            subject="CRITICAL Incident Alert",
            html_content="<b>Urgent</b>",
            plain_text_content="Urgent",
        )

        assert res.success is True
        assert res.delivery_status == "PROVIDER_ACCEPTED"
        assert res.http_status == 201
        assert res.message_id == "<202610091200.brevo-uuid@smtp-relay.brevo.com>"
        assert res.attempt_count == 1

        # Verify request headers & payload
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["headers"]["api-key"] == fake_key
        assert call_kwargs["json"]["sender"]["email"] == "soc@cyberguard.local"
        assert call_kwargs["json"]["to"][0]["email"] == "admin@cyberguard.local"


@pytest.mark.asyncio
async def test_brevo_unauthorized_401():
    fake_key = "xkeysib-invalid-secret-key"
    client = BrevoEmailClient(api_key=fake_key, default_sender_email="soc@cyberguard.local")

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = '{"message":"Key not found or IP not authorized","code":"unauthorized"}'
    mock_resp.json.return_value = {"message": "Key not found or IP not authorized", "code": "unauthorized"}

    with mock.patch("httpx.AsyncClient.post", new_callable=mock.AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await client.send_alert_email(
            recipient="admin@cyberguard.local",
            subject="Test",
            html_content="<p>Test</p>",
            plain_text_content="Test",
        )

        assert res.success is False
        assert res.delivery_status == "SEND_FAILED"
        assert res.http_status == 401
        assert "unauthorized" in res.error_message or "Key not found" in res.error_message
        assert mock_post.call_count == 1  # Permanent error, must NOT retry


@pytest.mark.asyncio
async def test_brevo_rate_limit_429():
    client = BrevoEmailClient(api_key="mock-key", default_sender_email="soc@cyberguard.local")

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 429
    mock_resp.text = '{"message":"Rate limit exceeded"}'
    mock_resp.json.return_value = {"message": "Rate limit exceeded"}

    with mock.patch("httpx.AsyncClient.post", new_callable=mock.AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await client.send_alert_email(
            recipient="admin@cyberguard.local",
            subject="Test",
            html_content="<p>Test</p>",
            plain_text_content="Test",
        )

        assert res.success is False
        assert res.delivery_status == "SEND_FAILED"
        assert res.http_status == 429
        assert "rate limit exceeded" in res.error_message.lower()


@pytest.mark.asyncio
async def test_brevo_transient_500_with_bounded_retries():
    client = BrevoEmailClient(api_key="mock-key", default_sender_email="soc@cyberguard.local", max_retries=2)

    err_resp = mock.MagicMock()
    err_resp.status_code = 502
    err_resp.text = "Bad Gateway"
    err_resp.json.side_effect = Exception("Not JSON")

    success_resp = mock.MagicMock()
    success_resp.status_code = 201
    success_resp.json.return_value = {"messageId": "<recovered-502-msg-id>"}

    with mock.patch("httpx.AsyncClient.post", new_callable=mock.AsyncMock) as mock_post:
        # Fails once with 502, then succeeds with 201
        mock_post.side_effect = [err_resp, success_resp]
        res = await client.send_alert_email(
            recipient="admin@cyberguard.local",
            subject="Test",
            html_content="<p>Test</p>",
            plain_text_content="Test",
        )

        assert res.success is True
        assert res.delivery_status == "PROVIDER_ACCEPTED"
        assert res.attempt_count == 2
        assert res.message_id == "<recovered-502-msg-id>"


@pytest.mark.asyncio
async def test_brevo_network_timeout():
    client = BrevoEmailClient(api_key="mock-key", default_sender_email="soc@cyberguard.local", max_retries=1)

    with mock.patch("httpx.AsyncClient.post", side_effect=httpx.ConnectTimeout("Connection timed out")):
        res = await client.send_alert_email(
            recipient="admin@cyberguard.local",
            subject="Test",
            html_content="<p>Test</p>",
            plain_text_content="Test",
        )

        assert res.success is False
        assert res.delivery_status == "SEND_FAILED"
        assert "ConnectTimeout" in res.error_message or "timed out" in res.error_message


def test_secret_redaction_sanitizer():
    secret_key = "xkeysib-super-confidential-secret-key-9999"
    client = BrevoEmailClient(api_key=secret_key, default_sender_email="soc@cyberguard.local")
    leak_string = f"Error sending with header api-key: {secret_key} on host"
    sanitized = client._sanitize_error_text(leak_string)
    assert secret_key not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized


# ── 2. Policy Gating & Notifier Logic Tests ────────────────────────────────────

def test_severity_level_evaluation():
    notifier = EmailNotifier()
    # When threshold is CRITICAL:
    assert notifier._should_trigger_for_level("CRITICAL", "CRITICAL") is True
    assert notifier._should_trigger_for_level("HIGH", "CRITICAL") is False
    assert notifier._should_trigger_for_level("MEDIUM", "CRITICAL") is False
    assert notifier._should_trigger_for_level("LOW", "CRITICAL") is False

    # When threshold is HIGH:
    assert notifier._should_trigger_for_level("CRITICAL", "HIGH") is True
    assert notifier._should_trigger_for_level("HIGH", "HIGH") is True
    assert notifier._should_trigger_for_level("MEDIUM", "HIGH") is False

    # When threshold is MEDIUM:
    assert notifier._should_trigger_for_level("MEDIUM", "MEDIUM") is True
    assert notifier._should_trigger_for_level("LOW", "MEDIUM") is False


@pytest.mark.asyncio
async def test_notification_disabled_policy():
    notifier = EmailNotifier()
    event = ThreatEvent(
        source="TestRunner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.CRITICAL,
        classification="TEST",
        explanation=Explanation(summary="Disabled test", reasoning="Policy check verification"),
        detector="UnitTestDetector",
    )

    with mock.patch.object(notifier, "_get_active_policy", return_value={"email_alerts_enabled": False}):
        with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
            res = await notifier.notify_threat_event(event)
            assert res["status"] == "skipped"
            assert res["reason"] == "EMAIL_ALERTS_DISABLED"
            mock_dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_below_threshold_suppression():
    notifier = EmailNotifier()
    event = ThreatEvent(
        source="TestRunner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.LOW,
        classification="TEST",
        explanation=Explanation(summary="Low risk event", reasoning="Below threshold check"),
        detector="UnitTestDetector",
    )


    with mock.patch.object(notifier, "_get_active_policy", return_value={"email_alerts_enabled": True, "email_alert_threshold": "CRITICAL"}):
        with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
            res = await notifier.notify_threat_event(event)
            assert res["status"] == "skipped"
            assert "BELOW_THRESHOLD" in res["reason"]
            mock_dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_safe_event_email_suppressed():
    notifier = EmailNotifier()
    safe_event = ThreatEvent(
        source="TestRunner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.SAFE,
        severity=RiskLevel.SAFE,
        classification="LIKELY_AUTHENTIC",
        explanation=Explanation(summary="Safe event", reasoning="Clean domain"),
        detector="UnitTestDetector",
    )

    with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
        res = await notifier.notify_threat_event(safe_event)
        assert res["status"] == "skipped"
        assert res["reason"] in ("SAFE_EVENT_SUPPRESSED", "AUTHENTIC_EVENT_SUPPRESSED")
        mock_dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_recipient_category_cooldown():
    notifier = EmailNotifier()
    target_recipient = "test_cooldown@cyberguard.defense"
    notifier._last_sent_by_target[f"{target_recipient}:PHISHING"] = 9999999999.0

    crit_event = ThreatEvent(
        source="TestRunner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.CRITICAL,
        classification="PHISHING_DETECTED",
        explanation=Explanation(summary="Phishing attempt", reasoning="Credential harvesting domain"),
        detector="UnitTestDetector",
        user_email=target_recipient,
    )

    with mock.patch.object(notifier, "_get_active_policy", return_value={"email_alerts_enabled": True, "email_alert_threshold": "CRITICAL"}):
        with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
            res = await notifier.notify_threat_event(crit_event, user_email=target_recipient)
            assert res["status"] == "skipped"
            assert res["reason"] == "COOLDOWN_ACTIVE"
            mock_dispatch.assert_not_called()


def test_numeric_threshold_evaluation():
    notifier = EmailNotifier()
    # "85" should mean 85% (rank 4 -> CRITICAL)
    assert notifier._should_trigger_for_level("CRITICAL", "85") is True
    assert notifier._should_trigger_for_level("HIGH", "85") is False
    assert notifier._should_trigger_for_level("MEDIUM", "85") is False
    # "70" should mean rank 3 -> HIGH
    assert notifier._should_trigger_for_level("HIGH", "70") is True
    assert notifier._should_trigger_for_level("MEDIUM", "70") is False


@pytest.mark.asyncio
async def test_daily_quota_protection():
    notifier = EmailNotifier()
    # Mock daily count exceeding limit
    with mock.patch.object(notifier, "_count_today_dispatched", return_value=250):
        res = await notifier._dispatch_email(
            recipient="test@cyberguard.local",
            subject="Exceeded Alert",
            alert_level="CRITICAL",
            risk_score=1.0,
            title="Title",
            description="Desc",
            actions=[],
            target_id="TGT-123",
            threat_type="PHISHING",
        )
        assert res["delivery_status"] == "SEND_FAILED"
        assert "limit exceeded" in res["error"].lower()


@pytest.mark.asyncio
async def test_duplicate_suppression():
    notifier = EmailNotifier()
    notifier.test_mode = True

    # Send first time
    with mock.patch("backend.alerts.brevo_client.BrevoEmailClient.send_alert_email", new_callable=mock.AsyncMock) as mock_send:
        mock_send.return_value = BrevoSendResult(
            success=True, delivery_status="PROVIDER_ACCEPTED", http_status=201, message_id="<dup-1>"
        )

        res1 = await notifier._dispatch_email(
            recipient="unique-soc@cyberguard.local",
            subject="Unique Incident Trigger 001",
            alert_level="CRITICAL",
            risk_score=1.0,
            title="Incident Title",
            description="Details",
            actions=[],
            target_id="TGT-DUP-1",
            threat_type="PHISHING",
        )
        assert res1["delivery_status"] == "PROVIDER_ACCEPTED"

        # Immediate repeat of same recipient + subject + threat_type
        res2 = await notifier._dispatch_email(
            recipient="unique-soc@cyberguard.local",
            subject="Unique Incident Trigger 001",
            alert_level="CRITICAL",
            risk_score=1.0,
            title="Incident Title",
            description="Details",
            actions=[],
            target_id="TGT-DUP-2",
            threat_type="PHISHING",
        )
        assert res2["status"] == "suppressed"
        assert res2["reason"] == "DUPLICATE_ALERT_SUPPRESSED"


# ── 3. Database Persistence & Admin Endpoints ─────────────────────────────────

def test_database_persistence_and_journal_query():
    notifier = EmailNotifier()
    test_id = f"test-db-{datetime.datetime.now().timestamp()}"
    rec = {
        "alert_id": test_id,
        "recipient": "db-test@cyberguard.local",
        "subject": "DB Persistence Verification",
        "alert_level": "CRITICAL",
        "risk_score": 0.99,
        "target_id": "TGT-DB",
        "threat_type": "TEST",
        "provider": "brevo",
        "delivery_status": "PROVIDER_ACCEPTED",
        "provider_message_id": "<test-msg-id-123>",
        "error_message": None,
        "attempt_count": 1,
    }
    notifier._persist_to_database(rec)

    alerts = notifier.get_recent_email_alerts(limit=10)
    assert len(alerts) > 0
    matched = [a for a in alerts if a.get("alert_id") == test_id]
    assert len(matched) == 1
    assert matched[0]["delivery_status"] == "PROVIDER_ACCEPTED"
    assert matched[0]["provider_message_id"] == "<test-msg-id-123>"


def test_admin_email_endpoints_rbac(client):
    # Unauthenticated should receive 401
    resp1 = client.get("/api/admin/email-alerts")
    assert resp1.status_code in (401, 403)

    resp2 = client.post("/api/admin/email-alerts/test", json={"severity": "CRITICAL"})
    assert resp2.status_code in (401, 403)


def test_admin_email_test_dispatch_and_journal(client, admin_headers):
    # Dispatch test alert via admin endpoint
    test_subj = f"Admin Pytest Verification {datetime.datetime.now().timestamp()}"
    resp = client.post(
        "/api/admin/email-alerts/test",
        headers=admin_headers,
        json={"severity": "CRITICAL", "subject": test_subj},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "dispatched"
    assert "delivery_status" in data

    # Query email alerts journal
    journal_resp = client.get("/api/admin/email-alerts", headers=admin_headers)
    assert journal_resp.status_code == 200
    j_data = journal_resp.json()
    entries = j_data.get("email_alerts") or j_data.get("emails") or []
    assert len(entries) > 0
    assert any(test_subj in e.get("subject", "") for e in entries)
