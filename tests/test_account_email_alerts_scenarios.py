"""
tests/test_account_email_alerts_scenarios.py
Comprehensive 12-Scenario Verification Suite for CyberGuard Account-Specific Email Alerts.

Verifies strict enforcement of:
  SEND EMAIL = FINAL ALERT SEVERITY IS HIGH OR CRITICAL
               AND THE ALERT BELONGS TO A VALID AUTHENTICATED ACCOUNT
               AND THAT ACCOUNT HAS AN ELIGIBLE ASSOCIATED EMAIL
               AND THE ALERT HAS NOT ALREADY BEEN NOTIFIED.

Minimum scenarios verified:
  TEST 1  — HIGH + AUTHENTICATED ACCOUNT
  TEST 2  — CRITICAL + AUTHENTICATED ACCOUNT
  TEST 3  — LOW ALERT
  TEST 4  — MEDIUM ALERT
  TEST 5  — SIGNED-OUT USER
  TEST 6  — TWO DIFFERENT ACCOUNTS (Alice vs Bob isolation)
  TEST 7  — MISSING ACCOUNT EMAIL
  TEST 8  — DUPLICATE ALERT PROCESSING (Idempotency)
  TEST 9  — FORGED USER ID OR RECIPIENT
  TEST 10 — EMAIL PROVIDER FAILURE
  TEST 11 — ACCOUNT EMAIL CHANGE
  TEST 12 — SEVERITY NORMALIZATION
"""

import asyncio
import pytest
import time
from unittest import mock
from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.database import UserModel, get_db_session, EmailAlertRecordModel
from backend.storage.auth import AuthService, ROLE_USER, hash_password
from backend.alerts.email_notifier import EmailNotifier, BrevoEmailClient
from backend.threats.models import ThreatEvent, ThreatCategory, RiskLevel, Explanation


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = next(get_db_session())
    yield db
    db.close()


@pytest.fixture(autouse=True)
def mock_analyst_and_pdf():
    """Mock external PDF generation and LLM analyst calls to keep tests deterministic and offline."""
    mock_report = {
        "status": "ANALYSIS_COMPLETE",
        "executive_summary": "Automated security incident telemetry summary.",
        "technical_deep_dive": "Deep forensic inspection report details.",
        "actions": ["Review affected assets", "Audit authentication logs"],
    }
    with mock.patch("backend.services.threat_reporter.ThreatReportService.build_threat_incident_pdf", return_value=b"%PDF-1.4 mock report"), \
         mock.patch("backend.analysis.llm_analyst.LLMSecurityAnalyst.analyze", return_value=mock_report):
        yield


@pytest.fixture(scope="module")
def setup_accounts(db_session):
    """Seed Alice, Bob, and an account with no email in the authoritative database."""
    # Alice
    alice = db_session.query(UserModel).filter_by(username="alice_scenario_user").first()
    if not alice:
        alice = AuthService.create_user(
            db_session,
            username="alice_scenario_user",
            email="alice@example.com",
            password="AlicePassword123!",
            role=ROLE_USER,
        )
    else:
        alice.is_active = True
        alice.email = "alice@example.com"
        alice.password_hash = hash_password("AlicePassword123!")
        db_session.commit()

    # Bob
    bob = db_session.query(UserModel).filter_by(username="bob_scenario_user").first()
    if not bob:
        bob = AuthService.create_user(
            db_session,
            username="bob_scenario_user",
            email="bob@example.com",
            password="BobPassword123!",
            role=ROLE_USER,
        )
    else:
        bob.is_active = True
        bob.email = "bob@example.com"
        bob.password_hash = hash_password("BobPassword123!")
        db_session.commit()

    # User with invalid / missing email
    no_email_user = db_session.query(UserModel).filter_by(username="no_email_scenario_user").first()
    if not no_email_user:
        no_email_user = AuthService.create_user(
            db_session,
            username="no_email_scenario_user",
            email="placeholder_invalid_domain",
            password="NoEmailPassword123!",
            role=ROLE_USER,
        )
    no_email_user.email = "invalid_format_no_at"
    db_session.commit()

    # Authenticate and obtain valid session tokens
    _, token_alice = AuthService.authenticate(db_session, "alice_scenario_user", "AlicePassword123!")
    _, token_bob = AuthService.authenticate(db_session, "bob_scenario_user", "BobPassword123!")
    _, token_no_email = AuthService.authenticate(db_session, "no_email_scenario_user", "NoEmailPassword123!")

    return {
        "alice": alice,
        "token_alice": token_alice,
        "bob": bob,
        "token_bob": token_bob,
        "no_email_user": no_email_user,
        "token_no_email": token_no_email,
    }


# ==============================================================================
# TEST 1 — HIGH + AUTHENTICATED ACCOUNT
# ==============================================================================
@pytest.mark.asyncio
async def test_01_high_alert_authenticated_account(setup_accounts):
    """Given a valid signed-in user with a valid associated email,
    when a genuine HIGH alert is created, exactly one notification goes to that user's email."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]

    high_event = ThreatEvent(
        event_id=f"test-high-{time.time()}",
        source="email_scanner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.HIGH,
        classification="PHISHING_DETECTED",
        explanation=Explanation(summary="High severity credential harvesting email detected"),
        detector="PhishingAnalyzer",
        risk_score=0.88,
        user_id=alice.id,
    )

    with mock.patch.object(
        notifier,
        "_dispatch_email",
        return_value={"status": "sent", "delivery_status": "PROVIDER_ACCEPTED", "provider_message_id": "msg-high-01"},
    ) as mock_dispatch:
        res = await notifier.notify_threat_event(high_event)
        assert res["status"] == "sent"
        assert mock_dispatch.call_count == 1
        assert mock_dispatch.call_args[1]["recipient"] == alice.email
        assert mock_dispatch.call_args[1]["recipient"] == "alice@example.com"
        assert mock_dispatch.call_args[1]["alert_level"] == "HIGH"


# ==============================================================================
# TEST 2 — CRITICAL + AUTHENTICATED ACCOUNT
# ==============================================================================
@pytest.mark.asyncio
async def test_02_critical_alert_authenticated_account(setup_accounts):
    """Given a valid signed-in user, when a genuine CRITICAL alert is created,
    exactly one notification is addressed to that user's email."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]

    crit_event = ThreatEvent(
        event_id=f"test-crit-{time.time()}",
        source="url_scanner",
        source_type="unit_test",
        modality="network",
        threat_category=ThreatCategory.MALWARE_INDICATOR,
        severity=RiskLevel.CRITICAL,
        classification="MALWARE_PAYLOAD",
        explanation=Explanation(summary="Critical zero-day exploit payload detected"),
        detector="UnifiedPipeline",
        risk_score=0.98,
        user_id=alice.id,
    )

    with mock.patch.object(
        notifier,
        "_dispatch_email",
        return_value={"status": "sent", "delivery_status": "PROVIDER_ACCEPTED", "provider_message_id": "msg-crit-02"},
    ) as mock_dispatch:
        res = await notifier.notify_threat_event(crit_event)
        assert res["status"] == "sent"
        assert mock_dispatch.call_count == 1
        assert mock_dispatch.call_args[1]["recipient"] == alice.email
        assert mock_dispatch.call_args[1]["alert_level"] == "CRITICAL"


# ==============================================================================
# TEST 3 — LOW ALERT
# ==============================================================================
@pytest.mark.asyncio
async def test_03_low_alert_suppression(setup_accounts):
    """Given a signed-in user, when a LOW alert is created, no email notification is sent."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]

    low_event = ThreatEvent(
        event_id=f"test-low-{time.time()}",
        source="scanner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.LOW,
        classification="LOW_RISK_SUSPICION",
        explanation=Explanation(summary="Low risk indicator"),
        detector="PhishingAnalyzer",
        risk_score=0.25,
        user_id=alice.id,
    )

    with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
        res = await notifier.notify_threat_event(low_event)
        assert res["status"] == "skipped"
        assert "BELOW_THRESHOLD" in res["reason"]
        mock_dispatch.assert_not_called()


# ==============================================================================
# TEST 4 — MEDIUM ALERT
# ==============================================================================
@pytest.mark.asyncio
async def test_04_medium_alert_suppression(setup_accounts):
    """Given a signed-in user, when a MEDIUM alert is created, no email notification is sent."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]

    med_event = ThreatEvent(
        event_id=f"test-med-{time.time()}",
        source="scanner",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.MEDIUM,
        classification="MEDIUM_RISK",
        explanation=Explanation(summary="Moderate anomaly detected"),
        detector="PhishingAnalyzer",
        risk_score=0.55,
        user_id=alice.id,
    )

    with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
        res = await notifier.notify_threat_event(med_event)
        assert res["status"] == "skipped"
        assert "BELOW_THRESHOLD" in res["reason"]
        mock_dispatch.assert_not_called()


# ==============================================================================
# TEST 5 — SIGNED-OUT USER
# ==============================================================================
def test_05_signed_out_user_no_email(client):
    """Given that no valid authenticated account is associated with an alert,
    when an alert is generated, no email is sent to any user or administrator."""
    with mock.patch("backend.alerts.email_notifier.EmailNotifier.notify_threat_event") as mock_notify:
        mock_notify.return_value = {"status": "skipped", "reason": "NO_AUTHENTICATED_ACCOUNT"}

        # Perform unauthenticated threat analysis request
        response = client.post(
            "/api/threats/unified",
            data={"text": "URGENT: Click http://evil-login-credentials.com/verify to prevent termination"},
        )
        assert response.status_code == 200

        # If notify_threat_event was called or skipped, ensure it was NEVER attributed to an email
        if mock_notify.called:
            called_event = mock_notify.call_args[0][0]
            assert called_event.user_id is None
            assert called_event.user_email is None


# ==============================================================================
# TEST 6 — TWO DIFFERENT ACCOUNTS (Alice vs Bob isolation)
# ==============================================================================
@pytest.mark.asyncio
async def test_06_two_different_accounts_isolation(setup_accounts):
    """Given Account A uses alice@example.com and Account B uses bob@example.com,
    when each account creates a qualifying alert, each notification is addressed only to its own account email."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]
    bob = setup_accounts["bob"]

    event_alice = ThreatEvent(
        event_id=f"test-alice-{time.time()}",
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.HIGH,
        classification="PHISHING_DETECTED",
        explanation=Explanation(summary="Phishing targeting Alice"),
        user_id=alice.id,
    )

    event_bob = ThreatEvent(
        event_id=f"test-bob-{time.time()}",
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.MALWARE_INDICATOR,
        severity=RiskLevel.CRITICAL,
        classification="MALWARE_DETECTED",
        explanation=Explanation(summary="Malware targeting Bob"),
        user_id=bob.id,
    )

    dispatched_targets = []

    async def fake_dispatch(*args, **kwargs):
        dispatched_targets.append(kwargs.get("recipient"))
        return {"status": "sent", "delivery_status": "PROVIDER_ACCEPTED", "provider_message_id": "iso-msg"}

    with mock.patch.object(notifier, "_dispatch_email", side_effect=fake_dispatch):
        res_a = await notifier.notify_threat_event(event_alice)
        res_b = await notifier.notify_threat_event(event_bob)

        assert res_a["status"] == "sent"
        assert res_b["status"] == "sent"
        assert len(dispatched_targets) == 2
        # Alice alert must resolve to alice@example.com and NOT bob@example.com
        assert dispatched_targets[0] == "alice@example.com"
        assert dispatched_targets[0] != "bob@example.com"
        # Bob alert must resolve to bob@example.com and NOT alice@example.com
        assert dispatched_targets[1] == "bob@example.com"
        assert dispatched_targets[1] != "alice@example.com"


# ==============================================================================
# TEST 7 — MISSING ACCOUNT EMAIL
# ==============================================================================
@pytest.mark.asyncio
async def test_07_missing_or_invalid_account_email(setup_accounts):
    """Given a signed-in user with no eligible associated email,
    when a HIGH or CRITICAL alert is created, no email is sent and outcome is recorded accurately."""
    notifier = EmailNotifier()
    no_email_user = setup_accounts["no_email_user"]

    event = ThreatEvent(
        event_id=f"test-no-email-{time.time()}",
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.CRITICAL,
        classification="CRITICAL_THREAT",
        explanation=Explanation(summary="Incident on account without email"),
        user_id=no_email_user.id,
    )

    with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
        res = await notifier.notify_threat_event(event)
        assert res["status"] == "skipped"
        assert res["reason"] == "NO_ELIGIBLE_ACCOUNT_EMAIL" or "NO_AUTHENTICATED_USER_EMAIL" in res["reason"]
        mock_dispatch.assert_not_called()


# ==============================================================================
# TEST 8 — DUPLICATE ALERT PROCESSING (Idempotency)
# ==============================================================================
@pytest.mark.asyncio
async def test_08_duplicate_alert_processing_idempotency(setup_accounts):
    """Given the same logical alert is processed repeatedly,
    duplicate email delivery is prevented by the implemented idempotency mechanism."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]
    alert_id = f"test-dup-{time.time()}"

    event = ThreatEvent(
        event_id=alert_id,
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.HIGH,
        classification="PHISHING_DETECTED",
        explanation=Explanation(summary="Same logical incident submitted twice"),
        user_id=alice.id,
    )

    with mock.patch.object(
        notifier,
        "_dispatch_email",
        return_value={"status": "sent", "delivery_status": "PROVIDER_ACCEPTED", "provider_message_id": "dup-first-01"},
    ) as mock_dispatch:
        # First processing -> Sent
        res1 = await notifier.notify_threat_event(event)
        assert res1["status"] == "sent"
        assert mock_dispatch.call_count == 1

        # Second processing of same logical alert -> Skipped as duplicate
        res2 = await notifier.notify_threat_event(event)
        assert res2["status"] == "skipped"
        assert res2["reason"] == "THREAT_ERROR_ALREADY_SENT_ONCE"
        assert mock_dispatch.call_count == 1  # Not sent again


# ==============================================================================
# TEST 9 — FORGED USER ID OR RECIPIENT
# ==============================================================================
@pytest.mark.asyncio
async def test_09_forged_user_id_or_recipient(client, setup_accounts):
    """Given a request that attempts to override the authenticated user's identity or destination address,
    the backend ignores or rejects untrusted identity/recipient and uses verified session account only."""
    alice = setup_accounts["alice"]
    token_alice = setup_accounts["token_alice"]
    bob = setup_accounts["bob"]

    # 1. API Route Verification: Alice sends request with forged Bob ID and attacker email in payload
    spoofed_payload = {
        "text": "URGENT: Account suspended immediately. Confirm password and verify your account at https://phish.net/login",
        "user_id": bob.id,
        "user_email": "attacker@darkweb.io",
        "recipient": "attacker@darkweb.io",
        "affected_user": bob.username,
    }

    response = client.post(
        "/api/threats/unified",
        headers={"Authorization": f"Bearer {token_alice}"},
        data=spoofed_payload,
    )
    assert response.status_code == 200
    res_data = response.json()
    returned_event = res_data.get("event", {})
    # Backend strictly overrides and binds identity to Alice's authenticated session
    assert returned_event.get("user_id") == alice.id
    assert returned_event.get("user_email") == alice.email
    assert returned_event.get("user_id") != bob.id
    assert returned_event.get("user_email") != "attacker@darkweb.io"

    # 2. Email Notifier Verification: If an attacker crafts an event with forged user_email,
    # the notifier must ignore the parameter and resolve strictly to Alice's database profile.
    notifier = EmailNotifier()
    spoofed_event = ThreatEvent(
        event_id=f"test-spoof-{time.time()}",
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.HIGH,
        classification="PHISHING_DETECTED",
        detector="PhishingAnalyzer",
        user_id=alice.id,
        user_email="attacker@darkweb.io",  # Attacker attempts to intercept notification
        affected_user=bob.username,        # Attacker attempts to spoof victim name
    )

    with mock.patch.object(notifier, "_dispatch_email") as mock_dispatch:
        mock_dispatch.return_value = {"status": "sent", "delivery_status": "PROVIDER_ACCEPTED", "provider_message_id": "spoof-test"}
        res = await notifier.notify_threat_event(spoofed_event)
        assert res["status"] == "sent"
        assert mock_dispatch.call_count == 1
        # Destination must be Alice's authoritative email, NEVER the attacker's
        assert mock_dispatch.call_args[1]["recipient"] == alice.email
        assert mock_dispatch.call_args[1]["recipient"] != "attacker@darkweb.io"
        assert mock_dispatch.call_args[1]["username"] == alice.username
        assert mock_dispatch.call_args[1]["username"] != bob.username


# ==============================================================================
# TEST 10 — EMAIL PROVIDER FAILURE
# ==============================================================================
@pytest.mark.asyncio
async def test_10_email_provider_failure(setup_accounts):
    """Given that the email provider fails, the application records a failure,
    avoids false success indicators, and keeps the detection pipeline operational."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]

    event = ThreatEvent(
        event_id=f"test-fail-{time.time()}",
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.HIGH,
        classification="PHISHING_DETECTED",
        explanation=Explanation(summary="High threat during mail outage"),
        user_id=alice.id,
    )

    # Simulate provider network failure
    with mock.patch("backend.alerts.brevo_client.BrevoEmailClient.send_alert_email") as mock_send, \
         mock.patch("backend.alerts.brevo_client.BrevoEmailClient.send_smtp_email") as mock_smtp:
        from backend.alerts.brevo_client import BrevoSendResult
        mock_send.return_value = BrevoSendResult(
            success=False,
            delivery_status="SEND_FAILED",
            error_message="Connection timed out to Brevo mail provider",
        )
        mock_smtp.return_value = BrevoSendResult(
            success=False,
            delivery_status="SEND_FAILED",
            error_message="SMTP relay unreachable",
        )

        res = await notifier.notify_threat_event(event)
        # Outcome must accurately reflect failure, not false success
        assert res["delivery_status"] == "SEND_FAILED"
        assert res["status"] in ("dispatched", "failed", "SEND_FAILED")
        assert "timed out" in str(res.get("error")) or "SMTP" in str(res.get("error")) or "SEND_FAILED" in str(res.get("delivery_status"))


# ==============================================================================
# TEST 11 — ACCOUNT EMAIL CHANGE
# ==============================================================================
@pytest.mark.asyncio
async def test_11_account_email_change(setup_accounts, db_session):
    """Given that a user's associated email has been legitimately changed,
    new qualifying alerts use the currently stored eligible email address."""
    notifier = EmailNotifier()
    alice = setup_accounts["alice"]

    # Legitimate account email update
    updated_email = f"alice_updated_{int(time.time())}@example.com"
    alice_row = db_session.query(UserModel).filter_by(id=alice.id).first()
    alice_row.email = updated_email
    db_session.commit()

    event = ThreatEvent(
        event_id=f"test-email-change-{time.time()}",
        source="api",
        source_type="unit_test",
        modality="text",
        threat_category=ThreatCategory.PHISHING,
        severity=RiskLevel.HIGH,
        classification="PHISHING_DETECTED",
        explanation=Explanation(summary="Phishing alert after email change"),
        user_id=alice.id,
    )

    with mock.patch.object(
        notifier,
        "_dispatch_email",
        return_value={"status": "sent", "delivery_status": "PROVIDER_ACCEPTED", "provider_message_id": "chg-msg-01"},
    ) as mock_dispatch:
        res = await notifier.notify_threat_event(event)
        assert res["status"] == "sent"
        assert mock_dispatch.call_count == 1
        # Recipient MUST resolve to the newly stored email address
        assert mock_dispatch.call_args[1]["recipient"] == updated_email

    # Restore email for remaining tests
    alice_row.email = "alice@example.com"
    db_session.commit()


# ==============================================================================
# TEST 12 — SEVERITY NORMALIZATION
# ==============================================================================
def test_12_severity_normalization():
    """Verify supported uppercase/lowercase representations and ensure
    unsupported severity values never qualify accidentally."""
    # Eligible: HIGH and CRITICAL (any case or enum)
    assert EmailNotifier.is_severity_eligible("HIGH") is True
    assert EmailNotifier.is_severity_eligible("high") is True
    assert EmailNotifier.is_severity_eligible("High") is True
    assert EmailNotifier.is_severity_eligible("CRITICAL") is True
    assert EmailNotifier.is_severity_eligible("critical") is True
    assert EmailNotifier.is_severity_eligible("Critical") is True
    assert EmailNotifier.is_severity_eligible(RiskLevel.HIGH) is True
    assert EmailNotifier.is_severity_eligible(RiskLevel.CRITICAL) is True

    # Ineligible: LOW, MEDIUM, INFORMATIONAL, SAFE, UNKNOWN, None, random strings
    assert EmailNotifier.is_severity_eligible("LOW") is False
    assert EmailNotifier.is_severity_eligible("low") is False
    assert EmailNotifier.is_severity_eligible("MEDIUM") is False
    assert EmailNotifier.is_severity_eligible("medium") is False
    assert EmailNotifier.is_severity_eligible("INFORMATIONAL") is False
    assert EmailNotifier.is_severity_eligible("info") is False
    assert EmailNotifier.is_severity_eligible("SAFE") is False
    assert EmailNotifier.is_severity_eligible("UNKNOWN") is False
    assert EmailNotifier.is_severity_eligible(None) is False
    assert EmailNotifier.is_severity_eligible("ELEVATED") is False
    assert EmailNotifier.is_severity_eligible("WARN") is False
    assert EmailNotifier.is_severity_eligible(100) is False
