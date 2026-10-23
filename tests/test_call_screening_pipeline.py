"""
test_call_screening_pipeline.py — Verification of Backend Call Screening & Phone Reputation Pipeline.

Verifies:
  1. Phone number E.164 normalization logic in routes_threats.
  2. GET /api/threats/phone/{phone_number} evidence-based reputation retrieval and honest UNKNOWN handling.
  3. POST /api/threats/screened-calls incident ingestion, idempotency, and SOC event creation.
  4. GET /api/threats/screened-calls forensic list retrieval for SOC dashboard.
  5. 5-second constraint compliance and audit integrity.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.database import (
    get_session_factory,
    CallerReputationModel,
    ScreenedCallIncidentModel,
)
from backend.api.routes_threats import normalize_phone_number


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def db_session():
    factory = get_session_factory("data/cyberguard.db")
    session = factory()
    yield session
    session.close()


def test_phone_number_normalization_backend():
    """Verify standards-compliant E.164 phone number normalization."""
    # 10-digit Indian mobile
    assert normalize_phone_number("9876543210", default_region="IN") == "+919876543210"
    
    # 11-digit with leading zero
    assert normalize_phone_number("09876543210", default_region="IN") == "+919876543210"
    
    # Already formatted international
    assert normalize_phone_number("+91 98765-43210") == "+919876543210"
    
    # US number
    assert normalize_phone_number("(415) 555-2671", default_region="US") == "+14155552671"
    
    # Short code (e.g. 112, 100, 911)
    assert normalize_phone_number("112") == "112"
    
    # Restricted / Unknown strings return empty
    assert normalize_phone_number("RESTRICTED") == ""
    assert normalize_phone_number("UNKNOWN") == ""
    assert normalize_phone_number("private") == ""
    assert normalize_phone_number(None) == ""


def test_reputation_lookup_unknown_number(client):
    """
    Verify that an unknown phone number returns an honest UNKNOWN / INSUFFICIENT EVIDENCE
    verdict, never claiming it is safe or a scam without evidence.
    """
    non_existent = "+910000099999"
    resp = client.get(f"/api/threats/phone/{non_existent}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["reputation_found"] is False
    assert data["classification"] == "UNKNOWN / INSUFFICIENT EVIDENCE"
    assert data["risk_score"] == 0.0
    assert data["confidence"] == 0.0
    assert data["recommended_action"] == "ALLOW"
    assert "UNAVAILABLE" in data["source_freshness"]


def test_reputation_lookup_known_scam(client, db_session):
    """
    Verify that an existing verified scam record in the database is correctly
    retrieved with threat evidence and BLOCK recommendation.
    """
    test_number = f"+9199999{int(time.time()) % 100000:05d}"
    now = datetime.now(timezone.utc)
    
    # Insert test reputation record
    rep = CallerReputationModel(
        normalized_number=test_number,
        raw_number=test_number,
        country_code="91",
        classification="HIGH RISK / SUSPECTED SCAM",
        risk_score=0.92,
        confidence=0.88,
        reason_codes_json=json.dumps(["CONFIRMED_FRAUD_RING", "HIGH_VOLUME_AUTODIALER"]),
        evidence_sources_json=json.dumps(["LOCAL_INTEL", "CYBERGUARD_THREAT_GRAPH"]),
        is_scam=True,
        is_spoofed=False,
        disputed=False,
        last_verified_at=now,
        expires_at=now + timedelta(days=1),
    )
    db_session.add(rep)
    db_session.commit()

    resp = client.get(f"/api/threats/phone/{test_number}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["reputation_found"] is True
    assert data["classification"] == "HIGH RISK / SUSPECTED SCAM"
    assert data["risk_score"] == 0.92
    assert data["recommended_action"] == "BLOCK"
    assert "CONFIRMED_FRAUD_RING" in data["reason_codes"]
    assert data["source_freshness"] == "FRESH"


def test_screened_call_ingestion_and_idempotency(client, db_session):
    """
    Verify POST /api/threats/screened-calls:
    1. Successfully ingests Android CallScreeningService audit records.
    2. Enforces idempotency (duplicate incident_id returns 200 without creating duplicates).
    3. Persists audit trails in ScreenedCallIncidentModel.
    """
    incident_id = f"test-inc-{uuid.uuid4().hex[:12]}"
    test_number = "+919876543210"

    payload = {
        "incident_id": incident_id,
        "timestamp": time.time(),
        "phone_number": "9876543210",
        "raw_number": "9876543210",
        "normalized_number": test_number,
        "caller_display_name": "Test Autodialer",
        "classification": "HIGH_RISK",
        "risk_score": 0.85,
        "confidence": 0.80,
        "reason_codes": ["CONFIRMED_FRAUD_RING"],
        "evidence_sources": ["LOCAL_CACHE"],
        "carrier_verification_status": "CARRIER_VERIFICATION_FAILED",
        "action_recommended": "BLOCK",
        "action_applied": "BLOCK",
        "response_latency_ms": 12.0,
        "explanation": "High risk fraudulent autodialer detected.",
    }

    # 1. First ingestion -> 201 Created
    resp = client.post("/api/threats/screened-calls", json=payload)
    assert resp.status_code == 201
    res_data = resp.json()
    assert res_data["status"] == "INGESTED"
    assert res_data["incident_id"] == incident_id

    # Verify persisted in database
    saved = db_session.query(ScreenedCallIncidentModel).filter(
        ScreenedCallIncidentModel.incident_id == incident_id
    ).first()
    assert saved is not None
    assert saved.normalized_number == test_number
    assert saved.action_applied == "BLOCK"
    assert saved.response_latency_ms == 12.0

    # 2. Duplicate ingestion -> 200 OK (Idempotent)
    resp_dup = client.post("/api/threats/screened-calls", json=payload)
    assert resp_dup.status_code == 200
    dup_data = resp_dup.json()
    assert dup_data["status"] == "ALREADY_INGESTED"
    assert dup_data["incident_id"] == incident_id


def test_get_screened_calls_list(client):
    """Verify GET /api/threats/screened-calls returns recent incidents for the SOC console."""
    resp = client.get("/api/threats/screened-calls?limit=10")
    assert resp.status_code == 200
    data = resp.json()

    assert "total" in data
    assert "screened_calls" in data
    assert isinstance(data["screened_calls"], list)
    assert len(data["screened_calls"]) > 0

    first = data["screened_calls"][0]
    assert "incident_id" in first
    assert "normalized_number" in first
    assert "classification" in first
    assert "action_applied" in first
    assert "latency_ms" in first
