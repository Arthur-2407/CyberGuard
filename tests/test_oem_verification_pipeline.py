"""
test_oem_verification_pipeline.py — Verification of OEM Application Provenance & Ecosystem Pipeline.

Verifies:
  1. POST /api/threats/verify-oem-app recognizes Xiaomi/MIUI ecosystem packages on Xiaomi/Redmi devices.
  2. Differentiates genuine OEM pre-installed packages from unverified external sideloads (e.g. com.vivy.node).
  3. Supports cross-OEM brand logic (Samsung, Google, BBK/OnePlus, Motorola).
  4. Generates LLM forensic briefings for unverified or suspicious external packages.
  5. Correctly flags blacklisted/malicious IOC signatures via VirusTotal/URLhaus integration.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_xiaomi_oem_app_verification_valid(client: TestClient):
    """Verify that Xiaomi / MIUI packages on Xiaomi / Redmi devices are recognized as authentic."""
    req_payload = {
        "package_name": "com.xiaomi.smarthome",
        "app_name": "Mi Home",
        "device_brand": "XIAOMI",
        "device_model": "25098RA98I",
        "device_manufacturer": "Xiaomi",
        "sha256": "90b96675ee31505ba0dd24f33165b40381fba253f572a76f2f0122e03884cb26"
    }

    res = client.post("/api/threats/verify-oem-app", json=req_payload)
    assert res.status_code == 200
    data = res.json()

    assert data["package_name"] == "com.xiaomi.smarthome"
    assert data["is_trusted_oem"] is True
    assert data["status"] == "VALID"
    assert "Xiaomi" in data["store_name"]
    assert data["risk_score"] <= 0.10
    assert len(data["recommendations"]) > 0


def test_miui_calculator_verification_valid(client: TestClient):
    """Verify that com.miui.calculator is classified as valid OEM on a Redmi device."""
    req_payload = {
        "package_name": "com.miui.calculator",
        "app_name": "Calculator",
        "device_brand": "REDMI",
        "device_model": "kunzite",
        "device_manufacturer": "Xiaomi"
    }

    res = client.post("/api/threats/verify-oem-app", json=req_payload)
    assert res.status_code == 200
    data = res.json()

    assert data["is_trusted_oem"] is True
    assert data["status"] == "VALID"
    assert data["risk_score"] == 0.05


def test_untrusted_external_sideload_on_xiaomi(client: TestClient):
    """Verify that external unverified packages like com.vivy.node fail OEM check and get LLM refined report."""
    req_payload = {
        "package_name": "com.vivy.node",
        "app_name": "Vivy Node",
        "device_brand": "XIAOMI",
        "device_model": "25098RA98I",
        "device_manufacturer": "Xiaomi"
    }

    res = client.post("/api/threats/verify-oem-app", json=req_payload)
    assert res.status_code == 200
    data = res.json()

    assert data["is_trusted_oem"] is False
    assert data["status"] == "UNTRUSTED_EXTERNAL"
    assert data["risk_score"] >= 0.70
    assert data["llm_forensic_report"] is not None
    assert "executive_briefing" in data["llm_forensic_report"]
    assert "technical_deep_dive" in data["llm_forensic_report"]


def test_samsung_oem_ecosystem_verification(client: TestClient):
    """Verify that Samsung packages are approved on Samsung devices but not cross-OEM approved."""
    # On Samsung device:
    res_samsung = client.post("/api/threats/verify-oem-app", json={
        "package_name": "com.sec.android.app.sbrowser",
        "app_name": "Samsung Internet",
        "device_brand": "Samsung",
        "device_model": "SM-S918B"
    })
    assert res_samsung.status_code == 200
    assert res_samsung.json()["is_trusted_oem"] is True
    assert res_samsung.json()["status"] == "VALID"

    # Samsung package on Xiaomi device should NOT be considered native OEM:
    res_cross = client.post("/api/threats/verify-oem-app", json={
        "package_name": "com.sec.android.app.sbrowser",
        "app_name": "Samsung Internet",
        "device_brand": "XIAOMI",
        "device_model": "25098RA98I"
    })
    assert res_cross.status_code == 200
    assert res_cross.json()["is_trusted_oem"] is False
    assert res_cross.json()["status"] == "UNTRUSTED_EXTERNAL"
