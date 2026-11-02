"""
Phase 4 Desktop Intelligence & Security Verification Test Suite
Tests:
  1. Independent 4-Tier Connectivity Diagnostics (Docker, Cloud, Tunnel, Vercel)
  2. Official Administrator Alert Notification via POST /api/alerts/dispatch-email
  3. Gmail 3-Stage Threat Inspection with Admin Exemption
  4. Active Network Interface Identification & Live Web Shield Evaluation
"""

import json
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app

ROOT_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_01_connectivity_service_diagnostics():
    """Verify that connectivity_service.js runs independent 4-tier diagnostics."""
    js_script = """
    const connectivityService = require('./desktop/engine/connectivity_service');
    connectivityService.runFullDiagnostics({ localPort: 3000, cloudUrl: 'https://cyberguard-backend-8rbz.onrender.com' })
      .then(res => {
        console.log(JSON.stringify(res));
      })
      .catch(err => {
        console.error(err);
        process.exit(1);
      });
    """
    proc = subprocess.run(
        ["node", "-e", js_script],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=15
    )
    assert proc.returncode == 0, f"Diagnostics script failed: {proc.stderr}"
    data = json.loads(proc.stdout)
    
    assert "local" in data
    assert "cloud" in data
    assert "tunnel" in data
    assert "vercel" in data
    assert data["local"]["tier"] == "LOCAL_DOCKER"
    assert data["cloud"]["tier"] in ["CLOUD_BACKEND", "DEPLOYED_CLOUD"]
    assert data["tunnel"]["tier"] == "CLOUDFLARE_TUNNEL"
    assert data["vercel"]["tier"] == "VERCEL_PORTAL"


def test_02_alert_email_dispatch_endpoint(client):
    """Verify POST /api/alerts/dispatch-email dispatches security alerts without infinite loops."""
    # Official admin address must be excluded from recursive self-notification
    payload_self = {
        "alert_id": "test-alert-loop-01",
        "recipient": "cyberguardadmin@gmail.com",
        "threat_title": "Test Self Trigger",
        "severity": "CRITICAL"
    }
    res_self = client.post("/api/alerts/dispatch-email", json=payload_self)
    assert res_self.status_code == 200
    assert res_self.json()["status"] == "skipped"
    assert res_self.json()["reason"] == "LOOP_PROTECTION_EXCLUDED"

    # Valid user notification dispatch
    payload_user = {
        "alert_id": "test-alert-user-02",
        "recipient": "target_analyst@company.com",
        "threat_title": "PayPal Phishing Alert",
        "severity": "HIGH",
        "sender": "security-update@paypal-verify.xyz",
        "indicators": ["Display name brand impersonation", "Suspicious TLD .xyz"]
    }
    res_user = client.post("/api/alerts/dispatch-email", json=payload_user)
    assert res_user.status_code == 200
    assert res_user.json()["official_sender"] == "cyberguardadmin@gmail.com"
    assert res_user.json()["recipient"] == "target_analyst@company.com"


def test_03_gmail_three_stage_inspection():
    """Verify Gmail 3-stage inspection via Node engine."""
    js_script = """
    const gmailService = require('./desktop/engine/gmail_service');

    // 1. Legitimate admin communication (whitelisted)
    const adminEmail = {
      from: 'CyberGuard Administrator <cyberguardadmin@gmail.com>',
      replyTo: 'cyberguardadmin@gmail.com',
      authenticationResults: 'spf=pass dkim=pass dmarc=pass',
      subject: 'Official Security Notice',
      body: 'Security definitions updated'
    };
    const resAdmin = gmailService.inspectEmail(adminEmail, 'user-123');

    // 2. High-threat phishing payload
    const threatEmail = {
      from: 'Support <service-update@paypal-verify.xyz>',
      replyTo: 'harvester@darkweb.ru',
      subject: 'URGENT: Verify your account immediately',
      body: 'Please verify at http://paypal-verify.xyz to avoid suspension.',
      attachments: [{ filename: 'security_patch.exe', size: 5000 }]
    };
    const resThreat = gmailService.inspectEmail(threatEmail, 'user-123');

    console.log(JSON.stringify({ admin: resAdmin, threat: resThreat }));
    """
    proc = subprocess.run(
        ["node", "-e", js_script],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=15
    )
    assert proc.returncode == 0, f"Gmail inspection test failed: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert data["admin"]["verdict"] == "CLEAN"
    assert data["admin"]["isTrustedAdmin"] is True
    assert data["threat"]["verdict"] in ["PHISHING_THREAT", "SUSPICIOUS"]
    assert len(data["threat"]["indicators"]) >= 2


def test_04_web_shield_network_interface_and_evaluation():
    """Verify WebShield network interface detection and live evaluation."""
    js_script = """
    const webShield = require('./desktop/engine/web_shield');

    async function test() {
      // 1. Interface detection
      const iface = webShield.getActiveNetworkInterface();
      if (!iface || !iface.type) {
        throw new Error('Failed to detect network interface');
      }

      // 2. Local blocklist domain
      const evalKnown = await webShield.evaluateUrlLive('http://testsafebrowsing.appspot.com/phishing', 'user-123');
      if (evalKnown.verdict !== 'BLOCKED') {
        throw new Error('Blocklist evaluation failed: ' + JSON.stringify(evalKnown));
      }

      // 3. Clean nominal domain
      const evalClean = await webShield.evaluateUrlLive('https://example.com', 'user-123');
      if (evalClean.verdict === 'BLOCKED') {
        throw new Error('False positive on clean domain: ' + JSON.stringify(evalClean));
      }

      console.log(JSON.stringify({ iface, evalKnown, evalClean }));
    }

    test().catch(err => {
      console.error(err);
      process.exit(1);
    });
    """
    proc = subprocess.run(
        ["node", "-e", js_script],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=15
    )
    assert proc.returncode == 0, f"WebShield test failed: {proc.stderr}"
    data = json.loads(proc.stdout)
    assert "type" in data["iface"]
    assert data["evalKnown"]["verdict"] == "BLOCKED"
    assert data["evalClean"]["verdict"] in ["CLEAN", "ALLOWED"]
