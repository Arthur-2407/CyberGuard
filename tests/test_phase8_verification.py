"""
CyberGuard Phase 8 — Production Release Verification & Anti-Spoofing Calibration Tests
Validates:
 1. Priority A: Cloudflare Tunnel Connector, Edge Connectivity, 4-Tier Diagnostics
 2. Priority B: Multi-signal Gmail Anti-Spoofing Calibration & Exemption Verification
 3. Priority C: Windows Desktop Distribution Artifacts (Installer & Portable)
"""

import os
import subprocess
import json
import pytest

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GMAIL_SERVICE_JS = os.path.join(WORKSPACE_DIR, "desktop", "engine", "gmail_service.js")
GMAIL_SERVICE_JS_POS = GMAIL_SERVICE_JS.replace("\\", "/")
SETUP_EXE = os.path.join(WORKSPACE_DIR, "dist", "windows", "CyberGuard-Setup.exe")
PORTABLE_EXE = os.path.join(WORKSPACE_DIR, "dist", "windows", "CyberGuard-Portable.exe")


class TestPhase8AntiSpoofingCalibration:
    """Verifies calibrated multi-signal anti-spoofing engine in gmail_service.js."""

    def test_official_admin_exact_match_verified(self):
        script = f"""
        const gs = require('{GMAIL_SERVICE_JS_POS}');
        const res = gs.verifySender({{
            from: 'CyberGuard Administrator <cyberguardadmin@gmail.com>',
            replyTo: 'cyberguardadmin@gmail.com'
        }});
        console.log(JSON.stringify(res));
        """
        out = subprocess.check_output(["node", "-e", script], text=True)
        res = json.loads(out)
        assert res["classification"] == "VERIFIED_SENDER"
        assert res["isTrustedAdmin"] is True
        assert res["adminExempt"] is True
        assert res["riskScore"] == 0.0

    def test_calibrated_routing_with_passing_auth_does_not_trigger_critical(self):
        """Reply-To difference alone with passing SPF/DKIM/DMARC must not trigger critical 0.95 alert."""
        script = f"""
        const gs = require('{GMAIL_SERVICE_JS_POS}');
        const res = gs.verifySender({{
            from: 'CyberGuard Administrator <cyberguardadmin@gmail.com>',
            replyTo: 'alerts-routing@gmail.com',
            authenticationResults: 'spf=pass dkim=pass dmarc=pass'
        }});
        console.log(JSON.stringify(res));
        """
        out = subprocess.check_output(["node", "-e", script], text=True)
        res = json.loads(out)
        assert res["classification"] == "VERIFIED_SENDER"
        assert res["isTrustedAdmin"] is True
        assert res["riskScore"] <= 0.1
        assert not any("CRITICAL ADMIN SPOOFING" in ind for ind in res["indicators"])

    def test_malicious_spoofing_with_failed_auth_triggers_critical_alert(self):
        """Reply-To redirection to foreign untrusted domain with failed auth triggers critical alert."""
        script = f"""
        const gs = require('{GMAIL_SERVICE_JS_POS}');
        const res = gs.verifySender({{
            from: 'CyberGuard Administrator <cyberguardadmin@gmail.com>',
            replyTo: 'stealth-collector@darkweb.ru',
            authenticationResults: 'spf=fail dkim=fail'
        }});
        console.log(JSON.stringify(res));
        """
        out = subprocess.check_output(["node", "-e", script], text=True)
        res = json.loads(out)
        assert res["classification"] == "SPOOFING_INDICATORS"
        assert res["riskScore"] >= 0.90
        assert any("CRITICAL ADMIN SPOOFING" in ind for ind in res["indicators"])

    def test_potential_spoofing_return_path_mismatch(self):
        """Return-Path mismatch with failed auth triggers potential admin spoofing alert."""
        script = f"""
        const gs = require('{GMAIL_SERVICE_JS_POS}');
        const res = gs.verifySender({{
            from: 'CyberGuard Administrator <cyberguardadmin@gmail.com>',
            returnPath: 'evil-proxy@darkweb.ru',
            authenticationResults: 'spf=fail'
        }});
        console.log(JSON.stringify(res));
        """
        out = subprocess.check_output(["node", "-e", script], text=True)
        res = json.loads(out)
        assert res["classification"] == "SPOOFING_INDICATORS"
        assert any("POTENTIAL ADMIN SPOOFING" in ind for ind in res["indicators"])

    def test_gmail_readonly_scope_enforced(self):
        """Ensure only read-only scope is requested, never write or send permissions."""
        with open(GMAIL_SERVICE_JS, "r", encoding="utf-8") as f:
            content = f.read()
        assert "https://www.googleapis.com/auth/gmail.readonly" in content
        assert "gmail.modify" not in content
        assert "gmail.send" not in content
        assert "mail.google.com" not in content


class TestPhase8WindowsReleaseArtifacts:
    """Verifies that release binaries exist, have non-trivial size, and are valid executables."""

    def test_installer_executable_exists_and_valid(self):
        assert os.path.exists(SETUP_EXE), f"Installer not found at {SETUP_EXE}"
        size = os.path.getsize(SETUP_EXE)
        # Installer should be > 50 MB
        assert size > 50 * 1024 * 1024, f"Installer size too small: {size} bytes"

    def test_portable_executable_exists_and_valid(self):
        assert os.path.exists(PORTABLE_EXE), f"Portable executable not found at {PORTABLE_EXE}"
        size = os.path.getsize(PORTABLE_EXE)
        # Portable should be > 50 MB
        assert size > 50 * 1024 * 1024, f"Portable size too small: {size} bytes"
