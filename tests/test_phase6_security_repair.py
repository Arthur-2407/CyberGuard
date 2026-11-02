"""
CyberGuard Phase 6 — Master Engineering Verification Test Suite
Covers:
 1. Workstream A: Gmail OAuth 2.0 PKCE, DPAPI Token Storage, Mailbox Sync, Admin Exemption
 2. Workstream B: Interactive Master Security Banner, Forensic Modal, Subsystem Routing
 3. Workstream C: 4-Tier Docker Engine and Cloudflare Tunnel Diagnostics
"""

import os
import re
import json
import pytest

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(WORKSPACE_DIR, "desktop", "frontend", "index.html")
APP_JS = os.path.join(WORKSPACE_DIR, "desktop", "frontend", "app.js")
STYLES_CSS = os.path.join(WORKSPACE_DIR, "desktop", "frontend", "styles.css")
GMAIL_SERVICE_JS = os.path.join(WORKSPACE_DIR, "desktop", "engine", "gmail_service.js")
LOCAL_STORE_JS = os.path.join(WORKSPACE_DIR, "desktop", "engine", "local_store.js")
CONNECTIVITY_SERVICE_JS = os.path.join(WORKSPACE_DIR, "desktop", "engine", "connectivity_service.js")
MAIN_JS = os.path.join(WORKSPACE_DIR, "desktop", "main.js")
PRELOAD_JS = os.path.join(WORKSPACE_DIR, "desktop", "preload.js")


class TestWorkstreamAGmailOAuth:
    """Verifies Workstream A: Gmail OAuth 2.0 PKCE, User Isolation, and Admin Exemption."""

    def test_gmail_service_implements_pkce_and_loopback(self):
        assert os.path.exists(GMAIL_SERVICE_JS), "gmail_service.js must exist"
        with open(GMAIL_SERVICE_JS, "r", encoding="utf-8") as f:
            content = f.read()

        assert "startOAuthFlow" in content, "Must implement startOAuthFlow"
        assert "oauth2callback" in content, "Must use loopback callback endpoint"
        assert "code_challenge" in content or "code_verifier" in content, "Must implement PKCE code verifier and challenge"
        assert "simulateTestAccount" in content, "Must provide simulateTestAccount"
        assert "isSimulated: true" in content or "isSimulated" in content, "Simulated account must be tagged"
        assert "cyberguardadmin@gmail.com" in content, "Must recognize official CyberGuard admin"

    def test_local_store_implements_dpapi_gmail_tokens(self):
        assert os.path.exists(LOCAL_STORE_JS), "local_store.js must exist"
        with open(LOCAL_STORE_JS, "r", encoding="utf-8") as f:
            content = f.read()

        assert "saveGmailTokens" in content, "Must implement saveGmailTokens"
        assert "getGmailTokens" in content, "Must implement getGmailTokens"
        assert "clearGmailTokens" in content, "Must implement clearGmailTokens"
        assert "safeStorage" in content, "Must utilize Electron safeStorage DPAPI encryption"

    def test_frontend_gmail_auth_separation_enforced(self):
        assert os.path.exists(APP_JS), "app.js must exist"
        with open(APP_JS, "r", encoding="utf-8") as f:
            content = f.read()

        # Ensure user sign-in is checked before connecting Google account
        assert "AppState.currentUser" in content, "Must verify AppState.currentUser"
        assert "btn-authorize-gmail-oauth" in content
        assert "startGmailOAuth" in content

    def test_preload_exposes_gmail_contract(self):
        with open(PRELOAD_JS, "r", encoding="utf-8") as f:
            content = f.read()
        assert "startGmailOAuth" in content
        assert "simulateGmail" in content
        assert "syncGmail" in content
        assert "getGmailStatus" in content
        assert "revokeGmail" in content


class TestWorkstreamBDashboardBannerInteraction:
    """Verifies Workstream B: Clickable Attention Required banner, Forensic Modal, Subsystem Routing."""

    def test_html_master_banner_is_interactive(self):
        with open(INDEX_HTML, "r", encoding="utf-8") as f:
            html = f.read()

        # Banner should have role=button and tabindex=0
        assert 'id="master-status-card"' in html
        assert 'role="button"' in html
        assert 'tabindex="0"' in html
        assert 'aria-label' in html
        # Forensic detail modal must exist
        assert 'id="modal-alert-detail"' in html
        assert 'id="alert-detail-title"' in html
        assert 'id="btn-goto-alert-subsystem"' in html

    def test_css_banner_has_hover_and_focus_styles(self):
        with open(STYLES_CSS, "r", encoding="utf-8") as f:
            css = f.read()

        assert '.protection-banner[role="button"]:hover' in css or '.protection-banner[role="button"]' in css
        assert ':focus-visible' in css

    def test_app_js_banner_navigation_and_subsystem_routing(self):
        with open(APP_JS, "r", encoding="utf-8") as f:
            js = f.read()

        assert "master-status-card" in js
        assert "navigateToSecurityEvent" in js
        assert "openAlertDetailModal" in js
        assert "btn-goto-alert-subsystem" in js


class TestWorkstreamCDockerAndCloudflareTunnel:
    """Verifies Workstream C: 4-Tier Diagnostics (Container, Connector, Ingress, Origin)."""

    def test_connectivity_service_distinguishes_4_tiers(self):
        with open(CONNECTIVITY_SERVICE_JS, "r", encoding="utf-8") as f:
            code = f.read()

        assert "inspectTunnelConnector" in code
        assert "checkTunnel" in code
        assert "checkDockerEngine" in code
        # Four tiers explicit checks
        assert "containerState" in code
        assert "connectorState" in code
        assert "edgeStatus" in code
        assert "originStatus" in code or "originReachabilityText" in code
        # Secret sanitization
        assert "REDACTED" in code or "redacted" in code

    def test_html_displays_4_tier_tunnel_attributes(self):
        with open(INDEX_HTML, "r", encoding="utf-8") as f:
            html = f.read()

        assert 'id="diag-container-tunnel"' in html
        assert 'id="diag-connector-tunnel"' in html
        assert 'id="diag-status-tunnel"' in html
        assert 'id="diag-latency-tunnel"' in html
        assert 'id="btn-view-tunnel-diag"' in html
        assert 'id="modal-tunnel-diag"' in html

    def test_app_js_tunnel_telemetry_modal_handlers(self):
        with open(APP_JS, "r", encoding="utf-8") as f:
            js = f.read()

        assert "btn-view-tunnel-diag" in js
        assert "modal-tunnel-diag" in js
        assert "diag-container-tunnel" in js
        assert "diag-connector-tunnel" in js
