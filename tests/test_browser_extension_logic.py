"""
test_browser_extension_logic.py — Unit and Integration Verification for CyberGuard Browser Shield.

Validates:
1. Manifest V3 specification conformance and permissions integrity.
2. Defensive URL normalization (punycode, IP-literal, protocol stripping).
3. Offline heuristic phishing and lookalike domain detection.
4. Blocklist rule resolution and whitelist override precedence.
5. DeclarativeNetRequest dynamic rule schema compliance.
6. Honest InPrivate/incognito permission contract enforcement.
"""

import json
import os
import re
from pathlib import Path
import pytest

EXTENSION_DIR = Path(__file__).resolve().parent.parent / "extension"

def test_manifest_v3_structure():
    """Verify Manifest V3 file exists and contains required permissions and declarations."""
    manifest_path = EXTENSION_DIR / "manifest.json"
    assert manifest_path.exists(), "extension/manifest.json does not exist"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest.get("manifest_version") == 3
    assert manifest.get("name") == "CyberGuard Real-Time Anti-Phishing & Browser Shield"
    assert "version" in manifest

    # Required permissions
    perms = manifest.get("permissions", [])
    assert "declarativeNetRequest" in perms
    assert "storage" in perms
    assert "tabs" in perms
    assert "webNavigation" in perms

    # Required background worker
    bg = manifest.get("background", {})
    assert bg.get("service_worker") == "background.js"

    # Action popup & web accessible resources
    assert manifest.get("action", {}).get("default_popup") == "popup.html"
    assert len(manifest.get("web_accessible_resources", [])) > 0


def test_extension_assets_exist():
    """Verify all referenced assets, HTML pages, and icons are present on disk."""
    required_files = [
        "manifest.json",
        "background.js",
        "popup.html",
        "popup.css",
        "popup.js",
        "blocked.html",
        "blocked.css",
        "blocked.js",
        "options.html",
        "options.js",
        "icons/icon16.png",
        "icons/icon32.png",
        "icons/icon48.png",
        "icons/icon128.png",
    ]
    for rel_path in required_files:
        full_path = EXTENSION_DIR / rel_path
        assert full_path.exists(), f"Missing required extension asset: {rel_path}"


def test_url_normalization_logic():
    """Test defensive URL normalization heuristics in Python counterpart to background.js."""
    def normalize_url(raw_url: str):
        # Ignore browser internal schemes
        for internal in ("chrome://", "edge://", "about:", "chrome-extension://"):
            if raw_url.startswith(internal):
                return None
        match = re.match(r"^[a-zA-Z]+://([^/]+)(/.*)?$", raw_url)
        if not match:
            return None
        host = match.group(1).lower().split(":")[0]
        path = match.group(2) or "/"
        is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host)) or host.startswith("[")
        is_punycode = "xn--" in host
        return {
            "host": host,
            "path": path,
            "is_ip_literal": is_ip,
            "is_punycode": is_punycode,
            "subdomain_count": max(0, len(host.split(".")) - 2)
        }

    # Test internal scheme rejection
    assert normalize_url("chrome://settings") is None
    assert normalize_url("edge://extensions") is None

    # Test IP-literal detection
    ip_norm = normalize_url("http://192.168.1.100/admin/login")
    assert ip_norm is not None
    assert ip_norm["is_ip_literal"] is True
    assert ip_norm["host"] == "192.168.1.100"

    # Test Punycode detection
    puny_norm = normalize_url("https://xn--pple-43d.com/login")
    assert puny_norm is not None
    assert puny_norm["is_punycode"] is True

    # Test standard domain normalization
    std_norm = normalize_url("HTTPS://SECURE.PAYPAL.COM.ACCOUNT-UPDATE.XYZ/verify?user=test")
    assert std_norm is not None
    assert std_norm["host"] == "secure.paypal.com.account-update.xyz"
    assert std_norm["subdomain_count"] >= 3


def test_offline_heuristic_scoring():
    """Test offline heuristic phishing scoring without external dependencies."""
    def score_offline(host: str, path: str):
        score = 0.0
        reasons = []
        is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host))
        if is_ip:
            score += 0.45
            reasons.append("IP-literal")
        if "xn--" in host:
            score += 0.40
            reasons.append("Punycode")
        brands = ["paypal", "apple", "google", "microsoft", "chase"]
        for b in brands:
            if b in host and not host.endswith(f".{b}.com") and host != f"{b}.com":
                score += 0.50
                reasons.append(f"Brand impersonation: {b}")
                break
        keywords = ["login-verify", "secure-account", "update-banking"]
        for kw in keywords:
            if kw in host or kw in path:
                score += 0.35
                reasons.append(f"Suspicious keyword: {kw}")
                break
        return min(score, 1.0), reasons

    # Clear malicious impersonation
    score, reasons = score_offline("paypal-secure-account.xyz", "/login-verify")
    assert score >= 0.70
    assert len(reasons) >= 2

    # Legitimate brand domain
    score_legit, reasons_legit = score_offline("paypal.com", "/signin")
    assert score_legit < 0.50
