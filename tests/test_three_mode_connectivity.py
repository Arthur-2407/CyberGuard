"""
CyberGuard Windows Endpoint Security — Phase 5 Three-Mode Networking & Connectivity Regression Suite

Verifies:
1. Authoritative State Single-Source-of-Truth:
   - Header status, 4-tier component cards, and resolved active health indicator are atomic and coherent.
   - Eliminates contradictory states (e.g., OFFLINE header with ONLINE active strip or indefinite PROBING).
2. Mode 1: Local Isolated Mode (Docker / Loopback listener, zero cloud dependency).
3. Mode 2: Deployed Cloud Mode (Direct OnRender synchronization without requiring local Docker).
4. Mode 3: Hybrid Auto-Failover (Multi-stage fallback: Local -> Tunnel -> Cloud).
5. Failure-Injection & Timeout Scenarios:
   - Simulated local port closed
   - Simulated cloud latency timeout
   - Optional unconfigured Cloudflare Tunnel
   - Graceful error boundary without unhandled exceptions
"""

import json
import subprocess
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def run_node_diagnostic(mode="hybrid", local_port=3000, cloud_url="https://cyberguard-backend-8rbz.onrender.com", custom_tunnel=""):
    """Executes connectivity_service.js directly via Node and parses the authoritative JSON response."""
    script = f"""
    const cs = require('./desktop/engine/connectivity_service');
    cs.runFullDiagnostics({{
      mode: '{mode}',
      localPort: {local_port},
      cloudUrl: '{cloud_url}',
      customTunnel: '{custom_tunnel}'
    }}).then(res => {{
      console.log(JSON.stringify(res));
    }}).catch(err => {{
      console.error(err);
      process.exit(1);
    }});
    """
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=15
    )
    assert proc.returncode == 0, f"Node process exited with code {proc.returncode}: {proc.stderr}"
    return json.loads(proc.stdout)


def test_01_single_source_of_truth_consistency():
    """Verify that diagnostics return both primary keys and backward-compatible aliases with consistent states."""
    res = run_node_diagnostic(mode="deployed")
    
    # Key normalization & backward-compatibility aliases
    assert "local" in res and "localDocker" in res
    assert "cloud" in res and "cloudBackend" in res
    assert "tunnel" in res and "cloudflareTunnel" in res
    assert "vercel" in res and "vercelPortal" in res
    assert "active" in res
    
    # Aliases must point to identical objects
    assert res["local"]["tier"] == res["localDocker"]["tier"] == "LOCAL_DOCKER"
    assert res["cloud"]["tier"] == res["cloudBackend"]["tier"] == "CLOUD_BACKEND"
    assert res["tunnel"]["tier"] == res["cloudflareTunnel"]["tier"] == "CLOUDFLARE_TUNNEL"
    assert res["vercel"]["tier"] == res["vercelPortal"]["tier"] == "VERCEL_PORTAL"

    # Both reachable and online boolean properties must exist and match
    for tier_key in ["local", "cloud", "tunnel", "vercel"]:
        tier = res[tier_key]
        assert "online" in tier, f"{tier_key} missing 'online' property"
        assert "reachable" in tier, f"{tier_key} missing 'reachable' property"
        assert tier["online"] == tier["reachable"]

    # Active resolution must agree with mode
    active = res["active"]
    assert active["mode"] == "deployed"
    assert active["activeTier"] == "cloud"
    if active["isReachable"]:
        assert active["headerPill"]["dotClass"] == "online"
        assert "ONLINE" in active["headerPill"]["label"]
        assert "ONLINE" in active["activeHealth"]
    else:
        assert active["headerPill"]["dotClass"] == "offline"
        assert "OFFLINE" in active["headerPill"]["label"]
        assert "OFFLINE" in active["activeHealth"]


def test_02_mode_1_local_isolated_operational():
    """Verify Mode 1 operates against local Docker / localhost without requiring cloud services."""
    res = run_node_diagnostic(mode="local", local_port=3000)
    
    active = res["active"]
    assert active["mode"] == "local"
    assert active["activeEndpoint"] == "http://127.0.0.1:3000"
    assert active["fallbackActive"] is False

    # Check local tier health
    local = res["local"]
    assert local["port"] == 3000
    assert local["endpoint"] == "http://127.0.0.1:3000"
    assert "status" in local
    assert local["status"] in ["HEALTHY", "DEGRADED", "OFFLINE", "TIMEOUT"]
    assert "diagnosticReason" in local


def test_03_mode_2_deployed_cloud_operational():
    """Verify Mode 2 operates against verified cloud infrastructure independently of local Docker."""
    res = run_node_diagnostic(mode="deployed", cloud_url="https://cyberguard-backend-8rbz.onrender.com")
    
    active = res["active"]
    assert active["mode"] == "deployed"
    assert active["activeEndpoint"] == "https://cyberguard-backend-8rbz.onrender.com"
    assert active["fallbackActive"] is False

    cloud = res["cloud"]
    assert cloud["endpoint"] == "https://cyberguard-backend-8rbz.onrender.com"
    assert "status" in cloud
    assert cloud["status"] in ["HEALTHY", "DEGRADED", "OFFLINE", "TIMEOUT"]


def test_04_mode_3_hybrid_auto_failover_stages():
    """Verify Hybrid Mode uses local Docker first, and falls back to cloud if local is unavailable."""
    # Test case A: Local Docker is online on port 3000
    res_normal = run_node_diagnostic(mode="hybrid", local_port=3000)
    if res_normal["local"]["online"]:
        assert res_normal["active"]["activeTier"] == "local"
        assert "127.0.0.1:3000" in res_normal["active"]["activeEndpoint"]
        assert res_normal["active"]["fallbackActive"] is False

    # Test case B: Local port closed (simulated on unused high port)
    res_failover = run_node_diagnostic(mode="hybrid", local_port=59999)
    assert res_failover["local"]["online"] is False
    assert res_failover["local"]["status"] in ["OFFLINE", "ERROR", "TIMEOUT"]

    # When local is down, hybrid must failover to Tunnel (Stage 2) if online, else Cloud (Stage 3)
    if res_failover.get("tunnel", {}).get("online"):
        assert res_failover["active"]["activeTier"] == "tunnel"
        assert res_failover["active"]["fallbackActive"] is True
        assert res_failover["active"]["headerPill"]["dotClass"] == "online"
        assert "HYBRID (TUNNEL)" in res_failover["active"]["headerPill"]["label"]
    elif res_failover["cloud"]["online"]:
        assert res_failover["active"]["activeTier"] == "cloud"
        assert res_failover["active"]["activeEndpoint"] == "https://cyberguard-backend-8rbz.onrender.com"
        assert res_failover["active"]["fallbackActive"] is True
        assert res_failover["active"]["headerPill"]["dotClass"] == "online"
        assert "HYBRID (CLOUD)" in res_failover["active"]["headerPill"]["label"]


def test_05_failure_injection_resilience():
    """Verify failure-injection scenarios return truthful diagnostic reasons without throwing unhandled exceptions."""
    # Invalid port / closed port
    script = """
    const cs = require('./desktop/engine/connectivity_service');
    Promise.all([
      cs.checkLocalBackend(58888),
      cs.checkTunnel('', { daemonAvailable: false, containers: [] }),
      cs.checkTunnel('https://invalid-nonexistent-subdomain-123456.trycloudflare.com')
    ]).then(([local, emptyTunnel, badTunnel]) => {
      console.log(JSON.stringify({ local, emptyTunnel, badTunnel }));
    }).catch(err => {
      console.error(err);
      process.exit(1);
    });
    """
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=15
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)

    assert data["local"]["online"] is False
    assert data["local"]["status"] in ["OFFLINE", "ERROR", "TIMEOUT"]
    assert len(data["local"]["diagnosticReason"]) > 0

    assert data["emptyTunnel"]["configured"] is False
    assert data["emptyTunnel"]["status"] == "NOT_CONFIGURED"

    assert data["badTunnel"]["configured"] is True
    assert data["badTunnel"]["online"] is False
    assert data["badTunnel"]["status"] in ["OFFLINE", "ERROR", "TIMEOUT"]


def test_06_desktop_html_and_css_design_system_tokens():
    """Verify desktop frontend tokens and design elements in index.html and styles.css."""
    html_path = ROOT_DIR / "desktop" / "frontend" / "index.html"
    css_path = ROOT_DIR / "desktop" / "frontend" / "styles.css"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # Verify no static contradictory initial status
    assert '<span id="active-backend-health" class="status-tag active ml-2">ONLINE</span>' not in html, \
        "Found hardcoded active ONLINE in initial HTML"
    assert 'id="active-backend-health"' in html

    # Verify diagnostic timestamp and telemetry toggle elements exist
    assert 'id="diag-last-checked-label"' in html
    assert 'id="btn-toggle-tech-diag"' in html
    assert 'id="tech-diag-container"' in html

    # Verify refined design system tokens
    for token in ["--bg-app", "--bg-surface", "--accent-primary", "--accent-secure", "--accent-warning", "--accent-critical"]:
        assert token in css, f"Missing design token {token} in styles.css"

    # Verify SVG containment rules to prevent SVG blowup
    assert "svg.brand-icon" in css
    assert "svg.alert-icon" in css
    assert "prefers-reduced-motion" in css
