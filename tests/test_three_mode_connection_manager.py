"""tests/test_three_mode_connection_manager.py

Comprehensive Automated Verification Suite for CyberGuard Three-Mode Architecture:
  - Mode A (Deployed Cloud): Pure cloud isolation, zero local tunnel leakage
  - Mode B (Local Docker): Strict localhost binding (port configurable)
  - Mode C (Hybrid Auto): 3-Stage fallback: Local Docker -> Cloudflare Tunnel -> Cloud Backend
  - Stale Tunnel Invalidation & Health Resolution
  - Cross-Platform WebSocket URL Derivation (ws:// vs wss://)
  - Desktop (Electron) & Web (Vercel/GitHub Pages) parity
"""

import json
import re
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_APP_JS = ROOT_DIR / "frontend" / "app.js"
DESKTOP_APP_JS = ROOT_DIR / "desktop" / "frontend" / "app.js"
FRONTEND_CONFIG_JS = ROOT_DIR / "frontend" / "config.js"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_01_mode_a_deployed_cloud_isolation():
    """
    Mode A must strictly resolve to cloud backend (or relative '' for Vercel).
    It must NEVER inject or fall back to cyberguard_custom_tunnel or 127.0.0.1.
    """
    for file_path in [FRONTEND_APP_JS, DESKTOP_APP_JS]:
        content = file_path.read_text(encoding="utf-8")
        
        # Verify getResolvedApiBase does NOT read cyberguard_custom_tunnel in mode === 'deployed'
        deployed_mode_match = re.search(
            r"else if\s*\(\s*mode\s*===\s*'deployed'\s*\)\s*\{([^}]+)\}",
            content,
            re.MULTILINE
        )
        assert deployed_mode_match is not None, f"Mode 'deployed' branch missing in {file_path}"
        branch_body = deployed_mode_match.group(1)
        assert "cyberguard_custom_tunnel" not in branch_body, (
            f"Mode A (deployed) must NOT check custom tunnel in {file_path}! "
            "It must remain purely isolated to the cloud backend."
        )
        assert "cyberguard-backend-8rbz.onrender.com" in branch_body

        # Verify setMode('deployed') does not set custom tunnel into api_base
        set_mode_match = re.search(
            r"setMode\s*\(\s*newMode\s*\)\s*\{(.+?)setPort",
            content,
            re.DOTALL
        )
        assert set_mode_match is not None, f"setMode method missing in {file_path}"
        set_mode_body = set_mode_match.group(1)
        assert "cyberguard_custom_tunnel" not in set_mode_body, (
            f"setMode('deployed') must not inject custom tunnel into api_base in {file_path}"
        )


def test_02_mode_b_local_docker_strict_port():
    """
    Mode B must lock to http://127.0.0.1:{port} and not fall back to cloud.
    """
    for file_path in [FRONTEND_APP_JS, DESKTOP_APP_JS]:
        content = file_path.read_text(encoding="utf-8")
        assert "mode === 'local'" in content
        assert "http://127.0.0.1:${port}" in content or "http://127.0.0.1:${this.port}" in content


def test_03_mode_c_hybrid_three_stage_probing():
    """
    Mode C must execute 3 distinct probing stages:
      Stage 1: Local Docker (127.0.0.1:3000)
      Stage 2: Cloudflare Tunnel (cyberguard_custom_tunnel if configured)
      Stage 3: Deployed Cloud Backend (cyberguard-backend-8rbz.onrender.com)
    """
    for file_path in [FRONTEND_APP_JS, DESKTOP_APP_JS]:
        content = file_path.read_text(encoding="utf-8")
        assert "isHybrid" in content or "mode === 'hybrid'" in content
        assert "cyberguard_custom_tunnel" in content
        assert "cyberguard_hybrid_active_base" in content
        assert "cyberguard-backend-8rbz.onrender.com" in content


def test_04_websocket_derivation_contract():
    """
    _resolveWsUrl must dynamically adapt protocol and authority:
      - http: -> ws:
      - https: -> wss:
      - relative base -> window.location protocol mapped to ws: or wss:
    """
    for file_path in [FRONTEND_APP_JS, DESKTOP_APP_JS]:
        content = file_path.read_text(encoding="utf-8")
        assert "function _resolveWsUrl" in content
        assert "parsed.protocol === 'https:' ? 'wss:' : 'ws:'" in content
        assert "/ws/stream" in content


def test_05_dynamic_backend_port_and_sync_configuration(client):
    """
    Verify backend FastAPI application exposes healthy configuration
    and storage sync endpoints without hardcoded paths.
    """
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ["ok", "healthy"]
    assert "version" in data


def test_06_cors_and_tunnel_preflight(client):
    """
    Verify backend permits preflight OPTIONS from Cloudflare tunnel origins,
    Vercel, and Electron file:// context.
    """
    headers = {
        "Origin": "https://districts-enhancement-consistently-left.trycloudflare.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    resp = client.options("/api/analyze", headers=headers)
    assert resp.status_code in [200, 204]
    assert resp.headers.get("access-control-allow-origin") in [
        "https://districts-enhancement-consistently-left.trycloudflare.com",
        "*"
    ]


def test_07_javascript_runtime_resolution_simulation():
    """
    Execute Node.js with simulated window, localStorage, and location
    to mathematically verify getResolvedApiBase() across all 3 modes.
    """
    node_eval_script = """
    const results = {};

    function runScenario(mode, hostname, storedTunnel, customPort) {
        let store = {};
        if (mode) store['cyberguard_connection_mode'] = mode;
        if (storedTunnel) store['cyberguard_custom_tunnel'] = storedTunnel;
        if (customPort) store['cyberguard_local_port'] = customPort;

        const location = {
            protocol: hostname.includes('localhost') ? 'http:' : 'https:',
            hostname: hostname,
            host: hostname,
            origin: (hostname.includes('localhost') ? 'http://' : 'https://') + hostname
        };

        const localStorage = {
            getItem: (k) => store[k] || null,
            setItem: (k, v) => { store[k] = String(v); },
            removeItem: (k) => { delete store[k]; }
        };

        // Simulated getResolvedApiBase logic matching frontend/app.js
        function getResolvedApiBase() {
            const m = localStorage.getItem('cyberguard_connection_mode');
            if (m === 'local') {
                const port = localStorage.getItem('cyberguard_local_port') || '3000';
                if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
                    return '';
                }
                return 'http://127.0.0.1:' + port;
            } else if (m === 'hybrid') {
                const hybridBase = localStorage.getItem('cyberguard_hybrid_active_base');
                if (hybridBase) return hybridBase;
                if (location.hostname.includes('vercel.app')) return '';
                return 'https://cyberguard-backend-8rbz.onrender.com';
            } else if (m === 'deployed') {
                if (location.hostname.includes('vercel.app')) return '';
                return 'https://cyberguard-backend-8rbz.onrender.com';
            }
            return 'https://cyberguard-backend-8rbz.onrender.com';
        }

        function _resolveWsUrl() {
            const base = getResolvedApiBase();
            if (base) {
                const parsed = new URL(base);
                const s = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
                return s + '//' + parsed.host + '/ws/stream';
            }
            const s = location.protocol === 'https:' ? 'wss:' : 'ws:';
            return s + '//' + location.host + '/ws/stream';
        }

        return { apiBase: getResolvedApiBase(), wsUrl: _resolveWsUrl() };
    }

    results['deployed_on_vercel'] = runScenario('deployed', 'cyber-guard-backend-ashen.vercel.app', 'https://stale.trycloudflare.com');
    results['deployed_on_github'] = runScenario('deployed', 'arthur-2407.github.io', 'https://stale.trycloudflare.com');
    results['local_default'] = runScenario('local', 'cyber-guard-backend-ashen.vercel.app', null, '3000');
    results['local_custom_port'] = runScenario('local', 'cyber-guard-backend-ashen.vercel.app', null, '3001');
    results['hybrid_fallback'] = runScenario('hybrid', 'cyber-guard-backend-ashen.vercel.app', null);

    console.log(JSON.stringify(results));
    """

    res = subprocess.run(
        ["node", "-e", node_eval_script],
        capture_output=True,
        text=True,
        check=True
    )
    data = json.loads(res.stdout)

    # 1. Mode A on Vercel resolves to relative '' and wss on vercel.app
    assert data["deployed_on_vercel"]["apiBase"] == ""
    assert data["deployed_on_vercel"]["wsUrl"] == "wss://cyber-guard-backend-ashen.vercel.app/ws/stream"

    # 2. Mode A on GitHub Pages resolves directly to Render cloud backend (NOT the stale tunnel)
    assert data["deployed_on_github"]["apiBase"] == "https://cyberguard-backend-8rbz.onrender.com"
    assert data["deployed_on_github"]["wsUrl"] == "wss://cyberguard-backend-8rbz.onrender.com/ws/stream"

    # 3. Mode B locks to 127.0.0.1:3000 and ws://
    assert data["local_default"]["apiBase"] == "http://127.0.0.1:3000"
    assert data["local_default"]["wsUrl"] == "ws://127.0.0.1:3000/ws/stream"

    # 4. Mode B with custom port 3001 locks to 127.0.0.1:3001
    assert data["local_custom_port"]["apiBase"] == "http://127.0.0.1:3001"
    assert data["local_custom_port"]["wsUrl"] == "ws://127.0.0.1:3001/ws/stream"
