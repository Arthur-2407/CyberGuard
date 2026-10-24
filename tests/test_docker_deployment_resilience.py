"""
CyberGuard Docker Deployment Resilience & On-Demand Architecture Test Suite.

Verifies:
1. Dockerfile container build specification, system libraries, non-root user, and healthcheck.
2. .dockerignore exclusion rules preventing context bloat from local training runs and secrets.
3. docker-compose.yml service topology (backend + secure Cloudflare tunnel companion).
4. CORS policy regex permitting Vercel, GitHub Pages, and secure tunnels (Cloudflare, ngrok).
5. Dynamic frontend config resolution without legacy Render endpoints.
6. Frontend UI contract: Docker navbar badge, modal console, and controller APIs.
7. Cross-platform management CLI script availability.
"""

import os
import re
from pathlib import Path
import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_dockerfile_specification_and_security_hardening():
    """Verify Dockerfile exists and contains required system packages, healthcheck, and non-root user."""
    dockerfile_path = ROOT_DIR / "Dockerfile"
    assert dockerfile_path.is_file(), "Dockerfile must exist in root directory"

    content = dockerfile_path.read_text(encoding="utf-8")
    assert "python:3.12-slim-bookworm" in content, "Must use python 3.12 slim bookworm base image"
    assert "libsndfile1" in content, "Must install libsndfile1 for audio decoding"
    assert "ffmpeg" in content, "Must install ffmpeg for media processing"
    assert "libzbar0" in content, "Must install libzbar0 for QR decoding"
    assert "curl" in content, "Must install curl for health checks"
    assert "HEALTHCHECK" in content, "Must declare container HEALTHCHECK directive"
    assert "EXPOSE 3000" in content, "Must expose port 3000"
    assert "USER cyberguard" in content, "Must drop privileges to non-root user cyberguard"
    assert "uvicorn" in content, "Must start uvicorn server"


def test_dockerignore_rules():
    """Verify .dockerignore excludes virtualenvs, git files, databases, and heavy intermediate checkpoints."""
    dockerignore_path = ROOT_DIR / ".dockerignore"
    assert dockerignore_path.is_file(), ".dockerignore must exist in root directory"

    content = dockerignore_path.read_text(encoding="utf-8")
    assert ".git" in content
    assert "venv/" in content
    assert "*.db*" in content
    assert "detector_adapted_*.pt" in content, "Must exclude intermediate adapted model weights"


def test_docker_compose_configuration():
    """Verify docker-compose.yml declares cyberguard-backend and secure tunnel companion services."""
    compose_path = ROOT_DIR / "docker-compose.yml"
    assert compose_path.is_file(), "docker-compose.yml must exist in root directory"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data
    services = compose_data["services"]

    # Backend service
    assert "cyberguard-backend" in services
    backend = services["cyberguard-backend"]
    assert "3000:3000" in [str(p) for p in backend.get("ports", [])]
    assert "healthcheck" in backend
    volumes = backend.get("volumes", [])
    assert any("./data:/app/data" in str(v) for v in volumes)

    # Tunnel service
    assert "tunnel" in services
    tunnel = services["tunnel"]
    assert "cloudflare/cloudflared" in tunnel.get("image", "")
    assert "tunnel" in tunnel.get("profiles", [])
    assert "cyberguard-backend" in tunnel.get("depends_on", {})


def test_cors_regex_allows_frontends_and_tunnels():
    """Verify backend CORS regex matches Vercel, GitHub Pages, and secure tunnels."""
    from backend.main import _cors_regex

    pattern = re.compile(_cors_regex)

    # Production frontends
    assert pattern.match("https://cyber-guard-backend-ashen.vercel.app")
    assert pattern.match("https://cyberguard-preview-xyz.vercel.app")
    assert pattern.match("https://arthur-2407.github.io")

    # Local development
    assert pattern.match("http://localhost:3000")
    assert pattern.match("http://127.0.0.1:3000")

    # Secure Tunnels
    assert pattern.match("https://random-subdomain.trycloudflare.com")
    assert pattern.match("https://cyberguard-test.ngrok-free.app")
    assert pattern.match("https://cyberguard.loca.lt")

    # Malicious origins rejected
    assert not pattern.match("https://evil-attacker.com")
    assert not pattern.match("https://phishing-site.net")


def test_frontend_config_has_no_render_dependency():
    """Verify frontend/config.js does not contain hardcoded render.com endpoints."""
    config_js_path = ROOT_DIR / "frontend" / "config.js"
    assert config_js_path.is_file()

    content = config_js_path.read_text(encoding="utf-8")
    assert "onrender.com" not in content, "Must not reference decommissioned onrender.com host"
    assert "window.__CYBERGUARD_CONFIG__" in content, "Must define __CYBERGUARD_CONFIG__ object"


def test_frontend_index_and_app_docker_ui_integration():
    """Verify frontend HTML and JS contain the Docker connectivity status badge and modal controller."""
    index_html_path = ROOT_DIR / "frontend" / "index.html"
    app_js_path = ROOT_DIR / "frontend" / "app.js"
    styles_css_path = ROOT_DIR / "frontend" / "styles.css"

    index_html = index_html_path.read_text(encoding="utf-8")
    app_js = app_js_path.read_text(encoding="utf-8")
    styles_css = styles_css_path.read_text(encoding="utf-8")

    # UI elements
    assert "backend-tunnel-widget" in index_html, "Navbar must contain backend-tunnel-widget"
    assert "nav-backend-btn" in index_html, "Navbar must contain nav-backend-btn"
    assert "backend-connectivity-modal" in index_html, "HTML must contain backend-connectivity-modal"

    # CSS classes
    assert ".backend-tunnel-widget" in styles_css
    assert ".nav-backend-btn" in styles_css
    assert ".backend-pulse-dot" in styles_css

    # JavaScript controller API
    assert "openBackendModal" in app_js
    assert "closeBackendModal" in app_js
    assert "testCustomBackendUrl" in app_js
    assert "saveCustomBackendUrl" in app_js
    assert "getResolvedApiBase" in app_js
    assert "setCyberGuardApiBase" in app_js


def test_cross_platform_management_scripts_exist():
    """Verify PowerShell, Batch, and Bash management scripts exist."""
    scripts_dir = ROOT_DIR / "scripts"
    assert (scripts_dir / "docker-manager.ps1").is_file()
    assert (scripts_dir / "docker-manager.bat").is_file()
    assert (scripts_dir / "docker-manager.sh").is_file()
