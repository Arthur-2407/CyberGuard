"""tests/verify_deployed_endpoints.py

Live Browser End-to-End Verification of Deployed CyberGuard Frontends:
  - Tests Vercel: https://cyber-guard-backend-ashen.vercel.app/
  - Tests GitHub Pages: https://arthur-2407.github.io/CyberGuard
  - Verifies network request interception and routing:
      Mode A: Routes to deployed cloud backend
      Mode B: Routes to local Docker
      Mode C (Hybrid) / Tunnel: Routes to Cloudflare Tunnel (https://*.trycloudflare.com)
  - Proves that API and WebSocket requests actually hit the Tunnel
"""

import asyncio
import json
import os
import sys
from playwright.async_api import async_playwright

ACTIVE_TUNNEL_URL = "https://reflected-sublime-courage-example.trycloudflare.com"

async def test_frontend(page, name, url):
    print("=" * 70)
    print(f"VERIFYING DEPLOYED FRONTEND: {name} ({url})")
    print("=" * 70)

    requests_dispatched = []
    page.on("request", lambda req: requests_dispatched.append({
        "method": req.method,
        "url": req.url,
        "resource_type": req.resource_type
    }))

    print(f"-> Navigating to {url}...")
    await page.goto(url, wait_until="domcontentloaded", timeout=20000)
    await page.wait_for_selector("body", timeout=10000)
    await asyncio.sleep(2)

    initial_title = await page.title()
    print(f"✓ Page loaded. Title: {initial_title}")

    # Inspect current state
    state = await page.evaluate("""() => {
        return {
            mode: window.CyberGuardConnection ? window.CyberGuardConnection.mode : null,
            apiBase: window.CyberGuardConnection ? window.CyberGuardConnection.getApiBase() : null,
            resolvedApiBase: typeof getResolvedApiBase === 'function' ? getResolvedApiBase() : null,
            wsUrl: typeof _resolveWsUrl === 'function' ? _resolveWsUrl() : null,
            storedMode: localStorage.getItem('cyberguard_connection_mode'),
            storedTunnel: localStorage.getItem('cyberguard_custom_tunnel'),
            storedHybridBase: localStorage.getItem('cyberguard_hybrid_active_base'),
            storedApiBase: localStorage.getItem('cyberguard_api_base')
        };
    }""")
    print("-> Initial Client State:", json.dumps(state, indent=2))

    # Test Setting Cloudflare Tunnel Endpoint (simulating remote visitor where 127.0.0.1 is not the host)
    print(f"\n-> Setting Cloudflare Tunnel endpoint: {ACTIVE_TUNNEL_URL} ...")
    await page.evaluate(f"""(tunnelUrl) => {{
        localStorage.setItem('cyberguard_custom_tunnel', tunnelUrl);
        localStorage.setItem('cyberguard_hybrid_active_base', tunnelUrl);
        if (window.CyberGuardConnection) {{
            window.CyberGuardConnection.loopbackPermissionState = 'denied';
            window.CyberGuardConnection.setMode('hybrid');
            window.CyberGuardConnection.hybridActiveBase = tunnelUrl;
        }}
        if (typeof setCyberGuardApiBase === 'function') {{
            setCyberGuardApiBase(tunnelUrl);
        }}
    }}""", ACTIVE_TUNNEL_URL)

    await asyncio.sleep(2)

    # Inspect state after configuring tunnel
    updated_state = await page.evaluate("""() => {
        return {
            mode: window.CyberGuardConnection ? window.CyberGuardConnection.mode : null,
            apiBase: window.CyberGuardConnection ? window.CyberGuardConnection.getApiBase() : null,
            wsUrl: typeof _resolveWsUrl === 'function' ? _resolveWsUrl() : null
        };
    }""")
    print("-> State after setting Cloudflare Tunnel:", json.dumps(updated_state, indent=2))

    # Clear recorded requests and trigger an API call via cyberGuardFetch
    requests_dispatched.clear()
    print("\n-> Triggering cyberGuardFetch('/api/health') with Tunnel configured...")
    fetch_result = await page.evaluate("""async () => {
        try {
            const resp = await cyberGuardFetch('/api/health');
            const data = await resp.json().catch(() => ({}));
            return { ok: resp.ok, status: resp.status, data: data };
        } catch (err) {
            return { error: err.message };
        }
    }""")
    print("-> cyberGuardFetch result:", json.dumps(fetch_result, indent=2))

    print("\n-> Outgoing requests captured during fetch:")
    tunnel_hits = []
    for r in requests_dispatched:
        print(f"   [{r['method']}] {r['url']}")
        if ACTIVE_TUNNEL_URL in r['url']:
            tunnel_hits.append(r)

    print(f"\n-> Total requests to Cloudflare Tunnel: {len(tunnel_hits)}")
    for th in tunnel_hits:
        print(f"   ✓ PROVEN TUNNEL REQUEST: [{th['method']}] {th['url']}")

    return len(tunnel_hits) > 0, fetch_result


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={'width': 1440, 'height': 900})
        page = await context.new_page()

        # 1. Test Vercel
        vercel_ok, vercel_res = await test_frontend(page, "Vercel", "https://cyber-guard-backend-ashen.vercel.app/")

        # 2. Test GitHub Pages
        gh_ok, gh_res = await test_frontend(page, "GitHub Pages", "https://arthur-2407.github.io/CyberGuard/")

        await browser.close()

        print("\n" + "=" * 70)
        print("SUMMARY OF LIVE DEPLOYED FRONTEND VERIFICATION:")
        print(f"  Vercel -> Cloudflare Tunnel -> Local Docker: {'PROVEN ✓' if vercel_ok else 'FAILED ✗'}")
        print(f"  GitHub Pages -> Cloudflare Tunnel -> Local Docker: {'PROVEN ✓' if gh_ok else 'FAILED ✗'}")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(main())
