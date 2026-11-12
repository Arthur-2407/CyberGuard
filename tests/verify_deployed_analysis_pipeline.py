"""tests/verify_deployed_analysis_pipeline.py

Live End-to-End Pipeline Verification:
  Tests deployed Vercel and GitHub Pages sending real threat analysis requests
  across Cloudflare Tunnel into the local Docker container.
"""

import asyncio
import json
import os
from playwright.async_api import async_playwright

ACTIVE_TUNNEL_URL = "https://reflected-sublime-courage-example.trycloudflare.com"

async def test_analysis(page, name, url):
    print("=" * 70)
    print(f"TESTING REAL THREAT PIPELINE ON: {name} ({url})")
    print("=" * 70)

    requests_captured = []
    page.on("request", lambda req: requests_captured.append({
        "method": req.method,
        "url": req.url
    }))

    await page.goto(url, wait_until="domcontentloaded", timeout=20000)
    await asyncio.sleep(2)

    # Configure Cloudflare Tunnel (simulating remote visitor where 127.0.0.1 is not the host)
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

    await asyncio.sleep(1)

    requests_captured.clear()

    print("-> Triggering POST /api/threats/url via cyberGuardFetch...")
    url_threat_res = await page.evaluate("""async () => {
        try {
            const formData = new FormData();
            formData.append('url', 'https://malicious-test-example.com/login');
            const resp = await cyberGuardFetch('/api/threats/url', {
                method: 'POST',
                body: formData
            });
            const data = await resp.json().catch(() => ({}));
            return { ok: resp.ok, status: resp.status, data: data };
        } catch (err) {
            return { error: err.message };
        }
    }""")

    print("-> URL Threat Analysis Result:", json.dumps(url_threat_res, indent=2))

    tunnel_requests = [r for r in requests_captured if ACTIVE_TUNNEL_URL in r["url"]]
    print(f"-> Captured Tunnel Requests: {len(tunnel_requests)}")
    for tr in tunnel_requests:
        print(f"   ✓ PROVEN [{tr['method']}] {tr['url']}")

    assert len(tunnel_requests) > 0, "No requests reached Cloudflare Tunnel!"
    assert url_threat_res.get("ok") is True, f"Threat analysis failed: {url_threat_res}"
    print(f"✓ REAL PIPELINE PASSED ON {name}!")

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        await test_analysis(page, "Vercel", "https://cyber-guard-backend-ashen.vercel.app/")
        await test_analysis(page, "GitHub Pages", "https://arthur-2407.github.io/CyberGuard/")

        await browser.close()
        print("\n" + "=" * 70)
        print("ALL DEPLOYED FRONTENDS FULLY PROVEN ROUTING THROUGH CLOUDFLARE TUNNEL!")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(main())
