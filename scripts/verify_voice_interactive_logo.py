import asyncio
import os
import sys
from playwright.async_api import async_playwright

async def verify_voice_logo():
    print("=" * 70)
    print("VERIFYING VOICE ANALYSIS INTERACTIVE ANIMATED LOGO")
    print("=" * 70)

    screenshot_dir = os.path.join(os.path.dirname(__file__), "..", "verification", "verification_evidence", "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)
    screenshot_path = os.path.join(screenshot_dir, "voice_analysis_interactive_logo_restored.png")

    console_errors = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={'width': 1600, 'height': 900})
        page = await context.new_page()

        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda err: console_errors.append(str(err)))

        print("\n[Step 1] Loading CyberGuard Console via file:///D:/BPUT/frontend/index.html...")
        file_url = 'file:///D:/BPUT/frontend/index.html'
        await page.goto(file_url, wait_until="load", timeout=15000)
        await page.wait_for_selector("body", timeout=10000)
        print("✓ Page loaded successfully")

        # Wait 1.5s for initial DOM ready & guest initialization
        await asyncio.sleep(1.5)

        print("\n[Step 2] Navigating to Voice Analysis tab...")
        tab_voice = page.locator("#tab-analyze")
        if await tab_voice.count() == 0:
            tab_voice = page.locator("button:has-text('Voice Analysis')")
        await tab_voice.click()
        await asyncio.sleep(1)

        print("\n[Step 3] Checking results-body and interactive logo presence...")
        results_body = page.locator("#results-body")
        assert await results_body.count() > 0, "results-body container missing!"
        
        logo = page.locator("#voice-interactive-logo")
        assert await logo.count() > 0, "voice-interactive-logo missing from results-body!"
        assert await logo.is_visible(), "voice-interactive-logo is not visible!"
        print("✓ #voice-interactive-logo is present and visible inside #results-body!")

        circle = page.locator("#acoustic-sonar-circle")
        assert await circle.count() > 0, "#acoustic-sonar-circle is missing!"
        assert await circle.is_visible(), "#acoustic-sonar-circle is not visible!"
        print("✓ #acoustic-sonar-circle is present and visible with holographic waves!")

        title = await page.locator("#acoustic-sensor-title").text_content()
        print(f"✓ Sensor Title: '{title.strip()}'")
        assert "STANDBY FOR INGESTION" not in title, f"Title still contains unwanted standby text: {title}"
        assert title.strip() == "ACOUSTIC SENSORS ONLINE", f"Unexpected title: {title}"

        sub = await page.locator("#acoustic-sensor-sub").text_content()
        print(f"✓ Sensor Subtitle: '{sub.strip()}'")
        assert len(sub.strip()) < 100, f"Subtitle not reduced: {sub}"

        # Verify no irritating chip or calibration text
        chip_count = await page.locator("#acoustic-interactive-chip").count()
        assert chip_count == 0, "Unwanted interactive chip is still present!"
        print("✓ Unwanted calibration chip completely removed.")

        # Test hover: Verify NO irritating 3D perspective / wobbly transform
        print("\n[Step 4] Testing mouse hover: verifying no irritating wobbly transform...")
        box = await logo.bounding_box()
        if box:
            await page.mouse.move(box["x"] + box["width"] / 3, box["y"] + box["height"] / 3)
            await asyncio.sleep(0.3)
            transform_val = await logo.evaluate("el => el.style.transform")
            print(f"✓ Transform on hover: '{transform_val}' (no wobble/perspective tilt)")
            assert "perspective" not in (transform_val or ""), f"Irritating perspective transform still present: {transform_val}"

        # Test subtle circle click interaction
        print("\n[Step 5] Testing subtle circle click interaction...")
        circle_el = page.locator("#acoustic-sonar-circle")
        await circle_el.click()
        await asyncio.sleep(0.2)
        has_ping = await circle_el.evaluate("el => el.classList.contains('acoustic-ping-active')")
        print(f"✓ Subtle ping wave triggered on circle click: {has_ping}")

        # Test resetAccountScopedState() does NOT wipe out the logo
        print("\n[Step 6] Testing resetAccountScopedState() resilience...")
        await page.evaluate("() => { if (typeof resetAccountScopedState === 'function') resetAccountScopedState(); }")
        await asyncio.sleep(0.5)
        assert await logo.is_visible(), "#voice-interactive-logo was destroyed by resetAccountScopedState()!"
        print("✓ #voice-interactive-logo survived resetAccountScopedState() cleanly!")

        # Take high-res screenshot
        print(f"\n[Step 7] Capturing screenshot to {screenshot_path}...")
        await page.screenshot(path=screenshot_path)
        print(f"✓ Screenshot saved: {screenshot_path}")

        print("\n" + "=" * 70)
        print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(verify_voice_logo())
