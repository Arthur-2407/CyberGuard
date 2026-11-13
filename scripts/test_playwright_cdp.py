import asyncio
from playwright.async_api import async_playwright

async def main():
    print("Testing Playwright connect_over_cdp...")
    async with async_playwright() as p:
        try:
            # Let's test connecting with the CDP endpoint or ws endpoint
            browser = await p.chromium.connect_over_cdp("http://127.0.0.1:9222", timeout=5000)
            print("Connected successfully over http://127.0.0.1:9222!")
            contexts = browser.contexts
            print(f"Contexts count: {len(contexts)}")
            for ctx in contexts:
                print(f"Pages: {len(ctx.pages)}")
                for page in ctx.pages:
                    print(f" - Page URL: {page.url}, Title: {await page.title()}")
            await browser.close()
        except Exception as e:
            print("connect_over_cdp failed with http:", e)

            # Let's try with ws endpoint from DevToolsActivePort
            try:
                ws_url = "ws://127.0.0.1:9222/devtools/browser/6608d397-f67d-4486-84f0-ee98b55e8151"
                print(f"Trying ws_url: {ws_url}")
                browser = await p.chromium.connect_over_cdp(ws_url, timeout=5000)
                print("Connected successfully via ws_url!")
                for ctx in browser.contexts:
                    for page in ctx.pages:
                        print(f" - Page URL: {page.url}, Title: {await page.title()}")
                await browser.close()
            except Exception as e2:
                print("connect_over_cdp failed with ws:", e2)

asyncio.run(main())

