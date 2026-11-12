import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
print("Attaching to new tab for Cloudflare Zero Trust...")
target_id = cdp.create_tab("about:blank")
session_id = cdp.attach_to_target(target_id)
print("Attached session:", session_id)

cdp.send_command("Page.enable", session_id=session_id)
print("Navigating to https://one.dash.cloudflare.com/ ...")
cdp.navigate(session_id, "https://one.dash.cloudflare.com/")

time.sleep(10)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body_text = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 800) : ''")

print(f"\n=== CLOUDFLARE ZERO TRUST INSPECTION ===")
print(f"Final URL: {url}")
print(f"Title: {title}")
print(f"Body preview:\n{body_text}\n")

# Close tab
cdp.close_tab(target_id)
cdp.close()

