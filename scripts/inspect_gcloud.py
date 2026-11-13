import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
print("Attaching to new tab...")
target_id = cdp.create_tab("about:blank")
session_id = cdp.attach_to_target(target_id)
print("Attached session:", session_id)

cdp.send_command("Page.enable", session_id=session_id)
print("Navigating to https://console.cloud.google.com/ ...")
cdp.navigate(session_id, "https://console.cloud.google.com/")

time.sleep(10)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body_text = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 800) : ''")

print(f"\n=== GOOGLE CLOUD CONSOLE INSPECTION ===")
print(f"Final URL: {url}")
print(f"Title: {title}")
print(f"Body preview:\n{body_text}\n")

# Close tab
cdp.close_tab(target_id)
cdp.close()
