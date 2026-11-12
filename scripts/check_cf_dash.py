import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = cdp.create_tab("about:blank")
cdp.send_command("Target.activateTarget", {"targetId": target_id})
session_id = cdp.attach_to_target(target_id)
cdp.send_command("Page.enable", session_id=session_id)

print("Navigating to https://dash.cloudflare.com/login ...")
cdp.navigate(session_id, "https://dash.cloudflare.com/login")

time.sleep(10)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
text = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1000) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Text:\n{text}")

cdp.close_tab(target_id)
cdp.close()
