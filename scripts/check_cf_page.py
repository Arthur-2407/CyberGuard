import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = cdp.create_tab("https://dash.cloudflare.com/one/")
session_id = cdp.attach_to_target(target_id)
cdp.send_command("Page.enable", session_id=session_id)

time.sleep(12)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
html_snippet = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Body text:\n{html_snippet}")

cdp.close_tab(target_id)
cdp.close()

