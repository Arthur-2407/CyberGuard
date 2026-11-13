import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = cdp.create_tab("https://dash.cloudflare.com/login")
session_id = cdp.attach_to_target(target_id)
cdp.send_command("Page.enable", session_id=session_id)

time.sleep(8)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
html_len = cdp.evaluate(session_id, "document.documentElement.outerHTML.length")
text = cdp.evaluate(session_id, "document.body ? (document.body.innerText || document.body.textContent).substring(0, 500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"HTML len: {html_len}")
print(f"Text:\n{text}")

cdp.close_tab(target_id)
cdp.close()

