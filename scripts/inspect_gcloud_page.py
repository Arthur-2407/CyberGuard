import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()

gcloud_page = None
for t in targets:
    if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', ''):
        gcloud_page = t.get('targetId')
        break

print(f"Target ID: {gcloud_page}")
if gcloud_page:
    session_id = cdp.attach_to_target(gcloud_page)
    cdp.send_command("Page.enable", session_id=session_id)
    url = cdp.evaluate(session_id, "window.location.href")
    title = cdp.evaluate(session_id, "document.title")
    print(f"URL: {url}")
    print(f"Title: {title}")

    # Inspect visible text & projects
    body_text = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")
    print(f"Body text:\n{body_text[:800]}")

cdp.close()

