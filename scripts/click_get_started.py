import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Clicking 'Get started'...")
res = cdp.evaluate(session_id, """
(() => {
    const links = Array.from(document.querySelectorAll('a, button'));
    const btn = links.find(l => l.innerText.trim().toLowerCase() === 'get started');
    if (btn) {
        btn.click();
        return "Clicked Get started";
    }
    return "Get started button not found";
})()
""")
print(f"Action: {res}")

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Body:\n{body}")

cdp.close()

