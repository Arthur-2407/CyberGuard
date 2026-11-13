import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Navigating to https://console.cloud.google.com/projectcreate ...")
cdp.navigate(session_id, "https://console.cloud.google.com/projectcreate")

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Body text:\n{body}")

# Check inputs
inputs = cdp.evaluate(session_id, """
Array.from(document.querySelectorAll('input, button')).map(el => ({
    tag: el.tagName,
    type: el.type,
    id: el.id,
    name: el.name,
    value: el.value,
    ariaLabel: el.getAttribute('aria-label'),
    text: el.innerText
}))
""")
print(f"Inputs and buttons count: {len(inputs)}")
for item in inputs:
    if item['type'] != 'hidden':
        print(item)

cdp.close()

