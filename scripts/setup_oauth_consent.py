import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

url_consent = "https://console.cloud.google.com/apis/credentials/consent?project=focus-flight-514216-d3"
print(f"Navigating to {url_consent} ...")
cdp.navigate(session_id, url_consent)

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Body text:\n{body}")

# Check options (e.g. Internal vs External radio buttons, Get Started, Create, etc.)
elements = cdp.evaluate(session_id, """
Array.from(document.querySelectorAll('input, button, a')).map(el => ({
    tag: el.tagName,
    type: el.type,
    id: el.id,
    name: el.name,
    value: el.value,
    text: el.innerText ? el.innerText.trim() : '',
    ariaLabel: el.getAttribute('aria-label')
})).filter(e => e.text || e.name || e.id || e.value).slice(0, 30);
""")
print(f"Elements: {elements}")

cdp.close()

