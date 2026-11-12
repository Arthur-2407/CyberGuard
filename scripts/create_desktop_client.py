import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

url_create_client = "https://console.cloud.google.com/auth/clients/create?project=focus-flight-514216-d3"
print(f"Navigating to {url_create_client} ...")
cdp.navigate(session_id, url_create_client)

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Body snippet:\n{body}")

# Inspect dropdowns and inputs for Application type: Desktop app
inputs = cdp.evaluate(session_id, """
Array.from(document.querySelectorAll('input, select, mat-select, [role="combobox"], [role="listbox"], button')).map(el => ({
    tag: el.tagName,
    type: el.type,
    id: el.id,
    name: el.name,
    role: el.getAttribute('role'),
    ariaLabel: el.getAttribute('aria-label'),
    placeholder: el.placeholder,
    value: el.value,
    text: el.innerText ? el.innerText.trim() : ''
})).filter(e => e.id || e.name || e.placeholder || e.ariaLabel || e.text).slice(0, 30);
""")
for i in inputs:
    print(i)

cdp.close()

