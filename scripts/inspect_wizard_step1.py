import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Inspecting step 1 inputs...")
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
})).filter(e => e.id || e.name || e.placeholder || e.ariaLabel || e.text)
""")
for i in inputs:
    print(i)

cdp.close()

