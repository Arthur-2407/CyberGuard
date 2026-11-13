import sys; sys.path.append('scripts')
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target = next((t['targetId'] for t in cdp.get_targets() if 'console.cloud' in t.get('url', '')), None)
session_id = cdp.attach_to_target(target)
cdp.send_command('Page.enable', session_id=session_id)

clickables = cdp.evaluate(session_id, """
(() => {
    return Array.from(document.querySelectorAll('button, [role="button"], [role="combobox"], mat-select, input')).map(el => ({
        tag: el.tagName,
        role: el.getAttribute('role'),
        ariaLabel: el.getAttribute('aria-label'),
        id: el.id,
        text: (el.innerText || el.placeholder || el.value || '').trim()
    })).filter(el => el.text || el.ariaLabel || el.role);
})()
""")

print("Clickables on Create Client page:")
for c in (clickables or []):
    print(" -", c)

cdp.close()

