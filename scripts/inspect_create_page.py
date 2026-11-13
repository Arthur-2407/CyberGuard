import sys; sys.path.append('scripts')
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target = next((t['targetId'] for t in cdp.get_targets() if 'console.cloud.google.com' in t.get('url', '')), None)
session_id = cdp.attach_to_target(target)
cdp.send_command('Page.enable', session_id=session_id)

elements = cdp.evaluate(session_id, """
(() => {
    return Array.from(document.querySelectorAll('mat-select, select, [role="combobox"], [role="listbox"], cfc-select, div[aria-haspopup]')).map(el => ({
        tag: el.tagName,
        id: el.id,
        role: el.getAttribute('role'),
        ariaLabel: el.getAttribute('aria-label'),
        ariaHasPopup: el.getAttribute('aria-haspopup'),
        text: (el.innerText || '').trim()
    }));
})()
""")
print("Select elements:", elements)
cdp.close()

