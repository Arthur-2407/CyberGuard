import sys; sys.path.append('scripts')
import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = "C3B2B1B88FCD27FDD72DC14F987492A4"

session_id = cdp.attach_to_target(target_id)
cdp.send_command('Page.enable', session_id=session_id)

cdp.navigate(session_id, 'https://console.cloud.google.com/auth/clients?project=focus-flight-514216-d3')
time.sleep(6)

buttons = cdp.evaluate(session_id, """
(() => {
    return Array.from(document.querySelectorAll('button, a[role="button"], [aria-label]')).map(el => ({
        tag: el.tagName,
        ariaLabel: el.getAttribute('aria-label'),
        title: el.getAttribute('title'),
        text: (el.innerText || '').trim(),
        href: el.href || ''
    })).filter(el => el.ariaLabel || el.title || el.text);
})()
""")

print("Buttons on clients page:")
for b in buttons:
    if any(k in str(b).lower() for k in ['download', 'secret', 'cyberguard', 'edit', 'action', 'json', 'more']):
        print(" -", b)

cdp.close()

