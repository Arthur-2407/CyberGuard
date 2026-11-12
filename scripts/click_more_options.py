import sys; sys.path.append('scripts')
import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = "C3B2B1B88FCD27FDD72DC14F987492A4"

session_id = cdp.attach_to_target(target_id)
cdp.send_command('Page.enable', session_id=session_id)

menu_info = cdp.evaluate(session_id, """
(() => {
    const moreBtn = Array.from(document.querySelectorAll('button[aria-label="More options"]')).pop();
    if (!moreBtn) return 'No more button found';
    moreBtn.click();
    return 'Clicked more options';
})()
""")
print("Menu action:", menu_info)
time.sleep(2)

items = cdp.evaluate(session_id, """
(() => {
    return Array.from(document.querySelectorAll('[role="menuitem"], button, [role="button"]')).map(el => ({
        text: (el.innerText || '').trim(),
        ariaLabel: el.getAttribute('aria-label') || ''
    })).filter(el => el.text.length > 2);
})()
""")

print("Menu items:")
for i in items:
    if any(k in str(i).lower() for k in ['download', 'secret', 'client', 'edit', 'delete', 'json']):
        print(" -", i)

cdp.close()

