import sys; sys.path.append('scripts')
import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = "C3B2B1B88FCD27FDD72DC14F987492A4"

session_id = cdp.attach_to_target(target_id)
cdp.send_command('Page.enable', session_id=session_id)

click_res = cdp.evaluate(session_id, """
(() => {
    const link = Array.from(document.querySelectorAll('a')).find(a => (a.innerText || '').includes('CyberGuard Windows Desktop'));
    if (!link) return 'Link not found';
    link.click();
    return 'Clicked CyberGuard Windows Desktop link';
})()
""")

print("Click result:", click_res)
time.sleep(5)

url = cdp.evaluate(session_id, 'window.location.href')
title = cdp.evaluate(session_id, 'document.title')
print('URL:', url)
print('Title:', title)

info = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const buttons = Array.from(document.querySelectorAll('button, a[role="button"]')).map(b => (b.innerText || '').trim()).filter(t => t.length > 2);
    return {
        snippet: text.substring(0, 1500),
        buttons: buttons
    };
})()
""")

print("Snippet:\n", info.get('snippet', ''))
print("\nButtons:\n", info.get('buttons', []))

cdp.close()

