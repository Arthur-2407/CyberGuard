import sys; sys.path.append('scripts')
import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = "C3B2B1B88FCD27FDD72DC14F987492A4"

session_id = cdp.attach_to_target(target_id)
cdp.send_command('Page.enable', session_id=session_id)

url = cdp.evaluate(session_id, 'window.location.href')
title = cdp.evaluate(session_id, 'document.title')
print('URL:', url)
print('Title:', title)

# Inspect table and details
details = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const rows = Array.from(document.querySelectorAll('tr, [role="row"]')).map(r => r.innerText.trim()).filter(t => t.length > 5);
    const links = Array.from(document.querySelectorAll('a, button, [role="link"]')).map(a => ({ text: (a.innerText || '').trim(), href: a.href || '' })).filter(a => a.text.includes('CyberGuard') || a.text.includes('Client') || a.text.includes('Secret') || a.text.includes('Download') || a.href.includes('client'));
    return {
        snippet: text.substring(0, 2000),
        rows: rows,
        links: links
    };
})()
""")

print("Snippet:\n", details.get('snippet', ''))
print("\nRows:\n")
for r in details.get('rows', []):
    print(" -", r)

print("\nRelevant links:\n")
for l in details.get('links', []):
    print(" -", l)

cdp.close()

