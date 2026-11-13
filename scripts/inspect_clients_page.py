import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_target = next((t['targetId'] for t in targets if 'console.cloud.google.com' in t.get('url', '')), None)
print('GCloud target:', gcloud_target)

session_id = cdp.attach_to_target(gcloud_target)
cdp.send_command('Page.enable', session_id=session_id)

cdp.navigate(session_id, 'https://console.cloud.google.com/auth/clients?project=focus-flight-514216-d3')
time.sleep(6)

url = cdp.evaluate(session_id, 'window.location.href')
title = cdp.evaluate(session_id, 'document.title')
print('URL:', url)
print('Title:', title)

info = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const rows = Array.from(document.querySelectorAll('tr, div[role="row"]')).map(r => r.innerText.trim()).filter(t => t.length > 5);
    const links = Array.from(document.querySelectorAll('a')).map(a => ({ text: a.innerText.trim(), href: a.href })).filter(a => a.href.includes('clients'));
    return {
        snippet: text.substring(0, 800),
        rows: rows.slice(0, 10),
        links: links.slice(0, 10)
    };
})()
""")

print("Snippet:\n", info.get('snippet', ''))
print("\nLinks:")
for l in info.get('links', []):
    print(" -", l)

cdp.close()

