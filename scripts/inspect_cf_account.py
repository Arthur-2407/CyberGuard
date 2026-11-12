import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()

cf_target = None
for t in targets:
    if t.get('type') == 'page' and 'dash.cloudflare.com' in t.get('url', ''):
        cf_target = t.get('targetId')
        break

print(f"Cloudflare tab target: {cf_target}")
if not cf_target:
    cf_target = cdp.create_tab("https://dash.cloudflare.com/")
    print(f"Created new Cloudflare tab: {cf_target}")

session_id = cdp.attach_to_target(cf_target)
cdp.send_command("Page.enable", session_id=session_id)

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
print(f"URL: {url}")
print(f"Title: {title}")

# Check links and buttons (e.g. Websites, Zero Trust, Account ID, Domains)
page_info = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const links = Array.from(document.querySelectorAll('a, button, [role="link"], h1, h2, h3')).map(el => ({
        tag: el.tagName,
        text: (el.innerText || '').trim(),
        href: el.href || ''
    })).filter(l => l.text.length > 1).slice(0, 40);
    return {
        snippet: text.substring(0, 1000),
        links: links
    };
})()
""")

print("Page snippet:\n", page_info['snippet'])
print("\nLinks and buttons:")
for l in page_info['links']:
    print(f" - [{l['tag']}] {l['text']} -> {l['href']}")

cdp.close()

