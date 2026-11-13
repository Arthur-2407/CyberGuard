import sys; sys.path.append('scripts')
import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = "C3B2B1B88FCD27FDD72DC14F987492A4"

session_id = cdp.attach_to_target(target_id)
cdp.send_command('Page.enable', session_id=session_id)

cdp.navigate(session_id, 'https://console.cloud.google.com/apis/credentials?project=focus-flight-514216-d3')
time.sleep(8)

url = cdp.evaluate(session_id, 'window.location.href')
title = cdp.evaluate(session_id, 'document.title')
print('URL:', url)
print('Title:', title)

info = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const links = Array.from(document.querySelectorAll('a, button')).map(el => ({
        tag: el.tagName,
        text: (el.innerText || '').trim(),
        ariaLabel: el.getAttribute('aria-label') || '',
        href: el.href || ''
    })).filter(el => el.text || el.ariaLabel);
    return {
        snippet: text.substring(0, 1500),
        links: links.filter(l => anyMatches(l))
    };
    function anyMatches(l) {
        const s = JSON.stringify(l).toLowerCase();
        return s.includes('desktop') || s.includes('cyberguard') || s.includes('download') || s.includes('client');
    }
})()
""")

print("Snippet:\n", info.get('snippet', ''))
print("\nMatched links/buttons:")
for l in info.get('links', []):
    print(" -", l)

cdp.close()

