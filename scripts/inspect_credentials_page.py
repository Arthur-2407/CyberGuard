import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_target = next((t['targetId'] for t in targets if 'console.cloud.google.com' in t.get('url', '')), None)
session_id = cdp.attach_to_target(gcloud_target)
cdp.send_command('Page.enable', session_id=session_id)

cdp.navigate(session_id, 'https://console.cloud.google.com/apis/credentials?project=focus-flight-514216-d3')
time.sleep(6)

url = cdp.evaluate(session_id, 'window.location.href')
title = cdp.evaluate(session_id, 'document.title')
print('URL:', url)
print('Title:', title)

info = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const tableData = Array.from(document.querySelectorAll('table, [role="grid"], [role="table"]')).map(t => t.innerText);
    const links = Array.from(document.querySelectorAll('a')).map(a => ({ text: a.innerText.trim(), href: a.href })).filter(a => a.href.includes('oauthclient') || a.href.includes('key'));
    return {
        snippet: text.substring(0, 1500),
        tableData: tableData,
        links: links
    };
})()
""")

print("Snippet:\n", info.get('snippet', ''))
print("\nTable data:\n", info.get('tableData', ''))
print("\nLinks:\n", info.get('links', ''))

cdp.close()

