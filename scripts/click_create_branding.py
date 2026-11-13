import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Clicking Create button...")
res = cdp.evaluate(session_id, """
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const createBtn = btns.find(b => b.innerText.trim() === 'Create');
    if (createBtn) {
        createBtn.click();
        return "Clicked Create button";
    }
    return "Create button not found";
})()
""")
print(f"Action: {res}")

print("Waiting 12 seconds for branding provisioning...")
time.sleep(12)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1000) : ''")

print(f"Post-create URL: {url}")
print(f"Post-create Title: {title}")
print(f"Body snippet:\n{body}")

cdp.close()

