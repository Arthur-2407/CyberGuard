import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

url_api = "https://console.cloud.google.com/marketplace/product/google/gmail.googleapis.com?project=focus-flight-514216-d3"
print(f"Navigating to {url_api} ...")
cdp.navigate(session_id, url_api)

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
print(f"URL: {url}")
print(f"Title: {title}")

# Inspect for "Enable" button
btn_text = cdp.evaluate(session_id, """
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const enableBtn = btns.find(b => b.innerText.trim().toLowerCase() === 'enable');
    if (enableBtn) {
        enableBtn.click();
        return "Clicked Enable button";
    }
    const manageBtn = btns.find(b => b.innerText.trim().toLowerCase() === 'manage');
    if (manageBtn) {
        return "Already Enabled (Manage button found)";
    }
    return "Available buttons: " + btns.map(b => b.innerText.trim()).filter(Boolean).slice(0, 10).join(', ');
})()
""")
print(f"Button action: {btn_text}")

if "Clicked" in btn_text:
    print("Waiting 12 seconds for API enablement...")
    time.sleep(12)
    new_url = cdp.evaluate(session_id, "window.location.href")
    new_title = cdp.evaluate(session_id, "document.title")
    print(f"New URL: {new_url}")
    print(f"New Title: {new_title}")

cdp.close()

