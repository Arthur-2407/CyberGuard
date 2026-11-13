import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Filling project name and submitting...")
res = cdp.evaluate(session_id, """
(() => {
    const input = document.getElementById('p6ntest-name-input');
    if (!input) return "No input found";
    input.value = "CyberGuard Email Security";
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));

    // Find Create button
    const btns = Array.from(document.querySelectorAll('button'));
    const createBtn = btns.find(b => b.innerText.trim() === 'Create');
    if (!createBtn) return "No create button found";
    createBtn.click();
    return "Clicked Create button successfully";
})()
""")
print(f"Result: {res}")

# Wait 15 seconds for project creation and redirection
print("Waiting 15 seconds for project provisioning...")
time.sleep(15)

url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
print(f"Post-creation URL: {url}")
print(f"Post-creation Title: {title}")

cdp.close()

