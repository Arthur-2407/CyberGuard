import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

url_aud = "https://console.cloud.google.com/auth/audience?project=focus-flight-514216-d3"
print(f"Navigating to {url_aud} ...")
cdp.navigate(session_id, url_aud)

time.sleep(8)
url = cdp.evaluate(session_id, "window.location.href")
title = cdp.evaluate(session_id, "document.title")
body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"URL: {url}")
print(f"Title: {title}")
print(f"Body snippet:\n{body}")

# Check for "Add users" button
action = cdp.evaluate(session_id, """
(() => {
    const btns = Array.from(document.querySelectorAll('button, a'));
    const addBtn = btns.find(b => b.innerText.toLowerCase().includes('add users') || b.innerText.toLowerCase().includes('add user'));
    if (addBtn) {
        addBtn.click();
        return "Clicked Add users";
    }
    return "Add users button not found";
})()
""")
print(f"Action: {action}")

if "Clicked" in action:
    time.sleep(2)
    # Enter email
    fill_res = cdp.evaluate(session_id, """
    (() => {
        const inp = document.querySelector('input[type="email"], input[aria-label*="email"], input[placeholder*="email"], input[id*="mat-input"]');
        if (inp) {
            inp.value = "cyberguardadmin@gmail.com";
            inp.dispatchEvent(new Event('input', { bubbles: true }));
            inp.dispatchEvent(new Event('change', { bubbles: true }));
            inp.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', keyCode: 13, bubbles: true }));
        }
        const saveBtns = Array.from(document.querySelectorAll('button'));
        const saveBtn = saveBtns.find(b => b.innerText.trim().toLowerCase() === 'save');
        if (saveBtn) {
            saveBtn.click();
            return "Saved test user";
        }
        return "Save button not found";
    })()
    """)
    print(f"Fill and Save: {fill_res}")
    time.sleep(3)

cdp.close()

