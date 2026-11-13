import time
import re
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Submitting Desktop client creation...")
sub_res = cdp.evaluate(session_id, """
(() => {
    const input = document.getElementById('_0rif_mat-input-0') || document.querySelector('input[type="text"]');
    if (input) {
        input.value = "CyberGuard Windows Desktop";
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }
    const btns = Array.from(document.querySelectorAll('button'));
    const createBtn = btns.find(b => b.innerText.trim() === 'Create');
    if (createBtn) {
        createBtn.click();
        return "Clicked Create";
    }
    return "Create button not found";
})()
""")
print(f"Action: {sub_res}")

print("Waiting 10 seconds for modal with Client ID...")
time.sleep(10)

modal_text = cdp.evaluate(session_id, """
(() => {
    return document.body ? document.body.innerText : '';
})()
""")

print("Inspecting page text for Client ID...")
match = re.search(r'([0-9]+-[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com)', modal_text)
if match:
    client_id = match.group(1)
    print(f"\n==========================================")
    print(f"SUCCESS! Extracted GOOGLE_CLIENT_ID: {client_id}")
    print(f"==========================================\n")
    with open("scripts/extracted_client_id.txt", "w") as f:
        f.write(client_id)
else:
    print("Could not find client id via regex. Page text snippet:")
    print(modal_text[:1500])

cdp.close()

