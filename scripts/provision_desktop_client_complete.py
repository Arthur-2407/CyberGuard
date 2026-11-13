import sys; sys.path.append('scripts')
import time
import re
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

if not gcloud_page:
    print("Could not find Google Cloud Console page target!")
    cdp.close()
    exit(1)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

create_url = "https://console.cloud.google.com/auth/clients/create?project=focus-flight-514216-d3"
print(f"Navigating to {create_url} ...")
cdp.navigate(session_id, create_url)
time.sleep(8)

# 1. Open Application type dropdown
print("Selecting Application Type: Desktop app ...")
cdp.evaluate(session_id, """
(() => {
    const sel = document.querySelector('cfc-select, [role="combobox"]');
    if (sel) sel.click();
})()
""")
time.sleep(2)

click_res = cdp.evaluate(session_id, """
(() => {
    const opts = Array.from(document.querySelectorAll('mat-option, [role="option"]'));
    const desktopOpt = opts.find(o => o.innerText.toLowerCase().includes('desktop'));
    if (desktopOpt) {
        desktopOpt.click();
        return "Selected Desktop app";
    }
    return "Desktop option not found";
})()
""")
print(f"Result: {click_res}")
time.sleep(2)

# 2. Enter client name
print("Setting client name to 'CyberGuard Desktop Endpoint' ...")
cdp.evaluate(session_id, """
(() => {
    const inputs = Array.from(document.querySelectorAll('input[type="text"]'));
    for (const inp of inputs) {
        inp.value = "CyberGuard Desktop Endpoint";
        inp.dispatchEvent(new Event('input', { bubbles: true }));
        inp.dispatchEvent(new Event('change', { bubbles: true }));
    }
})()
""")
time.sleep(1)

# 3. Click Create button
print("Clicking Create button ...")
btn_res = cdp.evaluate(session_id, """
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
print(f"Create action: {btn_res}")

print("Waiting 10 seconds for modal to appear ...")
time.sleep(10)

# 4. Extract Client ID and Client Secret from modal
modal_data = cdp.evaluate(session_id, """
(() => {
    const body = document.body ? document.body.innerText : '';
    // Look for GOCSPX- secret
    const secretMatch = body.match(/GOCSPX-[a-zA-Z0-9_\-]+/);
    const idMatch = body.match(/([0-9]+-[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com)/);
    
    // Also check inputs
    const inputs = Array.from(document.querySelectorAll('input')).map(i => ({
        val: i.value || '',
        lbl: i.getAttribute('aria-label') || ''
    }));

    let foundSecret = secretMatch ? secretMatch[0] : null;
    let foundId = idMatch ? idMatch[1] : null;

    for (const inp of inputs) {
        if (!foundSecret && inp.val.startsWith('GOCSPX-')) foundSecret = inp.val;
        if (!foundId && inp.val.includes('.apps.googleusercontent.com')) foundId = inp.val;
    }

    return {
        id: foundId,
        secret: foundSecret,
        bodySnippet: body.substring(0, 1500)
    };
})()
""")

client_id = modal_data.get('id')
client_secret = modal_data.get('secret')

if client_id:
    print(f"\n==========================================")
    print(f"SUCCESS: Extracted GOOGLE_CLIENT_ID: {client_id}")
    with open("scripts/extracted_client_id.txt", "w") as f:
        f.write(client_id)
else:
    print("Could not find Client ID.")

if client_secret:
    print(f"SUCCESS: Extracted GOOGLE_CLIENT_SECRET (starts with: {client_secret[:7]}..., len: {len(client_secret)})")
    # Update .env
    with open(".env", "r") as f:
        env_content = f.read()

    env_content = re.sub(r"GOOGLE_CLIENT_ID=.*", f"GOOGLE_CLIENT_ID={client_id}", env_content)
    if "GOOGLE_CLIENT_SECRET=" in env_content:
        env_content = re.sub(r"GOOGLE_CLIENT_SECRET=.*", f"GOOGLE_CLIENT_SECRET={client_secret}", env_content)
    else:
        env_content += f"\nGOOGLE_CLIENT_SECRET={client_secret}\n"

    with open(".env", "w") as f:
        f.write(env_content)
    print("Updated .env with GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")
else:
    print("Could not find Client Secret in modal. Modal snippet:")
    print(modal_data.get('bodySnippet', '')[:1000])

cdp.close()

