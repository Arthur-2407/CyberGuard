import sys; sys.path.append('scripts')
import time
import re
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
page_target = next((t['targetId'] for t in cdp.get_targets() if t.get('type') == 'page' and 'console.cloud' in t.get('url', '')), None)
print('Page target ID:', page_target)

session_id = cdp.attach_to_target(page_target)
cdp.send_command('Page.enable', session_id=session_id)

create_url = 'https://console.cloud.google.com/auth/clients/create?project=focus-flight-514216-d3'
print('Navigating to', create_url)
cdp.navigate(session_id, create_url)
time.sleep(8)

# 1. Click cfc-select
print('Clicking Application Type selector...')
click_sel = cdp.evaluate(session_id, """
(() => {
    const sel = document.querySelector('cfc-select') || document.querySelector('[role="combobox"]');
    if (sel) {
        sel.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
        sel.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
        sel.click();
        return 'Clicked selector: ' + (sel.id || sel.tagName);
    }
    return 'Selector not found';
})()
""")
print('Click selector:', click_sel)
time.sleep(2)

# 2. Select Desktop app
print('Selecting Desktop app...')
click_opt = cdp.evaluate(session_id, """
(() => {
    const opts = Array.from(document.querySelectorAll('*')).filter(e => (e.innerText || '').trim() === 'Desktop app' && e.children.length === 0);
    if (opts.length > 0) {
        opts[0].click();
        return 'Clicked Desktop app option';
    }
    return 'Desktop app option not found';
})()
""")
print('Click option:', click_opt)
time.sleep(2)

# 3. Enter Name
print('Setting Name input...')
fill_name = cdp.evaluate(session_id, """
(() => {
    const inputs = Array.from(document.querySelectorAll('input[type="text"]'));
    for (const inp of inputs) {
        inp.value = 'CyberGuard Desktop Guardian';
        inp.dispatchEvent(new Event('input', { bubbles: true }));
        inp.dispatchEvent(new Event('change', { bubbles: true }));
    }
    return 'Set name on ' + inputs.length + ' inputs';
})()
""")
print('Fill name:', fill_name)
time.sleep(1)

# 4. Click Create
print('Clicking Create button...')
click_create = cdp.evaluate(session_id, """
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const createBtn = btns.find(b => b.innerText.trim() === 'Create');
    if (createBtn) {
        createBtn.click();
        return 'Clicked Create button';
    }
    return 'Create button not found';
})()
""")
print('Click create:', click_create)

print('Waiting 10s for client creation modal...')
time.sleep(10)

# 5. Extract Client ID and Client Secret
modal_data = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    const secretMatch = text.match(/GOCSPX-[a-zA-Z0-9_-]+/);
    const idMatch = text.match(/([0-9]+-[a-zA-Z0-9_-]+\\.apps\\.googleusercontent\\.com)/);
    
    const inputs = Array.from(document.querySelectorAll('input')).map(i => i.value || '');
    let id = idMatch ? idMatch[1] : null;
    let secret = secretMatch ? secretMatch[0] : null;

    for (const v of inputs) {
        if (!id && v.includes('.apps.googleusercontent.com')) id = v;
        if (!secret && v.startsWith('GOCSPX-')) secret = v;
    }

    return {
        id: id,
        secret: secret,
        bodyText: text.substring(0, 1500)
    };
})()
""")

client_id = modal_data.get('id')
client_secret = modal_data.get('secret')

print("Extraction results:")
if client_id:
    print(f"Extracted GOOGLE_CLIENT_ID: {client_id}")
    with open("scripts/extracted_client_id.txt", "w") as f:
        f.write(client_id)
else:
    print("Could not find Client ID.")

if client_secret:
    print(f"Extracted GOOGLE_CLIENT_SECRET: starts with {client_secret[:7]}..., length {len(client_secret)}")
    # Update .env
    with open(".env", "r") as f:
        env = f.read()
    env = re.sub(r"GOOGLE_CLIENT_ID=.*", f"GOOGLE_CLIENT_ID={client_id}", env)
    if "GOOGLE_CLIENT_SECRET=" in env:
        env = re.sub(r"GOOGLE_CLIENT_SECRET=.*", f"GOOGLE_CLIENT_SECRET={client_secret}", env)
    else:
        env += f"\nGOOGLE_CLIENT_SECRET={client_secret}\n"
    with open(".env", "w") as f:
        f.write(env)
    print("Updated .env safely without secret leakage.")
else:
    print("Could not find Client Secret in modal text.")
    print("Modal text snippet:\n", modal_data.get('bodyText', '')[:800])

cdp.close()

