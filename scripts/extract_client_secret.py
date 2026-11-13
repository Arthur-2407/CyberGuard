import sys; sys.path.append('scripts')
import time
import re
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target_id = "C3B2B1B88FCD27FDD72DC14F987492A4"

session_id = cdp.attach_to_target(target_id)
cdp.send_command('Page.enable', session_id=session_id)

client_url = "https://console.cloud.google.com/auth/clients/676005930102-os27bg5qtmp01qvcnrflj2ckgcmookvs.apps.googleusercontent.com?project=focus-flight-514216-d3"
print(f"Navigating to client details page...")
cdp.navigate(session_id, client_url)
time.sleep(6)

url = cdp.evaluate(session_id, 'window.location.href')
title = cdp.evaluate(session_id, 'document.title')
print('URL:', url)
print('Title:', title)

# Look for client secret input or text safely without logging secrets
res = cdp.evaluate(session_id, """
(() => {
    const text = document.body ? document.body.innerText : '';
    // Look for client secret patterns
    const inputs = Array.from(document.querySelectorAll('input')).map(i => ({
        id: i.id,
        name: i.name,
        type: i.type,
        ariaLabel: i.getAttribute('aria-label') || '',
        valLen: (i.value || '').length,
        hasVal: Boolean(i.value)
    }));
    return {
        hasSecretLabel: text.includes('Client secret') || text.includes('client secret'),
        inputs: inputs
    };
})()
""")

print("Has client secret label:", res.get('hasSecretLabel'))
print("Inputs:", res.get('inputs'))

# Extract secret value safely directly to .env
secret_val = cdp.evaluate(session_id, """
(() => {
    // Check all inputs whose aria-label or predecessor text refers to Client secret
    const inputs = Array.from(document.querySelectorAll('input'));
    for (const inp of inputs) {
        const lbl = (inp.getAttribute('aria-label') || '').toLowerCase();
        if (lbl.includes('secret') && inp.value) {
            return inp.value.trim();
        }
    }
    // Alternatively look for span or div with secret
    const all = Array.from(document.querySelectorAll('div, span, td, p'));
    for (let i = 0; i < all.length; i++) {
        const t = (all[i].innerText || '').trim();
        if (t === 'Client secret' && i + 1 < all.length) {
            const nextT = (all[i+1].innerText || '').trim();
            if (nextT && nextT.length > 10 && nextT.startsWith('GOCSPX-')) {
                return nextT;
            }
        }
    }
    // Search raw body text for GOCSPX-
    const body = document.body ? document.body.innerText : '';
    const match = body.match(/GOCSPX-[a-zA-Z0-9_\-]+/);
    if (match) return match[0];
    return null;
})()
""")

if secret_val:
    print(f"Successfully located Client Secret (starts with: {secret_val[:7]}..., length: {len(secret_val)})")
    # Read existing .env
    with open(".env", "r") as f:
        env_content = f.read()

    if "GOOGLE_CLIENT_SECRET=" in env_content:
        env_content = re.sub(r"GOOGLE_CLIENT_SECRET=.*", f"GOOGLE_CLIENT_SECRET={secret_val}", env_content)
    else:
        env_content += f"\nGOOGLE_CLIENT_SECRET={secret_val}\n"

    with open(".env", "w") as f:
        f.write(env_content)
    print("Updated .env with GOOGLE_CLIENT_SECRET without logging secrets to stdout.")
else:
    print("Could not find GOCSPX- secret value automatically.")

cdp.close()

