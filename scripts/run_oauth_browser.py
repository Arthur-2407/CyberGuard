import subprocess
import time
import json
import re
from chrome_cdp_client import ChromeCDPClient

print("Starting OAuth loopback server...")
proc = subprocess.Popen(["node", "scripts/execute_real_oauth.js"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

auth_url = None
port = None

# Read lines until we see AUTH_URL
for _ in range(20):
    line = proc.stdout.readline()
    if not line:
        time.sleep(0.5)
        continue
    print("Node output:", line.strip())
    if line.startswith("AUTH_URL:"):
        auth_url = line.strip().split("AUTH_URL:")[1]
    if line.startswith("AUTH_SERVER_LISTENING:"):
        port = line.strip().split("AUTH_SERVER_LISTENING:")[1]
    if auth_url and port:
        break

if not auth_url:
    print("Failed to get AUTH_URL")
    proc.kill()
    exit(1)

print(f"\nCaptured Auth URL on port {port}:\n{auth_url}\n")

# Connect to Chrome via CDP
cdp = ChromeCDPClient()
print("Opening new tab in Chrome with Auth URL...")
tab_id = cdp.create_tab(auth_url)
print(f"Tab created: {tab_id}")

session_id = cdp.attach_to_target(tab_id)
cdp.send_command("Page.enable", session_id=session_id)

time.sleep(5)

# Inspect current URL and title in Chrome
for i in range(12):
    url = cdp.evaluate(session_id, "window.location.href")
    title = cdp.evaluate(session_id, "document.title")
    print(f"[{i*2}s] Page URL: {url}")
    print(f"[{i*2}s] Page Title: {title}")

    if "127.0.0.1" in str(url) and "oauth2callback" in str(url):
        print("Redirect to loopback detected!")
        break

    # Inspect page body and clickable elements
    info = cdp.evaluate(session_id, """
    (() => {
        const text = document.body ? document.body.innerText : '';
        const buttons = Array.from(document.querySelectorAll('button, [role="button"], a, input[type="submit"]')).map(b => ({
            tag: b.tagName,
            text: (b.innerText || b.value || '').trim(),
            id: b.id,
            ariaLabel: b.getAttribute('aria-label')
        })).filter(b => b.text.length > 0);
        return { text: text.substring(0, 400), buttons: buttons.slice(0, 15) };
    })()
    """)

    print(f"Snippet: {info.get('text', '')[:200] if info else 'None'}")
    btns = info.get('buttons', []) if info else []
    for b in btns:
        print(f" - Button: '{b.get('text')}' (id={b.get('id')})")

    # If account selector is visible, click cyberguardadmin@gmail.com
    action_taken = cdp.evaluate(session_id, """
    (() => {
        // Look for account with cyberguardadmin@gmail.com
        const allElements = Array.from(document.querySelectorAll('*'));
        const accountEl = allElements.find(el => (el.innerText || '').includes('cyberguardadmin@gmail.com') && el.closest('[role="link"], li, div[data-identifier]'));
        if (accountEl) {
            const clickable = accountEl.closest('[role="link"], li, div[data-identifier]') || accountEl;
            clickable.click();
            return 'Clicked account: cyberguardadmin@gmail.com';
        }

        // Check any unselected permission checkboxes (e.g. "View your email messages and settings")
        const checkboxes = Array.from(document.querySelectorAll('input[type="checkbox"], [role="checkbox"]'));
        for (const cb of checkboxes) {
            const isChecked = cb.checked || cb.getAttribute('aria-checked') === 'true';
            if (!isChecked) {
                cb.click();
            }
        }

        // Look for "Continue" or "Allow" button
        const continueBtn = Array.from(document.querySelectorAll('button, [role="button"]')).find(b => {
            const t = (b.innerText || '').toLowerCase();
            return t === 'continue' || t === 'allow' || t === 'select all' || t.includes('continue');
        });
        if (continueBtn) {
            continueBtn.click();
            return 'Clicked continue/allow: ' + continueBtn.innerText;
        }

        return 'No action taken';
    })()
    """)
    print("Action taken:", action_taken)

    time.sleep(3)

# Wait for node process to finish
try:
    stdout, stderr = proc.communicate(timeout=25)
    print("\n=== Node Process Output ===")
    print(stdout)
    if stderr:
        print("STDERR:", stderr)
except Exception as e:
    print("Process wait exception:", e)
    proc.kill()

cdp.close_tab(tab_id)
cdp.close()
