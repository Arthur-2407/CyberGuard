import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Filling OAuth branding wizard...")
res = cdp.evaluate(session_id, """
(() => {
    const logs = [];

    // Step 1: App Name
    const nameInput = document.querySelector('input[id*="mat-input-0"]') || document.querySelector('input[type="text"]');
    if (nameInput) {
        nameInput.value = "CyberGuard Email Security";
        nameInput.dispatchEvent(new Event('input', { bubbles: true }));
        nameInput.dispatchEvent(new Event('change', { bubbles: true }));
        logs.push("Set app name: CyberGuard Email Security");
    } else {
        logs.push("App name input not found");
    }

    // Step 1: User support email dropdown
    const select = document.querySelector('cfc-select, [role="combobox"]');
    if (select) {
        select.click();
        logs.push("Clicked select dropdown");
    }

    return logs.join("; ");
})()
""")
print(f"Initial actions: {res}")

time.sleep(2)
# Check options opened in the dropdown
options = cdp.evaluate(session_id, """
Array.from(document.querySelectorAll('mat-option, [role="option"]')).map(el => el.innerText.trim())
""")
print(f"Dropdown options: {options}")

# Click the option
sel_res = cdp.evaluate(session_id, """
(() => {
    const opts = Array.from(document.querySelectorAll('mat-option, [role="option"]'));
    const opt = opts.find(o => o.innerText.includes('cyberguardadmin@gmail.com')) || opts[0];
    if (opt) {
        opt.click();
        return "Selected option: " + opt.innerText;
    }
    return "No option found to select";
})()
""")
print(f"Select result: {sel_res}")

time.sleep(1)

# Step 2: Click Next or select External radio
step2_res = cdp.evaluate(session_id, """
(() => {
    const logs = [];
    const extRadio = document.querySelector('input[value="external"]') || document.getElementById('_0rif_mat-radio-1-input');
    if (extRadio) {
        extRadio.click();
        logs.push("Selected external radio");
    }

    // Developer email
    const emailInput = document.querySelector('input[aria-label*="email"], input[id*="chip-list-input"]');
    if (emailInput) {
        emailInput.value = "cyberguardadmin@gmail.com";
        emailInput.dispatchEvent(new Event('input', { bubbles: true }));
        emailInput.dispatchEvent(new Event('change', { bubbles: true }));
        // Simulate Enter key to commit the chip
        emailInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', keyCode: 13, bubbles: true }));
        logs.push("Entered developer contact email");
    }

    // Agreement checkbox
    const cb = document.querySelector('input[type="checkbox"]');
    if (cb && !cb.checked) {
        cb.click();
        logs.push("Checked agreement checkbox");
    }

    return logs.join("; ");
})()
""")
print(f"Step 2-3 actions: {step2_res}")

time.sleep(2)

# Check Create button state
btn_state = cdp.evaluate(session_id, """
(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const createBtn = btns.find(b => b.innerText.trim() === 'Create');
    if (createBtn) {
        return { disabled: createBtn.disabled, text: createBtn.innerText };
    }
    return "Create button not found";
})()
""")
print(f"Create button status: {btn_state}")

cdp.close()

