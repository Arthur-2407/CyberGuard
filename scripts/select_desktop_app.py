import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()
gcloud_page = next((t['targetId'] for t in targets if t.get('type') == 'page' and 'console.cloud.google.com' in t.get('url', '')), None)

session_id = cdp.attach_to_target(gcloud_page)
cdp.send_command("Page.enable", session_id=session_id)

print("Opening Application type dropdown...")
cdp.evaluate(session_id, """
(() => {
    const sel = document.querySelector('cfc-select, [role="combobox"]');
    if (sel) sel.click();
})()
""")

time.sleep(2)
opts = cdp.evaluate(session_id, """
Array.from(document.querySelectorAll('mat-option, [role="option"]')).map(el => el.innerText.trim())
""")
print(f"Dropdown options: {opts}")

# Click Desktop app
click_res = cdp.evaluate(session_id, """
(() => {
    const opts = Array.from(document.querySelectorAll('mat-option, [role="option"]'));
    const desktopOpt = opts.find(o => o.innerText.toLowerCase().includes('desktop'));
    if (desktopOpt) {
        desktopOpt.click();
        return "Clicked Desktop app option";
    }
    return "Desktop option not found in " + opts.join(', ');
})()
""")
print(f"Click result: {click_res}")

time.sleep(2)

# Check for Name input and Create button
form_inputs = cdp.evaluate(session_id, """
Array.from(document.querySelectorAll('input, button')).map(el => ({
    tag: el.tagName,
    type: el.type,
    id: el.id,
    placeholder: el.placeholder,
    value: el.value,
    text: el.innerText ? el.innerText.trim() : ''
})).filter(e => e.id || e.placeholder || e.text)
""")
print("Form inputs after selecting Desktop:")
for fi in form_inputs:
    print(fi)

cdp.close()

