import sys; sys.path.append('scripts')
import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
target = next((t['targetId'] for t in cdp.get_targets() if 'console.cloud' in t.get('url', '')), None)
session_id = cdp.attach_to_target(target)
cdp.send_command('Page.enable', session_id=session_id)

res = cdp.evaluate(session_id, """
(() => {
    const sel = document.getElementById('_0rif_cfc-select-0') || document.querySelector('cfc-select');
    if (sel) {
        sel.click();
        return 'Clicked ' + sel.id;
    }
    return 'Not found';
})()
""")
print("Click select:", res)
time.sleep(2)

options = cdp.evaluate(session_id, """
(() => {
    return Array.from(document.querySelectorAll('mat-option, [role="option"], cfc-option, li')).map(el => ({
        tag: el.tagName,
        text: (el.innerText || '').trim()
    })).filter(el => el.text.length > 2);
})()
""")

print("Options displayed:")
for o in (options or []):
    print(" -", o)

# Click Desktop app
click_opt = cdp.evaluate(session_id, """
(() => {
    const opts = Array.from(document.querySelectorAll('mat-option, [role="option"], cfc-option, li'));
    const dOpt = opts.find(o => o.innerText.toLowerCase().includes('desktop'));
    if (dOpt) {
        dOpt.click();
        return 'Clicked: ' + dOpt.innerText;
    }
    return 'Desktop option not found';
})()
""")
print("Click option:", click_opt)

cdp.close()

