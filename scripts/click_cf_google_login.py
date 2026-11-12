import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
cf_tab = cdp.create_tab("about:blank")
cdp.send_command("Target.activateTarget", {"targetId": cf_tab})
session_id = cdp.attach_to_target(cf_tab)
cdp.send_command("Page.enable", session_id=session_id)

cdp.navigate(session_id, "https://dash.cloudflare.com/login")
time.sleep(6)

print("Clicking Google sign-in button on Cloudflare...")
btn_res = cdp.evaluate(session_id, """
(() => {
    const btns = Array.from(document.querySelectorAll('button, a'));
    const gBtn = btns.find(b => b.innerText.trim().toLowerCase() === 'google' || (b.getAttribute('aria-label') || '').toLowerCase().includes('google'));
    if (gBtn) {
        gBtn.click();
        return "Clicked Google button";
    }
    return "Google button not found in: " + btns.map(b => b.innerText).filter(Boolean).slice(0, 10).join(', ');
})()
""")
print(f"Action: {btn_res}")

time.sleep(6)
url = cdp.evaluate(session_id, "window.location.href")
print(f"URL after clicking Google: {url}")

if "accounts.google.com" in url:
    print("On Google OAuth screen. Selecting cyberguardadmin@gmail.com account...")
    sel_res = cdp.evaluate(session_id, """
    (() => {
        const divs = Array.from(document.querySelectorAll('div, li, button'));
        const acc = divs.find(d => d.innerText && d.innerText.includes('cyberguardadmin@gmail.com'));
        if (acc) {
            acc.click();
            return "Clicked cyberguardadmin@gmail.com";
        }
        return "Account card not found";
    })()
    """)
    print(f"Account selection: {sel_res}")
    time.sleep(12)

final_url = cdp.evaluate(session_id, "window.location.href")
final_title = cdp.evaluate(session_id, "document.title")
final_body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"\nFinal URL: {final_url}")
print(f"Final Title: {final_title}")
print(f"Final Body:\n{final_body[:1000]}")

cdp.close_tab(cf_tab)
cdp.close()

