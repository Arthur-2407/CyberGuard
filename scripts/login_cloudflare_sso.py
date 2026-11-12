import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
cf_tab = cdp.create_tab("about:blank")
cdp.send_command("Target.activateTarget", {"targetId": cf_tab})
session_id = cdp.attach_to_target(cf_tab)
cdp.send_command("Page.enable", session_id=session_id)

print("Navigating to https://dash.cloudflare.com/ ...")
cdp.navigate(session_id, "https://dash.cloudflare.com/")

time.sleep(6)
url = cdp.evaluate(session_id, "window.location.href")
print(f"Initial URL: {url}")

if "accountchooser" in url or "signin" in url:
    print("Detected Google Account Chooser for Cloudflare SSO. Clicking cyberguardadmin@gmail.com...")
    click_res = cdp.evaluate(session_id, """
    (() => {
        const divs = Array.from(document.querySelectorAll('div, li, button'));
        const acc = divs.find(d => d.innerText && d.innerText.includes('cyberguardadmin@gmail.com'));
        if (acc) {
            acc.click();
            return "Clicked cyberguardadmin@gmail.com account card";
        }
        return "Account card not found";
    })()
    """)
    print(f"Click action: {click_res}")
    print("Waiting 12 seconds for Cloudflare dashboard redirect...")
    time.sleep(12)

cf_url = cdp.evaluate(session_id, "window.location.href")
cf_title = cdp.evaluate(session_id, "document.title")
cf_body = cdp.evaluate(session_id, "document.body ? document.body.innerText.substring(0, 1500) : ''")

print(f"\nFinal Cloudflare URL: {cf_url}")
print(f"Final Cloudflare Title: {cf_title}")
print(f"Body snippet:\n{cf_body[:1000]}")

cdp.close_tab(cf_tab)
cdp.close()

