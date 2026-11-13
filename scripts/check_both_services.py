import time
from chrome_cdp_client import ChromeCDPClient

cdp = ChromeCDPClient()
targets = cdp.get_targets()

gcloud_target = None
for t in targets:
    if 'console.cloud.google.com' in t.get('url', ''):
        gcloud_target = t.get('targetId')
        break

print("=== 1. GOOGLE CLOUD CONSOLE STATUS ===")
if gcloud_target:
    print(f"Found Google Cloud tab: {gcloud_target}")
    session_id = cdp.attach_to_target(gcloud_target)
    url = cdp.evaluate(session_id, "window.location.href")
    title = cdp.evaluate(session_id, "document.title")
    print(f"URL: {url}")
    print(f"Title: {title}")
    
    # Check current project or banner text
    proj_btn = cdp.evaluate(session_id, """
    (() => {
        const btn = document.querySelector('button[aria-label*="project"], [data-tracker-id*="project"], .cfc-switcher-button');
        return btn ? btn.innerText : 'No project switcher found';
    })()
    """)
    print(f"Project Switcher Text: {proj_btn}")

print("\n=== 2. CLOUDFLARE DASHBOARD STATUS ===")
cf_tab = cdp.create_tab("about:blank")
cdp.send_command("Target.activateTarget", {"targetId": cf_tab})
cf_session = cdp.attach_to_target(cf_tab)
cdp.send_command("Page.enable", session_id=cf_session)
print("Navigating to https://dash.cloudflare.com/ ...")
cdp.navigate(cf_session, "https://dash.cloudflare.com/")

time.sleep(8)
cf_url = cdp.evaluate(cf_session, "window.location.href")
cf_title = cdp.evaluate(cf_session, "document.title")
cf_body = cdp.evaluate(cf_session, "document.body ? document.body.innerText.substring(0, 500) : ''")
print(f"Cloudflare URL: {cf_url}")
print(f"Cloudflare Title: {cf_title}")
print(f"Cloudflare Body snippet:\n{cf_body}")

cdp.close_tab(cf_tab)
cdp.close()

