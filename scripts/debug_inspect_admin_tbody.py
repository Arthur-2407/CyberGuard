import subprocess
import os
import time
from playwright.sync_api import sync_playwright

exe = os.path.abspath('dist/windows/win-unpacked/CyberGuard.exe')
env = os.environ.copy()
for k in list(env.keys()):
    if 'ELECTRON' in k.upper():
        env.pop(k, None)

proc = subprocess.Popen([exe, '--remote-debugging-port=9333'], env=env)
time.sleep(3)

try:
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp('http://127.0.0.1:9333')
        pages = [pg for ctx in browser.contexts for pg in ctx.pages if 'index.html' in pg.url or 'CyberGuard' in pg.title()]
        page = pages[0]
        
        btn_signin = page.query_selector('#btn-header-sign-in')
        if btn_signin and btn_signin.is_visible():
            btn_signin.click()
            time.sleep(0.5)
            page.fill('#input-login-username', 'admin')
            page.fill('#input-login-password', 'Admin@CyberGuard2026!')
            page.click('#btn-submit-login')
            time.sleep(3)
        
        state_after_login = page.evaluate("() => ({ user: AppState.currentUser, activeView: AppState.activeView })")
        print("State after login:", state_after_login)
        
        page.on("dialog", lambda d: (print("DIALOG:", d.message), d.accept()))

        print("Switching to admin-console...")
        page.evaluate("switchView('admin-console')")
        time.sleep(3)
        u_tbody = page.query_selector('#admin-users-tbody')
        print('=== ADMIN USERS HTML ===\n', u_tbody.inner_html() if u_tbody else 'None')
        
        print("\nSwitching to training-review...")
        page.evaluate("switchView('training-review')")
        print("Calling loadReviewQueue directly...")
        res = page.evaluate("async () => { await loadReviewQueue(); return document.querySelector('#admin-review-tbody').innerHTML; }")
        print('=== TRAINING REVIEW HTML (DIRECT AWAIT) ===\n', res[:500] if res else 'None')
        browser.close()
finally:
    proc.kill()
