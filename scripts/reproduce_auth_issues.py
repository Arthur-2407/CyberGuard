import subprocess
import time
import os
import psutil
from playwright.sync_api import sync_playwright

def test_live_app():
    exe = os.path.abspath('dist/windows/win-unpacked/CyberGuard.exe')
    port = 9222
    cmd = [exe, f'--remote-debugging-port={port}']
    print(f"Launching {exe} with remote debugging on {port}...")

    # Clear ELECTRON_RUN_AS_NODE from environment!
    env = os.environ.copy()
    env.pop("ELECTRON_RUN_AS_NODE", None)

    # Clean old DevToolsActivePort
    app_data = os.path.expandvars(r"%APPDATA%\CyberGuard\DevToolsActivePort")
    if os.path.exists(app_data):
        try:
            os.remove(app_data)
        except Exception:
            pass

    proc = subprocess.Popen(cmd, env=env)
    
    # Read DevToolsActivePort from AppData
    app_data = os.path.expandvars(r"%APPDATA%\CyberGuard\DevToolsActivePort")
    ws_url = None
    for _ in range(20):
        if os.path.exists(app_data):
            try:
                with open(app_data, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f.readlines() if line.strip()]
                    if len(lines) >= 2:
                        p_val = lines[0]
                        guid = lines[1]
                        ws_url = f"ws://127.0.0.1:{p_val}{guid}"
                        print(f"Found active DevTools WS URL: {ws_url}")
                        break
            except Exception:
                pass
        time.sleep(0.5)

    if not ws_url:
        print("Could not find DevToolsActivePort!")
        return

    try:
        with sync_playwright() as p:
            print(f"Connecting to CDP via {ws_url}...")
            browser = p.chromium.connect_over_cdp(ws_url, timeout=10000)
            print("Connected! Contexts:", len(browser.contexts))
            page = None
            for ctx in browser.contexts:
                for pg in ctx.pages:
                    print("Found page:", pg.url, "Title:", pg.title())
                    if 'index.html' in pg.url or 'CyberGuard' in pg.title():
                        page = pg
                        break
                if page:
                    break
            
            if not page:
                print("Could not find CyberGuard page!")
                return
            
            print("Successfully found CyberGuard renderer page!")
            
            # Check top right Sign In button
            sign_in_btn = page.query_selector('#btn-header-sign-in')
            print("Header Sign In button visible:", sign_in_btn.is_visible() if sign_in_btn else False)
            
            # Click Header Sign In button
            if sign_in_btn and sign_in_btn.is_visible():
                print("Clicking Header Sign In button...")
                sign_in_btn.click()
                time.sleep(1)
            
            # Check modal
            modal = page.query_selector('#login-modal')
            print("Login modal visible:", modal.is_visible() if modal else False)
            
            # Check tabs
            tab_signin = page.query_selector('#tab-auth-signin')
            tab_reg = page.query_selector('#tab-auth-register')
            print("Sign In tab active:", 'active' in (tab_signin.get_attribute('class') or ''))
            print("Register tab active:", 'active' in (tab_reg.get_attribute('class') or ''))
            
            # Check Sign In inputs
            u_login = page.query_selector('#input-login-username')
            p_login = page.query_selector('#input-login-password')
            print("Login username placeholder:", u_login.get_attribute('placeholder') if u_login else None)
            print("Login username current value:", u_login.input_value() if u_login else None)
            print("Login password current value:", p_login.input_value() if p_login else None)
            
            # Try typing into login inputs
            print("Typing into login username...")
            u_login.fill("test_user_signin")
            print("Username after fill:", u_login.input_value())
            
            p_login.fill("test_password_signin")
            print("Password after fill:", p_login.input_value())
            
            # Check eye toggle
            eye_signin = page.query_selector('#btn-toggle-pwd-signin')
            print("Password type before toggle:", p_login.get_attribute('type'))
            if eye_signin:
                eye_signin.click()
                print("Password type after 1st toggle:", p_login.get_attribute('type'))
                eye_signin.click()
                print("Password type after 2nd toggle:", p_login.get_attribute('type'))
            
            # Switch to Create Account tab
            print("\nClicking Create Account tab...")
            if tab_reg:
                tab_reg.click()
                time.sleep(0.5)
            
            print("Sign In tab active:", 'active' in (tab_signin.get_attribute('class') or ''))
            print("Register tab active:", 'active' in (tab_reg.get_attribute('class') or ''))
            
            form_signin = page.query_selector('#auth-signin-form')
            form_reg = page.query_selector('#auth-register-form')
            print("Sign In form hidden:", 'hidden' in (form_signin.get_attribute('class') or ''))
            print("Register form hidden:", 'hidden' in (form_reg.get_attribute('class') or ''))
            
            # Check register inputs
            u_reg = page.query_selector('#input-reg-username')
            e_reg = page.query_selector('#input-reg-email')
            p_reg = page.query_selector('#input-reg-password')
            
            print("Register username visible:", u_reg.is_visible() if u_reg else False)
            print("Register email visible:", e_reg.is_visible() if e_reg else False)
            print("Register password visible:", p_reg.is_visible() if p_reg else False)
            
            print("Attempting to type into register username...")
            try:
                u_reg.click()
                u_reg.fill("new_user_123")
                print("Register username value:", u_reg.input_value())
            except Exception as ex:
                print("Error typing into register username:", ex)
                
            print("Attempting to type into register email...")
            try:
                e_reg.click()
                e_reg.fill("new_user@test.local")
                print("Register email value:", e_reg.input_value())
            except Exception as ex:
                print("Error typing into register email:", ex)
                
            print("Attempting to type into register password...")
            try:
                p_reg.click()
                p_reg.fill("SecurePass123!")
                print("Register password value:", p_reg.input_value())
            except Exception as ex:
                print("Error typing into register password:", ex)
                
            eye_reg = page.query_selector('#btn-toggle-pwd-reg')
            if eye_reg:
                eye_reg.click()
                print("Register password type after 1st toggle:", p_reg.get_attribute('type'))
                eye_reg.click()
                print("Register password type after 2nd toggle:", p_reg.get_attribute('type'))
                
            # Check if any admin credentials exist anywhere in DOM or localStorage or window
            eval_res = page.evaluate("""() => {
                return {
                    localStorage: { ...localStorage },
                    currentUser: window.AppState ? window.AppState.currentUser : 'undefined',
                    settingsProfileName: document.getElementById('profile-display-name') ? document.getElementById('profile-display-name').innerText : null,
                    settingsProfileEmail: document.getElementById('profile-display-email') ? document.getElementById('profile-display-email').innerText : null,
                    settingsProfileRole: document.getElementById('profile-display-role') ? document.getElementById('profile-display-role').innerText : null
                };
            }""")
            print("\nPage Evaluation Results:", eval_res)
            
            browser.close()
    finally:
        print("\nTerminating CyberGuard processes...")
        try:
            p = psutil.Process(proc.pid)
            for c in p.children(recursive=True):
                c.kill()
            p.kill()
        except Exception:
            pass

if __name__ == '__main__':
    test_live_app()
