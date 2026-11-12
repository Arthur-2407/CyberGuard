import subprocess
import time
import os
import psutil
from playwright.sync_api import sync_playwright

def run_test():
    exe = os.path.abspath('dist/windows/win-unpacked/CyberGuard.exe')
    port = 9333
    cmd = [exe, f'--remote-debugging-port={port}']
    print(f"Launching {exe} on port {port}...")

    env = os.environ.copy()
    env.pop("ELECTRON_RUN_AS_NODE", None)

    proc = subprocess.Popen(cmd, env=env)
    time.sleep(3)

    try:
        with sync_playwright() as p:
            print(f"Connecting to CDP at http://127.0.0.1:{port}...")
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
            print("Connected successfully!")
            
            pages = []
            for ctx in browser.contexts:
                pages.extend(ctx.pages)
            print(f"Total pages: {len(pages)}")
            for page in pages:
                print(f"URL: {page.url}, Title: {page.title()}")
            
            # Select the main CyberGuard page
            target_page = None
            for page in pages:
                if 'index.html' in page.url or 'CyberGuard' in page.title():
                    target_page = page
                    break
            
            if not target_page:
                print("Could not find CyberGuard window!")
                return
            
            print("Target page found:", target_page.title())
            
            # 1. Inspect initial state
            btn_signin = target_page.query_selector('#btn-header-sign-in')
            btn_logout = target_page.query_selector('#btn-header-logout')
            auth_indicator = target_page.query_selector('#auth-status-indicator')
            
            print("Header Sign In button visible:", btn_signin.is_visible() if btn_signin else False)
            print("Auth indicator visible:", auth_indicator.is_visible() if auth_indicator else False)
            
            # If already logged in, let's log out first to match the user's unauthenticated screenshot!
            if auth_indicator and auth_indicator.is_visible():
                print("App is currently signed in. Clicking Header Log Out to return to guest state...")
                btn_logout.click()
                time.sleep(1)
                print("Header Sign In button visible after logout:", btn_signin.is_visible())
            
            # 2. Click Header Sign In
            print("Clicking Header Sign In...")
            btn_signin.click()
            time.sleep(1)
            
            modal = target_page.query_selector('#login-modal')
            print("Login modal visible:", modal.is_visible() if modal else False)
            
            # 3. Test Sign In inputs
            u_in = target_page.query_selector('#input-login-username')
            p_in = target_page.query_selector('#input-login-password')
            
            print("Username placeholder:", u_in.get_attribute('placeholder'))
            print("Initial username value:", repr(u_in.input_value()))
            print("Initial password value:", repr(p_in.input_value()))
            
            print("Typing test username into sign-in...")
            u_in.click()
            u_in.type("testadmin")
            print("Username value after type:", repr(u_in.input_value()))
            
            print("Typing test password into sign-in...")
            p_in.click()
            p_in.type("MySecretPass123")
            print("Password value after type:", repr(p_in.input_value()))
            
            # Test eye toggle
            eye_btn = target_page.query_selector('#btn-toggle-pwd-signin')
            print("Password type before toggle:", p_in.get_attribute('type'))
            eye_btn.click()
            print("Password type after toggle:", p_in.get_attribute('type'))
            eye_btn.click()
            print("Password type after toggle back:", p_in.get_attribute('type'))
            
            # 4. Switch to Create Account tab
            tab_reg = target_page.query_selector('#tab-auth-register')
            print("\nClicking 'Create Account' tab...")
            tab_reg.click()
            time.sleep(0.5)
            
            tab_signin = target_page.query_selector('#tab-auth-signin')
            print("Sign In tab classes:", tab_signin.get_attribute('class'))
            print("Create Account tab classes:", tab_reg.get_attribute('class'))
            
            form_signin = target_page.query_selector('#auth-signin-form')
            form_reg = target_page.query_selector('#auth-register-form')
            print("Sign In form classes:", form_signin.get_attribute('class'))
            print("Create Account form classes:", form_reg.get_attribute('class'))
            
            # 5. Test Create Account inputs
            reg_u = target_page.query_selector('#input-reg-username')
            reg_e = target_page.query_selector('#input-reg-email')
            reg_p = target_page.query_selector('#input-reg-password')
            
            print("Reg username visible:", reg_u.is_visible())
            print("Reg email visible:", reg_e.is_visible())
            print("Reg password visible:", reg_p.is_visible())
            
            print("Typing into Reg username...")
            reg_u.click()
            reg_u.type("newoperator")
            print("Reg username value:", repr(reg_u.input_value()))
            
            print("Typing into Reg email...")
            reg_e.click()
            reg_e.type("operator@example.com")
            print("Reg email value:", repr(reg_e.input_value()))
            
            print("Typing into Reg password...")
            reg_p.click()
            reg_p.type("SecureP@ssw0rd!")
            print("Reg password value:", repr(reg_p.input_value()))
            
            # Test backspace / deletion
            reg_u.focus()
            target_page.keyboard.press("Backspace")
            target_page.keyboard.press("Backspace")
            print("Reg username after backspaces:", repr(reg_u.input_value()))
            target_page.keyboard.type("or")
            print("Reg username after retyping:", repr(reg_u.input_value()))
            
            # Test tab switching back and forth
            print("\nSwitching back to Sign In tab...")
            tab_signin.click()
            time.sleep(0.5)
            print("Sign In form classes:", form_signin.get_attribute('class'))
            print("Create Account form classes:", form_reg.get_attribute('class'))
            print("Sign In username value preserved:", repr(u_in.input_value()))
            print("Sign In password value preserved:", repr(p_in.input_value()))
            
            print("Switching to Create Account tab again...")
            tab_reg.click()
            time.sleep(0.5)
            print("Reg username value preserved:", repr(reg_u.input_value()))
            print("Reg email value preserved:", repr(reg_e.input_value()))
            print("Reg password value preserved:", repr(reg_p.input_value()))
            
            # Close modal
            btn_close = target_page.query_selector('#btn-close-login-modal')
            btn_close.click()
            time.sleep(0.5)
            print("Modal visible after close:", modal.is_visible())
            
            # Reopen modal
            btn_signin.click()
            time.sleep(0.5)
            print("Modal visible after reopen:", modal.is_visible())
            print("Active tab after reopen - Sign In active:", 'active' in (tab_signin.get_attribute('class') or ''))
            print("Active tab after reopen - Register active:", 'active' in (tab_reg.get_attribute('class') or ''))
            print("Sign In form visible after reopen:", not ('hidden' in (form_signin.get_attribute('class') or '')))
            print("Register form visible after reopen:", not ('hidden' in (form_reg.get_attribute('class') or '')))
            
            browser.close()
    finally:
        print("\nCleaning up process...")
        try:
            p_proc = psutil.Process(proc.pid)
            for c in p_proc.children(recursive=True):
                c.kill()
            p_proc.kill()
        except Exception as e:
            print("Cleanup error:", e)

if __name__ == '__main__':
    run_test()
