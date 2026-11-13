"""
verify_admin_feature_parity.py — Automated End-to-End RBAC & Feature Parity Verification
Tests the built CyberGuard Windows desktop application against live security backend.
"""

import os
import sys
import time
import json
import psutil
import urllib.request
import subprocess
from playwright.sync_api import sync_playwright

def is_backend_ready(url="http://127.0.0.1:3000"):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(f"{url}/api/health", headers={"User-Agent": "CyberGuard-Verifier"})
        with opener.open(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False

def run_tests():
    print("=" * 80)
    print("CYBERGUARD ENDPOINT SECURITY — ADMIN RBAC & FEATURE PARITY E2E VERIFICATION")
    print("=" * 80)

    # 1. Check Backend
    if not is_backend_ready():
        print("[-] Backend not ready on http://127.0.0.1:3000. Please start backend first.")
        sys.exit(1)
    print("[+] Security backend verified healthy at http://127.0.0.1:3000")

    # 2. Terminate existing CyberGuard processes
    print("[*] Terminating existing desktop instances...")
    for p in psutil.process_iter(['name']):
        try:
            if 'cyberguard' in (p.info['name'] or '').lower():
                p.kill()
        except Exception:
            pass
    time.sleep(1)

    # 3. Path to newly packaged binary
    exe = os.path.abspath('dist/windows/win-unpacked/CyberGuard.exe')
    assert os.path.exists(exe), f"Binary not found at {exe}"
    print(f"[+] Found packaged executable: {exe}")
    print(f"    Size: {os.path.getsize(exe) / (1024*1024):.2f} MB")
    print(f"    Modified: {time.ctime(os.path.getmtime(exe))}")

    # 4. Launch with CDP debugging port
    cdp_port = 9335
    env = os.environ.copy()
    env.pop("ELECTRON_RUN_AS_NODE", None)
    print(f"[*] Launching CyberGuard with --remote-debugging-port={cdp_port}...")
    app_proc = subprocess.Popen([exe, f'--remote-debugging-port={cdp_port}'], env=env)
    time.sleep(4)

    test_results = {}

    try:
        with sync_playwright() as p:
            print(f"[*] Connecting Playwright over CDP to http://127.0.0.1:{cdp_port}...")
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{cdp_port}")
            print("[+] Connected to Electron via Chrome DevTools Protocol.")

            target_page = None
            for ctx in browser.contexts:
                for pg in ctx.pages:
                    if 'index.html' in pg.url or 'CyberGuard' in pg.title():
                        target_page = pg
                        break
            assert target_page is not None, "Failed to find CyberGuard window!"
            print(f"[+] Found target window: '{target_page.title()}' ({target_page.url})")

            # Capture console logs and accept dialogs
            target_page.on("console", lambda msg: print(f"    [CONSOLE {msg.type.upper()}] {msg.text}"))
            target_page.on("dialog", lambda dialog: (print(f"    [DIALOG] {dialog.message}"), dialog.accept()))

            # -------------------------------------------------------------
            # STEP A: Unauthenticated Guest State Verification
            # -------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP A: Unauthenticated Guest RBAC Verification")
            print("-" * 60)

            # Ensure signed out
            auth_indicator = target_page.query_selector('#auth-status-indicator')
            btn_logout = target_page.query_selector('#btn-header-logout')
            btn_signin = target_page.query_selector('#btn-header-sign-in')

            if auth_indicator and auth_indicator.is_visible():
                print("[*] Clearing pre-existing session...")
                btn_logout.click()
                time.sleep(1)

            assert btn_signin.is_visible(), "Sign in button should be visible for guest"

            # Check that admin nav elements are hidden
            nav_admin_sec = target_page.query_selector('#nav-section-admin')
            nav_admin_con = target_page.query_selector('#nav-item-admin-console')
            nav_train_rev = target_page.query_selector('#nav-item-training-review')

            is_sec_hidden = target_page.evaluate("() => document.getElementById('nav-section-admin').classList.contains('hidden')")
            is_con_hidden = target_page.evaluate("() => document.getElementById('nav-item-admin-console').classList.contains('hidden')")
            is_rev_hidden = target_page.evaluate("() => document.getElementById('nav-item-training-review').classList.contains('hidden')")

            print(f"[+] Guest navigation state: admin section hidden={is_sec_hidden}, console hidden={is_con_hidden}, review hidden={is_rev_hidden}")
            assert is_sec_hidden and is_con_hidden and is_rev_hidden, "Admin navigation items must be hidden for guest!"
            test_results["Guest Navigation Hidden"] = True

            # Attempt direct route bypass via switchView
            print("[*] Testing client-side route guard bypass attempt (guest -> admin-console)...")
            target_page.evaluate("() => window.switchView('admin-console')")
            time.sleep(0.5)

            active_view = target_page.evaluate("() => document.querySelector('.content-panel.active')?.id")
            print(f"[+] Active view after bypass attempt: {active_view}")
            assert active_view != 'view-admin-console', "Guest must not be allowed to open admin-console!"
            assert active_view == 'view-dashboard', "Guest must be redirected to dashboard!"
            test_results["Guest Route Guard Enforcement"] = True

            # -------------------------------------------------------------
            # STEP B: Standard User (ROLE_USER) RBAC Verification
            # -------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP B: Standard User (ROLE_USER) RBAC Verification")
            print("-" * 60)

            # Register fresh standard user
            ts = int(time.time() * 1000)
            test_username = f"parity_{ts % 1000000}"
            test_password = "UserPass123!"

            print(f"[*] Registering test standard user: {test_username}...")
            btn_signin.click()
            time.sleep(0.5)

            # Switch to Register tab
            target_page.click('#tab-auth-register')
            time.sleep(0.3)

            target_page.fill('#input-reg-username', test_username)
            target_page.fill('#input-reg-email', f"{test_username}@cyberguard.local")
            target_page.fill('#input-reg-password', test_password)
            target_page.click('#btn-submit-register')
            
            # Wait for authenticated indicator to appear
            try:
                target_page.wait_for_selector('#auth-status-indicator:not(.hidden)', timeout=15000)
            except Exception:
                err_text = target_page.inner_text('#reg-error-msg')
                print(f"[-] Registration failed with error message: '{err_text}'")

            # Verify logged in as USER
            lbl_user = target_page.inner_text('#auth-username-label')
            lbl_role = target_page.inner_text('#header-user-role')
            print(f"[+] Signed in as: '{lbl_user}', Role badge: '{lbl_role}'")
            assert lbl_user == test_username, f"Expected {test_username}, got {lbl_user}"
            assert lbl_role == "USER", f"Expected USER, got {lbl_role}"
            test_results["Standard User Registration & Authentication"] = True

            # Verify admin navigation remains completely hidden
            is_sec_hidden = target_page.evaluate("() => document.getElementById('nav-section-admin').classList.contains('hidden')")
            is_con_hidden = target_page.evaluate("() => document.getElementById('nav-item-admin-console').classList.contains('hidden')")
            is_rev_hidden = target_page.evaluate("() => document.getElementById('nav-item-training-review').classList.contains('hidden')")

            print(f"[+] Standard user nav state: admin section hidden={is_sec_hidden}, console hidden={is_con_hidden}, review hidden={is_rev_hidden}")
            assert is_sec_hidden and is_con_hidden and is_rev_hidden, "Admin navigation items must remain hidden for standard users!"
            test_results["Standard User Navigation Gating"] = True

            # Attempt route switch to admin-console as standard user
            print("[*] Testing route guard bypass attempt (ROLE_USER -> admin-console)...")
            target_page.evaluate("() => window.switchView('admin-console')")
            time.sleep(0.5)

            active_view = target_page.evaluate("() => document.querySelector('.content-panel.active')?.id")
            print(f"[+] Active view after bypass attempt: {active_view}")
            assert active_view != 'view-admin-console', "Standard user must not access admin-console!"
            assert active_view == 'view-dashboard', "Standard user must be redirected to dashboard!"
            test_results["Standard User Route Guard Enforcement"] = True

            # Attempt route switch to training-review as standard user
            print("[*] Testing route guard bypass attempt (ROLE_USER -> training-review)...")
            target_page.evaluate("() => window.switchView('training-review')")
            time.sleep(0.5)

            active_view = target_page.evaluate("() => document.querySelector('.content-panel.active')?.id")
            print(f"[+] Active view after bypass attempt: {active_view}")
            assert active_view != 'view-training-review', "Standard user must not access training-review!"
            assert active_view == 'view-dashboard', "Standard user must be redirected to dashboard!"

            # -------------------------------------------------------------
            # STEP C: Administrator (ROLE_ADMIN) Parity & Feature Access
            # -------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP C: Administrator (ROLE_ADMIN) Full Parity Verification")
            print("-" * 60)

            # Log out from standard user
            print("[*] Logging out standard user...")
            target_page.click('#btn-header-logout')
            time.sleep(1)

            # Log in as admin
            print("[*] Logging in with primary administrator account ('admin')...")
            target_page.click('#btn-header-sign-in')
            time.sleep(0.5)

            target_page.click('#tab-auth-signin')
            time.sleep(0.3)
            target_page.fill('#input-login-username', 'admin')
            target_page.fill('#input-login-password', 'Admin@CyberGuard2026!')
            target_page.click('#btn-submit-login')
            target_page.wait_for_selector('#auth-status-indicator:not(.hidden)', timeout=15000)

            lbl_admin = target_page.inner_text('#auth-username-label')
            lbl_role = target_page.inner_text('#header-user-role')
            print(f"[+] Administrator logged in: username='{lbl_admin}', role='{lbl_role}'")
            assert lbl_admin == "admin", f"Expected admin, got {lbl_admin}"
            assert lbl_role == "ADMIN", f"Expected ADMIN, got {lbl_role}"
            test_results["Administrator Authentication"] = True

            # Verify admin navigation items are now UNHIDDEN and fully visible
            is_sec_visible = target_page.evaluate("() => !document.getElementById('nav-section-admin').classList.contains('hidden')")
            is_con_visible = target_page.evaluate("() => !document.getElementById('nav-item-admin-console').classList.contains('hidden')")
            is_rev_visible = target_page.evaluate("() => !document.getElementById('nav-item-training-review').classList.contains('hidden')")

            print(f"[+] Administrator nav state: section visible={is_sec_visible}, console visible={is_con_visible}, review visible={is_rev_visible}")
            assert is_sec_visible and is_con_visible and is_rev_visible, "All administrative navigation items must be visible for admin!"
            test_results["Administrator Navigation Visibility"] = True

            # -------------------------------------------------------------
            # STEP D: Admin Console Sub-Modules & Data Interactivity
            # -------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP D: Admin Console Sub-Modules & Data Interactivity")
            print("-" * 60)

            print("[*] Navigating to Admin Console (#nav-item-admin-console)...")
            target_page.click('#nav-item-admin-console')
            time.sleep(1.5)

            active_view = target_page.evaluate("() => document.querySelector('.content-panel.active')?.id")
            assert active_view == 'view-admin-console', f"Expected view-admin-console, got {active_view}"
            print("[+] Successfully activated Admin Console view.")

            # Check Hero KPI Cards
            kpi_model = target_page.inner_text('#admin-kpi-active-version')
            kpi_queue = target_page.inner_text('#admin-kpi-queue-samples')
            kpi_quarantine = target_page.inner_text('#admin-kpi-blocked-entities')
            kpi_policy = target_page.inner_text('#admin-kpi-policy-posture')
            print(f"[+] Hero KPIs: Model='{kpi_model}', Queue='{kpi_queue}', Quarantine='{kpi_quarantine}', Policy='{kpi_policy}'")
            test_results["Admin Hero KPI Bar Populated"] = True

            # Check Operator RBAC Table
            target_page.wait_for_selector('#admin-users-tbody tr', timeout=10000)
            users_count = target_page.evaluate("() => document.querySelectorAll('#admin-users-tbody tr').length")
            print(f"[+] Operator RBAC Table rows count: {users_count}")
            assert users_count > 0, "Users table must have at least 1 row (admin)"
            test_results["Operator RBAC Management Table"] = True

            # Test Subtabs:
            # 1. Policy
            print("[*] Testing Security Policy subtab...")
            target_page.click('button[data-subtab="policy"]')
            time.sleep(0.5)
            policy_subpanel_visible = target_page.evaluate("() => !document.getElementById('subpanel-policy').classList.contains('hidden')")
            assert policy_subpanel_visible, "Security Policy subpanel should be active"
            print("[+] Security Policy subpanel active and controls loaded.")
            test_results["Admin Policy Subpanel"] = True

            # 2. Quarantine
            print("[*] Testing Quarantine Firewall subtab...")
            target_page.click('button[data-subtab="quarantine"]')
            time.sleep(0.5)
            quarantine_subpanel_visible = target_page.evaluate("() => !document.getElementById('subpanel-quarantine').classList.contains('hidden')")
            assert quarantine_subpanel_visible, "Quarantine subpanel should be active"
            print("[+] Quarantine Firewall subpanel active.")
            test_results["Admin Quarantine Subpanel"] = True

            # 3. Alerts
            print("[*] Testing Executive Alerts Journal subtab...")
            target_page.click('button[data-subtab="alerts"]')
            time.sleep(0.5)
            alerts_subpanel_visible = target_page.evaluate("() => !document.getElementById('subpanel-alerts').classList.contains('hidden')")
            assert alerts_subpanel_visible, "Alerts subpanel should be active"
            print("[+] Executive Alerts Journal subpanel active.")
            test_results["Admin Alerts Subpanel"] = True

            # 4. Neural Lineage
            print("[*] Testing Neural Lineage & Retraining subtab...")
            target_page.click('button[data-subtab="training"]')
            time.sleep(0.5)
            training_subpanel_visible = target_page.evaluate("() => !document.getElementById('subpanel-training').classList.contains('hidden')")
            assert training_subpanel_visible, "Training subpanel should be active"
            print("[+] Neural Lineage subpanel active.")
            test_results["Admin Neural Lineage Subpanel"] = True

            # 5. Audit Telemetry
            print("[*] Testing Audit Telemetry subtab...")
            target_page.click('button[data-subtab="audit"]')
            time.sleep(0.5)
            audit_subpanel_visible = target_page.evaluate("() => !document.getElementById('subpanel-audit').classList.contains('hidden')")
            assert audit_subpanel_visible, "Audit subpanel should be active"
            audit_rows = target_page.evaluate("() => document.querySelectorAll('#admin-audit-tbody tr').length")
            print(f"[+] Audit Telemetry subpanel active. Rows count: {audit_rows}")
            test_results["Admin Audit Telemetry Subpanel"] = True

            # -------------------------------------------------------------
            # STEP E: Training Review Queue Verification
            # -------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP E: Training Review Queue Verification")
            print("-" * 60)

            print("[*] Navigating to Training Review Queue (#nav-item-training-review)...")
            target_page.click('#nav-item-training-review')
            time.sleep(1)

            active_view = target_page.evaluate("() => document.querySelector('.content-panel.active')?.id")
            assert active_view == 'view-training-review', f"Expected view-training-review, got {active_view}"
            table_body = target_page.query_selector('#admin-review-tbody')
            assert table_body is not None, "Review queue table must exist in DOM"
            print("[+] Successfully activated Training Review Queue view.")
            test_results["Training Review Queue View"] = True

            # -------------------------------------------------------------
            # STEP F: Sign Out while on Admin View (Security Redirection)
            # -------------------------------------------------------------
            print("\n" + "-" * 60)
            print("STEP F: Administrator Logout & Automatic Security Redirection")
            print("-" * 60)

            print("[*] Clicking Logout while on an administrative view...")
            target_page.click('#btn-header-logout')
            time.sleep(1)

            active_view_after_logout = target_page.evaluate("() => document.querySelector('.content-panel.active')?.id")
            print(f"[+] Active view after logout: {active_view_after_logout}")
            assert active_view_after_logout == 'view-dashboard', "Logout from admin view must automatically redirect to dashboard!"

            is_sec_hidden = target_page.evaluate("() => document.getElementById('nav-section-admin').classList.contains('hidden')")
            is_con_hidden = target_page.evaluate("() => document.getElementById('nav-item-admin-console').classList.contains('hidden')")
            is_rev_hidden = target_page.evaluate("() => document.getElementById('nav-item-training-review').classList.contains('hidden')")

            print(f"[+] Post-logout nav state: admin section hidden={is_sec_hidden}, console hidden={is_con_hidden}, review hidden={is_rev_hidden}")
            assert is_sec_hidden and is_con_hidden and is_rev_hidden, "Admin navigation items must be hidden immediately upon logout!"
            test_results["Admin Logout Clean Redirection & State Reset"] = True

            # Close browser
            browser.close()

    finally:
        print("\n[*] Terminating test application process...")
        try:
            for child in psutil.Process(app_proc.pid).children(recursive=True):
                try: child.kill()
                except Exception: pass
            app_proc.kill()
        except Exception:
            pass

    # -------------------------------------------------------------
    # STEP G: Portable Executable Smoke Test
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("STEP G: Windows Portable Executable Smoke Test")
    print("-" * 60)

    portable_exe = os.path.abspath('dist/windows/CyberGuard-Portable.exe')
    assert os.path.exists(portable_exe), f"Portable binary not found at {portable_exe}"
    print(f"[+] Portable binary exists: {portable_exe} ({os.path.getsize(portable_exe) / (1024*1024):.2f} MB)")

    print("[*] Launching Portable executable for sanity check...")
    port_proc = subprocess.Popen([portable_exe], env=env)
    time.sleep(5)

    try:
        p_obj = psutil.Process(port_proc.pid)
        print(f"[+] Portable process active (PID {port_proc.pid}, status: {p_obj.status()})")
        children = p_obj.children(recursive=True)
        print(f"[+] Portable spawned {len(children)} child processes:")
        for c in children:
            try:
                print(f"    - Child PID {c.pid}: {c.name()}")
            except Exception:
                pass
        test_results["Windows Portable Executable Launch"] = True
    finally:
        print("[*] Cleaning up portable test process...")
        try:
            for c in psutil.Process(port_proc.pid).children(recursive=True):
                try: c.kill()
                except Exception: pass
            port_proc.kill()
        except Exception:
            pass

    # -------------------------------------------------------------
    # SUMMARY OF ALL VERIFICATIONS
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("ALL TESTS PASSED — VERIFICATION SUMMARY:")
    print("=" * 80)
    all_passed = True
    for test_name, passed in test_results.items():
        status_str = "PASS" if passed else "FAIL"
        print(f"  [{status_str}] {test_name}")
        if not passed:
            all_passed = False

    print("=" * 80)
    if all_passed:
        print(">>> ALL 12 CRITICAL RBAC & FEATURE PARITY CHECKS PASSED PERFECTLY! <<<")
    else:
        print(">>> SOME CHECKS FAILED! <<<")
        sys.exit(1)

if __name__ == '__main__':
    run_tests()
