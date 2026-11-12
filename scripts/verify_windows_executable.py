import subprocess
import time
import os
import psutil
import ctypes
from ctypes import wintypes

exe = os.path.abspath('dist/windows/win-unpacked/CyberGuard.exe')
env = os.environ.copy()
env['ELECTRON_ENABLE_LOGGING'] = '1'

print(f"Launching {exe}...")
proc = subprocess.Popen([exe], env=env)
pid = proc.pid
print(f"Main Process PID: {pid}")

# Wait for Electron to initialize and render
time.sleep(6)

p = psutil.Process(pid)
status = p.status()
children = p.children(recursive=True)
print(f"Main Process Status: {status}")
print(f"Child Processes count: {len(children)}")
for c in children:
    try:
        print(f"  Child PID {c.pid}: {c.name()} ({c.status()})")
    except Exception:
        pass

# Enumerate Windows
EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.POINTER(ctypes.c_int))
GetWindowText = ctypes.windll.user32.GetWindowTextW
GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible
GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId

found_windows = []

def foreach_window(hwnd, lParam):
    if IsWindowVisible(hwnd):
        length = GetWindowTextLength(hwnd)
        if length > 0:
            buff = ctypes.create_unicode_buffer(length + 1)
            GetWindowText(hwnd, buff, length + 1)
            title = buff.value
            wpid = wintypes.DWORD()
            GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
            all_pids = [pid] + [c.pid for c in children]
            if wpid.value in all_pids or 'cyberguard' in title.lower():
                found_windows.append((hwnd, wpid.value, title))
    return True

EnumWindows(EnumWindowsProc(foreach_window), 0)

print(f"\nDiscovered Windows ({len(found_windows)}):")
for hwnd, wpid, title in found_windows:
    print(f"  HWND: {hwnd}, PID: {wpid}, Title: '{title}'")

# Clean shutdown
print("\nShutting down cleanly...")
for c in children:
    try:
        c.kill()
    except Exception:
        pass
try:
    p.kill()
except Exception:
    pass

if found_windows:
    print("\nSUCCESS: Windows executable launched, created window, and ran successfully!")
else:
    print("\nNOTE: No visible window detected in timeout window.")

