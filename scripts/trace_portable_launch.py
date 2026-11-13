import subprocess
import time
import os
import psutil

exe_path = os.path.abspath("dist/windows/CyberGuard-Portable.exe")
print(f"Launching {exe_path}...")
proc = subprocess.Popen([exe_path])
print(f"Launched PID: {proc.pid}")

tracked = {}
start = time.time()
while time.time() - start < 8:
    for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'status', 'ppid']):
        try:
            info = p.info
            name = (info['name'] or '').lower()
            if 'cyberguard' in name or (info['cmdline'] and any('cyberguard' in str(arg).lower() for arg in info['cmdline'])):
                pid = info['pid']
                if pid not in tracked:
                    tracked[pid] = info
                    print(f"[{time.time()-start:.2f}s] Detected process: PID={pid}, Name={info['name']}, PPID={info['ppid']}, Exe={info['exe']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(0.1)

print(f"\nTotal CyberGuard processes detected over 8 seconds: {len(tracked)}")
for pid, info in tracked.items():
    print(f"  PID {pid}: {info['name']} -> {info.get('exe')}")
    # Terminate cleanly
    try:
        p = psutil.Process(pid)
        p.kill()
        print(f"  Cleaned up PID {pid}")
    except Exception as e:
        print(f"  Cleanup note for PID {pid}: {e}")

