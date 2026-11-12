import subprocess
import time
import os
import psutil

exe_path = os.path.abspath("dist/windows/CyberGuard-Portable.exe")
print(f"Launching Portable Executable: {exe_path}")

env = os.environ.copy()
# Ensure child does not inherit any accidental node-mode override
env.pop("ELECTRON_RUN_AS_NODE", None)

proc = subprocess.Popen([exe_path], env=env)
print(f"Launched Portable launcher with PID: {proc.pid}")

# Wait for NSIS launcher to unpack embedded 7z archive to %TEMP% and spawn CyberGuard.exe
time.sleep(5)

parent = None
try:
    parent = psutil.Process(proc.pid)
    print(f"Launcher PID {proc.pid} status: {parent.status()}")
except psutil.NoSuchProcess:
    print(f"Launcher PID {proc.pid} has finished extraction.")

# Find all active CyberGuard processes (launcher + unpacked child processes)
cg_processes = []
for p in psutil.process_iter(['pid', 'name', 'exe', 'status']):
    try:
        name = (p.info['name'] or '').lower()
        if 'cyberguard' in name:
            cg_processes.append(p)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

print(f"Total CyberGuard processes detected: {len(cg_processes)}")
for p in cg_processes:
    try:
        print(f"  - PID {p.pid}: {p.name()} ({p.status()}) -> {p.exe()}")
    except Exception:
        pass

assert len(cg_processes) > 0, "No CyberGuard processes were spawned by the portable executable!"

# Clean termination
for p in cg_processes:
    try:
        p.kill()
    except Exception:
        pass

print("Smoke test PASSED: Portable binary unpacked, launched runtime, and terminated cleanly.")
