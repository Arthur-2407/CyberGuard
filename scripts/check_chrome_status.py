import psutil
import socket
import urllib.request
import json

print("=== CHROME PROCESSES ===")
chrome_procs = []
for p in psutil.process_iter(['pid', 'name', 'cmdline']):
    try:
        name = p.info['name'] or ''
        if 'chrome' in name.lower():
            cmd = ' '.join(p.info['cmdline'] or [])
            chrome_procs.append((p.info['pid'], cmd))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

print(f"Total Chrome processes found: {len(chrome_procs)}")
for pid, cmd in chrome_procs[:5]:
    print(f"PID {pid}: {cmd[:140]}")

print("\n=== PORT 9222 STATUS ===")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
res = s.connect_ex(('127.0.0.1', 9222))
print("Port 9222 connect result (0 = open):", res)
s.close()

if res == 0:
    try:
        req = urllib.request.Request("http://127.0.0.1:9222/json/version")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = resp.read().decode('utf-8')
            print("DevTools /json/version response:", data)
    except Exception as e:
        print("DevTools query failed:", e)

