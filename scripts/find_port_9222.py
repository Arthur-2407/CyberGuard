import psutil

print("Checking port 9222 listening process...")
for conn in psutil.net_connections(kind='inet'):
    if conn.laddr.port == 9222:
        try:
            proc = psutil.Process(conn.pid)
            print(f"Port 9222 bound to PID {conn.pid}: {proc.name()} ({proc.exe()})")
            print(f"Status: {conn.status}, Cmdline: {' '.join(proc.cmdline()[:4])}")
        except Exception as e:
            print(f"Port 9222 PID {conn.pid} lookup error: {e}")

