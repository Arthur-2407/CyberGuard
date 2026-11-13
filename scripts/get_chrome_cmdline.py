import psutil

try:
    p = psutil.Process(18016)
    print("Process name:", p.name())
    print("Cmdline:", p.cmdline())
    print("Cwd:", p.cwd())
    print("Create time:", p.create_time())
except Exception as e:
    print("Error:", e)

