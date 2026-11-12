import os

path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\DevToolsActivePort")
print("DevToolsActivePort path:", path)
print("Exists:", os.path.exists(path))
if os.path.exists(path):
    with open(path, "r", encoding="utf-8") as f:
        print("DevToolsActivePort content:\n", f.read())

