"""Safe Environment Credentials Audit Script for CyberGuard.

Extracts variable names and safe redacted status (CONFIGURED / EMPTY / MISSING)
without ever exposing secrets, passwords, or keys.
"""

from pathlib import Path
import re

ENV_FILES = [
    ".env",
    ".env.email",
    ".env.example",
    ".env.docker.example",
]

def audit():
    print("=== CYBERGUARD SAFE ENVIRONMENT CREDENTIAL AUDIT ===")
    for fname in ENV_FILES:
        p = Path(fname)
        if not p.exists():
            print(f"[-] {fname}: NOT FOUND")
            continue
        print(f"\n[+] File: {fname} (Exists, size={p.stat().st_size} bytes)")
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                status = "CONFIGURED" if len(val) > 0 else "EMPTY"
                is_placeholder = bool(re.match(r"^(your_.*|placeholder.*|xxx.*|<.*>|CHANGE_ME)$", val, re.I))
                if is_placeholder:
                    status = "PLACEHOLDER"
                print(f"    - {key}: {status} (length: {len(val)})")

if __name__ == "__main__":
    audit()
