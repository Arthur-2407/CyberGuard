import sqlite3
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.storage.database import init_db

print("Running init_db on data/cyberguard.db...")
init_db("data/cyberguard.db")

conn = sqlite3.connect("data/cyberguard.db")
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in c.fetchall()]
print(f"Total tables: {len(tables)}")
print(f"Tables: {sorted(tables)}")
conn.close()
