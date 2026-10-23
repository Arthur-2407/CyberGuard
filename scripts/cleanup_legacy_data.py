import sqlite3
import os
import glob
import shutil

def run_cleanup():
    print("--- Step 1: Cleaning data/cyberguard.db ---")
    conn = sqlite3.connect("data/cyberguard.db")
    cursor = conn.cursor()

    # 1. Clean users except admin
    cursor.execute("DELETE FROM users WHERE id != 1 AND role != 'admin' AND username != 'admin'")
    remaining_users = cursor.execute("SELECT id, username, email, role FROM users").fetchall()
    print("Remaining users:", remaining_users)

    # 2. Clean auth_sessions for non-admin users
    cursor.execute("DELETE FROM auth_sessions WHERE user_id NOT IN (SELECT id FROM users)")
    remaining_sessions = cursor.execute("SELECT count(*) FROM auth_sessions").fetchone()[0]
    print("Remaining auth sessions:", remaining_sessions)

    # 3. Clean Security Records and telemetry tables
    tables_to_clear = [
        "incidents", "threat_events", "threat_evidence", "audit_log", 
        "sessions", "analysis_records", "review_queue", "training_samples", 
        "training_runs", "threat_reports", "email_alert_records", 
        "blocked_entities", "admin_audit_log", "speakers"
    ]
    for tbl in tables_to_clear:
        try:
            cursor.execute(f"DELETE FROM {tbl}")
            cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{tbl}'")
            print(f"Cleared table: {tbl}")
        except Exception as e:
            print(f"Note on {tbl}: {e}")

    conn.commit()
    cursor.execute("VACUUM")
    conn.close()

    # 4. Clean data/reports
    if os.path.exists("data/reports"):
        for f in glob.glob("data/reports/*"):
            try:
                if os.path.isfile(f):
                    os.remove(f)
                elif os.path.isdir(f):
                    shutil.rmtree(f)
            except Exception as e:
                print(f"Error removing report {f}: {e}")
        print("Cleared data/reports")

    # 5. Clean data/audio_vault
    if os.path.exists("data/audio_vault"):
        for f in glob.glob("data/audio_vault/*"):
            try:
                if os.path.isfile(f):
                    os.remove(f)
                elif os.path.isdir(f):
                    shutil.rmtree(f)
            except Exception as e:
                print(f"Error removing vault file {f}: {e}")
        print("Cleared data/audio_vault")

    # 6. Clean data/voiceguard.db if present
    if os.path.exists("data/voiceguard.db"):
        try:
            vg_conn = sqlite3.connect("data/voiceguard.db")
            for tbl in ["incidents", "threat_events", "threat_evidence", "audit_log", "sessions", "speakers"]:
                try:
                    vg_conn.execute(f"DELETE FROM {tbl}")
                except Exception:
                    pass
            vg_conn.commit()
            vg_conn.close()
            print("Cleared data/voiceguard.db")
        except Exception as e:
            print(f"Error cleaning voiceguard.db: {e}")

    # 7. Ensure data/user_databases exists and is clean
    os.makedirs("data/user_databases", exist_ok=True)
    for f in glob.glob("data/user_databases/*"):
        try:
            if os.path.isfile(f):
                os.remove(f)
            elif os.path.isdir(f):
                shutil.rmtree(f)
        except Exception as e:
            print(f"Error cleaning user_databases: {e}")
    print("Prepared clean data/user_databases directory")

    print("--- Step 1 Complete: All non-admin users and legacy data successfully cleared! ---")

if __name__ == "__main__":
    run_cleanup()
