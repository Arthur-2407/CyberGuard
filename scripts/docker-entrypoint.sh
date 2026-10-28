#!/bin/bash
set -e

# ═══════════════════════════════════════════════════════════════════════════════
# CyberGuard Production Docker Entrypoint & Scanner Service Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

echo "[CyberGuard] Initializing CyberGuard SOC runtime environment..."

# 1. Directory creation and permissions validation
mkdir -p /app/data /app/data/yara_rules /var/lib/clamav /var/log/clamav /var/run/clamav

# 2. Check ClamAV signature database status
DB_DIR="/var/lib/clamav"
HAS_SIGNATURES=false

if [ -f "$DB_DIR/daily.cld" ] || [ -f "$DB_DIR/daily.cvd" ] || [ -f "$DB_DIR/main.cld" ] || [ -f "$DB_DIR/main.cvd" ]; then
    HAS_SIGNATURES=true
    echo "[CyberGuard] Verified existing ClamAV signature database in $DB_DIR."
fi

# Function to safely start clamd daemon if signatures exist
start_clamd() {
    if [ -f "$DB_DIR/daily.cld" ] || [ -f "$DB_DIR/daily.cvd" ] || [ -f "$DB_DIR/main.cld" ] || [ -f "$DB_DIR/main.cvd" ]; then
        if ! pgrep -x "clamd" > /dev/null 2>&1; then
            echo "[CyberGuard] Starting ClamAV daemon (clamd)..."
            clamd 2>/dev/null || true
        fi
    fi
}

# Function to safely execute freshclam signature update in background
run_freshclam_update() {
    echo "[CyberGuard] Starting freshclam signature update process..."
    if freshclam --quiet --stdout 2>/dev/null; then
        echo "[CyberGuard] ClamAV signature database initialized/updated successfully."
        start_clamd
    else
        echo "[CyberGuard] Note: freshclam returned non-zero (network or mirror restriction). Existing database status preserved."
    fi
}

start_clamd

if [ "$HAS_SIGNATURES" = "false" ]; then
    echo "[CyberGuard] ClamAV signatures missing in $DB_DIR. Initiating background download..."
    run_freshclam_update &
else
    # Run background check for incremental daily updates
    run_freshclam_update &
fi

# 3. Launch application server via uvicorn
echo "[CyberGuard] Starting ASGI application server on port ${PORT:-3000}..."
if [ "$#" -eq 0 ]; then
    exec python -m uvicorn backend.main:app --host 0.0.0.0 --port "${PORT:-3000}"
else
    exec "$@"
fi
