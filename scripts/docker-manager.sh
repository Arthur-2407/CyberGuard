#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyberGuard Docker On-Demand Management CLI (Bash)
# ═══════════════════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

CMD="${1:-status}"
TUNNEL_FLAG="${2:-}"

case "${CMD}" in
  start)
    if [ "${TUNNEL_FLAG}" = "-Tunnel" ] || [ "${TUNNEL_FLAG}" = "--tunnel" ]; then
      echo "[INFO] Starting CyberGuard Backend + Cloudflare Secure Tunnel..."
      docker compose --profile tunnel up -d --build
      echo "[SUCCESS] Containers started! Waiting 5s for tunnel assignment..."
      sleep 5
      "${SCRIPT_DIR}/docker-manager.sh" tunnel-url
    else
      echo "[INFO] Starting CyberGuard Backend container (Local port 3000)..."
      docker compose up -d --build cyberguard-backend
      echo "[SUCCESS] Backend started at http://localhost:3000"
    fi
    ;;

  stop)
    echo "[INFO] Stopping all CyberGuard containers..."
    docker compose --profile tunnel down
    echo "[SUCCESS] CyberGuard containers stopped."
    ;;

  restart)
    echo "[INFO] Restarting CyberGuard containers..."
    docker compose --profile tunnel down
    if [ "${TUNNEL_FLAG}" = "-Tunnel" ] || [ "${TUNNEL_FLAG}" = "--tunnel" ]; then
      docker compose --profile tunnel up -d
    else
      docker compose up -d cyberguard-backend
    fi
    echo "[SUCCESS] Restart complete."
    ;;

  status)
    echo "=== [CONTAINER STATUS] ==="
    docker compose --profile tunnel ps
    echo ""
    echo "=== [LOCAL HEALTH PROBE] ==="
    if curl -s -f http://localhost:3000/health >/dev/null 2>&1; then
      echo "  Backend HTTP Health: ONLINE"
    else
      echo "  Backend HTTP Health: OFFLINE (Container stopped or initializing)"
    fi
    ;;

  tunnel-url)
    echo "[INFO] Fetching Cloudflare Tunnel endpoint from logs..."
    TUNNEL_LOGS=$(docker logs cyberguard-tunnel 2>&1 || true)
    URL=$(echo "${TUNNEL_LOGS}" | grep -o 'https://[a-zA-Z0-9\-]*\.trycloudflare\.com' | tail -n 1)
    if [ -n "${URL}" ]; then
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "  LIVE SECURE TUNNEL URL:"
      echo "  ${URL}"
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    else
      echo "[WARN] Tunnel URL not found yet. Check logs: docker logs cyberguard-tunnel"
    fi
    ;;

  logs)
    docker compose --profile tunnel logs -f
    ;;

  health)
    curl -s http://localhost:3000/health
    echo ""
    ;;

  *)
    echo "Usage: $0 {start [--tunnel]|stop|restart|status|tunnel-url|logs|health}"
    exit 1
    ;;
esac
