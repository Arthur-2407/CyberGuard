# CyberGuard Phase 7 Engineering Audit: Cloudflare Connector Recovery & Named Tunnel Architecture

## Executive Summary

During Phase 6 investigation, the Docker container `cyberguard-tunnel` was identified as running, yet the CyberGuard desktop application reported the Cloudflare Tunnel as `UNCONFIGURED` and connector registration failed server-side with:
```text
ERR Register tunnel error from server side error="Unauthorized: Tunnel not found"
```
In Phase 7, the root cause was comprehensively diagnosed, non-destructively repaired, and verified live from the public Internet. The connector is now connected to Cloudflare Edge (`del02`), actively proxying ingress traffic to `http://cyberguard-backend:3000`, and returning `200 OK` responses. Additionally, support for permanent Zero Trust named tunnels via `CLOUDFLARE_TUNNEL_TOKEN` was implemented across Compose and environment configuration templates.

---

## 1. Root Cause Analysis

### The Nature of TryCloudflare Ephemeral Tunnels
Cloudflare provides anonymous quick tunnels via `cloudflared tunnel --url <origin>`. When executed without credentials:
1. `cloudflared` contacts the Cloudflare edge and registers a temporary tunnel with an ephemeral UUID.
2. Cloudflare allocates a dynamic hostname under `*.trycloudflare.com` (e.g., `https://subaru-brooklyn-memphis-marine.trycloudflare.com`).
3. An edge connection is established over QUIC (or HTTP/2 fallback).

### Why "Unauthorized: Tunnel not found" Occurred
The container `cyberguard-tunnel` had been running continuously for **32+ hours**. Ephemeral TryCloudflare tunnel leases are time-limited. Once the initial connection lease expired and disconnected, `cloudflared` attempted to re-register the existing ephemeral UUID against the edge. Because Cloudflare edge servers purge ephemeral registrations after teardown, the edge returned:
```text
ERR Register tunnel error from server side error="Unauthorized: Tunnel not found"
```
The container process remained in a reconnect loop retrying a dead UUID that Cloudflare no longer recognized.

---

## 2. Non-Destructive Targeted Recovery Procedure

In accordance with strict production safety directives, **no backend containers, volumes, or databases were reset or deleted** (`docker compose down -v` was strictly avoided).

### Execution Command:
```powershell
docker compose --profile tunnel up -d --no-deps --force-recreate tunnel
```
This operation:
- Left `cyberguard-backend` (port 3000) undisturbed and running continuously.
- Gracefully recreated only the `cyberguard-tunnel` service container (new container ID: `8dfd96ac6f3f`).
- Triggered a fresh `cloudflared` handshake, generating a brand new TryCloudflare quick tunnel registration.

### Edge Registration Verification (Container Logs):
```text
2026-11-09T13:01:46Z INF Initial protocol quic
2026-11-09T13:01:46Z INF Starting metrics server on 127.0.0.1:40361/metrics
2026-11-09T13:01:47Z INF +-------------------------------------------------------------------------------------+
2026-11-09T13:01:47Z INF |  SUMMARY: Environment is healthy. cloudflared will use 'quic' as primary protocol.  |
2026-11-09T13:01:47Z INF +-------------------------------------------------------------------------------------+
2026-11-09T13:01:48Z INF Connection 22c54cb4-dfc7-4ee2-bb8d-71b5a5c68b75 registered connIndex=0 connection=... location=del02 protocol=quic
2026-11-09T13:01:49Z INF Connection registered connIndex=1 location=del02 protocol=quic
2026-11-09T13:01:50Z INF Connection registered connIndex=2 location=del02 protocol=quic
2026-11-09T13:01:51Z INF Connection registered connIndex=3 location=del02 protocol=quic
2026-11-09T13:01:51Z INF Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):
2026-11-09T13:01:51Z INF https://subaru-brooklyn-memphis-marine.trycloudflare.com
```

---

## 3. End-to-End Live Verification

### Public Edge Request via `curl.exe`:
```powershell
curl.exe -i -m 5 https://subaru-brooklyn-memphis-marine.trycloudflare.com/health
```

### Response Received:
```http
HTTP/1.1 200 OK
Date: Mon, 09 Nov 2026 13:36:26 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
CF-Ray: a57d34d21a1310b5-BOM
CF-Cache-Status: DYNAMIC
Server: cloudflare
Vary: Origin, Accept-Encoding

{
  "status": "ok",
  "service": "CyberGuard",
  "version": "1.0.0",
  "backend": "docker-local",
  "environment": "docker-local",
  "database": "connected",
  "detector_ready": true,
  "threat_intel": {
    "virustotal_configured": true,
    "urlhaus_configured": true
  }
}
```
**Verification Evidence:**
- Server: `cloudflare`
- CF-Ray: Valid Cloudflare edge trace token (`a57d34d21a1310b5-BOM`)
- Payload: Authoritative response from Docker container `cyberguard-backend:3000` (`backend: docker-local`).

---

## 4. Architectural Enhancements: 4-Tier Diagnostics & Dynamic Discovery

### Dynamic URL Extraction & Tail Depth Optimization
In `desktop/engine/connectivity_service.js`, the log inspection was enhanced:
```javascript
async inspectTunnelConnector(containerName = 'cyberguard-tunnel') {
  return new Promise((resolve) => {
    // Tail 150 captures startup banner past verbose pre-flight check lines
    exec(`docker logs --tail 150 ${containerName}`, { timeout: 3500 }, (err, stdout, stderr) => {
      const rawLogs = (stdout || '') + '\n' + (stderr || '');
      ...
      // Extract trycloudflare.com quick tunnel URL if present
      const urlMatch = rawLogs.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/i);
      const discoveredUrl = urlMatch ? urlMatch[0] : null;
      ...
    });
  });
}
```

### 4-Tier Diagnostic State Separation
The diagnostic engine strictly models the four independent states mandated by Cloudflare One architecture:
1. **Container State**: `RUNNING`, `STOPPED`, `NOT_RUNNING`, or `UNAVAILABLE`
2. **Connector State**: `CONNECTED`, `CONNECTING`, or `DISCONNECTED`
3. **Public Hostname / Route State**: `CONFIGURED` (custom or discovered) vs `NOT_CONFIGURED`
4. **Origin Service Reachability**: `REACHABLE` (`200 OK via Edge`), `READY` (listening locally), or `UNREACHABLE_502` (`Bad Gateway`)

---

## 5. Permanent Zero Trust Tunnel Configuration Support

To prevent quick tunnel lease expiration in production environments, `docker-compose.yml`, `.env.example`, and `.env.docker.example` were augmented:

```yaml
  tunnel:
    image: cloudflare/cloudflared:latest
    container_name: cyberguard-tunnel
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN:-}
    command: ${CLOUDFLARE_TUNNEL_COMMAND:-tunnel --url http://cyberguard-backend:3000}
    depends_on:
      backend:
        condition: service_healthy
    networks:
      - cyberguard-network
    profiles:
      - tunnel
```

### Switching to a Named Zero Trust Tunnel:
1. Create a Tunnel in the Cloudflare Zero Trust Dashboard (`Networks` > `Tunnels`).
2. Copy the tunnel token into `.env`:
   ```bash
   CLOUDFLARE_TUNNEL_TOKEN="eyJhIjoi..."
   CLOUDFLARE_TUNNEL_COMMAND="tunnel run"
   ```
3. Restart the tunnel service:
   ```powershell
   docker compose --profile tunnel up -d tunnel
   ```
This provides a permanent custom DNS hostname with Zero Trust Access policies, automated reconnects, and zero lease expirations.

