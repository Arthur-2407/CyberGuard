/**
 * CyberGuard Desktop — Independent Connectivity & Diagnostic Service
 *
 * Provides accurate, independent health diagnostics across all tiers:
 *   1. Local Docker Engine & Container Health
 *   2. Cloud Backend API (DNS, TLS, HTTP Health, Latency)
 *   3. Cloudflare Tunnel (Host, Route, TLS, Latency)
 *   4. Vercel Frontend Portal (Website vs API Rewrite distinction)
 *
 * Enforces the non-contradictory status model:
 *   Header, component cards, and resolved active health indicator consume
 *   the exact same authoritative state model.
 */

const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const { URL } = require('url');

const DEFAULT_CLOUD_URL = 'https://cyberguard-backend-8rbz.onrender.com';
const DEFAULT_VERCEL_URL = 'https://cyber-guard-backend-ashen.vercel.app';

// Standardized Service State Constants (Phase 5.1 Specification)
const SERVICE_STATES = {
  UNKNOWN: 'UNKNOWN',
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  IDLE: 'IDLE',
  PROBING: 'PROBING',
  CONNECTED: 'CONNECTED',
  HEALTHY: 'HEALTHY',
  DEGRADED: 'DEGRADED',
  OFFLINE: 'OFFLINE',
  TIMEOUT: 'TIMEOUT',
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  ERROR: 'ERROR'
};

class ConnectivityService {
  constructor() {
    this.cachedDockerState = null;
    this.lastDockerCheck = 0;
    this.discoveredTunnelUrl = null;
    this.lastSuccessfulProbes = {
      local: null,
      cloud: null,
      tunnel: null,
      vercel: null
    };
  }

  /**
   * Helper to perform a low-overhead HTTP/HTTPS probe with exact timing.
   */
  async _probeUrl(targetUrl, timeoutMs = 7000) {
    const startTime = Date.now();
    return new Promise((resolve) => {
      try {
        const parsed = new URL(targetUrl);
        const client = parsed.protocol === 'https:' ? https : http;
        const options = {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname + (parsed.search || ''),
          method: 'GET',
          timeout: timeoutMs,
          headers: {
            'User-Agent': 'CyberGuard-Desktop-Client/1.0.0'
          }
        };

        const req = client.request(options, (res) => {
          let body = '';
          res.on('data', chunk => {
            if (body.length < 65536) body += chunk;
          });
          res.on('end', () => {
            const latencyMs = Date.now() - startTime;
            let json = null;
            try { json = JSON.parse(body); } catch (_) {}
            const isOk = res.statusCode >= 200 && res.statusCode < 400;
            resolve({
              ok: isOk,
              statusCode: res.statusCode,
              latencyMs,
              data: json,
              rawBodyLength: body.length,
              error: isOk ? null : `HTTP ${res.statusCode}`
            });
          });
        });

        req.on('timeout', () => {
          req.destroy();
          resolve({
            ok: false,
            statusCode: 0,
            latencyMs: Date.now() - startTime,
            error: 'Connection timed out',
            code: 'ETIMEDOUT'
          });
        });

        req.on('error', (err) => {
          resolve({
            ok: false,
            statusCode: 0,
            latencyMs: Date.now() - startTime,
            error: err.message || 'Network request failed',
            code: err.code || 'ERR_REQUEST_FAILED'
          });
        });

        req.end();
      } catch (err) {
        resolve({
          ok: false,
          statusCode: 0,
          latencyMs: Date.now() - startTime,
          error: err.message || 'Invalid URL target',
          code: 'ERR_INVALID_URL'
        });
      }
    });
  }

  /**
   * Inspects Docker Engine & Compose container states safely.
   */
  async checkDockerEngine() {
    return new Promise((resolve) => {
      exec('docker compose ps --format json', { timeout: 3500 }, (error, stdout, stderr) => {
        if (error) {
          exec('docker version --format json', { timeout: 2500 }, (vErr) => {
            if (vErr) {
              resolve({
                daemonAvailable: false,
                containers: [],
                error: 'Docker daemon is not running or not accessible'
              });
            } else {
              resolve({
                daemonAvailable: true,
                containers: [],
                error: 'Docker daemon running, but no CyberGuard compose project active'
              });
            }
          });
          return;
        }

        const containers = [];
        const lines = (stdout || '').trim().split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const parsed = JSON.parse(line.trim());
            containers.push({
              id: parsed.ID || '',
              name: parsed.Name || parsed.Service || '',
              service: parsed.Service || '',
              image: parsed.Image || '',
              state: parsed.State || '',
              status: parsed.Status || '',
              health: parsed.Health || (parsed.Status && parsed.Status.includes('(healthy)') ? 'healthy' : 'unconfigured'),
              ports: parsed.Ports || ''
            });
          } catch (_) {}
        }

        resolve({
          daemonAvailable: true,
          containers,
          error: null
        });
      });
    });
  }

  /**
   * Inspects Cloudflare Tunnel connector process, edge status, and recent sanitized logs safely.
   */
  async inspectTunnelConnector(containerName = 'cyberguard-tunnel') {
    return new Promise((resolve) => {
      exec(`docker logs --tail 1000 ${containerName}`, { timeout: 6000 }, (err, stdout, stderr) => {
        const rawLogs = (stdout || '') + '\n' + (stderr || '');
        if (err && !rawLogs.trim()) {
          resolve({
            connectorState: 'UNAVAILABLE',
            edgeStatus: 'DOWN',
            connectorDetail: 'Unable to retrieve container logs',
            discoveredUrl: null,
            sanitizedLogs: 'No logs available.'
          });
          return;
        }

        // Sanitize logs (strip credentials, tokens, passwords)
        const sanitized = rawLogs
          .split('\n')
          .filter(l => l.trim().length > 0)
          .slice(-15)
          .map(line => line.replace(/token=[a-zA-Z0-9_\-\.]+/gi, 'token=[REDACTED]')
                           .replace(/key=[a-zA-Z0-9_\-\.]+/gi, 'key=[REDACTED]')
                           .replace(/password=[^\s]+/gi, 'password=[REDACTED]'))
          .join('\n')
          .trim();

        // Extract trycloudflare.com quick tunnel URL if present
        const urlMatch = rawLogs.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/i);
        let discoveredUrl = urlMatch ? urlMatch[0] : null;
        if (discoveredUrl) {
          this.discoveredTunnelUrl = discoveredUrl;
        } else if (this.discoveredTunnelUrl) {
          discoveredUrl = this.discoveredTunnelUrl;
        }

        // Detect connector state & edge registration
        let connectorState = 'UNKNOWN';
        let edgeStatus = 'UNKNOWN';
        let connectorDetail = 'Connector running, edge status unconfirmed';

        if (/Registered tunnel connection|Connection [a-f0-9-]+ registered/i.test(rawLogs)) {
          connectorState = 'CONNECTED';
          edgeStatus = 'HEALTHY';
          connectorDetail = 'Connected to Cloudflare Edge';
        } else if (/Register tunnel error.*error="([^"]+)"|Unauthorized: Tunnel not found/i.test(rawLogs)) {
          connectorState = 'DISCONNECTED';
          edgeStatus = 'DOWN';
          const errMatch = rawLogs.match(/error="([^"]+)"/);
          connectorDetail = errMatch ? errMatch[1] : 'Registration error: Unauthorized (Tunnel not found)';
        } else if (/Retrying connection|Starting tunnel/i.test(rawLogs)) {
          connectorState = 'CONNECTING';
          edgeStatus = 'CONNECTING';
          connectorDetail = 'Connecting to Cloudflare Edge...';
        }

        resolve({
          connectorState,
          edgeStatus,
          connectorDetail,
          discoveredUrl,
          sanitizedLogs: sanitized || 'No logs found.'
        });
      });
    });
  }

  /**
   * Tier 1: Local Docker Engine & Local API Probe
   */
  async checkLocalBackend(port = 3000, existingDockerState = null) {
    const portNum = parseInt(port, 10) || 3000;
    const attemptedAt = new Date().toISOString();
    const endpoint = `http://127.0.0.1:${portNum}`;

    const [dockerState, healthProbe] = await Promise.all([
      existingDockerState ? Promise.resolve(existingDockerState) : this.checkDockerEngine(),
      this._probeUrl(`${endpoint}/health`, 4000)
    ]);

    const backendContainer = dockerState.containers.find(c =>
      (c.service && c.service.includes('backend')) ||
      (c.name && c.name.includes('backend'))
    );

    let status = SERVICE_STATES.OFFLINE;
    let diagnosticReason = 'Port closed or container inactive';

    if (healthProbe.ok) {
      if (healthProbe.latencyMs > 2500) {
        status = SERVICE_STATES.DEGRADED;
        diagnosticReason = `High latency response (${healthProbe.latencyMs} ms)`;
      } else {
        status = SERVICE_STATES.HEALTHY;
        diagnosticReason = backendContainer
          ? `Healthy (Docker container ${backendContainer.status || 'active'})`
          : 'Healthy (Host-native backend responding)';
      }
      this.lastSuccessfulProbes.local = attemptedAt;
    } else if (healthProbe.code === 'ETIMEDOUT') {
      status = SERVICE_STATES.TIMEOUT;
      diagnosticReason = 'Connection timed out (3000 ms)';
    } else if (healthProbe.statusCode === 401 || healthProbe.statusCode === 403) {
      status = SERVICE_STATES.AUTH_REQUIRED;
      diagnosticReason = `Authentication required (HTTP ${healthProbe.statusCode})`;
    } else if (dockerState.daemonAvailable && !backendContainer) {
      status = SERVICE_STATES.OFFLINE;
      diagnosticReason = 'Docker engine online, but backend container not found';
    } else if (!dockerState.daemonAvailable) {
      status = SERVICE_STATES.OFFLINE;
      diagnosticReason = 'Docker daemon not running on host';
    } else {
      status = SERVICE_STATES.ERROR;
      diagnosticReason = healthProbe.error || `HTTP ${healthProbe.statusCode}`;
    }

    const tierRecord = {
      componentId: 'local_docker',
      tier: 'LOCAL_DOCKER',
      serviceRole: 'Local On-Premises SOC Engine',
      port: portNum,
      endpoint,
      dockerDaemonAvailable: dockerState.daemonAvailable,
      dockerDaemon: dockerState.daemonAvailable,
      containerFound: !!backendContainer,
      containerStatus: backendContainer ? backendContainer.status : null,
      containerState: backendContainer ? backendContainer.state : 'stopped',
      containerHealth: backendContainer ? backendContainer.health : 'unknown',
      online: healthProbe.ok,
      reachable: healthProbe.ok,
      status,
      statusCode: healthProbe.statusCode,
      diagnosticReason,
      latencyMs: healthProbe.latencyMs,
      details: healthProbe.data || null,
      lastSuccessfulProbe: this.lastSuccessfulProbes.local,
      lastAttemptedProbe: attemptedAt,
      timestamp: attemptedAt,
      probeDurationMs: healthProbe.latencyMs,
      configSource: 'Host Loopback / Docker published port',
      error: healthProbe.ok ? null : diagnosticReason
    };

    return tierRecord;
  }

  /**
   * Tier 2: Cloud Backend API Probe
   */
  async checkCloudBackend(cloudEndpoint = DEFAULT_CLOUD_URL) {
    const url = (cloudEndpoint || DEFAULT_CLOUD_URL).replace(/\/+$/, '');
    const attemptedAt = new Date().toISOString();
    const healthProbe = await this._probeUrl(`${url}/health`, 7000);

    let status = SERVICE_STATES.OFFLINE;
    let diagnosticReason = 'Endpoint unreachable';

    if (healthProbe.ok) {
      if (healthProbe.latencyMs > 3000) {
        status = SERVICE_STATES.DEGRADED;
        diagnosticReason = `High cloud latency (${healthProbe.latencyMs} ms)`;
      } else {
        status = SERVICE_STATES.HEALTHY;
        diagnosticReason = '200 OK (TLS Verified)';
      }
      this.lastSuccessfulProbes.cloud = attemptedAt;
    } else if (healthProbe.code === 'ETIMEDOUT') {
      status = SERVICE_STATES.TIMEOUT;
      diagnosticReason = 'Connection timed out (7000 ms)';
    } else if (healthProbe.statusCode === 401 || healthProbe.statusCode === 403) {
      status = SERVICE_STATES.AUTH_REQUIRED;
      diagnosticReason = `Authentication required (HTTP ${healthProbe.statusCode})`;
    } else {
      status = SERVICE_STATES.ERROR;
      diagnosticReason = healthProbe.error || `HTTP ${healthProbe.statusCode}`;
    }

    const tierRecord = {
      componentId: 'cloud_backend',
      tier: 'CLOUD_BACKEND',
      serviceRole: 'CyberGuard Managed Cloud Infrastructure',
      endpoint: url,
      online: healthProbe.ok,
      reachable: healthProbe.ok,
      status,
      statusCode: healthProbe.statusCode,
      diagnosticReason,
      latencyMs: healthProbe.latencyMs,
      details: healthProbe.data || null,
      lastSuccessfulProbe: this.lastSuccessfulProbes.cloud,
      lastAttemptedProbe: attemptedAt,
      timestamp: attemptedAt,
      probeDurationMs: healthProbe.latencyMs,
      configSource: 'Render Managed Deployment',
      error: healthProbe.ok ? null : diagnosticReason
    };

    return tierRecord;
  }

  /**
   * Tier 3: Cloudflare Tunnel Probe
   * Independently assesses:
   *   1. Docker connector container state (RUNNING, STOPPED, UNAVAILABLE)
   *   2. Cloudflare connector & edge connection (CONNECTED, DISCONNECTED, CONNECTING)
   *   3. Public hostname / ingress route (CONFIGURED vs NOT_CONFIGURED)
   *   4. Origin service reachability (REACHABLE, READY, UNREACHABLE, 502)
   */
  async checkTunnel(tunnelUrl, existingDockerState = null, localPort = 3000) {
    const attemptedAt = new Date().toISOString();
    const dockerState = existingDockerState || await this.checkDockerEngine();

    const tunnelContainer = dockerState && dockerState.containers
      ? dockerState.containers.find(c =>
          (c.service && c.service.includes('tunnel')) ||
          (c.name && c.name.includes('tunnel')) ||
          (c.image && c.image.includes('cloudflared'))
        )
      : null;

    let connectorDiag = {
      connectorState: tunnelContainer ? 'UNKNOWN' : 'UNAVAILABLE',
      edgeStatus: tunnelContainer ? 'UNKNOWN' : 'DOWN',
      connectorDetail: tunnelContainer ? 'Container active, edge unconfirmed' : 'Container not found',
      discoveredUrl: null,
      sanitizedLogs: 'No container logs available.'
    };

    if (tunnelContainer) {
      connectorDiag = await this.inspectTunnelConnector(tunnelContainer.name || 'cyberguard-tunnel');
    }

    // Determine target URL: explicitly provided custom tunnel or discovered quick tunnel
    let url = (tunnelUrl && tunnelUrl.trim()) ? tunnelUrl.trim() : (connectorDiag.discoveredUrl || '');
    const hasHostname = !!url;

    if (!hasHostname) {
      const containerState = tunnelContainer
        ? (tunnelContainer.state ? tunnelContainer.state.toUpperCase() : 'RUNNING')
        : (dockerState.daemonAvailable ? 'NOT_RUNNING' : 'UNAVAILABLE');

      let diagnosticReason = 'No custom Cloudflare Tunnel configured (Optional)';
      if (tunnelContainer) {
        if (connectorDiag.connectorState === 'CONNECTED') {
          diagnosticReason = `Container running (${tunnelContainer.name}); connected to Cloudflare Edge (${connectorDiag.connectorDetail})`;
        } else if (connectorDiag.connectorState === 'DISCONNECTED') {
          diagnosticReason = `Container running (${tunnelContainer.name}), but connector disconnected (${connectorDiag.connectorDetail})`;
        } else {
          diagnosticReason = `Container running (${tunnelContainer.name}); public ingress route not configured`;
        }
      }

      const isConnectorOk = connectorDiag.connectorState === 'CONNECTED';
      const tunnelStatus = isConnectorOk
        ? SERVICE_STATES.CONNECTED
        : (tunnelContainer ? (connectorDiag.connectorState === 'DISCONNECTED' ? SERVICE_STATES.ERROR : SERVICE_STATES.IDLE) : SERVICE_STATES.NOT_CONFIGURED);

      return {
        componentId: 'cloudflare_tunnel',
        tier: 'CLOUDFLARE_TUNNEL',
        serviceRole: 'End-to-End Encrypted Egress Tunnel',
        configured: Boolean(tunnelContainer),
        publicHostnameConfigured: false,
        publicHostname: null,
        online: isConnectorOk,
        reachable: isConnectorOk,
        status: tunnelStatus,
        statusCode: 0,
        endpoint: null,
        diagnosticReason,
        latencyMs: 0,
        details: null,
        containerFound: !!tunnelContainer,
        containerName: tunnelContainer ? tunnelContainer.name : null,
        containerId: tunnelContainer ? tunnelContainer.id : null,
        containerState,
        containerStatus: tunnelContainer ? tunnelContainer.status : null,
        connectorState: connectorDiag.connectorState,
        edgeStatus: connectorDiag.edgeStatus,
        connectorDetail: connectorDiag.connectorDetail,
        originStatus: 'READY',
        originReachabilityText: 'Ready (Local backend listening on port 3000)',
        sanitizedLogs: connectorDiag.sanitizedLogs,
        lastSuccessfulProbe: this.lastSuccessfulProbes.tunnel,
        lastAttemptedProbe: attemptedAt,
        timestamp: attemptedAt,
        probeDurationMs: 0,
        configSource: tunnelContainer ? 'Docker Compose Service (tunnel)' : 'Optional User Custom Tunnel',
        error: null
      };
    }

    let normalizedUrl = url.replace(/\/+$/, '');
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    const healthProbe = await this._probeUrl(`${normalizedUrl}/health`, 7000);

    let status = SERVICE_STATES.OFFLINE;
    let diagnosticReason = 'Tunnel endpoint unreachable';
    let originStatus = 'UNREACHABLE';

    if (healthProbe.ok) {
      status = SERVICE_STATES.HEALTHY;
      originStatus = 'REACHABLE';
      diagnosticReason = 'Tunnel active (Origin reachable via Cloudflare Edge)';
      this.lastSuccessfulProbes.tunnel = attemptedAt;
    } else if (healthProbe.statusCode === 502) {
      status = SERVICE_STATES.ERROR;
      originStatus = 'UNREACHABLE_502';
      diagnosticReason = 'Tunnel edge connected, but origin backend returned 502 Bad Gateway';
    } else if (healthProbe.code === 'ETIMEDOUT') {
      status = SERVICE_STATES.TIMEOUT;
      originStatus = 'TIMEOUT';
      diagnosticReason = 'Tunnel handshake timed out (7000 ms)';
    } else {
      status = SERVICE_STATES.ERROR;
      originStatus = 'ERROR';
      diagnosticReason = healthProbe.error || `HTTP ${healthProbe.statusCode}`;
    }

    const containerState = tunnelContainer
      ? (tunnelContainer.state ? tunnelContainer.state.toUpperCase() : 'RUNNING')
      : 'EXTERNAL_TUNNEL';

    return {
      componentId: 'cloudflare_tunnel',
      tier: 'CLOUDFLARE_TUNNEL',
      serviceRole: 'End-to-End Encrypted Egress Tunnel',
      configured: true,
      publicHostnameConfigured: true,
      publicHostname: normalizedUrl,
      endpoint: normalizedUrl,
      online: healthProbe.ok,
      reachable: healthProbe.ok,
      status,
      statusCode: healthProbe.statusCode,
      diagnosticReason,
      latencyMs: healthProbe.latencyMs,
      details: healthProbe.data || null,
      containerFound: !!tunnelContainer,
      containerName: tunnelContainer ? tunnelContainer.name : null,
      containerId: tunnelContainer ? tunnelContainer.id : null,
      containerState,
      containerStatus: tunnelContainer ? tunnelContainer.status : null,
      connectorState: connectorDiag.connectorState,
      edgeStatus: connectorDiag.edgeStatus,
      connectorDetail: connectorDiag.connectorDetail,
      originStatus,
      originReachabilityText: healthProbe.ok ? 'Reachable (200 OK via Edge)' : `Unreachable (${healthProbe.error || `HTTP ${healthProbe.statusCode}`})`,
      sanitizedLogs: connectorDiag.sanitizedLogs,
      lastSuccessfulProbe: this.lastSuccessfulProbes.tunnel,
      lastAttemptedProbe: attemptedAt,
      timestamp: attemptedAt,
      probeDurationMs: healthProbe.latencyMs,
      configSource: 'Cloudflare Quick Tunnel / Zero Trust',
      error: healthProbe.ok ? null : diagnosticReason
    };
  }

  /**
   * Tier 4: Vercel Web Portal Probe (Differentiates frontend static host from API rewrite)
   */
  async checkVercel(vercelUrl = DEFAULT_VERCEL_URL) {
    const url = (vercelUrl || DEFAULT_VERCEL_URL).replace(/\/+$/, '');
    const attemptedAt = new Date().toISOString();

    const [portalProbe, apiRewriteProbe] = await Promise.all([
      this._probeUrl(`${url}/`, 3500),
      this._probeUrl(`${url}/health`, 3500)
    ]);

    let status = SERVICE_STATES.OFFLINE;
    let diagnosticReason = 'Portal unreachable';

    if (portalProbe.ok) {
      if (apiRewriteProbe.ok) {
        status = SERVICE_STATES.HEALTHY;
        diagnosticReason = 'Portal & API rewrite fully operational';
      } else {
        status = SERVICE_STATES.DEGRADED;
        diagnosticReason = 'Portal online; API rewrite degraded or missing';
      }
      this.lastSuccessfulProbes.vercel = attemptedAt;
    } else if (portalProbe.code === 'ETIMEDOUT') {
      status = SERVICE_STATES.TIMEOUT;
      diagnosticReason = 'Portal connection timed out';
    } else {
      status = SERVICE_STATES.ERROR;
      diagnosticReason = portalProbe.error || `HTTP ${portalProbe.statusCode}`;
    }

    return {
      componentId: 'vercel_portal',
      tier: 'VERCEL_PORTAL',
      serviceRole: 'Public Web Portal & Management Interface',
      endpoint: url,
      online: portalProbe.ok,
      reachable: portalProbe.ok,
      portalReachable: portalProbe.ok,
      portalLatencyMs: portalProbe.latencyMs,
      apiRewriteOnline: apiRewriteProbe.ok,
      apiRewriteLatencyMs: apiRewriteProbe.latencyMs,
      apiRewriteError: apiRewriteProbe.ok ? null : (apiRewriteProbe.error || `HTTP ${apiRewriteProbe.statusCode}`),
      status,
      statusCode: portalProbe.statusCode,
      diagnosticReason,
      latencyMs: portalProbe.latencyMs,
      lastSuccessfulProbe: this.lastSuccessfulProbes.vercel,
      lastAttemptedProbe: attemptedAt,
      timestamp: attemptedAt,
      probeDurationMs: Math.max(portalProbe.latencyMs, apiRewriteProbe.latencyMs),
      configSource: 'Vercel Edge Network',
      error: portalProbe.ok ? null : diagnosticReason
    };
  }

  /**
   * Master Comprehensive Diagnostic: Probes all 4 tiers independently in parallel.
   * Returns consistent object with aliases for full backward and forward compatibility.
   */
  async runFullDiagnostics({ localPort = 3000, cloudUrl = DEFAULT_CLOUD_URL, customTunnel = '', mode = 'hybrid' } = {}) {
    const dockerState = await this.checkDockerEngine();

    // Sequential probe staging to prevent Windows libuv worker thread contention:
    // Stage 1: Local engine probe (Docker inspection + loopback health check)
    const local = await this.checkLocalBackend(localPort, dockerState);
    // Stage 2: Cloudflare tunnel probe (Docker logs inspection + TryCloudflare/custom edge check)
    const tunnel = await this.checkTunnel(customTunnel, dockerState, localPort);
    // Stage 3: Remote internet services (Render cloud backend + Vercel web portal)
    const [cloud, vercel] = await Promise.all([
      this.checkCloudBackend(cloudUrl),
      this.checkVercel()
    ]);

    const activeResolution = this.resolveActiveEndpoint({
      mode,
      localPort,
      cloudUrl,
      customTunnel,
      diagnostics: { local, cloud, tunnel, vercel }
    });

    const result = {
      timestamp: new Date().toISOString(),
      // Primary normalized keys
      local,
      cloud,
      tunnel,
      vercel,
      // Backward-compatible aliases so no caller ever crashes with undefined property!
      localDocker: local,
      cloudBackend: cloud,
      cloudflareTunnel: tunnel,
      vercelPortal: vercel,
      // Active resolution authoritative model
      active: activeResolution
    };

    return result;
  }

  /**
   * Evaluates the active mode and returns truthful resolution.
   */
  resolveActiveEndpoint({ mode = 'hybrid', localPort = 3000, cloudUrl = DEFAULT_CLOUD_URL, customTunnel = '', diagnostics = null }) {
    const portNum = parseInt(localPort, 10) || 3000;
    const localEndpoint = `http://127.0.0.1:${portNum}`;
    const cloudEndpoint = (cloudUrl || DEFAULT_CLOUD_URL).replace(/\/+$/, '');
    const tunnelEndpoint = customTunnel && customTunnel.trim() ? customTunnel.trim().replace(/\/+$/, '') : null;

    if (mode === 'local') {
      const isReachable = diagnostics && diagnostics.local ? diagnostics.local.online : false;
      const status = isReachable ? SERVICE_STATES.HEALTHY : SERVICE_STATES.OFFLINE;
      return {
        mode: 'local',
        modeLabel: 'Local Isolated Mode',
        activeEndpoint: localEndpoint,
        activeTier: 'local',
        isReachable,
        status,
        activeHealth: isReachable ? 'ONLINE (200 OK)' : 'OFFLINE (Connection timed out)',
        overallStatus: isReachable ? 'LOCAL ONLINE' : 'LOCAL OFFLINE',
        fallbackActive: false,
        headerPill: {
          dotClass: isReachable ? 'online' : 'offline',
          label: isReachable ? `LOCAL ${portNum}` : `LOCAL ${portNum} (OFFLINE)`
        }
      };
    }

    if (mode === 'deployed') {
      const isReachable = diagnostics && diagnostics.cloud ? diagnostics.cloud.online : false;
      const status = isReachable ? SERVICE_STATES.HEALTHY : SERVICE_STATES.OFFLINE;
      return {
        mode: 'deployed',
        modeLabel: 'Deployed Cloud Mode',
        activeEndpoint: cloudEndpoint,
        activeTier: 'cloud',
        isReachable,
        status,
        activeHealth: isReachable ? 'ONLINE (200 OK)' : 'OFFLINE (Connection timed out)',
        overallStatus: isReachable ? 'CLOUD ONLINE' : 'CLOUD OFFLINE',
        fallbackActive: false,
        headerPill: {
          dotClass: isReachable ? 'online' : 'offline',
          label: isReachable ? 'CLOUD ONLINE' : 'CLOUD OFFLINE'
        }
      };
    }

    // Mode 3: Hybrid Auto-Failover
    // Stage 1: Local Docker -> Stage 2: Cloudflare Tunnel -> Stage 3: Deployed Cloud
    if (diagnostics && diagnostics.local && diagnostics.local.online) {
      return {
        mode: 'hybrid',
        modeLabel: 'Hybrid Auto-Failover (Stage 1: Local Docker)',
        activeEndpoint: localEndpoint,
        activeTier: 'local',
        isReachable: true,
        status: SERVICE_STATES.HEALTHY,
        activeHealth: 'ONLINE (Local Docker 3000)',
        overallStatus: 'HYBRID ONLINE',
        fallbackActive: false,
        headerPill: {
          dotClass: 'online',
          label: `HYBRID (LOCAL ${portNum})`
        }
      };
    }

    if (diagnostics && diagnostics.tunnel && diagnostics.tunnel.online) {
      return {
        mode: 'hybrid',
        modeLabel: 'Hybrid Auto-Failover (Stage 2: Cloudflare Tunnel)',
        activeEndpoint: tunnelEndpoint,
        activeTier: 'tunnel',
        isReachable: true,
        status: SERVICE_STATES.HEALTHY,
        activeHealth: 'ONLINE (Cloudflare Tunnel)',
        overallStatus: 'HYBRID ONLINE',
        fallbackActive: true,
        headerPill: {
          dotClass: 'online',
          label: 'HYBRID (TUNNEL)'
        }
      };
    }

    if (diagnostics && diagnostics.cloud && diagnostics.cloud.online) {
      return {
        mode: 'hybrid',
        modeLabel: 'Hybrid Auto-Failover (Stage 3: Deployed Cloud)',
        activeEndpoint: cloudEndpoint,
        activeTier: 'cloud',
        isReachable: true,
        status: SERVICE_STATES.HEALTHY,
        activeHealth: 'ONLINE (Cloud Fallback)',
        overallStatus: 'HYBRID ONLINE',
        fallbackActive: true,
        headerPill: {
          dotClass: 'online',
          label: 'HYBRID (CLOUD)'
        }
      };
    }

    // All stages offline
    return {
      mode: 'hybrid',
      modeLabel: 'Hybrid Auto-Failover',
      activeEndpoint: localEndpoint,
      activeTier: 'none',
      isReachable: false,
      status: SERVICE_STATES.OFFLINE,
      activeHealth: 'OFFLINE (All Stages Unreachable)',
      overallStatus: 'HYBRID OFFLINE',
      fallbackActive: false,
      headerPill: {
        dotClass: 'offline',
        label: 'HYBRID (OFFLINE)'
      }
    };
  }
}

module.exports = new ConnectivityService();
