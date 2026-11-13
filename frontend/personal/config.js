/**
 * CyberGuard Personal frontend configuration.
 * Configures the target Python FastAPI / WebSocket backend origin for static host deployments
 * (e.g. GitHub Pages at https://arthur-2407.github.io/CyberGuard/personal/ or Vercel).
 *
 * Precedence Order:
 * 1. URL query parameter: ?api_base=https://... or ?tunnel=https://... (persists to localStorage)
 * 2. Saved custom override: localStorage['cyberguard_api_base'] or localStorage['cyberguard_custom_tunnel']
 * 3. Localhost / loopback origin: http://127.0.0.1:3000 (direct port)
 * 4. Active Cloudflare Tunnel: bridges deployed HTTPS frontends (GitHub Pages & Vercel) to local Docker
 * 5. Same-origin relative fallback ("")
 */
window.__CYBERGUARD_PERSONAL_CONFIG__ = window.__CYBERGUARD_PERSONAL_CONFIG__ || {
  api_base: "",
  tunnel_url: "https://fax-heat-harris-sufficient.trycloudflare.com",
  cloud_backend_url: ""
};
