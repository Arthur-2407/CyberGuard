/**
 * CyberGuard Dynamic Deployment Configuration
 *
 * Sourced by frontend/index.html before app.js.
 * Configures the target Python FastAPI / WebSocket backend origin for static host deployments
 * (e.g. GitHub Pages at https://arthur-2407.github.io/CyberGuard or Vercel at https://cyber-guard-backend-ashen.vercel.app).
 *
 * Precedence Order:
 *   1. Explicit URL query parameter: ?api_base=https://<your-endpoint> or ?tunnel=https://... (persists to localStorage)
 *   2. Active Connection Mode:
 *        - Mode A (Deployed Cloud): 'https://cyber-guard-backend-ashen.vercel.app' (or '' on Vercel)
 *        - Mode B (Local Docker): 'http://127.0.0.1:3000'
 *        - Mode C (Hybrid Auto): Local Docker -> Cloudflare Tunnel -> Cloud Backend
 *   3. window.__CYBERGUARD_CONFIG__.api_base (manual static override, default empty)
 *   4. Active Cloudflare Tunnel: bridges deployed HTTPS frontends (GitHub Pages & Vercel) to local Docker
 *   5. Current origin fallback ('' for local 127.0.0.1:3000 / reverse-proxy deployments)
 */
window.__CYBERGUARD_CONFIG__ = window.__CYBERGUARD_CONFIG__ || {
  api_base: "",
  tunnel_url: "https://fax-heat-harris-sufficient.trycloudflare.com",
  cloud_backend_url: "https://cyber-guard-backend-ashen.vercel.app"
};
