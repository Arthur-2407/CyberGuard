/**
 * CyberGuard Dynamic Deployment Configuration
 *
 * Sourced by frontend/index.html before app.js.
 * Configures the target Python FastAPI / WebSocket backend origin for static host deployments
 * (e.g. GitHub Pages at https://arthur-2407.github.io/CyberGuard or Vercel at https://cyber-guard-backend-ashen.vercel.app).
 *
 * Architecture:
 * - Vercel and GitHub Pages frontends stay online 24/7.
 * - The CyberGuard backend runs in Docker or on hosted cloud infrastructure.
 *
 * Precedence Order:
 *   1. URL query parameter: ?api_base=https://<your-endpoint> (persists to localStorage)
 *   2. localStorage key: 'cyberguard_api_base' (saved via UI Backend Console / setCyberGuardApiBase)
 *   3. window.__CYBERGUARD_CONFIG__.api_base (manual static override, default empty)
 *   4. Current origin fallback ('' for local 127.0.0.1:3000 / reverse-proxy deployments)
 */
window.__CYBERGUARD_CONFIG__ = window.__CYBERGUARD_CONFIG__ || {
  api_base: " \n};
