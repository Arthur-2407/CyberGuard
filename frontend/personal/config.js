/**
 * CyberGuard Personal frontend configuration.
 * Set api_base to a trusted backend origin when deploying separately.
 * Do not put API keys, tokens, passwords or other secrets in this file.
 *
 * Runtime override order:
 * 1. ?api_base=https://backend.example (saved in localStorage)
 * 2. localStorage: cyberguard_personal_api_base
 * 3. this api_base value
 * 4. same-origin relative API requests
 */
window.__CYBERGUARD_PERSONAL_CONFIG__ = window.__CYBERGUARD_PERSONAL_CONFIG__ || {
  api_base: ""
};