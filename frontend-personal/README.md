# CyberGuard Personal Frontend

A separate, consumer-friendly interface for selected CyberGuard security services. It is intentionally isolated from the existing SOC console.

## Local preview

Serve this directory with any static web server (do not open the HTML file directly if you want API requests to work):

```bash
python -m http.server 3001
```

Open http://127.0.0.1:3001.

## Backend configuration

- Set `api_base` in `config.js`, or
- Open the app with `?api_base=https://your-backend.example`, or
- Set the backend address under Settings.

The frontend tries the following existing API route families:
- Link: `/api/threats/url`, then `/api/threats/phishing`
- File: `/api/threats/malware`, then `/api/threats/file`
- Image / QR: `/api/threats/media`, then `/api/threats/qr`
- Audio: `/api/threats/media`
- Health: `/health`

**Important:** the backend must expose compatible HTTP methods and multipart field names. The current frontend does not claim that every route is available; it reports endpoint/network errors instead of manufacturing a result. Confirm the deployed backend's exact request schemas and CORS allow-list before production use. Do not place API secrets in this static frontend.

## Deployment isolation

This directory is not wired into the existing GitHub Pages or Vercel deployment. The current Pages workflow still publishes `frontend/`, and the existing Vercel configuration is unchanged. Deploy this directory as a separate static site/project or add a dedicated workflow after reviewing the desired public URL.

## Privacy and interpretation

- Scan history is stored only in this browser's localStorage.
- Uploaded media is sent to the configured backend.
- Automated analysis is indicative, not proof. A clean result cannot guarantee safety; voice/image classifiers can make mistakes.
- Use HTTPS for remote backend connections and configure server-side CORS, authentication and upload limits.
