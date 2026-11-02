# CyberGuard Personal Frontend

A consumer-friendly interface served under `/personal/` alongside the existing CyberGuard SOC console. The SOC console remains the default homepage.

## Local preview

Run a static server from the repository's `frontend/` directory:

```bash
python -m http.server 3001
```

Open `http://127.0.0.1:3001/personal/`. Serving this directory directly also works for an isolated preview.

## Backend connection and pipeline compatibility

The Personal interface calls the existing FastAPI endpoints; it does not add a separate API or analysis engine. It reads the same browser settings as the SOC console: local/cloud/hybrid mode, local port, active hybrid backend, custom tunnel, `cyberguard_api_base`, and the existing authentication token keys. It sends the same bearer/session headers and includes browser credentials.

- Link: `POST /api/threats/url` (`url` multipart field)
- File: `POST /api/threats/unified` (`file` multipart field)
- Image forensics: `POST /api/threats/image` (`file` multipart field)
- QR code: `POST /api/threats/qr` (`file` multipart field)
- Voice: `POST /api/threats/deepfake` (`file` multipart field)
- Health: `GET /health`

Vercel continues to proxy `/api/*` and `/health` to the existing backend. On GitHub Pages, the consumer frontend uses the same deployed backend origin as the SOC frontend, unless local, hybrid, or custom backend mode is selected in shared browser storage.

## Switching and preservation

- SOC remains at the root and is the default.
- SOC navigation links to `/personal/`; Personal navigation links back to the SOC root.
- Switching pages does not stop services, clear data, change connection mode, or modify backend processes.
- Existing SOC HTML, JavaScript, styles, backend, Android app, and route handlers are preserved. Consumer assets are contained in `frontend/personal/`.

## Privacy and interpretation

- Consumer check history is local to this browser.
- Uploaded files are sent to the configured backend for analysis.
- Automated analysis is indicative, not proof. Clean results cannot guarantee safety; voice and image classifiers can make mistakes.
- Use HTTPS for remote backends and configure server-side CORS, authentication, and upload limits.
- Never put API keys or secrets in this public static frontend.
