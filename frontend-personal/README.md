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

The frontend uses the existing FastAPI route contracts found in `backend/api/routes_threats.py`:
- Link: `POST /api/threats/url` with multipart field `url`
- File: `POST /api/threats/unified` with multipart field `file`
- Image: `POST /api/threats/image` with multipart field `file`
- Voice: `POST /api/threats/deepfake` with multipart field `file`
- Backend health: `GET /health`

The backend also exposes a dedicated QR route at `POST /api/threats/qr`; the current image upload flow uses the general image-forensics route. A QR-specific mode can be wired to that route after the desired UI behavior is selected.

## Deployment isolation

This directory is not wired into the existing GitHub Pages or Vercel deployment. The current Pages workflow still publishes `frontend/`, and the existing Vercel configuration is unchanged. Deploy this directory as a separate static site/project or add a dedicated workflow after reviewing the desired public URL.

## Privacy and interpretation

- Scan history is stored only in this browser's localStorage.
- Uploaded media is sent to the configured backend.
- Automated analysis is indicative, not proof. A clean result cannot guarantee safety; voice/image classifiers can make mistakes.
- Use HTTPS for remote backend connections and configure server-side CORS, authentication and upload limits.
- No API keys or secrets belong in this static frontend.
