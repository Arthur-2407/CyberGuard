"""
verify_all_pipelines.py — Comprehensive live verification of all CyberGuard
pipelines and connections.
"""

import asyncio
import io
import json
import os
import sys
import wave
import numpy as np
import httpx
import websockets

BASE_URL = "http://127.0.0.1:3000"
WS_URL = "ws://127.0.0.1:3000/ws/stream"

passed = []
failed = []

def record_result(name: str, success: bool, detail: str = ""):
    if success:
        print(f"  [PASS] {name} {detail}")
        passed.append(name)
    else:
        print(f"  [FAIL] {name}: {detail}")
        failed.append((name, detail))

def make_test_wav(duration_sec=1.5, sr=16000, freq=440.0) -> bytes:
    num_samples = int(duration_sec * sr)
    t = np.linspace(0, duration_sec, num_samples, endpoint=False)
    audio = (0.5 * np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        wf.writeframes(audio.tobytes())
    return buf.getvalue()

def make_test_qr_png(data="https://google.com") -> bytes:
    import qrcode
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue()

async def test_rest_endpoints():
    print("\n--- 1. Testing Core & Frontend Endpoints ---")
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=15.0) as client:
        # Health
        try:
            r = await client.get("/health")
            record_result("GET /health", r.status_code == 200, f"({r.status_code}) -> {r.json().get('status')}")
        except Exception as e:
            record_result("GET /health", False, str(e))

        # Root HTML
        try:
            r = await client.get("/")
            record_result("GET / (Frontend index.html)", r.status_code == 200 and "CyberGuard" in r.text, f"({r.status_code})")
        except Exception as e:
            record_result("GET / (Frontend index.html)", False, str(e))

        # Static assets
        try:
            r = await client.get("/static/app.js")
            record_result("GET /static/app.js", r.status_code == 200, f"({r.status_code}) size: {len(r.text)} bytes")
        except Exception as e:
            record_result("GET /static/app.js", False, str(e))

        try:
            r = await client.get("/static/styles.css")
            record_result("GET /static/styles.css", r.status_code == 200, f"({r.status_code}) size: {len(r.text)} bytes")
        except Exception as e:
            record_result("GET /static/styles.css", False, str(e))

        print("\n--- 2. Testing Configuration & Alerts Pipelines ---")
        try:
            r = await client.get("/api/config/thresholds")
            record_result("GET /api/config/thresholds", r.status_code == 200, str(r.json()))
        except Exception as e:
            record_result("GET /api/config/thresholds", False, str(e))

        try:
            r = await client.get("/api/alerts/recent")
            record_result("GET /api/alerts/recent", r.status_code == 200, f"alerts: {len(r.json().get('alerts', []))}")
        except Exception as e:
            record_result("GET /api/alerts/recent", False, str(e))

        print("\n--- 3. Testing Threat Intel Provider Connections ---")
        try:
            r = await client.get("/api/threats/virustotal/status")
            data = r.json()
            record_result("VirusTotal Provider", r.status_code == 200 and data.get("status") == "READY", f"Status: {data.get('status')}")
        except Exception as e:
            record_result("VirusTotal Provider", False, str(e))

        try:
            r = await client.get("/api/threats/urlhaus/status")
            data = r.json()
            record_result("URLhaus Provider", r.status_code == 200 and data.get("status") == "READY", f"Status: {data.get('status')}")
        except Exception as e:
            record_result("URLhaus Provider", False, str(e))

        print("\n--- 4. Testing Incident Management Pipeline & DB ---")
        try:
            r = await client.get("/api/incidents/dashboard/summary")
            data = r.json()
            record_result("Incident Dashboard Summary", r.status_code == 200, f"total: {data.get('total_incidents')}, open: {data.get('open_incidents')}")
        except Exception as e:
            record_result("Incident Dashboard Summary", False, str(e))

        try:
            r = await client.get("/api/incidents/")
            data = r.json()
            record_result("Incidents List", r.status_code == 200 and isinstance(data, list), f"retrieved {len(data)} incidents")
        except Exception as e:
            record_result("Incidents List", False, str(e))

        print("\n--- 5. Testing Speaker Registry & Enrollment Pipeline ---")
        try:
            r = await client.get("/api/speakers")
            speakers = r.json()
            record_result("GET /api/speakers", r.status_code == 200, f"{len(speakers)} registered speakers")
        except Exception as e:
            record_result("GET /api/speakers", False, str(e))

        test_speaker_id = "test_pipeline_speaker"
        wav_data = make_test_wav(duration_sec=2.0)
        try:
            files = [("files", ("test.wav", wav_data, "audio/wav"))]
            data = {"name": "Pipeline Verification User", "speaker_id": test_speaker_id, "organization": "CyberGuard QA"}
            r = await client.post("/api/speakers/enroll", data=data, files=files)
            record_result("POST /api/speakers/enroll", r.status_code == 200, f"enrolled: {r.json().get('speaker_id')}")
        except Exception as e:
            record_result("POST /api/speakers/enroll", False, str(e))

        try:
            r = await client.delete(f"/api/speakers/{test_speaker_id}")
            record_result("DELETE /api/speakers/{id}", r.status_code == 200, f"deleted {test_speaker_id}")
        except Exception as e:
            record_result("DELETE /api/speakers/{id}", False, str(e))

        print("\n--- 6. Testing Audio Analysis Pipeline (REST) ---")
        try:
            files = {"file": ("audio_sample.wav", wav_data, "audio/wav")}
            r = await client.post("/api/analyze", files=files)
            data = r.json()
            record_result("POST /api/analyze (Audio File)", r.status_code == 200, f"risk: {data.get('final_risk')}, alert: {data.get('alert_level')}")
        except Exception as e:
            record_result("POST /api/analyze (Audio File)", False, str(e))

        print("\n--- 7. Testing Threat Analysis Pipelines ---")
        # Phishing analysis
        try:
            r = await client.post("/api/threats/phishing", data={"text": "URGENT: Your account has been suspended. Please login to verify your account immediately."})
            data = r.json()
            record_result("POST /api/threats/phishing", r.status_code == 200 and data.get("threat_category") == "PHISHING", f"risk: {data.get('severity')}")
        except Exception as e:
            record_result("POST /api/threats/phishing", False, str(e))

        # URL analysis
        try:
            r = await client.post("/api/threats/url", data={"url": "http://192.168.1.1/login/verify/credentials"})
            data = r.json()
            record_result("POST /api/threats/url", r.status_code == 200 and data.get("threat_category") == "MALICIOUS_URL", f"risk: {data.get('severity')}")
        except Exception as e:
            record_result("POST /api/threats/url", False, str(e))

        # QR analysis
        try:
            qr_bytes = make_test_qr_png("http://phishing-site.example.com/login")
            r = await client.post("/api/threats/qr", files={"file": ("test_qr.png", qr_bytes, "image/png")})
            data = r.json()
            record_result("POST /api/threats/qr", r.status_code == 200, f"category: {data.get('threat_category')}, risk: {data.get('severity')}")
        except Exception as e:
            record_result("POST /api/threats/qr", False, str(e))

        # Deepfake analysis (audio/video/image)
        try:
            r = await client.post("/api/threats/deepfake", files={"file": ("sample.wav", wav_data, "audio/wav")})
            data = r.json()
            record_result("POST /api/threats/deepfake", r.status_code == 200, f"modality: {data.get('modality')}, risk: {data.get('severity')}")
        except Exception as e:
            record_result("POST /api/threats/deepfake", False, str(e))

        # Anomaly detection event ingestion
        try:
            event_payload = {
                "user_agent": "curl/7.68.0",
                "ip_address": "45.33.32.156",
                "request_rate": 150,
                "endpoint": "/api/login",
                "auth_failure_count": 8
            }
            r = await client.post("/api/threats/events", json=event_payload)
            data = r.json()
            record_result("POST /api/threats/events", r.status_code == 200, f"severity: {data.get('severity')}")
        except Exception as e:
            record_result("POST /api/threats/events", False, str(e))

        # Unified Multi-Modal Pipeline
        try:
            r = await client.post("/api/threats/unified", data={"text": "Security Alert: Verify your one-time code to prevent card closure."})
            data = r.json()
            record_result("POST /api/threats/unified (Multi-Modal)", r.status_code == 200 and "event" in data, f"risk: {data.get('summary', {}).get('risk_level')}")
        except Exception as e:
            record_result("POST /api/threats/unified (Multi-Modal)", False, str(e))

        # IOC Search & Correlation lookup
        try:
            r = await client.get("/api/threats/search", params={"ioc": "http://101.205.70.39:58301/bin.sh"})
            data = r.json()
            record_result("GET /api/threats/search", r.status_code == 200, f"category: {data.get('threat_category')}, risk: {data.get('severity')}")
        except Exception as e:
            record_result("GET /api/threats/search", False, str(e))


async def test_websocket_pipeline():
    print("\n--- 8. Testing WebSocket Real-Time Audio Pipeline ---")
    try:
        async with websockets.connect(WS_URL, close_timeout=5.0) as ws:
            # 1. Expect session_start
            init_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            data = json.loads(init_msg)
            is_start = data.get("type") == "session_start"
            record_result("WebSocket Connection & Handshake", is_start, f"session_id: {data.get('session_id')}, detector_ready: {data.get('detector_ready')}")

            # 2. Send 2 seconds of 16kHz PCM audio bytes in chunks (audible sine wave so VAD detects speech)
            t = np.linspace(0, 2.0, 32000, endpoint=False)
            raw_pcm = (0.5 * np.sin(2 * np.pi * 440.0 * t) * 32767).astype(np.int16).tobytes()
            # Send in 0.5s slices (16000 bytes)
            chunk_size = 16000
            for i in range(0, len(raw_pcm), chunk_size):
                await ws.send(raw_pcm[i:i + chunk_size])
                await asyncio.sleep(0.05)

            # 3. Await risk update (loop to skip any initial status_update)
            is_update = False
            update_data = {}
            for _ in range(5):
                update_msg = await asyncio.wait_for(ws.recv(), timeout=10.0)
                update_data = json.loads(update_msg)
                if update_data.get("type") in ("risk_update", "alert"):
                    is_update = True
                    break
            record_result("WebSocket Real-Time Risk Inference", is_update, f"type: {update_data.get('type')}, risk_score: {update_data.get('risk_score')}, alert_level: {update_data.get('alert_level')}")

    except Exception as e:
        record_result("WebSocket Real-Time Pipeline", False, str(e))


async def main():
    print("======================================================================")
    print(" CyberGuard Live System Pipeline & Connection Diagnostic")
    print("======================================================================")
    await test_rest_endpoints()
    await test_websocket_pipeline()
    print("\n======================================================================")
    print(f" Summary: {len(passed)} PASSED, {len(failed)} FAILED")
    print("======================================================================")
    if failed:
        for f, err in failed:
            print(f" - {f}: {err}")
        sys.exit(1)
    else:
        print("ALL PIPELINES AND CONNECTIONS ARE HEALTHY AND FULLY OPERATIONAL!")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
