import pytest
import io
import wave
import struct
import numpy as np
from fastapi.testclient import TestClient

from backend.main import app
from backend.config import get_settings
from backend.threats.models import RiskLevel, ThreatCategory
from backend.analysis.unified_pipeline import UnifiedThreatPipeline
from backend.incidents.incident_manager import IncidentManager


@pytest.fixture
def client():
    return TestClient(app)


def _generate_test_wav(duration_sec=1.0, sample_rate=16000, freq=440.0):
    """Generate in-memory 16kHz mono PCM WAV bytes."""
    num_samples = int(duration_sec * sample_rate)
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        t = np.linspace(0, duration_sec, num_samples, endpoint=False)
        audio = (np.sin(2 * np.pi * freq * t) * 32767).astype(np.int16)
        wf.writeframes(audio.tobytes())
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_unified_pipeline_text_phishing():
    settings = get_settings()
    pipeline = UnifiedThreatPipeline(settings)

    phish_text = "URGENT: Your bank account is suspended immediately. Please login and verify your password now."
    result = await pipeline.analyze(text=phish_text, source="test_runner")

    event = result["event"]
    assert event.modality == "text"
    assert event.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)
    assert event.threat_category == ThreatCategory.PHISHING
    assert len(event.evidence) > 0
    assert any("urgency" in e.evidence_type or "credential" in e.evidence_type for e in event.evidence)
    assert event.mitre_technique_id == "T1566.002"
    assert len(result["pipeline_execution"]) > 0


@pytest.mark.asyncio
async def test_unified_pipeline_url():
    settings = get_settings()
    pipeline = UnifiedThreatPipeline(settings)

    test_url = "http://192.168.1.1/login/verify/bank/credential"
    result = await pipeline.analyze(url=test_url, source="test_runner")

    event = result["event"]
    assert event.modality == "url"
    assert event.severity in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert event.threat_category == ThreatCategory.MALICIOUS_URL
    assert event.mitre_technique_id == "T1071.001"


@pytest.mark.asyncio
async def test_unified_pipeline_local_ioc_protection():
    settings = get_settings()
    pipeline = UnifiedThreatPipeline(settings)

    local_target = "http://localhost:3000/"
    result = await pipeline.analyze(ioc=local_target, source="test_runner")

    event = result["event"]
    assert event.severity == RiskLevel.SAFE
    assert any(e.evidence_type == "local_private_indicator" for e in event.evidence)


@pytest.mark.asyncio
async def test_unified_pipeline_audio():
    settings = get_settings()
    pipeline = UnifiedThreatPipeline(settings)

    wav_bytes = _generate_test_wav(duration_sec=2.0)
    result = await pipeline.analyze(
        file_bytes=wav_bytes,
        filename="test_sample.wav",
        source="test_runner"
    )

    event = result["event"]
    assert event.modality == "audio"
    assert event.detector == "CyberGuard UnifiedThreatPipeline"
    assert any(e.source == "VoiceCloneDetector" for e in event.evidence)
    assert len(event.evidence) > 0
    assert "pipeline_execution" in result
    assert result["summary"]["category"] is not None


def test_unified_endpoint_api(client):
    # Test POST /api/threats/unified with text
    response = client.post(
        "/api/threats/unified",
        data={"text": "URGENT: Verify your account password immediately to avoid suspension."}
    )
    assert response.status_code == 200
    data = response.json()
    assert "event" in data
    assert "summary" in data
    assert "pipeline_execution" in data
    assert data["event"]["threat_category"] == "PHISHING"
    assert data["summary"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_unified_endpoint_api_file_upload(client):
    wav_bytes = _generate_test_wav(duration_sec=1.5)
    response = client.post(
        "/api/threats/unified",
        files={"file": ("test_voice.wav", wav_bytes, "audio/wav")}
    )
    assert response.status_code == 200
    data = response.json()
    assert "event" in data
    assert data["event"]["modality"] == "audio"
    assert data["event"]["detector"] == "CyberGuard UnifiedThreatPipeline"
    assert any(e["source"] == "VoiceCloneDetector" for e in data["event"]["evidence"])


def test_incident_manager_dashboard_summary():
    settings = get_settings()
    im = IncidentManager(settings, db_path=str(settings.abs_path(settings.storage.db_path)))
    summary = im.get_dashboard_summary()

    assert "total_incidents" in summary
    assert "open_incidents" in summary
    assert "total_events_analyzed" in summary
    assert "high_critical_threats" in summary
    assert "categories" in summary
    assert isinstance(summary["total_incidents"], int)
