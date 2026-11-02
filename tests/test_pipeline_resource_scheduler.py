"""
tests/test_pipeline_resource_scheduler.py — Verification of Intelligent Resource Orchestrator.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.resource_scheduler import (
    get_pipeline_scheduler,
    PipelineFeature,
    ExecutionState,
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_scheduler_status_endpoint(client):
    """Verify /api/scheduler/status returns accurate diagnostic telemetry and health."""
    resp = client.get("/api/scheduler/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "active_heavy_jobs" in data
    assert data["max_concurrent_heavy_jobs"] >= 1
    assert "essential_services_status" in data
    services = data["essential_services_status"]
    assert services["auth"] == "ONLINE"
    assert services["database"] == "ONLINE"
    assert services["email_notifications"] == "ONLINE"
    assert services["health_monitoring"] == "ONLINE"


@pytest.mark.asyncio
async def test_scheduler_session_isolation_and_admission():
    """Verify session-level reservation and admission concurrency."""
    scheduler = get_pipeline_scheduler()
    job1 = await scheduler.acquire_pipeline_execution(
        feature=PipelineFeature.VOICE_ANALYSIS,
        session_id="session-user-alpha",
        user_id=1,
    )
    assert job1.state in (ExecutionState.QUEUED, ExecutionState.READY, ExecutionState.ACTIVE)

    # Execute dummy workload
    async def dummy_workload():
        return {"synthetic_prob": 0.12}

    res = await scheduler.run_with_admission(job1, dummy_workload)
    assert res == {"synthetic_prob": 0.12}
    assert job1.state == ExecutionState.COMPLETED
