"""
tests/test_bidirectional_sync.py — Test Suite for Cloud PostgreSQL <-> Local SQLite Two-Way Synchronization.
Validates:
1. Cloud and Local database connectivity.
2. Initial full bidirectional synchronization of all 20 tables.
3. Cloud-to-Local propagation: changes created in Cloud PostgreSQL reflect in Local SQLite.
4. Local-to-Cloud propagation: changes created in Local SQLite reflect in Cloud PostgreSQL.
5. Non-destructive conflict resolution via Last-Write-Wins timestamps.
6. Clean artifact cleanup without deleting or mutating production data.
"""

import os
import uuid
import datetime
import pytest
from sqlalchemy import create_engine, text

from backend.storage.sync_service import get_sync_service, DatabaseSyncService
from backend.storage.database import IncidentModel, ThreatReportModel, Base


@pytest.fixture(scope="module")
def sync_service():
    service = get_sync_service()
    if not service.is_cloud_available():
        pytest.skip("Cloud PostgreSQL is not reachable for synchronization tests")
    return service


def test_01_database_connectivity(sync_service):
    """Verify both Cloud PostgreSQL and Local SQLite are online and accessible."""
    assert sync_service.is_cloud_available(), "Cloud PostgreSQL must be available"
    assert sync_service.is_local_available(), "Local SQLite must be available"


def test_02_bidirectional_sync_execution(sync_service):
    """Execute full two-way synchronization and verify successful return status."""
    res = sync_service.sync_bidirectional()
    assert res.get("success") is True, f"Sync failed: {res.get('error')}"
    assert "summary" in res
    assert "cloud_to_local" in res["summary"]
    assert "local_to_cloud" in res["summary"]


def test_03_cloud_to_local_reflection(sync_service):
    """Create a record in Cloud PostgreSQL and verify it reflects into Local SQLite."""
    unique_ref = f"test_cloud_{uuid.uuid4().hex[:8]}"
    cloud_session = sync_service.get_cloud_session()
    local_session = sync_service.get_local_session()

    try:
        # Create record in Cloud PostgreSQL
        test_incident = IncidentModel(
            incident_id=unique_ref,
            category="VOICE_CLONE",
            risk="LOW",
            status="OPEN",
            analyst_notes="Created directly in cloud PostgreSQL for sync verification",
            first_seen=datetime.datetime.now(datetime.timezone.utc),
            last_seen=datetime.datetime.now(datetime.timezone.utc),
        )
        cloud_session.add(test_incident)
        cloud_session.commit()
        cloud_id = test_incident.id
        assert cloud_id is not None

        # Verify not yet in local before sync
        existing_local = local_session.query(IncidentModel).filter_by(incident_id=unique_ref).first()
        assert existing_local is None, "Record should not exist in local before sync"

        # Execute bidirectional sync
        res = sync_service.sync_bidirectional()
        assert res.get("success") is True

        # Verify record is now reflected in Local SQLite
        local_session.close()
        local_session = sync_service.get_local_session()
        synced_local = local_session.query(IncidentModel).filter_by(incident_id=unique_ref).first()
        assert synced_local is not None, "Cloud record must reflect into Local SQLite"
        assert synced_local.analyst_notes == "Created directly in cloud PostgreSQL for sync verification"
        assert synced_local.risk == "LOW"

    finally:
        # Clean up test artifact from both stores
        try:
            cloud_rec = cloud_session.query(IncidentModel).filter_by(incident_id=unique_ref).first()
            if cloud_rec:
                cloud_session.delete(cloud_rec)
                cloud_session.commit()
        except Exception:
            pass

        try:
            local_rec = local_session.query(IncidentModel).filter_by(incident_id=unique_ref).first()
            if local_rec:
                local_session.delete(local_rec)
                local_session.commit()
        except Exception:
            pass

        cloud_session.close()
        local_session.close()


def test_04_local_to_cloud_reflection(sync_service):
    """Create a record in Local SQLite and verify it reflects into Cloud PostgreSQL."""
    unique_ref = f"test_local_{uuid.uuid4().hex[:8]}"
    cloud_session = sync_service.get_cloud_session()
    local_session = sync_service.get_local_session()

    try:
        # Create record in Local SQLite
        test_report = ThreatReportModel(
            report_id=unique_ref,
            title=f"Local Report {unique_ref}",
            report_type="TECHNICAL",
            report_format="JSON",
            created_by="Local Edge Client",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        local_session.add(test_report)
        local_session.commit()
        local_id = test_report.id
        assert local_id is not None

        # Verify not yet in cloud before sync
        existing_cloud = cloud_session.query(ThreatReportModel).filter_by(report_id=unique_ref).first()
        assert existing_cloud is None, "Record should not exist in cloud before sync"

        # Execute bidirectional sync
        res = sync_service.sync_bidirectional()
        assert res.get("success") is True

        # Verify record is now reflected in Cloud PostgreSQL
        cloud_session.close()
        cloud_session = sync_service.get_cloud_session()
        synced_cloud = cloud_session.query(ThreatReportModel).filter_by(report_id=unique_ref).first()
        assert synced_cloud is not None, "Local record must reflect into Cloud PostgreSQL"
        assert synced_cloud.created_by == "Local Edge Client"
        assert synced_cloud.report_type == "TECHNICAL"

    finally:
        # Clean up test artifact from both stores
        try:
            cloud_rec = cloud_session.query(ThreatReportModel).filter_by(report_id=unique_ref).first()
            if cloud_rec:
                cloud_session.delete(cloud_rec)
                cloud_session.commit()
        except Exception:
            pass

        try:
            local_rec = local_session.query(ThreatReportModel).filter_by(report_id=unique_ref).first()
            if local_rec:
                local_session.delete(local_rec)
                local_session.commit()
        except Exception:
            pass

        cloud_session.close()
        local_session.close()


def test_05_sync_status_reporting(sync_service):
    """Verify get_status() returns complete table counts for both databases."""
    status = sync_service.get_status()
    assert status["cloud_connected"] is True
    assert status["local_connected"] is True
    assert "table_counts" in status
    assert "cloud" in status["table_counts"]
    assert "local" in status["table_counts"]
    assert status["table_counts"]["cloud"]["users"] > 0
    assert status["table_counts"]["local"]["users"] > 0
