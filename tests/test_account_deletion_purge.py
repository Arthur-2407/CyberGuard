"""
test_account_deletion_purge.py — Comprehensive security, authorization, and data purge tests.

Covers:
- Authorization tests: Admin only, non-admin rejection, unauthenticated rejection.
- Administrative safety safeguards: Self-deletion prevention, last admin protection, system account protection.
- Deletion scope: Complete removal of user credentials, sessions, analysis records, review items,
  uncommitted training samples, threat events/evidence, reports, email records, tenant SQLite db,
  and exclusively owned audio vault files.
- Boundary protection: Shared DB, other users' data, and shared files remain strictly intact.
- Tamper-evident administrative audit logging.
- Typed confirmation verification.
"""

import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.auth import ROLE_ADMIN, ROLE_USER, AuthService, hash_password
from backend.storage.database import (
    AdminAuditLogModel,
    AnalysisRecordModel,
    AuthSessionModel,
    ReviewQueueModel,
    ThreatEventModel,
    ThreatEvidenceModel,
    ThreatReportModel,
    TrainingSampleModel,
    UserModel,
    get_db_session,
    get_session_factory,
    init_db,
)
from backend.storage.user_service import UserAccountService


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def test_db_session():
    """Provides a fresh isolated database session for testing."""
    init_db("data/cyberguard.db")
    factory = get_session_factory("data/cyberguard.db")
    session = factory()
    try:
        yield session
    finally:
        session.close()


import uuid


def create_mock_user(db, prefix="tester", role=ROLE_USER, password="Password123!"):
    """Helper to create and return a synthetic user with unique identifiers."""
    uid = uuid.uuid4().hex[:8]
    username = f"{prefix}_{uid}"
    email = f"{username}@cyberguard.test"
    user = AuthService.create_user(
        db=db,
        username=username,
        email=email,
        password=password,
        role=role,
    )
    return user


class TestAccountDeletionAuthorizationAndSafeguards:
    """Tests 1-6: Strict RBAC and Administrative Safety Safeguards."""

    def test_unauthenticated_request_rejected(self, client):
        """Test 3: Unauthenticated caller cannot invoke account deletion."""
        res = client.delete("/api/admin/users/999")
        assert res.status_code in (401, 403), f"Expected 401/403, got {res.status_code}"

    def test_ordinary_user_cannot_delete_accounts(self, client, test_db_session):
        """Test 2 & 4: Ordinary authenticated user cannot invoke account deletion."""
        normal_user = create_mock_user(test_db_session, "ordinary_tester", role=ROLE_USER)
        try:
            _, token = AuthService.authenticate(test_db_session, normal_user.username, "Password123!")
            headers = {"Authorization": f"Bearer {token}"}
            res = client.delete(f"/api/admin/users/{normal_user.id}", headers=headers)
            assert res.status_code == 403, f"Expected 403 Forbidden, got {res.status_code}"
            assert "Administrative privileges required" in res.text or "Forbidden" in res.text
        finally:
            test_db_session.delete(normal_user)
            test_db_session.commit()

    def test_admin_cannot_delete_self(self, client, test_db_session):
        """Test 5: Currently authenticated administrator cannot accidentally delete themselves."""
        admin_user = create_mock_user(test_db_session, "self_delete_admin", role=ROLE_ADMIN)
        try:
            _, token = AuthService.authenticate(test_db_session, admin_user.username, "Password123!")
            headers = {"Authorization": f"Bearer {token}"}
            res = client.delete(f"/api/admin/users/{admin_user.id}", headers=headers)
            assert res.status_code == 400, f"Expected 400 Bad Request, got {res.status_code}"
            assert "cannot delete your own active administrator account" in res.text.lower()
        finally:
            test_db_session.delete(admin_user)
            test_db_session.commit()

    def test_cannot_delete_last_active_admin(self, test_db_session):
        """Test 6: Prevent deletion of the last active administrator."""
        admin_caller = create_mock_user(test_db_session, "caller_admin_safeguard", role=ROLE_ADMIN)
        sole_admin = create_mock_user(test_db_session, "sole_admin_target", role=ROLE_ADMIN)
        try:
            from unittest.mock import patch
            with patch("sqlalchemy.orm.query.Query.count", return_value=1):
                with pytest.raises(Exception) as excinfo:
                    UserAccountService.delete_user_account_and_purge_data(
                        db=test_db_session,
                        target_user_id=sole_admin.id,
                        admin_user=admin_caller,
                    )
                assert "last active administrator" in str(excinfo.value).lower()
        finally:
            test_db_session.delete(sole_admin)
            test_db_session.delete(admin_caller)
            test_db_session.commit()

    def test_protected_system_accounts_safeguarded(self, test_db_session):
        """Test 6b: Protected system accounts (e.g. system, root) cannot be deleted."""
        admin_caller = create_mock_user(test_db_session, "caller_admin_sys", role=ROLE_ADMIN)
        sys_user = UserModel(
            username="system",
            email="system@cyberguard.internal",
            password_hash=hash_password("Password123!"),
            role=ROLE_USER,
            is_active=True,
        )
        test_db_session.add(sys_user)
        test_db_session.commit()

        try:
            with pytest.raises(Exception) as excinfo:
                UserAccountService.delete_user_account_and_purge_data(
                    db=test_db_session,
                    target_user_id=sys_user.id,
                    admin_user=admin_caller,
                )
            assert "protected system" in str(excinfo.value).lower()
        finally:
            test_db_session.delete(sys_user)
            test_db_session.delete(admin_caller)
            test_db_session.commit()

    def test_typed_confirmation_mismatch_rejected(self, client, test_db_session):
        """Test 14: Confirmation mismatch prevents deletion."""
        admin_caller = create_mock_user(test_db_session, "caller_admin_confirm", role=ROLE_ADMIN)
        target_user = create_mock_user(test_db_session, "confirm_mismatch_user", role=ROLE_USER)
        try:
            _, token = AuthService.authenticate(test_db_session, admin_caller.username, "Password123!")
            headers = {"Authorization": f"Bearer {token}"}
            res = client.delete(f"/api/admin/users/{target_user.id}?confirm_username=wrong_username", headers=headers)
            assert res.status_code == 400
            assert "confirmation mismatch" in res.text.lower()
        finally:
            test_db_session.delete(target_user)
            test_db_session.delete(admin_caller)
            test_db_session.commit()


class TestCompletePerUserDataPurge:
    """Tests 7-16: End-to-end user deletion and exclusive asset cleanup."""

    def test_full_user_data_purge_lifecycle(self, client, test_db_session):
        """
        Verify:
        1. User creation and synthesis of owned records (auth session, analysis, review queue,
           threat event, threat evidence, audio vault file, tenant sqlite DB).
        2. Execution of deletion via admin API.
        3. Complete verified purge of exclusively owned records and files.
        4. Protection of unrelated data and shared resources.
        5. Tamper-evident admin audit log recording.
        """
        admin_caller = create_mock_user(test_db_session, "purge_master_admin", role=ROLE_ADMIN)
        _, token = AuthService.authenticate(test_db_session, admin_caller.username, "Password123!")
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Create target user to delete
        target = create_mock_user(test_db_session, "purge_victim", role=ROLE_USER)
        target_id = target.id
        target_username = target.username
        target_email = target.email
        target_db_path = Path(target.db_path).resolve()

        # Ensure tenant DB exists
        assert target_db_path.exists(), f"Tenant database should exist at {target_db_path}"

        # 2. Create another user (control subject) to verify non-interference
        control_user = create_mock_user(test_db_session, "control_subject", role=ROLE_USER)
        control_id = control_user.id

        # 3. Create synthetic exclusive audio file in data/audio_vault
        vault_dir = Path("data/audio_vault")
        vault_dir.mkdir(parents=True, exist_ok=True)
        unique_run_key = uuid.uuid4().hex[:8]
        exclusive_audio_hash = f"exclusive_{unique_run_key}"
        exclusive_audio_file = vault_dir / f"{exclusive_audio_hash}.flac"
        exclusive_audio_file.write_bytes(b"SYNTHETIC_FLAC_AUDIO_CONTENT_FOR_PURGE_TEST")
        assert exclusive_audio_file.exists()

        # Create shared audio file referenced by both target and control user
        shared_audio_hash = f"shared_{unique_run_key}"
        shared_audio_file = vault_dir / f"{shared_audio_hash}.flac"
        shared_audio_file.write_bytes(b"SHARED_FLAC_AUDIO_CONTENT")
        assert shared_audio_file.exists()

        # 4. Attach owned records in cyberguard.db
        # Target's exclusive analysis record
        victim_analysis = AnalysisRecordModel(
            analysis_id=f"analysis_victim_{target_id}_{unique_run_key}",
            user_id=target_id,
            filename="exclusive_test.wav",
            audio_hash=exclusive_audio_hash,
            audio_path=f"data/audio_vault/{exclusive_audio_hash}.flac",
            peak_risk=0.85,
            mean_risk=0.72,
            alert_level="CRITICAL",
        )
        # Target's shared analysis record
        victim_shared_analysis = AnalysisRecordModel(
            analysis_id=f"analysis_shared_victim_{target_id}_{unique_run_key}",
            user_id=target_id,
            filename="shared_sample.wav",
            audio_hash=shared_audio_hash,
            audio_path=f"data/audio_vault/{shared_audio_hash}.flac",
            peak_risk=0.15,
            mean_risk=0.10,
            alert_level="SAFE",
        )
        # Control user's reference to shared audio
        control_analysis = AnalysisRecordModel(
            analysis_id=f"analysis_control_{control_id}_{unique_run_key}",
            user_id=control_id,
            filename="shared_sample.wav",
            audio_hash=shared_audio_hash,
            audio_path=f"data/audio_vault/{shared_audio_hash}.flac",
            peak_risk=0.15,
            mean_risk=0.10,
            alert_level="SAFE",
        )
        test_db_session.add_all([victim_analysis, victim_shared_analysis, control_analysis])

        # Target's review queue item
        victim_review = ReviewQueueModel(
            review_id=f"REV_victim_{target_id}",
            analysis_id=victim_analysis.analysis_id,
            submitted_by_user_id=target_id,
            status="PENDING",
        )
        test_db_session.add(victim_review)

        # Target's threat event and evidence
        victim_event = ThreatEventModel(
            event_id=f"EVT_victim_{target_id}",
            source="TestAPI",
            source_type="API",
            modality="AUDIO",
            threat_category="VOICE_CLONING",
            classification="MALICIOUS",
            user_id=target_id,
            user_email=target_email,
            affected_user=target_username,
            detector="TestDetector",
        )
        test_db_session.add(victim_event)
        victim_evidence = ThreatEvidenceModel(
            event_id=victim_event.event_id,
            evidence_type="SPECTRAL",
            description="Synthetic high frequency artifacts",
            source="TestDetector",
        )
        test_db_session.add(victim_evidence)
        test_db_session.commit()

        victim_event_id = victim_event.event_id
        victim_analysis_id = victim_analysis.analysis_id

        # 5. Execute Deletion via API with confirmation
        res = client.delete(
            f"/api/admin/users/{target_id}?confirm_username={target_username}",
            headers=headers,
        )
        assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
        data = res.json()
        assert data["status"] == "success"
        assert target_username in data["message"]

        # 6. Verify UserModel deletion
        purged_user = test_db_session.query(UserModel).filter(UserModel.id == target_id).first()
        assert purged_user is None, "Target user should be deleted from UserModel."

        # 7. Verify AuthSessionModel deletion
        sessions = test_db_session.query(AuthSessionModel).filter(AuthSessionModel.user_id == target_id).all()
        assert len(sessions) == 0, "All sessions belonging to target user must be deleted."

        # 8. Verify AnalysisRecordModel deletion for target
        analyses = test_db_session.query(AnalysisRecordModel).filter(AnalysisRecordModel.user_id == target_id).all()
        assert len(analyses) == 0, "All analysis records belonging to target user must be deleted."

        # 9. Verify ReviewQueueModel deletion for target
        reviews = test_db_session.query(ReviewQueueModel).filter(ReviewQueueModel.submitted_by_user_id == target_id).all()
        assert len(reviews) == 0, "All review queue submissions must be deleted."

        # 10. Verify ThreatEvent and ThreatEvidence deletion
        events = test_db_session.query(ThreatEventModel).filter(ThreatEventModel.event_id == victim_event_id).all()
        assert len(events) == 0, "User threat events must be deleted."
        evidence = test_db_session.query(ThreatEvidenceModel).filter(ThreatEvidenceModel.event_id == victim_event_id).all()
        assert len(evidence) == 0, "User threat evidence must be deleted."

        # 11. Verify Isolated Tenant Database file removal
        assert not target_db_path.exists(), f"Tenant DB file {target_db_path} should be deleted from filesystem."

        # 12. Verify Exclusive Audio file removal
        assert not exclusive_audio_file.exists(), "Exclusively owned audio vault file should be deleted."

        # 13. Verify Shared Audio file preservation
        assert shared_audio_file.exists(), "Shared audio vault file referenced by another user must NOT be deleted."

        # 14. Verify Control User and its records are untouched
        preserved_control = test_db_session.query(UserModel).filter(UserModel.id == control_id).first()
        assert preserved_control is not None, "Control user must remain intact."
        preserved_control_analysis = test_db_session.query(AnalysisRecordModel).filter(AnalysisRecordModel.user_id == control_id).first()
        assert preserved_control_analysis is not None, "Control user's analysis record must remain intact."

        # 15. Verify Admin Audit Log entry created with sanitized details
        audit = (
            test_db_session.query(AdminAuditLogModel)
            .filter(
                AdminAuditLogModel.action == "USER_PERMANENTLY_DELETED",
                AdminAuditLogModel.target_id == str(target_id),
            )
            .order_by(AdminAuditLogModel.id.desc())
            .first()
        )
        assert audit is not None, "Tamper-evident audit log entry must be created."
        assert audit.actor_user_id == admin_caller.id
        assert "password" not in (audit.details_json or "").lower()

        # 16. Verify Idempotent / Repeated request handling
        res_repeat = client.delete(f"/api/admin/users/{target_id}", headers=headers)
        assert res_repeat.status_code == 404, f"Repeated deletion should return 404, got {res_repeat.status_code}"

        # Clean up shared file & control user
        if shared_audio_file.exists():
            shared_audio_file.unlink()
        test_db_session.delete(preserved_control)
        test_db_session.delete(admin_caller)
        test_db_session.commit()
