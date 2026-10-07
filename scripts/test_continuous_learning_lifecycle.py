import time
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.storage.database import get_session_factory, TrainingRunModel, ModelVersionModel, TrainingSampleModel
from backend.services.continuous_learning import ContinuousLearningService

factory = get_session_factory("data/cyberguard.db")
db = factory()

# Record active production version so test rollback restores it rather than hardcoded v001
initial_mv = db.query(ModelVersionModel).filter(ModelVersionModel.status == "ACTIVE").first()
target_rollback = initial_mv.version if initial_mv else "v008"

print("=" * 65)
print("Testing Continuous Learning Retraining, Validation, Promotion, and Rollback")
print("=" * 65)
print(f"Base Production Model Version: {target_rollback}")

# 1. Trigger retraining
print("\n1. Triggering background retraining (epochs=2 for test speed)...")
ret = ContinuousLearningService.start_retraining_job(
    db=db,
    admin_id=1,
    admin_username="admin",
    epochs=2,
    lr=1e-4,
)
print("Trigger result:", ret)
run_id = ret["run_id"]

# 2. Wait for background worker to complete
print(f"\n2. Awaiting completion of run {run_id}...")
for attempt in range(60):
    time.sleep(2)
    db.expire_all()
    run = db.query(TrainingRunModel).filter(TrainingRunModel.run_id == run_id).first()
    print(f"  Attempt {attempt+1}: Status = {run.status}")
    if run.status in ("COMPLETED", "FAILED"):
        break

assert run.status == "COMPLETED", f"Training run failed: {run.failure_reason}"
print(f"✓ Training run completed successfully! Candidate checkpoint: {run.candidate_checkpoint_path}")
print(f"  Candidate SHA-256: {run.candidate_sha256}")
print(f"  Validation metrics: {run.validation_metrics_json}")

# 3. Test Candidate Promotion
print("\n3. Testing Atomic Model Promotion...")
prom_result = ContinuousLearningService.promote_candidate_model(
    db=db,
    run_id=run_id,
    admin_id=1,
    admin_username="admin",
    reason="Automated continuous learning test promotion",
)
print("Promotion result:", prom_result)
prom_version = prom_result["promoted_version"]
assert prom_version.startswith("v"), f"Expected version tag starting with 'v', got {prom_version}"

# Verify active version in model_versions
db.expire_all()
active_mv = db.query(ModelVersionModel).filter(ModelVersionModel.status == "ACTIVE").first()
assert active_mv.version == prom_version
print(f"✓ Active model version successfully updated to {active_mv.version} (SHA: {active_mv.sha256[:12]}...)")

# Verify active detector.pt exists on disk and is valid
det_pt = PROJECT_ROOT / "backend" / "models" / "weights" / "detector.pt"
assert det_pt.exists()
assert det_pt.stat().st_size > 30_000_000
print(f"✓ detector.pt verified on disk: {det_pt.stat().st_size:,} bytes")

# 4. Test Model Rollback
print(f"\n4. Testing Model Rollback to {target_rollback}...")
rb_result = ContinuousLearningService.rollback_model(
    db=db,
    target_version=target_rollback,
    admin_id=1,
    admin_username="admin",
)
print("Rollback result:", rb_result)
assert rb_result["status"] == "ROLLED_BACK"

db.expire_all()
restored_mv = db.query(ModelVersionModel).filter(ModelVersionModel.status == "ACTIVE").first()
assert restored_mv.version == target_rollback, f"Expected {target_rollback}, got {restored_mv.version}"
print(f"✓ Production model successfully restored to {restored_mv.version}!")

db.close()
print("=" * 65)
print("CONTINUOUS LEARNING LIFECYCLE TEST PASSED!")
print("=" * 65)
