import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.storage.database import init_db, get_session_factory, UserModel, ModelVersionModel
from backend.storage.auth import bootstrap_system, AuthService, verify_password

init_db("data/cyberguard.db")
bootstrap_system()

factory = get_session_factory("data/cyberguard.db")
db = factory()

# 1. Check admin user
admin = db.query(UserModel).filter(UserModel.username == "admin").first()
assert admin is not None, "Admin was not created!"
print(f"Admin user found: id={admin.id}, username='{admin.username}', role='{admin.role}'")
print(f"Password hash: {admin.password_hash[:30]}... (starts with scrypt: {admin.password_hash.startswith('scrypt:')})")
assert "Admin@CyberGuard2026!" not in admin.password_hash, "Plaintext password leak!"

# 2. Test authentication
user, token = AuthService.authenticate(db, "admin", "Admin@CyberGuard2026!")
assert user.id == admin.id
assert len(token) > 20
print(f"Auth success! Session token generated (len={len(token)})")

# 3. Test token lookup
looked_up = AuthService.get_user_from_token(db, token)
assert looked_up is not None and looked_up.username == "admin"
print("Token lookup success!")

# 4. Check model_versions table
v001 = db.query(ModelVersionModel).filter(ModelVersionModel.version == "v001").first()
assert v001 is not None, "v001 model version missing!"
print(f"Model version registered: version='{v001.version}', status='{v001.status}', sha256='{v001.sha256}'")

db.close()
print("ALL AUTH TESTS PASSED!")
