"""
auth.py — Cryptographically secure authentication and RBAC for CyberGuard.

Features:
  - NIST/OWASP approved memory-hard scrypt password hashing with cryptographic salt
  - Constant-time password verification via secrets.compare_digest
  - High-entropy session tokens (32 bytes urlsafe) stored as SHA-256 hashes
  - Role-Based Access Control: ROLE_USER, ROLE_ADMIN
  - Zero plaintext password exposure across APIs, logs, database, and admin UIs
  - Optional and required authentication dependencies for FastAPI
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import logging
import secrets
from typing import Optional, Tuple

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.storage.database import (
    AdminAuditLogModel,
    AuthSessionModel,
    ModelVersionModel,
    UserModel,
    get_db_session,
    get_session_factory,
)

logger = logging.getLogger(__name__)

# Roles
ROLE_USER = "user"
ROLE_ADMIN = "admin"

# Password hashing configuration (scrypt: N=16384, r=8, p=1, 16-byte salt)
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_SESSION_EXPIRY_DAYS = 7

bearer_scheme = HTTPBearer(auto_error=False)


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def hash_password(password: str) -> str:
    """
    Hash a password using memory-hard scrypt with a cryptographically random salt.
    Format: scrypt:{salt_b64}:{hash_b64}
    """
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    salt = secrets.token_bytes(_SALT_BYTES)
    h = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(h).decode("ascii")
    return f"scrypt:{salt_b64}:{hash_b64}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against the stored scrypt hash using constant-time comparison.
    """
    if not stored_hash or not plain_password:
        return False
    parts = stored_hash.split(":")
    if len(parts) != 3 or parts[0] != "scrypt":
        return False
    try:
        salt = base64.b64decode(parts[1])
        expected_hash = parts[2]
        h = hashlib.scrypt(
            plain_password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        )
        calculated_b64 = base64.b64encode(h).decode("ascii")
        return secrets.compare_digest(calculated_b64, expected_hash)
    except Exception as exc:
        logger.error(f"Error during password verification: {exc}")
        return False


def hash_token(raw_token: str) -> str:
    """Hash a session token with SHA-256 for safe storage in the database."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class AuthService:
    """Authentication and session management business logic."""

    @staticmethod
    def create_user(
        db: Session,
        username: str,
        email: str,
        password: str,
        role: str = ROLE_USER,
        actor_id: Optional[int] = None,
    ) -> UserModel:
        username = username.strip().lower()
        email = email.strip().lower()
        if role not in (ROLE_USER, ROLE_ADMIN):
            raise ValueError(f"Invalid role: {role}")

        existing = db.query(UserModel).filter(
            (UserModel.username == username) | (UserModel.email == email)
        ).first()
        if existing:
            raise ValueError("Username or email already exists.")

        pw_hash = hash_password(password)
        user = UserModel(
            username=username,
            email=email,
            password_hash=pw_hash,
            role=role,
            is_active=True,
            created_at=_utcnow(),
            password_changed_at=_utcnow(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Audit event
        AuthService.log_admin_action(
            db,
            actor_user_id=actor_id,
            actor_role="ADMIN" if actor_id else "SYSTEM",
            action="USER_CREATED",
            target_type="user",
            target_id=str(user.id),
            details={"username": user.username, "role": user.role},
        )
        return user

    @staticmethod
    def authenticate(
        db: Session,
        username_or_email: str,
        password: str,
    ) -> Tuple[UserModel, str]:
        """Authenticate user and return (user, raw_session_token)."""
        ident = username_or_email.strip().lower()
        user = db.query(UserModel).filter(
            (UserModel.username == ident) | (UserModel.email == ident)
        ).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated. Contact an administrator.",
            )

        if not verify_password(password, user.password_hash):
            user.failed_login_count = (user.failed_login_count or 0) + 1
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        # Reset failed login count and record last login
        user.failed_login_count = 0
        user.last_login_at = _utcnow()

        # Generate high-entropy token
        raw_token = secrets.token_urlsafe(32)
        t_hash = hash_token(raw_token)
        expires_at = _utcnow() + datetime.timedelta(days=_SESSION_EXPIRY_DAYS)

        session = AuthSessionModel(
            user_id=user.id,
            token_hash=t_hash,
            created_at=_utcnow(),
            expires_at=expires_at,
        )
        db.add(session)
        db.commit()

        return user, raw_token

    @staticmethod
    def get_user_from_token(db: Session, raw_token: str) -> Optional[UserModel]:
        """Look up user from session token."""
        if not raw_token:
            return None
        t_hash = hash_token(raw_token)
        now = _utcnow()
        session = db.query(AuthSessionModel).filter(
            AuthSessionModel.token_hash == t_hash,
            AuthSessionModel.revoked_at.is_(None),
            AuthSessionModel.expires_at > now,
        ).first()

        if not session:
            return None

        user = db.query(UserModel).filter(UserModel.id == session.user_id).first()
        if user and user.is_active:
            return user
        return None

    @staticmethod
    def revoke_token(db: Session, raw_token: str) -> bool:
        t_hash = hash_token(raw_token)
        session = db.query(AuthSessionModel).filter(
            AuthSessionModel.token_hash == t_hash
        ).first()
        if session:
            session.revoked_at = _utcnow()
            db.commit()
            return True
        return False

    @staticmethod
    def log_admin_action(
        db: Session,
        actor_user_id: Optional[int],
        actor_role: str,
        action: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        import json
        entry = AdminAuditLogModel(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            timestamp=_utcnow(),
            details_json=json.dumps(details) if details else None,
        )
        db.add(entry)
        db.commit()


# ── FastAPI Dependencies ───────────────────────────────────────────────────────

def get_token_from_request(
    request: Request,
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[str]:
    """Extract token from Authorization Bearer header or X-Session-Token or cookie."""
    if auth_header and auth_header.credentials:
        return auth_header.credentials
    # Check custom header
    token = request.headers.get("X-Session-Token")
    if token:
        return token
    # Check cookies
    cookie_token = request.cookies.get("cyberguard_session")
    if cookie_token:
        return cookie_token
    return None


def get_optional_user(
    token: Optional[str] = Depends(get_token_from_request),
    db: Session = Depends(get_db_session),
) -> Optional[UserModel]:
    """Returns current UserModel if valid token provided; None otherwise (non-blocking)."""
    if not token or db is None:
        return None
    return AuthService.get_user_from_token(db, token)


def require_user(
    user: Optional[UserModel] = Depends(get_optional_user),
) -> UserModel:
    """Enforce that the caller is an authenticated user."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(
    user: UserModel = Depends(require_user),
) -> UserModel:
    """Enforce that the caller has ADMIN privileges."""
    if user.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required.",
        )
    return user


def bootstrap_system():
    """
    Ensure the initial default admin and model_versions registry are seeded.
    Called once during application startup.
    """
    factory = get_session_factory("data/cyberguard.db")
    db = factory()
    try:
        # 1. Seed initial admin if no admin exists
        admin_count = db.query(UserModel).filter(UserModel.role == ROLE_ADMIN).count()
        if admin_count == 0:
            logger.info("No admin user found. Creating initial secure administrator...")
            AuthService.create_user(
                db=db,
                username="admin",
                email="admin@cyberguard.local",
                password="Admin@CyberGuard2026!",
                role=ROLE_ADMIN,
                actor_id=None,
            )
            logger.info("✓ Initial administrator created: username='admin'")

        # 2. Seed initial ModelVersion (v001) pointing to detector.pt
        v001 = db.query(ModelVersionModel).filter(ModelVersionModel.version == "v001").first()
        if not v001:
            from pathlib import Path
            det_path = Path("backend/models/weights/detector.pt")
            if det_path.exists():
                size = det_path.stat().st_size
                sha = hashlib.sha256(det_path.read_bytes()).hexdigest()
                mv = ModelVersionModel(
                    version="v001",
                    checkpoint_path="backend/models/weights/detector.pt",
                    sha256=sha,
                    file_size=size,
                    status="ACTIVE",
                    created_at=_utcnow(),
                    promoted_at=_utcnow(),
                    promotion_reason="Initial baseline native EnsembleDetector",
                )
                db.add(mv)
                db.commit()
                logger.info(f"✓ ModelVersion v001 registered in database (SHA: {sha[:12]}...)")
    except Exception as exc:
        db.rollback()
        logger.error(f"Bootstrap seeding error: {exc}")
    finally:
        db.close()
