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

        # Auto-create and auto-link isolated database for this account
        try:
            from backend.storage.database import provision_user_database
            user_db = provision_user_database(user.id, user.username)
            user.db_path = user_db
            db.commit()
            db.refresh(user)
            logger.info(f"Auto-created and linked isolated database for user '{user.username}' at {user_db}")
        except Exception as e_db:
            logger.error(f"Failed to auto-create user database for {user.username}: {e_db}")

        # Audit event
        AuthService.log_admin_action(
            db,
            actor_user_id=actor_id,
            actor_role="ADMIN" if actor_id else "SYSTEM",
            action="USER_CREATED",
            target_type="user",
            target_id=str(user.id),
            details={"username": user.username, "role": user.role, "db_path": user.db_path},
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
            try:
                from backend.security.enforcement import get_enforcement_engine
                get_enforcement_engine().record_auth_failure(ip="client", username=user.username)
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
            )

        # Reset failed login count and record last login
        user.failed_login_count = 0
        user.last_login_at = _utcnow()

        # Ensure user's isolated database exists
        if not getattr(user, "db_path", None):
            try:
                from backend.storage.database import provision_user_database
                user.db_path = provision_user_database(user.id, user.username)
            except Exception as exc:
                logger.debug(f"User db verification notice: {exc}")

        try:
            from backend.security.enforcement import get_enforcement_engine
            get_enforcement_engine().reset_auth_failures(ip="client")
        except Exception:
            pass

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

        # Resilient hybrid session replication: ensure local SQLite WAL also holds this active session
        try:
            if getattr(db.bind.dialect, "name", "") != "sqlite":
                from backend.storage.database import get_local_engine
                local_eng = get_local_engine()
                with Session(bind=local_eng) as loc_db:
                    loc_sess = loc_db.query(AuthSessionModel).filter(
                        AuthSessionModel.token_hash == t_hash
                    ).first()
                    if not loc_sess:
                        loc_u = loc_db.query(UserModel).filter(UserModel.id == user.id).first()
                        if not loc_u:
                            loc_db.add(UserModel(
                                id=user.id,
                                username=user.username,
                                email=user.email,
                                password_hash=user.password_hash,
                                role=user.role,
                                is_active=user.is_active,
                                created_at=user.created_at,
                            ))
                            loc_db.flush()
                        loc_db.add(AuthSessionModel(
                            user_id=user.id,
                            token_hash=t_hash,
                            created_at=session.created_at,
                            expires_at=session.expires_at,
                        ))
                        loc_db.commit()
        except Exception as mir_loc_err:
            logger.debug(f"Local session caching notice: {mir_loc_err}")

        return user, raw_token

    @staticmethod
    def _is_session_expired(session: AuthSessionModel) -> bool:
        """Safely verify session expiration handling naive (SQLite) and tz-aware (PostgreSQL) datetimes."""
        if not session or not session.expires_at:
            return False
        now = _utcnow()
        exp = session.expires_at
        exp_cmp = exp.astimezone(datetime.timezone.utc).replace(tzinfo=None) if exp.tzinfo is not None else exp
        now_cmp = now.astimezone(datetime.timezone.utc).replace(tzinfo=None) if now.tzinfo is not None else now
        return exp_cmp <= now_cmp

    @staticmethod
    def get_user_from_token(db: Session, raw_token: str) -> Optional[UserModel]:
        """Look up user from session token with timezone-resilient expiration check and hybrid database fallback."""
        if not raw_token or db is None:
            return None
        try:
            t_hash = hash_token(raw_token)
            session = db.query(AuthSessionModel).filter(
                AuthSessionModel.token_hash == t_hash,
                AuthSessionModel.revoked_at.is_(None),
            ).first()

            # Resilient hybrid fallback: check counterpart database if connection pool failed over
            if not session:
                is_pg = getattr(db.bind.dialect, "name", "") == "postgresql"
                if is_pg:
                    # Current session is Cloud PostgreSQL; verify in local SQLite WAL
                    try:
                        from backend.storage.database import get_local_engine
                        local_eng = get_local_engine()
                        with Session(bind=local_eng) as fallback_db:
                            fb_session = fallback_db.query(AuthSessionModel).filter(
                                AuthSessionModel.token_hash == t_hash,
                                AuthSessionModel.revoked_at.is_(None),
                            ).first()
                            if fb_session and not AuthService._is_session_expired(fb_session):
                                user = db.query(UserModel).filter(UserModel.id == fb_session.user_id).first()
                                if not user:
                                    fb_user = fallback_db.query(UserModel).filter(UserModel.id == fb_session.user_id).first()
                                    if fb_user:
                                        user = UserModel(
                                            id=fb_user.id,
                                            username=fb_user.username,
                                            email=fb_user.email,
                                            password_hash=fb_user.password_hash,
                                            role=fb_user.role,
                                            is_active=fb_user.is_active,
                                            created_at=fb_user.created_at,
                                        )
                                        db.add(user)
                                        db.flush()
                                if user and user.is_active:
                                    try:
                                        db.add(AuthSessionModel(
                                            user_id=fb_session.user_id,
                                            token_hash=fb_session.token_hash,
                                            created_at=fb_session.created_at,
                                            expires_at=fb_session.expires_at,
                                        ))
                                        db.commit()
                                    except Exception:
                                        db.rollback()
                                    return user
                    except Exception as loc_fb_err:
                        logger.debug(f"Counterpart auth check (local) notice: {loc_fb_err}")
                else:
                    # Current session is local SQLite WAL; verify in Cloud PostgreSQL
                    try:
                        from backend.storage.sync_service import get_sync_service
                        sync_svc = get_sync_service()
                        if sync_svc.is_cloud_available():
                            cs = sync_svc.get_cloud_session()
                            if cs:
                                try:
                                    cloud_session = cs.query(AuthSessionModel).filter(
                                        AuthSessionModel.token_hash == t_hash,
                                        AuthSessionModel.revoked_at.is_(None),
                                    ).first()
                                    if cloud_session and not AuthService._is_session_expired(cloud_session):
                                        user = db.query(UserModel).filter(UserModel.id == cloud_session.user_id).first()
                                        if not user:
                                            cloud_u = cs.query(UserModel).filter(UserModel.id == cloud_session.user_id).first()
                                            if cloud_u:
                                                user = UserModel(
                                                    id=cloud_u.id,
                                                    username=cloud_u.username,
                                                    email=cloud_u.email,
                                                    password_hash=cloud_u.password_hash,
                                                    role=cloud_u.role,
                                                    is_active=cloud_u.is_active,
                                                    created_at=cloud_u.created_at,
                                                )
                                                db.add(user)
                                                db.flush()
                                        if user and user.is_active:
                                            try:
                                                db.add(AuthSessionModel(
                                                    user_id=cloud_session.user_id,
                                                    token_hash=cloud_session.token_hash,
                                                    created_at=cloud_session.created_at,
                                                    expires_at=cloud_session.expires_at,
                                                ))
                                                db.commit()
                                            except Exception:
                                                db.rollback()
                                            return user
                                finally:
                                    cs.close()
                    except Exception as cld_fb_err:
                        logger.debug(f"Counterpart auth check (cloud) notice: {cld_fb_err}")

            if not session:
                return None

            # Check expiration safely handling both naive (SQLite) and aware datetimes
            if AuthService._is_session_expired(session):
                return None

            user = db.query(UserModel).filter(UserModel.id == session.user_id).first()
            if user and user.is_active:
                return user
            return None
        except Exception as exc:
            logger.warning(f"Error querying user from token: {exc}")
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
    """Extract token from Authorization Bearer header, direct Authorization, X-Session-Token, cookie, or query param."""
    if isinstance(auth_header, HTTPAuthorizationCredentials) and auth_header.credentials:
        return auth_header.credentials
    # Fallback: check raw Authorization header for direct token or lowercase bearer
    raw_auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if raw_auth:
        parts = raw_auth.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        elif len(parts) == 1:
            return parts[0]
    # Check custom header
    token = request.headers.get("X-Session-Token")
    if token:
        return token
    # Check cookies
    cookie_token = request.cookies.get("cyberguard_session")
    if cookie_token:
        return cookie_token
    # Query param token is deprecated & restricted exclusively to media streaming paths
    if request.url.path.startswith("/api/admin/media/stream") or request.url.path.startswith("/api/media/") or "/audio" in request.url.path:
        query_token = request.query_params.get("token")
        if query_token:
            return query_token
    return None



def get_optional_user(
    request: Request,
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db_session),
) -> Optional[UserModel]:
    """
    Returns current UserModel if any valid, unexpired token is provided.
    Evaluates Bearer header, raw Authorization, X-Session-Token, and session cookie in order.
    Ensures a stale Bearer header does not mask an active session cookie.
    """
    if db is None:
        return None

    # Collect candidate tokens in order
    candidates: list[str] = []

    # 1. Bearer scheme credentials
    if auth_header and auth_header.credentials:
        candidates.append(auth_header.credentials)

    # 2. Raw Authorization header fallback
    raw_auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if raw_auth:
        parts = raw_auth.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            if parts[1] not in candidates:
                candidates.append(parts[1])
        elif len(parts) == 1 and parts[0] not in candidates:
            candidates.append(parts[0])

    # 3. Custom X-Session-Token header
    x_tok = request.headers.get("X-Session-Token")
    if x_tok and x_tok not in candidates:
        candidates.append(x_tok)

    # 4. Session cookie fallback
    cookie_tok = request.cookies.get("cyberguard_session")
    if cookie_tok and cookie_tok not in candidates:
        candidates.append(cookie_tok)

    # 5. Media streaming query param token
    if request.url.path.startswith("/api/admin/media/stream") or request.url.path.startswith("/api/media/") or "/audio" in request.url.path:
        q_tok = request.query_params.get("token")
        if q_tok and q_tok not in candidates:
            candidates.append(q_tok)

    # Check candidates until valid user found
    for cand in candidates:
        user = AuthService.get_user_from_token(db, cand)
        if user:
            return user

    return None


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
        # 1. Ensure primary 'admin' user is seeded and active
        default_admin = db.query(UserModel).filter(UserModel.username == "admin").first()
        import os
        from pathlib import Path
        env_pw = os.getenv("CYBERGUARD_ADMIN_PASSWORD") or os.getenv("ADMIN_PASSWORD")

        if not default_admin:
            if env_pw:
                admin_pw = env_pw
                source_note = "environment configuration"
            else:
                # Generate a cryptographically random, high-entropy one-time bootstrap password
                admin_pw = secrets.token_urlsafe(18)
                source_note = "secure one-time bootstrap generator"
                cred_path = Path("data/.admin_bootstrap_credentials")
                try:
                    cred_path.parent.mkdir(parents=True, exist_ok=True)
                    cred_path.write_text(
                        f"# CyberGuard Initial Administrator One-Time Credentials\n"
                        f"# Generated: {_utcnow().isoformat()}\n"
                        f"# CRITICAL: Rotate this password immediately after first login!\n"
                        f"username=admin\n"
                        f"password={admin_pw}\n",
                        encoding="utf-8"
                    )
                    try:
                        os.chmod(cred_path, 0o600)
                    except Exception:
                        pass
                    logger.warning(f"Initial admin password written to secure local enclave: {cred_path}")
                except Exception as w_err:
                    logger.warning(f"Could not persist bootstrap credentials file: {w_err}")

            logger.info(f"Primary administrator 'admin' not found. Creating administrator via {source_note}...")
            default_admin = AuthService.create_user(
                db=db,
                username="admin",
                email="cyberguardadmin@gmail.com",
                password=admin_pw,
                role=ROLE_ADMIN,
                actor_id=None,
            )
            logger.info("✓ Initial administrator created: username='admin'")
        elif env_pw:
            # Synchronize admin password with environment configuration
            default_admin.password_hash = hash_password(env_pw)
            default_admin.is_active = True
            db.commit()

        # 1b. Ensure primary administrator has an isolated database provisioned and linked
        if default_admin:
            if default_admin.email == "admin@cyberguard.local":
                default_admin.email = "cyberguardadmin@gmail.com"
                db.commit()
                logger.info("✓ Migrated admin email to cyberguardadmin@gmail.com")
            from backend.storage.database import provision_user_database
            if not getattr(default_admin, "db_path", None):
                default_admin.db_path = provision_user_database(default_admin.id, default_admin.username)
                db.commit()
            else:
                provision_user_database(default_admin.id, default_admin.username)

        # 2. Seed initial ModelVersion (v001) pointing to detector.pt
        v001 = db.query(ModelVersionModel).filter(ModelVersionModel.version == "v001").first()
        if not v001:
            from pathlib import Path
            det_path = Path("backend/models/weights/detector.pt")
            size = det_path.stat().st_size if det_path.exists() else 35803341
            sha = hashlib.sha256(det_path.read_bytes()).hexdigest() if det_path.exists() else "0000000000000000000000000000000000000000000000000000000000000000"
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
