"""
routes_auth.py — Authentication REST API endpoints for CyberGuard.

Endpoints:
  POST /api/auth/login            Authenticate user, return session token & set cookie
  POST /api/auth/register         Register a new normal user (role=user)
  POST /api/auth/logout           Revoke active session token
  GET  /api/auth/me               Get profile of currently logged-in user
  POST /api/auth/change-password  Update password securely
"""

from __future__ import annotations

import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from backend.storage.auth import (
    ROLE_USER,
    AuthService,
    get_optional_user,
    get_token_from_request,
    hash_password,
    require_user,
    verify_password,
)
from backend.storage.database import UserModel, get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username_or_email: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

    def get_identifier(self) -> str:
        ident = self.username_or_email or self.username or self.email
        if not ident or not ident.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Username or email is required.",
            )
        return ident.strip()


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user: UserResponse


@router.post("/login", response_model=AuthResponse)
async def login(
    req: LoginRequest,
    response: Response,
    db: Session = Depends(get_db_session),
):
    """Authenticate and obtain session token."""
    user, raw_token = AuthService.authenticate(db, req.get_identifier(), req.password)

    # Set secure cookie
    response.set_cookie(
        key="cyberguard_session",
        value=raw_token,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
    )

    return AuthResponse(
        token=raw_token,
        user=UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else None,
            last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        ),
    )


@router.post("/register", response_model=AuthResponse)
async def register(
    req: RegisterRequest,
    response: Response,
    db: Session = Depends(get_db_session),
):
    """Self-register as a standard user."""
    try:
        user = AuthService.create_user(
            db=db,
            username=req.username,
            email=req.email,
            password=req.password,
            role=ROLE_USER,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Auto-login after registration
    user, raw_token = AuthService.authenticate(db, user.username, req.password)
    response.set_cookie(
        key="cyberguard_session",
        value=raw_token,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
    )

    return AuthResponse(
        token=raw_token,
        user=UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else None,
            last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        ),
    )


@router.post("/logout")
async def logout(
    response: Response,
    token: Optional[str] = Depends(get_token_from_request),
    db: Session = Depends(get_db_session),
):
    """Revoke session token and clear session cookie."""
    if token and db:
        AuthService.revoke_token(db, token)
    response.delete_cookie("cyberguard_session")
    return {"status": "success", "message": "Logged out successfully."}


@router.get("/me", response_model=Optional[UserResponse])
async def get_current_user_profile(
    user: Optional[UserModel] = Depends(get_optional_user),
):
    """Get the active user's profile (or null if not logged in)."""
    if not user:
        return None
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
    )


@router.post("/change-password")
async def change_password(
    req: ChangePasswordRequest,
    user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """Secure password change (requires existing password verification)."""
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password verification failed.",
        )
    try:
        user.password_hash = hash_password(req.new_password)
        user.password_changed_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"status": "success", "message": "Password changed successfully."}
