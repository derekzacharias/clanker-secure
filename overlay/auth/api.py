from __future__ import annotations

import os
from datetime import timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select, func

from clanker.main import app
from clanker.main import session_dep
from .models import SessionToken, User, UserRead, LoginAttempt, AuditLog, InviteToken
from .security import (
    create_session_token,
    get_current_user,
    hash_password,
    now_utc,
    verify_password,
)
from .security import require_roles


ACCESS_TTL = timedelta(minutes=30)
REFRESH_TTL = timedelta(days=7)


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenPair(BaseModel):
    access_token: str
    access_expires_at: str
    refresh_token: str
    refresh_expires_at: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    revoke_all: Optional[bool] = False


MAX_ATTEMPTS = 5
WINDOW_SECONDS = 600  # 10 minutes
MAX_IP_ATTEMPTS = 15


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else ""


@app.post("/auth/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, session: Session = Depends(session_dep)) -> TokenPair:
    # Basic rate limiting / lockout by recent failed attempts
    since = now_utc() - timedelta(seconds=WINDOW_SECONDS)
    fail_count = session.exec(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.email == payload.email, LoginAttempt.success == False, LoginAttempt.created_at >= since  # noqa: E712
        )
    ).one()
    ip = _client_ip(request)
    ip_fail_count = session.exec(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.ip == ip, LoginAttempt.success == False, LoginAttempt.created_at >= since  # noqa: E712
        )
    ).one()
    if int(fail_count or 0) >= MAX_ATTEMPTS:
        # Record throttled attempt (no password check)
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(AuditLog(actor_user_id=None, action="login_throttled", target=payload.email, ip=ip, detail=None))
        session.flush()
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")
    if int(ip_fail_count or 0) >= MAX_IP_ATTEMPTS:
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(AuditLog(actor_user_id=None, action="login_throttled_ip", target=payload.email, ip=ip, detail=None))
        session.flush()
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

    user = session.exec(select(User).where(User.email == payload.email)).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        session.add(LoginAttempt(email=payload.email, ip=_client_ip(request), success=False))
        session.add(AuditLog(actor_user_id=None, action="login_failure", target=payload.email, ip=_client_ip(request), detail=None))
        session.flush()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.active:
        raise HTTPException(status_code=403, detail="User disabled")

    session.add(LoginAttempt(email=payload.email, ip=_client_ip(request), success=True))
    session.add(AuditLog(actor_user_id=user.id, action="login_success", target=payload.email, ip=_client_ip(request), detail=None))

    access = create_session_token(session, user_id=user.id, token_type="access", lifetime=ACCESS_TTL)  # type: ignore[arg-type]
    refresh = create_session_token(session, user_id=user.id, token_type="refresh", lifetime=REFRESH_TTL)  # type: ignore[arg-type]

    return TokenPair(
        access_token=access.token,
        access_expires_at=access.expires_at.isoformat(),
        refresh_token=refresh.token,
        refresh_expires_at=refresh.expires_at.isoformat(),
    )


@app.post("/auth/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, session: Session = Depends(session_dep)) -> TokenPair:
    tok = session.exec(
        select(SessionToken).where(SessionToken.token == payload.refresh_token, SessionToken.token_type == "refresh")
    ).first()
    if tok and tok.expires_at and tok.expires_at.tzinfo is None:
        tok.expires_at = tok.expires_at.replace(tzinfo=timezone.utc)
        session.add(tok)
        session.flush()
    if not tok or tok.revoked or tok.expires_at <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = session.get(User, tok.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=403, detail="User disabled")

    access = create_session_token(session, user_id=user.id, token_type="access", lifetime=ACCESS_TTL)  # type: ignore[arg-type]
    refresh = create_session_token(session, user_id=user.id, token_type="refresh", lifetime=REFRESH_TTL)  # type: ignore[arg-type]

    session.add(AuditLog(actor_user_id=user.id, action="token_refreshed", target=user.email, ip=None, detail=None))
    return TokenPair(
        access_token=access.token,
        access_expires_at=access.expires_at.isoformat(),
        refresh_token=refresh.token,
        refresh_expires_at=refresh.expires_at.isoformat(),
    )


@app.get("/auth/me", response_model=UserRead)
def me(current=Depends(get_current_user)) -> UserRead:  # type: ignore[no-redef]
    u = current.user
    return UserRead(id=u.id, email=u.email, name=u.name, role=u.role, active=u.active, created_at=u.created_at)  # type: ignore[arg-type]


class MeUpdate(BaseModel):
    name: Optional[str] = None


@app.patch("/auth/me", response_model=UserRead)
def update_me(payload: MeUpdate, current=Depends(get_current_user), session: Session = Depends(session_dep)) -> UserRead:  # type: ignore[no-redef]
    user = session.get(User, current.user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.name is not None:
        user.name = payload.name
    session.add(user)
    session.flush()
    session.refresh(user)
    return UserRead(id=user.id, email=user.email, name=user.name, role=user.role, active=user.active, created_at=user.created_at)  # type: ignore[arg-type]


@app.post("/auth/logout")
def logout(payload: LogoutRequest, current=Depends(get_current_user), session: Session = Depends(session_dep)) -> dict:  # type: ignore[no-redef]
    if payload.revoke_all:
        for t in session.exec(select(SessionToken).where(SessionToken.user_id == current.user.id)).all():
            t.revoked = True
            session.add(t)
    else:
        current.token.revoked = True
        session.add(current.token)
    session.add(AuditLog(actor_user_id=current.user.id, action="logout", target=current.user.email, ip=None, detail=None))
    return {"status": "ok"}


def _seed_admin_if_configured(session: Session) -> None:
    email = os.getenv("CLANKER_ADMIN_EMAIL")
    password = os.getenv("CLANKER_ADMIN_PASSWORD")
    if not email or not password:
        return
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        return
    user = User(email=email, name="Administrator", hashed_password=hash_password(password), role="admin", active=True)
    session.add(user)


from clanker.db.session import get_session


@app.on_event("startup")
def _seed_admin_on_startup() -> None:
    try:
        with get_session() as s:
            _seed_admin_if_configured(s)
    except Exception:
        # Do not block startup on seed failures
        pass


# ---- Admin: User management ----
class UserCreate(BaseModel):
    email: str
    name: Optional[str] = None
    password: str
    role: str = "operator"  # admin | operator | viewer
    active: bool = True


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


@app.get("/users", response_model=list[UserRead])
def list_users(_: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> list[User]:
    return session.exec(select(User).order_by(User.created_at.desc())).all()


def _password_complex_enough(pw: str) -> bool:
    if len(pw) < 10:
        return False
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    return has_lower and has_upper and has_digit and has_symbol


@app.post("/users", response_model=UserRead, status_code=201)
def create_user(payload: UserCreate, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> User:
    existing = session.exec(select(User).where(User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    if not _password_complex_enough(payload.password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
    user = User(
        email=payload.email,
        name=payload.name,
        hashed_password=hash_password(payload.password),
        role=payload.role or "operator",
        active=payload.active,
    )
    session.add(user)
    session.flush()
    session.refresh(user)
    session.add(AuditLog(actor_user_id=None, action="user_created", target=str(user.id), ip=None, detail=user.email))
    return user


@app.patch("/users/{user_id}", response_model=UserRead)
def update_user(user_id: int, payload: UserUpdate, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> User:
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.name is not None:
        user.name = payload.name
    if payload.role is not None:
        user.role = payload.role
    if payload.active is not None:
        user.active = payload.active
    if payload.password:
        if not _password_complex_enough(payload.password):
            raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
        user.hashed_password = hash_password(payload.password)
    session.add(user)
    session.flush()
    session.refresh(user)
    session.add(AuditLog(actor_user_id=None, action="user_updated", target=str(user.id), ip=None, detail=None))
    return user


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


@app.post("/auth/change_password")
def change_password(payload: ChangePasswordRequest, current=Depends(get_current_user), session: Session = Depends(session_dep)) -> dict:  # type: ignore[no-redef]
    user = session.get(User, current.user.id)
    if not user or not verify_password(payload.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    if not _password_complex_enough(payload.new_password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
    user.hashed_password = hash_password(payload.new_password)
    session.add(user)
    session.add(AuditLog(actor_user_id=user.id, action="password_changed", target=str(user.id), ip=None, detail=None))
    return {"status": "ok"}


class SeedAdminRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = "Administrator"


@app.post("/auth/seed_admin")
def seed_admin(payload: SeedAdminRequest, session: Session = Depends(session_dep)) -> dict:
    # Only allow if there are no users yet
    existing = session.exec(select(User)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Users already exist")
    if not _password_complex_enough(payload.password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
    user = User(email=payload.email, name=payload.name, hashed_password=hash_password(payload.password), role="admin", active=True)
    session.add(user)
    session.flush()
    session.add(AuditLog(actor_user_id=user.id, action="user_created", target=str(user.id), ip=None, detail="seed_admin"))
    return {"status": "ok"}


# ---- Admin: Invite flow ----
class InviteRequest(BaseModel):
    email: str
    role: str = "operator"  # admin | operator | viewer
    expires_minutes: int = 60 * 24  # default 24h


class InviteResponse(BaseModel):
    token: str
    # Frontend can build a full link like /accept-invite?token=...
    accept_path: str
    expires_at: str


@app.post("/admin/users/invite", response_model=InviteResponse)
def invite_user(payload: InviteRequest, current=Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> InviteResponse:  # type: ignore[no-redef]
    # Upsert user without a usable password (invite required to set one)
    user = session.exec(select(User).where(User.email == payload.email)).first()
    placeholder_pw = hash_password(os.urandom(12).hex())
    if not user:
        user = User(email=payload.email, name=None, hashed_password=placeholder_pw, role=payload.role, active=True)
        session.add(user)
        session.flush()
    else:
        # Update role to the invited role; keep active state
        user.role = payload.role or user.role
        session.add(user)

    # Create one-time invite token
    from .security import new_token_value

    token_value = new_token_value()
    invite = InviteToken(
        email=payload.email,
        role=payload.role or "operator",
        token=token_value,
        expires_at=now_utc() + timedelta(minutes=max(5, min(payload.expires_minutes, 60 * 24 * 7))),
        created_by_user_id=current.user.id,
    )
    session.add(invite)
    session.flush()
    session.refresh(invite)

    return InviteResponse(token=invite.token, accept_path=f"/auth/accept_invite", expires_at=invite.expires_at.isoformat())


class AcceptInviteRequest(BaseModel):
    token: str
    password: str


@app.post("/auth/accept_invite")
def accept_invite(payload: AcceptInviteRequest, session: Session = Depends(session_dep)) -> dict:
    inv = session.exec(select(InviteToken).where(InviteToken.token == payload.token)).first()
    if not inv or inv.used_at is not None or inv.expires_at <= now_utc():
        raise HTTPException(status_code=400, detail="Invalid or expired invite token")

    # Basic password policy reuse
    if not _password_complex_enough(payload.password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")

    user = session.exec(select(User).where(User.email == inv.email)).first()
    if not user:
        # In case the user record was removed after invite issuance
        user = User(email=inv.email, name=None, hashed_password=hash_password(payload.password), role=inv.role, active=True)
        session.add(user)
        session.flush()
    else:
        user.hashed_password = hash_password(payload.password)
        user.role = inv.role or user.role
        user.active = True
        session.add(user)

    inv.used_at = now_utc()
    session.add(inv)
    session.add(AuditLog(actor_user_id=user.id, action="invite_accepted", target=inv.email, ip=None, detail=None))
    return {"status": "ok"}


# Audit log querying (admin)
from datetime import datetime as _dt
from fastapi import Query as _Query


class AuditLogRead(BaseModel):
    id: int
    created_at: str
    actor_user_id: Optional[int]
    action: str
    target: Optional[str]
    ip: Optional[str]
    detail: Optional[str]


@app.get("/audit_logs", response_model=list[AuditLogRead])
def list_audit_logs(
    _: object = Depends(require_roles("admin")),
    user_id: Optional[int] = _Query(default=None),
    action: Optional[str] = _Query(default=None),
    since: Optional[str] = _Query(default=None),
    until: Optional[str] = _Query(default=None),
    session: Session = Depends(session_dep),
) -> list[AuditLogRead]:
    q = select(AuditLog)
    if user_id is not None:
        q = q.where(AuditLog.actor_user_id == user_id)
    if action is not None:
        q = q.where(AuditLog.action == action)
    def _parse(ts: Optional[str]):
        if not ts:
            return None
        try:
            return _dt.fromisoformat(ts)
        except Exception:
            return None
    s_dt = _parse(since)
    u_dt = _parse(until)
    if s_dt is not None:
        q = q.where(AuditLog.created_at >= s_dt)
    if u_dt is not None:
        q = q.where(AuditLog.created_at <= u_dt)
    rows = session.exec(q.order_by(AuditLog.created_at.desc())).all()
    return [
        AuditLogRead(
            id=r.id,
            created_at=r.created_at.isoformat(),
            actor_user_id=r.actor_user_id,
            action=r.action,
            target=r.target,
            ip=r.ip,
            detail=r.detail,
        )
        for r in rows
    ]


from sqlmodel import SQLModel
from clanker.db.session import engine


@app.on_event("startup")
def _ensure_auth_tables() -> None:
    # Ensure auth tables exist for rate limiting and audit logging
    SQLModel.metadata.create_all(engine)
