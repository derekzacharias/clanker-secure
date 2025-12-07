from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select

from clanker.main import session_dep
from .models import SessionToken, User


def _b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def hash_password(password: str) -> str:
    # scrypt with per-password random salt; encoded as: scrypt$<salt_b64>$<key_b64>
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    return f"scrypt${_b64encode(salt)}${_b64encode(key)}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        scheme, salt_b64, key_b64 = hashed.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        expected = base64.urlsafe_b64decode(key_b64 + "==")
        actual = _derive_key(password, salt)
        return _const_eq(actual, expected)
    except Exception:
        return False


def _derive_key(password: str, salt: bytes) -> bytes:
    # Conservative scrypt params for server-side hashing
    # r=8, p=1, n=2**14 (16384); 32-byte key
    import hashlib

    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)


def _const_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


def new_token_value() -> str:
    return _b64encode(os.urandom(32))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def create_session_token(session: Session, user_id: int, token_type: str, lifetime: timedelta) -> SessionToken:
    token = SessionToken(
        user_id=user_id,
        token=new_token_value(),
        token_type=token_type,
        expires_at=now_utc() + lifetime,
    )
    session.add(token)
    session.flush()
    session.refresh(token)
    return token


bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    user: User
    token: SessionToken


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    session: Session = Depends(session_dep),
) -> CurrentUser:
    if creds is None or not creds.scheme.lower() == "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    token_str = creds.credentials
    token = session.exec(
        select(SessionToken).where(SessionToken.token == token_str, SessionToken.token_type == "access")
    ).first()
    def _aware(dt: datetime) -> datetime:
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    if not token or token.revoked or _aware(token.expires_at) <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = session.get(User, token.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=403, detail="User disabled")
    return CurrentUser(user=user, token=token)


def require_roles(*roles: str):
    def dep(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current.user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return current

    return dep
