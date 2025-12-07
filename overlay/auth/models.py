from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel
from typing import Optional
from datetime import datetime


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    email: str = Field(index=True, unique=True, max_length=255)
    name: Optional[str] = Field(default=None, max_length=255)
    hashed_password: str = Field()
    role: str = Field(default="admin", max_length=32)  # admin | operator | viewer
    active: bool = Field(default=True)

    # Omit reverse tokens relationship for simpler mapping in MVP
    # (avoids SQLAlchemy generic typing issue under 2.0)
    # tokens: List["SessionToken"] = Relationship(back_populates="user")


class SessionToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    user_id: int = Field(foreign_key="user.id")
    token: str = Field(index=True, unique=True)
    token_type: str = Field(default="access", max_length=16)  # access | refresh
    expires_at: datetime
    revoked: bool = Field(default=False)

    # No relationship field needed for MVP; use user_id directly


class UserRead(SQLModel):
    id: int
    email: str
    name: Optional[str]
    role: str
    active: bool
    created_at: datetime


__all__ = [
    "User",
    "SessionToken",
    "UserRead",
]


class LoginAttempt(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    email: str = Field(index=True, max_length=255)
    ip: Optional[str] = Field(default=None, max_length=48)
    success: bool = Field(default=False)


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    actor_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    action: str = Field(max_length=64)
    target: Optional[str] = Field(default=None, max_length=128)
    ip: Optional[str] = Field(default=None, max_length=48)
    detail: Optional[str] = Field(default=None)


__all__ += [
    "LoginAttempt",
    "AuditLog",
]


class InviteToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    email: str = Field(index=True, max_length=255)
    role: str = Field(default="operator", max_length=32)  # role granted upon acceptance
    token: str = Field(index=True, unique=True)
    expires_at: datetime
    used_at: Optional[datetime] = None
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")


__all__ += [
    "InviteToken",
]
