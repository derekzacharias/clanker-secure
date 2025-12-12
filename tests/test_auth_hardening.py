from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlmodel import delete, select, func

from clanker.db.models import AuditLog, LoginAttempt, SessionToken, User
from clanker.db.session import get_session, init_db
from clanker.main import MAX_ATTEMPTS, LoginRequest, hash_password, login


@pytest.fixture(autouse=True)
def _reset_auth_tables() -> None:
    """Start each test with a clean auth-related state."""
    init_db()
    with get_session() as session:
        session.exec(delete(SessionToken))
        session.exec(delete(LoginAttempt))
        session.exec(delete(AuditLog))
        session.exec(delete(User))


def _create_user(email: str, password: str) -> str:
    with get_session() as session:
        user = User(
            email=email,
            name="Test User",
            hashed_password=hash_password(password),
            role="admin",
            active=True,
        )
        session.add(user)
        session.flush()
        return user.email


def _build_request(ip: str = "203.0.113.10") -> Request:
    scope = {"type": "http", "headers": [], "client": (ip, 12345)}
    return Request(scope)  # type: ignore[arg-type]


def test_login_success_records_attempt_and_audit() -> None:
    email = _create_user("login-ok@example.com", "StrongPass123!")

    with get_session() as session:
        resp = login(LoginRequest(email=email, password="StrongPass123!"), _build_request(), session)
        assert resp.access_token

    with get_session() as session:
        attempts = session.exec(select(LoginAttempt)).all()
        assert len(attempts) == 1
        assert attempts[0].success is True

        audit = session.exec(select(AuditLog).where(AuditLog.action == "login_success")).first()
        assert audit is not None
        assert audit.target == email
        assert audit.ip is not None


def test_login_rate_limit_blocks_after_failures() -> None:
    email = _create_user("login-throttle@example.com", "StrongPass123!")

    for _ in range(MAX_ATTEMPTS):
        with get_session() as session:
            with pytest.raises(HTTPException) as excinfo:
                login(LoginRequest(email=email, password="WrongPassword!"), _build_request(), session)
            assert excinfo.value.status_code == 401

    with get_session() as session:
        with pytest.raises(HTTPException) as excinfo:
            login(LoginRequest(email=email, password="WrongPassword!"), _build_request(), session)
        assert excinfo.value.status_code == 429

    with get_session() as session:
        fail_attempts = session.exec(
            select(func.count()).select_from(LoginAttempt).where(LoginAttempt.success == False)  # noqa: E712
        ).one()
        assert int(fail_attempts or 0) >= MAX_ATTEMPTS

        throttled = session.exec(select(AuditLog).where(AuditLog.action == "login_throttled")).first()
        assert throttled is not None
        assert throttled.target == email
        assert throttled.ip is not None
