from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlmodel import delete, select, func

from clanker.db.models import AuditLog, LoginAttempt, SessionToken, User
from clanker.db.session import get_session, init_db
from clanker.main import MAX_ATTEMPTS, app, hash_password


@pytest.fixture(autouse=True)
def _reset_auth_tables() -> None:
    """Start each test with a clean auth-related state."""
    init_db()
    with get_session() as session:
        session.exec(delete(SessionToken))
        session.exec(delete(LoginAttempt))
        session.exec(delete(AuditLog))
        session.exec(delete(User))


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _create_user(email: str, password: str) -> User:
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
        session.refresh(user)
        return user


def test_login_success_records_attempt_and_audit(client: TestClient) -> None:
    user = _create_user("login-ok@example.com", "StrongPass123!")

    resp = client.post("/auth/login", json={"email": user.email, "password": "StrongPass123!"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body and "refresh_token" in body

    with get_session() as session:
        attempts = session.exec(select(LoginAttempt)).all()
        assert len(attempts) == 1
        assert attempts[0].success is True

        audit = session.exec(select(AuditLog).where(AuditLog.action == "login_success")).first()
        assert audit is not None
        assert audit.target == user.email
        assert audit.ip is not None


def test_login_rate_limit_blocks_after_failures(client: TestClient) -> None:
    user = _create_user("login-throttle@example.com", "StrongPass123!")

    for _ in range(MAX_ATTEMPTS):
        resp = client.post("/auth/login", json={"email": user.email, "password": "WrongPassword!"})
        assert resp.status_code == 401

    blocked = client.post("/auth/login", json={"email": user.email, "password": "WrongPassword!"})
    assert blocked.status_code == 429

    with get_session() as session:
        fail_attempts = session.exec(
            select(func.count()).select_from(LoginAttempt).where(LoginAttempt.success == False)  # noqa: E712
        ).one()
        assert int(fail_attempts or 0) >= MAX_ATTEMPTS

        throttled = session.exec(select(AuditLog).where(AuditLog.action == "login_throttled")).first()
        assert throttled is not None
        assert throttled.target == user.email
        assert throttled.ip is not None
