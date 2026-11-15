"""Security regressions for user management and access control.

Each test names the failure it prevents; the previous build had all of them.
"""

from __future__ import annotations

import os
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, delete, select

from clanker.core import authz
from clanker.db.models import AuditLog, LoginAttempt, SessionToken, User
from clanker.db.session import get_session, init_db
from clanker.main import (
    ACCESS_TTL,
    REFRESH_TTL,
    CurrentUser,
    _seed_admin_if_configured,
    app,
    create_session_token,
    hash_password,
    refresh,
    RefreshRequest,
)


@pytest.fixture(autouse=True)
def _clean() -> None:
    init_db()
    with get_session() as session:
        for model in (SessionToken, LoginAttempt, AuditLog, User):
            session.exec(delete(model))
        session.commit()


def _user(email: str, role: str = "admin", password: str = "Sup3r-secret-pw!", active: bool = True) -> dict:
    """Create a user and return plain values (an ORM instance would be detached)."""
    with get_session() as session:
        user = User(email=email, name="Test", hashed_password=hash_password(password), role=role, active=active)
        session.add(user)
        session.commit()
        session.refresh(user)
        return {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "active": user.active,
            "hashed_password": user.hashed_password,
        }


def _client_for(user: dict) -> TestClient:
    """A client whose bearer token belongs to `user`."""
    with get_session() as session:
        token = create_session_token(session, user_id=user["id"], token_type="access", lifetime=ACCESS_TTL)
        session.commit()
        token_value = token.token
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token_value}"})
    return client


# --- administrator bootstrap -------------------------------------------------

def test_bootstrap_never_rewrites_an_existing_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """A restart must not reset the admin password, re-grant the role or re-enable it."""
    user = _user("admin@example.com", role="viewer", active=False)
    original_hash = user["hashed_password"]
    monkeypatch.setenv("CLANKER_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("CLANKER_ADMIN_PASSWORD", "An0ther-secret-pw!")

    with get_session() as session:
        _seed_admin_if_configured(session)
        session.commit()

    with get_session() as session:
        after = session.exec(select(User).where(User.email == "admin@example.com")).first()
        assert after is not None
        after_hash, after_role, after_active = after.hashed_password, after.role, after.active
    assert after_hash == original_hash, "bootstrap reset the password"
    assert after_role == "viewer", "bootstrap re-granted a role"
    assert after_active is False, "bootstrap re-enabled a disabled account"


def test_bootstrap_creates_the_first_administrator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLANKER_ADMIN_EMAIL", "first@example.com")
    monkeypatch.setenv("CLANKER_ADMIN_PASSWORD", "Sup3r-secret-pw!")
    with get_session() as session:
        _seed_admin_if_configured(session)
        session.commit()
        created = session.exec(select(User).where(User.email == "first@example.com")).first()
        created_role = created.role if created else None
    assert created_role == "admin"


def test_bootstrap_does_not_clear_login_lockouts(monkeypatch: pytest.MonkeyPatch) -> None:
    _user("admin@example.com")
    monkeypatch.setenv("CLANKER_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("CLANKER_ADMIN_PASSWORD", "Sup3r-secret-pw!")
    with get_session() as session:
        session.add(LoginAttempt(email="admin@example.com"))
        session.commit()
    with get_session() as session:
        _seed_admin_if_configured(session)
        session.commit()
    with get_session() as session:
        assert session.exec(select(LoginAttempt)).first() is not None, "bootstrap cleared a lockout"


# --- role validation and least privilege -------------------------------------

def test_unknown_roles_are_refused() -> None:
    for bad in ["root", "superuser", "admin2", "operator "]:
        if bad == "operator ":
            # Surrounding whitespace is normalised, not rejected.
            assert authz.normalise_role(bad) == "operator"
            continue
        with pytest.raises(ValueError):
            authz.normalise_role(bad)
    # Case is normalised rather than refused.
    assert authz.normalise_role("Admin") == "admin"


def test_new_users_default_to_the_least_privileged_role() -> None:
    admin = _user("admin@example.com")
    client = _client_for(admin)
    res = client.post("/users", json={"email": "new@example.com", "password": "Sup3r-secret-pw!"})
    assert res.status_code == 201, res.text
    assert res.json()["role"] == "viewer", "creating a user must not grant operator by default"
    # And the default role cannot manage users.
    assert not authz.has_permission(res.json()["role"], "users.manage")


def test_user_creation_rejects_an_invented_role() -> None:
    admin = _user("admin@example.com")
    client = _client_for(admin)
    res = client.post("/users", json={"email": "x@example.com", "password": "Sup3r-secret-pw!", "role": "superuser"})
    assert res.status_code == 400
    assert "unknown role" in res.json()["detail"]


# --- permissions -------------------------------------------------------------

def test_permission_table_separates_assignment_from_execution() -> None:
    """A security engineer assigns work but cannot execute privileged change."""
    assert authz.has_permission("security_engineer", "findings.assign")
    assert not authz.has_permission("security_engineer", "remediation.execute")
    assert not authz.has_permission("security_engineer", "remediation.approve")
    # Approval and execution are distinct permissions, held by nobody implicitly.
    assert authz.has_permission("system_operator", "remediation.execute")
    assert not authz.has_permission("system_operator", "remediation.approve")


def test_operator_keeps_only_its_previous_capabilities() -> None:
    """The compatibility rule: no new privileges for existing operator accounts."""
    perms = authz.permissions_for("operator")
    assert {"assets.manage", "scans.run", "findings.assign"} <= perms
    assert "users.manage" not in perms
    assert "remediation.execute" not in perms
    assert "audit.read" not in perms


def test_viewer_and_auditor_cannot_manage_users() -> None:
    for role in ("viewer", "auditor", "developer", "system_operator"):
        assert not authz.has_permission(role, "users.manage"), role
    assert authz.has_permission("auditor", "audit.read")


def test_non_admin_cannot_reach_user_administration() -> None:
    viewer = _user("viewer@example.com", role="viewer")
    client = _client_for(viewer)
    assert client.get("/users").status_code == 403
    assert client.post("/users", json={"email": "y@e.com", "password": "Sup3r-secret-pw!"}).status_code == 403
    assert client.get("/audit_logs").status_code == 403
    assert client.get("/access/roles").status_code == 403


def test_access_me_reports_effective_permissions() -> None:
    user = _user("se@example.com", role="security_engineer")
    client = _client_for(user)
    body = client.get("/access/me").json()
    assert body["user"]["role"] == "security_engineer"
    assert "findings.assign" in body["permissions"]
    assert "remediation.execute" not in body["permissions"]
    assert body["default_role"] == "viewer"


def test_auditor_can_read_audit_but_not_manage() -> None:
    auditor = _user("auditor@example.com", role="auditor")
    client = _client_for(auditor)
    assert client.get("/audit_logs").status_code == 200
    assert client.get("/users").status_code == 200  # users.read is in the auditor bundle
    assert client.patch("/users/1", json={"role": "admin"}).status_code == 403


# --- sessions ----------------------------------------------------------------

def test_disabling_an_account_revokes_its_sessions() -> None:
    admin = _user("admin@example.com")
    victim = _user("victim@example.com", role="operator")
    victim_client = _client_for(victim)
    assert victim_client.get("/access/me").status_code == 200

    admin_client = _client_for(admin)
    res = admin_client.patch(f"/users/{victim['id']}", json={"active": False})
    assert res.status_code == 200, res.text

    # The old bearer token is dead immediately, not at expiry.
    assert victim_client.get("/access/me").status_code in (401, 403)
    with get_session() as session:
        live = session.exec(
            select(SessionToken).where(SessionToken.user_id == victim["id"], SessionToken.revoked == False)  # noqa: E712
        ).all()
    assert live == [], "sessions survived disabling the account"


def test_password_reset_revokes_sessions() -> None:
    admin = _user("admin@example.com")
    victim = _user("victim@example.com", role="operator")
    victim_id = victim["id"]
    victim_client = _client_for(victim)
    admin_client = _client_for(admin)
    res = admin_client.post(f"/users/{victim_id}/reset-password", json={"new_password": "An0ther-secret-pw!"})
    assert res.status_code == 200, res.text
    assert res.json()["sessions_revoked"] >= 1
    assert victim_client.get("/access/me").status_code in (401, 403)


def test_admin_can_revoke_sessions_explicitly() -> None:
    admin = _user("admin@example.com")
    victim = _user("victim@example.com", role="operator")
    victim_id = victim["id"]
    victim_client = _client_for(victim)
    admin_client = _client_for(admin)
    res = admin_client.post(f"/users/{victim_id}/revoke-sessions")
    assert res.status_code == 200
    assert victim_client.get("/access/me").status_code in (401, 403)


def test_refresh_rotation_and_replay_detection() -> None:
    user = _user("u@example.com", role="operator")
    with get_session() as session:
        first = create_session_token(session, user_id=user["id"], token_type="refresh", lifetime=REFRESH_TTL)
        session.commit()
        first_value = first.token

    with get_session() as session:
        pair = refresh(RefreshRequest(refresh_token=first_value), session)
        session.commit()
    assert pair.refresh_token != first_value, "the presented refresh token must be rotated"

    # Replaying the consumed token is treated as a leak: every session is revoked.
    with get_session() as session:
        with pytest.raises(HTTPException) as exc:
            refresh(RefreshRequest(refresh_token=first_value), session)
        assert exc.value.status_code == 401
        session.commit()
    with get_session() as session:
        live = session.exec(
            select(SessionToken).where(SessionToken.user_id == user["id"], SessionToken.revoked == False)  # noqa: E712
        ).all()
    assert live == [], "refresh reuse did not revoke the token family"


# --- audit attribution -------------------------------------------------------

def test_user_changes_are_attributed_to_the_administrator() -> None:
    admin = _user("admin@example.com")
    client = _client_for(admin)
    created = client.post("/users", json={"email": "audited@example.com", "password": "Sup3r-secret-pw!"})
    assert created.status_code == 201, created.text
    target_id = created.json()["id"]
    assert client.patch(f"/users/{target_id}", json={"role": "developer"}).status_code == 200

    with get_session() as session:
        rows = session.exec(
            select(AuditLog).where(
                AuditLog.target == str(target_id),
                AuditLog.action.in_(["user_created", "user_updated"]),  # type: ignore[attr-defined]
            )
        ).all()
        actors = [r.actor_user_id for r in rows]
    assert actors, "no audit rows for the change"
    assert all(a == admin["id"] for a in actors), f"audit rows are not attributed to the actor: {actors}"
