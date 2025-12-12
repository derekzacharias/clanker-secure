import json

import pytest
from fastapi import HTTPException
from sqlmodel import select

# Importing overlay ensures overrides are applied before we grab the app
from overlay import main_override  # noqa: F401
from overlay.auth.security import CurrentUser
from clanker.main import ACCESS_TTL, AgentIngestRequest, create_session_token, hash_password, ingest_agent_inventory
from clanker.db.models import AgentIngest, Asset, Finding, User
from clanker.db.session import get_session


def _ensure_current_user(session) -> CurrentUser:
    user = session.exec(select(User).where(User.email == "agent-ingest@example.com")).first()
    if not user:
        user = User(
            email="agent-ingest@example.com",
            name="Agent Ingest",
            hashed_password=hash_password("Password123!"),
            role="admin",
            active=True,
        )
        session.add(user)
        session.flush()
    token = create_session_token(session, user_id=user.id, token_type="access", lifetime=ACCESS_TTL)
    session.refresh(token)
    return CurrentUser(user=user, token=token)


def _ensure_asset(session) -> int:
    asset = session.exec(select(Asset).where(Asset.target == "10.10.10.10")).first()
    if not asset:
        asset = Asset(target="10.10.10.10", name="agent-host")
        session.add(asset)
        session.flush()
    session.refresh(asset)
    return asset.id  # type: ignore[return-value]


def test_agent_ingest_persists_inventory():
    with get_session() as session:
        current = _ensure_current_user(session)
        asset_id = _ensure_asset(session)
        payload = AgentIngestRequest(
            agent_id="agent-123",
            agent_version="0.1.0",
            asset_id=asset_id,
            inventory={
                "host_identifier": "host-uuid-1",
                "hostname": "agent-hostname",
                "os_name": "linux",
                "os_version": "Debian 12",
                "kernel_version": "6.1.0-18-amd64",
                "distro": "debian",
                "packages": [
                    {"name": "openssh-server", "version": "1:9.2p1"},
                    {"name": "curl", "version": "7.88.1"},
                ],
                "services": [
                    {"name": "ssh", "status": "active", "port": 22, "protocol": "tcp"},
                ],
                "configs": {"sshd_config": "PasswordAuthentication no"},
            },
        )
        resp = ingest_agent_inventory(payload, current=current, session=session)
        ingest_id = resp.ingest_id

    with get_session() as session:
        ingest = session.get(AgentIngest, ingest_id)
        assert ingest is not None
        assert ingest.asset_id == asset_id
        assert ingest.agent_id == "agent-123"
        assert ingest.package_count == 2
        assert ingest.service_count == 1
        assert ingest.host_identifier == "host-uuid-1"
        parsed = json.loads(ingest.raw_payload or "{}")
        assert parsed["inventory"]["hostname"] == "agent-hostname"


def test_agent_ingest_missing_asset_returns_404():
    with get_session() as session:
        current = _ensure_current_user(session)
        payload = AgentIngestRequest(asset_id=999999, inventory={"hostname": "bad-host"})

        with pytest.raises(HTTPException) as excinfo:
            ingest_agent_inventory(payload, current=current, session=session)
        assert excinfo.value.status_code == 404


def test_agent_ingest_creates_findings_from_inventory():
    with get_session() as session:
        current = _ensure_current_user(session)
        asset_id = _ensure_asset(session)
        payload = AgentIngestRequest(
            asset_id=asset_id,
            inventory={
                "host_identifier": "vuln-host",
                "hostname": "vuln-host",
                "os_name": "linux",
                "os_version": "Debian 11",
                "kernel_version": "5.10.0-10-amd64",
                "distro": "debian",
                "packages": [
                    {"name": "openssl", "version": "1.1.1k"},
                    {"name": "sudo", "version": "1.9.5p1"},
                ],
                "services": [
                    {"name": "ssh", "status": "active", "port": 22, "protocol": "tcp", "version": "8.2p1"},
                    {"name": "telnetd", "status": "active", "port": 23, "protocol": "tcp"},
                ],
                "configs": {"sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes"},
            },
        )
        resp = ingest_agent_inventory(payload, current=current, session=session)
        ingest_id = resp.ingest_id

    with get_session() as session:
        findings = session.exec(
            select(Finding)
            .where(Finding.asset_id == asset_id, Finding.host_address == "vuln-host")
            .order_by(Finding.id.desc())
        ).all()
        assert findings, "Expected findings persisted from agent inventory"
        assert any(f.rule_id and f.rule_id.startswith("AGENT-") for f in findings)
        assert any(f.evidence for f in findings)
        sources = []
        for f in findings:
            try:
                ev = json.loads(f.evidence or "[]")
            except Exception:
                ev = []
            for item in ev:
                if isinstance(item, dict):
                    data = item.get("data") or {}
                    src = data.get("rule_source")
                    if isinstance(src, str):
                        sources.append(src)
        assert sources, "Expected rule_source metadata in agent findings evidence"
