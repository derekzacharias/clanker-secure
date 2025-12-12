from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from fastapi import Response
from sqlmodel import delete

from clanker.db.models import (
    Asset,
    AuditLog,
    Finding,
    FindingComment,
    LoginAttempt,
    Scan,
    ScanAssetStatus,
    ScanEvent,
    ScanTarget,
    SessionToken,
    User,
)
from clanker.db.session import get_session, init_db
from clanker.main import list_assets, list_findings, list_scans


@pytest.fixture(autouse=True)
def _reset_db() -> None:
    """Start each test with a clean database."""
    init_db()
    with get_session() as session:
        for model in (
            FindingComment,
            Finding,
            ScanAssetStatus,
            ScanEvent,
            ScanTarget,
            Scan,
            Asset,
            SessionToken,
            LoginAttempt,
            AuditLog,
            User,
        ):
            session.exec(delete(model))


def _seed_assets(session):
    base = datetime(2024, 1, 1, 12, 0, 0)
    assets = [
        Asset(target="10.0.0.1", name="alpha-host", environment="prod", owner="team-red", created_at=base),
        Asset(
            target="10.0.0.2",
            name="beta-host",
            environment="staging",
            owner="team-blue",
            created_at=base + timedelta(minutes=1),
        ),
        Asset(
            target="10.0.0.3",
            name="gamma-host",
            environment="prod",
            owner="team-green",
            created_at=base + timedelta(minutes=2),
        ),
    ]
    session.add_all(assets)
    session.flush()
    return assets


def _seed_scans(session):
    base = datetime(2024, 1, 2, 9, 0, 0)
    scans = [
        Scan(status="queued", profile="quick", notes="initial quick", created_at=base),
        Scan(status="completed", profile="intense", notes="prod sweep", created_at=base + timedelta(minutes=1)),
        Scan(status="failed", profile="quick", notes="qa sweep", created_at=base + timedelta(minutes=2)),
    ]
    session.add_all(scans)
    session.flush()
    return scans


def _seed_findings(session, assets, scans):
    base = datetime(2024, 1, 3, 15, 0, 0)
    findings = [
        Finding(
            asset_id=assets[0].id,
            scan_id=scans[1].id,
            severity="high",
            status="open",
            service_name="ssh",
            description="SSH vulnerability",
            detected_at=base,
        ),
        Finding(
            asset_id=assets[0].id,
            scan_id=scans[1].id,
            severity="medium",
            status="resolved",
            service_name="http",
            description="Outdated HTTP stack",
            detected_at=base + timedelta(minutes=1),
        ),
        Finding(
            asset_id=assets[2].id,
            scan_id=scans[2].id,
            severity="critical",
            status="open",
            service_name="smtp",
            description="SMTP overflow",
            detected_at=base + timedelta(minutes=2),
        ),
    ]
    session.add_all(findings)
    session.flush()
    return findings


def test_list_assets_supports_filters_and_pagination():
    with get_session() as session:
        _seed_assets(session)

        response = Response()
        rows = list_assets(
            response=response,
            q=None,
            environment="prod",
            owner=None,
            limit=1,
            offset=1,
            session=session,
        )

        assert [asset.target for asset in rows] == ["10.0.0.1"]
        assert response.headers["X-Total-Count"] == "2"

        owner_response = Response()
        owner_rows = list_assets(
            response=owner_response,
            q=None,
            environment="prod",
            owner="team-red",
            limit=10,
            offset=0,
            session=session,
        )
        assert len(owner_rows) == 1
        assert owner_rows[0].target == "10.0.0.1"
        assert owner_response.headers["X-Total-Count"] == "1"

        search_response = Response()
        search_rows = list_assets(
            response=search_response,
            q="gamma",
            environment=None,
            owner=None,
            limit=5,
            offset=0,
            session=session,
        )
        assert len(search_rows) == 1
        assert search_rows[0].target == "10.0.0.3"
        assert search_response.headers["X-Total-Count"] == "1"


def test_list_scans_filters_and_paginates():
    with get_session() as session:
        scans = _seed_scans(session)

        response = Response()
        completed = list_scans(
            response=response,
            status="completed",
            profile=None,
            q=None,
            limit=5,
            offset=0,
            session=session,
        )
        assert len(completed) == 1
        assert completed[0].id == scans[1].id
        assert response.headers["X-Total-Count"] == "1"

        search_response = Response()
        searched = list_scans(
            response=search_response,
            status=None,
            profile=None,
            q=str(scans[0].id),
            limit=5,
            offset=0,
            session=session,
        )
        assert len(searched) == 1
        assert searched[0].id == scans[0].id
        assert search_response.headers["X-Total-Count"] == "1"

        paged_response = Response()
        paged = list_scans(
            response=paged_response,
            status=None,
            profile=None,
            q=None,
            limit=1,
            offset=1,
            session=session,
        )
        assert len(paged) == 1
        assert paged[0].id == scans[1].id  # second-most-recent by created_at desc
        assert paged_response.headers["X-Total-Count"] == "3"


def test_list_findings_filters_and_paginates():
    with get_session() as session:
        assets = _seed_assets(session)
        scans = _seed_scans(session)
        _seed_findings(session, assets, scans)

        response = Response()
        paged = list_findings(
            response=response,
            scan_id=scans[1].id,
            severity=None,
            status_filter=None,
            asset_id=None,
            search=None,
            limit=1,
            offset=1,
            session=session,
        )
        assert len(paged) == 1
        assert paged[0].service_name == "ssh"
        assert response.headers["X-Total-Count"] == "2"

        filtered_response = Response()
        filtered = list_findings(
            response=filtered_response,
            scan_id=None,
            severity="critical",
            status_filter="open",
            asset_id=assets[2].id,
            search="smtp",
            limit=5,
            offset=0,
            session=session,
        )
        assert len(filtered) == 1
        assert filtered[0].asset_id == assets[2].id
        assert filtered_response.headers["X-Total-Count"] == "1"

        bands = json.loads(filtered_response.headers["X-CVSS-Bands"])
        assert set(bands.keys()) == {"critical", "high", "medium", "low", "none", "unscored"}
        assert all(isinstance(v, int) for v in bands.values())

        search_response = Response()
        resolved = list_findings(
            response=search_response,
            scan_id=None,
            severity=None,
            status_filter="resolved",
            asset_id=None,
            search="http",
            limit=5,
            offset=0,
            session=session,
        )
        assert len(resolved) == 1
        assert resolved[0].status == "resolved"
