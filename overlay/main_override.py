from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional
import threading
import time
from datetime import datetime

from fastapi import Depends, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import ConfigDict
from sqlalchemy import bindparam, text
from sqlmodel import Session, select, func

from clanker.main import app as app  # reuse existing app
from clanker.main import session_dep
from clanker.db.models import (
    Asset,
    AssetRead,
    Finding,
    FindingRead,
    Scan,
    ScanCreate,
    ScanEvent,
    ScanRead,
    ScanAssetStatusRead,
    ScanDetail,
    ScanAssetStatus,
    ScanTarget,
)
from clanker.db.session import get_session
from overlay.src.clanker.db.scheduling_models import AssetGroup, AssetGroupMember, ScheduleJob
import clanker.main as cm
from overlay.auth.security import require_roles

# Ensure auth models and routes are registered (User/Token tables and /auth endpoints)
try:
    from overlay.auth import api as _auth_api  # noqa: F401
except Exception:
    pass

# Register security headers middleware (CSP, etc.) if available
try:
    from overlay import security_headers as _security_headers  # noqa: F401
except Exception:
    pass

# Register enrichment migrations and API
try:
    from overlay import startup_enrichment as _enrich_startup  # noqa: F401
    from overlay import enrichment_api as _enrich_api  # noqa: F401
    from overlay import auto_enrich as _auto_enrich  # noqa: F401
    from overlay import rbac_override as _rbac  # noqa: F401
except Exception:
    pass


def _parse_csv_env(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default
    return [part.strip() for part in raw.split(",") if part.strip()]


def _configure_cors_from_env() -> None:
    """Replace permissive default CORS settings with env-driven values."""
    origins = _parse_csv_env("CLANKER_CORS_ORIGINS", [])
    origin_regex = os.getenv("CLANKER_CORS_ORIGIN_REGEX")
    methods = _parse_csv_env("CLANKER_CORS_METHODS", ["GET", "POST", "PATCH", "DELETE", "OPTIONS"])
    headers = _parse_csv_env("CLANKER_CORS_HEADERS", ["Authorization", "Content-Type"])
    allow_credentials = os.getenv("CLANKER_CORS_ALLOW_CREDENTIALS", "false").lower() in {"1", "true", "yes", "y"}

    app.user_middleware = [m for m in app.user_middleware if getattr(m, "cls", None) is not CORSMiddleware]
    app.middleware_stack = None  # reset so we can safely add middleware before startup
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_origin_regex=origin_regex or None,
        allow_methods=methods or ["GET"],
        allow_headers=headers or ["Authorization", "Content-Type"],
        allow_credentials=allow_credentials,
    )
    app.middleware_stack = app.build_middleware_stack()


_configure_cors_from_env()


def _parse_references(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [s for s in data if isinstance(s, str)]
    except Exception:
        pass
    return []


class FindingWithEnrichment(FindingRead):
    cvss_v31_base: Optional[float] = None
    cvss_vector: Optional[str] = None
    references: Optional[List[str]] = None

    model_config = ConfigDict(from_attributes=True)


def _remove_route(path: str, method: str = "GET") -> None:
    to_keep = []
    for r in app.router.routes:  # type: ignore[attr-defined]
        try:
            if getattr(r, "path", None) == path and method in getattr(r, "methods", {"GET"}):
                continue
        except Exception:
            pass
        to_keep.append(r)
    app.router.routes = to_keep  # type: ignore[attr-defined]


# Remove legacy UI endpoint entirely; React app is the primary UI
_remove_route("/legacy", "GET")

_remove_route("/assets", "GET")
@app.get("/assets", response_model=List[AssetRead])
def list_assets(
    _: object = Depends(require_roles("admin", "operator", "viewer")),
    q: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    owner: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    response: Response = None,  # type: ignore[assignment]
    session: Session = Depends(session_dep),
) -> List[Asset]:
    query = select(Asset)
    if q:
        like = f"%{q}%"
        query = query.where((Asset.target.like(like)) | (Asset.name.like(like)))
    if environment:
        query = query.where(Asset.environment == environment)
    if owner:
        query = query.where(Asset.owner == owner)
    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.order_by(Asset.created_at.desc()).limit(limit).offset(offset)).all()
    if response is not None:
        response.headers["X-Total-Count"] = str(int(total or 0))
    return rows


_remove_route("/scans", "GET")
@app.get("/scans", response_model=List[ScanRead])
def list_scans(
    _: object = Depends(require_roles("admin", "operator", "viewer")),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    response: Response = None,  # type: ignore[assignment]
    session: Session = Depends(session_dep),
) -> List[Scan]:
    query = select(Scan)
    if status:
        query = query.where(Scan.status == status)
    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.order_by(Scan.created_at.desc()).limit(limit).offset(offset)).all()
    if response is not None:
        response.headers["X-Total-Count"] = str(int(total or 0))
    return rows


# Override scan creation to enqueue instead of immediate execution
_remove_route("/scans", "POST")
@app.post("/scans", response_model=ScanRead, status_code=201)
def create_scan(
    payload: ScanCreate,
    _: object = Depends(require_roles("admin", "operator")),
    session: Session = Depends(session_dep),
) -> Scan:
    if not payload.asset_ids:
        raise HTTPException(status_code=400, detail="asset_ids must not be empty")

    asset_ids = sorted(set(payload.asset_ids))
    assets = session.exec(select(Asset).where(Asset.id.in_(asset_ids))).all()
    if len(assets) != len(asset_ids):
        raise HTTPException(status_code=404, detail="One or more assets not found")

    profile_key = payload.profile or cm.DEFAULT_PROFILE_KEY  # type: ignore[attr-defined]
    if profile_key not in cm.SCAN_PROFILE_KEYS:  # type: ignore[attr-defined]
        raise HTTPException(status_code=400, detail="Unknown scan profile")

    scan = Scan(profile=profile_key, status="queued")
    session.add(scan)
    session.flush()

    for asset in assets:
        session.add(ScanTarget(scan_id=scan.id, asset_id=asset.id))
        cm._ensure_asset_status(session, scan.id, asset.id)  # type: ignore[attr-defined]

    session.commit()
    cm._record_scan_event(session, scan.id, "Scan enqueued")  # type: ignore[attr-defined]
    return scan


_remove_route("/findings", "GET")
@app.get("/findings", response_model=List[FindingWithEnrichment])
def list_findings(
    _: object = Depends(require_roles("admin", "operator", "viewer")),
    scan_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    response: Response = None,  # type: ignore[assignment]
    session: Session = Depends(session_dep),
) -> List[Finding]:
    query = select(Finding)
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if status_filter is not None:
        query = query.where(Finding.status == status_filter)
    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.order_by(Finding.detected_at.desc()).limit(limit).offset(offset)).all()
    enrichment_by_finding: Dict[int, Dict[str, Any]] = {}
    ids = [f.id for f in rows if f.id is not None]
    if ids:
        try:
            stmt = (
                text(
                    "SELECT finding_id, cvss_v31_base, cvss_vector, references_json "
                    "FROM finding_enrichment WHERE finding_id IN :ids"
                ).bindparams(bindparam("ids", expanding=True))
            )
            for row in session.exec(stmt, {"ids": ids}).all():
                data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
                fid = int(data.get("finding_id"))
                enrichment_by_finding[fid] = {
                    "cvss_v31_base": data.get("cvss_v31_base"),
                    "cvss_vector": data.get("cvss_vector"),
                    "references": _parse_references(data.get("references_json")),
                }
        except Exception:
            enrichment_by_finding = {}
    if response is not None:
        response.headers["X-Total-Count"] = str(int(total or 0))
    enriched: List[FindingWithEnrichment] = []
    for finding in rows:
        base = finding.model_dump()
        extra = enrichment_by_finding.get(finding.id or -1, {})
        payload = {
            **base,
            "cvss_v31_base": extra.get("cvss_v31_base"),
            "cvss_vector": extra.get("cvss_vector"),
            "references": extra.get("references") or None,
        }
        enriched.append(FindingWithEnrichment.model_validate(payload))
    return enriched


@app.get("/scans/{scan_id}/events/stream")
def stream_scan_events(
    scan_id: int,
    _: object = Depends(require_roles("admin", "operator", "viewer")),
):
    async def event_gen():
        last_id: Optional[int] = None
        while True:
            try:
                with get_session() as session:
                    q = select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc()).limit(1)
                    row = session.exec(q).first()
                    if row and row.id != last_id:
                        last_id = row.id
                        payload = {"id": row.id, "created_at": row.created_at.isoformat(), "message": row.message}
                        yield f"data: {json.dumps(payload)}\n\n"
            except Exception:
                pass
            await asyncio.sleep(2)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# ------------------------
# Cancel scan endpoint
# ------------------------

@app.post("/scans/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: int, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> Scan:
    scan = session.get(Scan, scan_id)
    if not scan:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in {"completed", "failed", "completed_with_errors", "cancelled"}:
        return scan
    cm._record_scan_event(session, scan_id, "Scan cancellation requested")  # type: ignore[attr-defined]
    # Mark pending assets as cancelled
    now = datetime.utcnow()
    statuses = session.exec(
        select(ScanAssetStatus).where(
            ScanAssetStatus.scan_id == scan_id,
            ScanAssetStatus.status == "pending",
        )
    ).all()
    for status in statuses:
        status.status = "cancelled"
        status.completed_at = now
        session.add(status)
    scan.status = "cancelled"
    scan.completed_at = scan.completed_at or now
    session.add(scan)
    session.commit()
    cm._record_scan_event(session, scan_id, "Scan cancelled")  # type: ignore[attr-defined]
    session.refresh(scan)
    return scan


# -----------------------------
# Override run_scan_job to respect cancellation
# -----------------------------

def run_scan_job(scan_id: int) -> None:  # noqa: C901
    from clanker.db.session import get_session as session_factory
    from clanker.core.scanner import get_scan_profile, execute_nmap, parse_nmap_xml
    from clanker.core.findings import build_findings

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            cm.logger.error("Scan %s vanished before start", scan_id)
            return
        if scan.status == "cancelled":
            cm._record_scan_event(session, scan_id, "Scan cancelled before start; skipping")  # type: ignore[attr-defined]
            session.commit()
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        session.add(scan)
        cm._record_scan_event(session, scan_id, "Scan started")  # type: ignore[attr-defined]
        session.commit()

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        asset_links = session.exec(
            select(Asset)
            .join(ScanTarget, ScanTarget.asset_id == Asset.id)
            .where(ScanTarget.scan_id == scan_id)
        ).all()

        if not asset_links:
            scan.status = "failed"
            scan.notes = "No assets were linked to the scan"
            cm._record_scan_event(session, scan_id, "No assets to scan")  # type: ignore[attr-defined]
            session.add(scan)
            session.commit()
            return

        profile = get_scan_profile(scan.profile)
        asset_errors = False
        for asset in asset_links:
            # Check if cancelled before processing next asset
            scan = session.get(Scan, scan_id)
            if scan and scan.status == "cancelled":
                cm._record_scan_event(session, scan_id, "Cancellation detected; stopping further asset scans")  # type: ignore[attr-defined]
                session.commit()
                break
            retrying = True
            while retrying:
                status_row = cm._ensure_asset_status(session, scan_id, asset.id or 0)  # type: ignore[attr-defined]
                status_row.status = "running"
                status_row.started_at = status_row.started_at or datetime.utcnow()
                status_row.attempts += 1
                session.add(status_row)
                session.commit()
                cm._record_scan_event(
                    session, scan_id, f"Scanning {asset.target} (attempt {status_row.attempts})"
                )  # type: ignore[attr-defined]

                try:
                    xml_path = execute_nmap(asset, profile)
                    observations = parse_nmap_xml(xml_path, asset)
                    build_findings(session, scan_id=scan_id, asset_id=asset.id or 0, observations=observations)
                    status_row.status = "completed"
                    status_row.completed_at = datetime.utcnow()
                    status_row.last_error = None
                    session.add(status_row)
                    session.commit()
                    cm._record_scan_event(
                        session, scan_id, f"Finished {asset.target} with {len(observations)} open services"
                    )  # type: ignore[attr-defined]
                    retrying = False
                except FileNotFoundError:
                    scan.status = "failed"
                    scan.notes = "nmap binary not found on host"
                    status_row.status = "failed"
                    status_row.last_error = "nmap missing"
                    status_row.completed_at = datetime.utcnow()
                    session.add_all([scan, status_row])
                    session.commit()
                    cm._record_scan_event(session, scan_id, "nmap binary missing. Aborting scan.")  # type: ignore[attr-defined]
                    return
                except Exception as exc:  # pylint: disable=broad-except
                    cm.logger.exception("Scan %s failed for asset %s: %s", scan_id, asset.target, exc)
                    status_row.status = "failed"
                    status_row.last_error = str(exc)
                    status_row.completed_at = datetime.utcnow()
                    session.add(status_row)
                    session.commit()
                    cm._record_scan_event(session, scan_id, f"Failed {asset.target}: {exc}")  # type: ignore[attr-defined]
                    if status_row.attempts <= cm.settings.scan_retry_limit:  # type: ignore[attr-defined]
                        scan.retry_count += 1
                        session.add(scan)
                        session.commit()
                        status_row.status = "pending"
                        session.add(status_row)
                        session.commit()
                        cm._record_scan_event(
                            session, scan_id, f"Retrying {asset.target} (attempt {status_row.attempts + 1})"
                        )  # type: ignore[attr-defined]
                        continue
                    asset_errors = True
                    retrying = False
                    break

        # Finalize only if not cancelled by user
        scan = session.get(Scan, scan_id)
        if scan and scan.status != "cancelled":
            scan.completed_at = datetime.utcnow()
            if asset_errors:
                scan.status = "completed_with_errors"
                scan.notes = "One or more assets failed to scan"
            else:
                scan.status = "completed"
                scan.notes = None
            session.add(scan)
            cm._record_scan_event(session, scan_id, f"Scan finished with status {scan.status}")  # type: ignore[attr-defined]
            session.commit()


# Patch the original symbol so existing callers use the override
cm.run_scan_job = run_scan_job


# -----------------------------
# Minimal scheduler (weekday/time)
# -----------------------------

def _valid_time(value: str) -> bool:
    if not value or ":" not in value:
        return False
    try:
        h_str, m_str = value.split(":", 1)
        h = int(h_str)
        m = int(m_str)
        return 0 <= h <= 23 and 0 <= m <= 59
    except Exception:
        return False


def _parse_times(raw: Optional[str]) -> List[str]:
    try:
        data = json.loads(raw) if raw else []
        if isinstance(data, list):
            times = []
            for t in data:
                s = str(t).strip()
                if _valid_time(s):
                    times.append(s)
            return times
    except Exception:
        pass
    return []


def _parse_days(raw: Optional[str]) -> List[int]:
    try:
        data = json.loads(raw) if raw else []
        if isinstance(data, list):
            days: List[int] = []
            for d in data:
                try:
                    n = int(d)
                    if 0 <= n <= 6:
                        days.append(n)
                except Exception:
                    continue
            return days
    except Exception:
        pass
    return []


def _should_run(job: ScheduleJob, now: datetime, last_run: Optional[datetime]) -> bool:
    days = _parse_days(job.days_of_week) or list(range(7))
    times = _parse_times(job.times) or ["00:00"]
    if now.weekday() not in days:
        return False
    if last_run and last_run.year == now.year and last_run.month == now.month and last_run.day == now.day:
        if last_run.hour == now.hour and last_run.minute == now.minute:
            return False
    now_hm = f"{now.hour:02d}:{now.minute:02d}"
    return now_hm in times


def _scheduler_ticker() -> None:
    from clanker.db.session import get_session as session_factory

    _ensure_scheduler_tables()
    while True:
        try:
            with session_factory() as session:
                now = datetime.utcnow()
                jobs = session.exec(select(ScheduleJob).where(ScheduleJob.enabled == True)).all()  # noqa: E712
                for job in jobs:
                    if not _should_run(job, now, job.last_run_at):
                        continue
                    asset_ids = [row.asset_id for row in session.exec(
                        select(AssetGroupMember).where(AssetGroupMember.asset_group_id == job.asset_group_id)
                    ).all()]
                    if not asset_ids:
                        job.last_run_at = now
                        session.add(job)
                        session.commit()
                        continue
                    running_scans = session.exec(
                        select(Scan.id)
                        .where(Scan.status.in_(["queued", "running"]))
                        .where(
                            Scan.id.in_(
                                select(ScanTarget.scan_id).where(ScanTarget.asset_id.in_(asset_ids))
                            )
                        )
                    ).all()
                    if running_scans:
                        try:
                            cm._record_scan_event(session, int(running_scans[0][0]), "Skipped scheduled run due to overlap")  # type: ignore[attr-defined]
                        except Exception:
                            pass
                        job.last_run_at = now
                        session.add(job)
                        session.commit()
                        continue
                    scan = Scan(profile=job.profile, status="queued")
                    session.add(scan)
                    session.flush()
                    for aid in sorted(set(asset_ids)):
                        session.add(ScanTarget(scan_id=scan.id, asset_id=aid))
                        cm._ensure_asset_status(session, scan.id, aid)  # type: ignore[attr-defined]
                    session.commit()
                    cm._record_scan_event(session, scan.id, f"Scheduled run for job '{job.name}' created")  # type: ignore[attr-defined]
                    job.last_run_at = now
                    session.add(job)
                    session.commit()
                    threading.Thread(target=cm.run_scan_job, args=(scan.id,), daemon=True).start()
        except Exception:
            cm.logger.exception("Scheduler ticker encountered an error")
        time.sleep(30)


@app.on_event("startup")
def _start_scheduler() -> None:
    t = threading.Thread(target=_scheduler_ticker, name="scheduler-ticker", daemon=True)
    t.start()


# -----------------------------
# Scan queue worker
# -----------------------------

def _scan_queue_worker() -> None:
    from clanker.db.session import get_session as session_factory

    while True:
        try:
            with session_factory() as session:
                scan = session.exec(
                    select(Scan).where(Scan.status == "queued").order_by(Scan.created_at).limit(1)
                ).first()
                if not scan:
                    time.sleep(5)
                    continue
                cm._record_scan_event(session, scan.id, "Dispatching scan from queue")  # type: ignore[attr-defined]
                session.commit()
                cm.run_scan_job(scan.id)  # type: ignore[attr-defined]
        except Exception:
            cm.logger.exception("Scan queue worker error")
            time.sleep(5)


@app.on_event("startup")
def _start_scan_queue() -> None:
    t = threading.Thread(target=_scan_queue_worker, name="scan-queue-worker", daemon=True)
    t.start()


# -----------------------------
# Minimal CRUD for scheduling
# -----------------------------


def _ensure_scheduler_tables() -> None:
    """Create scheduler tables if missing (idempotent)."""
    from clanker.db.session import engine

    ddl = [
        """
        CREATE TABLE IF NOT EXISTS assetgroup (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          description TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS assetgroupmember (
          asset_group_id INTEGER NOT NULL,
          asset_id INTEGER NOT NULL,
          PRIMARY KEY (asset_group_id, asset_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS schedulejob (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          cron TEXT NOT NULL,
          profile TEXT NOT NULL,
          asset_group_id INTEGER NOT NULL,
          enabled BOOLEAN DEFAULT 1,
          last_run_at TEXT,
          days_of_week TEXT,
          times TEXT
        )
        """
    ]
    with engine.connect() as conn:
        for stmt in ddl:
            conn.execute(text(stmt))
        for ddl_stmt in [
            "ALTER TABLE schedulejob ADD COLUMN days_of_week TEXT",
            "ALTER TABLE schedulejob ADD COLUMN times TEXT",
        ]:
            try:
                conn.execute(text(ddl_stmt))
            except Exception:
                pass
        conn.commit()


@app.post("/asset_groups", response_model=dict)
def create_asset_group(payload: dict, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> dict:
    name = payload.get("name")
    description = payload.get("description")
    asset_ids = list({int(a) for a in (payload.get("asset_ids") or [])})
    if not name:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="name is required")
    group = AssetGroup(name=name, description=description)
    session.add(group)
    session.flush()
    for aid in asset_ids:
        session.add(AssetGroupMember(asset_group_id=group.id, asset_id=aid))
    session.commit()
    return {"id": group.id, "name": group.name, "description": group.description, "asset_count": len(asset_ids)}


@app.get("/asset_groups", response_model=List[dict])
def list_asset_groups(_: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)) -> List[dict]:
    groups = session.exec(select(AssetGroup).order_by(AssetGroup.created_at.desc())).all()
    results: List[dict] = []
    for g in groups:
        count = session.exec(
            select(func.count()).select_from(select(AssetGroupMember).where(AssetGroupMember.asset_group_id == g.id).subquery())
        ).one()
        results.append({"id": g.id, "name": g.name, "description": g.description, "asset_count": int(count or 0)})
    return results


@app.post("/schedules", response_model=dict)
def create_schedule(payload: dict, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> dict:
    name = payload.get("name")
    profile = payload.get("profile") or "intense"
    asset_group_id = payload.get("asset_group_id")
    asset_ids = list({int(a) for a in (payload.get("asset_ids") or []) if isinstance(a, (int, str)) and str(a).isdigit()})
    days = payload.get("days_of_week") or payload.get("days")
    times = payload.get("times")
    days_list: List[int] = []
    times_list: List[str] = []
    if days and isinstance(days, list):
        for d in days:
            try:
                n = int(d)
                if 0 <= n <= 6:
                    days_list.append(n)
            except Exception:
                continue
    if times and isinstance(times, list):
        for t in times:
            s = str(t).strip()
            if _valid_time(s):
                times_list.append(s)
    if not name:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="name is required")
    if not asset_group_id and not asset_ids:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="asset_group_id or asset_ids is required")
    if not asset_group_id and asset_ids:
        group = AssetGroup(name=f"Schedule {name}", description=f"Auto group for schedule {name}")
        session.add(group)
        session.flush()
        for aid in asset_ids:
            session.add(AssetGroupMember(asset_group_id=group.id, asset_id=aid))
        asset_group_id = group.id
    if not times_list:
        times_list = ["00:00"]
    if not days_list:
        days_list = list(range(7))
    job = ScheduleJob(
        name=name,
        cron="* * * * *",
        profile=profile,
        asset_group_id=int(asset_group_id),
        enabled=bool(payload.get("enabled", True)),
        days_of_week=json.dumps(days_list),
        times=json.dumps(times_list),
    )
    session.add(job)
    session.commit()
    return {
        "id": job.id,
        "name": job.name,
        "profile": job.profile,
        "asset_group_id": job.asset_group_id,
        "asset_ids": asset_ids,
        "days_of_week": days_list,
        "times": times_list,
        "enabled": job.enabled,
    }


@app.get("/schedules", response_model=List[dict])
def list_schedules(_: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)) -> List[dict]:
    jobs = session.exec(select(ScheduleJob).order_by(ScheduleJob.id.desc())).all()
    return [
        {
            "id": j.id,
            "name": j.name,
            "profile": j.profile,
            "asset_group_id": j.asset_group_id,
            "asset_ids": list(
                session.exec(
                    select(AssetGroupMember.asset_id).where(AssetGroupMember.asset_group_id == j.asset_group_id)
                ).all()
            ),
            "days_of_week": _parse_days(j.days_of_week),
            "times": _parse_times(j.times),
            "enabled": j.enabled,
            "last_run_at": j.last_run_at,
        }
        for j in jobs
    ]


@app.patch("/schedules/{schedule_id}", response_model=dict)
def update_schedule(
    schedule_id: int, payload: dict, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)
) -> dict:
    job = session.get(ScheduleJob, schedule_id)
    if not job:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Schedule not found")

    if "name" in payload:
        job.name = payload.get("name") or job.name
    if "profile" in payload and payload.get("profile"):
        job.profile = payload["profile"]
    if "enabled" in payload:
        job.enabled = bool(payload.get("enabled", True))

    if "days_of_week" in payload:
        days_list: List[int] = []
        for d in payload.get("days_of_week") or []:
            try:
                n = int(d)
                if 0 <= n <= 6:
                    days_list.append(n)
            except Exception:
                continue
        if days_list:
            job.days_of_week = json.dumps(days_list)
    if "times" in payload:
        times_list: List[str] = []
        for t in payload.get("times") or []:
            s = str(t).strip()
            if _valid_time(s):
                times_list.append(s)
        if times_list:
            job.times = json.dumps(times_list)

    if "asset_ids" in payload and isinstance(payload.get("asset_ids"), list):
        asset_ids = list({int(a) for a in payload.get("asset_ids") if isinstance(a, (int, str)) and str(a).isdigit()})
        if asset_ids:
            # Ensure group exists
            if not job.asset_group_id:
                group = AssetGroup(name=f"Schedule {job.name}", description=f"Auto group for schedule {job.name}")
                session.add(group)
                session.flush()
                job.asset_group_id = group.id
            # Replace members
            session.exec(
                text("DELETE FROM assetgroupmember WHERE asset_group_id = :gid"),
                {"gid": job.asset_group_id},
            )
            for aid in asset_ids:
                session.add(AssetGroupMember(asset_group_id=job.asset_group_id, asset_id=aid))

    session.add(job)
    session.commit()
    return {
        "id": job.id,
        "name": job.name,
        "profile": job.profile,
        "asset_group_id": job.asset_group_id,
        "asset_ids": [
            row.asset_id
            for row in session.exec(
                select(AssetGroupMember.asset_id).where(AssetGroupMember.asset_group_id == job.asset_group_id)
            ).all()
        ],
        "days_of_week": _parse_days(job.days_of_week),
        "times": _parse_times(job.times),
        "enabled": job.enabled,
        "last_run_at": job.last_run_at,
    }


@app.delete("/schedules/{schedule_id}", status_code=204, response_class=Response)
def delete_schedule(schedule_id: int, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> Response:
    job = session.get(ScheduleJob, schedule_id)
    if not job:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Schedule not found")
    session.delete(job)
    session.commit()
    return Response(status_code=204)


@app.post("/schedules/{schedule_id}/run-now", response_model=dict)
def run_schedule_now(
    schedule_id: int, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)
) -> dict:
    job = session.get(ScheduleJob, schedule_id)
    if not job:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Schedule not found")
    asset_ids = [
        row.asset_id
        for row in session.exec(
            select(AssetGroupMember.asset_id).where(AssetGroupMember.asset_group_id == job.asset_group_id)
        ).all()
    ]
    asset_ids = [int(a) for a in asset_ids if a is not None]
    if not asset_ids:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="No assets linked to this schedule")
    scan = Scan(profile=job.profile, status="queued")
    session.add(scan)
    session.flush()
    for aid in asset_ids:
        session.add(ScanTarget(scan_id=scan.id, asset_id=aid))
        cm._ensure_asset_status(session, scan.id, aid)  # type: ignore[attr-defined]
    session.commit()
    cm._record_scan_event(session, scan.id, f"Manual run for schedule '{job.name}' created")  # type: ignore[attr-defined]
    threading.Thread(target=cm.run_scan_job, args=(scan.id,), daemon=True).start()
    return {"status": "queued", "scan_id": scan.id}

# Gate additional read endpoints defined in core
from clanker.main import (
    get_asset as _get_asset,
    get_scan as _get_scan,
    get_scan_asset_status as _get_scan_asset_status,
    list_scan_events as _list_scan_events,
)

_remove_route("/assets/{asset_id}", "GET")
@app.get("/assets/{asset_id}", response_model=AssetRead)
def get_asset_guarded(asset_id: int, _: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)):
    return _get_asset(asset_id, session)  # type: ignore[misc]

_remove_route("/scans/{scan_id}", "GET")
@app.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan_guarded(scan_id: int, _: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)):
    return _get_scan(scan_id, session)  # type: ignore[misc]

_remove_route("/scans/{scan_id}/assets", "GET")
@app.get("/scans/{scan_id}/assets", response_model=List[ScanAssetStatusRead])
def get_scan_assets_guarded(scan_id: int, _: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)):
    return _get_scan_asset_status(scan_id, session)  # type: ignore[misc]

_remove_route("/scans/{scan_id}/events", "GET")
@app.get("/scans/{scan_id}/events")
def list_scan_events_guarded(scan_id: int, _: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)):
    return _list_scan_events(scan_id, session)  # type: ignore[misc]
