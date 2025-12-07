from __future__ import annotations

import asyncio
import json
from typing import List, Optional
import threading
import time
from datetime import datetime

from fastapi import Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlmodel import Session, select, func

from clanker.main import app as app  # reuse existing app
from clanker.main import session_dep
from clanker.db.models import (
    Asset,
    AssetRead,
    Finding,
    FindingRead,
    Scan,
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

# Register enrichment migrations and API
try:
    from overlay import startup_enrichment as _enrich_startup  # noqa: F401
    from overlay import enrichment_api as _enrich_api  # noqa: F401
    from overlay import auto_enrich as _auto_enrich  # noqa: F401
    from overlay import rbac_override as _rbac  # noqa: F401
except Exception:
    pass


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


_remove_route("/findings", "GET")
@app.get("/findings", response_model=List[FindingRead])
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
    if response is not None:
        response.headers["X-Total-Count"] = str(int(total or 0))
    return rows


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
# Minimal scheduler (cron-like)
# -----------------------------

def _parse_minute_field(field: str, minute: int) -> bool:
    f = field.strip()
    if f == "*":
        return True
    if f.startswith("*/"):
        try:
            n = int(f[2:])
            return n > 0 and (minute % n == 0)
        except ValueError:
            return False
    try:
        return int(f) == minute
    except ValueError:
        return False


def _cron_due(cron: str, now: datetime, last_run: Optional[datetime]) -> bool:
    parts = (cron or "*").split()
    if len(parts) < 5:
        parts = parts + ["*"] * (5 - len(parts))
    minute_field = parts[0]
    if last_run and last_run.year == now.year and last_run.month == now.month and last_run.day == now.day:
        if last_run.hour == now.hour and last_run.minute == now.minute:
            return False
    return _parse_minute_field(minute_field, now.minute)


def _scheduler_ticker() -> None:
    from clanker.db.session import get_session as session_factory

    while True:
        try:
            with session_factory() as session:
                now = datetime.utcnow()
                jobs = session.exec(select(ScheduleJob).where(ScheduleJob.enabled == True)).all()  # noqa: E712
                for job in jobs:
                    if not _cron_due(job.cron, now, job.last_run_at):
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
# Minimal CRUD for scheduling
# -----------------------------

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
    cron = payload.get("cron") or "* * * * *"
    profile = payload.get("profile") or "intense"
    asset_group_id = payload.get("asset_group_id")
    if not name or not asset_group_id:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="name and asset_group_id are required")
    job = ScheduleJob(name=name, cron=cron, profile=profile, asset_group_id=int(asset_group_id), enabled=bool(payload.get("enabled", True)))
    session.add(job)
    session.commit()
    return {"id": job.id, "name": job.name, "cron": job.cron, "profile": job.profile, "asset_group_id": job.asset_group_id, "enabled": job.enabled}


@app.get("/schedules", response_model=List[dict])
def list_schedules(_: object = Depends(require_roles("admin", "operator", "viewer")), session: Session = Depends(session_dep)) -> List[dict]:
    jobs = session.exec(select(ScheduleJob).order_by(ScheduleJob.id.desc())).all()
    return [
        {
            "id": j.id,
            "name": j.name,
            "cron": j.cron,
            "profile": j.profile,
            "asset_group_id": j.asset_group_id,
            "enabled": j.enabled,
            "last_run_at": j.last_run_at,
        }
        for j in jobs
    ]

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
