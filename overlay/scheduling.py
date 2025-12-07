from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, select

from clanker.main import app, session_dep
from overlay.auth.security import require_roles
from clanker.db.models import Asset, Scan, ScanAssetStatus, ScanTarget
from clanker.db.session import get_session


class Schedule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=120)
    cron: str = Field(description="cron string, minute hour day month weekday")
    profile: str = Field(default="intense", max_length=50)
    asset_ids_json: str = Field(description="JSON array of asset IDs")
    active: bool = Field(default=True)
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None


class ScheduleCreate(BaseModel):
    name: str
    cron: str
    profile: str
    asset_ids: List[int]
    active: bool = True


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    cron: Optional[str] = None
    profile: Optional[str] = None
    asset_ids: Optional[List[int]] = None
    active: Optional[bool] = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cron_matches(dt: datetime, expr: str) -> bool:
    # Minimal matcher: support "* * * * *" or fixed minute/hour; accepts wildcards only
    # For advanced scheduling, integrate croniter later
    parts = expr.split()
    if len(parts) != 5:
        return False
    minute, hour, day, month, weekday = parts
    def _ok(p: str, v: int) -> bool:
        return p == "*" or p == str(v)
    return _ok(minute, dt.minute) and _ok(hour, dt.hour) and _ok(day, dt.day) and _ok(month, dt.month) and _ok(weekday, dt.weekday())


@app.on_event("startup")
def _ensure_schedule_table() -> None:
    # Create table if missing
    with get_session() as s:
        SQLModel.metadata.create_all(s.get_bind())  # ensure base
        s.exec(SQLModel.metadata.bind.execute if hasattr(SQLModel.metadata, 'bind') else select(Schedule)).first()  # touch


async def _scheduler_loop() -> None:
    while True:
        try:
            with get_session() as session:
                rows = session.exec(select(Schedule).where(Schedule.active == True)).all()  # noqa: E712
                now = _now()
                for sch in rows:
                    if sch.next_run_at and sch.next_run_at > now:
                        continue
                    if not _cron_matches(now, sch.cron):
                        continue
                    # Validate assets exist
                    asset_ids = []
                    try:
                        asset_ids = [int(x) for x in json.loads(sch.asset_ids_json) if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
                    except Exception:
                        asset_ids = []
                    if not asset_ids:
                        continue
                    assets = session.exec(select(Asset).where(Asset.id.in_(asset_ids))).all()
                    if not assets:
                        continue
                    # Create scan
                    scan = Scan(profile=sch.profile, status="queued")
                    session.add(scan)
                    session.flush()
                    for a in assets:
                        session.add(ScanTarget(scan_id=scan.id, asset_id=a.id))
                        session.add(ScanAssetStatus(scan_id=scan.id, asset_id=a.id, status="pending", attempts=0))
                    session.commit()
                    # Launch job
                    from clanker.main import run_scan_job  # type: ignore
                    loop = asyncio.get_event_loop()
                    loop.run_in_executor(None, run_scan_job, scan.id)
                    sch.last_run_at = now
                    session.add(sch)
                    session.commit()
        except Exception:
            pass
        await asyncio.sleep(60)


@app.on_event("startup")
async def _start_scheduler() -> None:
    loop = asyncio.get_event_loop()
    loop.create_task(_scheduler_loop())


@app.get("/schedules", response_model=list[Schedule])
def list_schedules(_: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> list[Schedule]:
    return session.exec(select(Schedule).order_by(Schedule.id.desc())).all()


@app.post("/schedules", response_model=Schedule, status_code=201)
def create_schedule(payload: ScheduleCreate, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> Schedule:
    sch = Schedule(name=payload.name, cron=payload.cron, profile=payload.profile, asset_ids_json=json.dumps(payload.asset_ids), active=payload.active)
    session.add(sch)
    session.flush()
    session.refresh(sch)
    return sch


@app.patch("/schedules/{schedule_id}", response_model=Schedule)
def update_schedule(schedule_id: int, payload: ScheduleUpdate, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> Schedule:
    sch = session.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if payload.name is not None:
        sch.name = payload.name
    if payload.cron is not None:
        sch.cron = payload.cron
    if payload.profile is not None:
        sch.profile = payload.profile
    if payload.asset_ids is not None:
        sch.asset_ids_json = json.dumps(payload.asset_ids)
    if payload.active is not None:
        sch.active = payload.active
    session.add(sch)
    session.flush()
    session.refresh(sch)
    return sch


@app.post("/schedules/{schedule_id}/run-now")
def run_now(schedule_id: int, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> dict:
    sch = session.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(status_code=404, detail="Schedule not found")
    sch.next_run_at = _now()
    session.add(sch)
    return {"status": "queued"}

