from __future__ import annotations

import asyncio
import json
from typing import List, Optional

from fastapi import Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlmodel import Session, select, func

# Reuse the existing application and dependencies
from clanker.main import app as app  # noqa: F401
from clanker.main import session_dep  # noqa: F401
from clanker.db.models import (
    Asset,
    AssetRead,
    Finding,
    FindingRead,
    Scan,
    ScanEvent,
    ScanRead,
)
from clanker.db.session import get_session


def _remove_route(path: str, method: str = "GET") -> None:
    # Remove existing route matching path+method so we can override
    to_keep = []
    for r in app.router.routes:  # type: ignore[attr-defined]
        try:
            if getattr(r, "path", None) == path and method in getattr(r, "methods", {"GET"}):
                continue
        except Exception:
            pass
        to_keep.append(r)
    app.router.routes = to_keep  # type: ignore[attr-defined]


# Override list endpoints with server-side pagination + filters
_remove_route("/assets", "GET")
@app.get("/assets", response_model=List[AssetRead])
def list_assets(
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


# SSE stream for scan events
@app.get("/scans/{scan_id}/events/stream")
def stream_scan_events(scan_id: int):
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
                # In case of transient DB errors, do not break the stream
                pass
            await asyncio.sleep(2)

    return StreamingResponse(event_gen(), media_type="text/event-stream")

