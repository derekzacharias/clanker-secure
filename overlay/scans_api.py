from __future__ import annotations

from fastapi import Depends, HTTPException
from clanker.main import app, session_dep
from sqlmodel import Session, select
from overlay.auth.security import require_roles
from clanker.db.models import Scan, ScanAssetStatus
from clanker.db.session import get_session
from datetime import datetime


@app.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> dict:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Mark statuses
    rows = session.exec(select(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id)).all()
    for row in rows:
        if row.status in ("pending", "running"):
            row.status = "cancelled"
            row.completed_at = row.completed_at or datetime.utcnow()
            session.add(row)
    # Mark scan
    scan.status = "cancelled"
    scan.completed_at = scan.completed_at or datetime.utcnow()
    if not (scan.notes or "").startswith("cancelled"):
        scan.notes = (scan.notes + "\n" if scan.notes else "") + "cancelled by user"
    session.add(scan)
    # Add event
    from clanker.main import _record_scan_event  # type: ignore

    _record_scan_event(session, scan_id, "Scan cancelled by user")
    session.commit()
    return {"status": "cancelled"}

