from __future__ import annotations

from typing import List, Optional

from fastapi import BackgroundTasks, Depends, HTTPException, Response
from sqlmodel import Session

from clanker.main import app, session_dep
from overlay.auth.security import require_roles

# Import original handlers to delegate business logic
from clanker.main import (
    create_asset as _create_asset,
    update_asset as _update_asset,
    delete_asset as _delete_asset,
    create_scan as _create_scan,
    delete_scan as _delete_scan,
    update_finding as _update_finding,
)
from clanker.db.models import AssetCreate, AssetRead, AssetUpdate, ScanCreate, ScanRead, FindingRead, FindingUpdate


def _remove_route(path: str, method: str) -> None:
    to_keep = []
    for r in app.router.routes:  # type: ignore[attr-defined]
        try:
            if getattr(r, "path", None) == path and method in getattr(r, "methods", {"GET"}):
                continue
        except Exception:
            pass
        to_keep.append(r)
    app.router.routes = to_keep  # type: ignore[attr-defined]


# Protect Assets write endpoints
_remove_route("/assets", "POST")
@app.post("/assets", response_model=AssetRead, status_code=201)
def create_asset_guarded(payload: AssetCreate, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> AssetRead:
    return _create_asset(payload, session)  # type: ignore[misc]


_remove_route("/assets/{asset_id}", "PATCH")
@app.patch("/assets/{asset_id}", response_model=AssetRead)
def update_asset_guarded(asset_id: int, payload: AssetUpdate, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> AssetRead:
    return _update_asset(asset_id, payload, session)  # type: ignore[misc]


_remove_route("/assets/{asset_id}", "DELETE")
@app.delete("/assets/{asset_id}", status_code=204)
def delete_asset_guarded(asset_id: int, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> Response:
    return _delete_asset(asset_id, session)  # type: ignore[misc]


# Protect Scans write endpoints
_remove_route("/scans", "POST")
@app.post("/scans", response_model=ScanRead, status_code=201)
def create_scan_guarded(payload: ScanCreate, background_tasks: BackgroundTasks, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> ScanRead:
    return _create_scan(payload, background_tasks, session)  # type: ignore[misc]


_remove_route("/scans/{scan_id}", "DELETE")
@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan_guarded(scan_id: int, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> Response:
    return _delete_scan(scan_id, session)  # type: ignore[misc]


# Protect update finding
_remove_route("/findings/{finding_id}", "PATCH")
@app.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding_guarded(finding_id: int, payload: FindingUpdate, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> FindingRead:
    return _update_finding(finding_id, payload, session)  # type: ignore[misc]
