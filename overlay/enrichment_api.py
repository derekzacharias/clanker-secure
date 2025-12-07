from __future__ import annotations

from fastapi import BackgroundTasks, Depends, HTTPException
from sqlmodel import Session, select

from clanker.main import app, session_dep
from clanker.db.models import Finding
from clanker.db.session import get_session
from overlay.core.enrichment import enrich_finding, get_enrichment
import json
from fastapi.responses import JSONResponse


@app.post("/enrichment/finding/{finding_id}")
def enrich_one(finding_id: int, background_tasks: BackgroundTasks, session: Session = Depends(session_dep)) -> dict:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    def _task(fid: int):
        with get_session() as s2:
            f = s2.get(Finding, fid)
            if f:
                changed = enrich_finding(s2, f)
                if changed:
                    s2.commit()

    background_tasks.add_task(_task, finding_id)
    return {"status": "queued"}


@app.post("/enrichment/scan/{scan_id}")
def enrich_scan(scan_id: int, background_tasks: BackgroundTasks) -> dict:
    def _task(sid: int):
        with get_session() as s2:
            rows = s2.exec(select(Finding).where(Finding.scan_id == sid)).all()
            changed_any = False
            for f in rows:
                if enrich_finding(s2, f):
                    changed_any = True
            if changed_any:
                s2.commit()

    background_tasks.add_task(_task, scan_id)
    return {"status": "queued"}


@app.post("/enrichment/rebuild_all")
def enrich_all(background_tasks: BackgroundTasks) -> dict:
    def _task():
        with get_session() as s2:
            rows = s2.exec(select(Finding)).all()
            changed_any = False
            for f in rows:
                if enrich_finding(s2, f):
                    changed_any = True
            if changed_any:
                s2.commit()

    background_tasks.add_task(_task)
    return {"status": "queued"}


@app.get("/finding_ext/{finding_id}")
def get_finding_ext(finding_id: int, session: Session = Depends(session_dep)) -> JSONResponse:
    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    ext = get_enrichment(session, finding_id) or {}
    # Compose response: include base finding fields plus enrichment fields under 'enrichment'
    base = {
        "id": f.id,
        "scan_id": f.scan_id,
        "asset_id": f.asset_id,
        "host_address": f.host_address,
        "host_os_name": f.host_os_name,
        "host_os_accuracy": f.host_os_accuracy,
        "host_vendor": f.host_vendor,
        "traceroute_summary": f.traceroute_summary,
        "host_report": f.host_report,
        "port": f.port,
        "protocol": f.protocol,
        "service_name": f.service_name,
        "service_version": f.service_version,
        "cve_ids": f.cve_ids,
        "severity": f.severity,
        "status": f.status,
        "description": f.description,
        "detected_at": f.detected_at.isoformat() if getattr(f, "detected_at", None) else None,
    }
    if ext and isinstance(ext.get("references_json"), str):
        try:
            ext["references"] = json.loads(ext["references_json"])  # type: ignore[name-defined]
        except Exception:
            ext["references"] = []
    if ext:
        ext.setdefault("references", [])
    return JSONResponse({"finding": base, "enrichment": ext})
