from __future__ import annotations

from typing import Optional

from sqlmodel import select

from clanker import main as core_main
from clanker.db.session import get_session
from clanker.db.models import Finding
from overlay.core.enrichment import enrich_finding


_original_run_scan_job = getattr(core_main, "run_scan_job", None)


def _run_scan_job_with_enrichment(scan_id: int) -> None:
    # Run the original scan job first
    if callable(_original_run_scan_job):
        _original_run_scan_job(scan_id)  # type: ignore[misc]

    # Kick off enrichment for all findings in this scan (best-effort)
    try:
        with get_session() as session:
            rows = session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
            changed_any = False
            for f in rows:
                if enrich_finding(session, f):
                    changed_any = True
            if changed_any:
                session.commit()
    except Exception:
        # Do not break scan flow if enrichment fails
        pass


if callable(_original_run_scan_job):
    # Monkey-patch the core function so new scans automatically trigger enrichment afterward
    core_main.run_scan_job = _run_scan_job_with_enrichment  # type: ignore[assignment]

