import time

from sqlmodel import select

from clanker import main as cm
from clanker.core.job_queue import ScanJobQueue
from clanker.db.models import Asset, ScanJob
from clanker.db.session import get_session, init_db


def _wait_for(predicate, timeout: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _create_scan(session):
    asset = Asset(target="192.0.2.10")
    session.add(asset)
    session.commit()
    session.refresh(asset)
    scan = cm._create_scan_record(session, [asset.id], "basic")
    session.commit()
    return scan.id


def _job_status(scan_id: int) -> str:
    with get_session() as session:
        job = session.exec(select(ScanJob).where(ScanJob.scan_id == scan_id)).first()
        return job.status if job else "missing"


def test_scan_job_enqueue_and_complete(monkeypatch):
    init_db()
    monkeypatch.setattr(cm.settings, "scan_job_max_attempts", 1)
    cm.scan_job_queue = ScanJobQueue(
        worker=lambda sid: cm._update_scan_job_status(sid, "completed"),
        hooks=cm._build_scan_queue_hooks(),
        poll_interval=0.01,
        max_retries=0,
    )
    cm.scan_job_dispatcher = None

    with get_session() as session:
        scan_id = _create_scan(session)
        cm._enqueue_scan_job(scan_id, session=session)

    cm._start_scan_job_worker()
    assert _wait_for(lambda: _job_status(scan_id) == "completed")


def test_scan_job_failure_records_attempts(monkeypatch):
    init_db()
    monkeypatch.setattr(cm.settings, "scan_job_max_attempts", 2)
    cm.scan_job_queue = ScanJobQueue(
        worker=lambda _: (_ for _ in ()).throw(RuntimeError("boom")),  # raise inside lambda
        hooks=cm._build_scan_queue_hooks(),
        poll_interval=0.01,
        max_retries=1,
    )
    cm.scan_job_dispatcher = None

    with get_session() as session:
        scan_id = _create_scan(session)
        cm._enqueue_scan_job(scan_id, session=session)

    cm._start_scan_job_worker()
    assert _wait_for(lambda: _job_status(scan_id) == "failed", timeout=1.5)
    with get_session() as session:
        job = session.exec(select(ScanJob).where(ScanJob.scan_id == scan_id)).first()
        assert job is not None
        assert job.attempts == 2
        assert job.last_error


def test_scan_job_cancelled_before_dispatch(monkeypatch):
    init_db()
    ran: list[int] = []
    queue = ScanJobQueue(
        worker=lambda sid: ran.append(sid),
        hooks=cm._build_scan_queue_hooks(),
        poll_interval=0.01,
        max_retries=0,
    )
    cm.scan_job_queue = queue
    cm.scan_job_dispatcher = None

    original_start = cm._start_scan_job_worker
    monkeypatch.setattr(cm, "_start_scan_job_worker", lambda: None)
    with get_session() as session:
        scan_id = _create_scan(session)
        cm._enqueue_scan_job(scan_id, session=session)
        cm._cancel_scan_in_db(session, scan_id, "user cancel")

    monkeypatch.setattr(cm, "_start_scan_job_worker", original_start)
    cm._start_scan_job_worker()
    time.sleep(0.1)
    with get_session() as session:
        job = session.exec(select(ScanJob).where(ScanJob.scan_id == scan_id)).first()
        assert job is not None
        assert job.status == "cancelled"
    assert ran == []
