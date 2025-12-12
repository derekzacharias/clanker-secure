from sqlmodel import select

from clanker.main import _record_scan_event, read_prometheus_metrics
from clanker.db.models import Scan, ScanEvent
from clanker.db.session import get_session, init_db


def test_prometheus_metrics_endpoint_serves_text():
    init_db()
    resp = read_prometheus_metrics()
    assert resp.status_code == 200
    assert "clanker_api_requests_total" in resp.body.decode()
    assert resp.media_type.startswith("text/plain")


def test_scan_event_sets_correlation_id():
    init_db()
    with get_session() as session:
        scan = Scan(profile="basic", status="queued", correlation_id=None)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        _record_scan_event(session, scan.id, "hello correlation")
        session.refresh(scan)
        event = session.exec(select(ScanEvent).where(ScanEvent.scan_id == scan.id)).first()
        corr = scan.correlation_id
        event_corr = event.correlation_id if event else None
    assert corr is not None
    assert event is not None
    assert event_corr == corr
