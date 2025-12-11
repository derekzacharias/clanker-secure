import time

from clanker.core.job_queue import QueueHooks, ScanJobQueue


def _wait_for(predicate, timeout: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_queue_skips_cancelled_jobs():
    processed: list[int] = []
    queue = ScanJobQueue(worker=lambda sid: processed.append(sid), poll_interval=0.01)
    queue.start()

    queue.cancel(1)
    queue.enqueue(1)

    time.sleep(0.05)
    assert processed == []


def test_queue_force_enqueue_after_cancel():
    processed: list[int] = []
    queue = ScanJobQueue(worker=lambda sid: processed.append(sid), poll_interval=0.01)
    queue.start()

    queue.cancel(2)
    queue.enqueue(2)
    time.sleep(0.05)
    assert processed == []

    queue.enqueue(2, force=True)
    assert _wait_for(lambda: processed == [2])


def test_queue_retries_failed_job_once():
    attempts: dict[int, int] = {}
    processed: list[int] = []

    def worker(scan_id: int) -> None:
        attempts[scan_id] = attempts.get(scan_id, 0) + 1
        if attempts[scan_id] == 1:
            raise RuntimeError("boom")
        processed.append(scan_id)

    queue = ScanJobQueue(worker=worker, poll_interval=0.01, max_retries=1)
    queue.start()

    queue.enqueue(3)

    assert _wait_for(lambda: processed == [3])
    assert attempts[3] == 2


def test_queue_hooks_fire_for_retry_and_cancel():
    events: list[tuple] = []

    def worker(_: int) -> None:
        raise RuntimeError("boom")

    hooks = QueueHooks(
        on_start=lambda sid, attempt: events.append(("start", sid, attempt)),
        on_retry=lambda sid, attempt: events.append(("retry", sid, attempt)),
        on_cancel=lambda sid: events.append(("cancel", sid)),
        on_fail=lambda sid, attempts, err: events.append(("fail", sid, attempts, err)),
    )
    queue = ScanJobQueue(worker=worker, poll_interval=0.01, max_retries=1, hooks=hooks)
    queue.start()

    queue.enqueue(9)
    queue.cancel(10)
    queue.enqueue(10)

    assert _wait_for(lambda: any(evt[0] == "fail" for evt in events), timeout=0.5)
    assert ("retry", 9, 1) in events
    assert ("start", 9, 1) in events
    assert ("start", 9, 2) in events
    assert any(evt[0] == "cancel" and evt[1] == 10 for evt in events)
    assert any(evt[0] == "fail" and evt[1] == 9 for evt in events)


def test_snapshot_includes_attempts_and_cancelled():
    queue = ScanJobQueue(worker=lambda _: None, poll_interval=0.01)
    queue.start()
    queue.cancel(1)
    queue.enqueue(1)

    assert _wait_for(lambda: queue.stats()["cancelled"] == 1, timeout=0.2)
    snap = queue.snapshot()
    assert snap["attempting"] == 0
    assert 1 in snap["cancelled_job_ids"]
