import time

from clanker.core.job_queue import ScanJobQueue


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
