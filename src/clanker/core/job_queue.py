import json
import logging
import threading
from dataclasses import dataclass
from queue import Queue, Empty
from time import sleep
from typing import Callable, Dict, Optional


logger = logging.getLogger(__name__)


def _log(event: str, payload: Dict[str, object]) -> None:
    try:
        logger.info("%s %s", event, json.dumps(payload))
    except Exception:
        logger.info("%s %s", event, payload)


@dataclass
class QueueMetrics:
    enqueued: int = 0
    started: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0


class ScanJobQueue:
    """Lightweight in-process queue for scan jobs.

    This is intentionally simple and single-threaded so it can run inside
    the API process without extra dependencies. It can be swapped for Redis
    or another broker later without changing the handlers that enqueue scans.
    """

    def __init__(self, worker: Callable[[int], None], poll_interval: float = 0.5, max_retries: int = 1):
        self.worker = worker
        self.poll_interval = poll_interval
        self.max_retries = max_retries
        self._queue: Queue[int] = Queue()
        self._cancelled: set[int] = set()
        self._lock = threading.Lock()
        self._metrics = QueueMetrics()
        self._thread: Optional[threading.Thread] = None
        self._attempts: Dict[int, int] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        _log("scan_queue_started", {})

    def enqueue(self, scan_id: int, *, force: bool = False) -> None:
        # force=True is used by explicit retries to clear a prior cancellation marker
        with self._lock:
            if force and scan_id in self._cancelled:
                self._cancelled.discard(scan_id)
            if force:
                self._attempts.pop(scan_id, None)
            self._metrics.enqueued += 1
        self._queue.put(scan_id)
        _log("scan_enqueue", {"scan_id": scan_id, "force": int(force)})

    def cancel(self, scan_id: int) -> None:
        with self._lock:
            self._cancelled.add(scan_id)
            self._metrics.cancelled += 1
            self._attempts.pop(scan_id, None)
        _log("scan_cancelled", {"scan_id": scan_id})

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "enqueued": self._metrics.enqueued,
                "started": self._metrics.started,
                "completed": self._metrics.completed,
                "failed": self._metrics.failed,
                "cancelled": self._metrics.cancelled,
                "in_queue": self._queue.qsize(),
                "thread_alive": int(bool(self._thread and self._thread.is_alive())),
                "max_retries": self.max_retries,
            }

    def _run(self) -> None:
        while True:
            try:
                scan_id = self._queue.get(timeout=self.poll_interval)
            except Empty:
                continue

            if scan_id in self._cancelled:
                with self._lock:
                    self._attempts.pop(scan_id, None)
                self._queue.task_done()
                _log("scan_skipped_cancelled", {"scan_id": scan_id})
                continue

            with self._lock:
                self._metrics.started += 1
                attempt = self._attempts.get(scan_id, 0) + 1
                self._attempts[scan_id] = attempt

            try:
                self.worker(scan_id)
                with self._lock:
                    self._metrics.completed += 1
                    self._attempts.pop(scan_id, None)
                _log("scan_job_completed", {"scan_id": scan_id})
            except Exception as exc:  # pylint: disable=broad-except
                logger.exception("scan_worker_error %s", json.dumps({"scan_id": scan_id, "error": str(exc)}))
                with self._lock:
                    should_retry = self._attempts.get(scan_id, 0) <= self.max_retries
                if should_retry:
                    _log("scan_job_retry", {"scan_id": scan_id, "attempt": self._attempts.get(scan_id, 0)})
                    self._queue.put(scan_id)
                else:
                    with self._lock:
                        self._metrics.failed += 1
                        self._attempts.pop(scan_id, None)
                    _log("scan_job_failed", {"scan_id": scan_id, "error": str(exc)})
            finally:
                self._queue.task_done()
                sleep(self.poll_interval)
