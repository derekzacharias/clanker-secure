import logging
import time

from clanker.config import settings
from clanker.core.observability import configure_logging
from clanker.db.session import init_db
from clanker import main as core_main

logger = logging.getLogger(__name__)


def run_worker() -> None:
    """Start the scan job dispatcher and worker loop."""
    configure_logging()
    init_db()
    core_main._start_scan_job_worker()  # type: ignore[attr-defined]
    logger.info(
        "scan_worker_started",
        extra={
            "component": "scan_worker",
            "event": "started",
            "dispatch_interval": settings.scan_job_dispatch_interval_seconds,
            "max_attempts": settings.scan_job_max_attempts,
        },
    )
    while True:
        time.sleep(5)


def main() -> None:
    run_worker()


if __name__ == "__main__":
    main()
