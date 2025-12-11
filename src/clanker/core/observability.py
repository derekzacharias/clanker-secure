from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


_RESERVED_LOG_KEYS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
    "stacklevel",
}


class JsonLogFormatter(logging.Formatter):
    """Minimal JSON formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        event = getattr(record, "event", None)
        if event:
            base["event"] = event
        payload = getattr(record, "payload", None)
        if isinstance(payload, dict):
            base.update(payload)
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOG_KEYS or key in base:
                continue
            base[key] = value
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, default=str)


_logging_configured = False


def configure_logging(level: Optional[str] = None) -> None:
    """Configure root logging with JSON output once."""
    global _logging_configured
    if _logging_configured:
        return
    log_level = (level or os.getenv("CLANKER_LOG_LEVEL", "INFO")).upper()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True

    _logging_configured = True


def log_event(logger: logging.Logger, event: str, **payload: Any) -> None:
    """Helper to emit structured events consistently."""
    logger.info(event, extra={"event": event, "payload": payload})


@dataclass
class ApiMetrics:
    requests_total: int = 0
    error_responses: int = 0
    latency_ms_sum: float = 0.0
    last_latency_ms: Optional[float] = None


@dataclass
class ScanMetrics:
    started: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    in_progress: int = 0
    total_duration_seconds: float = 0.0
    last_duration_seconds: Optional[float] = None


class Metrics:
    """Thread-safe metrics collector for API and scan jobs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.api = ApiMetrics()
        self.scans = ScanMetrics()
        self.ssh_scans = ScanMetrics()

    def record_api_request(self, status_code: int, duration_ms: float) -> None:
        with self._lock:
            self.api.requests_total += 1
            if status_code >= 500:
                self.api.error_responses += 1
            self.api.latency_ms_sum += duration_ms
            self.api.last_latency_ms = duration_ms

    def record_scan_started(self, kind: str) -> None:
        target = self._target(kind)
        with self._lock:
            target.started += 1
            target.in_progress += 1

    def record_scan_finished(self, kind: str, status: str, duration_seconds: float) -> None:
        target = self._target(kind)
        with self._lock:
            target.in_progress = max(0, target.in_progress - 1)
            if status == "cancelled":
                target.cancelled += 1
            elif status == "failed":
                target.failed += 1
            else:
                target.completed += 1
            target.total_duration_seconds += duration_seconds
            target.last_duration_seconds = duration_seconds

    def snapshot(
        self,
        queue_stats: Optional[Dict[str, Any]] = None,
        ssh_queue_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            avg_latency = (
                self.api.latency_ms_sum / self.api.requests_total if self.api.requests_total else 0.0
            )
            avg_scan_seconds = (
                self.scans.total_duration_seconds / self.scans.completed if self.scans.completed else 0.0
            )
            avg_ssh_scan_seconds = (
                self.ssh_scans.total_duration_seconds / self.ssh_scans.completed if self.ssh_scans.completed else 0.0
            )
            return {
                "api": {
                    "requests_total": self.api.requests_total,
                    "error_responses": self.api.error_responses,
                    "avg_latency_ms": round(avg_latency, 2),
                    "last_latency_ms": self.api.last_latency_ms,
                },
                "scanner": {
                    "network": {
                        "started": self.scans.started,
                        "completed": self.scans.completed,
                        "failed": self.scans.failed,
                        "cancelled": self.scans.cancelled,
                        "in_progress": self.scans.in_progress,
                        "avg_duration_seconds": round(avg_scan_seconds, 2),
                        "last_duration_seconds": self.scans.last_duration_seconds,
                    },
                    "ssh": {
                        "started": self.ssh_scans.started,
                        "completed": self.ssh_scans.completed,
                        "failed": self.ssh_scans.failed,
                        "cancelled": self.ssh_scans.cancelled,
                        "in_progress": self.ssh_scans.in_progress,
                        "avg_duration_seconds": round(avg_ssh_scan_seconds, 2),
                        "last_duration_seconds": self.ssh_scans.last_duration_seconds,
                    },
                },
                "queues": {
                    "network": queue_stats or {},
                    "ssh": ssh_queue_stats or {},
                },
            }

    def _target(self, kind: str) -> ScanMetrics:
        return self.ssh_scans if kind == "ssh" else self.scans


metrics = Metrics()


class Timer:
    """Lightweight context manager for timing blocks."""

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.duration = time.perf_counter() - self._start

