from __future__ import annotations

import asyncio
import base64
import csv
import inspect
import io
import json
import logging
import os
import atexit
import threading
import time
import hashlib
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional
from uuid import uuid4

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse, PlainTextResponse
from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import bindparam, case, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import selectinload
from sqlmodel import Session, func, select, delete

from clanker.config import settings
from clanker.core.agent_vuln_logic import agent_rule_counts, persist_agent_findings, reload_agent_rules
from clanker.core.coverage import load_rule_gaps, summarize_rule_gaps, stub_rule_from_gap
from clanker.core.evidence import dedupe_evidence, grade_evidence
from clanker.core.enrichment import enrich_from_feed, sync_nvd_cache
from clanker.core.findings import build_findings
from clanker.core.job_queue import QueueHooks, ScanJobQueue, build_scan_job_queue
from clanker.core.observability import configure_logging, log_event, metrics, render_prometheus_metrics
from clanker.core.enum_tools import run_enum_tools
from clanker.core.scanner import (
    DEFAULT_PROFILE_KEY,
    execute_nmap,
    get_scan_profile,
    list_scan_profiles,
    parse_nmap_xml,
)
from clanker.core.ssh_credentialed_scanner import SSHScanner
from clanker.core.types import ServiceObservation
from clanker.db.models import (
    AgentIngest,
    Asset,
    AssetCreate,
    AssetRead,
    AssetUpdate,
    AuditLog,
    Finding,
    FindingComment,
    FindingCommentRead,
    FindingRead,
    FindingUpdate,
    InviteToken,
    LoginAttempt,
    Scan,
    ScanAssetStatus,
    ScanAssetStatusRead,
    ScanJob,
    ScanCreate,
    ScanDetail,
    ScanEvent,
    ScanEventRead,
    ScanRead,
    ScanTarget,
    Schedule,
    ReportJob,
    SessionToken,
    User,
    UserRead,
    SSHScan,
    SSHScanHost,
)
from clanker.db.session import get_session, init_db

configure_logging()
logger = logging.getLogger(__name__)

startup_hooks: list[Callable[[], Awaitable[None] | None]] = []
shutdown_hooks: list[Callable[[], Awaitable[None] | None]] = []
nvd_sync_task: Optional[asyncio.Task] = None


def register_startup_hook(fn: Callable[[], Awaitable[None] | None]) -> Callable[[], Awaitable[None] | None]:
    startup_hooks.append(fn)
    return fn


def register_shutdown_hook(fn: Callable[[], Awaitable[None] | None]) -> Callable[[], Awaitable[None] | None]:
    shutdown_hooks.append(fn)
    return fn


async def _run_hooks(hooks: list[Callable[[], Awaitable[None] | None]]) -> None:
    for hook in hooks:
        result = hook()
        if isinstance(result, asyncio.Task):
            continue
        if inspect.isawaitable(result):
            await result


@asynccontextmanager
async def lifespan(_: FastAPI):
    await _run_hooks(startup_hooks)
    try:
        yield
    finally:
        await _run_hooks(list(reversed(shutdown_hooks)))


app = FastAPI(title="Clanker Vulnerability Scanner", version="0.2.0", lifespan=lifespan)
SCAN_PROFILE_CHOICES = list_scan_profiles()
SCAN_PROFILE_KEYS = {profile.key for profile in SCAN_PROFILE_CHOICES}
BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
VALID_FINDING_STATUSES = {"open", "in_progress", "resolved", "ignored"}
scan_job_queue: Optional[ScanJobQueue] = None
scan_job_dispatcher: Optional[threading.Thread] = None
scan_job_dispatcher_stop = threading.Event()
SSH_TIMEOUT_LIMIT = 60
SSH_COMMAND_TIMEOUT_LIMIT = 180
SSH_MAX_WORKERS_LIMIT = 16
SSH_RETRY_LIMIT = 2
ssh_scan_job_queue: Optional[ScanJobQueue] = None
_ssh_secret_cache: Dict[int, Dict[str, Any]] = {}
_ssh_retry_overrides: Dict[int, int] = {}
_ssh_secret_lock = threading.Lock()
REPORT_OUTPUT_DIR = settings.xml_output_dir / "reports"
REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


class FrontendStaticFiles(StaticFiles):
    # Avoid cached index.html pointing at stale hashed assets
    def file_response(self, path: str, stat_result, scope, status_code: int = 200):  # type: ignore[override]
        response = super().file_response(path, stat_result, scope, status_code=status_code)
        if path == "" or path.endswith("index.html"):
            response.headers["Cache-Control"] = "no-store"
        return response


def _get_scan_job(session: Session, scan_id: int) -> Optional[ScanJob]:
    return session.exec(select(ScanJob).where(ScanJob.scan_id == scan_id)).first()


def _coerce_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except Exception:
            pass
    return now_utc()


def _persist_scan_job(session: Session, scan_id: int, *, force: bool = False) -> ScanJob:
    now = now_utc()
    job = _get_scan_job(session, scan_id)
    if job is None:
        job = ScanJob(
            scan_id=scan_id,
            status="queued",
            attempts=0,
            max_attempts=settings.scan_job_max_attempts,
            enqueued_at=now,
            updated_at=now,
        )
    if force:
        job.attempts = 0
        job.last_error = None
        job.started_at = None
        job.completed_at = None
    job.status = "queued"
    job.enqueued_at = now
    job.updated_at = now
    job.max_attempts = settings.scan_job_max_attempts
    session.add(job)
    session.flush()
    return job


def _update_scan_job_status(
    scan_id: int, status: str, *, attempts: Optional[int] = None, error: Optional[str] = None
) -> None:
    from clanker.db.session import get_session as session_factory

    try:
        with session_factory() as session:
            job = _get_scan_job(session, scan_id)
            if not job:
                return
            now = now_utc()
            job.status = status
            job.updated_at = now
            if status == "queued":
                job.enqueued_at = now
            if attempts is not None:
                job.attempts = attempts
            if error is not None:
                job.last_error = error
            if status == "running" and job.started_at is None:
                job.started_at = now
            if status in {"completed", "completed_with_errors", "failed", "cancelled"}:
                job.completed_at = job.completed_at or now
            session.add(job)
    except Exception:
        logger.exception("Failed to update scan job %s status to %s", scan_id, status)


def _build_scan_queue_hooks() -> QueueHooks:
    from clanker.db.session import get_session as session_factory

    def _record_if_exists(scan_id: int, message: str) -> None:
        with session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                _record_scan_event(session, scan_id, message)

    return QueueHooks(
        on_start=lambda scan_id, attempt: (
            _update_scan_job_status(scan_id, "running", attempts=attempt),
            _record_if_exists(scan_id, f"Dequeued for processing (attempt {attempt})"),
        ),
        on_retry=lambda scan_id, attempt: (
            _update_scan_job_status(scan_id, "queued", attempts=attempt),
            _record_if_exists(scan_id, f"Retrying scan job (attempt {attempt + 1})"),
        ),
        on_cancel=lambda scan_id: (
            _update_scan_job_status(scan_id, "cancelled"),
            _record_if_exists(scan_id, "Scan cancelled before worker start"),
        ),
        on_fail=lambda scan_id, attempts, error: (
            _update_scan_job_status(scan_id, "failed", attempts=attempts, error=error),
            _record_if_exists(scan_id, f"Scan job failed after {attempts} attempt(s): {error}"),
        ),
    )


def _ensure_scan_queue() -> ScanJobQueue:
    global scan_job_queue
    if scan_job_queue is None:
        scan_job_queue = build_scan_job_queue(
            worker=run_scan_job,
            hooks=_build_scan_queue_hooks(),
            max_retries=max(0, settings.scan_job_max_attempts - 1),
            backend=settings.scan_job_queue_backend,
            max_concurrency=settings.scan_job_max_concurrency,
            name="network",
            redis_url=settings.scan_job_queue_redis_url,
        )
    scan_job_queue.start()
    return scan_job_queue


def _queue_status_snapshot(session: Session) -> Dict[str, Any]:
    stats = scan_job_queue.stats() if scan_job_queue else {}
    jobs = session.exec(select(ScanJob).order_by(ScanJob.updated_at.desc()).limit(50)).all()
    job_rows = [
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "status": row.status,
            "attempts": row.attempts,
            "max_attempts": row.max_attempts,
            "last_error": row.last_error,
            "enqueued_at": row.enqueued_at.isoformat() if row.enqueued_at else None,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
        for row in jobs
    ]
    return {"queue_stats": stats, "jobs": job_rows}


def _queue_job_detail(scan_id: int, session: Session) -> Dict[str, Any]:
    db_job = _get_scan_job(session, scan_id)
    job_payload = None
    if db_job:
        job_payload = {
            "id": db_job.id,
            "scan_id": db_job.scan_id,
            "status": db_job.status,
            "attempts": db_job.attempts,
            "max_attempts": db_job.max_attempts,
            "last_error": db_job.last_error,
            "enqueued_at": db_job.enqueued_at.isoformat() if db_job.enqueued_at else None,
            "started_at": db_job.started_at.isoformat() if db_job.started_at else None,
            "completed_at": db_job.completed_at.isoformat() if db_job.completed_at else None,
            "updated_at": db_job.updated_at.isoformat() if db_job.updated_at else None,
        }
    queue_detail = scan_job_queue.job_detail(scan_id) if scan_job_queue else {}
    return {"job": job_payload, "queue": queue_detail}


def _claim_next_scan_job() -> Optional[int]:
    """Atomically claim the next queued job to avoid duplicate dispatch across workers."""
    from clanker.db.session import get_session as session_factory

    try:
        init_db()
        with session_factory() as session:
            candidate = session.exec(
                select(ScanJob.id).where(ScanJob.status == "queued").order_by(ScanJob.enqueued_at).limit(1)
            ).first()
            if not candidate:
                return None
            if isinstance(candidate, tuple):
                job_id = candidate[0]
            elif hasattr(candidate, "id"):
                job_id = candidate.id  # type: ignore[attr-defined]
            else:
                job_id = candidate
            result = session.exec(
                text(
                    "UPDATE scanjob SET status='dispatching', updated_at=:now "
                    "WHERE id=:job_id AND status='queued'"
                ).bindparams(now=now_utc().isoformat(), job_id=job_id)
            )
            session.commit()
            if result.rowcount == 0:
                return None
            job = session.get(ScanJob, job_id)
            if job:
                job.status = "dispatching"
                job.updated_at = now_utc()
                session.add(job)
                session.commit()
                return job.scan_id
            return None
    except OperationalError:
        init_db(force=True)
        return None
    except Exception:
        logger.exception("Failed to claim next scan job")
        return None


def _dispatch_scan_jobs_forever(poll_interval: float = 0.5) -> None:
    queue = _ensure_scan_queue()
    while not scan_job_dispatcher_stop.is_set():
        try:
            job_scan_id = _claim_next_scan_job()
            if job_scan_id:
                queue.enqueue(job_scan_id)
        except Exception:
            logger.exception("scan_job_dispatch_loop_error")
        time.sleep(poll_interval)


def _start_scan_job_worker() -> None:
    global scan_job_dispatcher
    if not settings.scan_job_dispatch_enabled:
        return
    init_db()
    queue = _ensure_scan_queue()
    queue.start()
    if scan_job_dispatcher and scan_job_dispatcher.is_alive():
        return
    scan_job_dispatcher_stop.clear()
    scan_job_dispatcher = threading.Thread(
        target=_dispatch_scan_jobs_forever,
        kwargs={"poll_interval": settings.scan_job_dispatch_interval_seconds},
        daemon=True,
        name="scan-job-dispatcher",
    )
    scan_job_dispatcher.start()


def _stop_scan_job_worker() -> None:
    scan_job_dispatcher_stop.set()


atexit.register(_stop_scan_job_worker)


def _enqueue_scan_job(scan_id: int, *, force: bool = False, session: Optional[Session] = None) -> ScanJob:
    if session is not None:
        job = _persist_scan_job(session, scan_id, force=force)
        session.commit()
        _start_scan_job_worker()
        return job

    with get_session() as local_session:
        job = _persist_scan_job(local_session, scan_id, force=force)
        _start_scan_job_worker()
        return job


def _scan_job_status_counts(session: Session) -> Dict[str, int]:
    rows = session.exec(select(ScanJob.status, func.count()).group_by(ScanJob.status)).all()
    return {status: count for status, count in rows}


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_observability(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid4())
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = (time.perf_counter() - started) * 1000
        metrics.record_api_request(500, duration_ms)
        log_event(
            logger,
            "http_request",
            method=request.method,
            path=request.url.path,
            status=500,
            duration_ms=round(duration_ms, 2),
            request_id=request_id,
        )
        raise
    duration_ms = (time.perf_counter() - started) * 1000
    metrics.record_api_request(response.status_code, duration_ms)
    log_event(
        logger,
        "http_request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=round(duration_ms, 2),
        request_id=request_id,
    )
    response.headers["X-Request-ID"] = request_id
    return response

templates = Jinja2Templates(directory="templates")
if FRONTEND_DIST.exists():
    app.mount("/app", FrontendStaticFiles(directory=FRONTEND_DIST, html=True), name="react-app")

    @app.get("/", include_in_schema=False)
    def root_react() -> RedirectResponse:
        return RedirectResponse(url="/app/")


@register_startup_hook
def on_startup() -> None:
    init_db()
    global ssh_scan_job_queue
    _start_scan_job_worker()
    if ssh_scan_job_queue is None:
        ssh_scan_job_queue = build_scan_job_queue(
            worker=run_ssh_scan_job,
            backend=settings.scan_job_queue_backend,
            max_concurrency=settings.scan_job_max_concurrency,
            name="ssh",
            redis_url=settings.scan_job_queue_redis_url,
            max_retries=max(0, settings.scan_job_max_attempts - 1),
        )
    ssh_scan_job_queue.start()


async def _start_nvd_sync_loop() -> None:
    if not settings.nvd_sync_enabled:
        logger.info("NVD cache sync disabled via configuration")
        return
    interval_seconds = max(1, settings.nvd_feed_sync_interval_hours) * 3600
    while True:
        try:
            count = await asyncio.to_thread(sync_nvd_cache, False)
            logger.info("NVD cache sync completed (cached %s CVEs)", count)
        except asyncio.CancelledError:
            logger.info("NVD cache sync loop cancelled")
            break
        except Exception:
            logger.exception("NVD cache sync failed")
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            logger.info("NVD cache sync loop cancelled during sleep")
            break


@register_startup_hook
def on_startup_async() -> None:
    global nvd_sync_task
    if nvd_sync_task and not nvd_sync_task.done():
        return
    loop = asyncio.get_event_loop()
    nvd_sync_task = loop.create_task(_start_nvd_sync_loop())


@register_shutdown_hook
async def _stop_nvd_sync_task() -> None:
    global nvd_sync_task
    if nvd_sync_task is None:
        return
    nvd_sync_task.cancel()
    with suppress(asyncio.CancelledError):
        await nvd_sync_task
    nvd_sync_task = None


# Dependency

def session_dep() -> Session:
    with get_session() as session:
        yield session


@app.get("/metrics")
def read_metrics() -> Dict[str, Any]:
    queue_stats = scan_job_queue.stats() if scan_job_queue else {}
    ssh_stats = ssh_scan_job_queue.stats() if ssh_scan_job_queue else {}
    return metrics.snapshot(queue_stats=queue_stats, ssh_queue_stats=ssh_stats)


@app.get("/metrics/prometheus", response_class=PlainTextResponse)
def read_prometheus_metrics() -> PlainTextResponse:
    queue_stats = scan_job_queue.stats() if scan_job_queue else {}
    ssh_stats = ssh_scan_job_queue.stats() if ssh_scan_job_queue else {}
    snapshot = metrics.snapshot(queue_stats=queue_stats, ssh_queue_stats=ssh_stats)
    body = render_prometheus_metrics(snapshot)
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4")


def _paginate_query(session: Session, query, limit: int, offset: int) -> tuple[list[Any], int]:
    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.limit(limit).offset(offset)).all()
    return rows, int(total or 0)


def _build_observation_index(findings: List[Finding]) -> Dict[int, ServiceObservation]:
    observations: Dict[int, ServiceObservation] = {}
    for finding in findings:
        if finding.id is None:
            continue
        fingerprint = None
        evidence = None
        version_confidence = None
        if finding.fingerprint:
            try:
                fingerprint = json.loads(finding.fingerprint)
            except Exception:
                fingerprint = None
        if finding.evidence:
            try:
                evidence = json.loads(finding.evidence)
            except Exception:
                evidence = None
        if isinstance(fingerprint, dict):
            try:
                version_confidence = float(fingerprint.get("version_confidence"))
            except Exception:
                version_confidence = None
        observations[finding.id] = ServiceObservation(
            asset_id=finding.asset_id or 0,
            host_address=finding.host_address,
            host_os_name=finding.host_os_name,
            host_os_accuracy=finding.host_os_accuracy,
            host_vendor=finding.host_vendor,
            traceroute_summary=finding.traceroute_summary,
            host_report=finding.host_report,
            port=finding.port or 0,
            protocol=finding.protocol or "tcp",
            service_name=finding.service_name,
            service_version=finding.service_version,
            product=finding.service_name,
            version_confidence=version_confidence,
            fingerprint=fingerprint,
            evidence=evidence,
            evidence_summary=finding.evidence_summary,
        )
    return observations


def _cache_ssh_credentials(host_id: int, payload: Dict[str, Any]) -> None:
    with _ssh_secret_lock:
        _ssh_secret_cache[host_id] = payload


def _pop_ssh_credentials(host_id: int) -> Optional[Dict[str, Any]]:
    with _ssh_secret_lock:
        return _ssh_secret_cache.pop(host_id, None)


def _cache_ssh_retry(ssh_scan_id: int, retries: int) -> None:
    with _ssh_secret_lock:
        _ssh_retry_overrides[ssh_scan_id] = retries


def _pop_ssh_retry(ssh_scan_id: int) -> Optional[int]:
    with _ssh_secret_lock:
        return _ssh_retry_overrides.pop(ssh_scan_id, None)


def _serialize_ssh_host(row: SSHScanHost) -> SSHScanHostResult:
    raw: Dict[str, Any] = {}
    commands: List[Dict[str, Any]] = []
    hardening: Dict[str, Any] = {}
    facts: Dict[str, Any] = {}
    if row.raw_output:
        try:
            raw = json.loads(row.raw_output)
        except Exception:
            raw = {}
    if isinstance(raw.get("commands"), list):
        commands = raw["commands"]
    if row.ssh_config_hardening:
        try:
            hardening = json.loads(row.ssh_config_hardening)
        except Exception:
            hardening = {}
    elif isinstance(raw.get("ssh_config_hardening"), dict):
        hardening = raw.get("ssh_config_hardening", {})
    if row.facts:
        try:
            facts = json.loads(row.facts)
        except Exception:
            facts = {}
    attempts_val = raw.get("attempts") if isinstance(raw, dict) else 0
    try:
        attempts = int(attempts_val or 0)
    except Exception:
        attempts = 0
    return SSHScanHostResult(
        id=row.id or 0,
        host=row.host,
        port=row.port,
        username=row.username,
        auth_method=row.auth_method,
        use_sudo=row.use_sudo,
        sudo_path=row.sudo_path,
        latency_ms=row.latency_ms or (raw.get("latency_ms") if isinstance(raw, dict) else None),
        status=row.status,
        error=row.error or (raw.get("error") if isinstance(raw, dict) else None),
        started_at=isoformat_utc(row.started_at) if row.started_at else None,
        completed_at=isoformat_utc(row.completed_at) if row.completed_at else None,
        attempts=attempts,
        commands=[SSHCommandResult(**cmd) if isinstance(cmd, dict) else cmd for cmd in commands],
        ssh_config_hardening=hardening,
        facts=facts,
    )


def _build_finding_filters(
    scan_id: Optional[int],
    severity: Optional[str],
    status_filter: Optional[str],
    asset_id: Optional[int],
    evidence_grade: Optional[str],
    why_trace_filter: Optional[str],
    search: Optional[str],
):
    query = select(Finding)
    clauses = []
    params: Dict[str, Any] = {}
    grade_value = _unwrap_param(evidence_grade)
    why_value = _unwrap_param(why_trace_filter)

    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
        clauses.append("f.scan_id = :scan_id")
        params["scan_id"] = scan_id
    if severity is not None:
        query = query.where(Finding.severity == severity)
        clauses.append("f.severity = :severity")
        params["severity"] = severity
    if status_filter is not None:
        query = query.where(Finding.status == status_filter)
        clauses.append("f.status = :status_filter")
        params["status_filter"] = status_filter
    if asset_id is not None:
        query = query.where(Finding.asset_id == asset_id)
        clauses.append("f.asset_id = :asset_id")
        params["asset_id"] = asset_id
    if isinstance(grade_value, str):
        query = query.where(func.lower(Finding.evidence_grade) == grade_value.lower())
        clauses.append("lower(f.evidence_grade) = :evidence_grade")
        params["evidence_grade"] = grade_value.lower()
    if isinstance(why_value, str):
        col = func.coalesce(func.length(func.trim(Finding.why_trace)), 0)
        if why_value == "present":
            query = query.where(col > 0)
            clauses.append("coalesce(length(trim(f.why_trace)), 0) > 0")
        elif why_value == "missing":
            query = query.where((Finding.why_trace.is_(None)) | (col == 0))
            clauses.append("(f.why_trace IS NULL OR coalesce(length(trim(f.why_trace)), 0) = 0)")
        params["why_trace_filter"] = why_value
    if search:
        pattern = f"%{search.lower()}%"
        query = query.where(
            func.lower(Finding.service_name).like(pattern)
            | func.lower(Finding.host_address).like(pattern)
            | func.lower(Finding.description).like(pattern)
            | func.lower(Finding.evidence_summary).like(pattern)
            | func.lower(Finding.why_trace).like(pattern)
        )
        clauses.append(
            "("
            "lower(f.service_name) LIKE :q OR "
            "lower(f.host_address) LIKE :q OR "
            "lower(f.description) LIKE :q OR "
            "lower(f.evidence_summary) LIKE :q OR "
            "lower(f.why_trace) LIKE :q"
            ")"
        )
        params["q"] = pattern

    where_sql = " AND ".join(clauses) if clauses else "1=1"
    return query, where_sql, params


def _finding_order_by(sort: str):
    sort_value = _unwrap_param(sort)
    sort_key = (sort_value or "recent").lower()
    severity_rank = case(
        (func.lower(Finding.severity) == "critical", 5),
        (func.lower(Finding.severity) == "high", 4),
        (func.lower(Finding.severity) == "medium", 3),
        (func.lower(Finding.severity) == "low", 2),
        else_=1,
    )
    evidence_rank = case(
        (func.lower(Finding.evidence_grade) == "high", 3),
        (func.lower(Finding.evidence_grade) == "medium", 2),
        (func.lower(Finding.evidence_grade) == "low", 1),
        else_=0,
    )
    why_rank = case((func.coalesce(func.length(func.trim(Finding.why_trace)), 0) > 0, 1), else_=0)
    if sort_key == "severity":
        return [severity_rank.desc(), Finding.detected_at.desc()]
    if sort_key == "port":
        return [case((Finding.port.is_(None), 1), else_=0), Finding.port.asc(), Finding.detected_at.desc()]
    if sort_key in {"evidence", "evidence_grade"}:
        return [evidence_rank.desc(), Finding.detected_at.desc()]
    if sort_key in {"why", "why_trace"}:
        return [why_rank.desc(), Finding.why_trace.desc().nulls_last(), Finding.detected_at.desc()]
    return [Finding.detected_at.desc()]


def _load_enrichment(session: Session, finding_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    if not finding_ids:
        return {}
    stmt = (
        text(
            "SELECT finding_id, cpe, cpe_confidence, cvss_v31_base, cvss_vector, references_json, last_enriched_at, source "
            "FROM finding_enrichment WHERE finding_id IN :ids"
        ).bindparams(bindparam("ids", expanding=True))
    )
    enrichment: Dict[int, Dict[str, Any]] = {}
    try:
        for row in session.exec(stmt, {"ids": finding_ids}).all():
            data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
            fid = int(data.get("finding_id"))
            enrichment[fid] = {
                "cpe": data.get("cpe"),
                "cpe_confidence": data.get("cpe_confidence"),
                "cvss_v31_base": data.get("cvss_v31_base"),
                "cvss_vector": data.get("cvss_vector"),
                "references_json": data.get("references_json"),
                "last_enriched_at": data.get("last_enriched_at"),
                "source": data.get("source"),
            }
    except Exception:
        return {}
    return enrichment


def _parse_cve_ids(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [s for s in data if isinstance(s, str)]
    except Exception:
        if isinstance(raw, str) and "CVE-" in raw.upper():
            return [raw]
    return []


def _safe_json(raw: Optional[str]):
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return raw
    return raw


def _unwrap_param(value: Any) -> Any:
    return value.default if hasattr(value, "default") else value


def _normalize_evidence(finding: Finding) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
    """
    Parse and deduplicate evidence payloads for consistent grading/export.
    Returns (evidence_list_or_none, grade_or_none).
    """
    parsed = _safe_json(finding.evidence)
    if not isinstance(parsed, list):
        return None, None
    deduped = dedupe_evidence(parsed)
    if not deduped:
        return [], None
    return deduped, grade_evidence(deduped)


def _extract_rule_source(finding: Finding) -> Optional[str]:
    evidence, _ = _normalize_evidence(finding)
    if evidence is not None:
        for item in evidence:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            if isinstance(data, dict):
                src = data.get("rule_source")
                if isinstance(src, str) and src:
                    return src
    return None


def _fingerprint_metadata(finding: Finding) -> tuple[Optional[float], List[str]]:
    fingerprint = _safe_json(finding.fingerprint)
    evidence, _ = _normalize_evidence(finding)
    evidence_types: List[str] = []
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict):
                ev_type = item.get("type")
                if isinstance(ev_type, str) and ev_type:
                    evidence_types.append(ev_type)
    evidence_types = list(dict.fromkeys(evidence_types))
    version_confidence: Optional[float] = None
    if isinstance(fingerprint, dict):
        try:
            version_confidence = float(fingerprint.get("version_confidence"))
        except Exception:
            version_confidence = None
    return version_confidence, evidence_types


def _cvss_band(score: Optional[float]) -> str:
    if score is None:
        return "unscored"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _ensure_scanevent_correlation_id(session: Session) -> None:
    """
    SQLite deployments may lack the correlation_id column on scanevent if the DB predates the field.
    Attempt a lightweight migration in-place to unblock deletes and queries.
    """
    try:
        cols = session.exec(text("PRAGMA table_info(scanevent)")).all()
    except Exception:
        return
    names = {str(row[1]) for row in cols if len(row) > 1}
    if "correlation_id" in names:
        return
    try:
        session.exec(text("ALTER TABLE scanevent ADD COLUMN correlation_id VARCHAR(64)"))
        session.commit()
    except Exception:
        session.rollback()


def _serialize_finding_export(finding: Finding, enrichment: Dict[str, Any]) -> Dict[str, Any]:
    score = enrichment.get("cvss_v31_base")
    references: List[str] = []
    refs_raw = enrichment.get("references_json")
    if isinstance(refs_raw, str):
        try:
            parsed = json.loads(refs_raw)
            if isinstance(parsed, list):
                references = [r for r in parsed if isinstance(r, str)]
        except Exception:
            references = []
    cves = _parse_cve_ids(finding.cve_ids)
    evidence, computed_grade = _normalize_evidence(finding)
    version_confidence, evidence_types = _fingerprint_metadata(finding)
    evidence_payload = evidence if evidence is not None else _safe_json(finding.evidence)
    evidence_grade = computed_grade or finding.evidence_grade
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "assigned_user_id": finding.assigned_user_id,
        "owner": finding.owner,
        "rule_id": finding.rule_id,
        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
        "sla_due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
        "closed_at": finding.closed_at.isoformat() if finding.closed_at else None,
        "severity": finding.severity,
        "status": finding.status,
        "service_name": finding.service_name,
        "service_version": finding.service_version,
        "fingerprint": _safe_json(finding.fingerprint),
        "evidence": evidence_payload,
        "evidence_summary": finding.evidence_summary,
        "evidence_grade": finding.evidence_grade or evidence_grade,
        "why_trace": finding.why_trace,
        "host_address": finding.host_address,
        "port": finding.port,
        "protocol": finding.protocol,
        "description": finding.description,
        "cve_ids": cves,
        "cvss_v31_base": score,
        "cvss_vector": enrichment.get("cvss_vector"),
        "cpe": enrichment.get("cpe"),
        "cpe_confidence": enrichment.get("cpe_confidence"),
        "cvss_band": _cvss_band(score if isinstance(score, (float, int)) else None),
        "references": references,
        "rule_source": _extract_rule_source(finding),
        "version_confidence": version_confidence,
        "evidence_types": evidence_types,
    }


def _collect_finding_exports(
    session: Session,
    *,
    scan_id: Optional[int],
    severity: Optional[str],
    status_filter: Optional[str],
    asset_id: Optional[int],
    evidence_grade: Optional[str],
    why_trace: Optional[str],
    search: Optional[str],
    sort: str,
    limit: int,
    offset: int,
) -> tuple[list[Dict[str, Any]], int, Dict[str, int]]:
    base_query, where_sql, params = _build_finding_filters(
        scan_id, severity, status_filter, asset_id, evidence_grade, why_trace, search
    )
    total = session.exec(select(func.count()).select_from(base_query.subquery())).one()
    total_count = int(total or 0)
    rows = session.exec(base_query.order_by(*_finding_order_by(sort)).limit(limit).offset(offset)).all()
    enrichment = _load_enrichment(session, [r.id for r in rows if r.id is not None])
    export_rows = [_serialize_finding_export(f, enrichment.get(f.id or -1, {})) for f in rows]
    band_summary = _aggregate_cvss_bands(session, where_sql, params)
    return export_rows, total_count, band_summary


def _serialize_asset_status(rows: List[ScanAssetStatus]) -> List[Dict[str, Any]]:
    statuses: List[Dict[str, Any]] = []
    for row in rows:
        statuses.append(
            {
                "asset_id": row.asset_id,
                "status": row.status,
                "attempts": row.attempts,
                "last_error": row.last_error,
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            }
        )
    return statuses


def _asset_progress(statuses: List[ScanAssetStatus]) -> int:
    if not statuses:
        return 0
    total = len(statuses)
    score = 0.0
    for row in statuses:
        status = (row.status or "").lower()
        if status in {"completed", "failed"}:
            score += 1.0
        elif status == "running":
            score += 0.6
        elif status in {"queued", "pending"}:
            score += 0.1
        else:
            score += 0.3
    return min(100, round((score / max(total, 1)) * 100))


def _clamp_int(value: Optional[int], default: int, min_value: int, max_value: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(min_value, min(parsed, max_value))


def _aggregate_cvss_bands(session: Session, where_sql: str, params: Dict[str, Any]) -> Dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "unscored": 0}
    stmt = text(
        "SELECT "
        "CASE "
        "WHEN fe.cvss_v31_base >= 9 THEN 'critical' "
        "WHEN fe.cvss_v31_base >= 7 THEN 'high' "
        "WHEN fe.cvss_v31_base >= 4 THEN 'medium' "
        "WHEN fe.cvss_v31_base > 0 THEN 'low' "
        "WHEN fe.cvss_v31_base = 0 THEN 'none' "
        "ELSE 'unscored' END AS band, "
        "COUNT(*) AS count "
        "FROM finding f "
        "LEFT JOIN finding_enrichment fe ON fe.finding_id = f.id "
        f"WHERE {where_sql} "
        "GROUP BY band"
    )
    try:
        for row in session.exec(stmt, params).all():
            data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
            band = data.get("band")
            count = data.get("count")
            if band in summary:
                summary[band] = int(count or 0)
        if sum(summary.values()) == 0:
            fallback_total = session.exec(text(f"SELECT COUNT(*) FROM finding f WHERE {where_sql}"), params).one()
            summary["unscored"] = int(fallback_total or 0)
    except Exception:
        return summary
    return summary


def _record_scan_event(session: Session, scan_id: int, message: str) -> None:
    scan = session.get(Scan, scan_id)
    correlation_id = getattr(scan, "correlation_id", None) if scan else None
    if scan and not correlation_id:
        correlation_id = str(uuid4())
        scan.correlation_id = correlation_id
        session.add(scan)
    payload = {
        "scan_id": scan_id,
        "message": message,
        "ts": now_utc().isoformat(),
    }
    if correlation_id:
        payload["correlation_id"] = correlation_id
    log_event(logger, "scan_event", **payload)
    session.add(ScanEvent(scan_id=scan_id, message=message, correlation_id=correlation_id))
    session.commit()


def _reenrich_scan(scan_id: int, force_refresh_cache: bool = False) -> None:
    from clanker.db.session import get_session as session_factory

    try:
        with session_factory() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                return
            findings = session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
            if not findings:
                return
            observations = _build_observation_index(findings)
            enrich_from_feed(session, findings, observations=observations, force_refresh_cache=force_refresh_cache)
            session.commit()
            _record_scan_event(session, scan_id, "Enrichment refreshed from NVD cache")
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Re-enrichment failed for scan %s: %s", scan_id, exc)


def _reenrich_all_findings(force_refresh_cache: bool = False) -> None:
    from clanker.db.session import get_session as session_factory

    try:
        with session_factory() as session:
            findings = session.exec(select(Finding)).all()
            if not findings:
                return
            observations = _build_observation_index(findings)
            enrich_from_feed(session, findings, observations=observations, force_refresh_cache=force_refresh_cache)
            session.commit()
            logger.info("Enrichment refreshed for all findings")
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Re-enrichment failed for all findings: %s", exc)


def _schedule_reenrich_scan(scan_id: int, force_refresh_cache: bool = False) -> None:
    threading.Thread(target=_reenrich_scan, args=(scan_id, force_refresh_cache), daemon=True).start()


def _ensure_asset_status(session: Session, scan_id: int, asset_id: int) -> ScanAssetStatus:
    status = session.exec(
        select(ScanAssetStatus).where(
            ScanAssetStatus.scan_id == scan_id, ScanAssetStatus.asset_id == asset_id
        )
    ).first()
    if status is None:
        status = ScanAssetStatus(scan_id=scan_id, asset_id=asset_id)
        session.add(status)
        session.flush()
    return status


def _is_scan_cancelled(session: Session, scan_id: int) -> bool:
    scan = session.get(Scan, scan_id)
    return bool(scan and scan.status == "cancelled")


def _cancel_scan_in_db(session: Session, scan_id: int, reason: str) -> Optional[Scan]:
    scan = session.get(Scan, scan_id)
    if not scan:
        return None
    now = now_utc()
    scan.status = "cancelled"
    scan.completed_at = scan.completed_at or now
    scan.notes = reason
    statuses = session.exec(select(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id)).all()
    for status in statuses:
        if status.status not in {"completed", "failed", "cancelled"}:
            status.status = "cancelled"
            status.completed_at = status.completed_at or now
            session.add(status)
    session.add(scan)
    session.commit()
    _record_scan_event(session, scan_id, reason)
    _update_scan_job_status(scan_id, "cancelled")
    return scan


def _serialize_schedule(row: Schedule) -> ScheduleRead:
    return ScheduleRead(
        id=row.id or 0,
        name=row.name,
        profile=row.profile,
        asset_ids=[int(x) for x in _load_json_list(row.asset_ids_json)],
        days_of_week=[int(x) for x in _load_json_list(row.days_of_week_json)],
        times=[str(x) for x in _load_json_list(row.times_json)],
        active=row.active,
        created_at=row.created_at.isoformat(),
        last_run_at=row.last_run_at.isoformat() if row.last_run_at else None,
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def _load_json_list(raw: Optional[str]) -> List[Any]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except Exception:
        return []
    return []


def _dump_json_list(values: List[Any]) -> str:
    try:
        return json.dumps(values)
    except Exception:
        return "[]"


def _derive_key(password: str, salt: bytes) -> bytes:
    import hashlib

    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)


def _const_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= x ^ y
    return res == 0


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    return f"scrypt${_b64encode(salt)}${_b64encode(key)}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        scheme, salt_b64, key_b64 = hashed.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        expected = base64.urlsafe_b64decode(key_b64 + "==")
        actual = _derive_key(password, salt)
        return _const_eq(actual, expected)
    except Exception:
        return False


def _new_token_value() -> str:
    return _b64encode(os.urandom(32))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(dt: Optional[datetime] = None) -> str:
    return (dt or now_utc()).isoformat().replace("+00:00", "Z")


def create_session_token(session: Session, user_id: int, token_type: str, lifetime: timedelta) -> SessionToken:
    token = SessionToken(
        user_id=user_id,
        token=_new_token_value(),
        token_type=token_type,
        expires_at=now_utc() + lifetime,
    )
    session.add(token)
    session.flush()
    session.refresh(token)
    return token


bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    user: User
    token: SessionToken


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    session: Session = Depends(session_dep),
) -> CurrentUser:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    token_value = creds.credentials
    token = session.exec(
        select(SessionToken).where(SessionToken.token == token_value, SessionToken.token_type == "access")
    ).first()

    def _aware(dt: datetime) -> datetime:
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    if not token or token.revoked or _aware(token.expires_at) <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = session.get(User, token.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=403, detail="User disabled")
    return CurrentUser(user=user, token=token)


def require_roles(*roles: str):
    def dep(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current.user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return current

    return dep


@app.get("/ops/queues/scan", dependencies=[Depends(require_roles("admin"))])
def scan_queue_status(session: Session = Depends(session_dep)) -> Dict[str, Any]:
    return _queue_status_snapshot(session)


@app.get("/ops/queues/scan/{scan_id}", dependencies=[Depends(require_roles("admin"))])
def scan_queue_detail(scan_id: int, session: Session = Depends(session_dep)) -> Dict[str, Any]:
    return _queue_job_detail(scan_id, session)


def _extract_bearer_token(token_param: Optional[str], authorization: Optional[str]) -> Optional[str]:
    if token_param:
        return token_param
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _require_stream_user(token_param: Optional[str], authorization: Optional[str]) -> User:
    token_value = _extract_bearer_token(token_param, authorization)
    if not token_value:
        raise HTTPException(status_code=401, detail="Missing access token")
    with get_session() as session:
        token = session.exec(
            select(SessionToken).where(SessionToken.token == token_value, SessionToken.token_type == "access")
        ).first()
        if token and token.expires_at and token.expires_at.tzinfo is None:
            token.expires_at = token.expires_at.replace(tzinfo=timezone.utc)
        if not token or token.revoked or token.expires_at <= now_utc():
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = session.get(User, token.user_id)
        if not user or not user.active:
            raise HTTPException(status_code=403, detail="User disabled")
        return user


def _password_complex_enough(pw: str) -> bool:
    if len(pw) < 10:
        return False
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    return has_lower and has_upper and has_digit and has_symbol


ACCESS_TTL = timedelta(minutes=30)
REFRESH_TTL = timedelta(days=7)
MAX_ATTEMPTS = 5
MAX_IP_ATTEMPTS = 15
WINDOW_SECONDS = 600  # 10 minutes


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenPair(BaseModel):
    access_token: str
    access_expires_at: str
    refresh_token: str
    refresh_expires_at: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    revoke_all: Optional[bool] = False


class MeUpdate(BaseModel):
    name: Optional[str] = None


class UserCreate(BaseModel):
    email: str
    name: Optional[str] = None
    password: str
    role: str = "operator"
    active: bool = True


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class SeedAdminRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = "Administrator"


class SSHHostConfig(BaseModel):
    host: str
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = Field(default=None, exclude=True)
    key_path: Optional[str] = None
    passphrase: Optional[str] = Field(default=None, exclude=True)
    allow_agent: bool = False
    look_for_keys: bool = False
    use_sudo: bool = False
    sudo_path: Optional[str] = None


class SSHScanRequest(BaseModel):
    hosts: List[SSHHostConfig]
    port: Optional[int] = 22
    timeout: Optional[int] = 10
    command_timeout: Optional[int] = 30
    max_workers: Optional[int] = 4
    retries: Optional[int] = 1


class SSHCommandResult(BaseModel):
    name: str
    command: str
    stdout: str
    stderr: str
    exit_status: Optional[int]
    unavailable: bool
    error: Optional[str] = None


class SSHHardeningResult(BaseModel):
    permit_root_login: str
    password_authentication: str


class SSHScanHostResult(BaseModel):
    id: int
    host: Optional[str]
    port: Optional[int]
    username: Optional[str]
    auth_method: str
    use_sudo: bool = False
    sudo_path: Optional[str] = None
    latency_ms: Optional[float] = None
    status: str
    error: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    attempts: int = 0
    commands: List[SSHCommandResult] = Field(default_factory=list)
    ssh_config_hardening: Dict[str, Any] = Field(default_factory=dict)
    facts: Dict[str, Any] = Field(default_factory=dict)


class SSHScanCreateResponse(BaseModel):
    ssh_scan_id: int
    status: str
    host_count: int


class SSHScanDetail(BaseModel):
    id: int
    status: str
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    hosts: List[SSHScanHostResult]


class AuditLogRead(BaseModel):
    id: int
    created_at: str
    actor_user_id: Optional[int]
    action: str
    target: Optional[str]
    ip: Optional[str]
    detail: Optional[str]


class AgentPackage(BaseModel):
    name: str
    version: Optional[str] = None
    source: Optional[str] = None


class AgentService(BaseModel):
    name: str
    status: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    listen_address: Optional[str] = None


class AgentFile(BaseModel):
    path: str
    mode: Optional[str] = Field(default=None, description="Octal mode representation (e.g., 0644)")
    permissions: Optional[str] = Field(default=None, description="Alternate permissions field")


class AgentInterface(BaseModel):
    name: str
    address: Optional[str] = None
    mac: Optional[str] = None
    netmask: Optional[str] = None
    gateway: Optional[str] = None


class AgentInventory(BaseModel):
    host_identifier: Optional[str] = None
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None
    distro: Optional[str] = None
    packages: List[AgentPackage] = Field(default_factory=list)
    services: List[AgentService] = Field(default_factory=list)
    interfaces: List[AgentInterface] = Field(default_factory=list)
    configs: Dict[str, str] = Field(default_factory=dict)
    files: List[AgentFile] = Field(default_factory=list)
    collector_errors: Dict[str, str] = Field(default_factory=dict)


class AgentIngestRequest(BaseModel):
    asset_id: Optional[int] = Field(default=None, description="Attach to an existing asset if provided")
    agent_id: Optional[str] = None
    agent_version: Optional[str] = None
    inventory: AgentInventory


def _persist_agent_ingest(
    session: Session,
    inventory: AgentInventory | Dict[str, Any],
    *,
    asset_id: Optional[int],
    agent_id: Optional[str],
    agent_version: Optional[str],
    raw_payload: Optional[str] = None,
) -> AgentIngest:
    inv = inventory if isinstance(inventory, AgentInventory) else AgentInventory.model_validate(inventory)
    payload = raw_payload
    if payload is None:
        try:
            payload = json.dumps({"agent_id": agent_id, "agent_version": agent_version, "inventory": inv.model_dump()})
        except Exception:
            payload = None
    ingest = AgentIngest(
        asset_id=asset_id,
        agent_id=agent_id,
        agent_version=agent_version,
        host_identifier=inv.host_identifier or inv.hostname,
        hostname=inv.hostname,
        os_name=inv.os_name,
        os_version=inv.os_version,
        kernel_version=inv.kernel_version,
        distro=inv.distro,
        package_count=len(inv.packages),
        service_count=len(inv.services),
        interface_count=len(inv.interfaces),
        config_count=len(inv.configs),
        # file_count intentionally omitted from schema to avoid schema drift
        raw_payload=payload,
    )
    session.add(ingest)
    session.flush()
    return ingest


class AgentIngestResponse(BaseModel):
    ingest_id: int
    status: str


class AgentRuleReloadResponse(BaseModel):
    status: str
    packages: int
    services: int
    kernels: int
    path: str


class SchedulePayload(BaseModel):
    name: str
    profile: str
    asset_ids: List[int]
    days_of_week: List[int]
    times: List[str]
    active: bool = True


class ScheduleRead(BaseModel):
    id: int
    name: str
    profile: str
    asset_ids: List[int]
    days_of_week: List[int]
    times: List[str]
    active: bool
    created_at: str
    last_run_at: Optional[str]


class ScanJobRead(BaseModel):
    id: int
    scan_id: int
    status: str
    attempts: int
    max_attempts: int
    last_error: Optional[str]
    enqueued_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class ScanJobErrorRead(BaseModel):
    attempt: int
    error: str
    ts: datetime


class ScanJobDetailRead(BaseModel):
    job: ScanJobRead
    queue_attempt: int
    cancelled: bool
    errors: List[ScanJobErrorRead] = Field(default_factory=list)


class RuleGapExample(BaseModel):
    host: Optional[str] = None
    service_version: Optional[str] = None
    fingerprint: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    evidence_summary: Optional[str] = None


class RuleGapBucket(BaseModel):
    protocol: str
    port: Optional[int] = None
    service_name: str
    count: int
    examples: List[RuleGapExample] = Field(default_factory=list)
    stub_rule: Dict[str, Any]


class RuleGapRaw(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    fingerprint: Optional[Dict[str, Any]] = None
    evidence_summary: Optional[str] = None
    reason: Optional[str] = None


class RuleGapSummaryResponse(BaseModel):
    total: int
    buckets: List[RuleGapBucket]


class RuleGapRawResponse(BaseModel):
    total: int
    items: List[RuleGapRaw]


class FindingReadWithSource(FindingRead):
    rule_source: Optional[str] = None
    version_confidence: Optional[float] = None
    evidence_types: List[str] = Field(default_factory=list)


def _load_rule_gap_entries() -> List[Dict[str, Any]]:
    try:
        return load_rule_gaps()
    except Exception:
        return []


@app.get(
    "/coverage/rule_gaps/summary",
    response_model=RuleGapSummaryResponse,
    dependencies=[Depends(require_roles("admin", "operator"))],
)
def summarize_rule_gaps_endpoint() -> RuleGapSummaryResponse:
    entries = _load_rule_gap_entries()
    summary = summarize_rule_gaps(entries)
    buckets: List[RuleGapBucket] = []
    for bucket in summary:
        stub = stub_rule_from_gap(bucket)
        buckets.append(
            RuleGapBucket(
                protocol=bucket.get("protocol", "unknown"),
                port=bucket.get("port"),
                service_name=bucket.get("service_name") or "unknown",
                count=bucket.get("count", 0),
                examples=[RuleGapExample(**example) for example in bucket.get("examples", [])],
                stub_rule=stub,
            )
        )
    return RuleGapSummaryResponse(total=len(entries), buckets=buckets)


@app.get(
    "/coverage/rule_gaps/raw",
    response_model=RuleGapRawResponse,
    dependencies=[Depends(require_roles("admin", "operator"))],
)
def list_rule_gaps_raw(
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> RuleGapRawResponse:
    entries = _load_rule_gap_entries()
    window = entries[offset : offset + limit] if entries else []
    return RuleGapRawResponse(total=len(entries), items=[RuleGapRaw(**item) for item in window])


@app.delete(
    "/coverage/rule_gaps",
    response_model=Dict[str, str],
    dependencies=[Depends(require_roles("admin"))],
)
def clear_rule_gap_log() -> Dict[str, str]:
    path = settings.rule_gap_path
    try:
        path.write_text("")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to clear rule gap log")
    return {"status": "cleared", "path": str(path)}


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else ""


@app.post("/auth/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, session: Session = Depends(session_dep)) -> TokenPair:
    since = now_utc() - timedelta(seconds=WINDOW_SECONDS)
    ip = _client_ip(request)
    user_failures = session.exec(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.email == payload.email, LoginAttempt.success == False, LoginAttempt.created_at >= since  # noqa: E712
        )
    ).one()
    ip_failures = session.exec(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.ip == ip, LoginAttempt.success == False, LoginAttempt.created_at >= since  # noqa: E712
        )
    ).one()
    if int(user_failures or 0) >= MAX_ATTEMPTS:
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(
            AuditLog(
                actor_user_id=None,
                action="login_throttled",
                target=payload.email,
                ip=ip,
                detail=f"user_failures={int(user_failures or 0)} window_seconds={WINDOW_SECONDS}",
            )
        )
        session.flush()
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")
    if int(ip_failures or 0) >= MAX_IP_ATTEMPTS:
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(
            AuditLog(
                actor_user_id=None,
                action="login_throttled_ip",
                target=payload.email,
                ip=ip,
                detail=f"ip_failures={int(ip_failures or 0)} window_seconds={WINDOW_SECONDS}",
            )
        )
        session.flush()
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

    user = session.exec(select(User).where(User.email == payload.email)).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(
            AuditLog(
                actor_user_id=None,
                action="login_failure",
                target=payload.email,
                ip=ip,
                detail="invalid_credentials",
            )
        )
        session.flush()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.active:
        raise HTTPException(status_code=403, detail="User disabled")

    session.add(LoginAttempt(email=payload.email, ip=ip, success=True))
    session.add(
        AuditLog(
            actor_user_id=user.id,
            action="login_success",
            target=payload.email,
            ip=ip,
            detail=f"user_failures={int(user_failures or 0)}",
        )
    )

    access = create_session_token(session, user_id=user.id, token_type="access", lifetime=ACCESS_TTL)
    refresh = create_session_token(session, user_id=user.id, token_type="refresh", lifetime=REFRESH_TTL)

    return TokenPair(
        access_token=access.token,
        access_expires_at=access.expires_at.isoformat(),
        refresh_token=refresh.token,
        refresh_expires_at=refresh.expires_at.isoformat(),
    )


@app.post("/auth/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, session: Session = Depends(session_dep)) -> TokenPair:
    tok = session.exec(
        select(SessionToken).where(SessionToken.token == payload.refresh_token, SessionToken.token_type == "refresh")
    ).first()
    if tok and tok.expires_at and tok.expires_at.tzinfo is None:
        tok.expires_at = tok.expires_at.replace(tzinfo=timezone.utc)
        session.add(tok)
        session.flush()
    if not tok or tok.revoked or tok.expires_at <= now_utc():
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = session.get(User, tok.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=403, detail="User disabled")

    access = create_session_token(session, user_id=user.id, token_type="access", lifetime=ACCESS_TTL)
    refresh = create_session_token(session, user_id=user.id, token_type="refresh", lifetime=REFRESH_TTL)

    session.add(AuditLog(actor_user_id=user.id, action="token_refreshed", target=user.email, ip=None, detail=None))
    return TokenPair(
        access_token=access.token,
        access_expires_at=access.expires_at.isoformat(),
        refresh_token=refresh.token,
        refresh_expires_at=refresh.expires_at.isoformat(),
    )


@app.get("/auth/me", response_model=UserRead)
def me(current=Depends(get_current_user)) -> UserRead:  # type: ignore[no-redef]
    u = current.user
    return UserRead(id=u.id, email=u.email, name=u.name, role=u.role, active=u.active, created_at=u.created_at)  # type: ignore[arg-type]


@app.patch("/auth/me", response_model=UserRead)
def update_me(payload: MeUpdate, current=Depends(get_current_user), session: Session = Depends(session_dep)) -> UserRead:  # type: ignore[no-redef]
    user = session.get(User, current.user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.name is not None:
        user.name = payload.name
    session.add(user)
    session.flush()
    session.refresh(user)
    return UserRead(id=user.id, email=user.email, name=user.name, role=user.role, active=user.active, created_at=user.created_at)  # type: ignore[arg-type]


@app.post("/auth/logout")
def logout(payload: LogoutRequest, current=Depends(get_current_user), session: Session = Depends(session_dep)) -> dict:  # type: ignore[no-redef]
    if payload.revoke_all:
        for t in session.exec(select(SessionToken).where(SessionToken.user_id == current.user.id)).all():
            t.revoked = True
            session.add(t)
    else:
        current.token.revoked = True
        session.add(current.token)
    session.add(AuditLog(actor_user_id=current.user.id, action="logout", target=current.user.email, ip=None, detail=None))
    return {"status": "ok"}


@app.post("/auth/change_password")
def change_password(payload: ChangePasswordRequest, current=Depends(get_current_user), session: Session = Depends(session_dep)) -> dict:  # type: ignore[no-redef]
    user = session.get(User, current.user.id)
    if not user or not verify_password(payload.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    if not _password_complex_enough(payload.new_password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
    user.hashed_password = hash_password(payload.new_password)
    session.add(user)
    session.add(AuditLog(actor_user_id=user.id, action="password_changed", target=str(user.id), ip=None, detail=None))
    return {"status": "ok"}


@app.post("/auth/seed_admin")
def seed_admin(payload: SeedAdminRequest, session: Session = Depends(session_dep)) -> dict:
    existing = session.exec(select(User)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Users already exist")
    if not _password_complex_enough(payload.password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
    user = User(email=payload.email, name=payload.name, hashed_password=hash_password(payload.password), role="admin", active=True)
    session.add(user)
    session.flush()
    session.add(AuditLog(actor_user_id=user.id, action="user_created", target=str(user.id), ip=None, detail="seed_admin"))
    return {"status": "ok"}


@app.get("/users", response_model=List[UserRead])
def list_users(_: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> list[User]:
    return session.exec(select(User).order_by(User.created_at.desc())).all()


@app.post("/users", response_model=UserRead, status_code=201)
def create_user(payload: UserCreate, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> User:
    existing = session.exec(select(User).where(User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    if not _password_complex_enough(payload.password):
        raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
    user = User(
        email=payload.email,
        name=payload.name,
        hashed_password=hash_password(payload.password),
        role=payload.role or "operator",
        active=payload.active,
    )
    session.add(user)
    session.flush()
    session.refresh(user)
    session.add(AuditLog(actor_user_id=None, action="user_created", target=str(user.id), ip=None, detail=user.email))
    return user


@app.patch("/users/{user_id}", response_model=UserRead)
def update_user(user_id: int, payload: UserUpdate, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> User:
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.role is not None and user.role == "admin" and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Cannot change role for administrator accounts")
    if payload.active is not None and user.role == "admin" and payload.active is False:
        raise HTTPException(status_code=400, detail="Cannot disable administrator accounts")
    if payload.name is not None:
        user.name = payload.name
    if payload.role is not None:
        user.role = payload.role
    if payload.active is not None:
        user.active = payload.active
    if payload.password:
        if not _password_complex_enough(payload.password):
            raise HTTPException(status_code=400, detail="Password does not meet complexity requirements")
        user.hashed_password = hash_password(payload.password)
    session.add(user)
    session.flush()
    session.refresh(user)
    session.add(AuditLog(actor_user_id=None, action="user_updated", target=str(user.id), ip=None, detail=None))
    return user


@app.get("/audit_logs", response_model=List[AuditLogRead])
def list_audit_logs(
    _: object = Depends(require_roles("admin")),
    user_id: Optional[int] = Query(default=None),
    action: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
    session: Session = Depends(session_dep),
) -> list[AuditLogRead]:
    q = select(AuditLog)
    if user_id is not None:
        q = q.where(AuditLog.actor_user_id == user_id)
    if action is not None:
        q = q.where(AuditLog.action == action)

    def _parse(ts: Optional[str]):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return None

    s_dt = _parse(since)
    u_dt = _parse(until)
    if s_dt is not None:
        q = q.where(AuditLog.created_at >= s_dt)
    if u_dt is not None:
        q = q.where(AuditLog.created_at <= u_dt)
    rows = session.exec(q.order_by(AuditLog.created_at.desc())).all()
    return [
        AuditLogRead(
            id=r.id,
            created_at=r.created_at.isoformat(),
            actor_user_id=r.actor_user_id,
            action=r.action,
            target=r.target,
            ip=r.ip,
            detail=r.detail,
        )
        for r in rows
    ]


def _seed_admin_if_configured(session: Session) -> None:
    email = os.getenv("CLANKER_ADMIN_EMAIL")
    password = os.getenv("CLANKER_ADMIN_PASSWORD")
    if not email or not password:
        return
    hashed = hash_password(password)
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        existing.hashed_password = hashed
        existing.role = "admin"
        existing.active = True
        if not existing.name:
            existing.name = "Administrator"
        session.add(existing)
    else:
        user = User(email=email, name="Administrator", hashed_password=hashed, role="admin", active=True)
        session.add(user)
    # Clear lockouts for the seeded admin account
    for attempt in session.exec(select(LoginAttempt).where(LoginAttempt.email == email)).all():
        session.delete(attempt)


@register_startup_hook
def _seed_admin_on_startup() -> None:
    try:
        with get_session() as s:
            _seed_admin_if_configured(s)
    except Exception:
        pass

@app.post("/assets", response_model=AssetRead, status_code=201)
def create_asset(payload: AssetCreate, session: Session = Depends(session_dep)) -> Asset:
    asset = Asset(**payload.model_dump())
    session.add(asset)
    session.flush()
    session.refresh(asset)
    return asset


@app.get("/assets", response_model=List[AssetRead])
def list_assets(
    response: Response,
    q: Optional[str] = Query(default=None, description="Filter by partial target or name"),
    environment: Optional[str] = Query(default=None),
    owner: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(session_dep),
) -> List[Asset]:
    query = select(Asset)
    if q:
        pattern = f"%{q.lower()}%"
        query = query.where(func.lower(Asset.target).like(pattern) | func.lower(Asset.name).like(pattern))
    if environment:
        query = query.where(Asset.environment == environment)
    if owner:
        query = query.where(Asset.owner == owner)

    rows, total = _paginate_query(session, query.order_by(Asset.created_at.desc()), limit, offset)
    response.headers["X-Total-Count"] = str(total)
    return rows


@app.get("/assets/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: int, session: Session = Depends(session_dep)) -> Asset:
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@app.patch("/assets/{asset_id}", response_model=AssetRead)
def update_asset(asset_id: int, payload: AssetUpdate, session: Session = Depends(session_dep)) -> Asset:
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)
    session.add(asset)
    session.flush()
    session.refresh(asset)
    return asset


@app.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, session: Session = Depends(session_dep)) -> Response:
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    session.delete(asset)
    session.commit()
    return Response(status_code=204)


@app.post("/agents/ingest", response_model=AgentIngestResponse, status_code=202)
def ingest_agent_inventory(
    payload: AgentIngestRequest,
    current=Depends(require_roles("admin", "operator")),  # type: ignore[no-redef]
    session: Session = Depends(session_dep),
) -> AgentIngestResponse:
    asset_id: Optional[int] = None
    if payload.asset_id is not None:
        asset = session.get(Asset, payload.asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        asset_id = asset.id

    inv = payload.inventory
    raw_payload = json.dumps(payload.model_dump())
    ingest = _persist_agent_ingest(
        session,
        inv,
        asset_id=asset_id,
        agent_id=payload.agent_id,
        agent_version=payload.agent_version,
        raw_payload=raw_payload,
    )
    session.add(
        AuditLog(
            actor_user_id=current.user.id,
            action="agent_ingest",
            target=ingest.host_identifier or ingest.hostname or str(ingest.id),
            ip=None,
            detail=payload.agent_id or payload.agent_version,
        )
    )
    try:
        persist_agent_findings(session, inv, asset_id=asset_id, ingest_id=ingest.id)
    except Exception as exc:  # Defensive: do not block ingest on vuln logic issues
        logger.exception("Failed to persist agent findings for ingest %s: %s", ingest.id, exc)
    return AgentIngestResponse(ingest_id=ingest.id, status="accepted")


@app.post(
    "/agents/rules/reload",
    response_model=AgentRuleReloadResponse,
    dependencies=[Depends(require_roles("admin"))],
)
def reload_agent_rules_endpoint() -> AgentRuleReloadResponse:
    reload_agent_rules()
    pkg_count, svc_count, kernel_count = agent_rule_counts()
    return AgentRuleReloadResponse(
        status="reloaded",
        packages=pkg_count,
        services=svc_count,
        kernels=kernel_count,
        path=str(settings.agent_advisories_path),
    )


@app.post("/scans", response_model=ScanRead, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(session_dep),
) -> Scan:
    if not payload.asset_ids:
        raise HTTPException(status_code=400, detail="asset_ids must not be empty")

    asset_ids = sorted(set(payload.asset_ids))
    assets = session.exec(select(Asset).where(Asset.id.in_(asset_ids))).all()
    if len(assets) != len(asset_ids):
        raise HTTPException(status_code=404, detail="One or more assets not found")

    profile_key = payload.profile or DEFAULT_PROFILE_KEY
    if profile_key not in SCAN_PROFILE_KEYS:
        raise HTTPException(status_code=400, detail="Unknown scan profile")

    scan = _create_scan_record(session, [a.id for a in assets if a.id is not None], profile_key)
    session.commit()
    _enqueue_scan_job(scan.id, session=session)
    return scan


@app.get("/queues/scan")
def scan_queue_status(_: object = Depends(require_roles("admin", "operator"))) -> Dict[str, object]:
    queue = _ensure_scan_queue()
    with get_session() as session:
        job_counts = _scan_job_status_counts(session)
    snapshot = queue.snapshot()
    snapshot["jobs"] = job_counts
    return snapshot


@app.get("/scans/{scan_id}/job", response_model=ScanJobRead)
def get_scan_job_metadata(
    scan_id: int, _: object = Depends(require_roles("viewer", "operator", "admin")), session: Session = Depends(session_dep)
) -> ScanJob:
    job = session.exec(select(ScanJob).where(ScanJob.scan_id == scan_id)).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@app.get("/scans/{scan_id}/job/detail", response_model=ScanJobDetailRead)
def get_scan_job_detail(
    scan_id: int, _: object = Depends(require_roles("viewer", "operator", "admin")), session: Session = Depends(session_dep)
) -> ScanJobDetailRead:
    job = session.exec(select(ScanJob).where(ScanJob.scan_id == scan_id)).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    queue = _ensure_scan_queue()
    detail = queue.job_detail(scan_id) if queue else {}
    queue_attempt = int(detail.get("attempt") or job.attempts or 0) if isinstance(detail, dict) else job.attempts
    cancelled = bool((isinstance(detail, dict) and detail.get("cancelled")) or job.status == "cancelled")

    errors: List[ScanJobErrorRead] = []
    if isinstance(detail, dict):
        for entry in detail.get("errors", []):
            errors.append(
                ScanJobErrorRead(
                    attempt=int(entry.get("attempt") or job.attempts or 0),
                    error=str(entry.get("error") or job.last_error or ""),
                    ts=_coerce_datetime(entry.get("ts")),
                )
            )
    if not errors and job.last_error:
        errors.append(
            ScanJobErrorRead(
                attempt=job.attempts,
                error=job.last_error,
                ts=_coerce_datetime(job.completed_at or job.updated_at or job.enqueued_at),
            )
        )

    return ScanJobDetailRead(job=job, queue_attempt=queue_attempt, cancelled=cancelled, errors=errors)


@app.post("/scans/{scan_id}/enqueue", response_model=ScanJobRead)
def enqueue_scan_job(
    scan_id: int,
    force: bool = Query(default=False, description="Force re-enqueue even if a job exists"),
    _: object = Depends(require_roles("admin", "operator")),
    session: Session = Depends(session_dep),
) -> ScanJob:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Scan is currently running")
    if scan.status not in {"queued"} and not force:
        raise HTTPException(
            status_code=400, detail="Scan is not queued. Use /scans/{scan_id}/retry or set force=true to requeue."
        )
    job = _enqueue_scan_job(scan.id, force=force, session=session)
    session.refresh(job)
    return job


def _create_scan_record(session: Session, asset_ids: List[int], profile_key: str) -> Scan:
    scan = Scan(profile=profile_key, status="queued", correlation_id=str(uuid4()))
    session.add(scan)
    session.flush()

    for asset in session.exec(select(Asset).where(Asset.id.in_(asset_ids))).all():
        session.add(ScanTarget(scan_id=scan.id, asset_id=asset.id))
        _ensure_asset_status(session, scan.id, asset.id)
    if scan.id is not None:
        _record_scan_event(session, scan.id, "Scan queued")
    return scan


@app.get("/scans", response_model=List[ScanRead])
def list_scans(
    response: Response,
    status: Optional[str] = Query(default=None),
    profile: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None, description="Search by notes or scan id"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(session_dep),
) -> List[Scan]:
    query = select(Scan)
    if status:
        query = query.where(Scan.status == status)
    if profile:
        query = query.where(Scan.profile == profile)
    if q:
        if q.isdigit():
            query = query.where(Scan.id == int(q))
        else:
            pattern = f"%{q.lower()}%"
            query = query.where(func.lower(Scan.notes).like(pattern))
    rows, total = _paginate_query(session, query.order_by(Scan.created_at.desc()), limit, offset)
    response.headers["X-Total-Count"] = str(total)
    return rows


@app.get("/metrics/queue")
def get_queue_metrics() -> Dict[str, int]:
    if scan_job_queue is None:
        return {"status": "queue_not_initialized"}
    with get_session() as session:
        job_counts = _scan_job_status_counts(session)
    base = scan_job_queue.stats()
    base.update({f"jobs_{k}": v for k, v in job_counts.items()})
    return base


def _validate_schedule_payload(payload: SchedulePayload, session: Session) -> None:
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="Name is required")
    if payload.profile not in SCAN_PROFILE_KEYS:
        raise HTTPException(status_code=400, detail="Unknown scan profile")
    if not payload.asset_ids:
        raise HTTPException(status_code=400, detail="At least one asset is required")
    assets = session.exec(select(Asset.id).where(Asset.id.in_(payload.asset_ids))).all()
    if len(assets) != len(set(payload.asset_ids)):
        raise HTTPException(status_code=404, detail="One or more assets not found")
    if not payload.days_of_week:
        raise HTTPException(status_code=400, detail="days_of_week must not be empty")
    for t in payload.times:
        if ":" not in t:
            raise HTTPException(status_code=400, detail="Time values must be HH:MM")


@app.get("/schedules", response_model=List[ScheduleRead])
def list_schedules(_: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> List[ScheduleRead]:
    rows = session.exec(select(Schedule).order_by(Schedule.created_at.desc())).all()
    return [_serialize_schedule(r) for r in rows]


@app.post("/schedules", response_model=ScheduleRead, status_code=201)
def create_schedule(payload: SchedulePayload, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> ScheduleRead:
    _validate_schedule_payload(payload, session)
    row = Schedule(
        name=payload.name,
        profile=payload.profile,
        asset_ids_json=_dump_json_list(payload.asset_ids),
        days_of_week_json=_dump_json_list(payload.days_of_week),
        times_json=_dump_json_list(payload.times),
        active=payload.active,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return _serialize_schedule(row)


@app.patch("/schedules/{schedule_id}", response_model=ScheduleRead)
def update_schedule(schedule_id: int, payload: SchedulePayload, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> ScheduleRead:
    row = session.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _validate_schedule_payload(payload, session)
    row.name = payload.name
    row.profile = payload.profile
    row.asset_ids_json = _dump_json_list(payload.asset_ids)
    row.days_of_week_json = _dump_json_list(payload.days_of_week)
    row.times_json = _dump_json_list(payload.times)
    row.active = payload.active
    session.add(row)
    session.commit()
    session.refresh(row)
    return _serialize_schedule(row)


@app.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, _: object = Depends(require_roles("admin")), session: Session = Depends(session_dep)) -> Response:
    row = session.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    session.delete(row)
    session.commit()
    return Response(status_code=204)


@app.post("/schedules/{schedule_id}/run-now")
def run_schedule_now(schedule_id: int, background_tasks: BackgroundTasks, _: object = Depends(require_roles("admin", "operator")), session: Session = Depends(session_dep)) -> Dict[str, Any]:
    row = session.get(Schedule, schedule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if not row.active:
        raise HTTPException(status_code=400, detail="Schedule is paused")
    asset_ids = [int(x) for x in _load_json_list(row.asset_ids_json)]
    if not asset_ids:
        raise HTTPException(status_code=400, detail="Schedule has no assets")
    profile_key = row.profile or DEFAULT_PROFILE_KEY
    scan = _create_scan_record(session, asset_ids, profile_key)
    row.last_run_at = now_utc()
    session.add(row)
    session.commit()
    _enqueue_scan_job(scan.id, session=session)
    return {"status": "queued", "scan_id": scan.id}


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, session: Session = Depends(session_dep)) -> Response:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    _ensure_scanevent_correlation_id(session)
    session.exec(delete(Finding).where(Finding.scan_id == scan_id))
    session.exec(delete(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id))
    session.exec(delete(ScanEvent).where(ScanEvent.scan_id == scan_id))
    session.exec(delete(ScanTarget).where(ScanTarget.scan_id == scan_id))
    session.delete(scan)
    session.commit()
    return Response(status_code=204)


@app.post("/ssh_scans", response_model=SSHScanCreateResponse, status_code=202)
def queue_ssh_scan(
    payload: SSHScanRequest,
    current=Depends(require_roles("admin", "operator")),  # type: ignore[no-redef]
    session: Session = Depends(session_dep),
) -> SSHScanCreateResponse:
    if not payload.hosts:
        raise HTTPException(status_code=400, detail="hosts must not be empty")

    normalized_hosts: List[Dict[str, Any]] = []
    default_port = payload.port or 22
    timeout = _clamp_int(payload.timeout, 10, 1, SSH_TIMEOUT_LIMIT)
    command_timeout = _clamp_int(payload.command_timeout, 30, 5, SSH_COMMAND_TIMEOUT_LIMIT)
    max_workers = _clamp_int(payload.max_workers, 4, 1, SSH_MAX_WORKERS_LIMIT)
    retries = _clamp_int(payload.retries, 1, 0, SSH_RETRY_LIMIT)
    for host_cfg in payload.hosts:
        if not host_cfg.host.strip():
            raise HTTPException(status_code=400, detail="Host is required for each entry")
        if not host_cfg.username:
            raise HTTPException(status_code=400, detail=f"Username missing for host {host_cfg.host}")
        if not (host_cfg.password or host_cfg.key_path or host_cfg.allow_agent or host_cfg.look_for_keys):
            raise HTTPException(
                status_code=400,
                detail=f"Provide a password, key_path, or enable agent/key discovery for host {host_cfg.host}",
            )
        key_path = host_cfg.key_path
        if key_path:
            expanded = Path(key_path).expanduser()
            if not expanded.is_file():
                raise HTTPException(status_code=400, detail=f"SSH key for {host_cfg.host} not found at {expanded}")
            key_path = str(expanded)
        normalized_hosts.append(
            {
                "host": host_cfg.host,
                "port": host_cfg.port or default_port,
                "username": host_cfg.username,
                "password": host_cfg.password,
                "key_path": key_path,
                "passphrase": host_cfg.passphrase,
                "allow_agent": host_cfg.allow_agent,
                "look_for_keys": host_cfg.look_for_keys,
                "use_sudo": host_cfg.use_sudo or False,
                "sudo_path": host_cfg.sudo_path,
            }
        )

    ssh_scan = SSHScan(
        status="queued",
        port=default_port,
        timeout=timeout,
        command_timeout=command_timeout,
        max_workers=max_workers,
        created_by_user_id=current.user.id if getattr(current, "user", None) else None,
    )
    session.add(ssh_scan)
    session.flush()
    _cache_ssh_retry(ssh_scan.id or 0, retries)

    for host_cfg in normalized_hosts:
        asset = session.exec(select(Asset).where(Asset.target == host_cfg["host"])).first()
        host_row = SSHScanHost(
            ssh_scan_id=ssh_scan.id or 0,
            asset_id=asset.id if asset else None,
            host=host_cfg["host"],
            port=host_cfg.get("port") or default_port,
            username=host_cfg.get("username"),
            auth_method="key" if host_cfg.get("key_path") else "password" if host_cfg.get("password") else "unspecified",
            use_sudo=bool(host_cfg.get("use_sudo")),
            sudo_path=host_cfg.get("sudo_path"),
            status="queued",
        )
        session.add(host_row)
        session.flush()
        if host_row.id:
                    _cache_ssh_credentials(
                        host_row.id,
                        {
                            "password": host_cfg.get("password"),
                            "key_path": host_cfg.get("key_path"),
                            "passphrase": host_cfg.get("passphrase"),
                            "allow_agent": host_cfg.get("allow_agent", False),
                            "look_for_keys": host_cfg.get("look_for_keys", False),
                            "username": host_cfg.get("username"),
                            "sudo": bool(host_cfg.get("use_sudo")),
                            "sudo_path": host_cfg.get("sudo_path"),
                        },
                    )

    session.add(
        AuditLog(
            actor_user_id=current.user.id,
            action="ssh_scan_schedule",
            target=",".join([h.get("host", "") for h in normalized_hosts])[:120],
            ip=None,
            detail=f"{len(normalized_hosts)} host(s) queued for SSH scan",
        )
    )
    session.commit()

    if ssh_scan_job_queue is not None:
        ssh_scan_job_queue.enqueue(ssh_scan.id or 0)
    logger.info(
        "ssh_scan_scheduled %s",
        json.dumps(
            {
                "ssh_scan_id": ssh_scan.id,
                "hosts": len(normalized_hosts),
                "timeout": timeout,
                "command_timeout": command_timeout,
                "max_workers": max_workers,
                "retries": retries,
            }
        ),
    )

    return SSHScanCreateResponse(
        ssh_scan_id=ssh_scan.id or 0,
        status="queued",
        host_count=len(normalized_hosts),
    )


@app.post("/assets/{asset_id}/ssh_scan", response_model=SSHScanCreateResponse, status_code=202)
def queue_asset_ssh_scan(
    asset_id: int,
    current=Depends(require_roles("admin", "operator")),  # type: ignore[no-redef]
    session: Session = Depends(session_dep),
) -> SSHScanCreateResponse:
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.credentialed:
        raise HTTPException(status_code=400, detail="Asset is not marked as credentialed")
    if not asset.ssh_username:
        raise HTTPException(status_code=400, detail="SSH username is required")
    auth_method = asset.ssh_auth_method or "unspecified"
    has_password = auth_method == "password" and bool(asset.ssh_password)
    has_key = auth_method == "key" and bool(asset.ssh_key_path)
    has_agent = auth_method == "agent" and (asset.ssh_allow_agent or asset.ssh_look_for_keys)
    use_sudo = bool(asset.ssh_use_sudo) if hasattr(asset, "ssh_use_sudo") else False
    sudo_path = getattr(asset, "ssh_sudo_path", None)
    if not (has_password or has_key or has_agent):
        raise HTTPException(status_code=400, detail="Missing SSH credential for this asset")

    port = asset.ssh_port or 22
    ssh_scan = SSHScan(
        status="queued",
        port=port,
        timeout=10,
        command_timeout=30,
        max_workers=1,
        created_by_user_id=current.user.id if getattr(current, "user", None) else None,
    )
    session.add(ssh_scan)
    session.flush()
    _cache_ssh_retry(ssh_scan.id or 0, 1)

    host_row = SSHScanHost(
        ssh_scan_id=ssh_scan.id or 0,
        asset_id=asset.id,
        host=asset.target,
        port=port,
        username=asset.ssh_username,
        auth_method=auth_method,
        use_sudo=use_sudo,
        sudo_path=sudo_path,
        status="queued",
    )
    session.add(host_row)
    session.flush()
    if host_row.id:
        _cache_ssh_credentials(
            host_row.id,
            {
                "password": asset.ssh_password,
                "key_path": asset.ssh_key_path,
                "passphrase": None,
                "allow_agent": bool(asset.ssh_allow_agent),
                "look_for_keys": bool(asset.ssh_look_for_keys),
                "username": asset.ssh_username,
                "sudo": use_sudo,
                "sudo_path": sudo_path,
            },
        )

    session.add(
        AuditLog(
            actor_user_id=current.user.id,
            action="ssh_scan_schedule",
            target=asset.target,
            ip=None,
            detail="1 host queued for SSH scan via asset",
        )
    )
    session.commit()

    if ssh_scan_job_queue is not None:
        ssh_scan_job_queue.enqueue(ssh_scan.id or 0)

    return SSHScanCreateResponse(
        ssh_scan_id=ssh_scan.id or 0,
        status="queued",
        host_count=1,
    )


@app.get("/ssh_scans/{ssh_scan_id}", response_model=SSHScanDetail)
def get_ssh_scan_detail(ssh_scan_id: int, session: Session = Depends(session_dep)) -> SSHScanDetail:
    scan = session.get(SSHScan, ssh_scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="SSH scan not found")
    hosts = (
        session.exec(select(SSHScanHost).where(SSHScanHost.ssh_scan_id == ssh_scan_id).order_by(SSHScanHost.id)).all()
        or []
    )
    return SSHScanDetail(
        id=scan.id or 0,
        status=scan.status,
        created_at=isoformat_utc(scan.created_at),
        started_at=isoformat_utc(scan.started_at) if scan.started_at else None,
        completed_at=isoformat_utc(scan.completed_at) if scan.completed_at else None,
        hosts=[_serialize_ssh_host(h) for h in hosts],
    )


@app.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: int,
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> ScanDetail:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    asset_count = session.exec(
        select(func.count()).select_from(ScanTarget).where(ScanTarget.scan_id == scan_id)
    ).one()
    asset_count = int(asset_count or 0)
    severity_rows = session.exec(
        select(Finding.severity, func.count()).where(Finding.scan_id == scan_id).group_by(Finding.severity)
    ).all()
    severity_summary: Dict[str, int] = {severity: count for severity, count in severity_rows}
    recent_events = session.exec(
        select(ScanEvent.message)
        .where(ScanEvent.scan_id == scan_id)
        .order_by(ScanEvent.created_at.desc())
        .limit(5)
    ).all()
    return ScanDetail(
        id=scan.id,
        status=scan.status,
        profile=scan.profile,
        notes=scan.notes,
        retry_count=scan.retry_count,
        correlation_id=scan.correlation_id,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        asset_count=asset_count or 0,
        severity_summary=severity_summary,
        recent_events=[entry[0] for entry in recent_events],
    )


@app.post("/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: int,
    _: object = Depends(require_roles("admin", "operator")),
    session: Session = Depends(session_dep),
) -> Dict[str, str]:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in {"completed", "completed_with_errors", "failed", "cancelled"}:
        return {"status": scan.status}
    _cancel_scan_in_db(session, scan_id, "Scan cancelled by user")
    if scan_job_queue is not None:
        scan_job_queue.cancel(scan_id)
    return {"status": "cancelled"}


@app.post("/scans/{scan_id}/retry", response_model=ScanRead)
def retry_scan(
    scan_id: int,
    _: object = Depends(require_roles("admin", "operator")),
    session: Session = Depends(session_dep),
) -> Scan:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"failed", "completed", "completed_with_errors", "cancelled"}:
        raise HTTPException(status_code=400, detail="Scan is still running or queued")

    scan.status = "queued"
    scan.started_at = None
    scan.completed_at = None
    scan.notes = None
    asset_statuses = session.exec(select(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id)).all()
    for status in asset_statuses:
        status.status = "pending"
        status.attempts = 0
        status.last_error = None
        status.started_at = None
        status.completed_at = None
        session.add(status)
    session.add(scan)
    session.commit()
    _record_scan_event(session, scan_id, "Scan re-queued for retry")
    _enqueue_scan_job(scan.id, force=True, session=session)
    return scan


@app.get("/scans/{scan_id}/assets", response_model=List[ScanAssetStatusRead])
def get_scan_asset_status(
    scan_id: int,
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> List[ScanAssetStatusRead]:
    if not session.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    statuses = session.exec(
        select(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id).order_by(ScanAssetStatus.asset_id)
    ).all()
    return [
        ScanAssetStatusRead(
            asset_id=status.asset_id,
            status=status.status,
            attempts=status.attempts,
            last_error=status.last_error,
            started_at=status.started_at,
            completed_at=status.completed_at,
        )
        for status in statuses
    ]


@app.get("/scans/{scan_id}/events", response_model=List[ScanEventRead])
def list_scan_events(
    scan_id: int,
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> List[ScanEventRead]:
    if not session.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    events = session.exec(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc())
    ).all()
    return [
        ScanEventRead(
            id=event.id,
            created_at=event.created_at,
            message=event.message,
            correlation_id=event.correlation_id,
        )
        for event in events
    ]


@app.get("/scans/{scan_id}/events/stream")
def stream_scan_events(
    scan_id: int,
    token: Optional[str] = Query(default=None, description="Access token for SSE clients"),
    authorization: Optional[str] = Header(default=None),
):
    _require_stream_user(token, authorization)
    with get_session() as session:
        if not session.get(Scan, scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")

    async def event_gen():
        last_id: Optional[int] = None
        last_ping: float = 0.0
        last_status_fingerprint: Optional[str] = None
        while True:
            try:
                with get_session() as session:
                    row = session.exec(
                        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc()).limit(1)
                    ).first()
                    if row and row.id != last_id:
                        last_id = row.id
                        payload = {
                            "type": "event",
                            "id": row.id,
                            "created_at": row.created_at.isoformat(),
                            "message": row.message,
                            "correlation_id": row.correlation_id,
                        }
                        yield f"data: {json.dumps(payload)}\n\n"
                    statuses = session.exec(
                        select(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id).order_by(ScanAssetStatus.asset_id)
                    ).all()
                    serialized_status = _serialize_asset_status(statuses)
                    fingerprint = json.dumps(serialized_status, sort_keys=True)
                    if fingerprint != last_status_fingerprint:
                        last_status_fingerprint = fingerprint
                        status_payload = {
                            "type": "asset_status",
                            "assets": serialized_status,
                            "progress": _asset_progress(statuses),
                        }
                        yield f"data: {json.dumps(status_payload)}\n\n"
                    now = asyncio.get_event_loop().time()
                    if now - last_ping >= 10:
                        last_ping = now
                        yield ": keepalive\n\n"
            except HTTPException:
                raise
            except Exception:
                logger.debug("scan_event_stream_error", exc_info=True)
            await asyncio.sleep(2)

    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive"}
    return StreamingResponse(event_gen(), media_type="text/event-stream", headers=headers)


@app.get("/findings", response_model=List[FindingReadWithSource])
def list_findings(
    response: Response,
    scan_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    asset_id: Optional[int] = Query(default=None),
    evidence_grade: Optional[str] = Query(default=None, pattern="^(low|medium|high)$"),
    why_trace: Optional[str] = Query(default=None, pattern="^(present|missing)$"),
    search: Optional[str] = Query(default=None, alias="q"),
    sort: str = Query(default="recent", pattern="^(recent|severity|port|evidence|why)$"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> List[Finding]:
    query, where_sql, params = _build_finding_filters(
        scan_id, severity, status_filter, asset_id, evidence_grade, why_trace, search
    )
    rows, total = _paginate_query(session, query.order_by(*_finding_order_by(sort)), limit, offset)
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-CVSS-Bands"] = json.dumps(_aggregate_cvss_bands(session, where_sql, params))
    serialized: List[FindingReadWithSource] = []
    for row in rows:
        version_confidence, evidence_types = _fingerprint_metadata(row)
        _, computed_grade = _normalize_evidence(row)
        payload = row.model_dump()
        payload["evidence_grade"] = payload.get("evidence_grade") or computed_grade
        serialized.append(
            FindingReadWithSource(
                **payload,
                rule_source=_extract_rule_source(row),
                version_confidence=version_confidence,
                evidence_types=evidence_types,
            )
        )
    return serialized


@app.get("/reports/findings/export")
def export_findings_report(
    response: Response,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    scan_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    asset_id: Optional[int] = Query(default=None),
    evidence_grade: Optional[str] = Query(default=None, pattern="^(low|medium|high)$"),
    why_trace: Optional[str] = Query(default=None, pattern="^(present|missing)$"),
    search: Optional[str] = Query(default=None, alias="q"),
    sort: str = Query(default="recent", pattern="^(recent|severity|port|evidence|why)$"),
    limit: int = Query(default=5000, ge=1, le=20000),
    offset: int = Query(default=0, ge=0),
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> Any:
    fmt = format.lower()
    if fmt not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="Unsupported export format")

    export_rows, total_count, band_summary = _collect_finding_exports(
        session,
        scan_id=scan_id,
        severity=severity,
        status_filter=status_filter,
        asset_id=asset_id,
        evidence_grade=evidence_grade,
        why_trace=why_trace,
        search=search,
        sort=sort,
        limit=limit,
        offset=offset,
    )
    timestamp = isoformat_utc()

    response.headers["X-Total-Count"] = str(total_count)
    response.headers["X-CVSS-Bands"] = json.dumps(band_summary)

    if fmt == "csv":
        output = io.StringIO()
        fieldnames = [
            "id",
            "scan_id",
            "asset_id",
            "assigned_user_id",
            "detected_at",
            "sla_due_at",
            "closed_at",
            "severity",
            "status",
            "service_name",
            "service_version",
            "host_address",
            "port",
            "protocol",
            "description",
            "evidence_summary",
            "evidence_grade",
            "why_trace",
            "evidence",
            "fingerprint",
            "cvss_v31_base",
            "cvss_vector",
            "cvss_band",
            "cve_ids",
            "references",
            "rule_source",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        json_fields = {"evidence", "fingerprint"}
        for row in export_rows:
            normalized = {}
            for key in fieldnames:
                value = row.get(key)
                if key in json_fields and value not in (None, ""):
                    normalized[key] = json.dumps(value)
                elif key == "references":
                    normalized[key] = ";".join(value or [])
                else:
                    normalized[key] = value
            writer.writerow(
                {
                    **{k: normalized.get(k) for k in fieldnames if k != "cve_ids"},
                    "cve_ids": ";".join(row.get("cve_ids") or []),
                }
            )
        filename = f"findings_export_{now_utc().strftime('%Y%m%d_%H%M%S')}.csv"
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Total-Count": str(total_count),
            "X-CVSS-Bands": json.dumps(band_summary),
        }
        return Response(content=output.getvalue(), media_type="text/csv", headers=headers)

    return {
        "generated_at": timestamp,
        "filters": {
            "scan_id": scan_id,
            "severity": severity,
            "status": status_filter,
            "asset_id": asset_id,
            "evidence_grade": evidence_grade,
            "why_trace": why_trace,
            "search": search,
            "sort": sort,
            "limit": limit,
            "offset": offset,
        },
        "total": total_count,
        "returned": len(export_rows),
        "cvss_bands": band_summary,
        "rows": export_rows,
    }


class ReportJobRequest(BaseModel):
    type: str = Field(default="technical", pattern="^(executive|technical|delta)$")
    format: str = Field(default="csv", pattern="^(csv|json|pdf)$")
    scan_id: Optional[int] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    asset_id: Optional[int] = None
    evidence_grade: Optional[str] = Field(default=None, pattern="^(low|medium|high)$")
    why_trace: Optional[str] = Field(default=None, pattern="^(present|missing)$")
    search: Optional[str] = None
    sort: str = Field(default="recent", pattern="^(recent|severity|port|evidence|why)$")
    limit: int = Field(default=5000, ge=1, le=20000)
    offset: int = Field(default=0, ge=0)
    include_deltas: bool = Field(default=False)
    timeframe_from: Optional[datetime] = None
    timeframe_to: Optional[datetime] = None


class ReportJobRead(BaseModel):
    id: int
    type: str
    format: str
    status: str
    total_count: Optional[int]
    created_at: datetime
    completed_at: Optional[datetime]
    download_url: Optional[str] = None
    error: Optional[str] = None


def _delta_summary(rows: List[Dict[str, Any]], timeframe_from: Optional[datetime], timeframe_to: Optional[datetime]) -> Dict[str, Any]:
    if not timeframe_from and not timeframe_to:
        return {"new": 0, "resolved": 0, "reopened": 0, "severity_changes": [], "cvss_changes": []}
    def _parse(dt: Any) -> Optional[datetime]:
        if isinstance(dt, datetime):
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        if isinstance(dt, str):
            with suppress(Exception):
                parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return None
    start = _parse(timeframe_from)
    end = _parse(timeframe_to)
    new_count = 0
    resolved = 0
    for row in rows:
        detected = _parse(row.get("detected_at"))
        closed = _parse(row.get("closed_at"))
        if start and detected and detected >= start and (not end or detected <= end):
            new_count += 1
        if start and closed and closed >= start and (not end or closed <= end):
            resolved += 1
    return {"new": new_count, "resolved": resolved, "reopened": 0, "severity_changes": [], "cvss_changes": []}


def _write_report_file(
    fmt: str,
    report_type: str,
    rows: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> tuple[Path, str]:
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = now_utc().strftime("%Y%m%d_%H%M%S")
    filename = f"{report_type}_report_{timestamp}.{fmt}"
    path = REPORT_OUTPUT_DIR / filename
    if fmt == "csv":
        output = io.StringIO()
        fieldnames = [
            "id",
            "scan_id",
            "asset_id",
            "assigned_user_id",
            "detected_at",
            "sla_due_at",
            "closed_at",
            "severity",
            "status",
            "owner",
            "rule_id",
            "service_name",
            "service_version",
            "host_address",
            "port",
            "protocol",
            "description",
            "evidence_summary",
            "evidence_grade",
            "why_trace",
            "cvss_v31_base",
            "cvss_vector",
            "cvss_band",
            "cve_ids",
            "references",
            "rule_source",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            normalized = dict(row)
            normalized["owner"] = row.get("owner")
            normalized["references"] = ";".join(row.get("references") or [])
            normalized["cve_ids"] = ";".join(row.get("cve_ids") or [])
            writer.writerow({key: normalized.get(key) for key in fieldnames})
        path.write_text(output.getvalue(), encoding="utf-8")
    elif fmt == "json":
        payload = {"generated_at": isoformat_utc(), "summary": summary, "rows": rows}
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    else:  # pdf
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        except Exception as exc:  # pragma: no cover - dependency issues
            path.write_text(f"PDF generation unavailable: {exc}", encoding="utf-8")
            checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            return path, checksum

        doc = SimpleDocTemplate(str(path), pagesize=letter, title=f"{report_type.title()} Report")
        styles = getSampleStyleSheet()
        story = [
            Paragraph(f"{report_type.title()} Report", styles["Title"]),
            Paragraph(f"Generated at: {isoformat_utc()}", styles["Normal"]),
            Spacer(1, 12),
        ]
        cvss_bands = summary.get("cvss_bands", {}) or {}
        band_text = ", ".join(f"{k}: {v}" for k, v in cvss_bands.items()) or "None"
        story.append(Paragraph(f"Total findings: {summary.get('total', 0)}", styles["Heading3"]))
        story.append(Paragraph(f"CVSS distribution: {band_text}", styles["Normal"]))
        delta = summary.get("delta") or {}
        if delta:
            story.append(Paragraph("Delta summary", styles["Heading3"]))
            story.append(
                Paragraph(
                    f"New: {delta.get('new', 0)} | Resolved: {delta.get('resolved', 0)} | Reopened: {delta.get('reopened', 0)}",
                    styles["Normal"],
                )
            )
        story.append(Spacer(1, 12))

        table_data = [
            ["Severity", "Status", "Rule", "Service", "Host", "Summary", "CVSS"],
        ]
        for row in rows[:50]:
            table_data.append(
                [
                    row.get("severity") or "",
                    row.get("status") or "",
                    row.get("rule_id") or "",
                    row.get("service_name") or "",
                    row.get("host_address") or "",
                    row.get("evidence_summary") or row.get("description") or "",
                    row.get("cvss_v31_base") or "",
                ]
            )
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightyellow]),
                ]
            )
        )
        story.append(table)
        doc.build(story)
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, checksum


def _serialize_report_job(job: ReportJob) -> Dict[str, Any]:
    return {
        "id": job.id,
        "type": job.report_type,
        "format": job.format,
        "status": job.status,
        "total_count": job.total_count,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "download_url": f"/reports/{job.id}/download" if job.file_path and job.status == "completed" else None,
        "error": job.error,
    }


def _process_report_job(session: Session, payload: ReportJobRequest) -> ReportJob:
    job = ReportJob(
        kind="findings",
        report_type=payload.type,
        format=payload.format.lower(),
        status="processing",
        scope_json=json.dumps(
            {
                "scan_id": payload.scan_id,
                "severity": payload.severity,
                "status": payload.status,
                "asset_id": payload.asset_id,
                "search": payload.search,
            },
            default=str,
        ),
        include_json=json.dumps({"include_deltas": payload.include_deltas}, default=str),
        timeframe_from=payload.timeframe_from,
        timeframe_to=payload.timeframe_to,
    )
    session.add(job)
    session.flush()

    try:
        rows, total_count, band_summary = _collect_finding_exports(
            session,
            scan_id=payload.scan_id,
            severity=payload.severity,
            status_filter=payload.status,
            asset_id=payload.asset_id,
            evidence_grade=payload.evidence_grade,
            why_trace=payload.why_trace,
            search=payload.search,
            sort=payload.sort,
            limit=payload.limit,
            offset=payload.offset,
        )
        delta = _delta_summary(rows, payload.timeframe_from, payload.timeframe_to) if payload.include_deltas else {}
        summary = {"total": total_count, "cvss_bands": band_summary, "delta": delta}
        path, checksum = _write_report_file(payload.format.lower(), payload.type, rows, summary)
        job.status = "completed"
        job.file_path = str(path)
        job.checksum = checksum
        job.total_count = total_count
        job.completed_at = now_utc()
    except Exception as exc:  # pragma: no cover - defensive
        job.status = "failed"
        job.error = str(exc)
    session.add(job)
    session.flush()
    session.refresh(job)
    return job


@app.post("/reports", response_model=ReportJobRead, status_code=201)
def create_report_job(
    payload: ReportJobRequest,
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> Dict[str, Any]:
    job = _process_report_job(session, payload)
    return ReportJobRead(**_serialize_report_job(job))


@app.get("/reports/{job_id}", response_model=ReportJobRead)
def get_report_job(
    job_id: int,
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> Dict[str, Any]:
    job = session.get(ReportJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Report job not found")
    return ReportJobRead(**_serialize_report_job(job))


@app.get("/reports/{job_id}/download")
def download_report_job(
    job_id: int,
    _: object = Depends(require_roles("viewer", "operator", "admin")),
    session: Session = Depends(session_dep),
) -> Response:
    job = session.get(ReportJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Report job not found")
    if job.status != "completed" or not job.file_path:
        raise HTTPException(status_code=400, detail="Report is not ready")
    path = Path(job.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")
    media_type = "application/json"
    if job.format == "csv":
        media_type = "text/csv"
    elif job.format == "pdf":
        media_type = "application/pdf"
    headers = {"Content-Disposition": f'attachment; filename="{path.name}"'}
    return StreamingResponse(path.open("rb"), media_type=media_type, headers=headers)

@app.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: int, payload: FindingUpdate, session: Session = Depends(session_dep)) -> Finding:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    update_data = payload.model_dump(exclude_unset=True)
    if "status" in update_data:
        status_val = update_data["status"]
        if status_val is not None and status_val not in VALID_FINDING_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {', '.join(sorted(VALID_FINDING_STATUSES))}")
        if status_val in {"resolved", "ignored"}:
            update_data.setdefault("closed_at", now_utc())
        elif status_val == "open":
            update_data["closed_at"] = None
    assignee_id = update_data.get("assigned_user_id")
    if assignee_id is not None:
        assignee = session.get(User, assignee_id)
        if not assignee:
            raise HTTPException(status_code=400, detail="Assignee not found")
    for field, value in update_data.items():
        setattr(finding, field, value)
    session.add(finding)
    session.flush()
    session.refresh(finding)
    session.add(
        AuditLog(
            actor_user_id=None,
            action="finding_updated",
            target=str(finding.id),
            ip=None,
            detail=json.dumps(update_data),
        )
    )
    return finding


class FindingCommentCreate(BaseModel):
    message: str


@app.get("/findings/{finding_id}/comments", response_model=List[FindingCommentRead])
def list_finding_comments(finding_id: int, session: Session = Depends(session_dep)) -> List[FindingComment]:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    rows = session.exec(
        select(FindingComment).where(FindingComment.finding_id == finding_id).order_by(FindingComment.created_at.desc())
    ).all()
    return rows


@app.post("/findings/{finding_id}/comments", response_model=FindingCommentRead, status_code=201)
def add_finding_comment(
    finding_id: int,
    payload: FindingCommentCreate,
    current=Depends(require_roles("admin", "operator")),
    session: Session = Depends(session_dep),
) -> FindingComment:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="Message is required")
    comment = FindingComment(finding_id=finding_id, user_id=current.user.id, message=payload.message.strip())
    session.add(comment)
    session.flush()
    session.refresh(comment)
    session.add(
        AuditLog(
            actor_user_id=current.user.id,
            action="finding_commented",
            target=str(finding_id),
            ip=None,
            detail=payload.message[:240],
        )
    )
    return comment


def render_legacy_ui(request: Request, session: Session) -> HTMLResponse:
    scans = session.exec(select(Scan).order_by(Scan.created_at.desc()).limit(10)).all()
    findings = session.exec(select(Finding).order_by(Finding.detected_at.desc()).limit(10)).all()
    assets = session.exec(select(Asset).order_by(Asset.created_at.desc()).limit(10)).all()
    events = session.exec(select(ScanEvent).order_by(ScanEvent.created_at.desc()).limit(6)).all()
    status_rows = session.exec(
        select(ScanAssetStatus, Asset.target)
        .join(Asset, Asset.id == ScanAssetStatus.asset_id, isouter=True)
        .order_by(ScanAssetStatus.completed_at.desc())
        .limit(12)
    ).all()
    statuses = [
        {
            "scan_id": status.scan_id,
            "asset_id": status.asset_id,
            "status": status.status,
            "attempts": status.attempts,
            "started_at": status.started_at,
            "completed_at": status.completed_at,
            "last_error": status.last_error,
            "target": target_value,
        }
        for status, target_value in status_rows
    ]
    status_rows = session.exec(
        select(Scan.status, func.count()).group_by(Scan.status)
    ).all()
    status_summary = {status: count for status, count in status_rows}
    finding_severity = session.exec(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ).all()
    finding_severity_summary = {severity: count for severity, count in finding_severity}
    asset_count = len(assets)
    scan_count = len(scans)
    finding_count = len(findings)
    open_findings = sum(1 for finding in findings if finding.status.lower() == "open")
    summaries: List[str] = []
    scan_ids = [scan.id for scan in scans]
    if scan_ids:
        findings_per_scan: Dict[int, Dict[int, List[Finding]]] = {scan_id: {} for scan_id in scan_ids}
        findings = session.exec(
            select(Finding)
            .where(Finding.scan_id.in_(scan_ids))
            .options(selectinload(Finding.asset))
            .order_by(Finding.scan_id, Finding.asset_id, Finding.port)
        ).all()
        for finding in findings:
            if finding.scan_id not in findings_per_scan:
                findings_per_scan[finding.scan_id] = {}
            asset_map = findings_per_scan[finding.scan_id]
            asset_map.setdefault(finding.asset_id or 0, []).append(finding)

        for scan in scans[:5]:
            asset_map = findings_per_scan.get(scan.id, {})
            if not asset_map:
                continue
            lines = [
                f"Scan #{scan.id} ({scan.profile})",
                f"Started: {scan.started_at or '-'}  Completed: {scan.completed_at or '-'}",
            ]
            for asset_id, scan_findings in asset_map.items():
                asset = scan_findings[0].asset
                target_label = asset.target if asset else f"Asset {asset_id}"
                lines.append(f"Nmap scan report for {target_label}")
                open_ports = [
                    f"{finding.port}/{finding.protocol or 'tcp'} {finding.service_name or finding.rule_id or 'unknown'}"
                    for finding in scan_findings
                    if finding.port
                ]
                if open_ports:
                    lines.append("Open ports:")
                    for port_line in open_ports:
                        lines.append(f"  - {port_line}")
                else:
                    lines.append("No open ports recorded.")
                lines.append("")
            summaries.append("\n".join(lines).strip())
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "scans": scans,
            "findings": findings,
            "assets": assets,
            "events": events,
            "asset_statuses": statuses,
            "scan_profiles": SCAN_PROFILE_CHOICES,
            "default_profile": DEFAULT_PROFILE_KEY,
            "scan_status_summary": status_summary,
            "finding_severity_summary": finding_severity_summary,
            "asset_count": asset_count,
            "scan_count": scan_count,
            "finding_count": finding_count,
            "open_findings": open_findings,
            "scan_summaries": summaries,
        },
    )


if FRONTEND_DIST.exists():

    @app.get("/legacy", response_class=HTMLResponse)
    def legacy_home(request: Request, session: Session = Depends(session_dep)) -> HTMLResponse:
        return render_legacy_ui(request, session)
else:

    @app.get("/", response_class=HTMLResponse)
    def ui_home(request: Request, session: Session = Depends(session_dep)) -> HTMLResponse:
        return render_legacy_ui(request, session)


def run_ssh_scan_job(ssh_scan_id: int) -> None:
    from clanker.db.session import get_session as session_factory

    metrics.record_scan_started("ssh")
    started = time.perf_counter()
    metrics_status = "failed"
    try:
        with session_factory() as session:
            scan = session.get(SSHScan, ssh_scan_id)
            if not scan:
                logger.error("SSH scan %s missing", ssh_scan_id)
                metrics_status = "failed"
                return
            scan.status = "running"
            scan.started_at = now_utc()
            session.add(scan)
            session.commit()
            log_event(
                logger,
                "ssh_scan_started",
                ssh_scan_id=ssh_scan_id,
                host_count=session.exec(
                    select(func.count()).select_from(SSHScanHost).where(SSHScanHost.ssh_scan_id == ssh_scan_id)
                ).one(),
            )

        with session_factory() as session:
            scan = session.get(SSHScan, ssh_scan_id)
            hosts = session.exec(
                select(SSHScanHost).where(SSHScanHost.ssh_scan_id == ssh_scan_id).order_by(SSHScanHost.id)
            ).all()
            if not hosts:
                scan.status = "failed"
                scan.notes = "No SSH hosts to scan"
                scan.completed_at = now_utc()
                session.add(scan)
                session.commit()
                _pop_ssh_retry(ssh_scan_id)
                metrics_status = "failed"
                return

            scanner = SSHScanner(
                port=scan.port,
                timeout=_clamp_int(scan.timeout, 10, 1, SSH_TIMEOUT_LIMIT),
                command_timeout=_clamp_int(scan.command_timeout, 30, 5, SSH_COMMAND_TIMEOUT_LIMIT),
                max_workers=_clamp_int(scan.max_workers, 4, 1, SSH_MAX_WORKERS_LIMIT),
                max_retries=_clamp_int(_pop_ssh_retry(ssh_scan_id), 1, 0, SSH_RETRY_LIMIT),
                verbose=False,
            )
            host_payloads: List[Dict[str, Any]] = []
            for host_row in hosts:
                creds = _pop_ssh_credentials(host_row.id or 0) or {}
                if not (
                    creds.get("password")
                    or creds.get("key_path")
                    or creds.get("allow_agent")
                    or creds.get("look_for_keys")
                ):
                    host_row.status = "failed"
                    host_row.error = "Credentials missing for host"
                    host_row.completed_at = now_utc()
                    session.add(host_row)
                    continue
                host_row.status = "running"
                host_row.started_at = now_utc()
                session.add(host_row)
                log_event(
                    logger,
                    "ssh_host_started",
                    ssh_scan_id=ssh_scan_id,
                    host_id=host_row.id,
                    host=host_row.host,
                    port=host_row.port,
                )
                host_payloads.append(
                    {
                        "host": host_row.host,
                        "port": host_row.port,
                        "username": creds.get("username") or host_row.username,
                        "password": creds.get("password"),
                        "key_path": creds.get("key_path"),
                        "passphrase": creds.get("passphrase"),
                        "allow_agent": creds.get("allow_agent"),
                        "look_for_keys": creds.get("look_for_keys"),
                        "sudo": creds.get("sudo") if creds.get("sudo") is not None else host_row.use_sudo,
                        "sudo_path": creds.get("sudo_path") or host_row.sudo_path,
                        "host_id": host_row.id,
                    }
                )
            session.commit()

        if not host_payloads:
            with session_factory() as session:
                scan = session.get(SSHScan, ssh_scan_id)
                if scan:
                    scan.status = "failed"
                    scan.notes = "No hosts with valid credentials to scan"
                    scan.completed_at = now_utc()
                    session.add(scan)
                    session.commit()
            _pop_ssh_retry(ssh_scan_id)
            metrics_status = "failed"
            return

        results = scanner.scan_all(host_payloads)
        result_map: Dict[Optional[int], Dict[str, Any]] = {res.get("host_id"): res for res in results}

        with session_factory() as session:
            scan = session.get(SSHScan, ssh_scan_id)
            hosts = session.exec(
                select(SSHScanHost).where(SSHScanHost.ssh_scan_id == ssh_scan_id).order_by(SSHScanHost.id)
            ).all()
            errors = False
            for host_row in hosts:
                res = result_map.get(host_row.id) or {}
                host_row.error = host_row.error or res.get("error")
                host_row.status = "success" if res.get("status") == "success" else "failed"
                host_row.completed_at = now_utc()
                host_row.latency_ms = res.get("latency_ms")
                if res:
                    host_row.raw_output = json.dumps(res)
                    host_row.ssh_config_hardening = json.dumps(res.get("ssh_config_hardening") or {})
                    host_row.facts = json.dumps(SSHScanner.extract_basic_facts(res))
                session.add(host_row)
                if host_row.status != "success":
                    errors = True
                else:
                    try:
                        inventory = SSHScanner.to_agent_inventory(res)
                        inventory_model = AgentInventory.model_validate(inventory)
                        ingest = _persist_agent_ingest(
                            session,
                            inventory_model,
                            asset_id=host_row.asset_id,
                            agent_id=f"ssh-scan-{ssh_scan_id}-{host_row.id}",
                            agent_version="ssh_scanner",
                            raw_payload=json.dumps(
                                {
                                    "ssh_scan_id": ssh_scan_id,
                                    "ssh_scan_host_id": host_row.id,
                                    "inventory": inventory_model.model_dump(),
                                }
                            ),
                        )
                        persist_agent_findings(session, inventory_model, asset_id=host_row.asset_id, ingest_id=ingest.id)
                    except Exception as exc:  # do not fail scan if vuln ingestion fails
                        errors = True
                        logger.exception("Failed to persist findings for SSH host %s: %s", host_row.host, exc)
                log_event(
                    logger,
                    "ssh_host_completed",
                    ssh_scan_id=ssh_scan_id,
                    host_id=host_row.id,
                    host=host_row.host,
                    status=host_row.status,
                    error=host_row.error,
                )

            scan.completed_at = now_utc()
            scan.status = "completed_with_errors" if errors else "completed"
            metrics_status = scan.status
            session.add(scan)
            session.add(
                AuditLog(
                    actor_user_id=scan.created_by_user_id,
                    action="ssh_scan_complete",
                    target=str(ssh_scan_id),
                    ip=None,
                    detail=f"SSH scan {ssh_scan_id} finished with status {scan.status}",
                )
            )
            session.commit()
            log_event(
                logger,
                "ssh_scan_completed",
                ssh_scan_id=ssh_scan_id,
                status=scan.status,
                host_count=len(hosts),
                errors=int(errors),
            )
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("SSH scan %s crashed unexpectedly: %s", ssh_scan_id, exc)
        with session_factory() as session:
            scan = session.get(SSHScan, ssh_scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = scan.completed_at or now_utc()
                scan.notes = scan.notes or f"SSH scan worker error: {exc}"
                session.add(scan)
                session.commit()
        _pop_ssh_retry(ssh_scan_id)
        metrics_status = "failed"
    finally:
        metrics.record_scan_finished("ssh", metrics_status, time.perf_counter() - started)


def run_scan_job(scan_id: int) -> None:
    from clanker.db.session import get_session as session_factory

    metrics.record_scan_started("network")
    started = time.perf_counter()
    metrics_status = "failed"
    _update_scan_job_status(scan_id, "running")
    try:
        with session_factory() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                logger.error("Scan %s vanished before start", scan_id)
                _update_scan_job_status(scan_id, "failed", error="Scan record missing")
                metrics_status = "failed"
                return
            corr_id = scan.correlation_id
            if scan.status == "cancelled":
                _record_scan_event(session, scan_id, "Scan cancelled before start")
                _update_scan_job_status(scan_id, "cancelled")
                metrics_status = "cancelled"
                return
            scan.status = "running"
            scan.started_at = now_utc()
            session.add(scan)
            _record_scan_event(session, scan_id, "Scan started")
            session.commit()
            log_event(
                logger,
                "scan_job_started",
                scan_id=scan_id,
                profile=scan.profile,
                created_by=scan.created_by_user_id,
                correlation_id=corr_id,
            )

        with session_factory() as session:
            scan = session.get(Scan, scan_id)
            corr_id = scan.correlation_id if scan else None
            asset_links = session.exec(
                select(Asset)
                .join(ScanTarget, ScanTarget.asset_id == Asset.id)
                .where(ScanTarget.scan_id == scan_id)
            ).all()

            if not asset_links:
                scan.status = "failed"
                scan.notes = "No assets were linked to the scan"
                _record_scan_event(session, scan_id, "No assets to scan")
                session.add(scan)
                session.commit()
                _update_scan_job_status(scan_id, "failed", error="No assets linked to scan")
                metrics_status = "failed"
                return

            profile = get_scan_profile(scan.profile)
            asset_errors = False
            for asset in asset_links:
                session.refresh(scan)
                if scan.status == "cancelled":
                    _record_scan_event(session, scan_id, "Scan cancelled while running")
                    scan.completed_at = scan.completed_at or now_utc()
                    session.add(scan)
                    session.commit()
                    _update_scan_job_status(scan_id, "cancelled")
                    metrics_status = "cancelled"
                    return
                retrying = True
                while retrying:
                    status_row = _ensure_asset_status(session, scan_id, asset.id or 0)
                    status_row.status = "running"
                    status_row.started_at = status_row.started_at or now_utc()
                    status_row.attempts += 1
                    session.add(status_row)
                    session.commit()
                    _record_scan_event(
                        session, scan_id, f"Scanning {asset.target} (attempt {status_row.attempts})"
                    )
                    log_event(
                        logger,
                        "scan_asset_started",
                        scan_id=scan_id,
                        asset_id=asset.id,
                        target=asset.target,
                        attempt=status_row.attempts,
                        profile=scan.profile,
                        correlation_id=corr_id,
                    )

                    if _is_scan_cancelled(session, scan_id):
                        status_row.status = "cancelled"
                        status_row.completed_at = status_row.completed_at or now_utc()
                        session.add(status_row)
                        session.commit()
                        _record_scan_event(session, scan_id, "Scan cancelled mid-run")
                        metrics_status = "cancelled"
                        return

                    try:
                        xml_path = execute_nmap(asset, profile)
                        observations = parse_nmap_xml(xml_path, asset)
                        observation_map: Dict[int, Any] = {}
                        findings = build_findings(
                            session,
                            scan_id=scan_id,
                            asset_id=asset.id or 0,
                            observations=observations,
                            observation_map=observation_map,
                        )
                        session.commit()
                        try:
                            enrich_from_feed(session, findings, observations=observation_map)
                            session.commit()
                        except Exception as exc:  # pylint: disable=broad-except
                            session.rollback()
                            logger.exception("Enrichment failed for scan %s asset %s: %s", scan_id, asset.target, exc)
                        try:
                            enum_statuses = run_enum_tools(asset, observations, scan_id)
                            for enum_status in enum_statuses:
                                _record_scan_event(session, scan_id, f"[enum] {enum_status}")
                            session.commit()
                        except Exception as exc:  # pylint: disable=broad-except
                            session.rollback()
                            logger.exception("External enumeration failed for scan %s asset %s: %s", scan_id, asset.target, exc)
                            _record_scan_event(session, scan_id, f"[enum] failed for {asset.target}: {exc}")
                            session.commit()
                        status_row.status = "completed"
                        status_row.completed_at = now_utc()
                        status_row.last_error = None
                        session.add(status_row)
                        session.commit()
                        log_event(
                            logger,
                            "scan_asset_completed",
                            scan_id=scan_id,
                            asset_id=asset.id,
                            target=asset.target,
                            observations=len(observations),
                            correlation_id=corr_id,
                        )
                        _record_scan_event(
                            session, scan_id, f"Finished {asset.target} with {len(observations)} open services"
                        )
                        retrying = False
                    except FileNotFoundError:
                        scan.status = "failed"
                        scan.notes = "nmap binary not found on host"
                        status_row.status = "failed"
                        status_row.last_error = "nmap missing"
                        status_row.completed_at = now_utc()
                        session.add_all([scan, status_row])
                        session.commit()
                        _record_scan_event(session, scan_id, "nmap binary missing. Aborting scan.")
                        _update_scan_job_status(scan_id, "failed", error="nmap binary not found")
                        return
                    except Exception as exc:  # pylint: disable=broad-except
                        logger.exception("Scan %s failed for asset %s: %s", scan_id, asset.target, exc)
                        status_row.status = "failed"
                        status_row.last_error = str(exc)
                        status_row.completed_at = now_utc()
                        session.add(status_row)
                        session.commit()
                        _record_scan_event(session, scan_id, f"Failed {asset.target}: {exc}")
                        log_event(
                            logger,
                            "scan_asset_failed",
                            scan_id=scan_id,
                            asset_id=asset.id,
                            target=asset.target,
                            attempt=status_row.attempts,
                            error=str(exc),
                            correlation_id=corr_id,
                        )
                        if status_row.attempts <= settings.scan_retry_limit:
                            scan.retry_count += 1
                            session.add(scan)
                            session.commit()
                            status_row.status = "pending"
                            session.add(status_row)
                            session.commit()
                            _record_scan_event(
                                session, scan_id, f"Retrying {asset.target} (attempt {status_row.attempts + 1})"
                            )
                            continue
                        asset_errors = True
                        retrying = False
                        break

            scan.completed_at = now_utc()
            if asset_errors:
                scan.status = "completed_with_errors"
                scan.notes = "One or more assets failed to scan"
            else:
                scan.status = "completed"
                scan.notes = None
            metrics_status = scan.status
            session.add(scan)
            _record_scan_event(session, scan_id, f"Scan finished with status {scan.status}")
            log_event(
                logger,
                "scan_summary",
                scan_id=scan_id,
                status=scan.status,
                asset_count=len(asset_links),
                asset_errors=asset_errors,
                correlation_id=corr_id,
            )
            session.commit()
            _update_scan_job_status(scan_id, scan.status)
            _schedule_reenrich_scan(scan_id)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Scan %s crashed unexpectedly: %s", scan_id, exc)
        with session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = scan.completed_at or now_utc()
                scan.notes = scan.notes or f"Scan crashed: {exc}"
                session.add(scan)
                try:
                    _record_scan_event(session, scan_id, f"Scan worker error: {exc}")
                except Exception:
                    session.commit()
        _update_scan_job_status(scan_id, "failed", error=str(exc))
        metrics_status = "failed"
    finally:
        metrics.record_scan_finished("network", metrics_status, time.perf_counter() - started)


@app.post("/enrichment/finding/{finding_id}")
def enrich_one(
    finding_id: int,
    background_tasks: BackgroundTasks,
    force_refresh_cache: bool = Query(default=False),
) -> dict:
    def _task(fid: int, force_refresh: bool):
        with get_session() as s2:
            row = s2.get(Finding, fid)
            if row:
                obs_index = _build_observation_index([row])
                enrich_from_feed(s2, [row], observations=obs_index, force_refresh_cache=force_refresh)
                s2.commit()

    background_tasks.add_task(_task, finding_id, force_refresh_cache)
    return {"status": "queued", "finding_id": finding_id, "force_refresh": force_refresh_cache}


@app.post("/enrichment/scan/{scan_id}")
def enrich_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    force_refresh_cache: bool = Query(default=False),
    session: Session = Depends(session_dep),
) -> dict:
    if not session.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    background_tasks.add_task(_reenrich_scan, scan_id, force_refresh_cache)
    return {"status": "queued", "scan_id": scan_id, "force_refresh": force_refresh_cache}


@app.post("/enrichment/rebuild_all")
def enrich_all_findings(
    background_tasks: BackgroundTasks, force_refresh_cache: bool = Query(default=False)
) -> dict:
    background_tasks.add_task(_reenrich_all_findings, force_refresh_cache)
    return {"status": "queued", "scope": "all_findings", "force_refresh": force_refresh_cache}


@app.post("/enrichment/sync")
def sync_enrichment_cache(background_tasks: BackgroundTasks, force_refresh: bool = Query(default=False)) -> dict:
    background_tasks.add_task(sync_nvd_cache, force_refresh)
    return {"status": "queued", "force_refresh": force_refresh}


@app.get("/finding_ext/{finding_id}")
def get_finding_ext(finding_id: int, session: Session = Depends(session_dep)) -> JSONResponse:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    base = {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "host_address": finding.host_address,
        "host_os_name": finding.host_os_name,
        "host_os_accuracy": finding.host_os_accuracy,
        "host_vendor": finding.host_vendor,
        "traceroute_summary": finding.traceroute_summary,
        "host_report": finding.host_report,
        "port": finding.port,
        "protocol": finding.protocol,
        "service_name": finding.service_name,
        "service_version": finding.service_version,
        "fingerprint": finding.fingerprint,
        "evidence": finding.evidence,
        "evidence_summary": finding.evidence_summary,
        "cve_ids": finding.cve_ids,
        "severity": finding.severity,
        "status": finding.status,
        "description": finding.description,
        "detected_at": finding.detected_at.isoformat() if getattr(finding, "detected_at", None) else None,
    }
    ext = session.exec(text("SELECT * FROM finding_enrichment WHERE finding_id = :fid"), {"fid": finding_id}).mappings().first() or {}
    if ext and isinstance(ext.get("references_json"), str):
        try:
            ext["references"] = json.loads(ext["references_json"])
        except Exception:
            ext["references"] = []
    elif ext and ext.get("references_json") is None:
        ext["references"] = []
    if ext:
        ext.setdefault("references", [])
    return JSONResponse({"finding": base, "enrichment": ext})


__all__ = ["app"]
