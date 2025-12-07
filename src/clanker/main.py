from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import bindparam, text
from sqlalchemy.orm import selectinload
from sqlmodel import Session, func, select

from clanker.config import settings
from clanker.core.enrichment import enrich_from_feed
from clanker.core.findings import build_findings
from clanker.core.scanner import (
    DEFAULT_PROFILE_KEY,
    execute_nmap,
    get_scan_profile,
    list_scan_profiles,
    parse_nmap_xml,
)
from clanker.db.models import (
    Asset,
    AssetCreate,
    AssetRead,
    AssetUpdate,
    Finding,
    FindingRead,
    FindingUpdate,
    Scan,
    ScanAssetStatus,
    ScanAssetStatusRead,
    ScanCreate,
    ScanDetail,
    ScanEvent,
    ScanEventRead,
    ScanRead,
    ScanTarget,
    User,
    SessionToken,
    UserRead,
    LoginAttempt,
    AuditLog,
    InviteToken,
)
from clanker.db.session import get_session, init_db

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Clanker Vulnerability Scanner", version="0.2.0")
SCAN_PROFILE_CHOICES = list_scan_profiles()
SCAN_PROFILE_KEYS = {profile.key for profile in SCAN_PROFILE_CHOICES}
BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
templates = Jinja2Templates(directory="templates")
if FRONTEND_DIST.exists():
    app.mount("/app", StaticFiles(directory=FRONTEND_DIST, html=True), name="react-app")

    @app.get("/", include_in_schema=False)
    def root_react() -> RedirectResponse:
        return RedirectResponse(url="/app/")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


# Dependency

def session_dep() -> Session:
    with get_session() as session:
        yield session


def _paginate_query(session: Session, query, limit: int, offset: int) -> tuple[list[Any], int]:
    total = session.exec(select(func.count()).select_from(query.subquery())).one()
    rows = session.exec(query.limit(limit).offset(offset)).all()
    return rows, int(total or 0)


def _build_finding_filters(
    scan_id: Optional[int],
    severity: Optional[str],
    status_filter: Optional[str],
    asset_id: Optional[int],
    search: Optional[str],
):
    query = select(Finding)
    clauses = []
    params: Dict[str, Any] = {}

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
    if search:
        pattern = f"%{search.lower()}%"
        query = query.where(
            func.lower(Finding.service_name).like(pattern)
            | func.lower(Finding.host_address).like(pattern)
            | func.lower(Finding.description).like(pattern)
        )
        clauses.append(
            "(lower(f.service_name) LIKE :q OR lower(f.host_address) LIKE :q OR lower(f.description) LIKE :q)"
        )
        params["q"] = pattern

    where_sql = " AND ".join(clauses) if clauses else "1=1"
    return query, where_sql, params


def _load_enrichment(session: Session, finding_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    if not finding_ids:
        return {}
    stmt = (
        text(
            "SELECT finding_id, cvss_v31_base, cvss_vector, references_json "
            "FROM finding_enrichment WHERE finding_id IN :ids"
        ).bindparams(bindparam("ids", expanding=True))
    )
    enrichment: Dict[int, Dict[str, Any]] = {}
    try:
        for row in session.exec(stmt, {"ids": finding_ids}).all():
            data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
            fid = int(data.get("finding_id"))
            enrichment[fid] = {
                "cvss_v31_base": data.get("cvss_v31_base"),
                "cvss_vector": data.get("cvss_vector"),
                "references_json": data.get("references_json"),
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


def _serialize_finding_export(finding: Finding, enrichment: Dict[str, Any]) -> Dict[str, Any]:
    score = enrichment.get("cvss_v31_base")
    cves = _parse_cve_ids(finding.cve_ids)
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
        "severity": finding.severity,
        "status": finding.status,
        "service_name": finding.service_name,
        "service_version": finding.service_version,
        "host_address": finding.host_address,
        "port": finding.port,
        "protocol": finding.protocol,
        "description": finding.description,
        "cve_ids": cves,
        "cvss_v31_base": score,
        "cvss_vector": enrichment.get("cvss_vector"),
        "cvss_band": _cvss_band(score if isinstance(score, (float, int)) else None),
    }


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
    except Exception:
        return summary
    return summary


def _record_scan_event(session: Session, scan_id: int, message: str) -> None:
    session.add(ScanEvent(scan_id=scan_id, message=message))
    session.commit()


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


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


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


class AuditLogRead(BaseModel):
    id: int
    created_at: str
    actor_user_id: Optional[int]
    action: str
    target: Optional[str]
    ip: Optional[str]
    detail: Optional[str]


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else ""


@app.post("/auth/login", response_model=TokenPair)
def login(payload: LoginRequest, request: Request, session: Session = Depends(session_dep)) -> TokenPair:
    since = now_utc() - timedelta(seconds=WINDOW_SECONDS)
    ip = _client_ip(request)
    fail_count = session.exec(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.email == payload.email, LoginAttempt.success == False, LoginAttempt.created_at >= since  # noqa: E712
        )
    ).one()
    ip_fail_count = session.exec(
        select(func.count()).select_from(LoginAttempt).where(
            LoginAttempt.ip == ip, LoginAttempt.success == False, LoginAttempt.created_at >= since  # noqa: E712
        )
    ).one()
    if int(fail_count or 0) >= MAX_ATTEMPTS or int(ip_fail_count or 0) >= MAX_IP_ATTEMPTS:
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(AuditLog(actor_user_id=None, action="login_throttled", target=payload.email, ip=ip, detail=None))
        session.flush()
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

    user = session.exec(select(User).where(User.email == payload.email)).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        session.add(LoginAttempt(email=payload.email, ip=ip, success=False))
        session.add(AuditLog(actor_user_id=None, action="login_failure", target=payload.email, ip=ip, detail=None))
        session.flush()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.active:
        raise HTTPException(status_code=403, detail="User disabled")

    session.add(LoginAttempt(email=payload.email, ip=ip, success=True))
    session.add(AuditLog(actor_user_id=user.id, action="login_success", target=payload.email, ip=ip, detail=None))

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
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing:
        return
    user = User(email=email, name="Administrator", hashed_password=hash_password(password), role="admin", active=True)
    session.add(user)


@app.on_event("startup")
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

    scan = Scan(profile=profile_key, status="queued")
    session.add(scan)
    session.flush()

    for asset in assets:
        session.add(ScanTarget(scan_id=scan.id, asset_id=asset.id))
        _ensure_asset_status(session, scan.id, asset.id)

    session.commit()
    background_tasks.add_task(run_scan_job, scan.id)
    return scan


@app.get("/scans", response_model=List[ScanRead])
def list_scans(
    response: Response,
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(session_dep),
) -> List[Scan]:
    query = select(Scan)
    if status:
        query = query.where(Scan.status == status)
    rows, total = _paginate_query(session, query.order_by(Scan.created_at.desc()), limit, offset)
    response.headers["X-Total-Count"] = str(total)
    return rows


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, session: Session = Depends(session_dep)) -> Response:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    for finding in session.exec(select(Finding).where(Finding.scan_id == scan_id)).all():
        session.delete(finding)
    for status in session.exec(select(ScanAssetStatus).where(ScanAssetStatus.scan_id == scan_id)).all():
        session.delete(status)
    for event in session.exec(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).all():
        session.delete(event)
    for link in session.exec(select(ScanTarget).where(ScanTarget.scan_id == scan_id)).all():
        session.delete(link)

    session.delete(scan)
    session.commit()
    return Response(status_code=204)


@app.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, session: Session = Depends(session_dep)) -> ScanDetail:
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
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        asset_count=asset_count or 0,
        severity_summary=severity_summary,
        recent_events=[entry[0] for entry in recent_events],
    )


@app.get("/scans/{scan_id}/assets", response_model=List[ScanAssetStatusRead])
def get_scan_asset_status(scan_id: int, session: Session = Depends(session_dep)) -> List[ScanAssetStatusRead]:
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
def list_scan_events(scan_id: int, session: Session = Depends(session_dep)) -> List[ScanEventRead]:
    if not session.get(Scan, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    events = session.exec(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc())
    ).all()
    return [ScanEventRead(id=event.id, created_at=event.created_at, message=event.message) for event in events]


@app.get("/scans/{scan_id}/events/stream")
def stream_scan_events(scan_id: int):
    async def event_gen():
        last_id: Optional[int] = None
        while True:
            try:
                with get_session() as session:
                    row = session.exec(
                        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc()).limit(1)
                    ).first()
                    if row and row.id != last_id:
                        last_id = row.id
                        payload = {"id": row.id, "created_at": row.created_at.isoformat(), "message": row.message}
                        yield f"data: {json.dumps(payload)}\n\n"
            except Exception:
                # Keep stream alive on transient errors
                pass
            await asyncio.sleep(2)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/findings", response_model=List[FindingRead])
def list_findings(
    response: Response,
    scan_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    asset_id: Optional[int] = Query(default=None),
    search: Optional[str] = Query(default=None, alias="q"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(session_dep),
) -> List[Finding]:
    query, _, _ = _build_finding_filters(scan_id, severity, status_filter, asset_id, search)
    rows, total = _paginate_query(session, query.order_by(Finding.detected_at.desc()), limit, offset)
    response.headers["X-Total-Count"] = str(total)
    return rows


@app.get("/reports/findings/export")
def export_findings_report(
    response: Response,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    scan_id: Optional[int] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    asset_id: Optional[int] = Query(default=None),
    search: Optional[str] = Query(default=None, alias="q"),
    limit: int = Query(default=5000, ge=1, le=20000),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(session_dep),
) -> Any:
    fmt = format.lower()
    if fmt not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="Unsupported export format")

    base_query, where_sql, params = _build_finding_filters(scan_id, severity, status_filter, asset_id, search)
    total = session.exec(select(func.count()).select_from(base_query.subquery())).one()
    total_count = int(total or 0)
    rows = session.exec(
        base_query.order_by(Finding.detected_at.desc()).limit(limit).offset(offset)
    ).all()
    enrichment = _load_enrichment(session, [r.id for r in rows if r.id is not None])
    export_rows = [_serialize_finding_export(f, enrichment.get(f.id or -1, {})) for f in rows]
    band_summary = _aggregate_cvss_bands(session, where_sql, params)
    timestamp = datetime.utcnow().isoformat() + "Z"

    response.headers["X-Total-Count"] = str(total_count)
    response.headers["X-CVSS-Bands"] = json.dumps(band_summary)

    if fmt == "csv":
        output = io.StringIO()
        fieldnames = [
            "id",
            "scan_id",
            "asset_id",
            "detected_at",
            "severity",
            "status",
            "service_name",
            "service_version",
            "host_address",
            "port",
            "protocol",
            "description",
            "cvss_v31_base",
            "cvss_vector",
            "cvss_band",
            "cve_ids",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in export_rows:
            writer.writerow(
                {
                    **{k: row.get(k) for k in fieldnames if k != "cve_ids"},
                    "cve_ids": ";".join(row.get("cve_ids") or []),
                }
            )
        filename = f"findings_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
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
            "search": search,
            "limit": limit,
            "offset": offset,
        },
        "total": total_count,
        "returned": len(export_rows),
        "cvss_bands": band_summary,
        "rows": export_rows,
    }


@app.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: int, payload: FindingUpdate, session: Session = Depends(session_dep)) -> Finding:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(finding, field, value)
    session.add(finding)
    session.flush()
    session.refresh(finding)
    return finding


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


def run_scan_job(scan_id: int) -> None:
    from clanker.db.session import get_session as session_factory

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            logger.error("Scan %s vanished before start", scan_id)
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        session.add(scan)
        _record_scan_event(session, scan_id, "Scan started")
        session.commit()

    with session_factory() as session:
        scan = session.get(Scan, scan_id)
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
            return

        profile = get_scan_profile(scan.profile)
        asset_errors = False
        for asset in asset_links:
            retrying = True
            while retrying:
                status_row = _ensure_asset_status(session, scan_id, asset.id or 0)
                status_row.status = "running"
                status_row.started_at = status_row.started_at or datetime.utcnow()
                status_row.attempts += 1
                session.add(status_row)
                session.commit()
                _record_scan_event(
                    session, scan_id, f"Scanning {asset.target} (attempt {status_row.attempts})"
                )

                try:
                    xml_path = execute_nmap(asset, profile)
                    observations = parse_nmap_xml(xml_path, asset)
                    build_findings(session, scan_id=scan_id, asset_id=asset.id or 0, observations=observations)
                    status_row.status = "completed"
                    status_row.completed_at = datetime.utcnow()
                    status_row.last_error = None
                    session.add(status_row)
                    session.commit()
                    _record_scan_event(
                        session, scan_id, f"Finished {asset.target} with {len(observations)} open services"
                    )
                    retrying = False
                except FileNotFoundError:
                    scan.status = "failed"
                    scan.notes = "nmap binary not found on host"
                    status_row.status = "failed"
                    status_row.last_error = "nmap missing"
                    status_row.completed_at = datetime.utcnow()
                    session.add_all([scan, status_row])
                    session.commit()
                    _record_scan_event(session, scan_id, "nmap binary missing. Aborting scan.")
                    return
                except Exception as exc:  # pylint: disable=broad-except
                    logger.exception("Scan %s failed for asset %s: %s", scan_id, asset.target, exc)
                    status_row.status = "failed"
                    status_row.last_error = str(exc)
                    status_row.completed_at = datetime.utcnow()
                    session.add(status_row)
                    session.commit()
                    _record_scan_event(session, scan_id, f"Failed {asset.target}: {exc}")
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

        scan.completed_at = datetime.utcnow()
        if asset_errors:
            scan.status = "completed_with_errors"
            scan.notes = "One or more assets failed to scan"
        else:
            scan.status = "completed"
            scan.notes = None
        session.add(scan)
        _record_scan_event(session, scan_id, f"Scan finished with status {scan.status}")
        session.commit()


@app.post("/enrichment/finding/{finding_id}")
def enrich_one(finding_id: int, background_tasks: BackgroundTasks) -> dict:
    def _task(fid: int):
        with get_session() as s2:
            row = s2.get(Finding, fid)
            if row:
                enrich_from_feed(s2, [row])
                s2.commit()

    background_tasks.add_task(_task, finding_id)
    return {"status": "queued"}


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
    if ext:
        ext.setdefault("references", [])
    return JSONResponse({"finding": base, "enrichment": ext})


__all__ = ["app"]
