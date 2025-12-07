from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import Column, String
from sqlmodel import Field, Relationship, SQLModel


class ScanTarget(SQLModel, table=True):
    scan_id: Optional[int] = Field(default=None, foreign_key="scan.id", primary_key=True)
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id", primary_key=True)


class AssetBase(SQLModel):
    name: Optional[str] = Field(default=None, max_length=255)
    target: str = Field(
        sa_column=Column("address", String(255), index=True),
        description="Single host IP, CIDR, or hostname",
    )
    environment: Optional[str] = Field(default=None, max_length=100)
    owner: Optional[str] = Field(default=None, max_length=120)
    notes: Optional[str] = None


class Asset(AssetBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    scans: List["Scan"] = Relationship(back_populates="assets", link_model=ScanTarget)


class AssetCreate(AssetBase):
    pass


class AssetUpdate(SQLModel):
    name: Optional[str] = None
    target: Optional[str] = None
    environment: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None


class AssetRead(AssetBase):
    id: int
    created_at: datetime


class ScanBase(SQLModel):
    status: str = Field(default="queued", max_length=32)
    profile: str = Field(default="basic", max_length=50)
    notes: Optional[str] = None
    retry_count: int = Field(default=0)


class Scan(ScanBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    assets: List[Asset] = Relationship(back_populates="scans", link_model=ScanTarget)
    findings: List["Finding"] = Relationship(back_populates="scan")
    events: List["ScanEvent"] = Relationship(back_populates="scan")


class ScanCreate(SQLModel):
    asset_ids: List[int]
    profile: str = "intense"


class ScanRead(ScanBase):
    id: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class ScanDetail(ScanRead):
    asset_count: int
    severity_summary: Dict[str, int]
    recent_events: List[str]


class ScanAssetStatus(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    asset_id: int = Field(foreign_key="asset.id")
    status: str = Field(default="pending")
    attempts: int = Field(default=0)
    last_error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanAssetStatusRead(SQLModel):
    asset_id: int
    status: str
    attempts: int
    last_error: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class ScanEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    message: str

    scan: Optional[Scan] = Relationship(back_populates="events")


class ScanEventRead(SQLModel):
    id: int
    created_at: datetime
    message: str


class FindingBase(SQLModel):
    host_address: Optional[str] = None
    host_os_name: Optional[str] = None
    host_os_accuracy: Optional[str] = None
    host_vendor: Optional[str] = None
    traceroute_summary: Optional[str] = None
    host_report: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    rule_id: Optional[str] = None
    severity: str = Field(default="informational")
    cve_ids: Optional[str] = Field(default=None, description="JSON array stored as string")
    description: Optional[str] = None
    status: str = Field(default="open")
    owner: Optional[str] = Field(default=None, max_length=120)
    notes: Optional[str] = None


class Finding(FindingBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: Optional[int] = Field(default=None, foreign_key="scan.id")
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id")
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    scan: Optional[Scan] = Relationship(back_populates="findings")
    asset: Optional[Asset] = Relationship()


class FindingRead(FindingBase):
    id: int
    scan_id: int
    asset_id: int
    detected_at: datetime


class FindingUpdate(SQLModel):
    status: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    email: str = Field(index=True, unique=True, max_length=255)
    name: Optional[str] = Field(default=None, max_length=255)
    hashed_password: str = Field()
    role: str = Field(default="admin", max_length=32)  # admin | operator | viewer
    active: bool = Field(default=True)


class SessionToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    user_id: int = Field(foreign_key="user.id")
    token: str = Field(index=True, unique=True)
    token_type: str = Field(default="access", max_length=16)  # access | refresh
    expires_at: datetime
    revoked: bool = Field(default=False)


class UserRead(SQLModel):
    id: int
    email: str
    name: Optional[str]
    role: str
    active: bool
    created_at: datetime


class LoginAttempt(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    email: str = Field(index=True, max_length=255)
    ip: Optional[str] = Field(default=None, max_length=48)
    success: bool = Field(default=False)


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    actor_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    action: str = Field(max_length=64)
    target: Optional[str] = Field(default=None, max_length=128)
    ip: Optional[str] = Field(default=None, max_length=48)
    detail: Optional[str] = Field(default=None)


class InviteToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    email: str = Field(index=True, max_length=255)
    role: str = Field(default="operator", max_length=32)
    token: str = Field(index=True, unique=True)
    expires_at: datetime
    used_at: Optional[datetime] = None
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")


__all__ = [
    "Asset",
    "AssetCreate",
    "AssetUpdate",
    "AssetRead",
    "Scan",
    "ScanCreate",
    "ScanRead",
    "ScanDetail",
    "ScanTarget",
    "ScanAssetStatus",
    "ScanAssetStatusRead",
    "ScanEvent",
    "ScanEventRead",
    "Finding",
    "FindingRead",
    "FindingUpdate",
    "User",
    "SessionToken",
    "UserRead",
    "LoginAttempt",
    "AuditLog",
    "InviteToken",
]
