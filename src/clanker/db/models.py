from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import Column, String, Text
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
    credentialed: bool = Field(default=False, description="Whether credentialed scanning is enabled for this asset")
    ssh_username: Optional[str] = Field(default=None, max_length=255)
    ssh_port: Optional[int] = Field(default=None)
    ssh_auth_method: Optional[str] = Field(default=None, max_length=32)
    ssh_key_path: Optional[str] = Field(default=None, max_length=1024)
    ssh_allow_agent: bool = Field(default=False)
    ssh_look_for_keys: bool = Field(default=False)
    ssh_password: Optional[str] = Field(default=None, description="Stored for demo only; prefer agent/key auth")


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
    credentialed: Optional[bool] = None
    ssh_username: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_auth_method: Optional[str] = None
    ssh_key_path: Optional[str] = None
    ssh_allow_agent: Optional[bool] = None
    ssh_look_for_keys: Optional[bool] = None
    ssh_password: Optional[str] = None


class AssetRead(AssetBase):
    id: int
    created_at: datetime


class ScanBase(SQLModel):
    status: str = Field(default="queued", max_length=32)
    profile: str = Field(default="basic", max_length=50)
    notes: Optional[str] = None
    retry_count: int = Field(default=0)
    correlation_id: Optional[str] = Field(default=None, max_length=64, index=True)


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


class SSHScan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    status: str = Field(default="queued", max_length=32)
    notes: Optional[str] = None
    port: int = Field(default=22)
    timeout: int = Field(default=10)
    command_timeout: int = Field(default=30)
    max_workers: int = Field(default=4)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class SSHScanRead(SQLModel):
    id: int
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


class SSHScanHost(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ssh_scan_id: int = Field(foreign_key="sshscan.id")
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id")
    host: str = Field(max_length=255)
    port: int = Field(default=22)
    username: Optional[str] = Field(default=None, max_length=255)
    auth_method: str = Field(default="unspecified", max_length=32)
    status: str = Field(default="queued", max_length=32)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    raw_output: Optional[str] = Field(default=None, sa_column=Column("raw_output", Text))
    facts: Optional[str] = Field(default=None, sa_column=Column("facts", Text))
    ssh_config_hardening: Optional[str] = Field(default=None, sa_column=Column("ssh_config_hardening", Text))


class SSHScanHostRead(SQLModel):
    id: int
    ssh_scan_id: int
    asset_id: Optional[int]
    host: str
    port: int
    username: Optional[str]
    auth_method: str
    status: str
    error: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    raw_output: Optional[str]
    facts: Optional[str]
    ssh_config_hardening: Optional[str]


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
    correlation_id: Optional[str] = Field(default=None, max_length=64, index=True)

    scan: Optional[Scan] = Relationship(back_populates="events")


class ScanEventRead(SQLModel):
    id: int
    created_at: datetime
    message: str
    correlation_id: Optional[str]


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
    fingerprint: Optional[str] = Field(default=None, sa_column=Column("fingerprint", Text))
    evidence: Optional[str] = Field(default=None, sa_column=Column("evidence", Text))
    evidence_summary: Optional[str] = Field(default=None, max_length=500)
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
    assigned_user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    sla_due_at: Optional[datetime] = Field(default=None)
    closed_at: Optional[datetime] = Field(default=None)

    scan: Optional[Scan] = Relationship(back_populates="findings")
    asset: Optional[Asset] = Relationship()


class FindingRead(FindingBase):
    id: int
    scan_id: int
    asset_id: int
    assigned_user_id: Optional[int]
    detected_at: datetime
    sla_due_at: Optional[datetime]
    closed_at: Optional[datetime]


class FindingUpdate(SQLModel):
    status: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None
    assigned_user_id: Optional[int] = None
    sla_due_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None


class FindingComment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    user_id: int = Field(foreign_key="user.id")
    message: str = Field(max_length=2000)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)


class FindingCommentRead(SQLModel):
    id: int
    finding_id: int
    user_id: int
    message: str
    created_at: datetime


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


class Schedule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    name: str = Field(max_length=200)
    profile: str = Field(default="basic", max_length=50)
    asset_ids_json: str = Field(default="[]")
    days_of_week_json: str = Field(default="[]")
    times_json: str = Field(default="[]")
    active: bool = Field(default=True)
    last_run_at: Optional[datetime] = None


class AgentIngest(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id")
    agent_id: Optional[str] = Field(default=None, max_length=255)
    agent_version: Optional[str] = Field(default=None, max_length=50)
    host_identifier: Optional[str] = Field(default=None, max_length=255)
    hostname: Optional[str] = Field(default=None, max_length=255)
    os_name: Optional[str] = Field(default=None, max_length=100)
    os_version: Optional[str] = Field(default=None, max_length=100)
    kernel_version: Optional[str] = Field(default=None, max_length=120)
    distro: Optional[str] = Field(default=None, max_length=120)
    package_count: int = Field(default=0)
    service_count: int = Field(default=0)
    interface_count: int = Field(default=0)
    config_count: int = Field(default=0)
    raw_payload: Optional[str] = None


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
    "FindingComment",
    "FindingCommentRead",
    "User",
    "SessionToken",
    "UserRead",
    "LoginAttempt",
    "AuditLog",
    "InviteToken",
    "Schedule",
    "AgentIngest",
]
