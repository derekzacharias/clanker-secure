from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AssetGroup(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=120, index=True)
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class AssetGroupMember(SQLModel, table=True):
    asset_group_id: Optional[int] = Field(default=None, foreign_key="assetgroup.id", primary_key=True)
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id", primary_key=True)


class ScheduleJob(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=120, index=True)
    cron: str = Field(default="* * * * *", description="deprecated cron-like expression; minute field honored")
    profile: str = Field(default="intense", max_length=50)
    asset_group_id: int = Field(foreign_key="assetgroup.id")
    enabled: bool = Field(default=True)
    last_run_at: Optional[datetime] = None
    days_of_week: Optional[str] = Field(default=None, description="JSON array of weekday integers (0=Mon)")
    times: Optional[str] = Field(default=None, description="JSON array of HH:MM strings")


__all__ = ["AssetGroup", "AssetGroupMember", "ScheduleJob"]
