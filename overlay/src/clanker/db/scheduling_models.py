from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class AssetGroup(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=120, index=True)
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AssetGroupMember(SQLModel, table=True):
    asset_group_id: Optional[int] = Field(default=None, foreign_key="assetgroup.id", primary_key=True)
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id", primary_key=True)


class ScheduleJob(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=120, index=True)
    cron: str = Field(default="* * * * *", description="cron-like expression; minute field honored")
    profile: str = Field(default="intense", max_length=50)
    asset_group_id: int = Field(foreign_key="assetgroup.id")
    enabled: bool = Field(default=True)
    last_run_at: Optional[datetime] = None


__all__ = ["AssetGroup", "AssetGroupMember", "ScheduleJob"]

