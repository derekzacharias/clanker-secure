from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine


def _has_column(engine: Engine, table: str, column: str) -> bool:
    with engine.connect() as connection:
        result = connection.execute(text(f"PRAGMA table_info({table})"))
        for row in result.mappings():
            if row["name"] == column:
                return True
    return False


def add_column_if_missing(engine: Engine, table: str, column: str, ddl: str) -> None:
    if _has_column(engine, table, column):
        return
    with engine.connect() as connection:
        connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        connection.commit()


def apply_migrations(engine: Engine) -> None:
    add_column_if_missing(engine, "asset", "kind", "TEXT DEFAULT 'host'")
    add_column_if_missing(engine, "asset", "environment", "TEXT")
    add_column_if_missing(engine, "asset", "owner", "TEXT")
    add_column_if_missing(engine, "asset", "notes", "TEXT")
    add_column_if_missing(engine, "scan", "retry_count", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "finding", "owner", "TEXT")
    add_column_if_missing(engine, "finding", "notes", "TEXT")
    add_column_if_missing(engine, "finding", "host_address", "TEXT")
    add_column_if_missing(engine, "finding", "host_os_name", "TEXT")
    add_column_if_missing(engine, "finding", "host_os_accuracy", "TEXT")
    add_column_if_missing(engine, "finding", "host_vendor", "TEXT")
    add_column_if_missing(engine, "finding", "traceroute_summary", "TEXT")
    add_column_if_missing(engine, "finding", "host_report", "TEXT")
