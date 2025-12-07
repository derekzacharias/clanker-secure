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


def _table_exists(engine: Engine, table: str) -> bool:
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"), {"name": table}
        )
        return result.first() is not None


def ensure_finding_enrichment_table(engine: Engine) -> None:
    """
    Create the enrichment table if it does not exist.

    The table is kept separate from the SQLModel metadata so we can evolve enrichment
    without forcing a breaking migration on the core models.
    """
    if _table_exists(engine, "finding_enrichment"):
        return
    ddl = (
        "CREATE TABLE finding_enrichment ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "finding_id INTEGER NOT NULL UNIQUE,"
        "cpe TEXT,"
        "cvss_v31_base REAL,"
        "cvss_vector TEXT,"
        "references_json TEXT,"
        "last_enriched_at TEXT,"
        "source TEXT"
        ")"
    )
    with engine.connect() as connection:
        connection.execute(text(ddl))
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
    with engine.connect() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS finding_enrichment (\n"
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                "  finding_id INTEGER NOT NULL UNIQUE,\n"
                "  cpe TEXT,\n"
                "  cvss_v31_base REAL,\n"
                "  cvss_vector TEXT,\n"
                "  references_json TEXT,\n"
                "  last_enriched_at TEXT,\n"
                "  source TEXT\n"
                ")"
            )
        )
        connection.commit()
    ensure_finding_enrichment_table(engine)
