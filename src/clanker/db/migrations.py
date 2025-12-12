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
    if not _table_exists(engine, table):
        return
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
        "cpe_confidence TEXT,"
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
    add_column_if_missing(engine, "asset", "credentialed", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "asset", "ssh_username", "TEXT")
    add_column_if_missing(engine, "asset", "ssh_port", "INTEGER")
    add_column_if_missing(engine, "asset", "ssh_auth_method", "TEXT")
    add_column_if_missing(engine, "asset", "ssh_key_path", "TEXT")
    add_column_if_missing(engine, "asset", "ssh_allow_agent", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "asset", "ssh_look_for_keys", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "asset", "ssh_password", "TEXT")
    add_column_if_missing(engine, "scan", "retry_count", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "scan", "correlation_id", "TEXT")
    add_column_if_missing(engine, "finding", "owner", "TEXT")
    add_column_if_missing(engine, "finding", "notes", "TEXT")
    add_column_if_missing(engine, "finding", "host_address", "TEXT")
    add_column_if_missing(engine, "finding", "host_os_name", "TEXT")
    add_column_if_missing(engine, "finding", "host_os_accuracy", "TEXT")
    add_column_if_missing(engine, "finding", "host_vendor", "TEXT")
    add_column_if_missing(engine, "finding", "traceroute_summary", "TEXT")
    add_column_if_missing(engine, "finding", "host_report", "TEXT")
    add_column_if_missing(engine, "finding", "fingerprint", "TEXT")
    add_column_if_missing(engine, "finding", "evidence", "TEXT")
    add_column_if_missing(engine, "finding", "evidence_summary", "TEXT")
    add_column_if_missing(engine, "finding", "evidence_grade", "TEXT")
    add_column_if_missing(engine, "finding", "why_trace", "TEXT")
    add_column_if_missing(engine, "finding", "assigned_user_id", "INTEGER")
    add_column_if_missing(engine, "finding", "sla_due_at", "TEXT")
    add_column_if_missing(engine, "finding", "closed_at", "TEXT")
    add_column_if_missing(engine, "agentingest", "interface_count", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "agentingest", "config_count", "INTEGER DEFAULT 0")
    if not _table_exists(engine, "scanjob"):
        ddl = (
            "CREATE TABLE scanjob ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "scan_id INTEGER NOT NULL UNIQUE,"
            "status TEXT NOT NULL DEFAULT 'queued',"
            "attempts INTEGER NOT NULL DEFAULT 0,"
            "max_attempts INTEGER NOT NULL DEFAULT 3,"
            "last_error TEXT,"
            "enqueued_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "started_at TEXT,"
            "completed_at TEXT,"
            "updated_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "FOREIGN KEY(scan_id) REFERENCES scan(id)"
            ")"
        )
        with engine.connect() as connection:
            connection.execute(text(ddl))
            connection.commit()
    if not _table_exists(engine, "schedule"):
        ddl = (
            "CREATE TABLE schedule ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "name TEXT NOT NULL,"
            "profile TEXT NOT NULL,"
            "asset_ids_json TEXT NOT NULL DEFAULT '[]',"
            "days_of_week_json TEXT NOT NULL DEFAULT '[]',"
            "times_json TEXT NOT NULL DEFAULT '[]',"
            "active INTEGER NOT NULL DEFAULT 1,"
            "last_run_at TEXT"
            ")"
        )
        with engine.connect() as connection:
            connection.execute(text(ddl))
            connection.commit()
    add_column_if_missing(engine, "finding_enrichment", "kev", "INTEGER DEFAULT 0")
    add_column_if_missing(engine, "finding_enrichment", "epss", "REAL")
    add_column_if_missing(engine, "scan_event", "correlation_id", "TEXT")
    with engine.connect() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS finding_enrichment (\n"
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                "  finding_id INTEGER NOT NULL UNIQUE,\n"
                "  cpe TEXT,\n"
                "  cpe_confidence TEXT,\n"
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
    add_column_if_missing(engine, "finding_enrichment", "cpe_confidence", "TEXT")
    if not _table_exists(engine, "finding_comment"):
        ddl = (
            "CREATE TABLE finding_comment ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "finding_id INTEGER NOT NULL,"
            "user_id INTEGER NOT NULL,"
            "message TEXT NOT NULL,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "FOREIGN KEY(finding_id) REFERENCES finding(id),"
            "FOREIGN KEY(user_id) REFERENCES user(id)"
            ")"
        )
        with engine.connect() as connection:
            connection.execute(text(ddl))
            connection.commit()
