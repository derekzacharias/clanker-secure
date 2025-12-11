from __future__ import annotations

from clanker.main import app
from sqlalchemy import text
from clanker.db.session import engine


@app.on_event("startup")
def _ensure_enrichment_table() -> None:
    # Create separate enrichment table to avoid altering core models
    ddl = (
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
    with engine.connect() as conn:
        conn.execute(text(ddl))
        conn.commit()
