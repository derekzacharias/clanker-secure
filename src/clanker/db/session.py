from contextlib import contextmanager
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool

from clanker.config import settings
from clanker.db.migrations import apply_migrations
from clanker.db import models  # noqa: F401  # ensure models are registered with metadata

engine_kwargs = {"echo": False, "connect_args": {"check_same_thread": False}}
if settings.database_url.startswith("sqlite") and ":memory:" in settings.database_url:
    engine_kwargs["poolclass"] = StaticPool

engine = create_engine(settings.database_url, **engine_kwargs)
_initialized = False


def init_db(force: bool = False) -> None:
    global _initialized
    if _initialized and not force:
        return
    # In test runs, ensure a clean SQLite file once to avoid stale schema/index conflicts.
    if settings.database_url.startswith("sqlite:///") and "test" in settings.database_url and not _initialized:
        db_file = settings.database_url.replace("sqlite:///", "")
        path = Path(db_file)
        if path.exists():
            path.unlink()
    SQLModel.metadata.create_all(engine)
    apply_migrations(engine)
    _initialized = True


@contextmanager
def get_session() -> Session:
    global _initialized
    if not _initialized:
        init_db()
        _initialized = True
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
