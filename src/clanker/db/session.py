from contextlib import contextmanager

from sqlmodel import Session, SQLModel, create_engine

from clanker.config import settings
from clanker.db.migrations import apply_migrations
from clanker.db import models  # noqa: F401  # ensure models are registered with metadata

engine = create_engine(settings.database_url, echo=False, connect_args={"check_same_thread": False})


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    apply_migrations(engine)


@contextmanager
def get_session() -> Session:
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
