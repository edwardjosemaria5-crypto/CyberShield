"""SQLAlchemy engine and session management for CyberShield.

The module reads the connection URL from ``app.core.config`` at import
time. SQLite is the default development store; swapping the
``CYBERSHIELD_DATABASE_URL`` environment variable to a PostgreSQL URL is
sufficient to move to PostgreSQL later without touching the models or the
history service.
"""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import DATABASE_URL

_connect_args: dict = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Declarative base shared by all ORM models."""


def init_db() -> None:
    """Create any missing tables. Idempotent; never drops existing data."""
    from app.database import models  # noqa: F401 - registers the models

    Base.metadata.create_all(bind=engine)


def get_db_session() -> Iterator[Session]:
    """FastAPI dependency yielding a short-lived database session."""
    with SessionLocal() as session:
        yield session