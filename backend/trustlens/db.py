"""Database engine and session management.

SQLite is used for credential-free local development and tests. PostgreSQL
(local or Neon) is supported by setting DATABASE_URL. Alembic owns schema
changes in deployed environments; ``auto_create_schema`` is a local convenience.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import get_settings


class Base(DeclarativeBase):
    pass


def build_engine(url: str) -> Engine:
    kwargs: dict = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    else:
        kwargs.update(
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_recycle=300,
            pool_timeout=15,
        )
    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


_settings = get_settings()
engine: Engine = build_engine(_settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    """Create tables and seed the ruleset registry (local/dev only)."""
    from . import models  # noqa: F401  (registers mappers)
    from .models import RuleVersion, utcnow

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        if session.get(RuleVersion, "trustlens-rules-v1") is None:
            session.add(
                RuleVersion(
                    version="trustlens-rules-v1",
                    description="Deterministic baseline rules for URL, TLS, header, message and IOC evidence.",
                    active=True,
                    created_at=utcnow(),
                )
            )
            session.commit()
