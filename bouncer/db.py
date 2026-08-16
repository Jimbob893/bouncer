"""SQLite storage plumbing.

Threat model: the audit chain's integrity depends on appends being serialized.
If two writers read the same tail hash concurrently, they produce two rows
claiming the same predecessor and the chain forks. SQLite is configured here so
that every transaction takes a write lock up front (``BEGIN IMMEDIATE``), which
serializes appends across threads *and* across processes — the CLI approving an
item while the proxy is serving is exactly that case.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

__all__ = ["Base", "SessionFactory", "create_session_factory", "make_engine"]


class Base(DeclarativeBase):
    """Declarative base for every bouncer table."""


SessionFactory = sessionmaker[Session]


def make_engine(db_path: str | Path, *, echo: bool = False) -> Engine:
    """Create an engine with the pragmas bouncer's guarantees depend on."""
    path = Path(db_path).expanduser()
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(
        f"sqlite+pysqlite:///{path}",
        echo=echo,
        future=True,
        # Reuse one connection for in-memory databases so tests see one DB.
        poolclass=None,
        connect_args={"timeout": 30.0},
    )

    @event.listens_for(engine, "connect")
    def _configure(dbapi_connection: Any, _record: Any) -> None:
        # Hand transaction control to SQLAlchemy so the "begin" hook below can
        # choose the lock mode; pysqlite's implicit BEGIN would take a deferred
        # lock and allow two readers to race into the same append.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=FULL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
        finally:
            cursor.close()

    @event.listens_for(engine, "begin")
    def _begin_immediate(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def create_session_factory(engine: Engine) -> SessionFactory:
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
