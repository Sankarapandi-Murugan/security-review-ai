"""Shared SQLAlchemy engine factory.

Defaults to a local SQLite file (unchanged behavior for local dev/tests). Set the
``DATABASE_URL`` environment variable (e.g. ``postgresql+psycopg://user:pass@host/db``)
to run against a real Postgres instance in production — every repository in
``infrastructure/persistence`` uses this shared engine, so no other code needs to
change. Engines are cached per resolved URL so repeated repository construction
(e.g. the background-task pattern in ``AssessmentService``) reuses the same
connection pool instead of opening a new one each time.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import Engine, create_engine

_DEFAULT_SQLITE_PATH = "data/security_review.db"

_engine_cache: dict[str, Engine] = {}


def resolve_database_url(db_path: str | None = None) -> str:
    """Resolve the SQLAlchemy database URL to use.

    ``DATABASE_URL`` (if set) always wins and is shared by every repository,
    since a real database server isn't addressed by a local file path. Otherwise
    falls back to a SQLite file at ``db_path`` (or the default location),
    preserving the pre-existing local/dev/test behavior.
    """
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url

    path = Path(db_path or _DEFAULT_SQLITE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path}"


def get_engine(db_path: str | None = None) -> Engine:
    """Return a cached SQLAlchemy engine for the resolved database URL."""
    url = resolve_database_url(db_path)
    engine = _engine_cache.get(url)
    if engine is None:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        engine = create_engine(url, connect_args=connect_args, future=True)
        _engine_cache[url] = engine
    return engine


def reset_engine_cache() -> None:
    """Dispose and clear all cached engines. Primarily for test isolation."""
    for engine in _engine_cache.values():
        engine.dispose()
    _engine_cache.clear()
