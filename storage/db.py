"""
storage/db.py
=============
AgentShield Phase 5 — Database Connection & Session Management

Provides migration-managed SQLite persistence for AgentShield telemetry,
audit logs, approvals, and platform events. PostgreSQL is not claimed as a
validated deployment in this project phase.
"""

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# Database connection URL (defaults to SQLite agent_shield.db in workspace root)
DEFAULT_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "agent_shield.db")
)
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

if not DATABASE_URL.startswith("sqlite"):
    raise ValueError("AgentShield Phase 12 validates SQLite DATABASE_URL values only")

# Configure connect_args for SQLite thread safety and concurrency
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30.0

# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True,
)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _enable_sqlite_pragmas(dbapi_connection, connection_record):
        del connection_record
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

# Session factory
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


_migrated_urls: set[str] = set()


def run_migrations(database_url: str | None = None) -> None:
    """Upgrade a SQLite database to the Alembic head without dropping data.

    Uses an absolute alembic script location so the migration loader always
    finds the real alembic/ directory, even when the function is called with a
    temporary database URL from a different working directory.
    """

    url = database_url or DATABASE_URL
    if not url.startswith("sqlite"):
        raise ValueError("Only SQLite migration validation is supported in Phase 12")
    if url in _migrated_urls:
        return

    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import create_engine, inspect as _inspect

    # Resolve the project root from this function's own compiled filename
    # rather than from the ``storage.db`` module's ``__file__`` attribute.
    # On some test invocations the module object's ``__file__`` is mutated
    # (e.g. by test-harness import side-effects) while the function object
    # still points at the real ``storage/db.py``, so relying on
    # ``os.path.dirname(__file__)`` would silently resolve to the wrong
    # directory.  Using ``__code__.co_filename`` is immune to that.
    _this_file = os.path.abspath(run_migrations.__code__.co_filename)
    root = os.path.abspath(os.path.join(os.path.dirname(_this_file), ".."))
    alembic_ini = os.path.join(root, "alembic.ini")
    alembic_script = os.path.join(root, "alembic")

    config = Config(alembic_ini)
    config.attributes["sqlalchemy_url"] = url
    config.set_main_option("script_location", alembic_script)
    config.set_main_option("sqlalchemy.url", url)
    config.set_main_option("here", root)

    # Fail hard if Alembic cannot resolve the script directory.  On this
    # machine the test suite previously silently skipped migrations because
    # command.upgrade() swallowed the ScriptDirectory error and returned with
    # an empty database.  We verify the script directory ourselves so a
    # misconfigured *fresh* database is caught immediately rather than later as
    # a mysterious empty-table assertion.
    try:
        script = ScriptDirectory.from_config(config)
    except Exception as exc:
        raise RuntimeError(
            f"Alembic cannot load the script directory for {url}. "
            f"script_location={alembic_script!r}, error={exc}"
        ) from exc

    heads = script.get_heads()
    if not heads:
        raise RuntimeError(
            f"Alembic script directory for {url} contains no migration heads. "
            f"Checked {alembic_script!r}."
        )

    command.upgrade(config, "head")

    # Verify the migration actually wrote tables to the target file.  If
    # command.upgrade() appeared to succeed but left an empty database, raise
    # immediately so the failure is visible at the migration step rather than
    # later as a mysterious empty-table assertion.
    verify_engine = create_engine(
        url,
        connect_args={"check_same_thread": False},
        echo=True,
    )
    verify_inspector = _inspect(verify_engine)
    verified_tables = set(verify_inspector.get_table_names())
    if not verified_tables:
        # Also dump the raw sqlite_master to see if alembic wrote anything
        # under a different table-naming convention.
        import sqlite3 as _sqlite3

        with _sqlite3.connect(url.replace("sqlite:///", "")) as raw_conn:
            raw_rows = raw_conn.execute(
                "SELECT name, type FROM sqlite_master ORDER BY name"
            ).fetchall()
        raise RuntimeError(
            f"Alembic upgrade reported success for {url} but no tables were "
            f"found via SQLAlchemy inspect (tables={verified_tables!r}). "
            f"Raw sqlite_master contents: {raw_rows!r}."
        )
    _migrated_urls.add(url)


def init_db() -> None:
    """Compatibility entry point; production schema management is Alembic."""

    run_migrations()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager providing a transactional database session.
    Automatically commits on success or rolls back on exception.

    Usage:
        with get_db_session() as session:
            session.add(log_record)
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
