"""Versioned, forward-only schema management for the SQLite RunStore (u10).

A single migration in MVP-1: apply ``schema.sql`` (all DDL idempotent) and stamp
``schema_version``. The design keeps a real migration seam - ``_MIGRATIONS`` is an
ordered list of ``(version, sql)`` steps - so later units can append v2, v3 …
without rewriting existing rows (contract §4 KEEP: forward-only).

Every connection is opened with ``PRAGMA journal_mode=WAL`` and
``PRAGMA foreign_keys=ON`` (contract §4 KEEP). ``migrate()`` is idempotent: a
re-run on an already-current DB does nothing and returns the current version.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final

_SCHEMA_SQL_PATH: Final = Path(__file__).with_name("schema.sql")

# The current (latest) schema version. Bump + append to _MIGRATIONS to evolve.
SCHEMA_VERSION: Final = 1

# Ordered forward-only migration steps: (target_version, ddl). Step N is applied
# only when the DB is currently below N.
_MIGRATIONS: Final[list[tuple[int, str]]] = [
    (1, _SCHEMA_SQL_PATH.read_text(encoding="utf-8")),
]


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a SQLite connection with WAL + foreign keys enforced (contract §4).

    Creates the parent directory if needed; paths-with-spaces safe (``Path``).
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def current_version(conn: sqlite3.Connection) -> int:
    """Return the highest applied schema version, or 0 if unmigrated."""

    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if row is None:
        return 0
    version_row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    value = version_row["v"] if version_row is not None else None
    return int(value) if value is not None else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Apply every pending migration in one transaction; return the new version.

    Idempotent: if the DB is already at ``SCHEMA_VERSION`` nothing runs. DDL is
    written to be re-runnable (``CREATE TABLE IF NOT EXISTS``) so a partially
    applied step is safe to re-apply.
    """

    start = current_version(conn)
    with conn:  # single transaction; rolls back on error
        for version, ddl in _MIGRATIONS:
            if version <= start:
                continue
            conn.executescript(ddl)
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (version,),
            )
    return current_version(conn)
