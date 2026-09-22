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
from collections.abc import Callable
from pathlib import Path
from typing import Final

_SCHEMA_SQL_PATH: Final = Path(__file__).with_name("schema.sql")

# The current (latest) schema version. Bump + append to _MIGRATIONS to evolve.
SCHEMA_VERSION: Final = 3


def _add_run_context_columns(conn: sqlite3.Connection) -> None:
    """v2: record WHICH battery a run executed, against WHAT target, and what it spent.

    Both exist for ``--resume``, which reuses a run id across invocations: the digests let a
    resume refuse a battery that changed under it, and the spend lets the ledger open where
    the halted invocation stopped instead of granting a fresh ceiling every time.

    Written as a callable rather than DDL because SQLite's ``ADD COLUMN`` is not re-runnable
    (it errors when the column is already there), and every other step in this file is.
    """

    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "runs" not in tables:
        # A stamped database with no `runs` table (a drop, a partial restore). Previously it
        # opened and failed later at query time; failing here would be a new behaviour, and an
        # unannounced one, so the step does nothing and leaves the diagnosis where it was.
        return
    # Positional indexing, not row["name"]: `migrate(conn)` is public and used to work on a
    # plain connection, and requiring a `sqlite3.Row` factory would have broken that silently.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
    for column in ("spec_digests_json", "spend_json", "context_json"):
        if column not in existing:
            conn.execute(f"ALTER TABLE runs ADD COLUMN {column} TEXT")


# Ordered forward-only migration steps: (target_version, ddl-or-callable). Step N is applied
# only when the DB is currently below N.
_MIGRATIONS: Final[list[tuple[int, str | Callable[[sqlite3.Connection], None]]]] = [
    (1, _SCHEMA_SQL_PATH.read_text(encoding="utf-8")),
    (2, _add_run_context_columns),
    # v3 re-runs the SAME column step. The step is idempotent per column, but `migrate` skips
    # any step at or below the stored version, so a database stamped v2 by an intermediate
    # build (before `context_json` joined the step) would never gain the third column and every
    # write to it would fail with "no such column". Forward-only means adding a step, not
    # editing one that has already been stamped somewhere.
    (3, _add_run_context_columns),
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
        for version, step in _MIGRATIONS:
            if version <= start:
                continue
            if callable(step):
                step(conn)
            else:
                conn.executescript(step)
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (version,),
            )
    return current_version(conn)
