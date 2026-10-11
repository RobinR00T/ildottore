"""Versioned, forward-only schema management for the SQLite RunStore (u10).

A single migration in MVP-1: apply ``schema.sql`` (all DDL idempotent) and stamp
``schema_version``. The design keeps a real migration seam - ``_MIGRATIONS`` is an
ordered list of ``(version, sql)`` steps - so later units can append v2, v3 …
without rewriting existing rows (contract §4 KEEP: forward-only).

Every connection is opened with ``PRAGMA journal_mode=WAL`` and
``PRAGMA foreign_keys=ON`` (contract §4 KEEP). ``migrate()`` is idempotent: a
re-run on an already-current DB does nothing and returns the current version.

Several processes may open one store at the same time (six ``dottore run`` sharing a
``--run-db``): a connection waits :data:`BUSY_TIMEOUT_S` for a lock another one holds, the switch
to WAL is retried while SQLite refuses it as busy (it does not wait for that one), and a
migration takes the write lock before it reads the version it starts from (u10 A-80).
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final, TypeVar

_T = TypeVar("_T")

#: How long one connection waits for a lock another connection holds, in seconds. SQLite's
#: busy handler sleeps for it; the WAL switch and the migration's write lock are retried for it.
BUSY_TIMEOUT_S: Final = 30.0

_SCHEMA_SQL_PATH: Final = Path(__file__).with_name("schema.sql")

# The current (latest) schema version. Bump + append to _MIGRATIONS to evolve.
SCHEMA_VERSION: Final = 4


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
    # v4: the artifact journal. Every attempt artifact is recorded as it is written ("pending"
    # before the write, "written" after), so the evidence manifest no longer depends on a
    # finding having been saved: a resume interrupted mid-spec left artifacts no finding cited,
    # and the next resume refused the run as tampered (F11, withdrawn on 2026-10-04 for that).
    (
        4,
        """
        CREATE TABLE IF NOT EXISTS artifacts (
            run_id   TEXT NOT NULL,
            spec_id  TEXT NOT NULL,
            sha256   TEXT NOT NULL,
            state    TEXT NOT NULL DEFAULT 'pending',
            PRIMARY KEY (run_id, sha256)
        );
        CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts (run_id);
        """,
    ),
]


def connect(db_path: Path, *, timeout_s: float = BUSY_TIMEOUT_S) -> sqlite3.Connection:
    """Open a SQLite connection with WAL + foreign keys enforced (contract §4).

    Creates the parent directory if needed; paths-with-spaces safe (``Path``). The connection
    waits ``timeout_s`` for a lock another connection holds. SQLite answers the switch to WAL
    with SQLITE_BUSY at once, without that wait, while another connection holds the file (it
    would deadlock otherwise), so the switch is retried for as long: six processes opening a new
    store together lost five of them to "database is locked" (u10 A-80).
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)
    _create_private(db_path)
    conn = sqlite3.connect(db_path, timeout=timeout_s)
    try:
        conn.row_factory = sqlite3.Row
        _while_busy(lambda: conn.execute("PRAGMA journal_mode=WAL").fetchone(), timeout_s)
        conn.execute("PRAGMA foreign_keys=ON")
    except BaseException:
        conn.close()
        raise
    return conn


def _busy(exc: sqlite3.OperationalError) -> bool:
    """Whether ``exc`` is SQLite saying another connection holds the lock (BUSY or LOCKED)."""

    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code & 0xFF in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def _while_busy(operation: Callable[[], _T], timeout_s: float) -> _T:
    """Run ``operation``, again after a pause each time SQLite answers busy, for ``timeout_s``.

    For the two statements SQLite's own busy handler does not cover: the switch to WAL and a
    ``BEGIN IMMEDIATE`` it refuses to wait for because waiting could deadlock.
    """

    deadline = time.monotonic() + timeout_s
    pause = 0.005
    while True:
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if not _busy(exc) or time.monotonic() + pause > deadline:
                raise
        time.sleep(pause)
        pause = min(pause * 2, 0.25)


def _create_private(db_path: Path) -> None:
    """Create a new database file readable by its owner only; leave an existing one alone.

    sqlite3 creates the file with the process umask, usually world-readable, while every
    attempt artifact is 0600, and the run store holds what the reports are built from (audit
    SEC-10 of 2026-10-03). SQLite gives the ``-wal`` and ``-shm`` files the database file's mode.
    """

    if str(db_path) == ":memory:":
        return  # no file: `--run-db :memory:` left a stray empty file named ":memory:"
    # Through a symlink to the file it names, which may not exist yet: O_EXCL on the link
    # itself fails, and sqlite3 then created the target with the umask (pre-commit audit).
    target = os.path.realpath(db_path)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return  # it exists (keep its mode), or sqlite3 will report why it cannot be opened
    os.close(descriptor)


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


def migrate(conn: sqlite3.Connection, *, timeout_s: float = BUSY_TIMEOUT_S) -> int:
    """Apply every pending migration in one transaction; return the new version.

    Idempotent: if the DB is already at ``SCHEMA_VERSION`` nothing runs. DDL is
    written to be re-runnable (``CREATE TABLE IF NOT EXISTS``) so a partially
    applied step is safe to re-apply.

    The write lock is taken (``BEGIN IMMEDIATE``) before the version is read again, so two
    processes migrating one new store together apply each step once: reading it outside the
    lock, both found the same version and the second ``ADD COLUMN`` failed with "duplicate
    column name". It is one transaction for real: ``executescript`` commits whatever is open
    before it runs, so each script step used to commit on its own (u10 A-80).
    """

    if current_version(conn) >= SCHEMA_VERSION:
        return current_version(conn)
    if conn.in_transaction:
        conn.commit()
    _while_busy(lambda: conn.execute("BEGIN IMMEDIATE"), timeout_s)
    try:
        start = current_version(conn)
        for version, step in _MIGRATIONS:
            if version <= start:
                continue
            if callable(step):
                step(conn)
            else:
                for statement in _statements(step):
                    conn.execute(statement)
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (version,),
            )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return current_version(conn)


def _statements(script: str) -> list[str]:
    """``script`` cut into its statements, each complete as SQLite reads it (one per execute).

    A semicolon inside a string literal or a trigger body does not end a statement:
    ``sqlite3.complete_statement`` decides, not the character.
    """

    statements: list[str] = []
    buffer = ""
    for piece in script.split(";"):
        buffer += piece
        if sqlite3.complete_statement(buffer + ";"):
            if _has_code(buffer):
                statements.append(buffer + ";")
            buffer = ""
        else:
            buffer += ";"
    if _has_code(buffer):
        statements.append(buffer)
    return statements


def _has_code(text: str) -> bool:
    """Whether ``text`` holds anything but whitespace and ``--`` comments."""

    return any(line.strip() and not line.strip().startswith("--") for line in text.splitlines())
