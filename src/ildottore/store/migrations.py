"""Versioned, forward-only schema management for the SQLite RunStore (u10).

A single migration in MVP-1: apply ``schema.sql`` (all DDL idempotent) and stamp
``schema_version``. The design keeps a real migration seam - ``_MIGRATIONS`` is an
ordered list of ``(version, sql)`` steps - so later units can append v2, v3 …
without rewriting existing rows (contract §4 KEEP: forward-only).

Every connection is opened with ``PRAGMA journal_mode=WAL`` and
``PRAGMA foreign_keys=ON`` (contract §4 KEEP). ``migrate()`` is idempotent: a
re-run on an already-current DB does nothing and returns the current version.

Several processes may open one store at the same time (six ``dottore run`` sharing a
``--run-db``): a statement waits up to :data:`BUSY_TIMEOUT_S` for a lock another connection
holds, in short tries Python's signal handlers run between (Ctrl-C stops it), says on stderr
that it is waiting, and names the store when it gives up; the switch to WAL is retried the same
way (SQLite refuses it as busy without waiting), and a migration takes the write lock before it
reads the version it starts from (u10 A-80).
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Final, TypeVar

from ildottore.redactor import visible_controls

_T = TypeVar("_T")

#: How long a statement waits, in all, for a lock another connection holds, in seconds.
BUSY_TIMEOUT_S = 30.0
#: SQLite's own wait per try. SQLite sleeps in C, where Python runs no signal handler, so a 30 s
#: busy timeout held Ctrl-C for about 32 s (pre-merge audit of e6a1ab9b); the wait is Python's
#: loop over short tries instead.
_TRY_TIMEOUT_S: Final = 0.1
#: How long a wait goes on before it is said on stderr, once per connection.
NOTICE_AFTER_S = 1.0
#: SQLITE_BUSY_SNAPSHOT: a read transaction's snapshot went stale; waiting cannot clear it.
_BUSY_SNAPSHOT: Final = 517


class StoreLocked(sqlite3.OperationalError):
    """Another process held the run store's lock for the whole wait; the message names it."""


class StoreConnection(sqlite3.Connection):
    """A connection whose statements wait for a held lock in Python, interruptibly, and say so.

    ``execute``, ``executemany`` and ``commit`` retry while SQLite answers busy, for
    :attr:`wait_s` in all; the first time a wait passes :data:`NOTICE_AFTER_S` a one-line note
    goes to stderr, and a wait that runs out raises :class:`StoreLocked` naming
    :attr:`store_path`. A statement SQLite refused as busy changed nothing, so it is retried as
    it was; ``commit`` is retried as SQLite's documentation allows.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.store_path = ""
        self.wait_s = BUSY_TIMEOUT_S
        self._noticed = False

    def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
        return self._waiting(lambda: sqlite3.Connection.execute(self, sql, parameters))

    def executemany(self, sql: str, parameters: Iterable[Any], /) -> sqlite3.Cursor:
        rows = list(parameters)  # an iterator would be spent by the first try
        return self._waiting(lambda: sqlite3.Connection.executemany(self, sql, rows))

    def commit(self) -> None:
        self._waiting(lambda: sqlite3.Connection.commit(self))

    def _waiting(self, operation: Callable[[], _T]) -> _T:
        return _while_busy(operation, self.wait_s, on_wait=self._notice, store=self.store_path)

    def _notice(self) -> None:
        if self._noticed:
            return
        self._noticed = True
        try:
            sys.stderr.write(
                f"note: waiting for the run store at {visible_controls(self.store_path)}: another "
                f"process holds its lock (up to {self.wait_s:g} s; Ctrl-C stops the wait)\n"
            )
            sys.stderr.flush()
        except (OSError, ValueError):  # stderr closed: the wait goes on unsaid
            pass


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


def connect(db_path: Path, *, timeout_s: float | None = None) -> StoreConnection:
    """Open a SQLite connection with WAL + foreign keys enforced (contract §4).

    Creates the parent directory if needed; paths-with-spaces safe (``Path``). Each statement
    waits up to ``timeout_s`` (default :data:`BUSY_TIMEOUT_S`) for a lock another connection
    holds (:class:`StoreConnection`). That covers the switch to WAL, which SQLite answers with
    SQLITE_BUSY at once while another connection holds the file (it would deadlock otherwise):
    processes opening a new store together lost some of their runs to "database is locked"
    (u10 A-80).
    """

    wait_s = BUSY_TIMEOUT_S if timeout_s is None else timeout_s
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _create_private(db_path)
    conn = sqlite3.connect(db_path, timeout=_TRY_TIMEOUT_S, factory=StoreConnection)
    try:
        conn.store_path = str(db_path)
        conn.wait_s = wait_s
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL").fetchone()
        conn.execute("PRAGMA foreign_keys=ON")
    except BaseException:
        conn.close()
        raise
    return conn


def _busy(exc: sqlite3.OperationalError) -> bool:
    """Whether waiting can clear ``exc``: another connection holds the lock (BUSY or LOCKED).

    Not a stale snapshot (SQLITE_BUSY_SNAPSHOT, which only starting the transaction again
    clears), and not this module's own :class:`StoreLocked`, which is a wait that ran out.
    """

    if isinstance(exc, StoreLocked):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int):
        return code != _BUSY_SNAPSHOT and code & 0xFF in (
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        )
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def _while_busy(
    operation: Callable[[], _T],
    timeout_s: float,
    *,
    on_wait: Callable[[], None] | None = None,
    store: str = "",
) -> _T:
    """Run ``operation``, again after a pause each time SQLite answers busy, for ``timeout_s``.

    The pauses are ``time.sleep``, which a signal interrupts (Ctrl-C raises at once). ``on_wait``
    is called once the wait has lasted :data:`NOTICE_AFTER_S`. A wait that runs out raises
    :class:`StoreLocked` naming ``store`` when there is one, else SQLite's own error.
    """

    started = time.monotonic()
    deadline = started + timeout_s
    pause = 0.005
    while True:
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if not _busy(exc):
                raise
            now = time.monotonic()
            if now + pause > deadline:
                if not store:
                    raise
                raise StoreLocked(
                    f"the run store at {store} stayed locked by another process for {timeout_s:g} s"
                ) from exc
            if on_wait is not None and now - started >= NOTICE_AFTER_S:
                on_wait()
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


def migrate(conn: sqlite3.Connection, *, timeout_s: float | None = None) -> int:
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
        # It committed the caller's open transaction silently, as executescript did.
        raise ValueError(
            "migrate() runs in a transaction of its own: commit or roll back the connection's "
            "open transaction first"
        )
    _while_busy(
        lambda: conn.execute("BEGIN IMMEDIATE"), BUSY_TIMEOUT_S if timeout_s is None else timeout_s
    )
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
