"""Opening the run store: concurrent first opens, and a path that is not a store (u10 A-80).

Six `dottore run` started together on a new `--run-db` lost five of them to `OperationalError:
database is locked`: SQLite refuses the switch to WAL at once, without waiting, when another
connection holds the file, and two processes migrating together could both add the same column.
A `--run-db` naming a directory or a file that is not a SQLite database raised a bare sqlite3
error, which the CLI let through as a traceback with exit 1 ("findings below --fail-on").
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ildottore.store import RunStoreError, SqliteRunStore, migrations

SRC = Path(__file__).resolve().parents[2] / "src"

# Each worker announces itself, waits for the go file, then opens the store at once.
_WORKER = """
import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from ildottore.store.run_sqlite import SqliteRunStore
ready, go, db = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
ready.write_text("ready")
while not go.exists():
    time.sleep(0.001)
try:
    with SqliteRunStore(db) as store:
        store.schema_version()
    print("ok")
except Exception as exc:
    print(f"{type(exc).__name__}: {exc}")
"""


def _open_together(tmp_path: Path, processes: int) -> list[str]:
    db = tmp_path / "runs.sqlite"
    go = tmp_path / "go"
    readies = [tmp_path / f"ready-{i}" for i in range(processes)]
    workers = [
        subprocess.Popen(  # noqa: S603 - the interpreter running these tests, fixed arguments
            [sys.executable, "-c", _WORKER, str(SRC), str(ready), str(go), str(db)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for ready in readies
    ]
    deadline = time.monotonic() + 60
    while not all(r.exists() for r in readies):
        assert time.monotonic() < deadline, "the workers did not start"
        time.sleep(0.01)
    go.write_text("go")
    return [w.communicate(timeout=120)[0].strip() for w in workers]


def test_processes_opening_a_new_store_together_all_succeed(tmp_path: Path) -> None:
    """On main, 18 of 80 such opens failed (8 processes, 10 rounds); every one succeeds now."""

    for round_index in range(3):
        root = tmp_path / f"round-{round_index}"
        root.mkdir()
        outcomes = _open_together(root, 8)
        assert outcomes == ["ok"] * 8, outcomes


def test_a_directory_is_refused_as_a_run_store_naming_the_path(tmp_path: Path) -> None:
    with pytest.raises(RunStoreError) as raised:
        SqliteRunStore(tmp_path)
    shown = str(raised.value)
    assert shown.startswith(f"cannot open the run store at {tmp_path}: ")
    assert "directory" in shown
    assert isinstance(raised.value, OSError)  # the CLI's operational-error handlers catch it


def test_a_file_that_is_not_sqlite_is_refused_as_a_run_store(tmp_path: Path) -> None:
    garbage = tmp_path / "runs.sqlite"
    garbage.write_text("garbage" * 50)
    with pytest.raises(RunStoreError) as raised:
        SqliteRunStore(garbage)
    assert str(raised.value) == (f"cannot open the run store at {garbage}: file is not a database")
    assert garbage.read_text() == "garbage" * 50  # nothing was written into it


def test_a_store_under_a_regular_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("x")
    with pytest.raises(RunStoreError, match="cannot open the run store at "):
        SqliteRunStore(tmp_path / "file" / "runs.sqlite")


def test_a_failure_while_the_store_is_open_names_the_store(tmp_path: Path) -> None:
    """Inside ``with SqliteRunStore(...)``, a sqlite3 error says which store failed."""

    db = tmp_path / "runs.sqlite"
    with pytest.raises(RunStoreError) as raised, SqliteRunStore(db) as store:
        store._conn.execute("SELECT * FROM no_such_table")
    assert str(raised.value).startswith(f"the run store at {db} failed: no such table")
    assert isinstance(raised.value.__cause__, sqlite3.OperationalError)


def test_migrating_a_store_another_process_just_migrated_is_a_no_op(tmp_path: Path) -> None:
    """The version is read again under the write lock, so a second migration adds nothing.

    Read outside it, two processes could both find version 1 and both add the same column, the
    second failing with "duplicate column name".
    """

    db = tmp_path / "runs.sqlite"
    first = migrations.connect(db)
    second = migrations.connect(db)
    try:
        assert migrations.current_version(second) == 0
        migrations.migrate(first)
        assert migrations.migrate(second) == migrations.SCHEMA_VERSION
        versions = [r[0] for r in second.execute("SELECT version FROM schema_version")]
        assert sorted(versions) == list(range(1, migrations.SCHEMA_VERSION + 1))
    finally:
        first.close()
        second.close()


def test_a_migration_that_fails_leaves_nothing_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All steps commit together or none does (the old loop committed each script on its own)."""

    db = tmp_path / "runs.sqlite"
    conn = migrations.connect(db)
    steps = migrations._MIGRATIONS
    monkeypatch.setattr(migrations, "_MIGRATIONS", [*steps[:1], (2, "CREATE TABLE broken (")])
    try:
        with pytest.raises(sqlite3.Error):
            migrations.migrate(conn)
        assert migrations.current_version(conn) == 0
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "runs" not in tables
    finally:
        conn.close()


def test_the_connection_waits_for_a_held_lock(tmp_path: Path) -> None:
    """30 s in all, in tries of 0.1 s Python's signal handlers run between (not 5 s, the
    default, and not one 30 s wait in C that held Ctrl-C)."""

    db = tmp_path / "runs.sqlite"
    conn = migrations.connect(db)
    try:
        assert isinstance(conn, migrations.StoreConnection)
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 100
        assert conn.wait_s == migrations.BUSY_TIMEOUT_S == 30.0
        assert conn.store_path == str(db)
    finally:
        conn.close()


# --- pre-merge audit of e6a1ab9b: a lock wait is said, interruptible, and names the store ----


def _held(db: Path) -> sqlite3.Connection:
    """Another process's write lock on ``db``, held until the connection is closed."""

    with SqliteRunStore(db):
        pass  # created and migrated
    holder = sqlite3.connect(db, timeout=0)
    holder.execute("BEGIN IMMEDIATE")
    return holder


def test_a_lock_held_past_the_wait_names_the_store(tmp_path: Path) -> None:
    db = tmp_path / "runs.sqlite"
    holder = _held(db)
    try:
        conn = migrations.connect(db, timeout_s=0.4)
        started = time.monotonic()
        with pytest.raises(migrations.StoreLocked) as raised:
            conn.execute("INSERT INTO schema_version (version) VALUES (99)")
        waited = time.monotonic() - started
        conn.close()
    finally:
        holder.close()
    assert 0.3 <= waited < 3, waited
    assert str(raised.value) == (
        f"the run store at {db} stayed locked by another process for 0.4 s"
    )
    assert isinstance(raised.value, sqlite3.OperationalError)  # the handlers that catch it


def test_the_store_says_nothing_of_a_wait_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Round-2 audit of f51a7d07, LOW 4: a library user gets no CLI text on stderr."""

    monkeypatch.setattr(migrations, "NOTICE_AFTER_S", 0.05)
    db = tmp_path / "runs.sqlite"
    holder = _held(db)
    try:
        conn = migrations.connect(db, timeout_s=0.3)
        with pytest.raises(migrations.StoreLocked):
            conn.execute("INSERT INTO schema_version (version) VALUES (99)")
        conn.close()
    finally:
        holder.close()
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("given", ["argument", "context"])
def test_a_wait_is_reported_to_the_callers_callback_once_per_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, given: str
) -> None:
    monkeypatch.setattr(migrations, "NOTICE_AFTER_S", 0.05)
    db = tmp_path / "runs.sqlite"
    heard: list[tuple[str, float]] = []

    def hear(store: str, wait_s: float) -> None:
        heard.append((store, wait_s))

    holder = _held(db)
    try:
        if given == "argument":
            conn = migrations.connect(db, timeout_s=0.3, on_lock_wait=hear)
        else:
            with migrations.lock_waits_reported(hear):
                conn = migrations.connect(db, timeout_s=0.3)
        for _ in range(2):
            with pytest.raises(migrations.StoreLocked):
                conn.execute("INSERT INTO schema_version (version) VALUES (99)")
        conn.close()
    finally:
        holder.close()
    assert heard == [(str(db), 0.3)]


def test_the_lock_message_names_the_store_once(tmp_path: Path) -> None:
    """LOW 3: "the run store at X failed: the run store at X stayed locked ..."."""

    db = tmp_path / "runs.sqlite"
    holder = _held(db)
    try:
        with pytest.raises(RunStoreError) as raised, SqliteRunStore(db) as store:
            store._conn.wait_s = 0.2  # type: ignore[attr-defined]
            store._conn.execute("INSERT INTO schema_version (version) VALUES (99)")
    finally:
        holder.close()
    assert str(raised.value) == f"the run store at {db} stayed locked by another process for 0.2 s"


@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="needs setitimer")
def test_a_lock_wait_stops_on_ctrl_c(tmp_path: Path) -> None:
    """SQLite's busy timeout sleeps in C, where Python runs no signal handler: a 30 s timeout
    held Ctrl-C for about 32 s. The wait is Python's loop now, between short tries."""

    import signal

    def interrupt(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    db = tmp_path / "runs.sqlite"
    holder = _held(db)
    previous = signal.signal(signal.SIGALRM, interrupt)
    try:
        conn = migrations.connect(db, timeout_s=30)
        signal.setitimer(signal.ITIMER_REAL, 0.3)
        started = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            conn.execute("INSERT INTO schema_version (version) VALUES (99)")
        stopped = time.monotonic() - started
        conn.close()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        holder.close()
    assert stopped < 2, stopped


def test_an_error_that_is_not_a_lock_is_raised_at_once() -> None:
    calls = 0

    def missing() -> None:
        nonlocal calls
        calls += 1
        raise sqlite3.OperationalError("no such table: x")

    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        migrations._while_busy(missing, 5)
    assert calls == 1


def test_a_stale_snapshot_is_not_waited_on() -> None:
    """SQLITE_BUSY_SNAPSHOT cannot clear by waiting: the transaction has to start again."""

    calls = 0

    def stale() -> None:
        nonlocal calls
        calls += 1
        exc = sqlite3.OperationalError("database is locked")
        exc.sqlite_errorcode = 517  # type: ignore[attr-defined]
        raise exc

    with pytest.raises(sqlite3.OperationalError):
        migrations._while_busy(stale, 5)
    assert calls == 1


def test_a_busy_answer_is_retried_until_it_clears() -> None:
    answers = iter([sqlite3.OperationalError("database is locked")] * 3)

    def flaky() -> str:
        for exc in answers:
            raise exc
        return "done"

    assert migrations._while_busy(flaky, 5) == "done"


def test_migrate_refuses_a_connection_with_an_open_transaction(tmp_path: Path) -> None:
    """It used to commit the caller's transaction silently before its own."""

    conn = migrations.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute("CREATE TABLE mine (a)")
        conn.execute("INSERT INTO mine VALUES (1)")
        assert conn.in_transaction
        with pytest.raises(ValueError, match="open transaction"):
            migrations.migrate(conn)
        conn.rollback()
        assert conn.execute("SELECT COUNT(*) FROM mine").fetchone()[0] == 0
    finally:
        conn.close()


def test_a_migration_that_fails_closes_the_connection_and_names_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[sqlite3.Connection] = []
    real_connect = migrations.connect

    def connect(path: Path, **kwargs: object) -> sqlite3.Connection:
        conn = real_connect(path)
        opened.append(conn)
        return conn

    def broken(conn: sqlite3.Connection, **kwargs: object) -> int:
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(migrations, "connect", connect)
    monkeypatch.setattr(migrations, "migrate", broken)
    db = tmp_path / "runs.sqlite"
    with pytest.raises(RunStoreError) as raised:
        SqliteRunStore(db)
    assert str(raised.value) == (
        f"cannot open the run store at {db}: database disk image is malformed"
    )
    with pytest.raises(sqlite3.ProgrammingError):  # closed
        opened[0].execute("SELECT 1")
