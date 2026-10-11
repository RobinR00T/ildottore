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
    """A store another process is writing waits up to the busy timeout, not 5 s (the default)."""

    db = tmp_path / "runs.sqlite"
    conn = migrations.connect(db)
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == int(
            migrations.BUSY_TIMEOUT_S * 1000
        )
    finally:
        conn.close()
