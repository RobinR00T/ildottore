"""migrations.py - round-trip, idempotency, pragmas."""

from __future__ import annotations

from pathlib import Path

from ildottore.store import migrations


def test_fresh_db_migrates_to_latest(store_root: Path) -> None:
    conn = migrations.connect(store_root / "r.db")
    try:
        assert migrations.current_version(conn) == 0
        assert migrations.migrate(conn) == migrations.SCHEMA_VERSION
        assert migrations.current_version(conn) == migrations.SCHEMA_VERSION
    finally:
        conn.close()


def test_migrate_is_idempotent(store_root: Path) -> None:
    conn = migrations.connect(store_root / "r.db")
    try:
        migrations.migrate(conn)
        version_after_first = migrations.current_version(conn)
        assert migrations.migrate(conn) == version_after_first
        rows = conn.execute("SELECT COUNT(*) AS c FROM schema_version").fetchone()
        assert rows["c"] == migrations.SCHEMA_VERSION  # one row per applied version
    finally:
        conn.close()


def test_pragmas_enforced(store_root: Path) -> None:
    conn = migrations.connect(store_root / "r.db")
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()


def test_expected_tables_created(store_root: Path) -> None:
    conn = migrations.connect(store_root / "r.db")
    try:
        migrations.migrate(conn)
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {"runs", "findings", "schema_version"} <= tables
    finally:
        conn.close()


def test_connect_creates_parent_dir(tmp_path: Path) -> None:
    nested = tmp_path / "a b" / "c" / "r.db"
    conn = migrations.connect(nested)
    try:
        assert nested.parent.is_dir()
    finally:
        conn.close()
