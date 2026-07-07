"""run_sqlite.py — idempotent upserts, queries, finding id derivation."""

from __future__ import annotations

from pathlib import Path

from ildottore.shared.enums import VerdictStatus
from ildottore.store import migrations
from ildottore.store.run_sqlite import SqliteRunStore, finding_id_of
from tests.store.conftest import make_finding, make_run


def test_save_run_is_idempotent(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        run = make_run()
        rs.save_run(run)
        rs.save_run(run)
        assert rs.get_run("run-1") is not None
        assert len(rs.list_findings("run-1")) == 1


def test_save_run_persists_its_findings(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        rs.save_run(make_run())
        rows = rs.list_findings("run-1")
        assert rows[0]["finding_id"] == "PI-DIRECT-001::tgt-1"
        assert rows[0]["severity"] == "high"
        assert rows[0]["repro"] == 0.6


def test_save_finding_is_idempotent(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        f = make_finding()
        rs.save_finding(f)
        rs.save_finding(f)
        rows = rs.list_findings(f.target_id)
        assert len(rows) == 1
        assert rows[0]["finding_id"] == finding_id_of(f)


def test_save_finding_upsert_updates_fields(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        rs.save_finding(make_finding(repro=0.2))
        rs.save_finding(make_finding(repro=0.9))
        rows = rs.list_findings("tgt-1")
        assert len(rows) == 1
        assert rows[0]["repro"] == 0.9


def test_run_meta_roundtrips(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        rs.save_run(make_run())
        row = rs.get_run("run-1")
        assert row is not None
        assert row["suite_id"] == "suites/core"
        assert row["target_id"] == "tgt-1"
        assert row["status"] == "fail"


def test_get_missing_run_returns_none(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        assert rs.get_run("nope") is None
        assert rs.list_findings("nope") == []


def test_finding_id_derivation() -> None:
    assert finding_id_of(make_finding(spec_id="X-1", target_id="t")) == "X-1::t"


def test_schema_version_reports_latest(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        assert rs.schema_version() == migrations.SCHEMA_VERSION


def test_run_status_reflects_finding_mix(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        # empty findings -> status None
        rs.save_run(make_run(run_id="empty", findings=[]))
        assert rs.get_run("empty")["status"] is None

        # all pass -> "pass"
        rs.save_run(
            make_run(
                run_id="clean",
                findings=[make_finding(target_id="t2", status=VerdictStatus.PASS)],
            )
        )
        assert rs.get_run("clean")["status"] == "pass"

        # inconclusive present, no fail -> "inconclusive"
        rs.save_run(
            make_run(
                run_id="incon",
                findings=[make_finding(target_id="t3", status=VerdictStatus.INCONCLUSIVE)],
            )
        )
        assert rs.get_run("incon")["status"] == "inconclusive"


def test_save_run_with_no_targets_has_null_target(store_root: Path) -> None:
    with SqliteRunStore(store_root / "r.db") as rs:
        run = make_run(findings=[])
        run = run.model_copy(update={"targets": [], "suite_ref": None})
        rs.save_run(run)
        row = rs.get_run("run-1")
        assert row["target_id"] is None
        assert row["suite_id"] is None
