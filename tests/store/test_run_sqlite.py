"""run_sqlite.py - idempotent upserts, queries, finding id derivation."""

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


def test_a_malformed_context_column_raises_instead_of_reading_as_absent(tmp_path: Path) -> None:
    """A corrupt row must not pass for "nothing changed", "nothing spent", or "not recorded".

    Both columns drive a refusal (a changed battery) and a ceiling (the carried spend). The
    first version returned ``None`` for unparseable JSON, which the caller reports as "this run
    predates the check, continuing": an audit pointed out that an integrity record which cannot
    be READ is a stronger signal than one that was never written, and folding them together
    names the wrong cause and waves the run through.
    """

    store = SqliteRunStore(tmp_path / "runs.sqlite")
    store.save_run_context("run-abc123", spec_digests={"A": "sha256:aa"})
    store._conn.execute(
        "UPDATE runs SET spec_digests_json = ?, spend_json = ? WHERE run_id = ?",
        ("{not json", "[1, 2]", "run-abc123"),
    )
    store._conn.commit()

    import pytest

    from ildottore.store.run_sqlite import CorruptRunContext

    with pytest.raises(CorruptRunContext, match="spec_digests_json"):
        store.get_run_spec_digests("run-abc123")
    with pytest.raises(CorruptRunContext, match="spend_json"):
        store.get_run_spend("run-abc123")
    store.close()


def test_an_older_store_gains_the_context_columns_on_open(tmp_path: Path) -> None:
    """The v2 step runs against a v1 file, and twice in a row is a no-op."""

    db = tmp_path / "old.sqlite"
    conn = migrations.connect(db)
    conn.executescript(migrations._SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
    conn.execute("INSERT INTO schema_version (version) VALUES (1)")
    conn.commit()
    conn.close()

    with SqliteRunStore(db) as store:
        assert store.schema_version() == migrations.SCHEMA_VERSION
        store.save_run_context("run-old01", spend={"requests": 3})
        assert store.get_run_spend("run-old01") == {"requests": 3}
    with SqliteRunStore(db) as reopened:  # migrate() again on an already-current file
        assert reopened.schema_version() == migrations.SCHEMA_VERSION
        assert reopened.get_run_spend("run-old01") == {"requests": 3}


def test_a_store_stamped_by_an_intermediate_build_still_gains_every_column(
    tmp_path: Path,
) -> None:
    """A step already stamped is never re-run, so a later column has to be a later step.

    An intermediate build stamped v2 with two of the three context columns. Because `migrate`
    skips anything at or below the stored version, editing that step would have left those
    databases one column short for ever, failing every write with "no such column".
    """

    db = tmp_path / "intermediate.sqlite"
    conn = migrations.connect(db)
    conn.executescript(migrations._SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
    conn.execute("ALTER TABLE runs ADD COLUMN spec_digests_json TEXT")
    conn.execute("ALTER TABLE runs ADD COLUMN spend_json TEXT")
    conn.execute("INSERT INTO schema_version (version) VALUES (1)")
    conn.execute("INSERT INTO schema_version (version) VALUES (2)")
    conn.commit()
    conn.close()

    with SqliteRunStore(db) as store:
        store.save_run_context("run-int01", context={"runs": 3})
        assert store.get_run_context("run-int01") == {"runs": 3}
