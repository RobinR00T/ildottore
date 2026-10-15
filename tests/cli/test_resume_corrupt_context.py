"""A corrupt run-context value is refused, naming its field, never read as something else (L6).

CLI audit of 2026-10-11, L6, on ``de122e26``: ``adaptive: "x"`` was read as adaptive planning on
(and the resume refused for a mode the run never recorded); ``scope_sha256s: 7`` was read as a run
that predates scope digests, and the record was overwritten; a ``mutator_orders`` that was not a
list was overwritten too, the record lost; and a ``started_at`` that is not a timestamp reached
the report as the run's start. ``runs``, ``spend_json`` and three sampling booleans were already
refused this way (2026-10-07, u12 A-66, A-68); now every field the run context holds is checked
where it is read, and a value of the wrong shape is refused with exit 3, naming the field and
never quoting the value, before anything is sent or written.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.run import RunOptions, execute_run

from .conftest import make_spec, write_scope, write_spec_tree, write_target


def _opts(tmp_path: Path, **kw: object) -> RunOptions:
    opts = RunOptions(
        targets=[write_target(tmp_path, mock_scenario="vulnerable")],
        scope=write_scope(tmp_path),
        runs=3,
        quiet=True,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
        budget_requests=6,
        concurrency=1,
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    return opts


def _halted(tmp_path: Path) -> tuple[str, Path]:
    spec_dir = write_spec_tree(
        tmp_path,
        [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002"), make_spec("PI-DIRECT-003")],
    )
    outcome = execute_run(_opts(tmp_path), [spec_dir])
    assert outcome.exit_code == ExitCode.ERROR
    (run_id,) = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    return run_id, spec_dir


def _db(tmp_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(tmp_path / "runs.sqlite")


def _set(tmp_path: Path, key: str, value: object) -> str:
    with closing(_db(tmp_path)) as db:
        (raw,) = db.execute("SELECT context_json FROM runs").fetchone()
        context = json.loads(raw)
        context[key] = value
        written = json.dumps(context)
        db.execute("UPDATE runs SET context_json = ?", (written,))
        db.commit()
    return written


def _row(tmp_path: Path) -> tuple[object, ...]:
    with closing(_db(tmp_path)) as db:
        row = db.execute("SELECT * FROM runs").fetchone()
    assert row is not None
    return tuple(row)


def _resume_cli(tmp_path: Path, spec_dir: Path, run_id: str) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec-path",
            str(spec_dir),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--resume",
            run_id,
            "--budget-requests",
            "100",
            "-q",
        ],
    )
    return result.exit_code, result.output


_CORRUPT: list[tuple[str, object]] = [
    ("adaptive", "x"),
    ("adaptive", 1),
    ("scope_sha256s", 7),
    ("scope_sha256s", ["not a digest"]),
    ("scope_sha256s", []),
    ("mutator_orders", "fingerprinted"),
    ("mutator_orders", ["sideways"]),
    ("not_destructive_tools", "transfer_to_billing_agent"),
    ("not_destructive_tools", [3]),
    ("target_digest", 7),
    ("target_digest", "sha256:v2:short"),
    ("judge_digest", ["sha256"]),
    ("sampling_defaults_applied", "yes"),
    ("takes_sampling", "yes"),
    ("judge_takes_sampling", 0),
    ("judging_rules", "1"),
    ("judging_rules", True),
    ("judging_rules", 0),
    ("tool_version", 7),
    ("tool_version", ""),
    ("route", None),
    ("selection", "--spec PI-*"),
    ("selection", {"spec": "PI-*"}),
    ("spec_fields", {"PI-DIRECT-001": "abc"}),
    ("target_fields", {"endpoint": 7}),
]


@pytest.mark.parametrize(("key", "value"), _CORRUPT, ids=[f"{k}={v!r}" for k, v in _CORRUPT])
def test_a_corrupt_field_is_refused_with_exit_3_naming_it_and_nothing_is_written(
    tmp_path: Path, key: str, value: object
) -> None:
    run_id, spec_dir = _halted(tmp_path)
    _set(tmp_path, key, value)
    before = _row(tmp_path)
    stored = sorted(p.name for p in (tmp_path / "ev").rglob("*.json"))

    code, output = _resume_cli(tmp_path, spec_dir, run_id)

    assert code == ExitCode.ERROR, output
    article = "an" if key[0] in "aeiou" else "a"
    assert f"context_json holds {article} {key} value that is not" in output
    assert "refusing rather than continuing" in output
    if isinstance(value, str) and len(value) > 2:
        assert value not in output, "the value is never quoted"
    assert _row(tmp_path) == before, "a refused resume writes nothing"
    assert sorted(p.name for p in (tmp_path / "ev").rglob("*.json")) == stored


@pytest.mark.parametrize("started_at", ["not-a-date", "2026-13-40T99:00:00Z", "7"])
def test_a_start_that_is_not_a_timestamp_is_refused_and_never_reaches_a_report(
    tmp_path: Path, started_at: str
) -> None:
    run_id, spec_dir = _halted(tmp_path)
    with closing(_db(tmp_path)) as db:
        db.execute("UPDATE runs SET started_at = ?", (started_at,))
        db.commit()

    code, output = _resume_cli(tmp_path, spec_dir, run_id)

    assert code == ExitCode.ERROR, output
    assert "started_at holds a value that is not a timestamp" in output
    if len(started_at) > 2:
        assert started_at not in output, "the value is never quoted"


def test_a_start_as_this_tool_writes_it_is_kept(tmp_path: Path) -> None:
    run_id, spec_dir = _halted(tmp_path)
    with closing(_db(tmp_path)) as db:
        db.execute("UPDATE runs SET started_at = ?", ("2026-10-11T21:31:49Z",))
        db.commit()

    outcome = execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.results[0].run.started_at == "2026-10-11T21:31:49Z"


def test_an_append_never_overwrites_a_record_it_cannot_read(tmp_path: Path) -> None:
    """The store refuses too, so no path through it replaces a corrupt list with a fresh one."""

    from ildottore.store.run_sqlite import CorruptRunContext, SqliteRunStore

    run_id, _ = _halted(tmp_path)
    written = _set(tmp_path, "mutator_orders", "declared")
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        with pytest.raises(CorruptRunContext, match="mutator_orders"):
            store.add_run_order(run_id, "declared", resumed=True)
        with pytest.raises(CorruptRunContext, match="mutator_orders"):
            store.add_run_scope(run_id, "0" * 64, resumed=True)
    with closing(_db(tmp_path)) as db:
        (raw,) = db.execute("SELECT context_json FROM runs").fetchone()
    assert raw == written


def test_an_unknown_key_is_left_alone(tmp_path: Path) -> None:
    """A key a later version adds is not this version's to judge: the resume goes on."""

    run_id, spec_dir = _halted(tmp_path)
    _set(tmp_path, "something_a_later_version_records", {"any": ["shape"]})

    outcome = execute_run(_opts(tmp_path, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}
