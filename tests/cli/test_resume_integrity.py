"""``--resume`` is bound to the battery and to the money (contract u12, added 2026-09-22).

Two documented limits, both of the same shape: the command claimed a property of the whole
campaign while checking only the invocation in front of it.

* The specs could change between the halt and the resume. The two halves are merged into one
  finding per spec and scored as one campaign, so a prompt edited in between produced a single
  report, under a single run id, out of two different batteries, with nothing saying so.
* The hard budget was per invocation. A run halted at its ceiling, was resumed, and spent the
  whole ceiling again under the same id: "this scan will not cost more than X" was true of
  each command and false of the campaign being paid for.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.resume import load_resume_run
from ildottore.cli.run import RunOptions, execute_run
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_scope, write_spec_tree, write_target

_BUDGET = 6


def _opts(tmp_path: Path, spec_dir: Path, **kw: object) -> RunOptions:
    opts = RunOptions(
        targets=[write_target(tmp_path, mock_scenario="vulnerable")],
        scope=write_scope(tmp_path),
        runs=3,
        quiet=True,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
        budget_requests=_BUDGET,
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    return opts


def _halted_run(tmp_path: Path, spec_dir: Path) -> str:
    """Run until the request ceiling halts it; return the run id."""

    outcome = execute_run(_opts(tmp_path, spec_dir), [spec_dir])
    assert outcome.exit_code == ExitCode.ERROR, "the ceiling should have halted the run"
    run_ids = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    assert len(run_ids) == 1
    return run_ids[0]


def _specs(tmp_path: Path) -> Path:
    return write_spec_tree(
        tmp_path,
        [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002"), make_spec("PI-DIRECT-003")],
    )


def test_a_fresh_run_records_the_battery_it_executed(tmp_path: Path) -> None:
    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)

    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        digests = store.get_run_spec_digests(run_id)
        spend = store.get_run_spend(run_id)

    assert digests is not None
    assert set(digests) == {"PI-DIRECT-001", "PI-DIRECT-002", "PI-DIRECT-003"}
    assert all(d.startswith("sha256:") for d in digests.values())
    assert spend is not None and spend["requests"] == _BUDGET


def test_a_changed_spec_refuses_the_resume_and_names_it(tmp_path: Path) -> None:
    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)

    edited = make_spec("PI-DIRECT-001")
    edited = edited.model_copy(
        update={"attack": edited.attack.model_copy(update={"user_prompt": "a different question"})}
    )
    changed = write_spec_tree(
        tmp_path / "edited", [edited, make_spec("PI-DIRECT-002"), make_spec("PI-DIRECT-003")]
    )
    with pytest.raises(ValueError, match="PI-DIRECT-001"):
        execute_run(_opts(tmp_path, changed, resume=run_id, budget_requests=100), [changed])


def test_a_comment_only_edit_does_not_block_a_resume(tmp_path: Path) -> None:
    """The digest is over the loaded model, so formatting is not a battery change.

    A file-bytes digest would refuse a resume over a reflowed line or an added comment, which
    trains the operator to work around the check instead of reading it.
    """

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)

    for path in spec_dir.rglob("*.yaml"):
        path.write_text(
            "# an added comment, and nothing else\n" + path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    outcome = execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}


def test_a_ceiling_binds_the_campaign_not_the_command(tmp_path: Path) -> None:
    """Resuming under the same ceiling must not buy a second full ceiling."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    execute_run(_opts(tmp_path, spec_dir, resume=run_id), [spec_dir])

    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        spend = store.get_run_spend(run_id)

    assert spend is not None
    assert spend["requests"] == _BUDGET, (
        "the resumed invocation spent beyond the campaign's ceiling: "
        f"{spend['requests']} requests against a limit of {_BUDGET}"
    )


def test_a_run_from_before_the_digests_is_reported_unverifiable_not_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An absent record is not a match, and the operator is told so rather than nothing."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute("UPDATE runs SET spec_digests_json = NULL WHERE run_id = ?", (run_id,))
        store._conn.commit()

    target = write_target(tmp_path, mock_scenario="vulnerable")
    from ildottore.cli.wiring import load_target

    loaded = load_target(target)
    specs = [make_spec("PI-DIRECT-001")]
    load_resume_run(tmp_path / "ev", run_id, loaded, run_db=tmp_path / "runs.sqlite", specs=specs)
    assert "predates battery-digest recording" in capsys.readouterr().err
