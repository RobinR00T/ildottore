"""Each invocation of a campaign records the mutator order it planned in (OD-5, 2026-10-11).

``-sV``, ``-A`` and ``--deep`` all record adaptive planning, so a ``-sV`` campaign resumed with
``--deep`` alone keeps the mode and plans the rest in each spec's declared order: no fingerprint
is taken. OD-5 accepts that (the same attempts are sent and scored, only in another order), and
the pre-merge audit of ``be3f2e71`` found that nothing recorded it: both parts read
``"adaptive": true``, and the report has no planning field. Now ``context_json.mutator_orders``
holds one entry per invocation (``fingerprint`` or ``declared``; ``unrecorded`` first for a run
recorded before the list), a resume that plans in declared order inside an adaptive campaign
says so on stderr, and the planning-mode refusal no longer says reordering makes another
campaign, which OD-5's own reasoning contradicts.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.run import fingerprint_probe_count
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_scope, write_spec_tree, write_target

PROBES = fingerprint_probe_count()
#: Three specs at --runs 3 are nine attack requests: a ceiling of 6 halts the campaign.
HALT = 6
_NOTE = "plans in each spec's declared mutator order"


def _base(tmp_path: Path) -> list[str]:
    state = tmp_path / "state"
    return [
        "run",
        *("-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
        *("--spec-path", str(tmp_path / "specs"), "--concurrency", "1", "-q", "--runs", "3"),
        *("--evidence-root", str(state / "ev"), "--run-db", str(state / "runs.sqlite")),
    ]


def _setup(tmp_path: Path) -> None:
    write_target(tmp_path, mock_scenario="vulnerable")
    write_scope(tmp_path)
    write_spec_tree(tmp_path, [make_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 4)])


def _run_id(tmp_path: Path) -> str:
    runs = [p.name for p in (tmp_path / "state" / "ev").iterdir() if p.is_dir()]
    assert len(runs) == 1, runs
    return runs[0]


def _context(tmp_path: Path, run_id: str) -> dict[str, object]:
    with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
        context = store.get_run_context(run_id)
    assert context is not None
    return context


def _invoke(tmp_path: Path, *flags: str) -> Result:
    return CliRunner().invoke(app, [*_base(tmp_path), *flags])


def test_a_fresh_run_records_the_declared_order(tmp_path: Path) -> None:
    _setup(tmp_path)
    result = _invoke(tmp_path)
    assert result.exit_code != ExitCode.ERROR, result.stderr
    assert _context(tmp_path, _run_id(tmp_path))["mutator_orders"] == ["declared"]


def test_a_fresh_sv_run_records_the_fingerprint_order(tmp_path: Path) -> None:
    _setup(tmp_path)
    result = _invoke(tmp_path, "-sV")
    assert result.exit_code != ExitCode.ERROR, result.stderr
    assert _context(tmp_path, _run_id(tmp_path))["mutator_orders"] == ["fingerprint"]


def test_a_sv_campaign_resumed_with_deep_alone_records_both_orders_and_says_so(
    tmp_path: Path,
) -> None:
    _setup(tmp_path)
    halted = _invoke(tmp_path, "-sV", "--budget-requests", str(PROBES + HALT))
    assert halted.exit_code == ExitCode.ERROR, halted.stderr
    run_id = _run_id(tmp_path)
    assert _context(tmp_path, run_id)["mutator_orders"] == ["fingerprint"]

    resumed = _invoke(tmp_path, "--resume", run_id, "--deep", "--budget-requests", "500")
    stderr = resumed.stderr
    assert resumed.exit_code != ExitCode.ERROR, stderr
    context = _context(tmp_path, run_id)
    assert context["mutator_orders"] == ["fingerprint", "declared"]
    assert context["adaptive"] is True, "the recorded mode is unchanged"
    notes = [line for line in stderr.splitlines() if _NOTE in line]
    assert len(notes) == 1, stderr
    assert notes[0].startswith(f"note: {run_id} ") and "mutator_orders" in notes[0], notes[0]


def test_a_sv_resume_records_the_fingerprint_order_and_says_nothing(tmp_path: Path) -> None:
    _setup(tmp_path)
    halted = _invoke(tmp_path, "-sV", "--budget-requests", str(PROBES + HALT))
    assert halted.exit_code == ExitCode.ERROR
    run_id = _run_id(tmp_path)
    resumed = _invoke(tmp_path, "--resume", run_id, "-sV", "--budget-requests", "500")
    stderr = resumed.stderr
    assert resumed.exit_code != ExitCode.ERROR, stderr
    assert _context(tmp_path, run_id)["mutator_orders"] == ["fingerprint", "fingerprint"]
    assert _NOTE not in stderr


def test_a_deep_campaign_resumed_with_deep_says_nothing(tmp_path: Path) -> None:
    """Nothing changed: no invocation planned with a fingerprint, so there is nothing to note
    (verification of 877b2e2b: the note printed here, with mutator_orders declared, declared)."""

    _setup(tmp_path)
    halted = _invoke(tmp_path, "--deep", "--budget-requests", str(HALT))
    assert halted.exit_code == ExitCode.ERROR, halted.stderr
    run_id = _run_id(tmp_path)
    resumed = _invoke(tmp_path, "--resume", run_id, "--deep", "--budget-requests", "500")
    stderr = resumed.stderr
    assert resumed.exit_code != ExitCode.ERROR, stderr
    context = _context(tmp_path, run_id)
    assert context["mutator_orders"] == ["declared", "declared"]
    assert context["adaptive"] is True
    assert _NOTE not in stderr, stderr


def test_a_declared_campaign_resumed_says_nothing(tmp_path: Path) -> None:
    _setup(tmp_path)
    halted = _invoke(tmp_path, "--budget-requests", str(HALT))
    assert halted.exit_code == ExitCode.ERROR
    run_id = _run_id(tmp_path)
    resumed = _invoke(tmp_path, "--resume", run_id, "--budget-requests", "500")
    stderr = resumed.stderr
    assert resumed.exit_code != ExitCode.ERROR, stderr
    assert _context(tmp_path, run_id)["mutator_orders"] == ["declared", "declared"]
    assert _NOTE not in stderr


def test_a_run_recorded_before_the_list_starts_it_with_unrecorded(tmp_path: Path) -> None:
    _setup(tmp_path)
    halted = _invoke(tmp_path, "--budget-requests", str(HALT))
    assert halted.exit_code == ExitCode.ERROR
    run_id = _run_id(tmp_path)
    with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
        context = store.get_run_context(run_id) or {}
        del context["mutator_orders"]
        store._conn.execute(
            "UPDATE runs SET context_json = ? WHERE run_id = ?", (json.dumps(context), run_id)
        )
        store._conn.commit()
    resumed = _invoke(tmp_path, "--resume", run_id, "--budget-requests", "500")
    assert resumed.exit_code != ExitCode.ERROR, resumed.stderr
    assert _context(tmp_path, run_id)["mutator_orders"] == ["unrecorded", "declared"]


def test_the_planning_mode_refusal_says_what_the_mode_changes(tmp_path: Path) -> None:
    """It said "It reorders the mutators a spec runs, so the two halves would not be the same
    campaign", which OD-5 contradicts: the order changes which attempt goes first, never which
    attempts are sent."""

    _setup(tmp_path)
    halted = _invoke(tmp_path, "-sV", "--budget-requests", str(PROBES + HALT))
    assert halted.exit_code == ExitCode.ERROR
    run_id = _run_id(tmp_path)
    refused = _invoke(tmp_path, "--resume", run_id, "--budget-requests", "500")
    stderr = refused.stderr
    assert refused.exit_code == ExitCode.ERROR, stderr
    assert "would not be the same campaign" not in stderr, stderr
    assert "never which attempts are sent" in stderr, stderr


def test_rewriting_the_context_keeps_the_list(tmp_path: Path) -> None:
    """``save_run_context`` replaces the context; the list is kept, as the scope list is."""

    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        assert store.add_run_order("r", "fingerprint") == ["fingerprint"]
        store.save_run_context("r", context={"adaptive": True})
        assert store.add_run_order("r", "declared", resumed=True) == ["fingerprint", "declared"]
        assert store.get_run_context("r") == {
            "adaptive": True,
            "mutator_orders": ["fingerprint", "declared"],
        }
