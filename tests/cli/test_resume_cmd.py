"""``dottore run --resume``: finishing a campaign that halted (u12 wiring).

The engine has supported resume since u08 and **no command reached it**, which stopped being
academic the moment a halted run started exiting 3 and reporting "27 of 72 specs never ran":
the only way to finish the battery was to shrink `--runs`, which is the input to the
reproducibility axis of the risk score.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.resume import load_resume_run
from ildottore.cli.run import RunOptions, execute_run
from ildottore.shared.models import Target
from ildottore.store.replay import TamperError

from .conftest import make_spec, write_scope, write_spec_tree, write_target

TARGET = Target(id="mock-target", type="chatbot")  # type: ignore[arg-type]


def _opts(tmp_path: Path, target: Path, scope: Path, **kw: object) -> RunOptions:
    opts = RunOptions(
        targets=[target],
        scope=scope,
        runs=3,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    return opts


def _truncate_a_run(tmp_path: Path) -> tuple[RunOptions, list[Path], str]:
    """Run with a ceiling too small for the battery; return the halted run's id.

    ``concurrency=1`` is load-bearing, not tidiness. The budget is debited **before** each
    send, so with the default concurrency of 4 the number of attempts that finish before the
    ceiling bites depends on how the scheduler interleaves them: locally three attempts were
    stored, in CI zero were, and the first version of this helper therefore passed on my
    machine and failed on the runner with a missing evidence directory. Serialised, exactly
    ``budget_requests`` attempts complete and there is always something to resume from.
    """

    target = write_target(tmp_path, mock_scenario="vulnerable")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 5)])
    opts = _opts(tmp_path, target, scope, budget_requests=4, concurrency=1)
    outcome = execute_run(opts, [specs])
    assert outcome.exit_code is ExitCode.ERROR, "the setup must actually halt"

    evidence_root = tmp_path / "ev"
    assert evidence_root.is_dir(), (
        "the halted run stored no evidence at all, so there is nothing to resume: raise "
        "budget_requests, or check that attempts are still persisted as they complete"
    )
    run_ids = [p.name for p in evidence_root.iterdir() if p.is_dir()]
    assert len(run_ids) == 1, run_ids
    return opts, [specs], run_ids[0]


def test_a_halted_run_can_be_finished(tmp_path: Path) -> None:
    """The headline: resume the id the halt printed, and the campaign completes."""

    opts, specs, run_id = _truncate_a_run(tmp_path)

    before = load_resume_run(tmp_path / "ev", run_id, TARGET)
    done_ids = {a.attempt_id for f in before.findings for a in f.attempts}
    assert done_ids, "the halted run stored something to resume from"

    opts.resume = run_id
    opts.budget_requests = None
    outcome = execute_run(opts, specs)

    assert not outcome.incomplete
    assert outcome.exit_code is not ExitCode.ERROR
    # The resumed campaign keeps the ORIGINAL run id: a new one would file the continuation
    # as a separate, equally partial run, and the evidence is keyed by it.
    assert outcome.results[0].run.run_id == run_id


def test_the_completed_attempts_are_merged_not_re_scored(tmp_path: Path) -> None:
    """A resumed spec is scored on prior PLUS fresh attempts, never on the remainder.

    Scoring the remainder is how a resume under-reports reproducibility or drops a fail that
    already happened (audit M11), so the merge is the property worth pinning at this level.
    """

    opts, specs, run_id = _truncate_a_run(tmp_path)
    before = load_resume_run(tmp_path / "ev", run_id, TARGET)
    resumed_spec = before.findings[0].spec_id
    prior_ids = {a.attempt_id for a in before.findings[0].attempts}

    opts.resume = run_id
    opts.budget_requests = None
    outcome = execute_run(opts, specs)

    finding = next(f for f in outcome.findings if f.spec_id == resumed_spec)
    got = {a.attempt_id for a in finding.attempts}
    assert prior_ids <= got, "the already-persisted attempts survived into the final finding"
    assert len(got) == opts.runs, "and the spec is scored over its full N, not the remainder"


def test_resume_reconstructs_from_hash_verified_evidence(tmp_path: Path) -> None:
    """Evidence, not the sqlite store: it is content-addressed, and a tamper must not pass."""

    _, _specs, run_id = _truncate_a_run(tmp_path)
    attempts_dir = tmp_path / "ev" / run_id / "attempts"
    artifact = sorted(attempts_dir.glob("*.json"))[0]

    run = load_resume_run(tmp_path / "ev", run_id, TARGET)
    assert all(f.evidence for f in run.findings), "every reconstructed finding keeps its refs"
    ref = run.findings[0].evidence[0]
    assert ref.sha256 is not None and ref.uri.endswith(".json")

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    payload["mutation"] = "tampered"
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TamperError):
        load_resume_run(tmp_path / "ev", run_id, TARGET)


def test_an_unknown_run_id_is_refused(tmp_path: Path) -> None:
    """Resuming "nothing" would quietly re-run the whole battery under a borrowed id."""

    with pytest.raises(ValueError, match="nothing to resume"):
        load_resume_run(tmp_path / "ev", "run-does-not-exist", TARGET)


def test_resume_refuses_more_than_one_target(tmp_path: Path) -> None:
    """A campaign stores one run id per target, so one id names one target."""

    target = write_target(tmp_path)
    second = tmp_path / "second"
    second.mkdir()
    other = write_target(second, target_id="mock-target")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    opts = _opts(tmp_path, target, scope, resume="run-whatever")
    opts.targets = [target, other]
    with pytest.raises(ValueError, match="single target"):
        execute_run(opts, [specs])
