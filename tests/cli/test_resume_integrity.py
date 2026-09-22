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
        # Serial on purpose. With the default concurrency of 4, WHICH attempts finish before
        # the ceiling halts the campaign is scheduler-dependent: locally the first spec's
        # three attempts were always stored, and in CI the halt landed before any of them
        # were, so every test here failed on an evidence tree that did not exist. A resume
        # test needs a halted run with evidence, not a halted run.
        concurrency=1,
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    return opts


def _halted_run(tmp_path: Path, spec_dir: Path) -> str:
    """Run until the request ceiling halts it; return the run id."""

    outcome = execute_run(_opts(tmp_path, spec_dir), [spec_dir])
    assert outcome.exit_code == ExitCode.ERROR, "the ceiling should have halted the run"
    assert (tmp_path / "ev").is_dir(), (
        "precondition: the halted run stored evidence. If this fails, the ceiling stopped the "
        "campaign before a single attempt was persisted and there is nothing to resume, which "
        "is a broken fixture rather than a broken resume."
    )
    run_ids = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    assert len(run_ids) == 1
    stored = list((tmp_path / "ev" / run_ids[0] / "attempts").glob("*.json"))
    assert stored, "precondition: at least one attempt is on disk to resume from"
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


def test_a_run_from_before_the_digests_is_refused_and_can_be_opted_into(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An absent integrity record refuses, and the opt-in names what it costs.

    The first version continued with a notice, and an audit showed why that was wrong: a run
    recorded before the digest column also predates the SPEND column, so the same resume that
    could not verify the battery was handed a brand-new budget ceiling. The commit that
    claimed to have fixed the double ceiling could still reproduce it on every run that
    existed at the time. Refusing by default closes both halves at once.
    """

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(
            "UPDATE runs SET spec_digests_json = NULL, spend_json = NULL, context_json = NULL "
            "WHERE run_id = ?",
            (run_id,),
        )
        store._conn.commit()

    with pytest.raises(ValueError, match="cannot verify"):
        execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])

    execute_run(
        _opts(
            tmp_path,
            spec_dir,
            resume=run_id,
            budget_requests=100,
            resume_unverified=True,
        ),
        [spec_dir],
    )
    err = capsys.readouterr().err
    assert "--resume-unverified" in err or "cannot be verified" in err
    assert "no spend was recorded" in err, "the money half has to be named, not just the specs"


def test_a_corrupt_integrity_record_is_not_an_absent_one(tmp_path: Path) -> None:
    """A tampered column must read as stronger evidence than a missing one, not weaker."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(
            "UPDATE runs SET spec_digests_json = ? WHERE run_id = ?", ("not json", run_id)
        )
        store._conn.commit()

    with pytest.raises(ValueError, match="not readable JSON"):
        execute_run(
            _opts(
                tmp_path,
                spec_dir,
                resume=run_id,
                budget_requests=100,
                resume_unverified=True,
            ),
            [spec_dir],
        )


def test_the_offline_scenario_cannot_be_flipped_under_a_resume(tmp_path: Path) -> None:
    """`--resume --hardened` needed no file edit to publish one half as another's findings.

    The id matched and the specs matched, so both checks passed, while the answers came from
    a different replay. The target digest covers the resolved route for that reason.
    """

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)

    flipped = _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100)
    flipped.targets = [write_target(tmp_path, mock_scenario="hardened")]
    with pytest.raises(ValueError, match="different target"):
        execute_run(flipped, [spec_dir])


def test_changing_runs_under_a_resume_is_refused_but_omitting_it_inherits(
    tmp_path: Path,
) -> None:
    """One report must not score some specs over 3 samples and others over 1.

    Asking for a different sample size explicitly is refused. Not asking at all inherits the
    campaign's, because the store knows it and making the operator remember a number is how a
    check gets worked around.
    """

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)

    explicit = _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100, runs=1)
    explicit.runs_explicit = True
    with pytest.raises(ValueError, match="--runs"):
        execute_run(explicit, [spec_dir])

    inheriting = _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100, runs=5)
    execute_run(inheriting, [spec_dir])
    assert inheriting.runs == 3, "the resume inherited the campaign's sample size"


def test_a_resume_is_refused_before_the_fingerprint_sends_anything(tmp_path: Path) -> None:
    """`-sV --resume` put 17 probes on the endpoint and then exited 3 having done no work."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    edited = make_spec("PI-DIRECT-001")
    edited = edited.model_copy(
        update={"attack": edited.attack.model_copy(update={"user_prompt": "a different question"})}
    )
    changed = write_spec_tree(
        tmp_path / "edited", [edited, make_spec("PI-DIRECT-002"), make_spec("PI-DIRECT-003")]
    )

    sent: list[str] = []
    import ildottore.cli.wiring as wiring_mod

    original = wiring_mod.fingerprint_probe

    def _counting(*args: object, **kwargs: object) -> object:
        sent.append("probe pass")
        return original(*args, **kwargs)  # type: ignore[arg-type]

    wiring_mod.fingerprint_probe = _counting  # type: ignore[assignment]
    try:
        with pytest.raises(ValueError):
            execute_run(
                _opts(
                    tmp_path,
                    changed,
                    resume=run_id,
                    budget_requests=100,
                    fingerprint_first=True,
                ),
                [changed],
            )
    finally:
        wiring_mod.fingerprint_probe = original  # type: ignore[assignment]

    assert sent == [], "the refusal has to land before the probe pass, not after it"


def test_the_wall_ceiling_refusal_also_lands_before_the_probe_pass(tmp_path: Path) -> None:
    """The second refusal added that night sat BELOW the fingerprint block.

    So a resume whose wall budget was already spent sent 17 probes on a live endpoint with a
    real bearer token and then exited 3 having done no work: the exact defect the clause above
    it claims was fixed, reintroduced by the fix for it.
    """

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store.save_run_context(run_id, spend={"wall_s": 100000.0})

    sent: list[str] = []
    import ildottore.cli.wiring as wiring_mod

    original = wiring_mod.fingerprint_probe

    def _counting(*args: object, **kwargs: object) -> object:
        sent.append("probe pass")
        return original(*args, **kwargs)  # type: ignore[arg-type]

    wiring_mod.fingerprint_probe = _counting  # type: ignore[assignment]
    try:
        with pytest.raises(ValueError, match="wall-clock ceiling"):
            execute_run(
                _opts(
                    tmp_path,
                    spec_dir,
                    resume=run_id,
                    budget_requests=100,
                    budget_wall_s=1800,
                    fingerprint_first=True,
                ),
                [spec_dir],
            )
    finally:
        wiring_mod.fingerprint_probe = original  # type: ignore[assignment]

    assert sent == []
