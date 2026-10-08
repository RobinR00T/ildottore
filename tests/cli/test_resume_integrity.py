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
from typer.testing import CliRunner

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.run import RunOptions, execute_run
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import (
    LONG_OPTION,
    deep_json,
    make_spec,
    write_scope,
    write_spec_tree,
    write_target,
)

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
            # Digests and spend absent, context KEPT: the battery and the money are
            # unverifiable and waivable; the route is verifiable and has no opt-in (below).
            "UPDATE runs SET spec_digests_json = NULL, spend_json = NULL WHERE run_id = ?",
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


_SET_COLUMN = {
    column: f"UPDATE runs SET {column} = ? WHERE run_id = ?"  # noqa: S608 (a fixed column list)
    for column in ("spec_digests_json", "spend_json", "context_json")
}


@pytest.mark.parametrize("column", sorted(_SET_COLUMN))
def test_an_integrity_record_nested_too_deeply_is_corrupt(tmp_path: Path, column: str) -> None:
    """Past the parser's stack, `json.loads` raises RecursionError, not a JSONDecodeError: it
    escaped as a traceback with exit 1, findings below `--fail-on` (2026-10-07)."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(_SET_COLUMN[column], (deep_json(), run_id))
        store._conn.commit()

    with pytest.raises(ValueError, match=f"{column} is not readable JSON"):
        execute_run(
            _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100, resume_unverified=True),
            [spec_dir],
        )


@pytest.mark.parametrize("context", ['{"runs": []}', '{"runs": 1e400, "target_digest": null}'])
def test_a_bad_count_without_a_digest_is_still_refused(tmp_path: Path, context: str) -> None:
    """A count that is there is refused whatever else is in the row, so no reader of it ever
    converts a bad one with `int()`. (Today the target refusal would fire first anyway; this
    pins the store's own check.)"""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(_SET_COLUMN["context_json"], (context, run_id))
        store._conn.commit()

    with pytest.raises(ValueError, match="context_json holds no runs value"):
        execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])


def test_a_stored_column_is_bounded_at_a_hundred_levels() -> None:
    """Under the parser's stack a value can still be too deep to write back (below)."""

    from ildottore.store.run_sqlite import _loads

    assert _loads("[" * 100 + "]" * 100) is not None
    with pytest.raises(ValueError, match="nested too deeply"):
        _loads("[" * 101 + "]" * 101)
    with pytest.raises(ValueError, match="nested too deeply"):
        _loads('{"a": ' * 101 + "1" + "}" * 101)


def test_a_context_too_deep_to_write_back_is_corrupt(tmp_path: Path) -> None:
    """110,000 levels inside the scope list parse on 3.14, and the resume that wrote the
    context back overflowed `json.dumps` (past about 104,500): a traceback and exit 1
    (pre-merge audit of #61). An older parser refuses the text first; exit 3 either way."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    deep = "[" * 110_000 + "]" * 110_000
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        raw = store._conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        assert '"scope_sha256s":["' in raw, "precondition: the stored form the edit targets"
        edited = raw.replace('"scope_sha256s":["', '"scope_sha256s":[' + deep + ',"')
        store._conn.execute(_SET_COLUMN["context_json"], (edited, run_id))
        store._conn.commit()

    result = CliRunner().invoke(
        app,
        [
            "run",
            *("-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
            *("--spec-path", str(spec_dir), "--resume", run_id, "--budget-requests", "100"),
            *("--concurrency", "1", "-q", "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "runs.sqlite")),
        ],
    )

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.stderr[-300:])
    errors = [line for line in result.stderr.splitlines() if line.startswith("error:")]
    assert len(errors) == 1 and "context_json is not readable JSON" in errors[0]


def test_the_cli_exits_3_on_a_run_store_nested_too_deeply(tmp_path: Path) -> None:
    """Clause A-9 through the command itself: one `error:` line and exit 3."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(
            "UPDATE runs SET context_json = ? WHERE run_id = ?", (deep_json("object"), run_id)
        )
        store._conn.commit()

    result = CliRunner().invoke(
        app,
        [
            "run",
            *("-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
            *("--spec-path", str(spec_dir), "--resume", run_id, "--budget-requests", "100"),
            *("--concurrency", "1", "-q", "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "runs.sqlite")),
        ],
    )

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.stderr)
    errors = [line for line in result.stderr.splitlines() if line.startswith("error:")]
    assert len(errors) == 1 and "context_json is not readable JSON" in errors[0]


@pytest.mark.parametrize(
    "spend",
    [
        '{"tokens": 1e400}',
        '{"tokens": []}',
        '{"tokens": true}',
        '{"tokens": 1' + "0" * 400 + "}",
        '{"requests": -50}',
        '{"wall_s": NaN}',
    ],
    ids=["infinity", "list", "bool", "past-a-float", "negative", "nan"],
)
def test_a_spend_record_that_is_not_an_amount_is_corrupt(tmp_path: Path, spend: str) -> None:
    """`int()` of an infinity or of a list escaped as an OverflowError or a TypeError (a
    traceback and exit 1), an integer past a float did the same when the resume wrote its spend
    back, and a negative or NaN figure was taken as what the campaign had spent (2026-10-07)."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(_SET_COLUMN["spend_json"], (spend, run_id))
        store._conn.commit()

    with pytest.raises(ValueError, match="spend_json holds a value that is not"):
        execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])


@pytest.mark.parametrize(
    "runs",
    [
        '"runs":[],',
        '"runs":1e400,',
        '"runs":"sk-quoted-runs-value",',
        '"runs":true,',
        '"runs":1.9,',
        '"runs":0,',
        '"runs":null,',
        "",
    ],
    ids=[
        "list",
        "infinity",
        "text",
        "bool",
        "fraction",
        "zero",
        "null",
        "missing",
    ],
)
def test_a_stored_runs_value_that_is_not_a_count_is_corrupt(tmp_path: Path, runs: str) -> None:
    """`int()` of a list or an infinity was a traceback and exit 1, a string was quoted in the
    error, and `true` or `1.9` resumed at one run (pre-commit audit of the spend check). A null
    or a missing count, beside the target digest it is written with, resumed at this
    invocation's default and wrote it over the record (delta audit)."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        context = store.get_run_context(run_id)
        assert context is not None and context["runs"] == 3, "precondition: runs is recorded"
        raw = store._conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        assert '"runs":3,' in raw, "precondition: the stored form the replacement edits"
        store._conn.execute(_SET_COLUMN["context_json"], (raw.replace('"runs":3,', runs), run_id))
        store._conn.commit()

    for explicit in (False, True):  # inherited, and passed as --runs
        opts = _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100)
        opts.runs_explicit = explicit
        with pytest.raises(ValueError, match="context_json holds no runs value") as caught:
            execute_run(opts, [spec_dir])
        assert "sk-quoted" not in str(caught.value)


@pytest.mark.parametrize(("runs", "corrupt"), [(2**53, False), (2**53 + 1, True), (10**400, True)])
def test_a_stored_runs_count_is_read_up_to_the_flag_bound(
    tmp_path: Path, runs: int, corrupt: bool
) -> None:
    """Checked in the store, not through a resume: on ``2f6201a`` a resume of ``2**53 + 1``
    built a set of that many attempt ids per spec and was still growing at 3.7 GB when it was
    stopped after 4.5 minutes (A-55, OD-32), and one of 400 digits was an OverflowError in the
    plan, a traceback and exit 1. Through a resume, a regression could hang the suite."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        raw = store._conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        assert '"runs":3,' in raw, "precondition: the stored form the replacement edits"
        edited = raw.replace('"runs":3,', f'"runs":{runs},')
        store._conn.execute(_SET_COLUMN["context_json"], (edited, run_id))
        store._conn.commit()
        if corrupt:
            with pytest.raises(ValueError, match="context_json holds no runs value"):
                store.get_run_context(run_id)
        else:
            context = store.get_run_context(run_id)
            assert context is not None and context["runs"] == runs


def test_a_resume_of_the_largest_stored_count_checks_its_priors_without_building_the_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The halt path asked whether each started spec held every planned attempt by building the
    set of mutators x runs ids: with the `2**53` the store accepts, a resume grew without end
    (3.7 GB after 4.5 minutes on `2f6201a`, OD-32). The ids `attempt_id_for` builds are counted
    and stopped past 10,000, so a runner that builds the plan with it fails here at once instead
    of taking the machine with it (A-59); a plan written another way is not counted here."""

    import importlib

    import ildottore.core.runner as runner_mod
    from ildottore.core.reproduce import attempt_id_for

    calls = [0]

    def counting(spec_id: str, mutation: str, run_index: int) -> str:
        calls[0] += 1
        if calls[0] > 10_000:
            raise AssertionError("the runner built more than 10,000 planned attempt ids")
        return attempt_id_for(spec_id, mutation, run_index)

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        raw = store._conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        assert '"runs":3,' in raw, "precondition: the stored form the replacement edits"
        edited = raw.replace('"runs":3,', f'"runs":{2**53},')
        store._conn.execute(_SET_COLUMN["context_json"], (edited, run_id))
        store._conn.commit()
    # The runner, and anything that reaches the builder through its module: the resume's own
    # sends are a few hundred ids at most under this ceiling.
    monkeypatch.setattr(runner_mod, "attempt_id_for", counting, raising=False)
    monkeypatch.setattr(
        importlib.import_module("ildottore.core.reproduce"), "attempt_id_for", counting
    )

    outcome = execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])

    assert outcome.exit_code == ExitCode.ERROR, "the request ceiling halts the resume again"
    assert calls[0] < 10_000


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


def test_the_wall_ceiling_refusal_names_a_flag_dottore_run_accepts(tmp_path: Path) -> None:
    """The refusal told the operator to raise `--budget-wall-s`, and `dottore run` answers that
    with "No such option": the flag is `--budget-wall` (pre-commit audit of
    `fix/halt-reason-figures`, 2026-10-07).

    The advice is followed here as an operator would follow it. Every flag the refusal names is
    read from `dottore run`'s own parameters, not from a string copied into this test, and
    raising the flags it names past what the campaign spent lets the resume through.
    """

    import typer

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store.save_run_context(run_id, spend={"wall_s": 100000.0})
    resume = [
        "run",
        *("-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
        *("--spec-path", str(spec_dir), "--resume", run_id, "--budget-requests", "100"),
        *("--concurrency", "1", "-q", "--evidence-root", str(tmp_path / "ev")),
        *("--run-db", str(tmp_path / "runs.sqlite")),
    ]

    refused = CliRunner().invoke(app, resume)

    assert refused.exit_code == ExitCode.ERROR, (refused.exception, refused.stderr)
    errors = [line for line in refused.stderr.splitlines() if line.startswith("error:")]
    assert len(errors) == 1 and "wall-clock ceiling" in errors[0], refused.stderr
    named = set(LONG_OPTION.findall(errors[0]))
    assert named, f"the refusal names no flag to raise: {errors[0]}"
    run = typer.main.get_command(app).commands["run"]  # type: ignore[attr-defined]
    accepted = {opt for param in run.params for opt in (*param.opts, *param.secondary_opts)}
    assert named <= accepted, f"`dottore run` has no option {sorted(named - accepted)}"

    raised = CliRunner().invoke(
        app, [*resume, *(arg for f in sorted(named) for arg in (f, "200000"))]
    )

    assert "wall-clock ceiling" not in raised.stderr, raised.stderr
    assert raised.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}, (
        raised.exception,
        raised.stderr,
    )


# --- the third audit round (2026-09-23) ---------------------------------------------


def test_the_digest_covers_the_fields_that_gate_policy_and_feed_a_report() -> None:
    """The exclusion set, pinned by BEHAVIOUR, because the last fix to it never landed.

    A patch removed `tags` and `nist_ai_rmf` from the excluded set, matched the docstring,
    missed the constant (the formatter had reflowed it) and did not assert that replacement.
    The file shipped with a comment contradicting its own code, and the commit message
    described the comment. An audit found it by computing two digests.

    `tags` is what `policy/packs.py` reads for `layer_b` and `pii_elicitation`, so excluding it
    let a de-tagged spec become traffic on the wire under an unchanged digest, which is the DL4
    safety gate. `nist_ai_rmf` feeds a published rollup.
    """

    from ildottore.shared.digest import spec_digest

    base = make_spec("PI-DIRECT-001")
    assert spec_digest(base) != spec_digest(base.model_copy(update={"tags": ["layer_b"]}))
    assert spec_digest(base) != spec_digest(
        base.model_copy(update={"nist_ai_rmf": "GOVERN 1.1 (something else)"})
    )
    # `aisvs` is OUTSIDE: it feeds `dottore coverage`, never a run artifact. Inside, it made a
    # campaign halted before the AISVS mapping landed unresumable after it (measured 2026-10-03).
    assert spec_digest(base) == spec_digest(base.model_copy(update={"aisvs": ["v1.0-C2.1.6"]}))
    # And the cosmetic half still holds: an edited description does not refuse a resume.
    assert spec_digest(base) == spec_digest(
        base.model_copy(update={"description": "a clearer description of the same test"})
    )


def test_the_route_cannot_be_flipped_by_the_unverified_flag(tmp_path: Path) -> None:
    """`--resume-unverified` waives the battery and the spend. It may not waive the route.

    The target ID was made unwaivable and the target DIGEST was not, so one flag still reached
    the splice through a run row whose context column was absent: `--hardened` then flipped the
    offline replay and published one half's criticals as the other's.
    """

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute("UPDATE runs SET context_json = NULL WHERE run_id = ?", (run_id,))
        store._conn.commit()

    flipped = _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100, resume_unverified=True)
    flipped.targets = [write_target(tmp_path, mock_scenario="hardened")]
    with pytest.raises(ValueError, match=r"no flag for this|target and the route"):
        execute_run(flipped, [spec_dir])


@pytest.mark.parametrize(
    "context",
    [
        '{"runs": 3}',
        '{"target_digest": null}',
        '{"runs": null}',
        '{"target_digest": null, "runs": null}',
    ],
)
def test_a_context_row_missing_its_target_digest_refuses(tmp_path: Path, context: str) -> None:
    """A row that exists but carries no digest verified nothing, silently and with no notice.
    Without a digest, a missing or null count gets this refusal too, not the one about the
    count."""

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute("UPDATE runs SET context_json = ? WHERE run_id = ?", (context, run_id))
        store._conn.commit()

    with pytest.raises(ValueError, match=r"no flag for this|target and the route"):
        execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])


def test_the_probe_pass_is_debited_from_the_request_ceiling(tmp_path: Path) -> None:
    """`--budget-requests N` means N requests, probes included.

    They were recorded after the fact, which told the NEXT resume what had been spent and never
    stopped this invocation spending it: 17 probes plus a full N of attack traffic.
    """

    from ildottore.cli.run import fingerprint_probe_count

    ceiling = fingerprint_probe_count() + 3
    spec_dir = _specs(tmp_path)
    opts = _opts(tmp_path, spec_dir, fingerprint_first=True, budget_requests=ceiling)
    execute_run(opts, [spec_dir])

    run_ids = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        spend = store.get_run_spend(run_ids[0])

    assert spend is not None
    assert spend["requests"] <= ceiling, (
        f"the campaign spent {spend['requests']} requests against a ceiling of {ceiling}: the "
        "probe pass is not being debited"
    )


def test_a_resume_with_an_exhausted_ceiling_refuses_before_probing(tmp_path: Path) -> None:
    """Three sequential resumes used to run a whole probe pass each, past a spent ceiling."""

    from ildottore.cli.run import fingerprint_probe_count

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)

    sent: list[str] = []
    import ildottore.cli.wiring as wiring_mod

    original = wiring_mod.fingerprint_probe
    wiring_mod.fingerprint_probe = lambda *a, **k: sent.append("probe") or original(*a, **k)  # type: ignore[assignment,func-returns-value]
    try:
        with pytest.raises(ValueError, match="already spent"):
            execute_run(
                _opts(
                    tmp_path,
                    spec_dir,
                    resume=run_id,
                    budget_requests=_BUDGET + fingerprint_probe_count() - 1,
                    fingerprint_first=True,
                ),
                [spec_dir],
            )
    finally:
        wiring_mod.fingerprint_probe = original  # type: ignore[assignment]

    assert sent == []


def test_a_campaign_killed_mid_flight_can_still_be_resumed(tmp_path: Path) -> None:
    """The resume you most want after a crash used to be the one you could not have.

    Both halves of the run record were written when the campaign returned, so a run killed
    mid-flight (SIGKILL, a lost laptop, a CI timeout) left evidence on disk and no row, and the
    resume was refused outright because the target it belonged to could not be verified. The
    integrity half is known before the first request, so it is written first now.

    The spend of the dead half is recorded too since 2026-10-04: the runner hands it to the
    store however the campaign stops (it was lost, as a stated trade), and SIGTERM and SIGHUP
    are turned into Ctrl-C. A SIGKILL, which runs no code at all, still loses it.
    """

    from ildottore.core.runner import CampaignRunner

    spec_dir = _specs(tmp_path)
    opts = _opts(tmp_path, spec_dir, budget_requests=100)

    # A campaign that dies after sending, exactly where a crash hurts: evidence on disk, no
    # result returned, nothing written afterwards.
    original = CampaignRunner.run

    async def _die(self: CampaignRunner, **kwargs: object) -> None:
        await original(self, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt("the laptop closed")

    CampaignRunner.run = _die  # type: ignore[assignment,method-assign]
    try:
        with pytest.raises(KeyboardInterrupt):
            execute_run(opts, [spec_dir])
    finally:
        CampaignRunner.run = original  # type: ignore[method-assign]

    run_ids = [p.name for p in (tmp_path / "ev").iterdir() if p.is_dir()]
    assert len(run_ids) == 1, "precondition: the dead campaign left evidence"
    run_id = run_ids[0]

    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        assert store.get_run_context(run_id) is not None, (
            "the integrity record must exist before the campaign returns, or a crashed run is "
            "unresumable by construction"
        )
        spend = store.get_run_spend(run_id)
        assert spend is not None and spend["requests"] > 0, "the dead half's spend is recorded"

    outcome = execute_run(_opts(tmp_path, spec_dir, resume=run_id, budget_requests=100), [spec_dir])
    assert outcome.exit_code in {ExitCode.FINDINGS_AT_OR_ABOVE, ExitCode.FINDINGS_BELOW}


def test_a_live_run_without_a_judge_says_so_before_sending() -> None:
    """R13 (audit 2026-10-03): 74 of 75 specs use semantic_judge; a live deep run without one
    ended pass 1, fail 0, inconclusive 74, exit 0, and nothing said why."""

    from ildottore.cli import wiring
    from ildottore.cli.run import _no_judge_warning

    repo = Path(__file__).resolve().parents[2]
    spec = next(
        s for s in wiring.build_registry([repo / "specs"]).list() if s.id == "PI-DIRECT-001"
    )
    from types import SimpleNamespace

    target = SimpleNamespace(id="t")
    plans = [SimpleNamespace(target=target, selected=[spec])]
    live = [("t.yaml", target, (None, object()))]
    offline = [("t.yaml", target, ("hardened", None))]
    assert any(e.type.value == "semantic_judge" for e in spec.evaluators)
    message = _no_judge_warning(plans, live, None)  # type: ignore[arg-type]
    assert message is not None and "--judge" in message
    assert _no_judge_warning(plans, offline, None) is None  # type: ignore[arg-type]
    assert _no_judge_warning(plans, live, object()) is None  # type: ignore[arg-type]
