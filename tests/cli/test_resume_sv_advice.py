"""A refused ``--resume -sV`` gives only advice that lets the resume through (u12 A-48).

The refusal for a request ceiling that cannot hold the probe pass said "Raise
--budget-requests, or drop -sV", and it ran before the check of the campaign's planning mode.
Each half was right for one kind of campaign only (pre-commit audit of
``fix/resume-wall-flag-name``, 2026-10-07, measured on ``0501752``):

* a campaign halted WITHOUT ``-sV``: raising the ceiling was refused again, "halted with
  adaptive planning off and this invocation asks for on"; only dropping ``-sV`` went through;
* a campaign halted WITH ``-sV`` (or ``--deep``): dropping ``-sV`` was refused again, "halted
  with adaptive planning on and this invocation asks for off"; only raising went through.

Every test here follows every piece of advice the refusal gives, as an operator would, through
the CLI, and asserts that each one is a resume that goes through, not a second refusal. The
advice is read off the message with the grammar below, and each test pins the pieces it expects;
a flag named in the sentence of the advice that the grammar does not turn into an invocation
fails the test. Not read: a piece written as a sentence of its own ahead of the advice (third
audit round). "Goes through" is measured on the offline mock, where the plan prices every
request; retries are not priced (u12 A-48); the identity sweep is, since A-34 (u08).
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.run import fingerprint_probe_count
from ildottore.fingerprint import FingerprintEngine
from ildottore.shared.models import ModelFingerprint, ModelRequest
from ildottore.shared.protocols import TargetAdapter
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_scope, write_spec_tree, write_target

PROBES = fingerprint_probe_count()
#: Three specs at --runs 3 are nine attack requests: a ceiling of 6 halts the campaign.
HALT = 6

_FLAG = r"(?:--[a-z][\w-]*|-sV|-A)"
_FLAGS = re.compile(rf"(?<![\w-]){_FLAG}(?![\w-])")
#: The advice forms these refusals use. "resume with" lists alternatives (one invocation each);
#: "drop" and "resume without" remove every listed flag the invocation gave.
_ADVICE = re.compile(
    rf"\b(raise|drop|resume without|resume with)\s+({_FLAG}(?:(?:,\s*|\s+(?:and|or)\s+){_FLAG})*)",
    re.IGNORECASE,
)
_GOES_THROUGH = {ExitCode.CLEAN, ExitCode.FINDINGS_BELOW, ExitCode.FINDINGS_AT_OR_ABOVE}


def _base(tmp_path: Path, runs: str | None = "3") -> list[str]:
    state = tmp_path / "state"
    return [
        "run",
        *("-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
        *("--spec-path", str(tmp_path / "specs"), "--concurrency", "1", "-q"),
        *(("--runs", runs) if runs is not None else ()),
        *("--evidence-root", str(state / "ev"), "--run-db", str(state / "runs.sqlite")),
    ]


def _setup(tmp_path: Path, specs: int = 3) -> None:
    write_target(tmp_path, mock_scenario="vulnerable")
    write_scope(tmp_path)
    write_spec_tree(tmp_path, [make_spec(f"PI-DIRECT-{i:03d}") for i in range(1, specs + 1)])


def _errors(result: object) -> list[str]:
    stderr: str = getattr(result, "stderr", "")
    return [line for line in stderr.splitlines() if line.startswith("error:")]


def _halt(tmp_path: Path, *flags: str) -> str:
    """Run until the request ceiling halts the campaign; return its run id."""

    result = CliRunner().invoke(app, [*_base(tmp_path), *flags])
    assert result.exit_code == ExitCode.ERROR, (result.exception, result.stderr)
    assert "budget ceiling reached" in result.stderr, result.stderr
    runs = [p.name for p in (tmp_path / "state" / "ev").iterdir() if p.is_dir()]
    assert len(runs) == 1, runs
    return runs[0]


def _advice(error: str) -> list[tuple[str, list[str]]]:
    """Each piece of advice in ``error``: its verb and the flags it names."""

    found = list(_ADVICE.finditer(error))
    assert found, f"the refusal gives no advice to follow: {error}"
    pieces = [(m.group(1).lower(), _FLAGS.findall(m.group(2))) for m in found]
    # From the start of the sentence the first piece is in, so a piece written ahead of it in
    # words the grammar does not read ("Lower --concurrency, or raise ...") is still seen.
    sentence = error.rfind(". ", 0, found[0].start())
    named = set(_FLAGS.findall(error[sentence + 2 if sentence >= 0 else 0 :]))
    advised = {flag for _, flags in pieces for flag in flags}
    assert named == advised, f"advice this test cannot follow: {sorted(named - advised)}: {error}"
    return pieces


def _followed(argv: list[str], verb: str, flags: list[str]) -> Iterator[list[str]]:
    """The invocations an operator gets by following one piece of advice."""

    if verb == "raise":
        raised = list(argv)
        for flag in flags:
            if flag in raised:
                raised[raised.index(flag) + 1] = "500"
            else:
                raised += [flag, "500"]
        yield raised
    elif verb == "resume with":
        for flag in flags:
            assert flag not in argv, f"the advice adds {flag}, which was given: {argv}"
            yield [*argv, flag]
    else:
        given = [flag for flag in flags if flag in argv]
        assert given, f"the advice drops {flags}, none of which was given: {argv}"
        yield [arg for arg in argv if arg not in given]


Piece = tuple[str, tuple[str, ...]]
RAISE: Piece = ("raise", ("--budget-requests",))
DROP: Piece = ("drop", ("-sV",))
WITHOUT: Piece = ("resume without", ("-sV", "-A", "--deep"))
WITH: Piece = ("resume with", ("-sV", "-A", "--deep"))


def _follow_every_piece(tmp_path: Path, argv: list[str], expected: set[Piece]) -> list[str]:
    """Invoke ``argv``, which is refused, check that its advice is ``expected``, then follow
    each piece from the same state; return the refusal. Each followed invocation must go through.

    The advice is pinned as well as followed: the grammar reads only the verbs it knows, so a
    piece worded otherwise ("Increase --budget-requests", "Raise the ceiling") would otherwise
    go unread and unfollowed (pre-commit audit of u12 A-48)."""

    state = tmp_path / "state"
    snapshot = tmp_path / "snapshot"
    shutil.copytree(state, snapshot)
    refused = CliRunner().invoke(app, argv)
    errors = _errors(refused)
    assert refused.exit_code == ExitCode.ERROR and len(errors) == 1, (
        refused.exception,
        refused.stderr,
    )
    pieces = _advice(errors[0])
    assert {(verb, tuple(flags)) for verb, flags in pieces} == expected, errors[0]
    followed = 0
    for verb, flags in pieces:
        for invocation in _followed(argv, verb, flags):
            shutil.rmtree(state)
            shutil.copytree(snapshot, state)
            result = CliRunner().invoke(app, invocation)
            assert result.exit_code in _GOES_THROUGH and not _errors(result), (
                f"following '{verb} {', '.join(flags)}' of: {errors[0]}",
                invocation[len(_base(tmp_path)) :],
                result.exception,
                _errors(result),
            )
            followed += 1
    assert followed, errors[0]
    return errors


@pytest.mark.parametrize(
    ("halted_with", "resumed_with", "expected"),
    [
        # Raising the ceiling was refused again: the campaign ran without adaptive planning.
        (
            ["--budget-requests", str(HALT)],
            ["-sV", "--budget-requests", str(HALT + PROBES - 1)],
            {WITHOUT},
        ),
        # Dropping -sV was refused again: the campaign ran with adaptive planning.
        (
            ["-sV", "--budget-requests", str(PROBES + HALT)],
            ["-sV", "--budget-requests", str(PROBES + HALT + PROBES - 1)],
            {RAISE},
        ),
        # --deep turns adaptive planning on too, so dropping -sV was refused here as well.
        (
            ["--deep", "--budget-requests", str(HALT)],
            ["-sV", "--budget-requests", str(HALT + PROBES - 1)],
            {RAISE},
        ),
        # The other way round: the campaign ran with -sV and the resume left it out. The
        # refusal named no flag; the ceiling is ample, so -sV is a resume that goes through.
        (["-sV", "--budget-requests", str(PROBES + HALT)], ["--budget-requests", "500"], {WITH}),
    ],
    ids=["halted-without-sV", "halted-with-sV", "halted-with-deep", "resumed-without-sV"],
)
def test_every_piece_of_advice_a_refused_sv_resume_gives_goes_through(
    tmp_path: Path, halted_with: list[str], resumed_with: list[str], expected: set[Piece]
) -> None:
    _setup(tmp_path)
    run_id = _halt(tmp_path, *halted_with)

    _follow_every_piece(tmp_path, [*_base(tmp_path), "--resume", run_id, *resumed_with], expected)


def _forget(tmp_path: Path, run_id: str, *, mode: bool = False, spend: bool = False) -> None:
    """Make the run row one written before the planning mode, or the spend, was recorded."""

    with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
        if mode:
            context = store.get_run_context(run_id) or {}
            del context["adaptive"]
            store._conn.execute(
                "UPDATE runs SET context_json = ? WHERE run_id = ?", (json.dumps(context), run_id)
            )
        if spend:
            store._conn.execute("UPDATE runs SET spend_json = NULL WHERE run_id = ?", (run_id,))
        store._conn.commit()


@pytest.mark.parametrize(
    ("ceiling", "expected"),
    [
        (PROBES + HALT + PROBES - 1, {RAISE, DROP}),
        # 23 spent and 3 requests of the campaign left: 26 is the least that holds them.
        (PROBES + HALT + 3, {RAISE, DROP}),
        # One short of that, at the spend, and below it: dropping -sV resumed into a halt
        # (exit 3) that kept nothing, so it is not offered (pre-commit and delta audits).
        (PROBES + HALT + 2, {RAISE}),
        (PROBES + HALT, {RAISE}),
        (PROBES + HALT - 3, {RAISE}),
    ],
    ids=["ample", "rest-just-fits", "one-short", "at-the-spend", "spent-past-the-ceiling"],
)
def test_a_campaign_that_recorded_no_planning_mode_may_drop_sv_when_it_helps(
    tmp_path: Path, ceiling: int, expected: set[Piece]
) -> None:
    """A run row whose context lacks the planning mode is not bound to one, so dropping -sV is
    offered, as long as the ceiling leaves the attack traffic anything."""

    _setup(tmp_path)
    run_id = _halt(tmp_path, "-sV", "--budget-requests", str(PROBES + HALT))
    _forget(tmp_path, run_id, mode=True)

    _follow_every_piece(
        tmp_path,
        [*_base(tmp_path), "--resume", run_id, "-sV", "--budget-requests", str(ceiling)],
        expected,
    )


@pytest.mark.parametrize("mode", [True, False], ids=["adaptive-campaign", "no-recorded-mode"])
def test_the_preflight_of_a_resume_with_no_recorded_spend_gives_advice_that_goes_through(
    tmp_path: Path, mode: bool
) -> None:
    """With no spend on record the resume's pre-check has nothing to add the probes to, and the
    `--budget-requests` pre-flight refuses instead. No test followed its advice on a resume, and
    a mutant that offered "drop -sV" to every campaign there survived (pre-commit audit)."""

    _setup(tmp_path)
    run_id = _halt(tmp_path, "-sV", "--budget-requests", str(PROBES + HALT))
    _forget(tmp_path, run_id, mode=not mode, spend=True)

    errors = _follow_every_piece(
        tmp_path,
        [*_base(tmp_path), "--resume", run_id, "-sV", "--budget-requests", str(PROBES - 1)],
        {RAISE} if mode else {RAISE, DROP},
    )

    assert "more than the --budget-requests ceiling" in errors[0], errors[0]


class _RetryingEngine:
    """A fingerprint engine whose pass costs three requests more than its probes, as retries
    do: the real ledger counts them, so the real ceiling stops the pass."""

    def __init__(self, engine: FingerprintEngine) -> None:
        self._engine = engine

    def __getattr__(self, name: str) -> object:
        return getattr(self._engine, name)

    async def run(self, adapter: TargetAdapter) -> ModelFingerprint:
        for _ in range(3):
            await adapter.send(ModelRequest(prompt="the same probe, sent again"))
        return await self._engine.run(adapter)


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("fresh", {RAISE, DROP}),
        ("resumed", {RAISE}),
        # The pass's sends are recorded and fill the ceiling: dropping -sV halts at once.
        ("resumed-no-recorded-mode", {RAISE}),
        # No spend on record: the ceiling covers this invocation alone and holds the rest.
        ("resumed-no-recorded-spend", {RAISE, DROP}),
        # Seven specs are 21 requests of attack traffic, past the ceiling of 19 the pass met.
        ("fresh-battery-past-the-ceiling", {RAISE}),
    ],
    ids=[
        "fresh",
        "resumed",
        "resumed-no-recorded-mode",
        "resumed-no-recorded-spend",
        "fresh-battery-past-the-ceiling",
    ],
)
def test_a_probe_pass_stopped_by_the_ceiling_gives_advice_that_goes_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, expected: set[Piece]
) -> None:
    """Retries count as requests, so a pass can reach the ceiling after the pre-flight let it
    start. That refusal also said "drop -sV", which a campaign with adaptive planning refuses."""

    original = wiring.build_fingerprint_engine
    monkeypatch.setattr(wiring, "build_fingerprint_engine", lambda: _RetryingEngine(original()))
    _setup(tmp_path, specs=7 if case == "fresh-battery-past-the-ceiling" else 3)
    if case.startswith("resumed"):
        # The pre-flight lets the 17 probes start (23 + 17 <= 41, or 17 <= 19 with no spend on
        # record); their 20 requests do not fit.
        run_id = _halt(tmp_path, "-sV", "--budget-requests", str(PROBES + 3 + 3))
        no_spend = case == "resumed-no-recorded-spend"
        _forget(tmp_path, run_id, mode=case != "resumed", spend=no_spend)
        ceiling = str(PROBES + 2) if no_spend else "41"
        argv = [*_base(tmp_path), "--resume", run_id, "-sV", "--budget-requests", ceiling]
    else:
        (tmp_path / "state").mkdir()
        argv = [*_base(tmp_path), "-sV", "--budget-requests", str(PROBES + 2)]

    errors = _follow_every_piece(tmp_path, argv, expected)

    assert "reached the --budget-requests ceiling" in errors[0], errors[0]


@pytest.mark.parametrize(
    ("ceiling", "expected"),
    [
        (PROBES - 1, {RAISE, DROP}),
        # Nine requests of attack traffic: 9 holds them.
        (9, {RAISE, DROP}),
        # A ceiling below them halts a run without -sV too (at 0, before its first request),
        # so dropping -sV is not offered (delta audit).
        (8, {RAISE}),
        (0, {RAISE}),
    ],
    ids=["ample", "attack-just-fits", "one-short", "zero"],
)
def test_a_fresh_run_whose_ceiling_cannot_hold_the_probe_pass(
    tmp_path: Path, ceiling: int, expected: set[Piece]
) -> None:
    """No campaign to stay the same as: dropping -sV is offered when the battery fits."""

    _setup(tmp_path)
    (tmp_path / "state").mkdir()

    _follow_every_piece(
        tmp_path, [*_base(tmp_path), "-sV", "--budget-requests", str(ceiling)], expected
    )


def test_the_ceilings_a_resume_is_refused_against_are_the_campaigns_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The provisional plan behind the refusals was resolved before the resume inherited the
    campaign's --runs, so its derived ceiling was this invocation's: a campaign run at --runs 20
    (3,300 requests derived for the shipped battery) was refused against 2,000 (pre-commit
    audit of u12 A-48). The floor is lowered so three specs derive a ceiling of their own."""

    from ildottore.core.planner import DEFAULT_PLAN_BUDGETS

    monkeypatch.setattr(
        "ildottore.cli.run.DEFAULT_PLAN_BUDGETS",
        DEFAULT_PLAN_BUDGETS.model_copy(update={"max_requests": 10}),
    )
    _setup(tmp_path)
    # 60 requests of attack traffic at --runs 20: the ceiling halts it after 17 probes, the
    # first spec's 20 attempts (a batch cut short stores nothing on 0501752) and 5 more.
    halted = CliRunner().invoke(
        app, [*_base(tmp_path, runs="20"), "-sV", "--budget-requests", str(PROBES + 25)]
    )
    assert "budget ceiling reached" in halted.stderr, halted.stderr
    run_id = next(p.name for p in (tmp_path / "state" / "ev").iterdir() if p.is_dir())

    # Derived at --runs 20 the ceiling is 90 (60 x 1.5), which holds 42 spent + 17 probes; at the
    # invocation's default of 5 it was 22, and the resume was refused.
    estimate = CliRunner().invoke(
        app, [*_base(tmp_path, runs=None), "--resume", run_id, "-sV", "--estimate"]
    )

    assert estimate.exit_code == ExitCode.CLEAN and not _errors(estimate), estimate.stderr
    assert "continuing at --runs 20" in estimate.stderr, estimate.stderr


def _journal(tmp_path: Path) -> list[tuple[str, ...]]:
    with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
        rows = store._conn.execute("SELECT spec_id, sha256, state FROM artifacts ORDER BY sha256")
        return [tuple(row) for row in rows.fetchall()]


@pytest.mark.parametrize(
    "refusal", ["request ceiling", "wall-clock ceiling", "more than the --budget-requests"]
)
def test_a_resume_refused_for_money_leaves_the_journal_as_it_found_it(
    tmp_path: Path, refusal: str
) -> None:
    """The campaign checks now come before the money checks, and they read the evidence the
    resume adopts into the artifact journal. The adoption waits until nothing is left to
    refuse: a refused resume used to write nothing, and still writes nothing."""

    _setup(tmp_path)
    run_id = _halt(tmp_path, "-sV", "--budget-requests", str(PROBES + HALT))
    with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
        store._conn.execute("DELETE FROM artifacts")  # as a run written before the journal
        store._conn.commit()
        spent = store.get_run_spend(run_id)
    halted = {path.stem for path in (tmp_path / "state" / "ev" / run_id / "attempts").glob("*")}
    resume = [*_base(tmp_path), "--resume", run_id, "-sV"]
    if refusal == "wall-clock ceiling":
        with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
            store.save_run_context(run_id, spend={"wall_s": 100000.0})
            spent = store.get_run_spend(run_id)
        refused_argv = [*resume, "--budget-requests", "500", "--budget-wall", "1800"]
    elif refusal.startswith("more than"):
        # No spend on record (a run from before it was recorded): the resume's pre-check has
        # nothing to add the probes to, and the pre-flight against the bare ceiling refuses.
        with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
            store._conn.execute("UPDATE runs SET spend_json = NULL WHERE run_id = ?", (run_id,))
            store._conn.commit()
            spent = store.get_run_spend(run_id)
        refused_argv = [*resume, "--budget-requests", str(PROBES - 1)]
    else:
        refused_argv = [*resume, "--budget-requests", str(PROBES + HALT + PROBES - 1)]

    refused = CliRunner().invoke(app, refused_argv)

    assert refused.exit_code == ExitCode.ERROR and refusal in refused.stderr, refused.stderr
    assert _journal(tmp_path) == [], "a refused resume adopted the evidence into the journal"
    with SqliteRunStore(tmp_path / "state" / "runs.sqlite") as store:
        assert store.get_run_spend(run_id) == spent
    went_through = CliRunner().invoke(
        app, [*resume, "--budget-requests", "500", "--budget-wall", "200000"]
    )
    assert went_through.exit_code in _GOES_THROUGH, went_through.stderr
    # By digest: the resume journals the attempts it sends itself, so a count of rows passes
    # with no adoption at all.
    written = {sha for _, sha, state in _journal(tmp_path) if state == "written"}
    assert halted and halted <= written, "the resume that goes through adopts what it resumed from"
