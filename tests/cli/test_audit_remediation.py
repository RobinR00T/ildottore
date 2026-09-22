"""The audit findings, pinned as tests (2026-09-21).

Four adversarial audits found defects that CI could not see, because CI checked that the code
worked and not that **what it claimed was true**. Every test here asserts a claim against the
thing it claims about: a printed count against a real send count, an exit code against a run
that did not finish, an accepted framework code against the universe it is measured with.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.adapters.base import EndpointNotAllowed
from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.run import (
    RunOptions,
    budgets_for,
    estimate_plan,
    execute_run,
)
from ildottore.core.planner import DEFAULT_PLAN_BUDGETS
from ildottore.policy.errors import ScopeError
from ildottore.reporting.summary import pct_display
from ildottore.shared.enums import RequiresCapability
from ildottore.shared.models import PlanBudgets

from .conftest import make_spec, write_scope, write_spec_tree, write_target

runner = CliRunner()

SHIPPED_SPECS = Path("specs")


def _opts(tmp_path: Path, target: Path, scope: Path, **kw: object) -> RunOptions:
    opts = RunOptions(
        targets=[target],
        scope=scope,
        runs=1,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
    )
    for key, value in kw.items():
        setattr(opts, key, value)
    return opts


# --- #1 CRITICAL: the battery did not fit its own budget, and said nothing ----------


def test_shipped_battery_fits_the_budget_derived_from_its_plan() -> None:
    """The default battery must fit the ceilings a default run gives it.

    It did not. ``DEFAULT_PLAN_BUDGETS.max_tokens`` was a constant 500_000 while the default
    plan needed about 537_000, so a plain ``dottore run`` halted roughly two thirds of the
    way through, marked itself ``budget_exhausted`` internally, and reported the truncated
    campaign as a clean one. A constant ceiling drifts as the battery grows; a ceiling
    derived from the reviewed plan does not, and still bounds the run.
    """

    registry = wiring.build_registry([SHIPPED_SPECS])
    estimate = estimate_plan(list(registry.list()), runs=5)
    budgets = budgets_for(estimate)

    assert estimate.total_tokens <= (budgets.max_tokens or 0)
    assert estimate.requests <= (budgets.max_requests or 0)
    # And the derived ceiling is never LOWER than the conservative floor.
    assert (budgets.max_tokens or 0) >= (DEFAULT_PLAN_BUDGETS.max_tokens or 0)


def test_budgets_stretch_the_wall_clock_to_fit_a_slow_rate() -> None:
    """A deliberately slow ``--rate`` must not be killed by the wall-clock ceiling.

    Obeying one flag must not break another: with pacing now enforced, 600 requests at
    0.5 req/s take twenty minutes, which the default 1800s wall budget would cut short.
    """

    estimate = estimate_plan([make_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 60)], runs=10)
    slow = budgets_for(estimate, rate_rps=0.5)
    assert (slow.max_wall_s or 0) >= estimate.requests / 0.5


def test_a_truncated_run_exits_three_and_the_report_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A budget halt reaches the exit code, the terminal and the report.

    Reproduces the audit's finding end to end with a ceiling too small for the battery: the
    run used to print ``total: 45, run: 45`` (100% of itself), exit 0, and compute every
    coverage percentage over the subset that survived.
    """

    monkeypatch.setattr(
        run_mod, "budgets_for", lambda *a, **k: PlanBudgets(max_requests=2, max_tokens=10_000)
    )
    target = write_target(tmp_path, mock_scenario="vulnerable")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 7)])
    report = tmp_path / "report.json"
    opts = _opts(tmp_path, target, scope, outputs={"json": report})

    outcome = execute_run(opts, [specs])

    assert outcome.exit_code is ExitCode.ERROR
    assert outcome.incomplete, "a truncated run must be reported as incomplete"
    assert "budget ceiling reached" in next(iter(outcome.incomplete.values()))

    doc = json.loads(report.read_text(encoding="utf-8"))
    status = doc["summary"]["status"]
    assert status["state"] == "budget_exhausted"
    assert status["complete"] is False
    specs_block = doc["summary"]["coverage"]["specs"]
    assert specs_block["total"] > specs_block["run"], (
        "the denominator must be what was planned, not what survived"
    )


# --- #4 / #3: flags that were parsed and never read --------------------------------


def test_compare_without_two_targets_is_refused(tmp_path: Path) -> None:
    """``--compare`` renders a matrix across targets, so one target is a mistake, not a run."""

    target = write_target(tmp_path)
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    with pytest.raises(ValueError, match="two or more targets"):
        execute_run(_opts(tmp_path, target, scope, compare=True), [specs])


def test_rate_is_not_applied_to_an_offline_mock_but_is_declared(tmp_path: Path) -> None:
    """``--rate`` on an offline run is ignored, and the plan says so rather than pretending.

    Pacing protects a real endpoint; a mock run sends nothing. The flag used to be dropped in
    every case with no trace: ``--rate 0.0001`` (one request per 10_000s) finished eighteen
    specs in 0.67s.
    """

    target = write_target(tmp_path, mock_scenario="vulnerable")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--rate",
            "0.25",
            "--dry-run",
        ],
    )
    assert res.exit_code == 0
    assert "pacing:  not applied (0.25 req/s requested)" in res.output


# --- #9 / F3 / #7: refusals that used to be clean or misleading exits --------------


def test_an_empty_selection_is_refused(tmp_path: Path) -> None:
    """A ``--spec`` typo used to run nothing and exit 0: a green gate over an empty battery."""

    target = write_target(tmp_path)
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    with pytest.raises(ValueError, match="matched no specs"):
        execute_run(_opts(tmp_path, target, scope, spec_globs=["NOPE-*"]), [specs])


def test_malformed_target_yaml_is_a_value_error(tmp_path: Path) -> None:
    """A YAML syntax error must be a ``ValueError`` (exit 3), not an uncaught ``YAMLError``.

    ``yaml.YAMLError`` does not derive from ``ValueError``, so it escaped the CLI handler and
    surfaced as a traceback with exit **1**, which in this tool means "findings below the
    threshold" - and it did so in ``--dry-run``/``--estimate``, whose only job is validation.
    """

    bad = tmp_path / "target.yaml"
    bad.write_text("id: x\ntype: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        wiring.load_target(bad)


def test_malformed_target_yaml_exits_three_from_the_cli(tmp_path: Path) -> None:
    bad = tmp_path / "target.yaml"
    bad.write_text("id: x\ntype: [unclosed\n", encoding="utf-8")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(
        app,
        ["run", "-t", str(bad), "--scope", str(scope), "--spec-path", str(specs), "--dry-run"],
    )
    assert res.exit_code == 3
    assert "not valid YAML" in res.output


def test_adapter_error_exits_three_not_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``EndpointNotAllowed`` is an authorization failure: exit 3, not the findings-ish 1.

    It derives from ``AdapterError(Exception)``, outside the handler's ``(PolicyError,
    ValueError, OSError)`` tuple, so a refused endpoint used to reach the user as a traceback
    with exit 1 - a code a CI step may well treat as "carry on".
    """

    def _boom(*_a: object, **_k: object) -> None:
        raise EndpointNotAllowed("endpoint 'https://evil.example/v1' not on allowlist")

    monkeypatch.setattr(run_mod, "execute_run", _boom)
    target = write_target(tmp_path)
    scope = write_scope(tmp_path)
    res = runner.invoke(app, ["run", "-t", str(target), "--scope", str(scope)])
    assert res.exit_code == 3
    assert "not on allowlist" in res.output


# --- F1 / F2: the authorization gate ------------------------------------------------


def test_scope_entry_without_endpoints_is_refused(tmp_path: Path) -> None:
    """Membership is not reachability: an entry with an empty allowlist is not authorized.

    ``ScopeTarget.endpoints`` defaults to ``[]``, and the pre-flight gate used to ask only
    whether the id was present, so this scope passed it and every attempt was then denied by
    the engine - the run of unexplained inconclusives the gate exists to prevent.
    """

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\n'
        "targets:\n"
        "  - id: mock-target\n"
        '    base_url: "mock://mock-target"\n'
        # No `endpoints:` at all. The field defaults to an empty list, i.e. authorize
        # nothing, which is exactly the shape a typo in `host` also produces.
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://MOCK_KEY"\n',
        encoding="utf-8",
    )
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    with pytest.raises(ScopeError, match="not on allowlist"):
        execute_run(_opts(tmp_path, target, scope), [specs])


def test_an_unauthorized_judge_is_refused(tmp_path: Path) -> None:
    """The ``--judge`` model goes through the same gate as an attack target.

    It was loaded and never checked. With the judge missing from the scope (which is what
    ``fleet --judge`` generated), every ``semantic_judge`` verdict came back inconclusive for
    lack of authorization, the reason went only into the JSON, and the run exited 0.
    """

    target = write_target(tmp_path)
    scope = write_scope(tmp_path)
    judge_dir = tmp_path / "judge"
    judge_dir.mkdir()
    judge = write_target(judge_dir, target_id="judge-model")
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    with pytest.raises(ScopeError, match="judge-model"):
        execute_run(_opts(tmp_path, target, scope, judge=judge), [specs])


def test_fingerprint_refuses_a_target_outside_the_scope(tmp_path: Path) -> None:
    """``dottore fingerprint`` loaded the scope and discarded it (no id, no endpoint check)."""

    target = write_target(tmp_path, target_id="not-in-scope")
    scope = write_scope(tmp_path, target_id="some-other-target")
    res = runner.invoke(app, ["fingerprint", str(target), "--scope", str(scope)])
    assert res.exit_code == 3
    assert "not authorized by the scope" in res.output


# --- #12 and the percentage display ------------------------------------------------


def test_estimate_counts_the_implicit_identity_mutator() -> None:
    """A spec declaring one mutation runs TWO attempts: the planner prepends ``identity``.

    The estimate used ``len(spec.mutations or ["identity"])``, so it under-counted every spec
    that declared mutations without repeating the baseline carrier.
    """

    spec = make_spec("PI-DIRECT-001").model_copy(update={"mutations": ["base64"]})
    assert estimate_plan([spec], runs=1).requests == 2


@pytest.mark.parametrize(
    ("exercised", "total", "expected"),
    [
        (199, 200, "99%"),  # "%.0f" would print 100 here
        (200, 200, "100%"),
        (0, 200, "0%"),
        (1, 3, "33%"),
        (0, 0, "0%"),
    ],
)
def test_pct_display_never_rounds_up_to_complete(exercised: int, total: int, expected: str) -> None:
    assert pct_display(exercised, total) == expected


# --- the second audit round (2026-09-21, on this very branch) -----------------------


def test_the_planned_denominator_is_never_smaller_than_the_numerator(tmp_path: Path) -> None:
    """ "Specs run: 72 of 70 planned" is 102.9%, and it shipped in the first fix.

    The denominator counted ``selected + capability-skipped`` and left out the
    policy-blocked specs, whose findings stayed in the numerator. Both kinds of spec DO
    produce a finding (they are reported, not dropped), so the denominator is the whole
    selected battery.
    """

    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    report = tmp_path / "r.json"
    opts = _opts(tmp_path, target, scope, outputs={"json": report})

    outcome = execute_run(opts, [SHIPPED_SPECS])

    assert outcome.exit_code in (ExitCode.CLEAN, ExitCode.FINDINGS_BELOW)
    specs = json.loads(report.read_text(encoding="utf-8"))["summary"]["coverage"]["specs"]
    assert specs["run"] <= specs["total"]
    assert specs["run"] == specs["total"], "a complete run tested everything it planned"


def test_off_universe_values_are_reported_not_just_dropped(tmp_path: Path) -> None:
    """A run does not lint, so a dropped framework value has to be announced.

    A third-party pack can be measured without ever being linted: `dottore coverage` used to
    report an unchanged numerator over a larger spec count with no warning at all, which is
    the silent-shrink failure mode the axis exists to prevent.
    """

    from ildottore.cli.coverage import battery_coverage, render_coverage

    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text(
        "id: offpack\npack_version: '1.0'\nname: offpack\n", encoding="utf-8"
    )
    spec = make_spec("OFF-UNIVERSE-001").model_copy(update={"owasp": "LLM11"})
    (pack / "attacks" / "off.yaml").write_text(spec.model_dump_json(indent=2), encoding="utf-8")

    coverage = battery_coverage([pack])
    assert coverage.off_universe == (("OFF-UNIVERSE-001", "owasp", "LLM11"),)
    rendered = render_coverage(coverage, show_gaps=False)
    assert "WARNING" in rendered
    assert "LLM11" in rendered


def test_every_axis_label_names_its_edition() -> None:
    """A percentage whose taxonomy version is unstated cannot be checked by its reader.

    The first fix labelled the OWASP and ATLAS axes and left the two IoPC axes bare, in the
    one command written to be interrogable, while `shared/iopc.py` spends a paragraph
    explaining that the obvious label denotes a different 46-entry set.
    """

    from ildottore.cli.coverage import battery_coverage
    from ildottore.shared.frameworks import ATLAS_MATRIX_RELEASE, OWASP_LLM_EDITION
    from ildottore.shared.iopc import IOPC_TAXONOMY_VERSION

    labels = {a.key: a.label for a in battery_coverage([SHIPPED_SPECS]).axes}
    assert OWASP_LLM_EDITION in labels["owasp"]
    assert ATLAS_MATRIX_RELEASE in labels["atlas"]
    assert IOPC_TAXONOMY_VERSION in labels["iopc_techniques"]
    assert IOPC_TAXONOMY_VERSION in labels["iopc_impacts"]


def test_the_coverage_command_floors_its_percentages_like_every_other_surface() -> None:
    """One figure, one value. `dottore coverage` printed 96% where the run printed 95%."""

    from ildottore.cli.coverage import battery_coverage, render_coverage

    # The witness moved on 2026-09-22: the impact axis reached 23/23, so the fractional axis
    # that proves flooring is now ATLAS at 13/16 = 81.25%, which must print 81 and not 82.
    # The original witness was 22/23 = 95.65%, printed as 96% by this command and 95% by every
    # other surface.
    rendered = render_coverage(battery_coverage([SHIPPED_SPECS]), show_gaps=False)
    assert "13/16" in rendered
    assert "81%" in rendered
    assert "82%" not in rendered


# --- the second audit round: the sends, the clock, and the ceilings -----------------


def test_dry_run_with_sv_sends_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``--dry-run -sV`` printed "sent nothing" after posting ten live probes.

    Fingerprinting SENDS. The guard excluded ``-sn`` only, so the two commands that promise
    zero egress broke that promise the moment they were combined with the flag that
    fingerprints, and ``--quick --dry-run`` is the first command the README teaches.
    """

    probes: list[str] = []
    monkeypatch.setattr(wiring, "fingerprint_probe", lambda *a, **k: probes.append("sent") or None)
    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    for flags in ({"dry_run": True}, {"estimate": True}, {"discovery_only": True}):
        execute_run(_opts(tmp_path, target, scope, fingerprint_first=True, **flags), [specs])
    assert probes == [], "a command that promises zero sends must not fingerprint"


def test_a_real_run_does_fingerprint_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And the guard must not be so wide that ``-sV`` stops working on a real run."""

    from ildottore.shared.models import FingerprintGuess, ModelFingerprint

    calls: list[str] = []

    def _probe(_scope: object, target: object, **_kw: object) -> ModelFingerprint:
        calls.append(getattr(target, "id", "?"))
        return ModelFingerprint(
            target_id="mock-target",
            family=FingerprintGuess(guess="llama", confidence=0.5),
        )

    monkeypatch.setattr(wiring, "fingerprint_probe", _probe)
    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    execute_run(_opts(tmp_path, target, scope, fingerprint_first=True), [specs])
    assert calls == ["mock-target"]


def test_the_shipped_battery_completes_under_its_own_default_budget(tmp_path: Path) -> None:
    """The headline claim, end to end, with the REAL derived budget.

    The first fix derived the ceilings from the plan and asserted the arithmetic, which was
    true and beside the point: the axis that actually halted the run was ``max_wall_s``,
    because the composition root fed the budget ledger the deterministic evidence clock (a
    counter stepping 1.0 per READ). 1800 "seconds" was 1800 clock reads, fewer than a
    72-spec run performs, so the default battery could never finish, and a live run had no
    time bound at all.
    """

    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    report = tmp_path / "r.json"
    outcome = execute_run(
        _opts(tmp_path, target, scope, runs=5, outputs={"json": report}), [SHIPPED_SPECS]
    )

    assert not outcome.incomplete, f"the default battery did not finish: {outcome.incomplete}"
    doc = json.loads(report.read_text(encoding="utf-8"))
    assert doc["summary"]["status"]["state"] == "complete"
    specs = doc["summary"]["coverage"]["specs"]
    assert specs["run"] == specs["total"] == 75


def test_the_ledger_measures_seconds_not_clock_reads() -> None:
    """The wall axis has to be wired to a real clock, or it is not a wall axis."""

    import time

    from ildottore.core.runner import CampaignRunner

    runner = CampaignRunner(
        policy=None,  # type: ignore[arg-type]
        mutators=None,  # type: ignore[arg-type]
        evaluators=None,  # type: ignore[arg-type]
        scorer=None,  # type: ignore[arg-type]
        evidence_store=None,  # type: ignore[arg-type]
        run_store=None,  # type: ignore[arg-type]
        adapter_factory=lambda _t, _s: None,  # type: ignore[arg-type,return-value]
        now=lambda: 0.0,  # the deterministic evidence clock
    )
    assert runner._wall_clock is time.monotonic


def test_a_spec_pack_cannot_set_the_scanners_own_ceiling() -> None:
    """The derived budget is clamped, because otherwise the input decides the limit.

    Measured on a pack nobody would call hostile (200 specs, an ordinary 8k completion,
    4 mutations): a 61-million-token allowance, 123 times the old constant. A budget whose
    size comes from the thing it is meant to bound is not a budget.
    """

    from ildottore.cli.run import BUDGET_DERIVATION_CAP
    from ildottore.shared.models import Sampling

    huge = estimate_plan(
        [
            make_spec(f"PI-DIRECT-{i:03d}").model_copy(
                update={"sampling": Sampling(max_tokens=200_000), "mutations": ["base64"]}
            )
            for i in range(1, 40)
        ],
        runs=5,
    )
    capped = budgets_for(huge)
    # 39 specs x 2 mutators x 5 runs x 200k tokens derives ~117M; the cap holds it at 5M.
    assert huge.total_tokens > (BUDGET_DERIVATION_CAP.max_tokens or 0)
    assert capped.max_tokens == BUDGET_DERIVATION_CAP.max_tokens
    assert (capped.max_requests or 0) <= (BUDGET_DERIVATION_CAP.max_requests or 0)

    # ...and an operator can still authorize more, explicitly. That is the difference: a
    # human raising a ceiling is authorization; a spec file raising it is not.
    from ildottore.shared.models import PlanBudgets as PB

    assert budgets_for(huge, overrides=PB(max_tokens=99_000_000)).max_tokens == 99_000_000


@pytest.mark.parametrize("value", [-5_000_000, 0, 10_000_000])
def test_sampling_max_tokens_is_bounded(value: int) -> None:
    """Unbounded in the model, the schema AND the linter, which is how a spec could do it.

    A negative value was accepted too, and dragged a pack's estimate DOWN.
    """

    from pydantic import ValidationError

    from ildottore.shared.models import Sampling

    with pytest.raises(ValidationError):
        Sampling(max_tokens=value)


def test_a_barren_selection_is_refused(tmp_path: Path) -> None:
    """Every spec blocked by policy used to exit 0 with "3 of 0 planned" and zero requests."""

    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(
        tmp_path,
        [make_spec("AG-TOOLS-001").model_copy(update={"requires": [RequiresCapability.TOOLS]})],
    )
    with pytest.raises(ValueError, match="nothing would be sent"):
        execute_run(_opts(tmp_path, target, scope), [specs])


def test_an_explicit_timing_template_beats_the_intensity_flags() -> None:
    """``-T0 --deep`` quietly became T2: four times the pace on a target chosen for care."""

    res = runner.invoke(
        app,
        [
            "run",
            "-t",
            "examples/target.local.yaml",
            "--scope",
            "examples/scope.local.yaml",
            "--deep",
            "-T",
            "0",
            "--dry-run",
        ],
    )
    assert res.exit_code == 0
    assert "pacing:  0.5 req/s" in res.output


def test_a_stdio_command_line_is_masked_when_printed(tmp_path: Path) -> None:
    """A stdio MCP target's "endpoint" is a command line, and it can carry a secret.

    ``-sn`` and ``--dry-run`` printed it verbatim: the two commands an operator runs with
    least suspicion, whose output lands in tickets and CI logs.
    """

    from ildottore.cli.run import _safe_endpoint

    printed = _safe_endpoint("stdio:///usr/bin/env node server.js --token sk-AUDIT-9f3c1b7a2e")
    assert "sk-AUDIT-9f3c1b7a2e" not in printed
    assert "REDACTED" in printed


def test_the_machine_report_formats_carry_a_truncation(tmp_path: Path) -> None:
    """SARIF and JUnit are what CI reads, and both ignored the run status entirely.

    A truncated campaign rendered as a fully green JUnit suite (``errors="0"``, hardcoded)
    and a SARIF log with no ``invocations`` at all, which is SARIF's own field for this.
    """

    from ildottore.reporting import RunStatus, get_reporter
    from ildottore.shared.models import TestRun

    status = RunStatus(state="budget_exhausted", reason="27 of 72 specs never ran")
    sarif = json.loads(
        get_reporter("sarif", specs={}, run_status=status).render(TestRun(run_id="run-x"), [])
    )
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert "27 of 72" in str(sarif["runs"][0]["invocations"][0])

    junit = (
        get_reporter("junit", specs={}, run_status=status)
        .render(TestRun(run_id="run-x"), [])
        .decode()
    )
    assert 'errors="1"' in junit
    assert "<error" in junit and "27 of 72" in junit

    # A complete run says so rather than staying silent about it.
    ok = json.loads(get_reporter("sarif", specs={}).render(TestRun(run_id="y"), []))
    assert ok["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_diff_refuses_a_truncated_report(tmp_path: Path) -> None:
    """27 failing specs vanish, absence is not a regression, so the gate went green."""

    from ildottore.cli.diff import incomplete_reason

    truncated = tmp_path / "cur.json"
    truncated.write_text(
        json.dumps(
            {
                "findings": [],
                "summary": {
                    "status": {
                        "state": "budget_exhausted",
                        "complete": False,
                        "reason": "27 of 72 specs never ran",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    complete = tmp_path / "base.json"
    complete.write_text(
        json.dumps(
            {"findings": [], "summary": {"status": {"state": "complete", "complete": True}}}
        ),
        encoding="utf-8",
    )
    old_style = tmp_path / "old.json"  # report-1.0 without a status block
    old_style.write_text(json.dumps({"findings": []}), encoding="utf-8")

    assert incomplete_reason(truncated) is not None
    assert incomplete_reason(complete) is None
    assert incomplete_reason(old_style) is None, "silence in an old report is age, not a claim"

    res = runner.invoke(app, ["diff", str(complete), str(truncated)])
    assert res.exit_code == 3
    assert "did not complete" in res.output


def test_the_gate_authorizes_the_url_the_adapter_will_request() -> None:
    """Three notions of "the endpoint", now one.

    The pre-flight authorized the scope's ``base_url``, the adapter sent ``origin`` plus a
    HARDCODED provider path, and the operator wrote ``target.endpoint``. An audit of 252
    scope/target combinations found 80 disagreements, 41 of them refusals of configurations
    that the wire would have allowed. Azure OpenAI and LiteLLM host the API under a prefix,
    so discarding the declared path broke every gateway-hosted model.
    """

    from ildottore.policy import EndpointAllowlist
    from ildottore.shared.models import Target

    for endpoint in (
        "https://x.openai.azure.com/openai/deployments/gpt4o/chat/completions",
        "http://localhost:4000/litellm/v1/chat/completions",
        "https://api.openai.com/v1/chat/completions",
        "http://localhost:11434",  # origin only: the provider default path applies
    ):
        target = Target.model_validate(
            {"id": "t", "type": "model", "provider": "openai", "endpoint": endpoint}
        )
        gate_url = wiring.request_url_for(target)
        adapter = wiring.build_real_adapter(target, EndpointAllowlist([]), api_key=None)
        assert gate_url == adapter._full_url(), endpoint  # type: ignore[attr-defined]


def test_an_unreachable_target_is_not_a_clean_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authorized but dead: every attempt failed on transport, so nothing was measured.

    That used to exit 0 with a report of inconclusives and published coverage percentages,
    with the reason only inside the evidence: the same false green as an unscoped target,
    one layer further out.
    """

    from ildottore.cli.run import _unreachable_reason
    from ildottore.core.runner import CampaignResult
    from ildottore.shared.models import Attempt, ModelRequest, TestPlan, TestRun

    def _result(*, error: str | None) -> CampaignResult:
        finding = make_spec("PI-DIRECT-001")
        del finding
        from .conftest import make_finding

        base = make_finding("PI-DIRECT-001")
        attempt = Attempt(
            attempt_id="a1",
            spec_id="PI-DIRECT-001",
            request=ModelRequest(prompt="p"),
            response=None if error else base.attempts[0].response,
            error=error,
        )
        return CampaignResult(
            plan=TestPlan(plan_ref="p", target_id="t", adaptive=False),
            run=TestRun(run_id="r"),
            findings=[base.model_copy(update={"attempts": [attempt]})],
        )

    assert _unreachable_reason(_result(error="ConnectError: refused")) is not None
    assert _unreachable_reason(_result(error=None)) is None


def test_a_declared_ceiling_binds_the_fingerprint_probes(tmp_path: Path) -> None:
    """Contract u12 §7 A-11: a ceiling binds every request the tool makes.

    Probes do not travel through the runner, so the ledger never saw them:
    ``--budget-requests 2 -sV`` sent 30 requests and then reported "limit 2, attempted 3",
    counting only the half that passed the ledger. Checked before anything is sent, because
    the fingerprint is what feeds the plan the ledger is later derived from.
    """

    from ildottore.cli.run import fingerprint_probe_count

    target = write_target(tmp_path, mock_scenario="hardened")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    with pytest.raises(ValueError, match="more than the --budget-requests"):
        execute_run(
            _opts(tmp_path, target, scope, fingerprint_first=True, budget_requests=2), [specs]
        )

    # A ceiling that fits the probe pass is allowed through.
    opts = _opts(
        tmp_path,
        target,
        scope,
        fingerprint_first=True,
        budget_requests=fingerprint_probe_count() + 50,
    )
    execute_run(opts, [specs])
