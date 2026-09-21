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
