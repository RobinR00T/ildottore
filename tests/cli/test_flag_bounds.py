"""Every integer flag of ``run`` is bounded, and a rate near zero derives a ceiling (A-55, u12).

``--runs`` had a lower bound and no upper one, and the plan multiplies it into float arithmetic:
``dottore run ... --dry-run --runs <4,300 nines>`` (and ``--estimate``) exited 1 with
``OverflowError: int too large to convert to float``, a traceback and the exit code this tool
uses for "findings below the threshold" (found 2026-10-07 by the pre-commit audit of
``fix/huge-int-repr``, finding F6). A sweep of every numeric flag then found ``--rate 1e-308``
doing the same on a live target, and ``--budget-*`` of ``-1`` passing ``--dry-run`` and
``--estimate`` with exit 0 while the run refused it with exit 3.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from ildottore.cli.main import app
from ildottore.cli.run import (
    BUDGET_DERIVATION_CAP,
    DEFAULT_PLAN_BUDGETS,
    PlanEstimate,
    RunOptions,
    _validate_options,
    budgets_for,
)

from .conftest import write_scope, write_target

runner = CliRunner()

_REPO = Path(__file__).resolve().parents[2]
_LOCAL = ["-t", str(_REPO / "examples" / "target.local.yaml")]
_LOCAL_SCOPE = ["--scope", str(_REPO / "examples" / "scope.local.yaml")]
_BOUND = "9,007,199,254,740,992"
#: ``run.MAX_FLAG_VALUE``, written out so this file runs on a base without it.
_MAX = 2**53

#: (flag, its RunOptions field, the least value it takes)
_FLAGS = [
    ("--runs", "runs", 1),
    ("--top-tests", "top_tests", 1),
    ("--concurrency", "concurrency", 1),
    ("--budget-tokens", "budget_tokens", 0),
    ("--budget-requests", "budget_requests", 0),
    ("--budget-wall", "budget_wall_s", 0),
]
_FLAG_NAMES = [flag for flag, _, _ in _FLAGS]


def _run(tmp_path: Path, *extra: str) -> Result:
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec",
            "PI-DIRECT-001",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            *extra,
        ],
    )


def _assert_refused(result: Result, tmp_path: Path, *fragments: str) -> None:
    """Exit 3 with one ``error:`` line holding every fragment; no traceback, nothing ran."""

    assert "Traceback" not in result.output
    assert result.exit_code == 3, result.output
    errors = [line for line in result.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 1, result.output
    for fragment in fragments:
        assert fragment in errors[0], errors[0]
    assert not (tmp_path / "ev").exists(), "nothing ran before the refusal"


@pytest.mark.parametrize("mode", [["--dry-run"], ["--estimate"], []], ids=["dry", "est", "run"])
@pytest.mark.parametrize(
    ("value", "shown"),
    [
        ("9" * 4300, "a number of more than 21 digits"),  # the audit's value
        (str(10**308), "a number of more than 21 digits"),  # the first past a float
        (str(_MAX + 1), "9,007,199,254,740,993"),
    ],
    ids=["4300-nines", "1e308", "2^53+1"],
)
@pytest.mark.parametrize("flag", _FLAG_NAMES)
def test_a_value_past_the_bound_is_refused_before_anything_runs(
    tmp_path: Path, flag: str, value: str, shown: str, mode: list[str]
) -> None:
    result = _run(tmp_path, *mode, f"{flag}={value}")

    _assert_refused(result, tmp_path, f"{flag} must be at most {_BOUND} (got {shown})")


@pytest.mark.parametrize("flag", _FLAG_NAMES)
def test_the_bound_itself_is_accepted(tmp_path: Path, flag: str) -> None:
    result = _run(tmp_path, "--dry-run", f"{flag}={_MAX}")

    assert "Traceback" not in result.output
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("mode", [["--dry-run"], ["--estimate"], []], ids=["dry", "est", "run"])
@pytest.mark.parametrize("flag", ["--budget-tokens", "--budget-requests", "--budget-wall"])
def test_a_negative_budget_is_refused_by_the_dry_run_too(
    tmp_path: Path, flag: str, mode: list[str]
) -> None:
    """The dry run and the estimate printed ``budgets: -1 tokens`` and exited 0."""

    _assert_refused(_run(tmp_path, *mode, f"{flag}=-1"), tmp_path, f"{flag} must be at least 0")


@pytest.mark.parametrize("flag", ["--budget-tokens", "--budget-requests", "--budget-wall"])
def test_a_zero_budget_still_passes_the_dry_run(tmp_path: Path, flag: str) -> None:
    """A ceiling of 0 is one the ledger accepts (the run then halts before its first send)."""

    assert _run(tmp_path, "--dry-run", f"{flag}=0").exit_code == 0


@pytest.mark.parametrize(("flag", "field", "least"), _FLAGS)
def test_the_lower_bounds_keep_their_message(flag: str, field: str, least: int) -> None:
    with pytest.raises(ValueError, match=f"^{flag} must be at least {least} \\(got -5\\)$"):
        _validate_options(RunOptions(targets=[], scope=None, **{field: -5}))  # type: ignore[arg-type]


@pytest.mark.parametrize(("flag", "field", "least"), _FLAGS)
def test_a_bound_set_in_code_is_checked_too(flag: str, field: str, least: int) -> None:
    """``fleet --run`` builds its ``RunOptions`` in code; the check is on the options."""

    _validate_options(RunOptions(targets=[], scope=None, **{field: _MAX}))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=f"^{flag} must be at most {_BOUND} "):
        _validate_options(RunOptions(targets=[], scope=None, **{field: 10**400}))  # type: ignore[arg-type]


def test_a_hugely_negative_value_is_described_not_printed() -> None:
    with pytest.raises(ValueError, match=r"^--runs must be at least 1 \(got a negative number "):
        _validate_options(RunOptions(targets=[], scope=None, runs=-(10**400)))


def test_fleet_run_refuses_a_runs_past_the_bound(tmp_path: Path) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        'version: "1"\ntargets:\n  - id: local\n'
        '    endpoint: "http://localhost:11434/v1/chat/completions"\n'
        '    model: "llama3.2:1b"\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["fleet", str(fleet), "--out", str(tmp_path / "out"), "--run", "--runs", "9" * 4300]
    )

    assert "Traceback" not in result.output
    assert result.exit_code == 3, result.output
    assert f"--runs must be at most {_BOUND}" in result.output


def _live_dry_run(*extra: str) -> Result:
    return runner.invoke(
        app, ["run", *_LOCAL, *_LOCAL_SCOPE, "--spec", "PI-DIRECT-001", "--dry-run", *extra]
    )


@pytest.mark.parametrize(
    ("rate", "extra", "wall"),
    [
        ("1e-308", [], "7,200"),  # a traceback on the base: the derived ceiling overflowed
        ("5e-324", [], "7,200"),
        ("0.0001", [], "7,200"),
        ("0.001", ["--budget-wall", "5"], "5"),  # still waiting past 45 s on a live stub
        # A zero ceiling was exempt, and with -sV the probe pass, which reads no ceiling, waited
        # without end (delta audit of A-55).
        ("5", ["--budget-wall", "0"], "0"),
        ("1e-308", ["--budget-wall", "0", "-sV"], "0"),
    ],
)
def test_a_rate_under_one_request_per_wall_ceiling_is_refused(
    rate: str, extra: list[str], wall: str
) -> None:
    """The ceiling is checked when a send is charged, not while the rate limiter sleeps.

    Once ``--rate 1e-308`` stopped overflowing the derivation, a live run waited past its
    ceiling without end (pre-commit audit of A-55); dry runs, so a regression cannot hang. The
    rate is printed in scientific notation: as typed, the CLI's redactor masked 3,214 of 20,000
    refused rates as phone or card numbers (delta audit).
    """

    result = _live_dry_run("--rate", rate, *extra)

    assert "Traceback" not in result.output
    assert result.exit_code == 3, result.output
    assert (
        f"--rate {float(rate):.3e} is less than one request per {wall}-second wall-clock ceiling"
        in result.output
    )


@pytest.mark.parametrize(
    ("rate", "extra"),
    [("0.0002", []), ("0.001", ["--budget-wall", "1000"]), ("inf", []), ("5", [])],
)
def test_a_rate_of_one_request_per_ceiling_or_more_is_accepted(rate: str, extra: list[str]) -> None:
    result = _live_dry_run("--rate", rate, *extra)

    assert result.exit_code == 0, result.output


def test_a_template_pace_is_checked_too() -> None:
    """``-T0`` paces at 0.5 requests per second, which ``--rate 0.5`` was refused for."""

    result = _live_dry_run("-T0", "--budget-wall", "1")

    assert result.exit_code == 3, result.output
    assert (
        "the -T0 pace of 5.000e-01 requests per second is less than one request per "
        "1-second wall-clock ceiling" in result.output
    )


def test_an_offline_mock_run_is_not_paced_so_not_checked(tmp_path: Path) -> None:
    """The pace applies to traffic that leaves the process; the plan says it is not applied."""

    result = _run(tmp_path, "--dry-run", "--rate", "0.0001", "--budget-wall", "0")

    assert result.exit_code == 0, result.output


def _estimate(requests: int) -> PlanEstimate:
    return PlanEstimate(
        specs=1, requests=requests, input_tokens=requests * 100, output_tokens=0, by_category={}
    )


@pytest.mark.parametrize("rate", [1e-308, 1e-320, 5e-324])
def test_budgets_for_a_rate_near_zero_is_the_cap(rate: float) -> None:
    assert budgets_for(_estimate(10), rate_rps=rate).max_wall_s == (
        BUDGET_DERIVATION_CAP.max_wall_s
    )


def test_a_paced_wall_under_the_cap_is_derived_as_before() -> None:
    """100 requests at 0.05 per second: 2,000 s, times the 1.5 headroom, plus one."""

    derived = budgets_for(_estimate(100), rate_rps=0.05).max_wall_s

    assert DEFAULT_PLAN_BUDGETS.max_wall_s is not None
    assert DEFAULT_PLAN_BUDGETS.max_wall_s < derived < (BUDGET_DERIVATION_CAP.max_wall_s or 0)
    assert derived == 3001
