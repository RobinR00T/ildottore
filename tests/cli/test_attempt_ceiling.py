"""The attempts ceiling is the request ceiling, and an attempt counts once its request is
accepted (u08 A-80).

A campaign of more than 20,000 attempts could never finish: the attempts ceiling was derived
from the estimate and capped at 20,000, `--budget-requests` did not move it and no flag did, so
`--runs 100` over the battery halted on `max_attempts` with requests to spare. And an attempt
was counted before its request was refused at a ceiling: 128 attempts recorded for 100
requests, and every resume that met the same ceiling added one per spec it started (43).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.cli.run import (
    BUDGET_DERIVATION_CAP,
    PlanEstimate,
    budgets_for,
)
from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.shared.models import PlanBudgets

from .conftest import make_spec, write_scope, write_spec_tree, write_target

REPO = Path(__file__).resolve().parents[2]


def _estimate(requests: int) -> PlanEstimate:
    return PlanEstimate(
        specs=1, requests=requests, input_tokens=requests, output_tokens=0, by_category={}
    )


def test_the_attempts_ceiling_follows_an_explicit_request_ceiling() -> None:
    budgets = budgets_for(_estimate(40_000), overrides=PlanBudgets(max_requests=50_000))
    assert budgets.max_requests == 50_000
    assert budgets.max_attempts == 50_000  # was 20,000 whatever the flag said


@pytest.mark.parametrize("requests", [10, 1_000, 13_000, 1_000_000])
def test_the_derived_attempts_ceiling_is_the_derived_request_ceiling(requests: int) -> None:
    budgets = budgets_for(_estimate(requests))
    assert budgets.max_attempts == budgets.max_requests
    assert budgets.max_requests is not None
    assert budgets.max_requests <= (BUDGET_DERIVATION_CAP.max_requests or 0)


def test_a_library_caller_can_still_set_an_attempts_ceiling_of_its_own() -> None:
    budgets = budgets_for(_estimate(100), overrides=PlanBudgets(max_requests=500, max_attempts=7))
    assert (budgets.max_requests, budgets.max_attempts) == (500, 7)


def test_an_attempt_refused_at_the_request_ceiling_is_not_counted() -> None:
    ledger = BudgetLedger(max_requests=1, max_attempts=10)
    ledger.debit_request(opens_attempt=True)
    with pytest.raises(BudgetExhausted) as raised:
        ledger.debit_request(opens_attempt=True)
    assert raised.value.axis == "max_requests"
    snap = ledger.snapshot()
    assert (snap.requests, snap.attempts, snap.tokens) == (1, 1, 0)


def test_an_attempt_refused_at_the_token_ceiling_is_not_counted() -> None:
    ledger = BudgetLedger(max_tokens=100)
    ledger.debit_request(tokens=60, opens_attempt=True)
    with pytest.raises(BudgetExhausted):
        ledger.debit_request(tokens=60, opens_attempt=True)
    snap = ledger.snapshot()
    assert (snap.requests, snap.attempts, snap.tokens) == (1, 1, 60)


def test_an_attempt_refused_at_the_attempts_ceiling_sends_nothing() -> None:
    ledger = BudgetLedger(max_requests=10, max_attempts=1)
    ledger.debit_request(opens_attempt=True)
    ledger.debit_request()  # a retry, or the next turn of the same conversation
    with pytest.raises(BudgetExhausted) as raised:
        ledger.debit_request(opens_attempt=True)
    assert raised.value.axis == "max_attempts"
    snap = ledger.snapshot()
    assert (snap.requests, snap.attempts) == (2, 1)


def _workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    specs = [make_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 9)]
    return (
        write_target(tmp_path, mock_scenario="vulnerable"),
        write_scope(tmp_path),
        write_spec_tree(tmp_path, specs),
    )


def _spend(run_db: Path) -> dict[str, float]:
    conn = sqlite3.connect(run_db)
    try:
        rows = conn.execute("SELECT spend_json FROM runs").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    spend: dict[str, float] = json.loads(rows[0][0])
    return spend


def _run(tmp_path: Path, *extra: str) -> tuple[int, str]:
    target, scope, specs = _workspace(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "run",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "-q",
            "--no-color",
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_a_halt_at_the_request_ceiling_records_no_more_attempts_than_requests(
    tmp_path: Path,
) -> None:
    """Eight specs of five attempts each under 12 requests: before, 12 requests and 18 attempts
    (one more for every spec that started after the ceiling); a resume added 6 more."""

    code, shown = _run(tmp_path, "--budget-requests", "12", "--concurrency", "1")
    assert code == 3, shown
    assert "budget ceiling reached on 'max_requests'" in shown
    spend = _spend(tmp_path / "runs.sqlite")
    assert spend["requests"] == 12
    assert spend["attempts"] == 12

    run_id = next(p.name for p in (tmp_path / "ev").iterdir())
    code, shown = _run(
        tmp_path, "--budget-requests", "12", "--concurrency", "1", "--resume", run_id
    )
    assert code == 3, shown
    spend = _spend(tmp_path / "runs.sqlite")
    assert (spend["requests"], spend["attempts"]) == (12, 12)


def test_a_resume_of_a_run_that_counted_refused_attempts_opens_at_its_requests(
    tmp_path: Path,
) -> None:
    """A run recorded before this fix holds more attempts than requests; the resume reads the
    attempts as the requests, or its attempts ceiling (now the request ceiling) would bind
    first, with requests left."""

    code, _ = _run(tmp_path, "--budget-requests", "12", "--concurrency", "1")
    assert code == 3
    db = tmp_path / "runs.sqlite"
    conn = sqlite3.connect(db)
    try:
        row = conn.execute("SELECT run_id, spend_json FROM runs").fetchone()
        spend = json.loads(row[1])
        spend["attempts"] = 18.0  # what the old accounting recorded for this run
        conn.execute("UPDATE runs SET spend_json = ? WHERE run_id = ?", (json.dumps(spend), row[0]))
        conn.commit()
    finally:
        conn.close()
    code, shown = _run(
        tmp_path, "--budget-requests", "40", "--concurrency", "1", "--resume", row[0]
    )
    assert code == 2, shown  # the whole battery: 40 requests, 40 attempts, no attempts halt
    assert (_spend(db)["requests"], _spend(db)["attempts"]) == (40, 40)


def test_the_estimate_and_the_dry_run_show_the_attempts_ceiling(tmp_path: Path) -> None:
    target, scope, specs = _workspace(tmp_path)
    base = ["run", str(target), "--scope", str(scope), "--spec-path", str(specs), "--no-color"]
    estimate = CliRunner().invoke(app, [*base, "--estimate", "--budget-requests", "50000"])
    assert estimate.exit_code == 0, estimate.output
    assert (
        "  ceilings: 50000 requests, 50000 attempts (one per accepted request), "
        "500000 tokens, 1800s wall" in estimate.output
    )
    dry = CliRunner().invoke(app, [*base, "--dry-run", "--budget-requests", "50000"])
    assert dry.exit_code == 0, dry.output
    assert "  budgets: 500000 tokens, 50000 requests, 50000 attempts, 1800s wall" in dry.output
