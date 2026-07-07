"""Runner budget breach ⇒ partial run marked budget_exhausted (§7)."""

from __future__ import annotations

from ildottore.core.runner import CampaignRunner
from ildottore.shared.models import PlanBudgets

from .conftest import (
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    mock_adapter_factory,
    no_sleep,
)


def _runner(scenario, *, evaluators, mutators, scorer, stores, budgets, n=5, concurrency=1):
    evidence, runs = stores
    return CampaignRunner(
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=n,
        concurrency=concurrency,
        sleep=no_sleep,
        now=lambda: 0.0,
    )


async def test_request_budget_breach_marks_exhausted(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    # Only 2 requests allowed but N=5 → breach mid-spec.
    budgets = PlanBudgets(max_requests=2)
    runner = _runner(
        scenario,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
        budgets=budgets,
    )
    result = await runner.run(
        run_id="r1", target=make_target(), specs=[make_spec()], budgets=budgets
    )
    assert result.status == "budget_exhausted"
    # The run is still persisted (partial, not raised away).
    _, runs = stores
    assert runs.get_run("r1") is not None


async def test_attempt_budget_breach_marks_exhausted(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    budgets = PlanBudgets(max_attempts=3)  # < N=5
    runner = _runner(
        scenario,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
        budgets=budgets,
    )
    result = await runner.run(
        run_id="r1", target=make_target(), specs=[make_spec()], budgets=budgets
    )
    assert result.status == "budget_exhausted"


async def test_partial_findings_survive_breach(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    # Enough budget for the first spec (5 attempts + 5 requests = 10 reqs) but not both.
    budgets = PlanBudgets(max_requests=6)
    specs = [make_spec("JB-REFUSAL-001"), make_spec("JB-REFUSAL-002")]
    runner = _runner(
        scenario,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
        budgets=budgets,
        concurrency=1,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=specs, budgets=budgets)
    assert result.status == "budget_exhausted"
    # At least one spec's work was retained (no total loss on breach).
    assert len(result.findings) >= 1


async def test_generous_budget_completes(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    budgets = PlanBudgets(max_requests=1000, max_attempts=1000, max_tokens=1_000_000)
    runner = _runner(
        scenario,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
        budgets=budgets,
    )
    result = await runner.run(
        run_id="r1", target=make_target(), specs=[make_spec()], budgets=budgets
    )
    assert result.status == "complete"
