"""Resume by run_id: completed attempts are not re-sent (§7)."""

from __future__ import annotations

from ildottore.core.runner import CampaignRunner
from ildottore.shared.models import PlanBudgets

from .conftest import (
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    no_sleep,
)


class CountingAdapter:
    def __init__(self, scenario, *, id: str = "t1") -> None:
        from ildottore.adapters.mock import MockTarget

        self._inner = MockTarget(scenario, id=id)
        self.id = id
        self.sends = 0

    async def send(self, request):
        self.sends += 1
        return await self._inner.send(request)

    def capabilities(self):
        return self._inner.capabilities()


def _runner(adapter, *, evaluators, mutators, scorer, stores, budgets=None):
    evidence, runs = stores
    return CampaignRunner(
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=5,
        concurrency=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )


async def test_resume_skips_completed_attempts(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)

    # First run: budget cut short after a couple of sends → partial run.
    adapter1 = CountingAdapter(scenario)
    partial_budget = PlanBudgets(max_requests=2)
    runner1 = _runner(
        adapter1,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
        budgets=partial_budget,
    )
    partial = await runner1.run(
        run_id="run-x", target=make_target(), specs=[make_spec()], budgets=partial_budget
    )
    assert partial.status == "budget_exhausted"
    first_sends = adapter1.sends
    assert first_sends >= 1

    # Resume: same run_id, generous budget, resume_from the partial run.
    adapter2 = CountingAdapter(scenario)
    runner2 = _runner(
        adapter2, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    resumed = await runner2.run(
        run_id="run-x",
        target=make_target(),
        specs=[make_spec()],
        resume_from=partial.run,
    )
    assert resumed.status == "complete"
    # Completed attempts from the partial run are NOT re-sent.
    completed_ids = {
        a.attempt_id for f in partial.run.findings for a in f.attempts if a.response is not None
    }
    resumed_ids = {a.attempt_id for f in resumed.findings for a in f.attempts}
    # No completed attempt id was re-executed by the resume adapter (fresh send count
    # equals only the remaining attempts).
    assert adapter2.sends == 5 - len(completed_ids)
    # The resumed finding MERGES the prior completed attempts with the fresh ones, so it covers
    # the FULL run (all 5), not just the remainder (audit M11, previously it dropped the prior).
    assert resumed_ids == {f"JB-REFUSAL-001::identity#{i}" for i in range(5)}
    # A vulnerable target exploited on every run ⇒ reproducibility 5/5, not undercounted.
    assert resumed.findings[0].risk.reproducibility == 1.0
    # And every attempt id is unique (no duplicates from the merge).
    all_ids = [a.attempt_id for f in resumed.findings for a in f.attempts]
    assert len(all_ids) == len(set(all_ids))
    assert len(all_ids) == 5


async def test_resume_without_prior_run_is_full(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    adapter = CountingAdapter(scenario)
    runner = _runner(
        adapter, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(
        run_id="run-x", target=make_target(), specs=[make_spec()], resume_from=None
    )
    assert result.status == "complete"
    assert adapter.sends == 5
