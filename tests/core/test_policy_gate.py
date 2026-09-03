"""Policy gate is first + mandatory: blocked specs never reach the adapter (§7)."""

from __future__ import annotations

from ildottore.core.runner import CampaignRunner
from ildottore.shared.enums import Category, VerdictStatus

from .conftest import (
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    no_sleep,
)


class CountingAdapter:
    """Wraps a mock and counts sends so we can assert *zero* sends on a block."""

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


async def test_blocked_spec_produces_finding_with_zero_sends(
    evaluators, mutators, scorer, stores
) -> None:
    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    adapter = CountingAdapter(scenario)
    # Pack allows only prompt_injection; the jailbreak spec is NOT enabled → blocked.
    policy = make_policy_engine(allow_categories=[Category.PROMPT_INJECTION])
    runner = CampaignRunner(
        policy=policy,
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])

    assert adapter.sends == 0  # the gate refused before any egress
    finding = result.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert "blocked_by_policy" in finding.reasoning
    assert finding.attempts == []


async def test_out_of_scope_target_blocks(evaluators, mutators, scorer, stores) -> None:
    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    adapter = CountingAdapter(scenario, id="unknown")
    policy = make_policy_engine(allow_categories=[Category.JAILBREAK], target_id="t1")
    runner = CampaignRunner(
        policy=policy,
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    # target id "other" is not in the scope (which only knows "t1").
    result = await runner.run(run_id="r1", target=make_target("other"), specs=[make_spec()])
    assert adapter.sends == 0
    assert "not in scope" in result.findings[0].reasoning


async def test_requires_policy_blocked_by_default_zero_sends(
    evaluators, mutators, scorer, stores
) -> None:
    """OD-11 acceptance: a requires_policy spec under a default scope never sends."""

    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    adapter = CountingAdapter(scenario)
    # Category is enabled, but the pack enables NO capabilities → gate blocks.
    policy = make_policy_engine(allow_categories=[Category.AGENT_TOOL_ABUSE])
    spec = make_spec(
        "AG-EXTORT-CHAIN-001",
        category=Category.AGENT_TOOL_ABUSE,
        requires_policy=["offensive_simulation"],
    )
    runner = CampaignRunner(
        policy=policy,
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[spec])

    assert adapter.sends == 0  # zero egress - the capability gate refused first
    finding = result.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert "blocked_by_policy" in finding.reasoning
    assert "offensive_simulation" in finding.reasoning
    assert finding.attempts == []


async def test_requires_policy_runs_when_capability_enabled(
    evaluators, mutators, scorer, stores
) -> None:
    """OD-11 acceptance: same spec runs once the engagement opts the capability in."""

    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    adapter = CountingAdapter(scenario)
    policy = make_policy_engine(
        allow_categories=[Category.AGENT_TOOL_ABUSE],
        enabled_capabilities=["offensive_simulation"],
    )
    spec = make_spec(
        "AG-EXTORT-CHAIN-001",
        category=Category.AGENT_TOOL_ABUSE,
        requires_policy=["offensive_simulation"],
    )
    runner = CampaignRunner(
        policy=policy,
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[spec])

    assert adapter.sends > 0  # capability enabled → the spec actually executed
    finding = result.findings[0]
    assert "blocked_by_policy" not in (finding.reasoning or "")
    assert finding.attempts != []


async def test_denied_spec_blocks(evaluators, mutators, scorer, stores) -> None:
    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    adapter = CountingAdapter(scenario)
    policy = make_policy_engine(allow_categories=[Category.JAILBREAK], deny=["JB-REFUSAL-001"])
    runner = CampaignRunner(
        policy=policy,
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])
    assert adapter.sends == 0
    assert "denied" in result.findings[0].reasoning
