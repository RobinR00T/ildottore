"""Capability gating: missing capability ⇒ inconclusive, never a pass (§7)."""

from __future__ import annotations

from ildottore.core.runner import CampaignRunner
from ildottore.shared.enums import Category, RequiresCapability, VerdictStatus
from ildottore.shared.models import Capabilities

from .conftest import (
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    mock_adapter_factory,
    no_sleep,
)


def _runner(scenario, *, evaluators, mutators, scorer, stores):
    evidence, runs = stores
    return CampaignRunner(
        policy=make_policy_engine(
            allow_categories=[Category.JAILBREAK, Category.AGENT_TOOL_ABUSE, Category.RAG_SECURITY]
        ),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        sleep=no_sleep,
        now=lambda: 0.0,
    )


async def test_missing_tools_capability_is_inconclusive_not_pass(
    evaluators, mutators, scorer, stores
) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    spec = make_spec(
        "AG-TOOL-001", category=Category.AGENT_TOOL_ABUSE, requires=[RequiresCapability.TOOLS]
    )
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    # Target declares no tools capability.
    result = await runner.run(
        run_id="r1", target=make_target(capabilities=Capabilities(tools=False)), specs=[spec]
    )
    finding = result.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert finding.status is not VerdictStatus.PASS
    assert "capability_unavailable" in finding.reasoning
    assert finding.attempts == []  # never sent


async def test_present_capability_runs_normally(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE, capabilities=Capabilities(tools=True))
    spec = make_spec(
        "AG-TOOL-001", category=Category.AGENT_TOOL_ABUSE, requires=[RequiresCapability.TOOLS]
    )
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(
        run_id="r1", target=make_target(capabilities=Capabilities(tools=True)), specs=[spec]
    )
    # Capability present → the spec actually runs (5 attempts).
    assert result.findings[0].status is not VerdictStatus.INCONCLUSIVE
    assert len(result.findings[0].attempts) == 5


async def test_all_env_errors_yield_inconclusive_finding(
    evaluators, mutators, scorer, stores
) -> None:
    """Every send env-errors after retries → attempts recorded, verdict inconclusive."""

    from ildottore.core.execute import RetryPolicy

    class AlwaysEnvError:
        id = "t1"

        async def send(self, request):
            exc = TimeoutError("provider down")
            raise exc

        def capabilities(self):
            return Capabilities()

    evidence, runs = stores
    runner = CampaignRunner(
        policy=make_policy_engine(allow_categories=[Category.JAILBREAK]),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: AlwaysEnvError(),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=2,
        retry=RetryPolicy(max_retries=0, base_delay_s=0.0),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])
    finding = result.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE
    # Attempts ARE recorded (env-errored, not evaluated) - never masked as pass/fail.
    assert len(finding.attempts) == 2
    assert all(a.verdict.status is VerdictStatus.INCONCLUSIVE for a in finding.attempts)


async def test_mixed_specs_partial_skip(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    runnable = make_spec("JB-REFUSAL-001", category=Category.JAILBREAK)
    gated = make_spec("RAG-001", category=Category.RAG_SECURITY, requires=[RequiresCapability.RAG])
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(
        run_id="r1",
        target=make_target(capabilities=Capabilities(rag=False)),
        specs=[runnable, gated],
    )
    by_id = {f.spec_id: f for f in result.findings}
    assert by_id["JB-REFUSAL-001"].status is VerdictStatus.FAIL
    assert by_id["RAG-001"].status is VerdictStatus.INCONCLUSIVE
    assert by_id["RAG-001"].attempts == []


async def test_unrenderable_media_is_isolated_not_campaign_abort(
    evaluators, mutators, scorer, stores
) -> None:
    """A malformed media carrier fails ONLY its spec (inconclusive), never aborts the batch."""

    good = make_spec("JB-OK-001", category=Category.JAILBREAK)
    bad = make_spec(
        "MM-BAD-001", category=Category.JAILBREAK, requires=[RequiresCapability.MULTIMODAL]
    )
    # A schema-valid-but-unrenderable media part (no render_text / data_b64 / asset).
    bad = bad.model_copy(
        update={"attack": bad.attack.model_copy(update={"media": [{"kind": "image"}]})}
    )
    scenario = make_scenario(VULNERABLE_RESPONSE, capabilities=Capabilities(multimodal=True))
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(
        run_id="r1",
        target=make_target(capabilities=Capabilities(multimodal=True)),
        specs=[good, bad],
    )
    by_id = {f.spec_id: f for f in result.findings}
    assert set(by_id) == {"JB-OK-001", "MM-BAD-001"}  # both produced a finding; no abort
    assert by_id["MM-BAD-001"].status is VerdictStatus.INCONCLUSIVE
    assert "media_error" in by_id["MM-BAD-001"].reasoning
    assert by_id["MM-BAD-001"].attempts == []  # nothing sent
