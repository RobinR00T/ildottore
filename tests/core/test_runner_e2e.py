"""End-to-end campaign loop against MockTarget with real evaluators (contract §5/§7)."""

from __future__ import annotations

from pathlib import Path

from ildottore.core.runner import CampaignRunner
from ildottore.shared.enums import VerdictStatus

from .conftest import (
    HARDENED_RESPONSE,
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    mock_adapter_factory,
    no_sleep,
)


def _runner(scenario, *, evaluators, mutators, scorer, stores, policy=None, n=5, **kw):
    evidence, runs = stores
    return CampaignRunner(
        policy=policy if policy is not None else make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=n,
        sleep=no_sleep,
        now=lambda: 0.0,
        **kw,
    )


async def test_vulnerable_target_yields_fail_finding(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])

    assert result.status == "complete"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status is VerdictStatus.FAIL
    assert finding.spec_id == "JB-REFUSAL-001"
    # 5 attempts persisted, each with a verdict.
    assert len(finding.attempts) == 5
    assert all(a.verdict is not None for a in finding.attempts)
    # Reproducibility = 5/5 (every run was exploited).
    assert finding.risk.reproducibility == 1.0
    assert finding.confirmed is True


async def test_hardened_target_yields_pass_finding(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(HARDENED_RESPONSE)
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])

    finding = result.findings[0]
    assert finding.status is VerdictStatus.PASS
    assert finding.risk.reproducibility == 0.0
    assert finding.confirmed is False


async def test_evidence_and_run_persisted(evaluators, mutators, scorer, stores) -> None:
    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])

    # Run row persisted + queryable.
    assert runs.get_run("r1") is not None
    findings = runs.list_findings("r1")
    assert len(findings) == 1
    # Evidence refs written for every attempt (content-addressed on disk).
    assert len(result.findings[0].evidence) == 5
    for ref in result.findings[0].evidence:
        assert ref.sha256 is not None
        assert (evidence.root / Path(ref.uri)).exists()


async def test_mutations_expand_attempts(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    spec = make_spec(mutations=["rot13"])  # identity + rot13 → 2 variants
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores, n=3
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[spec])
    # 2 mutators x 3 runs = 6 attempts.
    assert len(result.findings[0].attempts) == 6
    assert {a.mutation for a in result.findings[0].attempts} == {"identity", "rot13"}


async def test_multi_spec_findings_sorted(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(HARDENED_RESPONSE)
    specs = [
        make_spec("JB-REFUSAL-002"),
        make_spec("JB-REFUSAL-001"),
    ]
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(
        run_id="r1",
        target=make_target(),
        specs=specs,
        suite_ref="owasp:llm",
    )
    assert [f.spec_id for f in result.findings] == ["JB-REFUSAL-001", "JB-REFUSAL-002"]
    assert result.run.suite_ref == "owasp:llm"
    assert result.run.summary.total == 2


async def test_run_summary_counts_by_status(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])
    assert result.run.summary.by_status.get("fail") == 1
