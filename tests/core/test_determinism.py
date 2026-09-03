"""Determinism replay: same suite + target + seed ⇒ identical plan + findings (§7)."""

from __future__ import annotations

from ildottore.core.runner import CampaignRunner

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
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=5,
        # Fixed clock so latency_ms is byte-stable across runs (measurement noise
        # is the only non-determinism the design tolerates - pinned here).
        now=lambda: 0.0,
        sleep=no_sleep,
    )


async def test_identical_plan_and_findings_across_two_runs(
    evaluators, mutators, scorer, stores, tmp_path
) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    specs = [make_spec("JB-REFUSAL-001", mutations=["rot13"]), make_spec("JB-REFUSAL-002")]

    runner_a = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result_a = await runner_a.run(run_id="run-x", target=make_target(), specs=specs)

    # A second, independent store set (fresh tmp) - determinism must not depend on it.
    from ildottore.store.evidence_fs import FsEvidenceStore
    from ildottore.store.run_sqlite import SqliteRunStore

    evidence_b = FsEvidenceStore(tmp_path / "ev2")
    runs_b = SqliteRunStore(tmp_path / "runs2.db")
    try:
        runner_b = _runner(
            scenario,
            evaluators=evaluators,
            mutators=mutators,
            scorer=scorer,
            stores=(evidence_b, runs_b),
        )
        result_b = await runner_b.run(run_id="run-x", target=make_target(), specs=specs)
    finally:
        runs_b.close()

    # Byte-identical TestPlan.
    assert result_a.plan.model_dump_json() == result_b.plan.model_dump_json()

    # Identical finding id set (spec_id::target_id) and identical statuses.
    ids_a = [(f.spec_id, f.target_id, f.status.value) for f in result_a.findings]
    ids_b = [(f.spec_id, f.target_id, f.status.value) for f in result_b.findings]
    assert ids_a == ids_b

    # Byte-identical persisted findings (attempts + verdicts + risk), with the
    # injected fixed clock the whole TestRun serializes identically.
    assert result_a.run.model_dump_json() == result_b.run.model_dump_json()


async def test_attempt_ids_are_stable(evaluators, mutators, scorer, stores) -> None:
    scenario = make_scenario(VULNERABLE_RESPONSE)
    runner = _runner(
        scenario, evaluators=evaluators, mutators=mutators, scorer=scorer, stores=stores
    )
    result = await runner.run(
        run_id="run-x", target=make_target(), specs=[make_spec(mutations=["rot13"])]
    )
    ids = sorted(a.attempt_id for a in result.findings[0].attempts)
    expected = sorted(
        f"JB-REFUSAL-001::{mut}#{i}" for mut in ("identity", "rot13") for i in range(5)
    )
    assert ids == expected
