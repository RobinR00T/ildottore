"""Direct coverage of runner combination/status helpers + degenerate branches."""

from __future__ import annotations

from ildottore.core import runner as R
from ildottore.core.runner import CampaignRunner
from ildottore.shared.enums import (
    InconclusiveReason,
    VerdictStatus,
)
from ildottore.shared.models import Attack, Attempt, ModelRequest, Verdict

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


def _v(status: VerdictStatus, *, conf: float = 0.9, matched=None, reason=None) -> Verdict:
    return Verdict(
        status=status,
        confidence=conf,
        reasoning="t",
        matched=matched or [],
        evaluator_type="e",
        inconclusive_reason=reason,
    )


# --- combine ----------------------------------------------------------------


def test_combine_empty_is_inconclusive() -> None:
    v = R._combine_verdicts([], make_spec())
    assert v.status is VerdictStatus.INCONCLUSIVE


def test_combine_any_inconclusive_dominates() -> None:
    v = R._combine_verdicts(
        [
            _v(VerdictStatus.PASS),
            _v(VerdictStatus.INCONCLUSIVE, reason=InconclusiveReason.CAPABILITY_UNAVAILABLE),
        ],
        make_spec(),
    )
    assert v.status is VerdictStatus.INCONCLUSIVE
    assert v.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE


def test_combine_fail_wins_over_pass() -> None:
    v = R._combine_verdicts(
        [_v(VerdictStatus.PASS), _v(VerdictStatus.FAIL, matched=["x"])], make_spec()
    )
    assert v.status is VerdictStatus.FAIL
    assert "x" in v.matched


def test_combine_all_pass() -> None:
    v = R._combine_verdicts(
        [_v(VerdictStatus.PASS, conf=0.8), _v(VerdictStatus.PASS, conf=0.6)], make_spec()
    )
    assert v.status is VerdictStatus.PASS
    assert v.confidence == 0.6  # min of passes


def test_shared_reason_none_when_conflicting() -> None:
    reasons = [
        _v(VerdictStatus.INCONCLUSIVE, reason=InconclusiveReason.CAPABILITY_UNAVAILABLE),
        _v(VerdictStatus.INCONCLUSIVE, reason=InconclusiveReason.JUDGE_COMPROMISED),
    ]
    assert R._shared_inconclusive_reason(reasons) is None


# --- status / repro helpers -------------------------------------------------


def test_dominant_status_all_inconclusive() -> None:
    assert (
        R._dominant_status(
            [_v(VerdictStatus.INCONCLUSIVE, reason=InconclusiveReason.BLOCKED_BY_POLICY)]
        )
        is VerdictStatus.INCONCLUSIVE
    )


def test_dominant_status_empty() -> None:
    assert R._dominant_status([]) is VerdictStatus.INCONCLUSIVE


def test_confirmed_requires_fail_and_threshold() -> None:
    spec = make_spec(confidence_threshold=0.95)
    # A fail below threshold is NOT confirmed.
    assert R._is_confirmed(VerdictStatus.FAIL, [_v(VerdictStatus.FAIL, conf=0.5)], spec) is False
    # Non-fail status never confirmed.
    assert R._is_confirmed(VerdictStatus.PASS, [_v(VerdictStatus.PASS)], spec) is False


def test_base_prompt_carrier_and_turns() -> None:
    carrier_spec = make_spec()
    carrier_spec = carrier_spec.model_copy(update={"attack": Attack(carrier="in a doc")})
    assert R._base_prompt(carrier_spec) == "in a doc"

    turns_spec = make_spec().model_copy(update={"attack": Attack(turns=["first", "second"])})
    assert R._base_prompt(turns_spec) == "first"


def test_completed_attempt_ids_reads_responses_and_errors() -> None:
    a1 = Attempt(attempt_id="a1", spec_id="S", request=ModelRequest(prompt="x"), error="boom")
    from ildottore.shared.enums import ScanBand
    from ildottore.shared.enums import VerdictStatus as VS
    from ildottore.shared.models import Finding, RiskScore

    finding = Finding(
        spec_id="S",
        target_id="t",
        status=VS.INCONCLUSIVE,
        risk=RiskScore(
            impact=1,
            exploitability=1,
            reproducibility=0.0,
            risk=0.0,
            band=ScanBand.INFO,
            confidence=0.0,
        ),
        confirmed=False,
        attempts=[a1],
    )
    from ildottore.shared.models import TestRun

    run = TestRun(run_id="r", findings=[finding])
    assert R._completed_attempt_ids(run) == {"a1"}
    assert R._completed_attempt_ids(None) == set()


# --- runner: unregistered evaluator + unregistered mutation -----------------


async def test_unregistered_evaluator_type_is_inconclusive(mutators, scorer, stores) -> None:
    """An evaluator type absent from the registry yields inconclusive, not a crash."""

    class EmptyEvaluators:
        def has(self, type_name: str) -> bool:
            return False

        def get(self, type_name: str):  # pragma: no cover - never reached
            raise KeyError(type_name)

    evidence, runs = stores
    scenario = make_scenario(VULNERABLE_RESPONSE)
    runner = CampaignRunner(
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=EmptyEvaluators(),
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=2,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])
    assert result.findings[0].status is VerdictStatus.INCONCLUSIVE


def test_confirmed_false_when_status_fail_but_no_fail_verdicts() -> None:
    # Defensive: status says FAIL but the verdict list carries no fail (shouldn't
    # happen in practice) → not confirmed rather than a divide-by-zero.
    spec = make_spec()
    assert R._is_confirmed(VerdictStatus.FAIL, [_v(VerdictStatus.PASS)], spec) is False


async def test_product_exception_propagates_through_runner(
    mutators, evaluators, scorer, stores
) -> None:
    """A non-budget adapter exception is a real defect and must not be masked."""

    class ExplodingAdapter:
        id = "t1"

        async def send(self, request):
            raise RuntimeError("product defect")

        def capabilities(self):
            from ildottore.shared.models import Capabilities

            return Capabilities()

    evidence, runs = stores
    runner = CampaignRunner(
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: ExplodingAdapter(),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=2,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    import pytest

    with pytest.raises(RuntimeError, match="product defect"):
        await runner.run(run_id="r1", target=make_target(), specs=[make_spec()])


async def test_unregistered_mutation_falls_back_to_identity(evaluators, scorer, stores) -> None:
    """A mutation not in the registry is applied as identity (unchanged carrier)."""

    class NoMutators:
        def has(self, name: str) -> bool:
            return False

        def get(self, name: str):  # pragma: no cover
            raise KeyError(name)

    evidence, runs = stores
    scenario = make_scenario(HARDENED_RESPONSE)
    spec = make_spec(mutations=["unknown_mut"])
    runner = CampaignRunner(
        policy=make_policy_engine(),
        mutators=NoMutators(),
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(scenario),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=2,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = await runner.run(run_id="r1", target=make_target(), specs=[spec])
    # identity + unknown_mut both ran (fallback = identity transform), 2 muts x 2 runs.
    assert len(result.findings[0].attempts) == 4
