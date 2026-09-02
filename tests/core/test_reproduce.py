"""N-run reproducibility tests (contract §5.5, §7)."""

from __future__ import annotations

import pytest

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.core.budgets import BudgetLedger
from ildottore.core.reproduce import attempt_id_for, repro_from_verdicts, reproduce
from ildottore.shared.enums import InconclusiveReason, VerdictStatus
from ildottore.shared.models import ModelRequest, Sampling, Verdict


def _req() -> ModelRequest:
    return ModelRequest(prompt="hi", sampling=Sampling(temperature=0.0))


def _verdict(status: VerdictStatus) -> Verdict:
    reason = (
        InconclusiveReason.CAPABILITY_UNAVAILABLE if status is VerdictStatus.INCONCLUSIVE else None
    )
    return Verdict(
        status=status,
        confidence=0.9,
        reasoning="t",
        evaluator_type="refusal",
        inconclusive_reason=reason,
    )


def test_attempt_id_stable() -> None:
    assert attempt_id_for("S-1", "identity", 3) == "S-1::identity#3"


async def test_reproduce_walks_sequence_deterministically() -> None:
    scenario = MockScenario(response=["a", "b", "c"])
    target = MockTarget(scenario)
    ledger = BudgetLedger()
    results = await reproduce(
        target,
        _req(),
        spec_id="S-1",
        mutation="identity",
        sampling=Sampling(temperature=0.0),
        ledger=ledger,
        n=5,
    )
    texts = [r.attempt.response.text for r in results if r.attempt.response]
    # 5 runs cycling a 3-element sequence: a b c a b.
    assert texts == ["a", "b", "c", "a", "b"]
    # 5 attempts + 5 requests debited.
    assert ledger.snapshot().attempts == 5
    assert ledger.snapshot().requests == 5


async def test_reproduce_is_byte_stable_across_runs() -> None:
    scenario = MockScenario(response=["x", "y"])
    r1 = await reproduce(
        MockTarget(scenario),
        _req(),
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=BudgetLedger(),
        n=4,
        now=lambda: 0.0,
    )
    r2 = await reproduce(
        MockTarget(scenario),
        _req(),
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=BudgetLedger(),
        n=4,
        now=lambda: 0.0,
    )
    dump1 = [r.attempt.model_dump_json() for r in r1]
    dump2 = [r.attempt.model_dump_json() for r in r2]
    assert dump1 == dump2


async def test_reproduce_skips_completed_for_resume() -> None:
    scenario = MockScenario(response="a")
    ledger = BudgetLedger()
    completed = {attempt_id_for("S", "identity", 0), attempt_id_for("S", "identity", 1)}
    results = await reproduce(
        MockTarget(scenario),
        _req(),
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=ledger,
        n=3,
        completed=completed,
    )
    # Only run #2 executes; #0 and #1 are skipped (resume).
    assert [r.attempt.attempt_id for r in results] == ["S::identity#2"]
    assert ledger.snapshot().attempts == 1


async def test_reproduce_rejects_zero_n() -> None:
    with pytest.raises(ValueError, match="n must be"):
        await reproduce(
            MockTarget(MockScenario(response="a")),
            _req(),
            spec_id="S",
            mutation="identity",
            sampling=None,
            ledger=BudgetLedger(),
            n=0,
        )


def test_repro_fraction_counts_only_fails() -> None:
    verdicts = [
        _verdict(VerdictStatus.FAIL),
        _verdict(VerdictStatus.FAIL),
        _verdict(VerdictStatus.PASS),
        _verdict(VerdictStatus.INCONCLUSIVE),
    ]
    # 2 successful attacks over N=5 (inconclusive counts in denominator, not as success).
    assert repro_from_verdicts(verdicts, 5) == pytest.approx(0.4)


def test_repro_all_pass_is_zero() -> None:
    verdicts = [_verdict(VerdictStatus.PASS)] * 3
    assert repro_from_verdicts(verdicts, 3) == 0.0


def test_repro_rejects_zero_n() -> None:
    with pytest.raises(ValueError, match="n must be"):
        repro_from_verdicts([], 0)


async def test_max_tokens_is_a_pre_spend_reservation() -> None:
    """M12: a request's max_tokens is reserved BEFORE the send, so the token ceiling is a
    hard pre-spend cap, a send that would breach it never reaches the adapter."""

    from ildottore.core.budgets import BudgetExhausted, BudgetLedger

    class SpyTarget:
        id = "spy"

        def __init__(self) -> None:
            self.sends = 0

        async def send(self, request):
            self.sends += 1
            from ildottore.shared.models import ModelResponse

            return ModelResponse(text="ok")

        def capabilities(self):
            from ildottore.shared.models import Capabilities

            return Capabilities()

    spy = SpyTarget()
    ledger = BudgetLedger(max_tokens=100)
    req = ModelRequest(prompt="hi", sampling=Sampling(temperature=0.0, max_tokens=200))
    try:
        await reproduce(
            spy,
            req,
            spec_id="S",
            mutation="identity",
            sampling=req.sampling,
            ledger=ledger,
            n=1,
        )
        raise AssertionError("expected BudgetExhausted before any send")
    except BudgetExhausted as exc:
        assert exc.axis == "max_tokens"
    assert spy.sends == 0  # the cap was enforced before the provider was ever called
