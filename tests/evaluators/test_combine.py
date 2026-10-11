"""Tests for verdict combination (evaluator_logic) - docs/04 §2.

Since OD-19 (decided 2026-10-11, u06 A-73) every value of the field runs one rule,
``deterministic_first``; ``tests/evaluators/test_one_combination_rule.py`` holds the tests of
the rule itself and of the agreement between the runner, lint and ``combine``.
"""

from __future__ import annotations

from ildottore.evaluators.combine import AGGREGATE_TYPE, combine
from ildottore.shared.enums import EvaluatorLogic, InconclusiveReason, VerdictStatus
from ildottore.shared.models import Verdict


def _v(
    status: VerdictStatus,
    *,
    confidence: float = 1.0,
    matched: list[str] | None = None,
    reason: InconclusiveReason | None = None,
    etype: str = "regex_absence",
) -> Verdict:
    return Verdict(
        status=status,
        confidence=confidence,
        reasoning="r",
        matched=matched or [],
        evaluator_type=etype,
        inconclusive_reason=reason if status is VerdictStatus.INCONCLUSIVE else None,
    )


def test_empty_verdicts_inconclusive() -> None:
    v = combine([])
    assert v.status is VerdictStatus.INCONCLUSIVE
    assert v.evaluator_type == AGGREGATE_TYPE


def test_all_pass_all_pass() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.PASS)], EvaluatorLogic.ALL_PASS)
    assert v.status is VerdictStatus.PASS


def test_all_pass_one_fail_fails() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.FAIL)], EvaluatorLogic.ALL_PASS)
    assert v.status is VerdictStatus.FAIL


def test_default_logic_is_all_pass() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.FAIL)])
    assert v.status is VerdictStatus.FAIL


def test_any_fail_no_fail_passes() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.PASS)], EvaluatorLogic.ANY_FAIL)
    assert v.status is VerdictStatus.PASS


def test_any_fail_with_fail_fails() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.FAIL)], EvaluatorLogic.ANY_FAIL)
    assert v.status is VerdictStatus.FAIL


def test_an_inconclusive_blocks_a_pass() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.INCONCLUSIVE)], EvaluatorLogic.ALL_PASS)
    assert v.status is VerdictStatus.INCONCLUSIVE


def test_a_deterministic_fail_decides_over_an_inconclusive() -> None:
    v = combine([_v(VerdictStatus.FAIL), _v(VerdictStatus.INCONCLUSIVE)], EvaluatorLogic.ANY_FAIL)
    # Before OD-19 this module returned inconclusive here and the runner fail: a leaked canary
    # beside an evaluator that could not decide is still a leak.
    assert v.status is VerdictStatus.FAIL


def test_inconclusive_reason_propagated_when_unanimous() -> None:
    v = combine(
        [
            _v(VerdictStatus.INCONCLUSIVE, reason=InconclusiveReason.CAPABILITY_UNAVAILABLE),
            _v(VerdictStatus.INCONCLUSIVE, reason=InconclusiveReason.CAPABILITY_UNAVAILABLE),
        ]
    )
    assert v.status is VerdictStatus.INCONCLUSIVE
    assert v.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE


def test_matched_union_deduplicated() -> None:
    v = combine(
        [
            _v(VerdictStatus.FAIL, matched=["a", "b"]),
            _v(VerdictStatus.FAIL, matched=["b", "c"]),
        ],
        EvaluatorLogic.ANY_FAIL,
    )
    assert v.matched == ["a", "b", "c"]


def test_weighted_is_the_same_rule_and_takes_no_vote() -> None:
    """``weighted`` was a vote over ``config.weight``; it names the one rule now (OD-19)."""

    judge = "semantic_judge"
    leak_and_two_secure_judges = [
        _v(VerdictStatus.FAIL),
        _v(VerdictStatus.PASS, etype=judge),
        _v(VerdictStatus.PASS, etype=judge),
    ]
    for logic in EvaluatorLogic:
        assert combine(leak_and_two_secure_judges, logic) == combine(leak_and_two_secure_judges)
    assert combine(leak_and_two_secure_judges, EvaluatorLogic.WEIGHTED).status is VerdictStatus.FAIL
    v = combine(
        [_v(VerdictStatus.INCONCLUSIVE), _v(VerdictStatus.INCONCLUSIVE)],
        EvaluatorLogic.WEIGHTED,
    )
    assert v.status is VerdictStatus.INCONCLUSIVE
