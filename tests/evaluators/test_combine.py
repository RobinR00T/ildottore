"""Tests for verdict combination (evaluator_logic) — docs/04 §2."""

from __future__ import annotations

from ildottore.evaluators.combine import AGGREGATE_TYPE, combine
from ildottore.shared.enums import EvaluatorLogic, InconclusiveReason, VerdictStatus
from ildottore.shared.models import EvaluatorConfig, Verdict


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


def test_inconclusive_dominates_all_pass() -> None:
    v = combine([_v(VerdictStatus.PASS), _v(VerdictStatus.INCONCLUSIVE)], EvaluatorLogic.ALL_PASS)
    assert v.status is VerdictStatus.INCONCLUSIVE


def test_inconclusive_dominates_any_fail() -> None:
    v = combine([_v(VerdictStatus.FAIL), _v(VerdictStatus.INCONCLUSIVE)], EvaluatorLogic.ANY_FAIL)
    # Required inconclusive is never coerced — even a fail cannot override it.
    assert v.status is VerdictStatus.INCONCLUSIVE


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


def test_weighted_fail_majority() -> None:
    configs = [
        EvaluatorConfig(type="semantic_judge", weight=3.0),  # type: ignore[arg-type]
        EvaluatorConfig(type="regex_absence", weight=1.0),  # type: ignore[arg-type]
    ]
    v = combine(
        [_v(VerdictStatus.FAIL), _v(VerdictStatus.PASS)],
        EvaluatorLogic.WEIGHTED,
        configs=configs,
    )
    assert v.status is VerdictStatus.FAIL
    assert v.confidence == 0.75  # 3 / 4


def test_weighted_pass_majority() -> None:
    configs = [
        EvaluatorConfig(type="semantic_judge", weight=1.0),  # type: ignore[arg-type]
        EvaluatorConfig(type="regex_absence", weight=3.0),  # type: ignore[arg-type]
    ]
    v = combine(
        [_v(VerdictStatus.FAIL), _v(VerdictStatus.PASS)],
        EvaluatorLogic.WEIGHTED,
        configs=configs,
    )
    assert v.status is VerdictStatus.PASS


def test_weighted_excludes_inconclusive_from_tally() -> None:
    # One fail + one inconclusive → fail is 100% of the decisive weight.
    v = combine(
        [_v(VerdictStatus.FAIL), _v(VerdictStatus.INCONCLUSIVE)],
        EvaluatorLogic.WEIGHTED,
    )
    assert v.status is VerdictStatus.FAIL


def test_weighted_all_inconclusive_is_inconclusive() -> None:
    v = combine(
        [_v(VerdictStatus.INCONCLUSIVE), _v(VerdictStatus.INCONCLUSIVE)],
        EvaluatorLogic.WEIGHTED,
    )
    assert v.status is VerdictStatus.INCONCLUSIVE


def test_weighted_default_weights_when_configs_mismatch() -> None:
    # configs length mismatch → defaults to weight 1.0 each; 1 of 2 fail = 50% ≥ threshold.
    v = combine(
        [_v(VerdictStatus.FAIL), _v(VerdictStatus.PASS)],
        EvaluatorLogic.WEIGHTED,
        configs=[EvaluatorConfig(type="regex_absence")],  # type: ignore[arg-type]
    )
    assert v.status is VerdictStatus.FAIL
