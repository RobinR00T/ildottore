"""Confidence aggregation + state gate tests (ADR-0003, OD-6, contract §4/§7)."""

from __future__ import annotations

import pytest

from ildottore.scoring.confidence import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    FindingState,
    aggregate_confidence,
    gate_state,
    has_capability_gap,
    has_judge_disagreement,
)
from ildottore.shared.enums import InconclusiveReason, VerdictStatus

from .conftest import make_verdict


def test_default_threshold_is_od6() -> None:
    assert DEFAULT_CONFIDENCE_THRESHOLD == 0.75


def test_aggregate_mean() -> None:
    verdicts = [make_verdict(confidence=0.8), make_verdict(confidence=0.6)]
    assert aggregate_confidence(verdicts) == pytest.approx(0.7)


def test_aggregate_empty_is_zero() -> None:
    assert aggregate_confidence([]) == 0.0


def test_confirmed_when_high_confidence_and_unanimous() -> None:
    verdicts = [make_verdict(VerdictStatus.FAIL, 0.9), make_verdict(VerdictStatus.FAIL, 0.85)]
    assert gate_state(verdicts, aggregate_confidence(verdicts)) is FindingState.CONFIRMED


def test_needs_review_below_threshold() -> None:
    verdicts = [make_verdict(VerdictStatus.FAIL, 0.5)]
    assert gate_state(verdicts, aggregate_confidence(verdicts)) is FindingState.NEEDS_REVIEW


def test_needs_review_on_judge_disagreement_even_if_confident() -> None:
    """High mean confidence but split verdicts ⇒ needs-review (contract §5)."""
    verdicts = [make_verdict(VerdictStatus.FAIL, 0.95), make_verdict(VerdictStatus.PASS, 0.95)]
    assert has_judge_disagreement(verdicts)
    assert gate_state(verdicts, aggregate_confidence(verdicts)) is FindingState.NEEDS_REVIEW


def test_needs_review_on_capability_gap() -> None:
    verdicts = [
        make_verdict(
            VerdictStatus.INCONCLUSIVE,
            0.95,
            reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
        )
    ]
    assert has_capability_gap(verdicts)
    assert gate_state(verdicts, aggregate_confidence(verdicts)) is FindingState.NEEDS_REVIEW


def test_no_capability_gap_for_other_inconclusive_reasons() -> None:
    verdicts = [
        make_verdict(
            VerdictStatus.INCONCLUSIVE,
            0.95,
            reason=InconclusiveReason.BLOCKED_BY_POLICY,
        )
    ]
    assert not has_capability_gap(verdicts)


def test_no_disagreement_single_verdict() -> None:
    assert not has_judge_disagreement([make_verdict(VerdictStatus.FAIL)])
    assert not has_judge_disagreement([])


def test_threshold_boundary_is_inclusive() -> None:
    """confidence == threshold ⇒ confirmed."""
    verdicts = [make_verdict(VerdictStatus.FAIL, 0.75)]
    assert gate_state(verdicts, 0.75, 0.75) is FindingState.CONFIRMED


def test_empty_verdicts_needs_review() -> None:
    assert gate_state([], aggregate_confidence([])) is FindingState.NEEDS_REVIEW
