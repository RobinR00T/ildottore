"""Risk-magnitude + reproducibility tests (docs/05 §2, docs/01 §5, contract §7)."""

from __future__ import annotations

import pytest

from ildottore.scoring.risk import reproducibility_from_attempts, risk_magnitude
from ildottore.shared.enums import InconclusiveReason, VerdictStatus

from .conftest import make_attempt


def test_reproducibility_k_over_n() -> None:
    """k/N successes ⇒ reproducibility == k/N (contract §7)."""
    attempts = [make_attempt(VerdictStatus.FAIL) for _ in range(3)]
    attempts += [make_attempt(VerdictStatus.PASS) for _ in range(2)]
    assert reproducibility_from_attempts(attempts) == pytest.approx(3 / 5)


def test_reproducibility_all_fail_is_one() -> None:
    attempts = [make_attempt(VerdictStatus.FAIL) for _ in range(4)]
    assert reproducibility_from_attempts(attempts) == 1.0


def test_reproducibility_no_successes_is_zero() -> None:
    """N=0 successes ⇒ reproducibility 0 (⇒ risk 0 ⇒ Info downstream)."""
    attempts = [make_attempt(VerdictStatus.PASS) for _ in range(4)]
    assert reproducibility_from_attempts(attempts) == 0.0


def test_reproducibility_empty_is_zero() -> None:
    assert reproducibility_from_attempts([]) == 0.0


def test_inconclusive_attempts_count_in_the_denominator() -> None:
    """F1 / F-23 (audit 2026-10-03): ``k / N`` over every attempt, as ``docs/01 §5``,
    ``core.reproduce`` and ``dottore replay`` compute it. An inconclusive attempt is not
    coerced to pass; it is a run that did not demonstrate the exploit."""
    attempts = [
        make_attempt(VerdictStatus.FAIL),
        make_attempt(VerdictStatus.PASS),
        make_attempt(
            VerdictStatus.INCONCLUSIVE,
            inconclusive_reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
        ),
    ]
    assert reproducibility_from_attempts(attempts) == pytest.approx(1 / 3)


def test_one_exploit_and_four_timeouts_is_not_fully_reproducible() -> None:
    """The measured case: it scored 1.0 and Critical."""
    attempts = [make_attempt(VerdictStatus.FAIL)] + [
        make_attempt(VerdictStatus.FAIL, error="timeout") for _ in range(4)
    ]
    assert reproducibility_from_attempts(attempts) == pytest.approx(0.2)


def test_errored_and_verdictless_attempts_count_but_never_succeed() -> None:
    attempts = [
        make_attempt(VerdictStatus.FAIL),
        make_attempt(None),  # no verdict
        make_attempt(VerdictStatus.FAIL, error="timeout"),  # errored
    ]
    assert reproducibility_from_attempts(attempts) == pytest.approx(1 / 3)


def test_all_inconclusive_is_zero() -> None:
    attempts = [make_attempt(VerdictStatus.INCONCLUSIVE) for _ in range(3)]
    assert reproducibility_from_attempts(attempts) == 0.0


def test_risk_magnitude_product() -> None:
    assert risk_magnitude(4, 4, 1.0) == 16.0
    assert risk_magnitude(2, 3, 0.5) == 3.0
    assert risk_magnitude(1, 1, 0.0) == 0.0


def test_risk_magnitude_returns_raw_float_unrounded() -> None:
    """OD-6: product is the raw float, not rounded."""
    val = risk_magnitude(3, 3, 1 / 3)
    assert val == pytest.approx(3.0)
    val2 = risk_magnitude(4, 3, 2 / 3)
    assert val2 == pytest.approx(8.0)
