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


def test_inconclusive_excluded_from_denominator() -> None:
    """inconclusive is never coerced to pass/fail (contract §4 KEEP): excluded from N."""
    attempts = [
        make_attempt(VerdictStatus.FAIL),
        make_attempt(VerdictStatus.PASS),
        make_attempt(
            VerdictStatus.INCONCLUSIVE,
            inconclusive_reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
        ),
    ]
    # 1 fail / 2 decisive == 0.5 (the inconclusive drops out).
    assert reproducibility_from_attempts(attempts) == pytest.approx(0.5)


def test_errored_and_verdictless_attempts_excluded() -> None:
    attempts = [
        make_attempt(VerdictStatus.FAIL),
        make_attempt(None),  # no verdict
        make_attempt(VerdictStatus.FAIL, error="timeout"),  # errored
    ]
    assert reproducibility_from_attempts(attempts) == 1.0  # only the clean fail counts


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
