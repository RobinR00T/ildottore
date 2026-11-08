"""The Wilson score interval behind every reproducibility rate (u07 A-126)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ildottore.shared.intervals import described_rate, wilson_interval


@pytest.mark.parametrize(
    ("k", "n", "low", "high"),
    [
        # Wilson (1927) at z = 1.96, from the closed form; 1/5 is the textbook worked example.
        (1, 5, 0.0362, 0.6245),
        (0, 1, 0.0, 0.7935),
        (3, 10, 0.1078, 0.6032),
        (200, 1000, 0.1764, 0.2259),
        (5, 5, 0.5655, 1.0),
    ],
)
def test_known_intervals(k: int, n: int, low: float, high: float) -> None:
    got_low, got_high = wilson_interval(k, n)
    assert got_low == pytest.approx(low, abs=1e-4)
    assert got_high == pytest.approx(high, abs=1e-4)


def test_one_in_five_and_two_hundred_in_a_thousand_are_not_the_same_evidence() -> None:
    small = wilson_interval(1, 5)
    large = wilson_interval(200, 1000)
    assert small[1] - small[0] > 10 * (large[1] - large[0])


def test_the_ends_are_exact() -> None:
    assert wilson_interval(0, 7)[0] == 0.0
    assert wilson_interval(7, 7)[1] == 1.0


@pytest.mark.parametrize(("k", "n"), [(0, 0), (1, 0), (-1, 3), (4, 3)])
def test_no_trial_or_impossible_counts_are_refused(k: int, n: int) -> None:
    with pytest.raises(ValueError):
        wilson_interval(k, n)


_COUNTS = st.integers(min_value=1, max_value=10_000).flatmap(
    lambda n: st.tuples(st.integers(0, n), st.just(n))
)


@given(_COUNTS)
def test_the_interval_holds_the_rate_inside_zero_one(case: tuple[int, int]) -> None:
    k, n = case
    low, high = wilson_interval(k, n)
    assert 0.0 <= low <= k / n <= high <= 1.0


def test_described_rate() -> None:
    assert described_rate(1, 5) == "1/5, 95% CI 0.04 to 0.62"
