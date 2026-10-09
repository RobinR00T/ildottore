"""The two predicates every reader of a figure written by someone else goes through."""

from __future__ import annotations

import pytest

from ildottore.shared.amounts import MAX_EXACT_COUNT, is_amount, is_count

_HUGE = int("9" * 400)


def test_the_count_ceiling_is_the_last_integer_a_float_holds_exactly() -> None:
    assert float(MAX_EXACT_COUNT) == MAX_EXACT_COUNT
    assert float(MAX_EXACT_COUNT + 1) != MAX_EXACT_COUNT + 1


@pytest.mark.parametrize("value", [0, 1, 513, MAX_EXACT_COUNT])
def test_a_count(value: int) -> None:
    assert is_count(value)


@pytest.mark.parametrize(
    "value",
    [-1, MAX_EXACT_COUNT + 1, _HUGE, True, False, 12.0, float("inf"), float("nan"), "12", None],
)
def test_not_a_count(value: object) -> None:
    assert not is_count(value)


@pytest.mark.parametrize("value", [0, 0.0, 12.5, MAX_EXACT_COUNT + 1, 10**300, 1.7e308])
def test_an_amount(value: float) -> None:
    assert is_amount(value)


@pytest.mark.parametrize(
    "value", [-1, -0.5, _HUGE, True, float("inf"), float("-inf"), float("nan"), "12", None, [1]]
)
def test_not_an_amount(value: object) -> None:
    assert not is_amount(value)
