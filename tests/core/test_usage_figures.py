"""Where a reported usage figure stops being read: the boundaries of ``_reported_total``.

The CLI tests (``tests/cli/test_usage_figures.py``) show the run finishing; these pin which
figures are believed. A send of ``"hi"`` with no ``max_tokens`` reserves 513 tokens, so 513 in
the ledger means the reservation stood.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.shared.amounts import MAX_EXACT_COUNT
from tests.test_audit_leftovers import _attempt_with

_RESERVED = 513
_PAST = MAX_EXACT_COUNT + 1
_HUGE = int("9" * 400)


def _recorded(usage: Mapping[str, object]) -> int:
    ledger = BudgetLedger()  # no ceiling: a believed figure is recorded, never refused
    _attempt_with(dict(usage), ledger)  # type: ignore[arg-type]
    return ledger.snapshot().tokens


@pytest.mark.parametrize(
    "usage",
    [
        {"total_tokens": MAX_EXACT_COUNT},
        {"tokens": MAX_EXACT_COUNT},
        {"input_tokens": MAX_EXACT_COUNT - 10, "output_tokens": 10},
        {"prompt_tokens": 10, "completion_tokens": MAX_EXACT_COUNT - 10},
        {"input_tokens": 1, "output_tokens": 1, "cache_read_input_tokens": MAX_EXACT_COUNT - 2},
    ],
)
def test_a_figure_up_to_two_to_the_53_is_believed(usage: dict[str, int]) -> None:
    assert _recorded(usage) == MAX_EXACT_COUNT


@pytest.mark.parametrize("figure", [_PAST, _HUGE], ids=["2**53+1", "400-digits"])
@pytest.mark.parametrize(
    "key",
    [
        "total_tokens",
        "tokens",
        "input_tokens",
        "output_tokens",
        "prompt_tokens",
        "completion_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ],
)
def test_a_figure_past_two_to_the_53_is_no_usage(key: str, figure: int) -> None:
    usage: dict[str, int] = {key: figure}
    if key.startswith("cache_"):
        usage.update(input_tokens=5, output_tokens=5)
    elif key in ("input_tokens", "output_tokens"):
        usage.setdefault("input_tokens", 5)
        usage.setdefault("output_tokens", 5)
    elif key in ("prompt_tokens", "completion_tokens"):
        usage.setdefault("prompt_tokens", 5)
        usage.setdefault("completion_tokens", 5)
    assert _recorded(usage) == _RESERVED


def test_a_sum_past_two_to_the_53_is_no_usage() -> None:
    half = MAX_EXACT_COUNT // 2
    assert _recorded({"input_tokens": half, "output_tokens": half}) == MAX_EXACT_COUNT
    assert _recorded({"input_tokens": half, "output_tokens": half + 1}) == _RESERVED
    usage = {"input_tokens": half, "output_tokens": half, "cache_read_input_tokens": 1}
    assert _recorded(usage) == _RESERVED


def test_an_unreadable_figure_falls_through_to_the_next_shape() -> None:
    assert _recorded({"total_tokens": _HUGE, "prompt_tokens": 7, "completion_tokens": 3}) == 10
    assert _recorded({"total_tokens": -1, "tokens": 40}) == 40
    pairs = {"input_tokens": _HUGE, "output_tokens": 5, "prompt_tokens": 7, "completion_tokens": 3}
    assert _recorded(pairs) == 10


def test_the_reading_order() -> None:
    """``total_tokens``, then ``tokens``, then input plus output, then prompt plus completion:
    the first readable shape wins, whatever the others say."""

    assert _recorded({"total_tokens": 9, "tokens": 700, "prompt_tokens": 50}) == 9
    assert _recorded({"total_tokens": 9, "input_tokens": 50, "output_tokens": 50}) == 9
    assert _recorded({"tokens": 40, "prompt_tokens": 50, "completion_tokens": 50}) == 40
    both = {"input_tokens": 1, "output_tokens": 1, "prompt_tokens": 50, "completion_tokens": 50}
    assert _recorded(both) == 2


@pytest.mark.parametrize("cache", [-1, "12", 1.5, True, _PAST, _HUGE])
def test_an_unreadable_cache_figure_makes_the_pair_a_floor(cache: object) -> None:
    """Trued up to the pair, never down. A negative, fractional or non-numeric cache figure was
    read as 0 before, so the reservation was trued down past cache tokens the reply says it
    billed; a larger one was believed. Read as no usage at all (the first version of this
    fix), it kept the 513 reserved below a pair of 100,005 (pre-commit audit)."""

    for pair in (("input_tokens", "output_tokens"), ("prompt_tokens", "completion_tokens")):
        small = {pair[0]: 5, pair[1]: 5, "cache_read_input_tokens": cache}
        assert _recorded(small) == _RESERVED
        large = {pair[0]: 100_000, pair[1]: 5, "cache_creation_input_tokens": cache}
        assert _recorded(large) == 100_005


def test_the_readable_cache_figure_still_counts_in_the_floor() -> None:
    usage = {
        "input_tokens": 5,
        "output_tokens": 5,
        "cache_creation_input_tokens": 1_000,
        "cache_read_input_tokens": "x",
    }
    assert _recorded(usage) == 1_010
    # One readable cache figure does not make the pair whole: 13 is still only a floor.
    usage["cache_creation_input_tokens"] = 3
    assert _recorded(usage) == _RESERVED


def test_a_floor_past_two_to_the_53_is_no_usage() -> None:
    usage = {"input_tokens": MAX_EXACT_COUNT, "output_tokens": 1, "cache_read_input_tokens": "x"}
    assert _recorded(usage) == _RESERVED


def test_a_floor_over_the_ceiling_is_recorded_and_halts() -> None:
    ledger = BudgetLedger(max_tokens=50_000)
    usage = {"input_tokens": 100_000, "output_tokens": 5, "cache_read_input_tokens": "x"}
    with pytest.raises(BudgetExhausted):
        _attempt_with(usage, ledger)  # type: ignore[arg-type]
    assert ledger.snapshot().tokens == 100_005


def test_cache_figures_of_zero_are_read() -> None:
    """A cache figure of 0 is a figure. Read as unreadable, the pair beside it would be only a
    floor, and a send that used less than its reservation would release none of it."""

    usage = {
        "input_tokens": 5,
        "output_tokens": 5,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    assert _recorded(usage) == 10


def test_a_cache_figure_beside_a_total_is_not_read() -> None:
    """The total already counts what the reply billed: a cache figure is summed only into a
    pair, so an unreadable one beside a readable total changes nothing."""

    assert _recorded({"total_tokens": 10, "cache_read_input_tokens": _HUGE}) == 10


def test_a_null_cache_figure_is_not_reported() -> None:
    usage = {"input_tokens": 5, "output_tokens": 5, "cache_creation_input_tokens": None}
    assert _recorded(usage) == 10
