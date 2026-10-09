"""What counts as a figure, for numbers a target or a stored record hands back (u00 shared).

A reply's ``usage`` and a run's stored spend are JSON written by someone else, and JSON numbers
have no bound: Python reads a 400-digit integer as an ``int``, ``1e400`` as an infinity and
``NaN`` as a NaN. Taken as figures, they were tracebacks and exit 1 wherever a float was made
of them (``float()`` of an integer past the largest float raises ``OverflowError``), and a
negative or NaN figure was taken as what was spent (2026-10-07). Every reader of such a figure
checks it with one of these first.
"""

from __future__ import annotations

import math
from typing import Final, TypeGuard

__all__ = ["MAX_EXACT_COUNT", "is_amount", "is_count"]

#: The last whole number in the run of integers a float holds exactly (``2**53``). A spend is
#: persisted through ``float`` and read back with ``int``, so every figure under it is exact in
#: that float, and no provider bills a reply anywhere near it. The bound is per figure: a
#: campaign's total can pass it, and is then rounded, not lost.
MAX_EXACT_COUNT: Final = 2**53


def is_amount(value: object) -> TypeGuard[int | float]:
    """A spend or latency figure: a finite, non-negative number a float can hold (not a bool)."""

    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:  # an integer past the largest float
        return False


def is_count(value: object) -> TypeGuard[int]:
    """A whole number from 0 to :data:`MAX_EXACT_COUNT` (a JSON bool or a float is not one)."""

    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_EXACT_COUNT
