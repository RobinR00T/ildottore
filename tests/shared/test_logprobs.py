"""The figure a reply's logprob may be (clause A-39): a finite JSON number at or below zero."""

from __future__ import annotations

import math

import pytest

from ildottore.shared.logprobs import readable_logprob


def _short(value: object) -> str:
    """A test id that stays short for a 400-digit integer."""

    text = repr(value)
    return text if len(text) <= 24 else f"{text[:6]}...{len(text)}-chars"


@pytest.mark.parametrize(
    "value",
    [
        10**400,
        -(10**400),
        float("inf"),
        float("-inf"),
        float("nan"),
        0.5,
        1e-300,
        1,
        True,
        False,
        "-0.5",
        "abc",
        None,
        [1],
        {},
    ],
    ids=_short,
)
def test_a_figure_no_model_produces_is_not_read(value: object) -> None:
    """``log p`` of a probability in (0, 1] is finite and never above zero; a ``bool`` is not a
    number in JSON, and a string that spells one is not read as one either."""

    assert readable_logprob(value) is None


@pytest.mark.parametrize(
    ("value", "figure"),
    [(0, 0.0), (-3, -3.0), (-0.01, -0.01), (-0.0, -0.0), (-9999.0, -9999.0), (-1e300, -1e300)],
    ids=_short,
)
def test_a_figure_a_model_produces_is_read_as_a_float(value: object, figure: float) -> None:
    read = readable_logprob(value)

    assert type(read) is float
    assert read == figure
    assert math.copysign(1.0, read) == math.copysign(1.0, figure)


def test_the_largest_integer_a_float_holds_is_read() -> None:
    """The boundary of ``float()`` itself: the most negative integer it converts is read, the
    next one past it is not (it would raise ``OverflowError``)."""

    edge = -(2**1024 - 2**970 - 1)

    assert readable_logprob(edge) == float(edge)
    assert readable_logprob(edge - 1) is None
