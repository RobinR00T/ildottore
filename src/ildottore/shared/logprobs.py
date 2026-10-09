"""The figure a reply's logprob may be (u04 §7, clause A-39).

A logprob is ``log p`` of a probability ``p`` in ``(0, 1]``: a finite number at or below zero.
JSON bounds no number, so a reply can carry a figure no model produces, and ``float()`` either
raised on it or let it through: a 400-digit integer raised ``OverflowError`` and a list or an
object ``TypeError``, so ``fingerprint`` and ``run -sV`` exited 1 with no report and ``run``
aborted the campaign with exit 3; a positive token figure was scored as a "likely memorized"
finding; a NaN or an infinity was written into the report and the evidence as a bare token that
is not JSON (code audit of 2026-10-07).

The adapter (``adapters.base.map_logprobs``) reads a reply's figures through
:func:`readable_logprob`, and ``logprob_membership`` checks the figures it scores with it, so a
plugin adapter that builds its own ``TokenLogprob`` cannot get an impossible one scored either.
"""

from __future__ import annotations

import math

__all__ = ["readable_logprob"]


def readable_logprob(value: object) -> float | None:
    """The float ``value`` stands for when it is a logprob a model produces, else ``None``.

    Read: a JSON number (``int`` or ``float``, never a ``bool``) that converts to a finite float
    at or below zero, ``0`` included (certainty). Not read: anything else, including a string
    that spells a number and an integer too large for a float.
    """

    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        figure = float(value)
    except OverflowError:
        return None
    if not math.isfinite(figure) or figure > 0:
        return None
    return figure
