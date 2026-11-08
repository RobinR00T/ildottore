"""The Wilson score interval of a success rate ``k / n`` (u07 A-126).

A reproducibility of 0.2 means one exploit in five tries or two hundred in a thousand, and the
two are not the same evidence. The reports print the count beside the rate and this interval:
the range of true rates consistent with ``k`` successes in ``n`` independent trials at 95%.
Wilson's interval keeps inside ``[0, 1]`` and does not collapse to a point at ``k = 0`` or
``k = n``, where the textbook normal interval says ``0.0 to 0.0`` after a single try.

Pure arithmetic, no I/O; in ``shared`` so the scorer and every reporter read the same function.
"""

from __future__ import annotations

import math
from typing import Final

__all__ = ["Z_95", "described_rate", "wilson_interval"]

#: The two-sided 95% normal quantile.
Z_95: Final = 1.959963984540054


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """The Wilson score interval for ``successes`` in ``trials``, as ``(low, high)``.

    Raises :class:`ValueError` for ``trials < 1`` or ``successes`` outside ``0..trials``: an
    interval over no trial is not ``(0, 1)``, it is no measurement.
    """

    if trials < 1:
        raise ValueError(f"an interval needs at least one trial, got {trials}")
    if not 0 <= successes <= trials:
        raise ValueError(f"successes must be in 0..{trials}, got {successes}")
    p = successes / trials
    z2 = z * z
    denom = 1.0 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials)) / denom
    # The exact bounds at k = 0 and k = n are 0 and 1; floating point can miss them by an ulp.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == trials else min(1.0, centre + half)
    return low, high


def described_rate(successes: int, trials: int) -> str:
    """``"1/5, 95% CI 0.04 to 0.62"``: the counts and the interval, as every report prints them."""

    low, high = wilson_interval(successes, trials)
    return f"{successes}/{trials}, 95% CI {low:.2f} to {high:.2f}"
