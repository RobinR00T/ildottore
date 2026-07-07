"""Risk magnitude axis: ``Impact x Exploitability x Reproducibility`` (``docs/05 §2``).

Pure/deterministic (contract §3). Impact and Exploitability are **spec-declared** inputs
(1-4, from :class:`~ildottore.shared.models.Scoring`) — this unit never sets them (contract
§8). Reproducibility is computed from raw per-attempt outcomes: the successful-attack rate
across N runs (``docs/01 §5``), where a *successful attack* is an attempt whose verdict is
``fail`` (fail = exploited, repo-wide polarity — ``docs/04``). A not-reproduced finding
(0 successes) yields reproducibility ``0`` ⇒ risk ``0`` ⇒ Info band (contract §7).

Confidence is **never** a factor here (ADR-0003, contract §8 hard fence).
"""

from __future__ import annotations

from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Attempt

__all__ = ["reproducibility_from_attempts", "risk_magnitude"]


def reproducibility_from_attempts(attempts: list[Attempt]) -> float:
    """Successful-attack rate ``k / N`` over the given attempts (``docs/01 §5``).

    ``N`` counts attempts that produced a decisive verdict (``pass`` or ``fail``); ``k``
    counts ``fail`` (exploited) verdicts among them. Attempts with no verdict, an error, or
    an ``inconclusive`` verdict are **excluded from the denominator** — they neither prove
    nor disprove reproducibility, and ``inconclusive`` is never coerced to pass/fail
    (contract §4 KEEP). With no decisive attempts, reproducibility is ``0.0`` (not
    reproduced). Result is exact ``k / N`` (OD-6 — banded on the raw float downstream).
    """
    decisive = 0
    successes = 0
    for attempt in attempts:
        verdict = attempt.verdict
        if verdict is None or attempt.error is not None:
            continue
        if verdict.status is VerdictStatus.FAIL:
            decisive += 1
            successes += 1
        elif verdict.status is VerdictStatus.PASS:
            decisive += 1
        # inconclusive → excluded from N (never coerced).
    if decisive == 0:
        return 0.0
    return successes / decisive


def risk_magnitude(impact: int, exploitability: int, reproducibility: float) -> float:
    """Compute ``impact x exploitability x reproducibility`` ∈ ``[0, 16]``.

    ``impact`` and ``exploitability`` are spec-declared integers in ``1..4``;
    ``reproducibility`` is a rate in ``[0, 1]``. The product is a float in ``[0, 16]``
    and is returned **unrounded** (OD-6): banding operates on this raw value.
    """
    return float(impact) * float(exploitability) * reproducibility
