"""Severity banding: ``RiskScore`` float → :class:`ScanBand` → SARIF level.

Bands and cutoffs per ``docs/05 §3`` (contract §4 KEEP). Cutoffs are **policy-tunable**
(a policy pack may override them) — not hardcoded magic. The default cutoffs are::

    Critical >= 12  (error)
    High      8-11  (error)
    Medium    4-7   (warning)
    Low       1-3   (note)
    Info      0     (note)

Banding runs on the **raw float** ``risk`` before any rounding (OD-6): a score of ``11.9``
bands *High*, not *Critical* by rounding up. This module is pure and deterministic — a
function of its inputs only (contract §3), never touching confidence (ADR-0003).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ildottore.shared.enums import ScanBand

__all__ = ["BandPolicy", "band_for_risk", "sarif_level_for_band"]


# SARIF level per band (``docs/05 §3``). Stable — not policy-tunable.
_SARIF_LEVEL: dict[ScanBand, str] = {
    ScanBand.CRITICAL: "error",
    ScanBand.HIGH: "error",
    ScanBand.MEDIUM: "warning",
    ScanBand.LOW: "note",
    ScanBand.INFO: "note",
}


@dataclass(frozen=True)
class BandPolicy:
    """Lower-bound cutoffs for each band, applied to the **raw float** risk.

    A risk ``r`` lands in the highest band whose cutoff it meets: ``r >= critical`` →
    Critical, else ``r >= high`` → High, and so on. Anything strictly below ``low`` (i.e.
    a not-reproduced ``0``) is Info. Defaults mirror ``docs/05 §3``; a policy pack may pass
    its own instance to :func:`band_for_risk` (contract §4 KEEP — tunable, not magic).
    """

    critical: float = 12.0
    high: float = 8.0
    medium: float = 4.0
    low: float = 1.0

    # Ordered high→low band/cutoff pairs, memoized for a deterministic scan.
    _ordered: tuple[tuple[ScanBand, float], ...] = field(
        default=(), init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        ordered = (
            (ScanBand.CRITICAL, self.critical),
            (ScanBand.HIGH, self.high),
            (ScanBand.MEDIUM, self.medium),
            (ScanBand.LOW, self.low),
        )
        object.__setattr__(self, "_ordered", ordered)


_DEFAULT_POLICY = BandPolicy()


def band_for_risk(risk: float, policy: BandPolicy | None = None) -> ScanBand:
    """Map a raw ``risk`` float in ``[0, 16]`` to its severity band.

    Bands on the raw float (OD-6) — no rounding. Any risk below the ``low`` cutoff
    (canonically a not-reproduced ``0.0``) is :attr:`ScanBand.INFO`.
    """
    active = policy or _DEFAULT_POLICY
    for band, cutoff in active._ordered:
        if risk >= cutoff:
            return band
    return ScanBand.INFO


def sarif_level_for_band(band: ScanBand) -> str:
    """Return the SARIF level (``error`` / ``warning`` / ``note``) for a band."""
    return _SARIF_LEVEL[band]
