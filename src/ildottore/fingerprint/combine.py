"""Weighted evidence fusion → guesses, confidence, spoofing flags (u09, step 6).

Consumes the flat :class:`~ildottore.shared.models.FingerprintEvidence` list from
every layer and fuses it into per-field guesses (contract §5 step 6):

* **family** - sum the (positive) weights of every family-attributed signal per
  family; the top family wins; ``confidence`` is its share of the total mass,
  softened so a lone weak signal never reads as certainty (contract §4 KEEP:
  empty/contradictory ⇒ low confidence, never a fabricated guess).
* **version** - same, restricted to signals that also carry a version, scoped to
  the winning family.
* **spoofing_flags** - if a weak ``self_report`` names a family that disagrees
  with the family the *statistical* layer most supports, raise
  ``self_report_conflicts_with_statistical``. The self-report's small weight is
  **excluded** from the family tally on conflict so it can never inflate the guess
  (contract §7: "0 cases where a spoofed self-id silently wins").

The combiner is pure and deterministic. A tie between the two leading families gives
``unknown`` and a tie between versions gives no version (a tie used to be broken by name, so
the alphabet chose); ranking helpers still order ties by name so replay is stable.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ildottore.fingerprint.attribution import parse_signal
from ildottore.fingerprint.layers.behavioral import SELF_REPORT_DETAIL
from ildottore.shared.models import FingerprintEvidence, FingerprintGuess

__all__ = ["SPOOF_FLAG", "CombinedFingerprint", "combine", "rank_families", "rank_versions"]

_STAT_LAYER = "statistical"
SPOOF_FLAG = "self_report_conflicts_with_statistical"
#: Evidence weights are rounded to six decimals, so a sum of several carries an error of a few
#: millionths: three 0.133333 weights are 0.399999, which must still tie with 0.4.
_TIE_TOLERANCE = 1e-5


@dataclass(frozen=True)
class CombinedFingerprint:
    """Fusion result the engine assembles into a ``ModelFingerprint``."""

    family: FingerprintGuess
    version: FingerprintGuess | None
    spoofing_flags: list[str]


def _confidence(top_mass: float, total_mass: float) -> float:
    """Confidence = share of mass, damped by absolute mass so weak wins stay low.

    ``share`` alone would report 1.0 for a single 0.05-weight signal; multiplying
    by a saturating absolute-evidence term keeps a thin verdict honestly uncertain
    (contract §4 KEEP). Bounded to ``[0,1]``.
    """

    if total_mass <= 0.0:
        return 0.0
    share = top_mass / total_mass
    saturation = total_mass / (total_mass + 0.5)  # → 1 as evidence accumulates
    return round(min(max(share * saturation, 0.0), 1.0), 6)


def combine(evidence: list[FingerprintEvidence]) -> CombinedFingerprint:
    """Fuse layer evidence into family/version guesses + spoofing flags."""

    self_report_family = _self_report_family(evidence)
    stat_family = _top_statistical_family(evidence)

    spoofing_flags: list[str] = []
    excluded_self_report = False
    if (
        self_report_family is not None
        and stat_family is not None
        and self_report_family != stat_family
    ):
        spoofing_flags.append(SPOOF_FLAG)
        excluded_self_report = True

    family_mass = _family_mass(evidence, exclude_self_report=excluded_self_report)
    family_guess = _guess_from_mass(family_mass)

    version_guess: FingerprintGuess | None = None
    if family_guess.confidence > 0.0:
        version_guess = _version_guess(evidence, family_guess.guess)

    return CombinedFingerprint(
        family=family_guess,
        version=version_guess,
        spoofing_flags=spoofing_flags,
    )


def rank_families(evidence: list[FingerprintEvidence]) -> list[str]:
    """Families ranked by fused positive mass (descending; ties by name).

    Exposed for the detection gate's top-k version/family scoring (contract §7).
    The self-report is included here (spoofing exclusion is a fusion-time concern,
    not a ranking concern) - callers wanting the spoof-safe guess use :func:`combine`.
    """

    mass = _family_mass(evidence, exclude_self_report=False)
    return sorted(mass, key=lambda fam: (-mass[fam], fam))


def rank_versions(evidence: list[FingerprintEvidence], family: str) -> list[str]:
    """Versions of ``family`` ranked by fused mass (descending; ties by name).

    Used by the detection gate to compute version **top-1 / top-3** accuracy
    (``docs/10 §6``, contract §7).
    """

    mass: dict[str, float] = {}
    for ev in evidence:
        if ev.weight <= 0.0:
            continue
        attr = parse_signal(ev.signal)
        if attr.family != family or attr.version is None:
            continue
        mass[attr.version] = mass.get(attr.version, 0.0) + ev.weight
    return sorted(mass, key=lambda ver: (-mass[ver], ver))


def _self_report_family(evidence: list[FingerprintEvidence]) -> str | None:
    """The family a weak ``self_report`` signal claims, if any."""

    for ev in evidence:
        attr = parse_signal(ev.signal)
        if attr.detail == SELF_REPORT_DETAIL and attr.family is not None:
            return attr.family
    return None


def _top_statistical_family(evidence: list[FingerprintEvidence]) -> str | None:
    """The family the statistical layer most supports (max positive weight)."""

    mass: dict[str, float] = {}
    for ev in evidence:
        if ev.layer != _STAT_LAYER or ev.weight <= 0.0:
            continue
        attr = parse_signal(ev.signal)
        if attr.family is None:
            continue
        mass[attr.family] = mass.get(attr.family, 0.0) + ev.weight
    if not mass:
        return None
    return max(sorted(mass), key=lambda fam: mass[fam])


def _family_mass(
    evidence: list[FingerprintEvidence], *, exclude_self_report: bool
) -> dict[str, float]:
    """Total positive weight per family across all layers (contradictions netted)."""

    mass: dict[str, float] = {}
    for ev in evidence:
        if ev.weight <= 0.0:
            continue
        attr = parse_signal(ev.signal)
        if attr.family is None:
            continue
        if exclude_self_report and attr.detail == SELF_REPORT_DETAIL:
            continue  # a conflicting self-report never counts toward the guess
        mass[attr.family] = mass.get(attr.family, 0.0) + ev.weight
    return mass


def _tied(first: float, second: float) -> bool:
    """Equal up to the rounding of evidence weights (see :data:`_TIE_TOLERANCE`)."""

    return math.isclose(first, second, rel_tol=0.0, abs_tol=_TIE_TOLERANCE)


def _guess_from_mass(mass: dict[str, float]) -> FingerprintGuess:
    """Pick the top family; empty ⇒ an explicit unknown at confidence 0."""

    if not mass:
        return FingerprintGuess(guess="unknown", confidence=0.0)
    total = sum(mass.values())
    ranked = sorted(mass, key=lambda fam: (-mass[fam], fam))
    if len(ranked) > 1 and _tied(mass[ranked[0]], mass[ranked[1]]):
        # A tie names no family: it used to be broken by name, so the alphabet picked it.
        return FingerprintGuess(guess="unknown", confidence=0.0)
    top_family = ranked[0]
    return FingerprintGuess(
        guess=top_family,
        confidence=_confidence(mass[top_family], total),
    )


def _version_guess(evidence: list[FingerprintEvidence], family: str) -> FingerprintGuess | None:
    """Fuse version signals scoped to the winning ``family``."""

    mass: dict[str, float] = {}
    for ev in evidence:
        if ev.weight <= 0.0:
            continue
        attr = parse_signal(ev.signal)
        if attr.family != family or attr.version is None:
            continue
        mass[attr.version] = mass.get(attr.version, 0.0) + ev.weight
    if not mass:
        return None
    total = sum(mass.values())
    ranked = sorted(mass, key=lambda ver: (-mass[ver], ver))
    if len(ranked) > 1 and _tied(mass[ranked[0]], mass[ranked[1]]):
        # A tie names no version. Every family-wide signal adds the same mass to each version of
        # the family (the pack shares fragments and centroids between them), so the name decided:
        # llama-3-8b with a 2023-03 cutoff, gpt-4-turbo, claude-opus (audit of the fingerprint).
        return None
    top_version = ranked[0]
    return FingerprintGuess(
        guess=top_version,
        confidence=_confidence(mass[top_version], total),
    )
