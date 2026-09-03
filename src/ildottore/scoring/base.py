"""The default :class:`~ildottore.shared.protocols.RiskScorer` implementation (``docs/05``).

``DefaultRiskScorer.score(spec, verdicts, attempts)`` turns one spec's verdicts and attempts
into a :class:`~ildottore.shared.models.RiskScore` on **two independent axes** (ADR-0003):

* **magnitude** ``risk = impact x exploitability x reproducibility`` ∈ ``[0, 16]``, banded on
  the raw float (OD-6); and
* **confidence** ∈ ``[0, 1]``, carried alongside and used only by the caller to gate finding
  state - never multiplied into ``risk``.

Impact and Exploitability are spec-declared (``spec.scoring``); reproducibility is the
successful-attack rate over ``attempts``; confidence is the mean over ``verdicts``. The state
gate (``confirmed`` vs ``needs-review``) is exposed via :meth:`DefaultRiskScorer.state` so a
caller can build a :class:`~ildottore.shared.models.Finding` without re-deriving it. Pure and
deterministic: identical inputs → byte-identical :class:`RiskScore` (contract §7).
"""

from __future__ import annotations

from ildottore.scoring.banding import BandPolicy, band_for_risk
from ildottore.scoring.confidence import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    FindingState,
    aggregate_confidence,
    gate_state,
)
from ildottore.scoring.risk import reproducibility_from_attempts, risk_magnitude
from ildottore.shared.models import AttackSpec, Attempt, RiskScore, Verdict

__all__ = ["DefaultRiskScorer"]


class DefaultRiskScorer:
    """Reference risk scorer (implements ``shared.protocols.RiskScorer``).

    ``band_policy`` and ``confidence_threshold`` are policy-tunable (contract §4 KEEP / OD-6);
    the defaults mirror ``docs/05 §3`` and OD-6 (``0.75``).
    """

    #: Advertised scorer id (parallels the ``type`` string on other primitives).
    name: str = "default"

    def __init__(
        self,
        band_policy: BandPolicy | None = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        self._band_policy = band_policy or BandPolicy()
        self._confidence_threshold = confidence_threshold

    def score(
        self,
        spec: AttackSpec,
        verdicts: list[Verdict],
        attempts: list[Attempt],
    ) -> RiskScore:
        """Compute the two-axis :class:`RiskScore` for one spec (``docs/05 §2``)."""
        impact = spec.scoring.impact
        exploitability = spec.scoring.exploitability
        reproducibility = reproducibility_from_attempts(attempts)
        risk = risk_magnitude(impact, exploitability, reproducibility)
        band = band_for_risk(risk, self._band_policy)
        confidence = aggregate_confidence(verdicts)
        return RiskScore(
            impact=impact,
            exploitability=exploitability,
            reproducibility=reproducibility,
            risk=risk,
            band=band,
            confidence=confidence,
        )

    def state(
        self,
        spec: AttackSpec,
        verdicts: list[Verdict],
    ) -> FindingState:
        """Gate the finding state (``confirmed`` vs ``needs-review``) for these verdicts.

        The spec declares its own ``confidence_threshold`` (schema-mandatory); this scorer's
        configured default (OD-6) is the fallback only if a caller ever supplies a spec
        without one. Confidence gates state only - never risk (ADR-0003).
        """
        threshold = spec.scoring.confidence_threshold
        confidence = aggregate_confidence(verdicts)
        return gate_state(verdicts, confidence, threshold)
