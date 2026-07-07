"""Scoring unit (u07): two-axis risk model + run aggregation (``docs/05``, ADR-0003).

Public surface (see each submodule for detail):

* ``base.DefaultRiskScorer`` - the ``RiskScorer`` implementation.
* ``registry.get_scorer`` / ``registry.list_scorers`` - scorer discovery.
* ``banding.band_for_risk``, ``banding.BandPolicy`` - severity bands (policy-tunable).
* ``confidence.gate_state``, ``confidence.FindingState`` - confirmed vs needs-review.
* ``summary.build_run_summary`` / ``summary.build_test_run_summary`` - run aggregation.
* ``matrix.build_comparison_matrix`` - model-comparison matrix.
"""

from __future__ import annotations

from ildottore.scoring.banding import BandPolicy, band_for_risk, sarif_level_for_band
from ildottore.scoring.base import DefaultRiskScorer
from ildottore.scoring.confidence import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    FindingState,
    aggregate_confidence,
    gate_state,
)
from ildottore.scoring.matrix import ComparisonMatrix, MatrixCell, build_comparison_matrix
from ildottore.scoring.registry import get_scorer, list_scorers, register_scorer
from ildottore.scoring.risk import reproducibility_from_attempts, risk_magnitude
from ildottore.scoring.summary import (
    CategoryCounts,
    RunSummary,
    build_run_summary,
    build_test_run_summary,
)

__all__ = [
    "DEFAULT_CONFIDENCE_THRESHOLD",
    "BandPolicy",
    "CategoryCounts",
    "ComparisonMatrix",
    "DefaultRiskScorer",
    "FindingState",
    "MatrixCell",
    "RunSummary",
    "aggregate_confidence",
    "band_for_risk",
    "build_comparison_matrix",
    "build_run_summary",
    "build_test_run_summary",
    "gate_state",
    "get_scorer",
    "list_scorers",
    "register_scorer",
    "reproducibility_from_attempts",
    "risk_magnitude",
    "sarif_level_for_band",
]
