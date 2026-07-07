"""Report-side run summary + model-comparison matrix (contract u11 §2, §6; ``docs/05 §4-§5``).

Reporting **reads** scored findings and rolls them into the ``RunSummary`` every format
embeds; it never computes or re-derives risk/bands/state (that is u07 — contract §8). It
also cannot import ``ildottore.scoring`` (same architecture layer, import-linter forbids
sibling imports), so the aggregation is re-derived here from the read-only
:class:`~ildottore.shared.models.Finding` / :class:`~ildottore.shared.models.RiskScore`
fields alone.

Framework attribution (OWASP / ATLAS tactic / NIST function) lives on the originating
:class:`~ildottore.shared.models.AttackSpec`, so callers pass a ``spec_id → AttackSpec`` map;
a finding whose spec is absent contributes ``unknown`` to the rollups (never silently dropped).
The model-comparison matrix is populated only when the run spans **more than one target**
(``docs/05 §5``). All collections are sorted so two renders are byte-identical (contract §7).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ildottore.shared.models import AttackSpec, Finding

__all__ = [
    "FrameworkCounts",
    "MatrixCell",
    "ModelComparison",
    "RunSummary",
    "build_run_summary",
]

_UNKNOWN = "unknown"


@dataclass(frozen=True)
class FrameworkCounts:
    """Finding counts bucketed by each framework taxonomy (``docs/05 §4``)."""

    owasp: dict[str, int] = field(default_factory=dict)
    atlas: dict[str, int] = field(default_factory=dict)
    nist: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class MatrixCell:
    """One ``spec x target`` outcome in the comparison matrix (``docs/05 §5``)."""

    spec_id: str
    target_id: str
    band: str
    reproducibility: float
    confidence: float


@dataclass(frozen=True)
class ModelComparison:
    """Benchmark matrix across >1 target (``docs/05 §5``); cells sorted for determinism."""

    spec_ids: tuple[str, ...]
    target_ids: tuple[str, ...]
    cells: tuple[MatrixCell, ...]
    #: OWASP category → band → count, over all cells.
    category_rollups: dict[str, dict[str, int]] = field(default_factory=dict)


@dataclass(frozen=True)
class RunSummary:
    """The aggregate every report embeds (contract §6 ``RunSummary``)."""

    total: int
    by_status: dict[str, int]
    by_band: dict[str, int]
    by_framework: FrameworkCounts
    repro_distribution: dict[str, float]
    confidence_distribution: dict[str, float]
    confirmed_count: int
    needs_review_count: int
    model_comparison: ModelComparison | None = None


def _distribution(values: list[float]) -> dict[str, float]:
    """min/max/mean/count for a list of ``[0,1]`` rates; zeros on empty (honest no-data)."""

    if not values:
        return {"count": 0.0, "min": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "count": float(len(values)),
        "min": min(values),
        "max": max(values),
        "mean": sum(values) / len(values),
    }


def _sorted_counts(counter: Counter[str]) -> dict[str, int]:
    """Return counts as a key-sorted dict (stable JSON key order)."""

    return {key: counter[key] for key in sorted(counter)}


def _build_comparison(
    findings: list[Finding],
    spec_map: dict[str, AttackSpec],
) -> ModelComparison:
    cells: dict[tuple[str, str], MatrixCell] = {}
    spec_ids: set[str] = set()
    target_ids: set[str] = set()
    rollups: dict[str, Counter[str]] = {}

    for finding in findings:
        band = finding.risk.band.value
        cells[finding.spec_id, finding.target_id] = MatrixCell(
            spec_id=finding.spec_id,
            target_id=finding.target_id,
            band=band,
            reproducibility=finding.risk.reproducibility,
            confidence=finding.risk.confidence,
        )
        spec_ids.add(finding.spec_id)
        target_ids.add(finding.target_id)
        spec = spec_map.get(finding.spec_id)
        category = spec.owasp if spec is not None else _UNKNOWN
        rollups.setdefault(category, Counter())[band] += 1

    ordered_cells = tuple(cells[key] for key in sorted(cells))
    return ModelComparison(
        spec_ids=tuple(sorted(spec_ids)),
        target_ids=tuple(sorted(target_ids)),
        cells=ordered_cells,
        category_rollups={cat: _sorted_counts(counts) for cat, counts in sorted(rollups.items())},
    )


def build_run_summary(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> RunSummary:
    """Aggregate ``findings`` into a :class:`RunSummary` (``docs/05 §4-§5``).

    ``specs`` maps ``spec_id → AttackSpec`` for framework attribution. ``model_comparison`` is
    populated only when the findings span more than one distinct ``target_id``.
    """

    spec_map = specs or {}
    by_status: Counter[str] = Counter()
    by_band: Counter[str] = Counter()
    owasp: Counter[str] = Counter()
    atlas: Counter[str] = Counter()
    nist: Counter[str] = Counter()
    repro_values: list[float] = []
    conf_values: list[float] = []
    confirmed = 0
    needs_review = 0
    targets: set[str] = set()

    for finding in findings:
        by_status[finding.status.value] += 1
        by_band[finding.risk.band.value] += 1
        repro_values.append(finding.risk.reproducibility)
        conf_values.append(finding.risk.confidence)
        targets.add(finding.target_id)
        if finding.confirmed:
            confirmed += 1
        else:
            needs_review += 1
        spec = spec_map.get(finding.spec_id)
        if spec is None:
            owasp[_UNKNOWN] += 1
            atlas[_UNKNOWN] += 1
            nist[_UNKNOWN] += 1
        else:
            owasp[spec.owasp] += 1
            atlas[spec.mitre_atlas.tactic] += 1
            nist[spec.nist_ai_rmf] += 1

    comparison = _build_comparison(findings, spec_map) if len(targets) > 1 else None

    return RunSummary(
        total=len(findings),
        by_status=_sorted_counts(by_status),
        by_band=_sorted_counts(by_band),
        by_framework=FrameworkCounts(
            owasp=_sorted_counts(owasp),
            atlas=_sorted_counts(atlas),
            nist=_sorted_counts(nist),
        ),
        repro_distribution=_distribution(repro_values),
        confidence_distribution=_distribution(conf_values),
        confirmed_count=confirmed,
        needs_review_count=needs_review,
        model_comparison=comparison,
    )
