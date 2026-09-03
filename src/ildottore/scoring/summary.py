"""Run-summary aggregation (``docs/05 §4``, contract §5-§6).

Rolls a list of :class:`~ildottore.shared.models.Finding` into honest, uncertainty-aware
counts: by verdict status, by severity band, by framework category (OWASP LLM / MITRE ATLAS
tactic / NIST AI-RMF function), plus reproducibility and confidence distributions. ``TestRun``
carries the slim shared :class:`~ildottore.shared.models.TestRunSummary` (owned by u00); this
module builds both that slim shape (:func:`build_test_run_summary`) and the richer
:class:`RunSummary` the contract §6 describes (with distributions). Pure/deterministic.

Category attribution requires the originating :class:`~ildottore.shared.models.AttackSpec`
(the OWASP/ATLAS/NIST fields live there, not on the finding), so callers pass a
``spec_id → AttackSpec`` map; findings whose spec is absent are counted in ``by_status``/
``by_band`` but contribute ``unknown`` to the category rollups (never silently dropped).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ildottore.shared.models import AttackSpec, Finding, TestRunSummary

__all__ = ["CategoryCounts", "RunSummary", "build_run_summary", "build_test_run_summary"]

_UNKNOWN = "unknown"


@dataclass(frozen=True)
class CategoryCounts:
    """Finding counts bucketed by each framework taxonomy (``docs/05 §4``)."""

    owasp: dict[str, int] = field(default_factory=dict)
    atlas: dict[str, int] = field(default_factory=dict)
    nist: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RunSummary:
    """Rich run summary with distributions (contract §6 ``RunSummary``)."""

    total: int
    by_status: dict[str, int]
    by_band: dict[str, int]
    by_category: CategoryCounts
    repro_dist: dict[str, float]
    conf_dist: dict[str, float]


def _distribution(values: list[float]) -> dict[str, float]:
    """Summary stats for a list of ``[0,1]`` rates: min/max/mean/count.

    Empty input yields zeros - an honest "no data" rather than a divide-by-zero or a
    misleading default (``docs/05 §4``).
    """
    if not values:
        return {"count": 0.0, "min": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "count": float(len(values)),
        "min": min(values),
        "max": max(values),
        "mean": sum(values) / len(values),
    }


def build_run_summary(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> RunSummary:
    """Aggregate ``findings`` into a :class:`RunSummary` (``docs/05 §4``).

    ``specs`` maps ``spec_id → AttackSpec`` for framework-category attribution; when a
    finding's spec is missing it contributes ``unknown`` to the category rollups.
    """
    spec_map = specs or {}
    by_status: Counter[str] = Counter()
    by_band: Counter[str] = Counter()
    owasp: Counter[str] = Counter()
    atlas: Counter[str] = Counter()
    nist: Counter[str] = Counter()
    repro_values: list[float] = []
    conf_values: list[float] = []

    for finding in findings:
        by_status[finding.status.value] += 1
        by_band[finding.risk.band.value] += 1
        repro_values.append(finding.risk.reproducibility)
        conf_values.append(finding.risk.confidence)
        spec = spec_map.get(finding.spec_id)
        if spec is None:
            owasp[_UNKNOWN] += 1
            atlas[_UNKNOWN] += 1
            nist[_UNKNOWN] += 1
        else:
            owasp[spec.owasp] += 1
            atlas[spec.mitre_atlas.tactic] += 1
            nist[spec.nist_ai_rmf] += 1

    return RunSummary(
        total=len(findings),
        by_status=dict(by_status),
        by_band=dict(by_band),
        by_category=CategoryCounts(
            owasp=dict(owasp),
            atlas=dict(atlas),
            nist=dict(nist),
        ),
        repro_dist=_distribution(repro_values),
        conf_dist=_distribution(conf_values),
    )


def build_test_run_summary(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> TestRunSummary:
    """Build the slim shared :class:`TestRunSummary` (u00 shape) for ``TestRun.summary``.

    ``by_category`` here is the flattened OWASP rollup (the shared model has a single
    ``by_category`` dict); the richer per-framework view lives in :class:`RunSummary`.
    """
    rich = build_run_summary(findings, specs)
    return TestRunSummary(
        by_status=rich.by_status,
        by_band=rich.by_band,
        by_category=rich.by_category.owasp,
        total=rich.total,
    )
