"""Model-comparison matrix (``docs/05 §5``, contract §6 ``ComparisonMatrix``).

When one suite runs against N targets, "compare models" becomes a first-class output: a
matrix ``(spec_id, target_id) → {band, repro, conf}`` plus per-category rollups, so the tool
earns its "benchmark + pentest" claim (``docs/05 §5``). Built from the same
:class:`~ildottore.shared.models.Finding` list as the run summary. Pure/deterministic - cell
ordering is sorted so replay is byte-identical (contract §7).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ildottore.shared.models import AttackSpec, Finding

__all__ = ["ComparisonMatrix", "MatrixCell", "build_comparison_matrix"]

_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MatrixCell:
    """One ``spec x target`` outcome (``docs/05 §5``)."""

    band: str
    repro: float
    conf: float


@dataclass(frozen=True)
class ComparisonMatrix:
    """``spec x target`` cells + per-OWASP-category band rollups (contract §6)."""

    cells: dict[tuple[str, str], MatrixCell]
    spec_ids: tuple[str, ...]
    target_ids: tuple[str, ...]
    #: category → band → count, over all cells (benchmark rollup, ``docs/05 §5``).
    category_rollups: dict[str, dict[str, int]] = field(default_factory=dict)


def build_comparison_matrix(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> ComparisonMatrix:
    """Build the ``spec x target`` :class:`ComparisonMatrix` from ``findings``.

    A ``(spec_id, target_id)`` pair appearing more than once keeps the **last** finding for
    that cell (callers pass one finding per pair per suite run). ``spec_ids`` / ``target_ids``
    are sorted for deterministic layout. Category rollups bucket each cell's band under its
    spec's OWASP category (``unknown`` when the spec is absent from ``specs``).
    """
    spec_map = specs or {}
    cells: dict[tuple[str, str], MatrixCell] = {}
    spec_ids: set[str] = set()
    target_ids: set[str] = set()
    rollups: dict[str, Counter[str]] = {}

    for finding in findings:
        key = (finding.spec_id, finding.target_id)
        band = finding.risk.band.value
        cells[key] = MatrixCell(
            band=band,
            repro=finding.risk.reproducibility,
            conf=finding.risk.confidence,
        )
        spec_ids.add(finding.spec_id)
        target_ids.add(finding.target_id)
        spec = spec_map.get(finding.spec_id)
        category = spec.owasp if spec is not None else _UNKNOWN
        rollups.setdefault(category, Counter())[band] += 1

    return ComparisonMatrix(
        cells=cells,
        spec_ids=tuple(sorted(spec_ids)),
        target_ids=tuple(sorted(target_ids)),
        category_rollups={cat: dict(counts) for cat, counts in sorted(rollups.items())},
    )
