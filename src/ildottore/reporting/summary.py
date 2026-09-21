"""Report-side run summary + model-comparison matrix (contract u11 §2, §6; ``docs/05 §4-§5``).

Reporting **reads** scored findings and rolls them into the ``RunSummary`` every format
embeds; it never computes or re-derives risk/bands/state (that is u07 - contract §8). It
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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from ildottore.shared.frameworks import (
    ATLAS_MATRIX_RELEASE,
    ATLAS_OUT_OF_MATRIX,
    ATLAS_TACTIC_UNIVERSE,
    OWASP_LLM_EDITION,
    OWASP_LLM_TOTAL,
    OWASP_LLM_UNIVERSE,
    OWASP_RAI_UNIVERSE,
)
from ildottore.shared.iopc import (
    IOPC_IMPACT_UNIVERSE,
    IOPC_IMPACTS,
    IOPC_TECHNIQUE_UNIVERSE,
    IOPC_TECHNIQUES,
)
from ildottore.shared.models import AttackSpec, Finding

__all__ = [
    "ATLAS_MATRIX_RELEASE",
    "ATLAS_OUT_OF_MATRIX",
    "ATLAS_TACTIC_UNIVERSE",
    "OWASP_LLM_EDITION",
    "OWASP_LLM_TOTAL",
    "OWASP_LLM_UNIVERSE",
    "OWASP_RAI_UNIVERSE",
    "AxisCoverage",
    "BatteryCoverage",
    "Coverage",
    "FrameworkCounts",
    "MatrixCell",
    "ModelComparison",
    "RunStatus",
    "RunSummary",
    "build_battery_coverage",
    "build_run_summary",
    "pct_display",
]

_UNKNOWN = "unknown"


def pct_display(exercised: int, total: int) -> str:
    """An integer percentage that reads ``100%`` only when the axis really is complete.

    ``"%.0f" % (199 / 200 * 100)`` prints ``100``, so one uncovered code out of two hundred
    would be published as full coverage. Every percentage in this tool is read as a claim
    about what was tested, so the display floors instead of rounding: an incomplete axis
    tops out at ``99%``, and ``100%`` is reachable only by ``exercised >= total``.
    """

    if total <= 0:
        return "0%"
    if exercised >= total:
        return "100%"
    return f"{exercised * 100 // total}%"


# The Nova IoPC universe lives in ``shared.iopc`` because the linter validates against it too
# and ``registry`` and ``reporting`` are peers that must not import each other (docs/01 §2).

# The OWASP LLM and MITRE ATLAS universes live in ``shared.frameworks`` for the same reason
# the IoPC one lives in ``shared.iopc``: the linter validates against them too, and
# ``registry`` and ``reporting`` are peers that must not import each other (docs/01 §2).
# Re-exported here because every caller of coverage already imports them from this module.


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
class Coverage:
    """How much of the framework surface a run actually exercised (``docs/12`` P1).

    Coverage answers "passed the scan - of *what*?". It reports the fraction of the OWASP
    LLM Top 10, the MITRE ATLAS tactic matrix and both Nova IoPC axes (techniques = the how,
    impacts = the damage) that the run's specs touched, plus a
    breakdown of specs run vs. inconclusive/blocked, so a green run over a narrow suite can
    never masquerade as broad assurance. Percentages are fractions in ``[0, 1]`` (multiply by
    100 for display); ``unknown`` framework buckets (specs the reporter could not attribute)
    do **not** count toward the numerator.
    """

    #: distinct OWASP categories exercised (excludes ``unknown``).
    owasp_categories: tuple[str, ...]
    owasp_exercised: int
    owasp_total: int
    owasp_pct: float
    #: distinct *known* ATLAS tactics exercised (excludes ``unknown`` + off-universe names).
    atlas_tactics: tuple[str, ...]
    atlas_exercised: int
    atlas_total: int
    atlas_pct: float
    #: spec-execution disposition counts (rolled up from finding verdict status).
    specs_total: int
    specs_run: int
    specs_pass: int
    specs_fail: int
    specs_inconclusive: int
    #: distinct IoPC TECHNIQUE codes exercised (the *how*); see ``shared.iopc``.
    iopc_techniques: tuple[str, ...] = ()
    iopc_techniques_exercised: int = 0
    iopc_techniques_total: int = 0
    iopc_techniques_pct: float = 0.0
    #: distinct IoPC IMPACT codes exercised (the *damage*): the axis a committee reads.
    iopc_impacts: tuple[str, ...] = ()
    iopc_impacts_exercised: int = 0
    iopc_impacts_total: int = 0
    iopc_impacts_pct: float = 0.0


@dataclass(frozen=True)
class RunStatus:
    """Whether the run that produced this summary actually finished (contract §6).

    The runner already computes this (``complete`` | ``budget_exhausted`` | ``parked``) and
    every report used to throw it away, so a campaign halted by a budget ceiling rendered as
    an ordinary clean report of whatever had finished. A reader cannot discount a number they
    cannot see, so the state travels with the summary into every format.
    """

    state: str = "complete"
    reason: str | None = None

    @property
    def complete(self) -> bool:
        return self.state == "complete"


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
    coverage: Coverage
    model_comparison: ModelComparison | None = None
    run_status: RunStatus = field(default_factory=RunStatus)


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


def _build_coverage(
    findings: list[Finding],
    spec_map: dict[str, AttackSpec],
    *,
    planned_specs: int | None = None,
) -> Coverage:
    """Compute framework-surface coverage + spec disposition counts (``docs/12`` P1).

    A category/tactic is "exercised" when at least one finding's originating spec maps to it;
    ``unknown`` (unattributed) findings never contribute. ATLAS tactics count toward coverage
    only when they are in :data:`ATLAS_TACTIC_UNIVERSE` (an off-universe name is a spec-
    authoring error, not surface coverage) so ``atlas_pct`` stays in ``[0, 1]``.

    ``planned_specs`` is how many specs the **plan** selected. Without it ``specs_total`` was
    set to the number of findings, i.e. to ``specs_run``, so the pair always read ``45/45``:
    a run halted after 45 of 72 specs reported 100% of itself. The caller that knows the
    intended denominator passes it; absent it, the two stay equal and the report says so.
    """

    owasp_seen: set[str] = set()
    atlas_seen: set[str] = set()
    iopc_tech_seen: set[str] = set()
    iopc_impact_seen: set[str] = set()
    specs_pass = 0
    specs_fail = 0
    specs_inconclusive = 0

    for finding in findings:
        status = finding.status.value
        if status == "pass":
            specs_pass += 1
        elif status == "fail":
            specs_fail += 1
        else:
            specs_inconclusive += 1
        spec = spec_map.get(finding.spec_id)
        if spec is None:
            continue
        if spec.owasp in OWASP_LLM_UNIVERSE:
            owasp_seen.add(spec.owasp)
        if spec.mitre_atlas.tactic in ATLAS_TACTIC_UNIVERSE:
            atlas_seen.add(spec.mitre_atlas.tactic)
        if spec.iopc is not None:
            # Off-universe codes are a spec-authoring error (the linter rejects them), so they
            # never contribute to the numerator and both percentages stay in [0, 1].
            iopc_tech_seen.update(
                c for c in (spec.iopc.techniques or []) if c in IOPC_TECHNIQUE_UNIVERSE
            )
            iopc_impact_seen.update(
                c for c in (spec.iopc.impacts or []) if c in IOPC_IMPACT_UNIVERSE
            )

    owasp_exercised = len(owasp_seen)
    atlas_exercised = len(atlas_seen)
    total = len(findings)
    return Coverage(
        owasp_categories=tuple(sorted(owasp_seen)),
        owasp_exercised=owasp_exercised,
        owasp_total=OWASP_LLM_TOTAL,
        owasp_pct=owasp_exercised / OWASP_LLM_TOTAL if OWASP_LLM_TOTAL else 0.0,
        atlas_tactics=tuple(sorted(atlas_seen)),
        atlas_exercised=atlas_exercised,
        atlas_total=len(ATLAS_TACTIC_UNIVERSE),
        atlas_pct=(atlas_exercised / len(ATLAS_TACTIC_UNIVERSE) if ATLAS_TACTIC_UNIVERSE else 0.0),
        specs_total=planned_specs if planned_specs is not None else total,
        specs_run=total,
        specs_pass=specs_pass,
        specs_fail=specs_fail,
        specs_inconclusive=specs_inconclusive,
        iopc_techniques=tuple(sorted(iopc_tech_seen)),
        iopc_techniques_exercised=len(iopc_tech_seen),
        iopc_techniques_total=len(IOPC_TECHNIQUE_UNIVERSE),
        iopc_techniques_pct=(
            len(iopc_tech_seen) / len(IOPC_TECHNIQUE_UNIVERSE) if IOPC_TECHNIQUE_UNIVERSE else 0.0
        ),
        iopc_impacts=tuple(sorted(iopc_impact_seen)),
        iopc_impacts_exercised=len(iopc_impact_seen),
        iopc_impacts_total=len(IOPC_IMPACT_UNIVERSE),
        iopc_impacts_pct=(
            len(iopc_impact_seen) / len(IOPC_IMPACT_UNIVERSE) if IOPC_IMPACT_UNIVERSE else 0.0
        ),
    )


def build_run_summary(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
    *,
    planned_specs: int | None = None,
    run_status: RunStatus | None = None,
) -> RunSummary:
    """Aggregate ``findings`` into a :class:`RunSummary` (``docs/05 §4-§5``).

    ``specs`` maps ``spec_id → AttackSpec`` for framework attribution. ``model_comparison`` is
    populated only when the findings span more than one distinct ``target_id``.
    ``planned_specs`` / ``run_status`` carry what the run *intended* and whether it *finished*,
    which findings alone cannot express (see :class:`RunStatus`).
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
        coverage=_build_coverage(findings, spec_map, planned_specs=planned_specs),
        model_comparison=comparison,
        run_status=run_status if run_status is not None else RunStatus(),
    )


# --- static battery coverage (no scan) ----------------------------------------------


@dataclass(frozen=True)
class AxisCoverage:
    """What one framework axis the SPEC REGISTRY covers, independent of any run."""

    key: str
    label: str
    exercised: int
    total: int
    pct: float
    #: (code, human title) pairs, sorted. ``title`` falls back to the code when the framework
    #: has no separate name (OWASP codes, ATLAS tactic names are already readable).
    covered: tuple[tuple[str, str], ...]
    missing: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class BatteryCoverage:
    """Coverage of the shipped battery itself: what these specs TEST, before any target.

    The run-time :class:`Coverage` answers "this run exercised X of Y". This answers the
    question asked *before* a run, and before a purchase: "what does this battery actually
    test?". It is computed from the specs alone, so it needs no target, no key and no sends.
    """

    specs: int
    axes: tuple[AxisCoverage, ...]


def _axis(
    key: str,
    label: str,
    universe: tuple[str, ...],
    seen: set[str],
    titles: Mapping[str, str] | None = None,
) -> AxisCoverage:
    def title(code: str) -> str:
        return (titles or {}).get(code, code)

    covered = tuple(sorted((c, title(c)) for c in universe if c in seen))
    missing = tuple(sorted((c, title(c)) for c in universe if c not in seen))
    return AxisCoverage(
        key=key,
        label=label,
        exercised=len(covered),
        total=len(universe),
        pct=(len(covered) / len(universe) if universe else 0.0),
        covered=covered,
        missing=missing,
    )


def build_battery_coverage(specs: Iterable[AttackSpec]) -> BatteryCoverage:
    """Compute what the given specs cover, on every framework axis, with no run involved.

    Off-universe values never reach a numerator (a Responsible-AI ``RAI0x`` code is not an
    OWASP LLM category, an unrecognised ATLAS tactic name is a spec-authoring error, an IoPC
    code outside the pinned taxonomy is a lint error), so every percentage stays in [0, 1].
    """

    spec_list = list(specs)
    owasp: set[str] = set()
    atlas: set[str] = set()
    tech: set[str] = set()
    impact: set[str] = set()

    for spec in spec_list:
        if spec.owasp in OWASP_LLM_UNIVERSE:
            owasp.add(spec.owasp)
        if spec.mitre_atlas.tactic in ATLAS_TACTIC_UNIVERSE:
            atlas.add(spec.mitre_atlas.tactic)
        if spec.iopc is not None:
            tech.update(c for c in (spec.iopc.techniques or []) if c in IOPC_TECHNIQUE_UNIVERSE)
            impact.update(c for c in (spec.iopc.impacts or []) if c in IOPC_IMPACT_UNIVERSE)

    return BatteryCoverage(
        specs=len(spec_list),
        axes=(
            _axis("owasp", "OWASP LLM Top 10", OWASP_LLM_UNIVERSE, owasp),
            _axis("atlas", "MITRE ATLAS tactics", ATLAS_TACTIC_UNIVERSE, atlas),
            _axis(
                "iopc_techniques",
                "IoPC techniques",
                IOPC_TECHNIQUE_UNIVERSE,
                tech,
                IOPC_TECHNIQUES,
            ),
            _axis("iopc_impacts", "IoPC impacts", IOPC_IMPACT_UNIVERSE, impact, IOPC_IMPACTS),
        ),
    )
