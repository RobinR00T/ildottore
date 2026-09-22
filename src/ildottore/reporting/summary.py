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
    not_tested_by_design_reason,
    out_of_reach_reason,
)
from ildottore.shared.iopc import (
    IOPC_IMPACT_UNIVERSE,
    IOPC_IMPACTS,
    IOPC_TAXONOMY_VERSION,
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
    #: ``(spec_id, field, value)`` for framework values this run did NOT count because they
    #: are outside their pinned universe. A run does not lint, so without this the numerator
    #: shrinks and the report reads as if nothing were missing.
    off_universe: tuple[tuple[str, str, str], ...] = ()
    #: Specs that produced a finding but never sent a request (policy-blocked, or skipped for
    #: a capability the target does not declare). They are reported, and they do NOT count as
    #: covered surface: crediting them told the reader a tactic had been exercised when the
    #: spec for it was refused before the first send.
    not_exercised: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunStatus:
    """Whether the run that produced this summary actually finished (contract §6).

    The runner already computes this (``complete`` | ``budget_exhausted`` | ``parked``) and
    every report used to throw it away, so a campaign halted by a budget ceiling rendered as
    an ordinary clean report of whatever had finished. A reader cannot discount a number they
    cannot see, so the state travels with the summary into every format.
    """

    #: ``complete`` | ``budget_exhausted`` (the runner) | ``unreachable`` (the CLI, when a
    #: target answered nothing at all). Not ``parked``: the contract reserves that word for
    #: the PITV park rule and nothing produces it.
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
    off_universe: list[tuple[str, str, str]] = []
    not_exercised: list[str] = []
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
        # A spec that never reached the wire covers nothing. A policy-blocked spec and a
        # capability-skipped one both produce a finding (they are reported, not dropped), and
        # crediting their framework codes inflated the published figure by a whole tactic: a
        # default run claimed 13/16 ATLAS while `Credential Access` was covered solely by
        # `AG-CRED-SWEEP-001`, which the pack blocks and which sent nothing.
        if not any(a.response is not None for a in finding.attempts):
            not_exercised.append(spec.id)
            continue

        # Off-universe values are a spec-authoring error (the linter refuses them), so they
        # never contribute to a numerator and every percentage stays in [0, 1]. They are also
        # RECORDED, because a run does not lint: dropping one in silence is how a numerator
        # shrinks with nobody told, which is the defect this axis exists to prevent.
        if spec.owasp in OWASP_LLM_UNIVERSE:
            owasp_seen.add(spec.owasp)
        elif spec.owasp not in OWASP_RAI_UNIVERSE:
            off_universe.append((spec.id, "owasp", spec.owasp))
        if spec.mitre_atlas.tactic in ATLAS_TACTIC_UNIVERSE:
            atlas_seen.add(spec.mitre_atlas.tactic)
        elif spec.mitre_atlas.tactic not in ATLAS_OUT_OF_MATRIX:
            off_universe.append((spec.id, "mitre_atlas.tactic", spec.mitre_atlas.tactic))
        if spec.iopc is not None:
            for code in spec.iopc.techniques or []:
                if code in IOPC_TECHNIQUE_UNIVERSE:
                    iopc_tech_seen.add(code)
                else:
                    off_universe.append((spec.id, "iopc.techniques", code))
            for code in spec.iopc.impacts or []:
                if code in IOPC_IMPACT_UNIVERSE:
                    iopc_impact_seen.add(code)
                else:
                    off_universe.append((spec.id, "iopc.impacts", code))

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
        off_universe=tuple(sorted(set(off_universe))),
        not_exercised=tuple(sorted(set(not_exercised))),
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
    #: Not covered **yet**: the roadmap. A code lands here only when a black-box runtime
    #: scanner could in principle test it.
    missing: tuple[tuple[str, str], ...]
    #: ``(code, title, reason)`` for what this kind of tool cannot reach at all (training
    #: pipelines, provenance, attacker-side staging). Separated from ``missing`` because
    #: "8 of 10" otherwise invites the reader to assume the other two are coming.
    out_of_reach: tuple[tuple[str, str, str], ...] = ()
    #: ``(code, title, reason)`` for what this scanner deliberately does not test. A decision,
    #: not a property of the category, and printed apart from ``out_of_reach`` for exactly that
    #: reason: one of these could be revisited tomorrow and none of the others can.
    #: Both lists stay in ``total`` (clause A-12).
    by_design: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class BatteryCoverage:
    """Coverage of the shipped battery itself: what these specs TEST, before any target.

    The run-time :class:`Coverage` answers "this run exercised X of Y". This answers the
    question asked *before* a run, and before a purchase: "what does this battery actually
    test?". It is computed from the specs alone, so it needs no target, no key and no sends.
    """

    specs: int
    axes: tuple[AxisCoverage, ...]
    #: ``(spec_id, field, value)`` for every framework value that was NOT counted because it
    #: is outside its pinned universe. Reported rather than dropped: nothing in the coverage
    #: path runs the linter, so a third-party pack can be measured without ever being linted,
    #: and a silently shrinking numerator is the failure this whole axis exists to avoid.
    off_universe: tuple[tuple[str, str, str], ...] = ()


def _axis(
    key: str,
    label: str,
    universe: tuple[str, ...],
    seen: set[str],
    titles: Mapping[str, str] | None = None,
) -> AxisCoverage:
    def title(code: str) -> str:
        return (titles or {}).get(code, code)

    # ``set`` on both sides: a universe with a duplicated entry would otherwise inflate the
    # denominator, and ``seen`` is already a set, so the numerator counts distinct codes.
    distinct = tuple(dict.fromkeys(universe))
    covered = tuple(sorted((c, title(c)) for c in distinct if c in seen))
    uncovered = [c for c in distinct if c not in seen]
    missing = tuple(
        sorted(
            (c, title(c))
            for c in uncovered
            if out_of_reach_reason(c) is None and not_tested_by_design_reason(c) is None
        )
    )
    unreachable = tuple(
        sorted(
            (c, title(c), reason)
            for c in uncovered
            if (reason := out_of_reach_reason(c)) is not None
        )
    )
    deliberate = tuple(
        sorted(
            (c, title(c), reason)
            for c in uncovered
            if (reason := not_tested_by_design_reason(c)) is not None
        )
    )
    return AxisCoverage(
        key=key,
        label=label,
        exercised=len(covered),
        total=len(distinct),
        pct=(len(covered) / len(distinct) if distinct else 0.0),
        covered=covered,
        missing=missing,
        out_of_reach=unreachable,
        by_design=deliberate,
    )


def build_battery_coverage(specs: Iterable[AttackSpec]) -> BatteryCoverage:
    """Compute what the given specs cover, on every framework axis, with no run involved.

    Off-universe values never reach a numerator (a Responsible-AI ``RAI0x`` code is not an
    OWASP LLM category, an unrecognised ATLAS tactic name is a spec-authoring error, an IoPC
    code outside the pinned taxonomy is a lint error), so every percentage stays in [0, 1].
    """

    # De-duplicated by id: a suite may list the same spec more than once, and "72 specs" has
    # to mean 72 distinct specs or the headline count is as soft as the percentages were.
    spec_list = list({spec.id: spec for spec in specs}.values())
    owasp: set[str] = set()
    atlas: set[str] = set()
    tech: set[str] = set()
    impact: set[str] = set()
    off: list[tuple[str, str, str]] = []

    for spec in spec_list:
        if spec.owasp in OWASP_LLM_UNIVERSE:
            owasp.add(spec.owasp)
        elif spec.owasp not in OWASP_RAI_UNIVERSE:
            off.append((spec.id, "owasp", spec.owasp))
        if spec.mitre_atlas.tactic in ATLAS_TACTIC_UNIVERSE:
            atlas.add(spec.mitre_atlas.tactic)
        elif spec.mitre_atlas.tactic not in ATLAS_OUT_OF_MATRIX:
            off.append((spec.id, "mitre_atlas.tactic", spec.mitre_atlas.tactic))
        if spec.iopc is not None:
            for code in spec.iopc.techniques or []:
                if code in IOPC_TECHNIQUE_UNIVERSE:
                    tech.add(code)
                else:
                    off.append((spec.id, "iopc.techniques", code))
            for code in spec.iopc.impacts or []:
                if code in IOPC_IMPACT_UNIVERSE:
                    impact.add(code)
                else:
                    off.append((spec.id, "iopc.impacts", code))

    return BatteryCoverage(
        specs=len(spec_list),
        axes=(
            _axis("owasp", f"OWASP LLM Top 10 ({OWASP_LLM_EDITION})", OWASP_LLM_UNIVERSE, owasp),
            _axis(
                "atlas",
                f"MITRE ATLAS tactics ({ATLAS_MATRIX_RELEASE})",
                ATLAS_TACTIC_UNIVERSE,
                atlas,
            ),
            _axis(
                "iopc_techniques",
                f"IoPC techniques ({IOPC_TAXONOMY_VERSION})",
                IOPC_TECHNIQUE_UNIVERSE,
                tech,
                IOPC_TECHNIQUES,
            ),
            _axis(
                "iopc_impacts",
                f"IoPC impacts ({IOPC_TAXONOMY_VERSION})",
                IOPC_IMPACT_UNIVERSE,
                impact,
                IOPC_IMPACTS,
            ),
        ),
        off_universe=tuple(sorted(set(off))),
    )
