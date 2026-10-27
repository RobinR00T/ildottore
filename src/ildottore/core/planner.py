"""The plan-builder - the sole owner of ``build_plan`` (u08, ADR-0006).

``build_plan(specs, fingerprint, capabilities) -> TestPlan`` turns an ordered spec
set + the target's declared :class:`Capabilities` (+ an optional
:class:`ModelFingerprint`) into the canonical reviewable :class:`TestPlan`
(ADR-0006 §3, ``docs/10 §3``):

1. **Capability filter** - a spec whose ``requires`` names a capability the target
   does not declare is **skipped with an explicit reason** (never silently dropped;
   at run time the same gap yields ``inconclusive: capability_unavailable``).
2. **Per-spec mutator selection** - the spec's declared ``mutations`` (``identity``
   is always included as the baseline carrier), ordered family-effectively when a
   fingerprint is supplied.
3. **Explicit, byte-stable output** - deterministic ordering (specs in input order,
   skips in input order) so the same inputs produce a byte-identical plan
   (contract §7 determinism replay).

The planner reads one key of a fingerprint, ``capability_guess["effective_mutators"]``.
It used to read a per-category ``guardrails["baseline_resistance"]`` map, which no
fingerprint layer writes, into a plan field nothing read; both were removed on
2026-10-11 (OD-17, ADR-0008 option B), to come back with a layer that measures it.

``--no-adaptive`` (``adaptive=False``) is a **pass-through**: no fingerprint
tailoring, mutator order is the spec's declared order - the full selected suite runs
for apples-to-apples benchmark parity (``docs/10 §3``).

Pure and side-effect-free: no I/O, no clock, no RNG. ``core`` imports only shared
models here (contract §8).
"""

from __future__ import annotations

from ildottore.shared.enums import RequiresCapability
from ildottore.shared.models import (
    AttackSpec,
    Capabilities,
    ModelFingerprint,
    PlanBudgets,
    PlanSelection,
    PlanSkip,
    TestPlan,
)

__all__ = [
    "DEFAULT_PLAN_BUDGETS",
    "IDENTITY_MUTATOR",
    "build_plan",
]

#: The always-present baseline carrier (the un-mutated attack). Mirrors u05's
#: ``IdentityMutator.name`` without importing the concrete (contract §8).
IDENTITY_MUTATOR = "identity"

#: Conservative default per-campaign hard budgets (contract §9; human-confirmable).
#: Surfaced here so a plan is never budget-less - the runner turns these into a
#: :class:`~ildottore.core.budgets.BudgetLedger`.
DEFAULT_PLAN_BUDGETS = PlanBudgets(
    max_tokens=500_000,
    max_requests=2_000,
    max_wall_s=1_800,
    max_attempts=5_000,
)

# Map the spec-level ``requires`` vocabulary (RequiresCapability) to the fields on
# the target-declared ``Capabilities`` model. ``system_prompt`` is a *setup*
# prerequisite the adapter always materializes locally (no target capability flag),
# so it never gates capability filtering here (docs/01 §4.2, enums.py note).
_REQUIRES_TO_CAP: dict[RequiresCapability, str] = {
    RequiresCapability.RAG: "rag",
    RequiresCapability.TOOLS: "tools",
    RequiresCapability.MEMORY: "memory",
    RequiresCapability.STREAMING: "streaming",
    RequiresCapability.LOGPROBS: "logprobs",
    RequiresCapability.MULTI_IDENTITY: "multi_identity",
    RequiresCapability.MULTIMODAL: "multimodal",
    RequiresCapability.AUDIO: "audio",
    RequiresCapability.MCP: "mcp",
    RequiresCapability.MCP_PINS: "mcp_pins",
}


def _missing_capabilities(spec: AttackSpec, capabilities: Capabilities) -> list[str]:
    """The capability flags ``spec`` needs that the target does not declare.

    ``system_prompt`` is excluded (setup prerequisite, not a target flag). Order is
    the spec's declared ``requires`` order for a byte-stable skip reason.
    """

    missing: list[str] = []
    for req in spec.requires:
        field = _REQUIRES_TO_CAP.get(req)
        if field is None:
            continue  # system_prompt - always satisfiable via setup
        if not getattr(capabilities, field):
            missing.append(field)
    return missing


def _select_mutators(spec: AttackSpec, *, fingerprint: ModelFingerprint | None) -> list[str]:
    """Per-spec mutator list: identity baseline + declared mutations.

    ``identity`` (the un-mutated carrier) is always first so every spec has a
    baseline attempt. When a fingerprint is supplied the declared mutations are
    ordered family-effectively (a stable, documented weighting); otherwise they
    keep the spec's declared order (benchmark parity). Duplicates are collapsed
    preserving first occurrence so the list is deterministic.
    """

    declared = list(spec.mutations or [])
    if fingerprint is not None and declared:
        declared = _order_family_effective(declared, fingerprint)
    ordered = [IDENTITY_MUTATOR, *declared]
    seen: dict[str, None] = {}
    for name in ordered:
        seen.setdefault(name, None)
    return list(seen)


def _order_family_effective(mutations: list[str], fingerprint: ModelFingerprint) -> list[str]:
    """Stable family-effective ordering of a spec's declared mutations.

    Fingerprints may carry a per-family ``effective_mutators`` hint in
    ``capability_guess`` (a free-shaped probe result - ADR-0006 §3). Named
    mutators that the hint lists as historically effective sort first (in the
    hint's order); the rest follow in their declared order. Absent a hint, the
    declared order is preserved - never a silent reshuffle (``docs/10 §3``).
    """

    hint = fingerprint.capability_guess.get("effective_mutators")
    if not isinstance(hint, (list, tuple)):
        return list(mutations)
    promoted = {str(name) for name in hint}
    # Stable sort into two groups, and **the spec's declared order is kept inside each**.
    # Ranking by the hint's own position was ranking by nothing: the carrier probe scores are
    # binary, so the hint arrives alphabetically and the tie-break silently became the whole
    # ordering, discarding what the spec author wrote.
    return sorted(mutations, key=lambda name: 0 if name in promoted else 1)


def build_plan(
    specs: list[AttackSpec],
    fingerprint: ModelFingerprint | None,
    capabilities: Capabilities,
    *,
    target_id: str,
    plan_ref: str,
    adaptive: bool = False,
    budgets: PlanBudgets | None = None,
) -> TestPlan:
    """Build the canonical :class:`TestPlan` (ADR-0006 §3).

    ``adaptive=False`` (``--no-adaptive``) is a pass-through: capability filtering
    still applies (a spec that *cannot* run is always skipped, adaptive or not), but
    no fingerprint tailoring is recorded and mutators keep the spec's declared order.
    ``adaptive=True`` with a ``fingerprint`` enables family-effective mutator ordering.

    Deterministic: same inputs ⇒ byte-identical plan (specs kept in input order;
    skips recorded in input order; no clock/RNG).
    """

    effective_fp = fingerprint if adaptive else None
    fingerprint_ref = (
        fingerprint.recommended_plan_ref if (adaptive and fingerprint is not None) else None
    )

    selected: list[PlanSelection] = []
    skipped: list[PlanSkip] = []
    for spec in specs:
        missing = _missing_capabilities(spec, capabilities)
        if missing:
            skipped.append(
                PlanSkip(
                    spec_id=spec.id,
                    reason=(
                        f"capability_unavailable: target does not declare {', '.join(missing)}"
                    ),
                )
            )
            continue
        selected.append(
            PlanSelection(
                spec_id=spec.id,
                reason=_selection_reason(spec, adaptive=adaptive),
                mutators=_select_mutators(spec, fingerprint=effective_fp),
            )
        )

    return TestPlan(
        plan_ref=plan_ref,
        target_id=target_id,
        adaptive=adaptive,
        fingerprint_ref=fingerprint_ref,
        selected=selected,
        skipped=skipped,
        budgets=budgets if budgets is not None else DEFAULT_PLAN_BUDGETS,
    )


def _selection_reason(spec: AttackSpec, *, adaptive: bool) -> str:
    """Human-readable reason a spec was selected (reviewable plan - docs/10 §3)."""

    mode = "adaptive-tailored" if adaptive else "full-suite (benchmark parity)"
    return f"{mode}: {spec.category.value} spec applicable to declared capabilities"
