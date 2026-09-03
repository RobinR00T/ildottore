# ADR-0006: TestPlan/planner seam & Pydantic-first schemas

- **Status:** Accepted
- **Date:** 2026-07-07
- **Resolves:** consistency-review blockers (Stage-2), OD-14, and the schema-ownership gap.

## Context
The Stage-2 consistency gate found the only real fractures clustered at the `TestPlan`/planner
seam between u08 (execution engine) and u09 (fingerprint): two incompatible `TestPlan` shapes,
the plan-builder responsibility claimed by both units, `TestPlan` defined in neither the u00
shared registry, and three referenced schema files (`suite`, `pack`, `test-plan`) that don't
exist while every unit declares `schemas/` must-not-touch.

## Decision
1. **`TestPlan` and `ModelFingerprint` are shared wire models → owned by u00** (`shared.models`)
   and listed in the `00-INDEX` interface registry. They are cross-unit shapes (produced by one
   unit, consumed by others), so they belong with the other shared models.
2. **The plan-builder lives in exactly one place: u08**: `core/planner.py`,
   `build_plan(specs, fingerprint: ModelFingerprint | None, capabilities) -> TestPlan`
   (capability filtering, family-effective mutator weighting, skip reasons, budgets).
   **u09 does NOT build a TestPlan**: it only produces `ModelFingerprint` and feeds it to the
   u08 planner. `src/ildottore/fingerprint/planner.py` is removed from u09's scope.
3. **Canonical `TestPlan` shape** (the richer u08 form):
   `{plan_ref, target_id, adaptive: bool, fingerprint_ref: str | None,
   selected: [{spec_id, reason, mutators: [str], baseline_resistance}],
   skipped: [{spec_id, reason}], budgets: {max_tokens, max_requests, max_wall_s, max_attempts}}`.
   Per-spec `mutators`/`baseline_resistance` (not top-level).
4. **`ModelFingerprint.capability_guess`** is renamed from `.capabilities` to make explicit that
   a fingerprint *guess* (may include `json_mode`, `vision`, `max_context_tokens`) is a distinct
   shape from the target-declared `Capabilities` enum.
5. **Pydantic-first schemas.** Only `schemas/attack-spec.schema.json` is hand-authored (the
   author-facing spec format). `suite`, `pack` and `test-plan` schemas are **generated from the
   Pydantic models** via `shared/schema_export.py` (`dottore schema export`), owned by **u00**.
   Contracts must validate against the Pydantic model (or the generated schema), not treat those
   three files as frozen upstream oracles. This resolves OD-14 (schema ownership = u00).

## Consequences
- (+) One `TestPlan`, one builder, one owner: the u08/u09 fixtures can't diverge.
- (+) No hand-maintained schema drift; the model is the single source of truth.
- (−) u09 loses its own planner module (net simpler). Contracts u00/u08/u09 carry a
  reconciliation note pointing here; INDEX registry updated.
