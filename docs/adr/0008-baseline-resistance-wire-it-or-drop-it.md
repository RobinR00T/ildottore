# ADR-0008: `baseline_resistance`, wire it or drop it (OD-17)

* **Status:** accepted on 2026-10-11: **B, now** (drop it), decided under the owner's delegation
  of the same day, 10:09 ("arreglalo todo según mejores prácticas", fix everything according to
  best practice), and revisable by the owner (the reversal is at the end)
* **Date:** 2026-09-23 (proposed), 2026-10-11 (accepted and built)
* **Context:** OD-17 in `specs/contracts/00-INDEX.md`

## The problem

`PlanSelection.baseline_resistance` is dead at both ends:

* **nothing writes it.** `core/planner._baseline_resistance` reads
  `fingerprint.guardrails["baseline_resistance"]`, and no fingerprint layer emits that key.
  `docs/10` has said so since the layer was written.
* **nothing reads it.** No consumer anywhere in `src/` reads the field the planner fills.

It is nonetheless declared in the u00 wire shape, described in the u08 and u09 contracts as part
of the plan, and present in a golden fixture, so a reader takes it for a working feature. 27
references across 11 files.

## Options

**A. Wire it.** A fingerprint layer would have to measure per-category resistance, which means
sending category-shaped probes and scoring how the target answers them. That is more recognition
traffic (today `-sV` is 18 requests), and it only means anything against a live target: the
offline decoder cannot produce a resistance profile that reflects any real model. Then a consumer
has to use it, which is a planning change with its own measurement. Cost: a new layer, more
probes, a planner change, and a live run to validate. It cannot be honestly built before the live
validation in `docs/16` happens.

**B. Drop it.** Remove the field from the wire shape, the planner function, the two contracts,
the golden fixture and the docs. Cost: 27 references in 11 files, one of which is the u00 shared
model, so it is a contract revision rather than a tidy-up. Reversible: the field can come back
with the layer that populates it.

**C. Leave it, documented.** Cost: nothing. It stays in the shape and in two contracts, labelled
dead at both ends, which is what happens today.

## Recommendation

**B, after the live validation, or C until then.** A is not honestly buildable yet: a resistance
number produced offline would be a fiction with a confidence attached, which is the failure this
project corrected twice this week. Dropping it now costs a contract revision for a field nobody
uses; leaving it labelled costs nothing and keeps the option open. The one thing not to do is
leave it *unlabelled*, which is what it was until 2026-09-23.

## Consequences

If B: `TestPlan` loses a field, `u08` and `u09` lose a line each, `docs/10`'s note becomes
history, and the golden plan fixture is regenerated. If C: nothing changes and OD-17 stays open
with its label, to be revisited when a live run makes A buildable.

## Decision (2026-10-11)

**B, now**, decided under the owner's delegation (best practice, revisable). The recommendation
was "B after the live validation, or C until then"; there are no live keys on this date, so the
choice was between dropping the field now and keeping it documented as reserved (C). Dropped,
because:

* **A field nothing writes and nothing reads is a claim, not a feature.** Every plan said
  `baseline_resistance: null` in a shape that reads as a working capability, and the u00 wire
  shape, two contracts, a golden fixture and the generated test-plan schema all carried it. The
  project's own rule is zero dead code, and the cheapest correct state of a dead field is its
  absence; a label next to it ("reserved", "dead at both ends") has to be read to be believed,
  and it was unlabelled until 2026-09-23.
* **Reserving it buys nothing.** A layer that measures per-category resistance does not exist
  and cannot be honestly built before a live run (option A, above). When it is, its value, its
  type and the planner change that reads it will be designed together, and the field is added
  back with them. Keeping today's `float | None` would pre-commit that design to a shape chosen
  before any data.
* **Consistent with OD-40.** The same day, the guardrail profile's `input_filter` was kept and
  filled from the one input-filter signal a pass sees (u09 A-67): the rule for both is that a
  field ships only with a producer that can make it true.

### As built

* `PlanSelection` (u00) loses `baseline_resistance`; `core/planner.py` loses
  `_baseline_resistance` and its call, and its docstrings say what the planner reads (one key of
  a fingerprint, `capability_guess["effective_mutators"]`). The golden plan
  (`tests/fixtures/plans/adaptive-plan.json`) loses the key; the three planner tests that pinned
  the dead reader are gone, and `tests/core/test_no_baseline_resistance.py` (4 tests, all failing
  on `52cd923`) pins the removal: no field, no property in the generated schema, a fingerprint
  holding the old map orders nothing, and a plan JSON written with the field is refused.
* **Compatibility, stated.** `PlanSelection` forbids unknown keys (`extra="forbid"`, mirrored as
  `additionalProperties: false` in `dottore schema export --name test-plan`), so a plan JSON that
  still carries the key fails validation against the new model and the new schema. No command
  reads a plan from disk: the plan lives in one invocation's result, and the run store keeps the
  integrity context, not the plan. The report schema (`report-1.0`) never held the plan. A
  program that stored an exported schema or a dumped plan has to drop the key. No verdict, no
  plan ordering and no report changes.

### Reversal

Restore the field (`baseline_resistance: float | None = None`), `_baseline_resistance` and its
call, the golden key and the three tests from `52cd923`, and delete
`tests/core/test_no_baseline_resistance.py`.
