# ADR-0008: `baseline_resistance`, wire it or drop it (OD-17)

* **Status:** proposed, awaiting the owner's decision
* **Date:** 2026-09-23
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
traffic (today `-sV` is 17 requests), and it only means anything against a live target: the
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
