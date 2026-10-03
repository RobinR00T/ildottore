# ADR-0010: `weighted` is declared by 33 specs and implemented in no run path (OD-19)

* **Status:** proposed, awaiting the owner's decision
* **Date:** 2026-10-03
* **Context:** OD-19 in `specs/contracts/00-INDEX.md`; found by the AISVS mapping audit of the
  same day, measured before this was written

## The problem

A spec's `evaluator_logic` says how its evaluators' verdicts combine. 33 of the 75 specs declare
`weighted`, several with a comment explaining the intent ("canary/regex are hard signals; judge
resolves nuance"). `docs/04` §2 and the u06 contract describe it as a weighted vote with a
threshold, and the runner's docstrings say combination "honours the spec's `evaluator_logic`".

No path that produces a verdict implements it:

* **the runner** (`core/runner.py` `_combine_verdicts`) never reads the field. Its rule is fixed:
  any deterministic fail decides; otherwise any inconclusive decides; otherwise a judge fail;
  otherwise pass;
* **the lint fixture engine** (`registry/fixtures_engine.py` `_combine`) reads the field and then
  treats `weighted` like `all_pass`: any fail decides. So lint and runner agree with each other;
* **the weighted vote itself** exists in `evaluators/combine.py` (`_combine_weighted`), is
  exported, and is called by neither.

What that does in practice: the judge can only break a tie when every deterministic arm passes,
so a noisy deterministic arm decides alone. On the 9 weighted specs with two or more deterministic
arms, the noisiest arm sets the false-positive rate. That is how `PI-INDIRECT-RAG-001` and
`PI-INDIRECT-TOOL-001` scored a refusal as a breach while their own judge rubric called the same
reply a PASS (fixed at the spec on 2026-10-03).

## Options

**A. Make the documents true: the runner calls the weighted vote.** Then a judge PASS plus a
passing regex could outvote a leaked canary. A confirmed exploit scored as a pass is the worst
failure a security scanner has, and a weighted vote makes it reachable by configuration.

**B. Make the code's rule the documented one.** State in `docs/04`, u06, the runner's docstrings
and the spec comments what the runner actually does: a deterministic fail is a confirmed exploit
and is never outvoted; the judge decides only when no deterministic arm fails or abstains. Rename
the value to say that (for example `deterministic_first`), keep `weighted` as a deprecated alias
so third-party packs keep loading, and either remove `_combine_weighted` or keep it with a test
that pins it as unused. Noisy arms are then fixed where they live, in the spec, as the two
indirect-injection specs were.

**C. Leave it, documented as dead.** Costs nothing; leaves 33 specs declaring a behaviour that
does not exist.

## Amendment (same day, after the full audit)

The audit of the whole repository that afternoon found one consequence of the runner's rule this
ADR had not seen. When every deterministic evaluator passes and the judge says `fail`, the
attempt is a `fail`; the per-attempt aggregate hides the disagreement, so across the runs the
finding comes out **confirmed** and trips `--fail-on`. The FAQ, the README and the manual all
said the judge never overrides a deterministic verdict. The judge is the one evaluator a target
can prompt-inject, so a confirmed finding decided by it alone is exactly the kind CI should not
gate on without corroboration.

## Recommendation

**B, with one change: a fail decided only by the judge is reported but `needs-review`.** Keep
the runner's priority (a deterministic fail is never outvoted), document it, rename the value,
and make the confirmed gate require a deterministic fail somewhere in the confirming variant. A
judge-only finding still appears in every report and still counts in the spec's status; it
stops gating CI unless `--include-needs-review` is passed. The documents now describe today's
behaviour and point here, so nothing reads as decided until this is.

## Consequences

If B: a schema enum gains a value and deprecates one, `docs/04` §2 and u06 §2 are rewritten,
the 33 specs are migrated mechanically (asserted, not hoped), and `evaluators/combine.py` loses
or quarantines its weighted path. No verdict changes, because the runner already behaves this way.
The amendment changes one thing that users see: a judge-only fail moves from `confirmed` to
`needs-review`, so a CI gate that was red on such a finding turns green unless it passes
`--include-needs-review`.
