# ADR-0010: `weighted` is declared by 33 specs and implemented in no run path (OD-19)

* **Status:** accepted on 2026-10-11: **B, with the amendment**, decided under the owner's
  delegation of the same day, 10:09 ("arreglalo todo según mejores prácticas", fix everything
  according to best practice), and revisable by the owner (the reversal is at the end)
* **Date:** 2026-10-03 (proposed), 2026-10-11 (accepted and built, u06 §7 A-73)
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
finding comes out **confirmed** and trips `--fail-on` whenever the judge says `fail` on every
attempt of one mutation variant, which is the rule any fail is confirmed by (precision added
2026-10-04; the amendment's finding stands). The FAQ, the README and the manual all
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

## Decision (2026-10-11)

**B, with the amendment**, decided under the owner's delegation (best practice, revisable), and
built as u06 §7 A-73 (halves in u08, u02 and u00). Why, against today's code (`main` at
`6d5f7ae`, with OD-16 on the same branch):

* **A deterministic fail is evidence; a vote over it is not.** A canary in a reply, a forbidden
  tool call, an `<script>` in an output are facts about the target, and a security scanner that
  lets a model's opinion outvote a fact turns a confirmed exploit into a clean report by
  configuration (option A). The rule the runner already applied is the one to keep; what was
  wrong was the documents and the two other paths.
* **One rule, one implementation, one name.** Three paths combined verdicts three ways (the
  runner's rule, the lint engine's "any fail fails", and `combine`'s boolean modes and vote,
  which disagreed with the runner on a leak beside an unconfigured judge). Each of them now
  calls `shared.combination.combine_verdicts`, so they cannot drift again, and a Hypothesis
  property asserts it. The rule's name, `deterministic_first`, is the one value the shipped
  battery writes; the three old names, which never meant what they said (`weighted` named a vote,
  and `all_pass` and `any_fail` were run by the same rule as each other), stay loadable as
  deprecated aliases with a lint warning, the usual way to retire a schema value without breaking
  a third-party pack.
* **The judge is the attack surface.** `docs/04` §4 hardens it, and it is still the one
  evaluator a target can talk to. Best practice for an LLM-as-judge is corroboration before an
  automated gate acts on it: its verdict is reported, and a human reviews it. So a judge-only fail
  is `needs-review`, the amendment's recommendation, and `--include-needs-review` lets a CI that
  wants it gate on it anyway.
* **Consistent with OD-41 and OD-42.** A blocked attempt (OD-41) never reaches the rule; the
  OD-42 branch (not merged on this date) scores a cut reply with the deterministic evaluators
  alone through `_combine_verdicts`, so it inherits the rule unchanged.

### As built

* **The rule** (`shared/combination.py`): a judge consulted and abstaining without a reason is
  dropped; a deterministic fail decides; else an `inconclusive`; else a judge fail, whose
  reasoning is `semantic judge reported exploited`; else pass. Byte-identical reasonings to
  the runner's, so stored attempts read the same.
* **The three paths.** `core.runner._combine_verdicts` calls it (around its `authz_leak`
  set-aside, unchanged); `registry.fixtures_engine._combine` builds its stubs' verdicts and calls
  it, which changes no lint result, since the stubs return only `pass` or `fail`;
  `evaluators.combine.combine(verdicts, logic=None)` calls it and ignores `logic`. Removed:
  `combine`'s `configs` argument, `_combine_weighted`, `_combine_boolean` and `_resolve_weights`,
  and the runner's `_combine_decisive`; `_shared_inconclusive_reason` and `_union_matched` moved to
  `shared` (`shared_inconclusive_reason`, `union_matched`).
* **The schema and the battery.** `evaluator_logic` gains `deterministic_first` (and a
  description); the 75 shipped specs declare it (42 were `any_fail`, 33 `weighted`), asserted by a
  test; the three old names load and are a `DEPRECATED_COMBINATION` lint warning, and so is an
  evaluator `weight` (no shipped spec declares one). `EvaluatorLogic.DETERMINISTIC_FIRST` and
  `DEPRECATED_EVALUATOR_LOGIC` in `shared.enums`.
* **The amendment.** `core.runner._is_confirmed`: a variant (or the pooled attempts, below
  `MIN_VARIANT_ATTEMPTS`) confirms only when every attempt failed above the threshold and at least
  one fail was not the judge's alone (`decided_by_judge_alone`, which reads the reasoning above,
  stored since 2026-09-03). The finding's reasoning adds `; <j>/<k> decided by the judge alone,
  which never confirms a finding on its own`. Status, reproducibility, risk and band are
  unchanged.
* **Measured.** The vulnerable mock over the battery, every capability declared, `--runs 2`: 224
  failing attempts, none decided by the judge alone, so the 67 confirmed fails stay confirmed; the
  bare and hardened mocks are unchanged spec by spec; lint `0 error(s), 0 warning(s)` over 75
  specs. A spec whose only failing evaluator is the judge, against the vulnerable mock with
  `--runs 3` and `--fail-on high`: `fail`, needs review, exit 0 (it was confirmed, exit 2); exit 2
  with `--include-needs-review`.

### Left out, and why

* **A second rule.** The field keeps its name and its enum, so a future rule can be a value of
  it; none is built.
* **Removing the old names.** They load, with a warning, until a release that says it drops them.
* **The judge's self-consistency disagreement** (`docs/04` §2, open question): the rule still drops
  a reasonless judge abstention, as before. Not part of this decision.

### Reversal

To make a judge-only fail confirm again, drop the `corroborated` test in `_is_confirmed` and the
judge count in `_finding_reasoning`. To restore the three paths, revert `shared/combination.py`,
`evaluators/combine.py`, `registry/fixtures_engine._combine` and the runner's `_combine_decisive`
from `530fb30`, the schema enum, the `DEPRECATED_COMBINATION` lint code and the 75 spec lines,
and delete `tests/evaluators/test_one_combination_rule.py` and
`tests/registry/test_deprecated_combination.py`.
