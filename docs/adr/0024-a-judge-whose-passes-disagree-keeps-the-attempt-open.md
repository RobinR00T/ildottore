# ADR-0024: A judge whose self-consistency passes disagree keeps the attempt `inconclusive` (u06 A-121, OD-45)

* **Status:** accepted, 2026-11-02, as decided on 2026-11-01 under the owner's delegation (best
  practice, revisable).
* **Date:** 2026-11-02
* **Context:** the semantic judge asks its model at least twice (`docs/04 §4` item 4). When the
  passes return different verdicts, `docs/02 §4` and `docs/04 §4` say the result is
  `inconclusive`. The evaluator did return `inconclusive`, but with no reason, and
  `shared.combination.combine_verdicts` (OD-19, ADR-0010) drops a reasonless judge abstention, so
  the deterministic evaluators decided the attempt as if the judge had not been asked: a `pass`
  when they all passed. A judge that a crafted reply pushed to say `exploited` once and `secure`
  once, the case the self-consistency probe exists for, let the attempt pass. Clause u06 §7 A-121
  in `specs/contracts/unit-06-evaluators.md`; OD-45 in its §9 and in u08 §9.

## The decision

* **A reason of its own.** `InconclusiveReason` gains `judge_disagreed` (this ADR is the one the
  enum's docstring requires to extend it). `SemanticJudgeEvaluator` returns it when its passes
  disagree.
* **Kept, not dropped.** `combine_verdicts` drops only a judge abstention with no reason, which is
  now a judge whose passes agree below the spec's confidence threshold. A disagreement is kept: a
  deterministic `fail` still decides the attempt; otherwise the attempt is `inconclusive` with the
  reason `judge_disagreed` (the aggregate carries it when it is the only reason, as for every
  other reason).
* **The spec-level rule is unchanged.** A spec passes on a strict majority of passing attempts,
  so one disagreement among four attempts that pass does not stop it; a disagreement on most
  attempts makes it `inconclusive`.
* **Escalation is unchanged.** With `--judge-escalate` (ADR-0020) a disagreement of the first
  judge is handed to the second, whose verdict stands; if the second judge's passes disagree too,
  that verdict is `judge_disagreed`.
* **Judging rules 8.** Verdicts change, so `JUDGING_RULES_VERSION` is bumped: a run halted under
  version 7 is refused by its resume, naming both.

## Not taken

* **Dropping the disagreement, as built.** It contradicts `docs/02 §4` and lets a judge an
  injection split pass the attempt.
* **Reusing `capability_unavailable`.** The judge was reachable and answered; a capability gap
  reads as "the target could not be exercised", which it was.
* **Keeping the low-confidence abstention too.** Not decided; it stays dropped, as OD-19 left it.

## Costs, stated

More `inconclusive` attempts from a noisy judge, and so more specs that do not pass on a run with
`--judge`. The JSON report already carries `inconclusive_reason` as a string (no schema change);
no report section counts it apart.

## Reversal

Remove the `reason=` argument in `SemanticJudgeEvaluator._reconcile`; the enum value then has no
producer and can be removed with the next judging rules version.
