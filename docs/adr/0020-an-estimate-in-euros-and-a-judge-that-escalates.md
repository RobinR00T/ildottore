# ADR-0020: an estimate in euros, and a judge that hands what it cannot settle to a second (u12 A-108, u06 A-109)

* **Status:** accepted, 2026-10-30, as the smallest reversible versions: rates the operator
  declares in the target file (none baked into the tool), and a second judge asked only on an
  `inconclusive`. OD-64 (the cost) and OD-65 (the escalation) are open.
* **Date:** 2026-10-30
* **Context:** `--estimate` counted requests and tokens and ended with "multiply by your
  provider's per-token rate": the operator did the arithmetic, per model, by hand, and the judge's
  share was never told apart from the target's. And a judge is one model: a cheap one disagrees
  with itself or answers under the threshold often enough that its `inconclusive` buries the
  verdicts a stronger model would settle, while an expensive one on every attempt costs more than
  most runs need. Clauses u12 §7 A-108 (`specs/contracts/u12-cli.md`) and u06 §7 A-109
  (`specs/contracts/unit-06-evaluators.md`).

## The decision: the estimate in euros (A-108)

A target file may declare what its model costs the operator:

```yaml
pricing:
  input_eur_per_mtok: 2.5    # euros per million tokens sent
  output_eur_per_mtok: 10    # euros per million tokens received
```

* **The operator's figure, not the tool's.** Il Dottore ships no price list: prices change,
  differ by contract and by region, and a stale table in a security tool would be a wrong number
  stated with authority. A rate is a finite number from 0 to 10,000; anything else, a missing
  half or an unknown key is refused when the file is loaded.
* **Cost, not identity.** `pricing` is cosmetic to the target digest, as `name` and
  `description` are: it changes what a run costs, never what answers, so changing a rate neither
  splits a comparison nor refuses a resume. A target without it dumps as before.
* **One line per model.** `--estimate` prints `~cost: X EUR` and, per model, the input and output
  tokens at its rates: each target, the `--judge` model, the `--judge-escalate` model. The
  output tokens are the same gloss the token count already uses. A model that sends and has no
  `pricing:` makes the total a floor (`at least`), named `unpriced`. With nothing priced the
  estimate reads as before, and its last line says where to declare a rate. `-q` appends the
  figure to its one line.

## The decision: a judge that escalates (A-109)

With **`dottore run --judge cheap.yaml --judge-escalate strong.yaml`**, the semantic judge asks
the first model as before, and **only when its reading is `inconclusive`** (a self-consistency
disagreement, a confidence under the spec's threshold, an outage, free text, an emitted tripwire)
asks the second, with the same hardening and the same passes. The second judge's verdict stands,
whatever it is, and its reasoning starts `escalated to the second judge (the first could not
settle the attempt: <why>)`.

* **Only an `inconclusive` escalates.** A `pass` or a `fail` the first judge settles never
  reaches the second. A judge-alone fail still never confirms a finding (OD-19): a stronger judge
  is still the one evaluator a target can prompt-inject.
* **Needs `--judge`.** `--judge-escalate` alone is refused before anything is sent. Its file is a
  live target the scope authorizes and whose credential is checked, as the judge's.
* **Priced as the worst case.** `--estimate` and `--dry-run` count every judgement once more for
  the second model (`of which up to N to the --judge-escalate model`), each model at its own
  rate.
* **A resume escalates as its run did.** The run context records the second judge's digest
  (`judge_escalate_digest`); a resume that offers another, or none where one was, or one where
  none was, is refused: one campaign is not arbitrated two ways.

## Not taken

* **A built-in price table.** See above. The operator's rates are the only defensible figure.
* **The measured cost from the run's own usage.** The estimate is before the send; a run's spend
  from the `usage` block of each reply is another feature (OD-64).
* **Escalating a `fail` too.** It would let the stronger judge overturn a cheap judge's fail,
  the half of the arbitration the combination rule already keeps out of confirmation. OD-65
  names it.
* **The expensive judge for `--verify`.** The second pass (A-107) uses the `--judge` model. OD-65
  names whether it should use the escalation model when one is given.

## Known limits

* The second judge's sampling notes and its resume continuity of `takes_sampling` are not
  recorded as the first judge's are; its digest is.
* The second judge is a live model only: the offline mock has no scripted second judge, so an
  example shows its `--estimate` and `--dry-run`, not a run.

## Costs, stated

`evaluators/semantic_judge.py` and `evaluators/registry.py` are in the judging digest: judging
rules 7 re-pinned, no rule of judgement changed (without `--judge-escalate` the judge reads as
before; with it, only an attempt the first judge returned `inconclusive` is read again). A run
with escalation sends at most twice the judge's requests.

## Reversal

Drop `pricing:` from a target file (the estimate reads as before), and run without
`--judge-escalate` (nothing is escalated, the run context stores `null`); in code, the
`escalate_to` argument of `SemanticJudgeEvaluator` defaults to `None`.
