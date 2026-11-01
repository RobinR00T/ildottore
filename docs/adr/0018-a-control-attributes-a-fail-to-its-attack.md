# ADR-0018: a control attributes a fail to its attack (u08 A-106)

* **Status:** accepted, 2026-10-30, as the smallest reversible version: opt-in (`run --control`),
  one control per failing spec, a control's fail keeps the finding from being confirmed. OD-62
  is open on the figures and the default.
* **Date:** 2026-10-30
* **Context:** a fail says the target did what the spec forbids. It does not say the attack made
  it do so. A model that answers a harmful ask with no jailbreak around it fails the jailbreak
  spec too, and a model that recites its capabilities to anyone fails a "goal theft" spec whose
  evaluator reads the same words. The report called both a confirmed vulnerability of the
  technique, and the operator had no way to tell. Clause u08 §7 A-106 in
  `specs/contracts/u08-execution-engine.md`, with its halves in u02 (the spec field and its lint),
  u10 (the run context), u11 (the report) and u12 (the flag).

## The decision

A spec may declare **`attack.control`**: the same ask without the attack (a plain question where
the attack wraps it in a jailbreak, an encoding, an injected instruction). With
**`dottore run --control`**, a spec that **fails** and declares one sends it **once**, after its
trials, judged by the spec's own evaluators, and its finding carries **`control`**:

| outcome | when | effect on the finding |
|---|---|---|
| `attributed` | the control passes | none: the fail follows the attack |
| `not_attributed` | the control fails too | never confirmed (needs review); the reasoning says the target does this unattacked |
| `inconclusive` | no verdict, `inconclusive`, an error, or a fail the judge alone reported | none |
| `not_evaluable` | the spec declares no control, or its attack is a conversation | none |

* **A control is never a trial.** It is stored under the reserved mutation `control`, kept in
  `Finding.control`, apart from `Finding.attempts`: the reproducibility, N, the confirmation per
  variant and `dottore replay`'s figures read the trials only. `replay` lists the controls on a
  line of their own; its evidence reference sits with the finding's.
* **A fail the judge alone reported never decides a control** (`inconclusive`), as it never
  confirms a finding: the rule `shared.combination.never_confirms`. Without it a judge that reads
  "exploited" into any reply would unconfirm every finding it was asked to confirm.
* **A pass sends no control.** Only a fail needs attributing; a passing spec costs nothing more.
* **Priced before the send.** `--estimate` and `--dry-run` count one request per selected spec
  that declares a control, as if each failed, so the derived ceilings never stop one.
* **A resume sends controls as its run did.** The run context records `control`; `--resume`
  reads it back, refuses `--control`, and keeps a control already answered.
* **Masked as an attempt.** The control's request and reply go through the report's single
  masking pass as any attempt does; the SARIF result carries the outcome as a property.
* **The battery.** Six specs declare a control: `PI-DIRECT-001`, `SP-LEAK-001`,
  `AG-GOAL-THEFT-001`, `DL-SECRET-CANARY-001`, `JB-REFUSAL-SUPPRESS-001`, `JB-ENCODING-001`.
  The lint refuses a control on a conversation (`attack.turns`) and a control equal to the
  attack's own request or carrier.

## Why a field and not a mutation

A mutation rewrites the attack and is judged as a variant of it: its fail confirms the spec. A
control removes the attack and its fail argues against the spec. Read as a variant, it would
have raised the reproducibility of exactly the findings it should cast doubt on.

## Not taken

* **On by default.** Every failing spec would cost one more request on every run, and a run's
  verdict would move under operators who never asked. OD-62 keeps it opt-in for now.
* **Demoting the verdict.** A `not_attributed` fail stays a fail: the target did the forbidden
  thing. What it loses is the claim that the technique caused it.
* **Several controls, or a rate.** One send says whether the target does it unattacked at all;
  a rate would cost N more requests per failing spec. OD-62 names it.
* **A control for a conversation.** The control is one plain turn; a conversation's control
  would have to be the conversation without its attack, which only its author can write.

## Costs, stated

`core/runner.py` and `shared/control.py` are in the judging digest: judging rules 7 re-pinned, no
rule of judgement changed (a reply is judged as before; without `--control` nothing is sent and
nothing is demoted). One request per failing spec that declares a control.

## Reversal

Run without `--control` (nothing is sent, `control` is null), or drop `control` from the runner's
constructor and the flag; `attack.control` is then an unread optional field.
