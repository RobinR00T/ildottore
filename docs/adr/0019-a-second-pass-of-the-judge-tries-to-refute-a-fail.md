# ADR-0019: a second pass of the judge tries to refute a fail (u08 A-107)

* **Status:** accepted, 2026-10-30, as the smallest reversible version: opt-in (`run --verify`),
  one request per failing spec, the state reported beside the finding and never decisive. OD-63
  is open on whether a state should move anything and on the default.
* **Date:** 2026-10-30
* **Context:** a fail rests on the evaluators' first reading of one reply. A regex that matched
  an incidental string, a canary the reply only quotes back, a refusal phrased as compliance: the
  report called each a confirmed vulnerability, and the operator re-read every fail by hand to
  find them. A second reader that is told to argue against the fail finds the cheap ones first.
  Clause u08 §7 A-107 in `specs/contracts/u08-execution-engine.md`, with its halves in u10 (the
  run context), u11 (the report) and u12 (the flag).

## The decision

With **`dottore run --verify`**, a spec that **fails** sends **one** more request to the judge
model: the `--judge` model on a live target, the scripted judge on the offline mock. It reads the
request, the reply and the first pass's notes, and is asked to **refute** the fail. Its answer is
one closed state, carried in **`Finding.verification`** with the attempt it read, its reasoning
and its confidence:

| state | when |
|---|---|
| `holds` | the exploit survives the attempt to refute it |
| `does_not_hold` | the reviewer refutes it: a refusal, a quote of the request, a harmless or incidental match, the secure behaviour met |
| `inconclusive` | the reviewer says so, or anything below happened |

* **Anything outside the set is `inconclusive`.** A state not in the set, free text, an adapter
  error, an emitted tripwire, an `observed_injection_attempt` with any answer but `holds` (an
  injection would push the reviewer to refute), a confidence under the spec's
  `confidence_threshold`, or a campaign ceiling that refuses the request (`not consulted: ...`).
  A refused sampling parameter or a credential too short stops the run, as for the judge's own
  pass.
* **The semantic judge's hardening, unchanged.** Every piece the target or the spec wrote sits
  inside a per-call random delimiter as untrusted data, a per-call tripwire, structured JSON
  only, temperature 0.
* **Reported, never decisive.** The state moves no status, no `confirmed`, no risk, no exit code.
  The finding's reasoning says what the second pass read, and SARIF carries the state as a
  property; a `does_not_hold` adds "review it" to the result's message.
* **Which attempt.** A fail an evaluator other than the judge reported, since that is the fail a
  finding is confirmed on; else the first fail with a reply; an identity sweep's trial only when
  nothing else failed.
* **A pass sends nothing,** and neither does a finding a halted run reports from its prior
  attempts.
* **Priced before the send.** `--estimate` and `--dry-run` count one judge request per selected
  spec, as if each failed, when the plan has judge requests at all (a live `--judge`). The
  offline mock's judge is not priced.
* **A resume reviews as its run did.** The run context records `verify`; `--resume` reads it
  back and refuses `--verify`. A spec the resume scores again is reviewed again.
* **Masked.** The reviewer's reasoning goes through the report's single masking pass; the state
  and the attempt id are restored, as a tool's name is.
* **Refused without a reviewer.** On a live target `--verify` needs `--judge`.

## Why reported and not decisive

The combination rule (`shared.combination`, OD-19) already keeps a fail only the judge reported
from confirming a finding: the judge is the one evaluator a target can prompt-inject. A confirmed
finding rests on a deterministic fail. Letting the same judge unconfirm it would hand the target
a lever over exactly the findings the rule protects. Reported beside the finding, the state does
its job (it tells the operator which fails to read first) and costs nothing in trust.

## Not taken

* **`does_not_hold` keeps a finding from being confirmed.** Simple, and the lever above. OD-63
  names it, and names the narrower version: a `does_not_hold` on a fail that only the judge
  reported (already unconfirmed) taken out of the `--include-needs-review` gate.
* **On by default.** One judge request more per failing spec on every run, and a reader that
  needs a judge model the operator may not have. OD-63 keeps it opt-in.
* **Several passes, or a vote.** One pass answers the cheap refutations; a vote would multiply
  the cost for a state that decides nothing.
* **Kept in the evidence.** The verification is in the report only. `dottore replay`, which reads
  the evidence, does not show it.

## Costs, stated

`core/runner.py` and the new `evaluators/fail_verifier.py` are in the judging digest: judging
rules 7 re-pinned, no rule of judgement changed (without `--verify` nothing is sent and
`verification` is null; with it, nothing a state says moves a verdict). One judge request per
failing spec.

## Reversal

Run without `--verify` (nothing is sent, `verification` is null), or drop `verifier` from the
runner's constructor and the flag; `Finding.verification` is then an optional field nobody sets.
