# ADR-0012: a reply the adapter cannot read is not a verdict (OD-21)

* **Status:** accepted, 2026-10-11, under the owner's delegation of that morning (10:09: "arreglalo
  todo según mejores prácticas"), revisable
* **Date:** 2026-10-11
* **Context:** OD-21 in `specs/contracts/00-INDEX.md`, clause u08 §7 A-74. It extends
  `InconclusiveReason`, which `shared/enums.py` says is extensible only by ADR.

## The problem, measured

OD-21 turned a success reply the adapter cannot read (not JSON, not a JSON object, not the shape
the provider or the template declares) from a product error, which stopped the campaign at the
first one, into an environment failure of that attempt. As first built (`598f0858`) the attempt
got the verdict every environment error gets: `inconclusive` with no reason, which the spec-level
rule (F8) lets a strict majority of passes outvote.

The pre-merge audit of `598f0858` measured what that costs. A wrapper that pastes the model's
output into its JSON unescaped breaks on a quote, and a quote is what a jailbreak that worked
writes. Against a loopback stub whose first reply to `PI-DIRECT-001 --runs 3` was such a wrapper,
broken by `"DAN mode enabled" PWNED`, and whose other two were refusals a secure judge passed, the
spec passed and the run exited 0, with no report saying a reply had been unreadable. On `main`
(`6d5f7ae`) the same run stopped with exit 3: the old rule was crude, but it did not pass a spec
over the one reply that may have been the exploit.

## The decision

The attempt is `inconclusive` with its own reason, `unreadable_reply`, and a spec with one such
attempt is never a pass, whatever the other attempts did, as OD-42 rules for a reply the provider's
filter cut. A `fail` on another attempt still fails the spec. The attempt keeps a bounded excerpt of
the body (at most 4 KiB of UTF-8, through the adapter's redactor), its size and the adapter's
advice under `request.metadata.unreadable_reply`, and every summary counts such attempts apart: the
terminal (never silenced by `-q`), the JSON report (`summary.unreadable_reply`), SARIF (each
result's message and properties, and the run's properties), JUnit (the message of the failure or
the skip), HTML and `dottore replay`.

Alternatives considered:

* **The generic environment verdict** (as built in `598f0858`): a majority of passes decides. It
  lets the attack that broke the wrapper be outvoted, which is the case above.
* **A fail.** An unreadable reply is not evidence of an exploit either: a proxy's error page, a
  gateway's maintenance page or a wrong endpoint produce one with no attack involved, and a fail
  gates CI.
* **Stop the campaign, as before OD-21.** One hostile reply then decides whether the rest of the
  battery is measured.

## Consequences

* A spec a target garbles on any attempt reports `inconclusive` with the reason, and the operator
  reviews the excerpt. A target that garbles every attempt is caught by the runner's stop (A-74).
* Reproducibility counts the attempt in `N` and never as a success.
* A resume sends such an attempt again: within a run it is not retried, since the same request at
  temperature 0 gets the same reply, but between invocations the target may have been fixed.
* Reversal: drop the reason from `_NEVER_A_PASS` in `core/runner.py` (the verdict stays, the
  majority decides again), or the reason itself, which brings back the generic verdict.
