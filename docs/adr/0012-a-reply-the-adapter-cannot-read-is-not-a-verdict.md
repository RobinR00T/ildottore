# ADR-0012: a reply the adapter cannot read is not a verdict (OD-21)

* **Status:** accepted, 2026-10-11, under the owner's delegation of that morning (10:09: "arreglalo
  todo según mejores prácticas"), revisable; amended the same day after the verification of
  `07aa0b3a` (the stop's benign check, a resume that starts proven)
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

## The stop on a run of them, and its check

A wrong endpoint answers every request with something the adapter cannot read, and so does a
target that breaks mid-run (an expired session behind a proxy that serves a login page with HTTP
200). The runner counts unreadable replies in a row, each reply it reads starting the count again,
and stops the campaign at 5 in a row while it has read nothing, or at 20 in a row once it has
(u08 A-74). A content filter in front of the endpoint that answers attack prompts with a 200 block
page reads the same way, and the verification of `07aa0b3a` measured what that cost: with a filter
on words such as "ignore", "instruction", "system prompt", "secret" and "bypass", the default
battery at `--concurrency 1` read 69 of 284 replies as block pages, 20 of them in a row, and
stopped with exit 3; every resume sent its 69 unreadable attempts first, and a fresh count read the
first five as a wrong endpoint and stopped after 5 requests, though 110 attempts had been answered.
The run could never finish.

So, before either stop, the runner sends one benign request (`Please reply with the single word:
ready.`), debited and paced like any send and filed with the recognition probes; when its reply
is read, the endpoint still answers as the provider does, the count starts again and the run goes
on, the blocked attempts left `inconclusive`. Only when the check cannot be read either does the
campaign stop, and its reason names a filter's block page among the causes. A resume of a run that
holds a read reply starts with the endpoint proven, so only 20 in a row stop it. With the same
filter at `--concurrency 1`, the battery now finishes: 160 of 550 attacks blocked, 2 checks sent,
exit 0.

Alternatives considered: no stop after the first readable reply (a broken target sends the whole
battery, 355 requests and exit 0 in the first audit); a stop with no check (the case above); a
check before every unreadable reply (a request per blocked attack). The check costs one request
per run of 5 or 20; a wrong endpoint now costs 6 requests at `--concurrency 1`, where it cost 5.

## Consequences

* A spec a target garbles on any attempt reports `inconclusive` with the reason, and the operator
  reviews the excerpt. A target that garbles every attempt is caught by the runner's stop (A-74),
  after one benign check that it answers nothing readable.
* A target behind a filter that blocks many attack prompts with a block page finishes its battery
  with those specs `inconclusive`, never a pass, and the summary counts them; one whose replies
  break at random (30% in the verification's probe) leaves every spec `inconclusive`, which is
  what such a target supports: none of its specs can be shown to hold.
* Reproducibility counts the attempt in `N` and never as a success.
* A resume sends such an attempt again: within a run it is not retried, since the same request at
  temperature 0 gets the same reply, but between invocations the target may have been fixed.
* Reversal: drop the reason from `_NEVER_A_PASS` in `core/runner.py` (the verdict stays, the
  majority decides again), or the reason itself, which brings back the generic verdict.
