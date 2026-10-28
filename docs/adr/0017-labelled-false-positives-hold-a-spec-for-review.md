# ADR-0017: labelled false positives hold a spec for review (u08 A-105)

* **Status:** accepted, 2026-10-27. OD-61 decided the same day by the owner, as built: per
  spec, the last 50 labelled fails, more than 30% false alarms with 5 at least, `inconclusive`
  counted as a false alarm, no expiry
* **Date:** 2026-10-27
* **Context:** `dottore calibrate` (docs/12, "Human-in-the-loop feedback loop", built 2026-09-03)
  measured the scanner against an operator's labels and threw the labels away. A spec that keeps
  raising false alarms on a target kept failing the CI gate run after run, and the only remedies
  were to drop the spec from the selection or to stop gating on it by hand. Clause u08 §7 A-105
  in `specs/contracts/u08-execution-engine.md`, with its halves in u10 (the run context) and u12
  (the two flags).

## The decision

A labels ledger, and a breaker that reads it before the campaign:

* **`dottore calibrate REPORT LABELS --record LEDGER`** appends one JSON line per spec scored
  (in the report and in the labels): the report's run id, the spec, the scanner's verdict, the
  operator's, the time. Created 0600, never through a symbolic link, appended in whole lines. A
  report with no run id (a bare list of findings) cannot be recorded, and a record that would
  take the ledger past the 1 MiB a run reads is refused there, not found by the next run.
* **`dottore run --fp-ledger LEDGER`** reads the ledger before anything is sent. Per spec it
  takes the last 50 labelled records whose scanner verdict was `fail`; with 5 or more of them, a
  spec is **held** when more than 30% were labelled anything but `fail` (an `inconclusive` label
  on a fail is a false alarm too). A run and spec labelled twice count once, at the latest label.
* **A held spec runs, is judged, scored and reported as before; its fail is never confirmed.**
  The runner decides it where it decides `confirmed`, before the finding is stored, reported or
  gated, so a held fail is a fail that needs review: it does not trip `--fail-on` unless
  `--include-needs-review` is given, SARIF caps its level at `warning`, and its reasoning ends with
  `held for review by the labels ledger: N of its last M labelled fails were false positives`.
  The run prints the holds on stderr, under `--quiet` too, as it prints an inherited `--runs`.
* **A resume holds what its run held.** The holds go into the run context (`review_holds`, spec
  id to the two counts) before the first send; `--resume` reads them back and refuses
  `--fp-ledger`, so one campaign is never gated under two ledgers.
* **Fails closed.** A ledger line that is not a label record stops the run before it sends (exit
  3): a breaker that skipped what it could not read would hold less than the operator labelled.

## Why here and not after the run

A breaker applied to the report after the exit code was computed holds nothing: the gate has
already fired. And a breaker applied in the CLI after the runner returns would leave the run
store saying `confirmed` where the report says `needs review`, so `replay` and a resume would
disagree with the report. The hold is one more reason `_is_confirmed`'s answer is overruled, in
the one place that answer is made.

## Not taken

* **Per spec and target.** Holding a spec only on the target its false alarms came from is more
  precise and needs many more labels per pair before a rate means anything. The ledger records the
  run id, from which the target can be recovered later. OD-61 kept the spec as the key (2026-10-27);
  it is the first thing to revisit when one spec is scanned against targets that differ.
* **Changing the verdict.** A held fail stays a fail: the operator decides, the scanner does not
  rewrite what it saw.
* **Dropping the spec from the run.** It would stop measuring the very spec whose rate the next
  labels have to bring down.
* **An expiry.** A hold that lapsed after some days without a label would gate again on the
  same false alarm nobody re-examined. OD-61 chose none: new labels lift a hold, and so does the
  window of 50 once the false alarms leave it.
* **Writing the ledger from `run`.** The labels are the operator's; only `calibrate`, which reads
  them, writes them.

## Costs, stated

`core/runner.py` is in the judging digest: judging rules 7 re-pinned, no rule of judgement
changed (a reply is judged as before; without `--fp-ledger` nothing is held). A ledger grows by
one line per labelled spec per run and is read whole: about 8,000 labels fit in 1 MiB, and only
the last 50 labelled fails of a spec count, so an operator who fills it starts a new one.

## Reversal

Drop `--fp-ledger` from the run (nothing is held), or delete `review_holds` from the runner's
constructor and the two flags; a stored run context with `review_holds` is read by nothing else.
