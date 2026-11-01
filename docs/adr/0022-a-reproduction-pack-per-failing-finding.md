# ADR-0022: a reproduction pack per failing finding (u12 A-111)

* **Status:** accepted, 2026-10-30, as the smallest reversible version: an option of `replay`
  that writes what is already stored, and sends nothing. OD-67 is open.
* **Date:** 2026-10-30
* **Context:** a finding lived in the operator's evidence tree and run store. Handing it to the
  owner of the target meant a report, which names the finding and does not carry what to send
  again, or the whole evidence tree, which carries every other finding too and needs Il Dottore
  to read. Clause u12 §7 A-111 in `specs/contracts/u12-cli.md`.

## The decision

**`dottore replay RUN_ID --pack DIR [--finding SPEC_ID ...]`** writes, after the replay has
verified the evidence tree against the run store, one directory per failing finding of the run
(`DIR/<finding id>`, the characters outside `[A-Za-z0-9._-]` written `_`):

* `attempts/<sha256>.json`: each attempt the finding was scored from, copied byte for byte, so
  each file is still named by the SHA-256 of its content;
* `finding.json` (`pack_format: 1`): run, finding, spec and target ids, status, severity,
  reproducibility, `runs`, attempts and fails, the tool version, the judging rules and their
  digest, the spec digest the run recorded, the spec's name, OWASP code and CWE, and the list of
  attempt files with their verdicts;
* `README.md`: the same in prose, the `dottore run` line that reproduces it, how to send the
  request by hand, and per attempt its verdict and reasoning and, for a fail, the request sent
  (once per distinct request);
* `SHA256SUMS`: every file of the pack, for `shasum -a 256 -c`.

Rules:

* **Read-only, and nothing sent.** It reads the evidence and the run store; it never re-sends.
* **Verified first.** It needs the run store (`--run-db`): the findings it packs are the ones the
  run recorded, and the evidence it copies is the evidence `check_manifest` verified. Tampered
  evidence refuses the replay, and no pack is written.
* **Never overwrites.** `DIR` must not exist or be empty.
* **The reply stays in the attempt file.** The README quotes what Il Dottore sent (the spec's
  attack, as stored) and the verdict; the reply is text the target wrote, which can carry harmful
  content or markup aimed at whoever opens the README. Every line the README echoes is written
  through `visible_controls`, and a fence is longer than any backtick run it holds.
* **Today's labels, the run's spec.** The spec's name, OWASP code and CWE come from the specs read
  now, and only when that spec's digest matches the one the run recorded; otherwise the pack says
  the spec changed, or is not found, and names none. The digest leaves the labels out (`name`,
  `description`, `cwe` are cosmetic), so a label edited since the run is today's.
* **Redacted, as stored.** A value the redactor masked reads `«REDACTED:<kind>:<hash>»` in the
  pack as in the evidence; the README says so, and that a run with Il Dottore plants a fresh
  canary.

## Not taken

* **A `reproduce.sh` that sends the request with `curl`.** It would send outside the scope's
  allowlist, its budget and its redaction: the pack says how to reproduce with `dottore run`,
  which keeps all three, and how to send the request by hand, which is the owner's act.
* **The reply in the README.** See above; it is in the attempt file.
* **Packing the passes and the needs-review state.** The run store records a finding's status,
  not whether it was confirmed; the README carries each verdict's reasoning, which names the
  evaluators that failed it. OD-67 names a `confirmed` field.
* **A zip.** A directory with `SHA256SUMS` is checked with a standard tool and archived with any.

## Costs, stated

`cli/app.py` and `cli/repro_pack.py` are in the judging digest: judging rules 7 re-pinned, no
rule of judgement changed (the pack reads verdicts, never makes one).

## Reversal

Run `replay` without `--pack`; in code, delete `cli/repro_pack.py` and the three options.
