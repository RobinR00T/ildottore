# ADR-0025: A reply the target's own application wrote is `inconclusive: canned_by_target` (u08 A-130, OD-72)

* **Status:** accepted, 2026-11-09, built as the smallest reversible version; OD-72 is open.
* **Date:** 2026-11-09
* **Context:** OD-41 and OD-42 (ADR-0011) keep a reply the provider's filter refused, cut or
  replaced from being read as the model resisting. A deployment can put a filter of its own in
  front of the model: a classifier that, on a prompt it flags, answers HTTP 200 with a fixed text
  from a small pool and never calls the model. No provider stop reason comes with it, so the reply
  was read as the model's: the `refusal` evaluator or the judge called it secure, and the spec
  passed on the application's words. Measured on `main` (`b4361d0e`, 2026-11-09) through the CLI
  against a loopback stub that answers every attack with one such text: `PI-DIRECT-001` at
  `--runs 2` with a judge, `status=pass`, exit 0. The pattern was seen in a field engagement
  (no detail of it belongs here): the same rejection, byte for byte, on the control and on every
  trigger, so nothing proved the prompt ever reached the model. Clause u08 §7 A-130 in
  `specs/contracts/u08-execution-engine.md`; OD-72 in its §9.

## The decision

* **The operator declares the texts.** A target file may list `canned_replies`: 1 to 50 texts,
  each at most 2,000 characters, with visible text. They are part of the target digest, since
  they change how a reply is scored. Left out of a dump when absent, so every other target is
  stored and hashed as before.
* **Compared by words, not bytes.** `shared.provider_filter.canned_key`: Unicode NFC, case
  folded, the empty format characters dropped, every run of whitespace one space. A reply with a
  tool call is the model's turn and is never marked.
* **Marked once, before anything reads it.** The runner wraps the campaign's adapter
  (`_CannedAdapter`) and marks each reply of the identity sweep, so a single attempt, a
  conversation, the sweep and a resume read the same mark: `ModelResponse.canned_reply`, left out
  of a dump when false.
* **A filter's reply on a side of its own.** `shared.provider_filter.filter_side` reads a canned
  reply on the `application` side, whatever stop came with it. The execution engine routes it as
  it routes a cut reply (`filter_cut`), and the runner scores it with the evaluators that read a
  replaced reply only: a canary in it still fails. Otherwise the attempt is `inconclusive` with
  the reason `canned_by_target` (this ADR is the one the enum's docstring requires to extend it).
* **Never a pass, never silent.** The reason joins `CUT_REASONS`, so a spec with one cannot pass,
  and a resume keeps the attempt rather than sending it again. Every report counts it apart: the
  finding's line, JSON `summary.canned_by_target` (optional in report-1.0), SARIF, JUnit, the
  HTML, the terminal summary and `replay`. Such an attempt does not exercise its framework
  categories in the coverage. A run the application answered throughout is `filtered`, exit 3.
* **Judging rules 13.** Verdicts change for a target that declares the texts, so
  `JUDGING_RULES_VERSION` is bumped: a run halted under 12 is refused by its resume (12 went to
  the mixed-signal refusal fix, u06 A-136, which merged first).

## Not taken (OD-72)

* **Detecting the pool on its own.** The same reply byte for byte across the control and every
  trigger of a spec looks like a canned text, but a model at temperature 0 can give the identical
  refusal to different prompts, and `run --control` sends a control only for a failing spec, so
  the rule would mark honest refusals and see nothing on a passing spec. Not built; OD-72 asks
  whether to add it as a note, as a verdict, or not at all.
* **Reusing `provider_filter_side_unknown`.** No provider said anything: the name would send the
  operator to the wrong vendor's console.
* **Regular expressions in the declaration.** A pattern that matches any refusal would make every
  refusal `inconclusive`. Exact texts, compared by words, are the smallest rule that works.

## Reversal

Remove `canned_replies` from the loader: no reply is marked, and every verdict is as before.
