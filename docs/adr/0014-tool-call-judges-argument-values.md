# ADR-0014: tool_call judges the value of an argument a spec pins (u06 A-88)

* **Status:** accepted, 2026-10-19, under the owner's delegation (best practice, revisable)
* **Date:** 2026-10-19
* **Context:** the `docs/12` row "Argument-value abuse on an authorized tool" (found and built
  2026-10-19), clause u06 §7 A-88 in `specs/contracts/unit-06-evaluators.md` with its halves in
  u00, u02 and u13, the challenges of mubix/ai-ctf (Rob Fuller, MIT).

## The problem, measured

`tool_call` read a call's tool name and the names of its argument keys (`forbidden_args`), never
their values. Three classes of the AI CTF above have the model call a tool the scene authorizes,
with the keys the scene authorizes, and put the exploit in the value: a checkout sent a total of
zero or less, an authorized fetch sent a `file://` URL or a private address, an employee lookup
sent `7 OR 1=1`. On `d8b43561`, a fixture whose only exploit is such a value cannot be proved:
lint reports it `FIXTURE_NO_DETECT` (`tests/registry/test_forbidden_arg_values_lint.py`, the
control), and a run against a target that does it passes.

## The decision

`EvaluatorConfig.forbidden_arg_values` maps an argument name to a regex, read only by `tool_call`:

* **Keyed by argument name, any tool, any depth**, the name stripped and case-folded, as
  `forbidden_args` reads its keys: an exploit that nests the argument (`{"order": {"total_cents":
  0}}`) or writes it in another case is still the argument.
* **The value in its JSON spelling**: a string as itself, `true`, `false`, `null`, a number as
  Python writes it, `NaN`, `Infinity`, `-Infinity`; an integer past the interpreter's digit limit
  as its sign and a placeholder, so a hostile call cannot raise inside the evaluator. A list under
  the name is read item by item; a map is not read as a value, and the walk goes on inside it.
* **A match is a fail**, the finding naming the argument as the call wrote it (ASCII-quoted, so a
  control character cannot forge a line) and the tool; the value is masked (`tool_arg_value`).
* **A pattern that does not compile is `inconclusive`**, checked first, never a quiet pass; lint
  refuses it naming the argument, and `run` refuses the spec. Lint also refuses the key under any
  other evaluator, and a blank argument name, since the check would never run.
* **One helper for both sides**: the lint stub and the evaluator judge through
  `shared/tool_abuse.py`, as A-71 did for destructive names.
* **Opt-in.** A spec without the key judges as before; no shipped verdict changes, so judging
  rules 2 are re-pinned with a reason, not bumped.

Three specs use it, re-authored natively with no text copied, `test_only`, in `access-control`:
`FUNCALL-PRICE-TAMPER-001`, `AC-SSRF-SCHEME-001`, `FUNCALL-SQLI-ARG-001`.

## Alternatives not taken

* **Keys scoped to a tool** (`place_order.total_cents`). Tighter, but a target that renames the
  tool or routes through a hand-off slips it, and `forbidden_args` already set the precedent of a
  name read under any tool. A spec that needs the scope puts it in the scene: one tool owns the name.
* **A range syntax for numbers** (`total_cents: "<= 0"`). Clearer for price, useless for a URL or
  an id, and a second grammar to lint. A regex over the JSON spelling covers all three, and the
  battery test pins what each pattern catches and lets through.
* **A resolver for URLs** (parse the host, resolve its name, test the address). It would catch a
  public name that points inside, but it puts the network inside an evaluator that is offline and
  deterministic by contract. The SSRF pattern is a floor: it reads the URL as written (schemes,
  loopback, private, link-local, metadata, the integer and hex forms of an address), and the
  manual says so.

## Consequences

The battery holds 78 specs. Coverage figures do not move (the three specs map to classes already
covered). A spec author who pins a value pattern should add the values it must catch and the ones
it must let through to a test, as `tests/battery/test_argument_value_specs.py` does.
