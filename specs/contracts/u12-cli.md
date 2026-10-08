# u12-cli.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/09` +
`docs/01 §3` + all upstream unit contracts before implementing. This unit is the **composition
root**: it wires concrete implementations to the `shared.protocols` interfaces and owns the
`dottore` command surface. It adds **no** attack/eval/scoring logic of its own.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/cli/`: `app.py` (Typer root + `dottore`/`dott` entry), `wiring.py`
  (composition root: builds adapters, evaluators, mutators, scorer, stores, reporters, engine
  from config + injects them), `run.py`, `fingerprint.py`, `registry.py`, `describe.py`,
  `new_spec.py`, `replay.py`, `flags.py` (nmap-style flag parsing + `-T` template expansion),
  `exit_codes.py`, `render.py` (live progress + summary table). Note: `cli/lint.py` is owned by
  **u02**: this unit only mounts it as a subcommand.
- **MUST NOT touch:** `shared/`, `core/`, `adapters/`, `evaluators/`, `scoring/`, `mutators/`,
  `store/`, `reporting/`, `registry/`, `policy/`, `cli/lint.py`, any spec/suite YAML, `schemas/`.

## §2 Intended behavior
Give a red teamer who knows `nmap` a productive CLI in 5 minutes (`docs/09`): target positional,
scan-type/intensity flags, selectable specs (our "NSE"), multi-format output, sane defaults.
The CLI **resolves** config → scope → suite/spec selection → engine plan, **delegates** execution
to `u08` core, **streams** progress, **renders** the summary, and **maps** the outcome to a
scriptable exit code. Commands: `run` (designed as the default when a target is given; as built
it must be typed: `dottore target.yaml` answers "No such command"), `fingerprint` (`-sV`),
`lint` (mounted from u02), `registry`, `describe`, `new-spec`, `replay`. The **scope/allowlist
gate is never bypassable**: not by `-A`, not by any flag (`docs/09 §5`, `docs/01 §6`).

## §3 Dependencies & interface contracts
- Depends on **all** units (W5 integration). Constructs concretes and injects them **only**
  through `shared.protocols`: `TargetAdapter, Evaluator, Mutator, RiskScorer, EvidenceStore,
  RunStore, Reporter`, and the `u08` engine facade. Consumes `shared.models.{TestRun, Finding,
  ModelFingerprint, RiskScore}` for rendering only.
- `run` calls the `u08` execution engine; `fingerprint` calls the `u09` fingerprint engine;
  `registry`/`describe`/`new-spec` call the `u02` spec registry; `replay` reads via the `u10`
  evidence/run store. The CLI holds **no** business logic beyond wiring + I/O.
- Reporters selected by `-o*` flags map to `Reporter.format ∈ {json, html, sarif, junit}`.

## §4 Known constraints: KEEP / DECIDE
- KEEP: composition root is the **only** place concretes meet interfaces; import-linter forbids
  `cli` being imported by any package and forbids core/adapters importing `cli` (`docs/01 §2`).
- KEEP: `--scope` is REQUIRED for any command that sends traffic (`run`, `fingerprint`, `-A`,
  `--quick`, `--deep`); default-deny; `--allow-endpoint`/`--unsafe-render` are audited, never
  silent. (As built neither flag exists, so nothing widens the allowlist from the command line,
  and the HTML report never shows prompts; the KEEP binds whoever adds them. The JSON report is
  another matter: it carries every attempt's request, prompt included, through the redactor,
  which masks secret, PII and high-entropy shapes only, so the attack text of a `test_only` spec
  is readable there; no reporter reads `test_only`.) `--dry-run` resolves + validates and sends
  nothing.
- KEEP: exit codes `0` clean · `1` findings below `--fail-on` · `2` at/above `--fail-on` · `>2`
  operational error (`docs/09 §4`). As built the operational code is `3`, and it also covers a
  run that did not finish and a command-line usage error (an unknown option exits 3, so it
  cannot be read as "findings at/above"). `--fail-on` gates **confirmed** findings; `--include-needs-review`
  extends the gate to the unconfirmed **fails** only (an inconclusive or a pass never gates,
  although an inconclusive that was sent reads `needs_review` in the reports, `docs/05 §2`).
- KEEP: `-T0..-T5` expand to concrete rate/concurrency/timeout defaults in `flags.py` (documented
  table); explicit `--rate/--concurrency/--timeout` override the template.
- DECIDE (OD-5), resolved as built: there is no `--adaptive` flag. `-sV` and `-A` fingerprint
  and the planner orders mutators by the result; `--deep` sets adaptive mode too, which orders
  nothing without a fingerprint (`00-INDEX.md` OD-5).

## §5 Implementation plan (each step its own commit, green before next)
1. `app.py` + `flags.py` + `exit_codes.py`: Typer root, `-T` template table, exit-code enum,
   `--version`, `-v/-vv/-q/--no-color`. No traffic yet.
2. `wiring.py`: composition root: build stores/adapters/evaluators/mutators/scorer/reporters
   from resolved config; assemble the `u08` engine. Pure DI, unit-tested with fakes.
3. `run.py`: positional target + `-t`, `-sn/-sV/-A/--quick/--deep`, `--suite/-p/--spec/--exclude/
   --top-tests`, execution flags, `-o*`/`-oA`, `--fail-on/--include-needs-review/--compare`.
4. `render.py`: live per-spec progress line + category×severity×reproducibility summary table.
5. `fingerprint.py`, `registry.py`, `describe.py`, `new_spec.py`, `replay.py` (thin delegators).
6. `[project.scripts]` entry points `dottore`/`dott`; mount u02 `lint` subcommand.

## §6 Data/wire shapes
- No new persisted models. Emits reporter bytes to `-o*` paths (`-oA <prefix>` writes all four
  formats). `--compare` renders a target×spec matrix from multiple `TestRun`s.
- `-T` template → `{rate_rps, concurrency, timeout_s}` map lives in `flags.py` (golden-tested).
- Exit code is a pure function of `(findings, --fail-on, --include-needs-review, error_state)`
  in `exit_codes.py`: no side effects, table-tested.
- All terminal output honors the central redactor; secrets/PII never printed (`AGENTS.md §2`).
  (As built, for errors, `cli/app._masked`: URL passwords are masked first, on the whole text.
  A 64-hex value is then kept readable in exactly two cases: an evidence file name
  (`<sha256>.json`), and a digest the error itself carries as one the tool computed (the
  `digests` attribute: on a scope checksum mismatch the digest computed from the body; the
  `checksum:` value the operator typed is not quoted at all; on a tamper refusal the hash the
  artifact's content has now). A scope validation error names fields and reasons, never the
  input value, and so does a target file's `capabilities` or `sampling_defaults` refusal (A-45).
  A spec file a load refusal names is kept readable when it is a relative path to
  an entry on disk under a spec path (the `spec_files` attribute of `SpecLoadError`) and no
  token character of the entropy rule (`[\w+/=-]`) is glued to it where it matched; what the
  loader quotes from inside the file goes through the redactor (the name is the spec tree
  author's choice, the operator's or an installed pack's, not a value of the run). A kept token
  that is part of a credential the process registered, from 8 characters, prints as
  `«REDACTED:credential»` (one that contains a registered credential loses it to the value rule
  first), and every other 64-hex value goes through the redactor. An error
  quotes an `auth_ref` only when it is a reference (it contains `://`, as `env://NAME` does); a
  literal pasted where a reference belongs prints as "a literal value (not shown)", because the
  redactor alone caught such a value only by its entropy; the `fleet --judge` mismatch follows
  the same rule.)

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/cli -q` green; coverage ≥ 85% for `src/ildottore/cli`. (As built CI enforces
  85% on the aggregate over `src/ildottore` only; no per-package figure is gated, OD-13.)
- `ruff check .` + `ruff format --check .` clean; `mypy src/ildottore/cli` clean.
- `lint-imports` green: `cli` imported by nobody; `core/adapters/evaluators/...` never import
  `cli`; concretes appear **only** in `cli/wiring.py` (import-contract assertion in `docs/07`).
- **Exit-code golden table** (`tests/cli/test_exit_codes.py`): clean→0, below-threshold→1,
  at/above→2, operational-error→>2; `--include-needs-review` flips unconfirmed fails into the gate.
- **Scope gate is non-bypassable** (`tests/cli/test_scope_gate.py`): `run`/`fingerprint`/`-A`
  without `--scope` → exit >2 with a clear error and **zero** adapter sends (asserted via fake
  adapter call count). (`--allow-endpoint` emits an audit record: not built, the flag does not
  exist.)
- **`-T` template golden** (`tests/cli/test_timing.py`): `-T0..-T5` expand to the documented
  rate/concurrency/timeout; explicit flags override.
- **CLI-map golden** (`tests/cli/test_flags.py`): every nmap↔dottore mapping in `docs/09 §1` is
  parseable; `docs/09 §3` cheat-sheet invocations parse without error under `--dry-run`. As
  built no test runs a cheat-sheet line as written. `test_flags.py` has three tests named after
  it: `test_cheatsheet_quick_scan_dry_run` asserts that `--quick` is REFUSED (exit 3) on a spec
  tree without a `quick` suite (`test_quick_narrows_the_battery_against_the_shipped_specs` runs
  `--quick` against `specs/` and expects exit 0); `test_cheatsheet_sv_suite_multiformat_dry_run`
  runs `-sV -p pi,leakage -T 4 --fail-on high`, with no `--suite` and no output flag; and
  `test_cheatsheet_aggressive_adaptive_budget_dry_run` runs `-A`. Nothing covers `--suite
  owasp:llm`, `-oH`/`-oS`/`-oX` or `--compare`. All five lines of `docs/09 §3` were run by hand
  under `--dry-run` on 2026-10-04 (the first as written, the others against offline mock target
  and scope files) and each exited 0. The `eu:ai-act` preset line was removed from `docs/09 §3`
  because it exits 3 (the preset is not built).
- **Composition smoke** (`tests/cli/test_wiring.py`): `wiring.build()` returns an engine whose
  injected components satisfy each `shared.protocols` type; no concrete leaks past the root.
- `--dry-run` sends nothing (fake adapter send-count == 0); `-oA` writes exactly 4 report files.

**A-7 A no-send promise holds under COMBINATION (added 2026-09-22).** `--dry-run`,
`--estimate` and `-sn` send zero requests in **every** flag combination, asserted with socket,
DNS and httpx entry points patched to raise, and with a positive control proving the
instrument fires. Each alone was clean; `--dry-run -sV` printed "sent nothing" immediately
after ten live probes with a real bearer token, because the guard named one of three modes.

**A-8 Every printed number is produced by the code that does the work.** A count the CLI
prints (specs selected, requests to send, probes, budget ceilings) is computed by calling the
same planner and policy gate the run calls, and a test pins the printed figure to the **real
send count**. The dry-run printed the raw selection before both filters and promised 845
requests where the run sent 499, and understated a multi-target run by half.

**A-9 An operational failure exits 3.** Never 1 (which this tool uses for "findings below
`--fail-on`") and never 2 (at or above). That binds every exception class that can reach a
command: a malformed YAML, an adapter refusal, a tampered artifact, an unreadable scope. Each
one shipped as a 1 or a 2 at some point, because the handler tuple was written by listing the
classes somebody remembered. A test drives each failure through the CLI and asserts the code.
A file nested past the JSON parser's stack is one of them (2026-10-07): `json.loads` raises
`RecursionError`, which is not a `ValueError`, and `diff`, `calibrate`, `replay` and
`run --resume` exited 1 on it. The fix is where the file or column is parsed, into a
`ValueError` that names the file or the column. So is a value that parsed and overflowed later,
when it was formatted, walked or written back: a report's run status is formatted only as
text, a run store column is refused past 100 levels, and a YAML file (spec, scope, target,
fleet, labels, pack) is refused past 100 levels with its aliases expanded, which chained anchors
reach from 4 KB of text (`tests/cli/test_deep_json.py`, `test_replay.py`,
`test_resume_integrity.py`), and past 100,000 nodes with them expanded, which 15 doubling
anchors reach from 265 bytes (u01 A-37, `tests/cli/test_yaml_expansion.py`).

**A-10 A resumed run is bound to its target.** `--resume` refuses a run id whose stored run
belongs to a different target, and refuses when no run store is available to check. Unbound, it
produced a full report for an unprobed target with **zero requests sent**, in both directions:
a vulnerable target inheriting a clean bill of health and exiting 0, or a hardened one
inheriting criticals. The evidence cannot detect this (an `Attempt` carries no target); the run
store can.

**A-11 A declared ceiling binds every request the tool makes.** `--rate` and
`--budget-requests` cover fingerprint probes as well as attack traffic. Probes do not travel
through the runner, so they were bounded by neither: `--budget-requests 2 -sV` sent 30 requests
and then reported "limit 2, attempted 3", counting only the half that passed the ledger.
Amended 2026-10-03 (audit F6 / F-7): the multi-identity sweep and the `--judge` model were the
two remaining exceptions (ten identities under a ceiling of two; `--budget-requests 5` sent 15
with a judge). The sweep debits the ledger and is skipped on a resume of a finished spec; the
judge is wrapped in `core.metering.MeteredAdapter`, bound to the campaign's ledger and pacer,
and the estimate and the derived ceilings count it.

**A-24 A resume is bound to its campaign: the battery, the target, the route, the sample size
and the money (added 2026-09-22, widened the same night after audit).** Every one of these was
a claim about a whole campaign checked only against the invocation in front of it.

* **The battery.** Both halves are merged into one finding per spec and scored together, so an
  edited prompt produced one report, under one run id, out of two different batteries. Per-spec
  digests are recorded and a resume refuses a changed battery naming what changed (exit 3). The
  digest is over a **behavioural projection** of the loaded model, so a corrected description or
  a reflowed line is not a change: hashing the whole model refused a resume over an edited
  `tags` line, which is how a check teaches the operator to route around it.
* **The target and the route.** The id check was one field deep. `--resume --hardened` needed no
  file edit at all: it flipped the offline replay, and a vulnerable half's criticals were
  published as a hardened run's findings. A target digest now covers the loaded target and the
  resolved route.
* **The sample size.** `--runs` is the denominator of the reproducibility axis. Changing it
  explicitly is refused; omitting it **inherits** the campaign's, because the store knows it.
* **The money.** The hard budget reset on every command. The cumulative spend is persisted and
  the ledger opens there, **including the `-sV` probe pass**, which runs outside the runner's
  ledger by design and was therefore pre-checked against the ceiling and then never billed: 17
  requests per target per resume, unrecorded (and recorded only at the ceiling when the pass
  stopped, until A-46). It binds **sequential** invocations: two concurrent
  resumes of one run id are not serialised (no lease), so they can each spend the remainder. The
  write is monotonic per axis, so a refused write can no longer discard a higher token or wall
  figure along with the request count, and the record cannot under-report what was spent.
* **The judge and the planning mode.** `semantic_judge` decides verdicts, so a different
  `--judge` mid-campaign arbitrates one report with two models; the planning mode decides the
  order of the mutators a spec runs. Both are in the recorded context now. (The recorded mode is
  `adaptive`, set by `-sV`, `-A` or `--deep`. Only a fingerprint reorders anything, so `--deep`
  alone, which is timing template T2 over the same battery, records adaptive mode without
  changing any order; a resume must still match it.)

**The target AND ITS ROUTE are the things with no opt-in.** `--resume-unverified` waives the battery, the
context and the spend, and a second audit pointed it at a run row with no target id and resumed
a vulnerable app's evidence into a hardened app's report with zero requests sent: one flag was
disarming two checks, and its help text advertises a budget consequence. A run that does not record its target, **or its route**, is refused outright, with no flag. The
first version made only the target ID unwaivable, and a third audit walked through the gap it
left: a run row whose context column was absent still accepted `--resume-unverified --hardened`,
which flips the offline replay, so one half's criticals were published as the other's. A context
row that merely lacked the digest key skipped the check silently, with no flag and no notice.

**The integrity record is written before the campaign sends, the spend after it returns.** Both
halves used to be written when the campaign returned, so a run killed mid-flight left evidence
on disk and no row, and its resume was refused outright because the target could not be
verified: the resume you most want after a crash was the one you could not have. Everything in
the integrity half is known before the first request. The spend is not; since 2026-10-04 the
runner hands it to the store however the campaign stops (a ceiling, an abort, Ctrl-C, and SIGTERM
or SIGHUP, which `execute_run` turns into Ctrl-C), and a resumed run's `-sV` probe pass is
recorded however it ends (A-46). A SIGKILL still loses the dead half's spend; the resume then
opens at whatever was last recorded: the trade against a database write per request.

**A-46 A resumed run records what its `-sV` probe pass sent, however the pass ends (added
2026-10-07).** The pass runs outside the runner's ledger, and only the request ceiling recorded
what it had sent before stopping. Every other stop lost it: a probe answered 503 three times (the
meter retries it twice, then the adapter's environment error stops the pass) left the run store
at 20 requests while the target had served 23, and a 401, a 200 that is not JSON, Ctrl-C, SIGTERM,
or anything stopping the run between a pass that succeeded and the runner's ledger opening lost
the pass the same way; the next resume then probed again against a ceiling that had never seen
those requests (delta audit of PR #68, reproduced on main `0501752`). The CLI now owns the pass's
ledger and, on a resume whose spend is recorded, writes the prior spend plus every request the
pass sent, retries included, as soon as the pass ends, success included. Requests are counted as
the ledger counts them, every send attempted: one that never reached the target (a refused
connection) counts, as it does for the attack traffic, and so does a send in flight when a signal
arrives. Each probe is counted once: the store keeps the highest figure per axis, so the runner's
later record of the same probes plus the attack does not add them again.

Signals were the hard part, found by three audit rounds. The write after a pass that succeeded
sits inside the handlers: placed after them, a real SIGINT a few milliseconds after the last probe
lost all 17 in 2 of 16 tries (pre-commit audit). A handler's own write has nothing after it: one
SIGINT landing there just after a 503 stop lost the pass in 2 of 41 tries (delta audit). Writing
again on that signal closed it, and on a locked store made Ctrl-C wait one more busy timeout per
interrupted write (9.9 s instead of 4.7 after a 503, 15.1 instead of 9.8 after a pass that
succeeded) for a record lost anyway (pre-merge audit); it was withdrawn rather than given a further
rule. So the record can fall below what was sent in three cases: a signal landing while a handler
writes it (a few milliseconds; after an error or the ceiling stopped the pass one signal is
enough, after a signal or a pass that succeeded it takes a second), a SIGKILL, and a write that
fails, which is a warning and never replaces the error or the Ctrl-C that stopped the pass. The
first two are written here and not pinned by a test.

When an error or a signal ends the pass before its record is complete, stderr says how many
requests it sent and what the run now records, or that they could not be added, even under `-q`:
the error's own text says `exhausted 1 attempt(s)` after three sends, because the meter, not the
adapter, owns the retries (the ceiling's refusal gives its own count). A signal landing during that
write also cuts the line. Not recorded, as on the ceiling path before: a fresh run's pass
(its run row is written after the pass, so there is nothing to resume) and a `--resume-unverified`
run whose spend was never recorded (it was told its ceiling covers that invocation alone). Such a
resume that completes still records its own invocation's spend as the run's, which predates this
clause and is not changed by it.

Checked through the real CLI against a counting stub by `tests/cli/test_probe_pass_spend.py`: a
503, a 401 and a 200 that is not JSON on the first and on the sixth probe; SIGINT and SIGTERM sent
to a subprocess with a probe on the wire (its Ctrl-C handler restored, since a shell that starts
pytest with `&` passes SIGINT on ignored); an interruption at the write after a pass that
succeeded; a write that fails; a stop after the write; a resume that completes; and the two cases
not recorded, each comparing the store with what the stub served.

**An unverifiable resume is refused, not noticed.** The first version continued with a warning,
and an audit showed why that is wrong: a run recorded before the digest column also predates the
spend column, so the same resume that could not verify the battery was handed a brand-new budget
ceiling, and the commit that claimed to fix the double ceiling could still reproduce it on every
run that existed. `--resume-unverified` is the explicit opt-in, and it says in its own message
that the ceiling then covers one invocation. A **corrupt** integrity record is not the same as an
absent one and raises rather than continuing. All of it is checked before the fingerprint pass,
which sends: `-sV --resume` used to put 17 probes on a live endpoint and then exit 3 having done
no work. Checked by `tests/cli/test_resume_integrity.py`.
A **corrupt** record includes, since 2026-10-07, a column nested past the JSON parser's stack, a
spend figure that is not a finite, non-negative number and a stored `--runs` that is missing
beside the target digest or not a positive whole number (an infinity or a list was a traceback
and exit 1, a negative spend was taken as spent, `true` resumed at one run, a missing count at
the invocation's default).

**A-42 A run parses each target file once (added 2026-10-07).** `dottore run` and `dottore
fingerprint` parse a target file once per time it is named (`wiring.read_target_file`), and the
target the scope authorizes, its route (mock or live), its `mock_scenario`, the target handed to the
live adapter, the plans and a resume's binding all come from that one parse. `run --dry-run` parsed
a mock target four times (to load it, to ask whether it is a mock, to read its scenario, and for the
plan) and a live one five (the target loaded again for the adapter, and a second plan), three times
under `--hardened`, and `fingerprint` up to four, so a file costly to build cost that many times
over (a 450 KB target with a base-60 value was accepted after 37 s, found by the pre-commit audit of
A-37), the live target sent to came from a later read of the file than the one the scope authorized,
and a target that can be read once (`-t /dev/stdin`) was refused on its second read. Not covered: a
file named twice is parsed once per name (`-t X -t X`, refused as a repeated id, and `-t X --judge
X`), and `fleet --run --judge` parses its judge file once to generate the scope and once to run. A
scope with a `checksum:` line is still parsed twice, by design: the second parse is the check that
the line is part of no other value (u01). Checks: `tests/cli/test_yaml_construction_cost.py`,
counting parses where the YAML is parsed: a mock run under `--dry-run`, `--estimate`, both with
`-sV`, a full run, `-sV` and `--hardened`; a live dry run and estimate; `--hardened` on a live
target; two targets; a resumed run; a judge file; a target piped in on `/dev/stdin`; and
`fingerprint` offline and on a mock target, each target file parsed exactly once.

**A-45 A target file's `capabilities` or `sampling_defaults` refusal names the file, the field and
the reason, on one line, never the value (added 2026-10-07).** `load_target` handed a target file's
`capabilities` and `sampling_defaults` blocks to pydantic without catching its `ValidationError`.
That error is a `ValueError`, so every command's handler caught it and printed pydantic's own text:
four lines (`error: 1 validation error for Capabilities`, the field, `input_value='maybe-later'` and
a docs URL) that quoted the operator's value and named no file, while the scope and fleet loaders
already gave `scope file <path> failed validation: <field>: <reason>` (`fleet file ...`, and `policy
pack <path> ...` for a pack), through `shared/config_errors.validation_problems`, which keeps the
input value and the URL out. Both blocks now raise a plain `ValueError` of that kind, `target file
<path> 'capabilities' failed validation: tools: Input should be a valid boolean, ...`, with the
block's problems on the one line as `validation_problems` lists them, and exit 3 through `run -t`,
`run --judge`, `fingerprint` and `fleet --judge` (`tests/cli/test_target_file_validation.py`: 19 of
its 24 tests fail on `0501752`; the other 5 check that the redactor leaves each test value readable,
and the CLI tests fail on any mask in the output, since a first value was masked as a phone number
and proved nothing; and they look for every 8-character piece of a value, since pydantic printed the
first 24 and the last 23 characters of a long one). Outside the clause, and said so rather than
pinned:
* other refusals of a target file still quote what it says: the `type` and `mock_scenario`
  values (whatever was written there, a map included), the tool name a `seeded_setup` both maps
  and grants, and the target's `id`, which several refusals name (two files with one id,
  `--hardened` on a live target, a target the scope does not authorize);
* a key the operator typed is part of the location and is printed as pydantic renders it (a
  `true:` key as `1`), control characters included, so a key holding a line break still splits
  the message until the terminal writes them out (#51);
* a file with both blocks wrong is refused on its `capabilities` block alone;
* only what pydantic cannot read as the field's type is refused: `tools: 'off'` reads as false,
  `temperature: '0.5'` as 0.5, `temperature: true` as 1.0, and `temperature` and `top_p` have no
  range (`.nan`, `-3`, `top_p: 7.5` are kept);
* `capabilities` that is not a mapping but is empty or false (`false`, `0`, `[]`, `""`) was read
  as no capabilities, and a key it does not know was dropped without a word (`sampling_defaults`
  refuses both): both are refused since A-50.

**A-50 A target file's `capabilities` is a mapping of the keys `Capabilities` knows, or nothing;
anything else is refused before anything is sent, and `dottore fleet` refuses it before it writes
(added 2026-10-07; OD-29 decided).** `load_target` validated only the keys of `capabilities` that
`Capabilities` knows and dropped the rest without a word, so `tool: true` written for `tools` ran
the target with tools off and took the tool specs out of the plan: on `2f6201a`, a chatbot with
`rag` and `memory` on planned 40 specs with 33 skipped for a capability, against 59 and 8 with
`tools`, and the dry run counted the skipped specs but named no key. A `capabilities` that was not a
mapping but read as false (`false`, `0`, `0.0`, `[]`, `""`, `no`) was taken as no capabilities,
while `true`, `1` or `[tools]` was refused as "must be a mapping"; `sampling_defaults` refuses both.
`dottore fleet` typed an entry's map as `dict[str, bool]` and copied any text key into the target
file it wrote, with exit 0, where the loader then dropped it. Now:
* a key `Capabilities` does not know is refused on the one A-45 line, `target file <path>
  'capabilities' failed validation: tool: Extra inputs are not permitted` (a key that is not text:
  `1: Keys should be strings`), beside the block's other problems, never the value;
* only an absent or null `capabilities` (the key with nothing after it, `null`, `~`) or an empty
  mapping is no capabilities; any other value that is not a mapping is refused as `target file
  <path> 'capabilities' must be a mapping`, without quoting it;
* a fleet entry's `capabilities` is the target file's own `Capabilities` model, so `fleet` refuses
  an unknown key (`fleet file <path> failed validation: targets.0.capabilities.tool: Extra inputs
  are not permitted`, exit 3) and writes nothing, and the target file it writes holds `tools` (true
  for `kind: mcp`) and `rag` overridden by exactly the keys the entry wrote, as before, though in
  the model's field order rather than the order written (same values, same loaded target).

`tests/cli/test_target_capabilities_strict.py`: 19 of its 40 tests fail on `2f6201a`, each on the
old behavior (the file loads, or the command exits 0); the other 21 guard what stays (a file with no
capabilities, every known key, the values that were already refused, what `fleet` writes) and that
the redactor leaves each test value readable, and one loads every target and fleet file under
`examples/`, `specs/` and `tests/` and every such YAML block of the docs through the real loaders.
Refusing both is the owner's decision (OD-29), as the smallest reversible change: the filter and the
`or {}` in `_target_from` (`load_target`'s body since #77), and `dict[str, bool]` in `FleetTarget`
with `**entry.capabilities` in `_target_doc` (the `Capabilities` import in `cli/fleet.py` then goes,
or ruff fails), undo it, with this test file removed. Outside the clause, and said so rather than
pinned (pre-commit, delta and pre-merge audits):
* a top-level key a target file does not know (`endpont:`, or `tools: true` under a
  `capabilities:` left empty by a lost indent) is still dropped without a word, and so is a `name`,
  `provider`, `endpoint`, `model`, `auth_ref` or `transport` that is not text;
* a fleet entry's `capabilities` that is not a mapping, `null` included, was refused and still is,
  now in pydantic's words for a model (`Input should be a valid dictionary or instance of
  Capabilities`), where a target file reads `null` as none;
* what pydantic can read as a boolean is taken as read (`tools: 'off'` is false), as in A-45;
* an unknown key is printed as the location, as A-45 says of any key: one that is not text as
  pydantic renders it (`on:` as `1`, `off:` as `0`, `~:` as `None`), an empty key or one holding
  half a character (a lone surrogate) as `<root>` (the latter with `Input should be a valid
  string`), and control characters as written until #51 writes them out; a credential pasted as a
  key is masked as any error text is (a registered credential and the known key shapes first, then
  the entropy rule), and the entropy rule leaves a low-entropy one readable (about 1 in 20 random
  64-hex keys, and the tests' repeated value);
* every unknown key is listed on the one line, as `sampling_defaults` lists them on `2f6201a`
  (20,000 keys gave a 789 KB line); the default of 20 listed problems that #76
  (`fix/operator-file-read-cap`) gives `validation_problems` bounds both once it lands;
* a run halted before this change with such a key resumes once the key is deleted (it was never
  read, so the target is the same; measured end to end, exit 0) and is refused as another target
  once the key is corrected to the one meant, which changes the capabilities; that refusal's
  advice to restore the target as it was is followed by deleting the key, since the file as
  written no longer loads. A `capabilities: false` resumes the same way once deleted or written
  as `{}`.

## §8 Out of scope / forbidden
- MUST NOT implement attack/mutation/evaluation/scoring/reporting/fingerprint logic (u05-u11,
  u13): only wire and call them. MUST NOT own `cli/lint.py` (u02) or edit any spec YAML.
- MUST NOT provide any way to bypass the scope/allowlist or the redactor (`docs/09 §5`).
- MUST NOT print or log secrets/PII, raw dangerous payloads (except an audited `--unsafe-render`,
  which is not built),
  or commit/push from a build loop (`AGENTS.md §2`).
- MUST NOT be imported by any other package (composition-root direction only).
- Not its call: adaptive-default decision (OD-5) · judge model (OD-3) · scope signing (OD-2).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-5** whether `--adaptive` defaults ON under `-sV`/`-A` or is opt-in (CLI mirrors engine
  default; propose opt-in for MVP‑1 to bound cost). Resolved as built: no flag, `-sV`/`-A` imply
  adaptive ordering (see §4 and `00-INDEX.md`).
- Short alias `dott` alongside `dottore`: confirm both ship in `[project.scripts]` (propose yes).
  As built: both ship.
- `--compare` matrix output format for the terminal (propose compact table; JSON via `-oJ`).
- **OD-29** (decided 2026-10-07 by the owner: option 1, refuse both; built, A-50): whether a target
  file's `capabilities` refuses a key it does not know and a value that is not a mapping but reads
  as false, as `sampling_defaults` does. Built: both refused before anything is sent, and in
  `dottore fleet` before anything is written. Alternatives: keep dropping them in silence (main
  until A-50: a typo of `tools` takes the tool specs out of the plan); warn and go on (the warning
  goes where the run's output goes, and a CI log nobody reads loses the same specs); refuse the
  unknown key and keep `false` as none (the one shape an operator may write on purpose to mean
  "none", though `{}` or leaving the key out says it too). A file that loads on main and is refused
  now holds a key `Capabilities` does not know or a `capabilities` of `false`, `0`, `[]` or `""`; no
  file of the repository does. Reversal: the filter and the `or {}` in `_target_from`
  (`load_target`'s body since #77), `dict[str, bool]` in `FleetTarget` and `**entry.capabilities` in
  `_target_doc` (dropping the `Capabilities` import in `cli/fleet.py`), and
  `tests/cli/test_target_capabilities_strict.py` removed.