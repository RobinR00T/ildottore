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
- **Every long option the tool names is one it accepts** (`tests/cli/test_flags.py`, added
  2026-10-07). A string literal under `src/ildottore` (docstrings aside) or a help text the command
  tree renders that names a `--option` no command or group accepts fails the test (an option is
  `--`, not right after a letter, a digit, `_` or `-`, then a lowercase ASCII letter, read up to the
  first character that is not a letter, a digit, `_` or `-`, so `--budget-wall_s` is not taken for
  `--budget-wall`). The resume refusal for a spent wall-clock ceiling told the operator to raise
  `--budget-wall-s`, which `dottore run` answers with "No such option"; the flag is `--budget-wall`.
  That refusal is also followed through the CLI as an operator would follow it: the flags it names
  are read from `dottore run`'s parameters, and raising them lets the resume through
  (`tests/cli/test_resume_integrity.py`).
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

**A-60 SIGTERM and SIGHUP stop a run as Ctrl-C does, inside a callback too (added
2026-10-08).** `execute_run` turned them into Ctrl-C by installing `signal.default_int_handler`,
which raises KeyboardInterrupt wherever the main thread is. Raised inside a weakref callback,
Python prints "Exception ignored" and drops it, and the run goes on: in CI the `[sigterm]` case of
`tests/cli/test_probe_pass_spend.py` saw a resume keep sending after its SIGTERM (41 requests
served where 25 were expected, `WeakSet._remove` in the child's stderr; three first attempts on
two PRs: #72's runs 37755261302 and 37758633140 and #82's run 37689645382, Linux, Python 3.11.16
and 3.11.17), and in older versions a SIGTERM or SIGHUP raised inside a weakref callback under
`asyncio.run` was dropped every time. Ctrl-C was never dropped there:
inside `asyncio.run` the SIGINT handler is asyncio's, which cancels the run instead of raising.
SIGTERM and SIGHUP now call whatever SIGINT handler is in place at that moment, so inside the
event loop the first of them cancels the run as Ctrl-C does (a second, or one after the run's task
has finished, raises in place as before), and they raise as before only when SIGINT has no Python
handler (ignored, as for a job a script starts with `&`, where asyncio installs none). A program
that embeds `execute_run` and gives Ctrl-C a handler that does nothing, or one installed through
`loop.add_signal_handler`, makes them do nothing either; `dottore` does neither. An
ignored SIGHUP still stays ignored (`nohup`). Outside the event loop (planning, the store writes,
the reports) a signal still raises where the main thread is, so one landing in a callback there
is dropped, as Ctrl-C is in any Python program; with SIGINT ignored that holds inside the loop
too, and there a signal can also land in one of asyncio's own callbacks (gather's, which wakes
the task awaiting it) and leave that task with nothing to wake it: `asyncio.run` cancels the
other tasks as it closes, so the run stops sending, but the process waits for that task until a
second signal, and the stuck part's spend is recorded only when Python collects the task
(pre-merge audit of #94; measured through `execute_run` with SIGINT ignored and the first SIGTERM
raised inside the runner's gather: it waited for the second, sent 3 s later, and the spend was
written as the process exited). It is documented and not fixed, because each fix in view changes how
every stop works and is not a follow-up's to make: raising from a loop callback of its own would
avoid both, but one that arrives as the last loop stops would then be queued on a loop that does not
run again, and lost; cancelling the run's task without raising, as asyncio does for Ctrl-C, needs a
handle on the task `asyncio.run` creates and its own review. The MANUAL says to send the signal
again. The requests are sent inside the loop. Checked by `tests/cli/test_termination_signals.py`:
SIGTERM, SIGHUP and, as a control, SIGINT raised inside a real weakref callback under `asyncio.run`
(the first two fail on `e4d6c83`); SIGTERM and SIGHUP outside a loop with SIGINT at its default and
ignored; SIGTERM inside a loop with SIGINT ignored; and a SIGTERM raised inside gather's callback,
which takes a second one with SIGINT ignored (ten turns of the closing loop later the task is still
cancelled and not done) and not with SIGINT at its default; the second is queued from inside the
first, so no clock decides it, and the stuck task is collected inside the test. The SIGHUP cases
give SIGHUP a handler of its own first, so they hold when the suite runs under `nohup`.

**A-61 A run id is never masked as a phone number (added 2026-10-09).** A run id was `run-` and the
first 12 hexadecimal digits of a UUID4. When all twelve came out decimal, (10/16) ** 12 of the draws
or about one run in 281, the redactor every report and every CLI error goes through read them as a
phone number: the JSON report named the run `run-«REDACTED:phone»`, in `run.run_id` and in every
evidence reference, and `dottore replay` refused the id read back from it (`error: unsafe run_id:
'run-«REDACTED:phone»'`, exit 3). `new_run_id` draws again when the twelve are all decimal. The
redactor keeps its rule: excusing `run-` would let a target hide a 12-digit number behind four
letters, and with one letter among the twelve none of its default rules matches (a phone's digits
have to fill a word from edge to edge, a card needs 13 digits). The id keeps its shape, so a run
minted before, all digits or not, resumes and replays by the name of its evidence directory; the
reports it wrote keep the mask, and so do the reports of its resumes, which keep its id. Checked by
`tests/cli/test_run_id_digits.py`: the UUID source made to draw twelve decimal digits first, through
`run -oJ` and a `replay` of the id read back from the report; an all-digit id of an older version,
masked in its report and replayed by its directory name; 2,000 ids minted from draws weighted
towards decimal digits (693 drawn again), each left as it is by the redactor, alone, quoted in a
message and in a path; and one letter in each of the twelve places. 3 of its 15 tests fail on
`6401ee2`.

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
`or {}` in `_target_from` (called by `load_target` and `read_target_file` since #77), and `dict[str,
bool]` in `FleetTarget` with `**entry.capabilities` in `_target_doc` (the `Capabilities` import in
`cli/fleet.py` then goes, or ruff fails), undo it, with this test file removed. Outside the clause,
and said so rather than pinned (pre-commit, delta and pre-merge audits):
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
* unknown keys are listed on the one line as `validation_problems` lists any block's problems
  since #76: the first 20, then `and N more`, each path cut at 300 characters (20,000 keys give
  a line of 1,040 bytes, where `sampling_defaults` on `2f6201a` printed 789 KB);
* a run halted before this change with such a key resumes once the key is deleted (it was never
  read, so the target is the same; measured end to end, exit 0) and is refused as another target
  once the key is corrected to the one meant, which changes the capabilities; that refusal's
  advice to restore the target as it was is followed by deleting the key, since the file as
  written no longer loads. A `capabilities: false` resumes the same way once deleted or written
  as `{}`.

**A-48 The advice of a refusal is advice the tool would accept, and a resume is checked for being
the same campaign before it is checked for money (added 2026-10-07).** `run --resume -sV` with a
request ceiling that could not hold the probe pass was refused with "Raise --budget-requests, or
drop -sV", before the check of the planning mode (A-24). Each half was right for one kind of
campaign only, measured through the CLI on `0501752` (pre-commit audit of
`fix/resume-wall-flag-name`): on a campaign halted without `-sV`, raising the ceiling was refused
again ("halted with adaptive planning off and this invocation asks for on"); on one halted with
`-sV` or `--deep`, dropping `-sV` was ("on" and "off" the other way). Now:

* the checks that the resume continues the same campaign (target, route, judge, planning mode,
  `--runs`, battery and evidence) run before the wall-clock and request-ceiling refusals, and the
  resume inherits the campaign's `--runs` before the provisional plan those ceilings are derived
  from (at the invocation's default of 5, a campaign run at `--runs 20` was refused against a
  derived 2,000 requests where its own was 3,300). The checks only read: the evidence is adopted
  into the artifact journal after the last refusal before any traffic, so a resume refused before
  it sends writes nothing (on `0501752` the `--budget-requests` pre-flight refused a resume with no
  recorded spend after adopting);
* the planning-mode refusal names the flags that set the mode, `-sV`, `-A` and `--deep`, to leave
  out or to put back (it named none);
* the three refusals of a probe pass that does not fit the request ceiling (the resume's
  pre-check, the `--budget-requests` pre-flight and the pass that reaches the ceiling) offer
  dropping `-sV` only when the ceiling would hold the rest of the campaign without the probes,
  priced as `--estimate --resume` prices it, and never to a campaign that recorded adaptive
  planning (a resume whose spend left one request of room halted after it, exit 3, keeping
  nothing; after a pass that reached the ceiling on a resume with a spend on record, its sends are
  recorded and fill the ceiling). Otherwise they say to raise `--budget-requests`, and every one
  names that flag (two said "the ceiling").

`tests/cli/test_resume_sv_advice.py` follows every piece of advice each of these refusals gives,
through the CLI, and asserts that each is an invocation that goes through, not a second refusal;
each test pins the advice it expects, and a flag the advice names that its grammar cannot turn into
an invocation fails it. 20 of the 24 it had then fail on `0501752`; the other four guard what did
not change (a campaign that recorded no planning mode may still drop `-sV` when the ceiling holds
the rest, and a resume refused for the wall-clock or the request ceiling leaves the journal as it
found it). Limits, written here rather than fixed in a test: the advice answers the check that
refused, so following "Resume with -sV" adds the probe pass, which a tight ceiling then refuses on
its own (with advice that goes through), and following "Resume without -sV, -A or --deep" under a
ceiling that does not hold the rest of the campaign halts (measured with 6 spent and 3 to send: at
ceilings 6, 7 and 8), as any resume did on `0501752`; "whichever it ran with" asks the operator for
what the run store does not keep (one flag for the three); the advice reads the request axis only,
so a campaign halted on `--budget-tokens` is still told about requests, as on `0501752`; the
estimate leaves out the multi-identity sweep of a live target with two or more identities and
retries, so a followed "drop -sV" at an exact fit can still halt, and it over-prices a resume's rest
with `--judge` (the safe direction); the test grammar does not read a piece written as a sentence of
its own ahead of the advice; the advice names `-sV` where the invocation said `-A`, which implies
it; and the stored mode is read by truthiness, as the planning-mode check reads it, so the advice
and the check agree on a value that is not a boolean.

The resume's pre-check writes its figures as the halt reason writes the figure that stopped a run
(#69, u08 A-6), with the same helper, `budgets.budget_figure`: grouped (`has already spent
123,456,789 of its 123,456,805-request ceiling, and -sV would send 17 more`), and from 10**18 as a
magnitude rounded away from the ceiling (a stored spend of 2**1000 reads `1.072e+301`, where grouped
it was 402 characters: a stored spend is bounded only by what a float holds). Bare, from nine digits
the redactor every CLI error goes through read each as a phone number, and the operator got
`«REDACTED:phone»` for both figures to compare (2026-10-09; the last test of the file, whose three
cases fail on `6401ee2`).

**A-55 Every integer flag of `run` is bounded above as well as below, and so is a live run's pace
against the wall-clock ceiling (added 2026-10-07).** `--runs` had a lower bound only, and the plan
multiplies its token estimate by the budget headroom, a float: `dottore run ... --dry-run --runs
<4,300 nines>` (and `--estimate`, and the run) exited 1 with `OverflowError: int too large to
convert to float`, a traceback and the code this tool uses for "findings below the threshold" (from
305 nines with `PI-DIRECT-001` alone, 303 with the shipped battery, against a mock target with every
capability). Found on 2026-10-07 by the pre-commit audit of `fix/huge-int-repr` (finding F6). A
sweep of every numeric flag of `run` (the seven integer ones and `--rate` and `--timeout`) with
hostile values, 168 dry-run and estimate cases and 48 runs against the mock, found two more: `--rate
1e-308` (or `5e-324`) on a live target was the same traceback in `budgets_for` (`cannot convert
float infinity to integer`, from the request count over the rate), `--dry-run` included; and
`--budget-tokens`, `--budget-requests` or `--budget-wall` of `-1` passed `--dry-run` and
`--estimate` with exit 0 while the run refused it with exit 3. The pre-commit audit of this clause
found that bounding the quotient alone turned `--rate 1e-308` into a live run that never stopped
(still running after 25 s with `--budget-wall 3`): the ceiling is checked when a send is charged
(`core/budgets.py`), not while the rate limiter waits for the next one (`core/pacing.py`), and the
same held for any pace slow enough (`--rate 0.001 --budget-wall 5` was still running after 45 s
against a local stub). Its delta audit found the first answer exempting a zero ceiling, where
`--budget-wall 0 --rate 1e-6 -sV` ran past 25 s because the probe pass reads no ceiling, and reading
`--rate` only, so `-T0 --budget-wall 1` passed where `--rate 0.5 --budget-wall 1` was refused.

So `_validate_options` refuses, with exit 3 and before anything is sent (`fleet --run` writes its
scope and target files first), a `--runs`, `--top-tests` or `--concurrency` below 1, a
`--budget-tokens`, `--budget-requests` or `--budget-wall` below 0, and any of the six above
`MAX_FLAG_VALUE`, `2**53` (9,007,199,254,740,992, where the run of whole numbers a float holds
exactly ends; `--budget-wall` of that many seconds is 285 million years): `error: --runs must be at
most 9,007,199,254,740,992 (got a number of more than 21 digits)`. Through `run` and `fleet --run`,
which builds its options in code. Once the timing is resolved, and before the resume block and the
probe pass, which send, a live run whose pace (`--rate`, or the timing template's) is under one
request per wall-clock ceiling (`--budget-wall`, or the 7,200 s cap a derived ceiling cannot pass)
is refused, the product compared so that a NaN refuses too (`--rate inf` against a zero ceiling is
`inf * 0`, which the pre-merge audit got past a `< 1` test): `--rate 1.000e-308 is less than one
request per 7,200-second wall-clock ceiling, so the run would wait past that ceiling between two
sends; raise the rate or --budget-wall` (`the -T0 pace of 5.000e-01 requests per second ...` for a
template). Under `--budget-wall 0` no pace sends, so the advice names the one flag that helps:
`--budget-wall 0 leaves a live run no time to send anything, at any pace; raise --budget-wall`. An
offline mock run is not paced, so not checked. A resume inherits the count its run store recorded,
after these checks, so the store refuses a stored `--runs` past `2**53` as a corrupt record, as it
refuses one below 1 (a 400-digit count edited into the store was the same traceback once inherited).
A figure is printed with thousands separators, which the CLI's redactor left readable in all of
63,000 sampled values (1 to 21 digits, either sign), and described past 21 digits; a rate in
scientific notation, which it left readable in all of 20,000 sampled refused rates, where 2,782
written as typed were masked as phone or card numbers. The wall-clock derivation also bounds its
quotient at `MAX_FLAG_VALUE` before `int()`, for any caller of `budgets_for`; the cap it is clamped
to afterwards makes the result identical for every finite quotient. The flag sweep, repeated on the
code before the delta audit: 0 tracebacks in 216 cases (8 on `2f6201a`). Checked by
`tests/cli/test_flag_bounds.py` (105 tests, 87 failing on `c3e70d8`; the 18 that pass are the bound
itself accepted for each flag, a zero budget still passing the dry run of a mock run, the three
lower bounds that already existed keeping their message, four paces of one request per ceiling or
more, a mock run not paced so not checked, and a paced wall under the cap derived as before; the
refused paces are tried in dry runs, so a regression cannot hang the suite), and by three cases in
`tests/cli/test_resume_integrity.py` that read a stored count in the store, not through a resume (it
reads `2**53` and refuses `2**53 + 1` and a 400-digit count; the last two fail on `c3e70d8`).

Outside the clause, and said so rather than pinned:
* the wall-clock ceiling is not a deadline at an accepted pace either: each concurrent spec waits
  its own interval and the `-sV` probe pass reads no ceiling, so `--rate 0.5 --budget-wall 2`
  against a local stub ran 2.6 s at `--concurrency 1`, 8.6 s at the default 4, 18.7 s at 12 and 34.8
  s with `-sV` (delta audit); a deadline in the rate limiter, or the probe pass under the campaign's
  ceiling, would close it and is u08's and u09's;
* `2**53` is not a bound with a meaning. It did not bound the work either: a resume built a set of
  mutators x runs attempt ids for each spec the halted run had started (10^7 runs, 1.3 to 3.7 GiB;
  `2**53 + 1` still growing at 3.7 GB after 4.5 minutes), until A-59 (u08) had the runner count what
  is stored instead (OD-32, decided 2026-10-08);
* `-T` was already refused outside 0 to 5, but a value of 9 digits or more is printed as
  `«REDACTED:phone»`;
* a resume is checked against the whole wall-clock ceiling, not what the halted run left of it (a
  run halted at 12 s of 16 s resumed at 0.07 requests per second and stopped at 26.3 s, pre-merge
  audit), and a live `--judge` in a run whose attack targets are all mocks is neither paced nor
  checked, as on `c3e70d8`;
* `--rate inf` turns pacing off (the limiter reads its interval as 0) and the dry run prints `inf
  req/s ceiling`; `--timeout inf` and `--timeout 1e308` are accepted.

**A-49 A report finding that fails validation is refused on one line that names the report and gives
each problem's place and reason, never the value (added 2026-10-07).** `diff.load_findings` handed
each finding of a JSON run report to `Finding.model_validate` without catching its
`ValidationError`. That error is a `ValueError`, so the handlers of `dottore diff` and `dottore
calibrate` caught it (exit 3 was already right) and printed pydantic's own text: several lines
(`error: 1 validation error for Finding`, the field, `input_value='maybe-later'` and a docs URL)
that quoted the report's value and did not say which of the two files it was in, while the other
loaders give one line through `shared/config_errors.validation_problems` (`scope file <path> failed
validation: <field>: <reason>`, `fleet file <path> ...`, `policy pack <path> ...`, `target file
<path> '<block>' ...`; pre-commit audit of A-45). The findings are still validated one at a time,
and the first that fails raises a plain `ValueError`: `the report <absolute path> failed validation:
findings.1.status: Input should be 'pass', 'fail' or 'inconclusive'`, with that finding's index (a
bare list of findings is addressed as `findings` too) and its problems, the model's fields in the
model's order and then the keys it does not have in the report's order, at most 20 and the rest
counted, the spec loader's figure. A first version validated them all together to list every bad
finding, and the pre-commit audit measured what that built: every error of every finding before 20
were listed, 1,116 MiB against 135 MiB on a 12 MB report. Two tests hold it: one counts the
validations, and one checks that loading 2,000 bad findings peaks no higher in `tracemalloc` than
reading their JSON, which caught two checks of every finding by another route that got past the
count (delta audit). A check by another route that keeps pydantic's exceptions without listing their
errors is seen by neither (457 and 375 MiB on the same report, pre-merge audit); that gap is written
here, not tested. The path is absolute with no colon after it, so the CLI keeps it readable, except
where it cuts every message's path short (a path holding a space or one of `()[],;'"`, until #70)
(`tests/cli/test_diff_report_validation.py`: 24 of its 31 tests fail on `de392e1`, 23 on the defect
and the one that counts the validations because the helper it counts is not there; of the 7 that
pass, 6 check that the redactor leaves each test value readable, so that the CLI tests can fail on
any mask in the output and on any 8-character piece of a value, and the memory test passes because
the base stops at the first bad finding too). Outside the clause, and said so rather than pinned:
* the report's other refusals keep their form, among them: an object without `findings` prints
  `error: 'findings'`, and a `summary` that is not an object and not empty or zero (a number, text,
  a list, `true`) prints `error: '<type>' object has no attribute 'get'`, exit 3 and no file named,
  while an empty or zero one (`0`, `""`, `[]`, `false`, `null`) reads as no summary; `<path>:
  expected a JSON run report or a list of findings` has a colon after the path as typed; and the
  refusals of a report with several targets or two findings for one spec, and of two reports about
  different targets, quote the target ids and the spec id the reports hold;
* a key a finding does not know is part of the place and goes through the CLI's redactor with the
  rest of the line: what the redactor recognises in it (an email, a known token format, a labelled
  secret, a run of high enough entropy) is masked, while a key of hex digits often is not, and the
  mask can take the `findings.0.` before it or the `: ` after it, while a short password-like key
  (`hunter2`) prints as written; it is printed as pydantic renders it, control characters included,
  so a key holding a line break still splits the line until the terminal writes them out (#51), and
  whole until #76 cuts a place past 300 characters (a key of 1 MiB prints 1 MiB);
* the finding that fails still builds all of its own errors before 20 are listed, as on the base
  (one finding with a million keys it does not have peaks over 1 GiB on both, by an amount that
  varies from run to run, and the base also printed 195 MB of error text);
* the wrapper that gives the index costs CPU on a valid report: 1.07 s against 1.00 s to load
  100,000 findings (best of 3), with the same peak memory;
* what pydantic can read is taken as read: `confirmed: "yes"` is true and `risk.impact: "2"` is 2;
* the labels file `calibrate` reads is not a report and keeps its own refusals.

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
  file of the repository does. Reversal: the filter and the `or {}` in `_target_from` (called by
  `load_target` and `read_target_file` since #77), `dict[str, bool]` in `FleetTarget` and
  `**entry.capabilities` in `_target_doc` (dropping the `Capabilities` import in `cli/fleet.py`),
  and `tests/cli/test_target_capabilities_strict.py` removed.
- **OD-32** how far `--runs` may go (2026-10-07). **Decided 2026-10-08 by the owner: the runner
  counts what is stored instead of building the plan (A-59, u08), and `--runs` keeps its `2**53`
  bound.** A-55 bounds it at `2**53`, which only keeps the plan's float arithmetic finite. The
  runner built a set of mutators x runs attempt ids per spec on a resume and in the multi-identity
  sweep, for each spec the halted run had started: with `PI-DIRECT-001` and `OUT-XSS-001`, a stored
  count of 10^6 took 209 MiB with one spec started and 593 to 679 MiB with both (three
  measurements; 653 to 678 on 2026-10-07), 10^7 took 3.5 s and 1.3 GiB with one and 16.3 s and
  3.7 GiB with both, and `2**53 + 1` was still growing at 3.7 GB when it was stopped after 4.5
  minutes on `2f6201a`. A bound with a meaning (the schema caps a
  spec's own unread `runs:` at 50) would have refused values that run today; counting does not.
