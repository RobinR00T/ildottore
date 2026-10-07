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
  A kept token that overlaps a credential the process
  registered is masked anyway, and every other 64-hex value goes through the redactor. An error
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
  requests per target per resume, unrecorded. It binds **sequential** invocations: two concurrent
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
or SIGHUP, which `execute_run` turns into Ctrl-C). A SIGKILL still loses the dead half's spend,
and so does a Ctrl-C during a resumed run's `-sV` probe pass; the resume then opens at whatever
was last recorded: the trade against a database write per request.

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
* `capabilities` that is not a mapping but is empty or false (`false`, `0`, `[]`, `""`) is read
  as no capabilities, and a key it does not know is dropped without a word (`sampling_defaults`
  refuses both).

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
an invocation fails it. 20 of its 24 tests fail on `0501752`; the other four guard what did not
change (a campaign that recorded no planning mode may still drop `-sV` when the ceiling holds the
rest, and a resume refused for the wall-clock or the request ceiling leaves the journal as it found
it). Limits, written here rather than fixed in a test: the advice answers the check that refused, so
following "Resume with -sV" adds the probe pass, which a tight ceiling then refuses on its own (with
advice that goes through), and following "Resume without -sV, -A or --deep" under a ceiling that
does not hold the rest of the campaign halts (measured with 6 spent and 3 to send: at ceilings 6, 7
and 8), as any resume did on `0501752`; "whichever it ran with" asks the operator for what the run
store does not keep (one flag for the three); the advice reads the request axis only, so a campaign
halted on `--budget-tokens` is still told about requests, as on `0501752`; the estimate leaves out
the multi-identity sweep of a live target with two or more identities and retries, so a followed
"drop -sV" at an exact fit can still halt, and it over-prices a resume's rest with `--judge` (the
safe direction); the test grammar does not read a piece written as a sentence of its own ahead of
the advice; the advice names `-sV` where the invocation said `-A`, which implies it; and the stored
mode is read by truthiness, as the planning-mode check reads it, so the advice and the check agree
on a value that is not a boolean.

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
