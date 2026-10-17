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
  cannot be read as "findings at/above"). `--fail-on` gates **confirmed** findings;
  `--include-needs-review` extends the gate to the unconfirmed **fails** only (an inconclusive or a
  pass never gates, although an inconclusive that was sent reads `needs_review`
  in the reports, `docs/05 §2`).
- KEEP: `-T0..-T5` expand to concrete rate/concurrency/timeout defaults in `flags.py` (documented
  table); explicit `--rate/--concurrency/--timeout` override the template.
- DECIDED (OD-5, signed off as built on 2026-10-11 under the owner's delegation, revisable):
  there is no `--adaptive` flag. `-sV` and `-A` fingerprint and the planner orders mutators by
  the result; `--deep` sets adaptive mode too, which orders nothing without a fingerprint
  (`00-INDEX.md` OD-5, reasoning in u08 §9).

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
  (As built, for errors, `cli/app._masked`: the redactor runs on the whole text, URL passwords
  included (until #96 the URL rule ran on its own first, on the raw text, and cut a registered
  credential holding an `@` or a `:`), and an endpoint an error cuts comes without its userinfo
  before it is cut (u01 A-51, #96); one quoted whole (`EndpointNotAllowed`, a WebSocket close) is
  the redactor's to mask.
  Besides the existing part of an absolute path, a path that exists, written whole, is kept
  out of the entropy rule (A-38); the name of a file that does not exist is not (OD-25).
  Outside one, a 64-hex value is kept readable in exactly two cases: an evidence file name
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
  that holds 8 consecutive characters of a credential the process registered prints as
  `«REDACTED:credential»` (one that contains a registered credential loses it to the value rule
  first), and every other 64-hex value goes through the redactor. An error
  quotes an `auth_ref` only when it is a reference (it contains `://`, as `env://NAME` does); a
  literal pasted where a reference belongs prints as "a literal value (not shown)", because the
  redactor alone caught such a value only by its entropy; the `fleet --judge` mismatch follows
  the same rule. A registered credential split by control or format characters (Unicode Cf), or
  by U+FFFD (what half a character in a reply reads as, u04 A-47), is masked whole by the
  redactor itself (`redact_text`, since PR #57; u01 A-32), with the digest of the unsplit
  credential, on the terminal as in the reports: it used to print in two readable halves. Last,
  after every mask, `_masked` writes every control character out (`redactor.visible_controls`:
  C0 and DEL as control pictures, C1, U+2028, U+2029, lone surrogates and format characters
  (Unicode Cf, since PR #51) as Python escapes; U+FFFD, which shows, is printed as it is). The
  other terminal paths that print what a pack, a report or a target wrote do the same
  (`Redactor.for_terminal` where the text is redacted), the `rich` lines of a run are printed as
  plain, unwrapped text, the `--compare` table prints target ids as text, and `diff`/`calibrate`
  refuse a report spec id that is not a spec id: no line of those paths starts with such text,
  except a `replay` line, which starts with an attempt or probe id read from the evidence tree.
  The same paths write the second `#` of `##<letters>[` as `\x23`, the shape of the commands a
  runner reads anywhere in a line (GitHub's legacy `##[cmd]`, Azure Pipelines'
  `##vso[area.event]`), and so do the off-universe values `coverage` and the run's summary print
  as their `repr`, the `-vv` plan's reasons for a refused spec (a pack's `requires_policy`; a
  skipped or not seeded one's too, defensively) and the scope digests the resume note reads back
  from the run store. The JSON outputs escape every control character (`fingerprint` escapes DEL
  and non-ASCII inside pydantic's own output) and keep every value as it is; since OD-20 (decided
  2026-10-11 under the owner's delegation, revisable) each of them, `lint --json`, `coverage
  --json`, `dottore fingerprint`, `schema export`, the JSON report and the SARIF report, writes
  that same `#` as `\u0023` (`redactor.log_safe_json`), JSON's own escape for it, and the JUnit XML
  report as `&#35;` (`redactor.log_safe_xml`, since the pre-merge audit of `598f0858`, LOW 4), so a
  reader parses the same value and a CI log carries no command from it
  (`tests/test_json_log_commands.py`: the parsed document is the plain serializer's, and
  serialized again with the output's options it is the plain bytes). This does not cover the
  operator's own values in the plan lines.)

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
Amended 2026-10-12 (A-80): a class nobody listed no longer reaches the terminal as a traceback
with exit 1: the root command group maps any exception no handler caught to exit 3 with one line,
and a sqlite3 error from the run store is named after the store. Amended 2026-10-16 (A-83): an exit
asked for with a code that is no exit status (a text, a bool, a number outside 0 to 255) is exit 3
with the stray-exit line, masked; `typer.Exit("<text>")` exited 0.

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
and the estimate and the derived ceilings count it. Amended 2026-10-07 (A-34): the estimate
and the derived ceilings count the identity sweep too, one send per scope identity for each
spec that sweeps, which they had never done; `--estimate --resume` subtracts it for a spec whose
every planned attempt is answered, as the runner then skips the sweep, counted from what is stored
as the runner counts it (A-59, u08), and the room check of the `-sV` refusals (A-48) reads the
same figure.

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

**The target AND ITS ROUTE are the things with no opt-in.** `--resume-unverified` waives the
battery, the context and the spend, and a second audit pointed it at a run row with no target id and
resumed a vulnerable app's evidence into a hardened app's report with zero requests sent: one flag
was disarming two checks, and its help text advertises a budget consequence. A run that does not
record its target, **or its route**, is refused outright, with no flag. The first version made only
the target ID unwaivable, and a third audit walked through the gap it left: a run row whose context
column was absent still accepted `--resume-unverified --hardened`, which flips the offline replay,
so one half's criticals were published as the other's. A context row that merely lacked the digest
key skipped the check silently, with no flag and no notice.

**A refusal says what changed and the flag that restores it (amended 2026-10-12, CLI audit of
2026-10-11, M1 and L6).** Three refusals said neither: a spec edit read "restore the specs as they
were", a different `--spec` with no file changed read the same ("71 no longer selected"), and
`--resume --hardened` over an unchanged target file read "Restore the target as it was". The run
context records, when a run starts, the selection flags (`selection`: suite, `--quick`, `-p`,
`--spec`, `--exclude`, `--top-tests`, each string masked with the store's fixed identity salt, and
kept by every resume), an 8-hex digest of each field of each spec's digest projection
(`spec_fields`, about 40 KB for the 75 shipped specs) and of the target's digest payload
(`target_fields`, `__route__` included), and the route (`route`: the offline scenario, or `live`).
The digests themselves are unchanged. So the battery refusal names the field (`1 changed
(PI-DIRECT-001), in attack`; the same field edited in two specs, `2 changed (PI-DIRECT-001,
SP-LEAK-001), in severity (2)`) and says to point `--spec-path` at the
specs the run was made with; a selection that differs is named both ways (`the run was made with
--spec PI-DIRECT-001 --spec SP-LEAK-001 and this invocation selects with no selection flag. Resume
with ...`); the same selection over another spec tree points at `--spec-path`; the target refusal
names the fields that differ (`its capabilities field changed ... Restore that field of the
target file as it was`), and a change of the route alone says so
and names its flag (`was made on the offline 'vulnerable' replay and this invocation resolves the
offline 'hardened' replay (--hardened forces it). The target file is otherwise unchanged ...
Resume without --hardened`; `Resume with --hardened`; `Restore the target file's mock_scenario`).
A run that recorded none of it gets the earlier wording; a run that records no judging rules (one a
version before `shared.judging_rules.JUDGING_RULES_SINCE` halted) is refused for its rules first
(A-81), so the `--spec-path` advice is given only where it is safe. Every
field the context holds is checked where it is read (u10 §6): a value of the wrong shape is refused
with exit 3, naming the field and never quoting the value, where `adaptive: "x"` read as on,
`scope_sha256s: 7` as a run older than scope digests (the record then overwritten), a
`mutator_orders` that was not a list was overwritten, and `started_at: not-a-date` reached every
report of the resume. Checked by `tests/cli/test_resume_refusal_advice.py` (15, all failing on
`de122e26`) and `tests/cli/test_resume_corrupt_context.py` (31, 28 failing there).

**The integrity record is written before the campaign sends, the spend after it returns.** Both
halves used to be written when the campaign returned, so a run killed mid-flight left evidence
on disk and no row, and its resume was refused outright because the target could not be
verified: the resume you most want after a crash was the one you could not have. Everything in
the integrity half is known before the first request. The spend is not; since 2026-10-04 the
runner hands it to the store however the campaign stops (a ceiling, an abort, Ctrl-C, and SIGTERM
or SIGHUP, which `execute_run` turns into Ctrl-C), and a resumed run's `-sV` probe pass is
recorded however it ends (A-46). A SIGKILL still loses the dead half's spend; the resume then
opens at whatever was last recorded: the trade against a database write per request.

**A halt keeps what it paid for, and a run that spent is resumable (amended 2026-10-07).** A
request ceiling that stopped a run inside `DL-XTENANT-001`'s identity sweep, or between two
attempts of one batch, stored nothing for that spec: the attempts the batch had answered went
down with the exception, the run store recorded requests the evidence did not show, and
`--resume` refused the run as one that "sent nothing", so its spend was stranded under an id
nothing could continue (delta audit of `fix/authz-leak-identity-sweep`, reproduced on main
`0f936b6`: three requests sent, then the refusal). The runner now stores every reply its batch
received before the halt (u08, budget gates), and a run whose run store records a request spent
is resumed even with no attempt stored, every spec from the start, its spend carried. Refused
still, each for the reason that is then true: a run that recorded no request spent; an empty
`--evidence-root` when the artifact journal holds any digest for the run, `pending` included
(from the tree alone that looks the same, and resuming would send everything again; a `pending`
digest is a write begun and never confirmed, on another tree or failed on this one, and the
message says both, where the first version called it "not the tree the run wrote"); and an
empty tree for a run that does not record the scope it went out under (D-17, built after the
journal), which may predate the journal, so its silence proves nothing (the last two from the
pre-commit audit, which had a pre-journal run and a pending-only journal resumed from the wrong
tree). An attempt is **kept** by a resume (not sent again, A-11's sweep skip, and what
`--estimate --resume` subtracts) when it has a reply and a verdict, or failed in a way a retry
would repeat; a reply stored without a verdict, its evaluation stopped by the ceiling refusing
the judge's request, is sent again and judged (with `--judge` that reply is paid for twice: it
is re-sent rather than re-judged, a design choice; judging the stored reply on resume is a
possible follow-up, and would save that one target request). A run halted by this
version is not for an older one to resume: it would keep the unjudged reply and score the spec
without it (pre-merge audit). A prior spec is **finished** (published by a
halted resume, scored by the seeding gate) only when every planned attempt has a verdict.
`--estimate --resume` subtracts what is kept, the judge's two requests per kept attempt of a
spec it reads included (it priced the whole battery's judge, 12 for a resume that sent 8), so it
prices what the resume sends, an identity sweep included since A-34 (u08, PR #60: the three
sweeping shapes, a strict `xfail` until both had landed, are plain tests now), and the room
check of the `-sV` refusals (A-48) takes off the same judge share. A finished run does not store
the sweep's replies either, so a halted sweep leaves only its spend. Checked through the real CLI by
`tests/cli/test_resume_halted_mid_batch.py`: every halt-then-resume test asserts the halted run's
spend, the final spend and the resume's sends as the loopback stub counted them, and the estimate
wherever it is exact.

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
503 and a 401 on the first and on the sixth probe (a 200 that is not JSON stopped the pass too
until OD-21, 2026-10-11; it fails only its probe now, checked beside a reply nested too deeply);
SIGINT and SIGTERM sent to a subprocess with a probe on the wire (its Ctrl-C handler restored, since
a shell that starts pytest with `&` passes SIGINT on ignored); an interruption at the write after a
pass that succeeded; a write that fails; a stop after the write; a resume that completes; and the
two cases not recorded, each comparing the store with what the stub served.

**A-60 SIGTERM and SIGHUP stop a run as Ctrl-C does, inside a callback too (added 2026-10-08,
amended 2026-10-09 and 2026-10-10).** `execute_run` turned them into Ctrl-C by installing
`signal.default_int_handler`, which raises KeyboardInterrupt wherever the main thread is. Raised
inside a weakref callback, Python prints "Exception ignored" and drops it, and the run goes on: in
CI the `[sigterm]` case of `tests/cli/test_probe_pass_spend.py` saw a resume keep sending after its
SIGTERM (41 requests served where 25 were expected, `WeakSet._remove` in the child's stderr; three
first attempts on two PRs: #72's runs 37755261302 and 37758633140 and #82's run 37689645382, Linux,
Python 3.11.16 and 3.11.17), and in older versions a SIGTERM or SIGHUP raised inside a weakref
callback under `asyncio.run` was dropped every time. Ctrl-C was never dropped there: inside
`asyncio.run` the SIGINT handler is asyncio's, which cancels the run instead of raising. #94 made
SIGTERM and SIGHUP call whatever SIGINT handler was in place, which left Ctrl-C ignored (a job a
script starts with `&`, where asyncio installs no handler): there they still raised, and one raised
inside one of asyncio's own callbacks (gather's, which wakes the task awaiting it) left that task
with nothing to wake it, so `asyncio.run` stopped the sending as it closed but waited for that task
until a second signal, and the stuck part's spend was recorded only when Python collected the task
(pre-merge audit of #94; measured through the real CLI with Ctrl-C ignored and the first SIGTERM
raised inside the runner's gather, on Python 3.12.13 and 3.14.7: it was still running 3.0 s after it
started, when a second SIGTERM ended it with exit 130, and the spend of 6 requests was written
outside the loop as the process exited, after "Task was destroyed but it is pending!").

Every loop a campaign runs, the `-sV` probe pass and each target's campaign, is now one of
`interrupts.run_until_stopped`, which does for SIGTERM and SIGHUP what `asyncio.run` does for
Ctrl-C, whatever Ctrl-C's disposition. The coroutine `asyncio.Runner` runs (`_drive`) makes the
campaign a task and awaits it at once, so a cancel of that coroutine reaches the task from its first
step (the first version made the task before the loop started: its first step ran before the
coroutine awaited it, a Ctrl-C there cancelled only the coroutine, and a second Ctrl-C during the
stop left the task pending, its spend written when Python collected it; pre-merge audit of the fix).
The first SIGTERM or SIGHUP stops the run without raising: with Ctrl-C at its default it goes to the
Ctrl-C handler that run's `asyncio.Runner` installed, which counts it with Ctrl-C's, cancels that
coroutine and wakes the loop; with Ctrl-C ignored, or with a handler of the program's own, the
handler cancels the task and wakes the loop (it may be waiting in select() for a reply) itself.
Nothing is raised inside a callback, asyncio's or a weakref's; the task unwinds inside the loop,
where the runner's `finally` writes the spend; and KeyboardInterrupt (exit 130) is raised once the
loop is closed. A signal that comes after the task is done, as the loop closes or inside
`loop.close()`, is kept and raised then too: this is why raising from a loop callback of our own was
rejected, since such a signal would be queued on a loop that does not run again, and lost. The loop
is let go while the run is still armed, so a signal during its `__del__` is the run's too. A second
signal of either kind before the run has stopped raises in place, as a second Ctrl-C does: asyncio's
handler counts the two together, and otherwise a signal after a stop some handler began (that
coroutine is being cancelled) is read as the second (the first version counted SIGTERM apart from
Ctrl-C, and Ctrl-C then SIGTERM, or SIGTERM then Ctrl-C, was one more cancellation). A second signal
raised in place can, like a second Ctrl-C under `asyncio.run`, land in one of asyncio's callbacks
and leave the run waiting for a third: with the second signal one line event after the first, 66 of
413 points of the sweep below waited for a third (16%), against 59 of 385 (15%) for a double Ctrl-C
under plain `asyncio.run`. Measured through the real CLI, with the first SIGTERM raised inside the
runner's gather: one SIGTERM, the process gone, with exit 130, 0.99 to 1.11 s after it started, the
spend of 6 requests written inside the loop, with Ctrl-C ignored and at its default.

Outside a loop (planning, the store writes, the reports) a signal calls whatever SIGINT handler is
in place, and raises where the main thread is when there is none. One that Python drops there
(raised inside a weakref callback or a `__del__`), or that a Ctrl-C handler of the program's own
ignores, is remembered by `terminations_watched`: the campaign's next loop does not start, so
nothing is sent after it, and past its last loop the campaign ends with KeyboardInterrupt as
`execute_run`'s block does (it used to end with the run's own exit code). Only the main thread
watches: a block in another thread used to reset what the main campaign had noted, and its next loop
started. The SIGTERM and SIGHUP handlers are set and put back with Ctrl-C, SIGTERM and SIGHUP held
back (`pthread_sigmask`), what each replaces recorded before it is set: a signal halfway through the
swap used to leave a handler of the campaign installed after `execute_run` returned (38 of about
6,000 points in the audit's sweep). The put-back is retried when a signal raises just before the
hold takes effect, and one that arrives before the put-back's last check, in a process whose only
thread is the main thread (another can take a signal the main thread holds back), is the campaign's
(accepted with `sigwait` and noted), not the restored handler's, whose default would end the process
with no exit code; the hold is let go right after that check, and one that comes in between goes to
the handler put back. A program that embeds `execute_run` sees the difference: inside a loop SIGTERM
and SIGHUP no longer call its own Ctrl-C handler (only asyncio's), and one that its Ctrl-C handler
ignores outside a loop still stops the campaign, at its next loop or as its block ends. An ignored
SIGHUP still stays ignored (`nohup`). Outside the main thread no handler is set and
`run_until_stopped` is `asyncio.run`. A send is bounded by `asyncio.timeout`, not
`asyncio.wait_for`: on Python 3.11 `wait_for` returned a reply and dropped a cancellation that
landed as the send completed (CPython gh-86296), so a spec a signal stopped at that instant went on
sending (`core/execute.py`; from 3.12 `wait_for` is built on `asyncio.timeout`).

Swept with the audit's tool (a signal raised at every line event while the campaign's handler is in
place, one forked child per point, over a probe pass and two campaigns of three gathered children
each): SIGTERM with Ctrl-C ignored, at its default and with a handler that does nothing, and SIGHUP
with Ctrl-C ignored and at its default, 8 of 31,030 points bad, where `2001e7f` had 50 of 6,032, 50
of 6,095 and 21 of 6,011 in the three SIGTERM arms (a handler left installed, a signal dropped in a
`__del__`, the run's own exit code after the last loop). The points left are the `while True:` and
`try:` of the put-back, which compile to NOP alone, where CPython never runs a signal handler; only
a line-event tracer reaches them.

Checked by `tests/cli/test_termination_signals.py` (48 tests): SIGTERM, SIGHUP and, as a control,
SIGINT raised inside a real weakref callback under `run_until_stopped` and under `asyncio.run`
(under `asyncio.run`, SIGTERM and SIGHUP fail on `e4d6c83`); SIGTERM and SIGHUP outside a loop with
SIGINT at its default and ignored; SIGTERM and SIGHUP in a loop, which the campaign sees as
CancelledError; a second SIGTERM, which raises in place, and a second signal of the other kind in
both orders and after a stop a handler of the program's own began (all five fail on `7a0be1d`); a
SIGTERM raised inside gather's callback, which one signal stops with SIGINT at its default and
ignored (with #94's handler its ignored arm fails, and so do the CancelledError cases with SIGINT
ignored): a safety net queued from inside the first signal sends a second only if ten turns of the
loop later the task is still not done, and it is never needed, so no clock decides it; a Ctrl-C in
the campaign's first step, then a second during the stop, after which the campaign's `finally` runs
inside a loop and asyncio logs nothing (it fails on `2001e7f`); a SIGTERM while the Runner makes its
loop, which cancels the task as it is made; a cancellation that is no signal's, which stays a
CancelledError; a SIGTERM once the task is done and one inside `loop.close()`, both raised after the
loop is closed (the second fails a handler that raises from a loop callback of its own); one that
arrives while the loop waits in select() with nothing scheduled, which has to wake it (a selector
that polls tells a loop that was not woken from one that was, the poll's length deciding nothing;
without the wake the CLI case below still passes, but in 32 s instead of about 2); one dropped
outside a loop, which keeps the next loop from starting, and one dropped after the last loop, which
ends the campaign with KeyboardInterrupt, each with Ctrl-C at its default, ignored and with a
handler that does nothing; a worker thread's block, which no longer resets the main campaign; a
signal while the handlers are set, while they are put back, and just before the put-back holds
anything, none of which leaves a handler behind (the first two fail on `2dcf954`); the handlers set
and put back without `pthread_sigmask` (Windows) and from another thread; and `run_until_stopped`
outside the main thread and inside a running loop. `tests/core/test_retry_classification.py`: an
attempt cancelled in the callback that delivers its reply ends with CancelledError (with CPython
3.11's `wait_for` in place of `asyncio.timeout` it returns the reply). Through the real CLI,
`tests/cli/test_probe_pass_spend.py` has a `[sigterm-ctrl-c-ignored]` case with a probe on the wire,
and its three signal cases check exit 130. The SIGHUP cases give SIGHUP a handler of its own first,
so they hold when the suite runs under `nohup`.

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

**A-66 A target file's `sampling_defaults` fills, field by field, what a request's own sampling
leaves unset, where the adapter sends sampling, and the evidence records what went out (added
2026-10-09; OD-39 decided).** The block was parsed, validated (A-45, A-50) and kept in the
target's digest, and no request carried it: an attack went out with the spec's own `sampling`
(temperature 0 when a spec declares none), a `-sV` probe with `PROBE_SAMPLING` and the judge with
its own, so `sampling_defaults: { top_p: 0.25 }` reached nothing and the manual said "applied to
nothing today". The owner decided that it applies as a fallback. Built:
* **precedence, per field** (`temperature`, `top_p`, `max_tokens`, `seed`): the request's own
  value, then the block of the file the request goes to, then the provider's default. No CLI flag
  sets sampling. An attack's own value is the spec's `sampling`, and a spec that declares none
  goes out at temperature 0 once the block has filled what it holds
  (`core.runner.spec_sampling`), so the block's temperature wins over the scanner's pin and loses
  to the spec's; a probe's is `PROBE_SAMPLING` (temperature 0, 512 tokens), so the block adds
  `top_p` and `seed`; the judge's is temperature 0, then 0.5, and `top_p` 1.0, so its own file's
  block (never the scanned target's) adds `max_tokens` and `seed`;
* **only what the adapter sends** (`wiring.sampling_fallback`): all four fields for `openai`,
  all but `seed` for `anthropic`, none for a REST template, an MCP server or a WebSocket target
  (by design: their wire shape has no sampling field) and none on the offline route; the block's
  `seed` only to a file whose `capabilities.seed` is true (false unless set, as every
  capability: the file says its provider takes a seed);
* **the adapter's own rule** (`wiring.sent_sampling_for`, the same function the adapter builds
  its request with): the Anthropic adapter sends no `seed` and no `top_p` beside a
  `temperature`, the spec's own, the block's and the judge's alike
  (`adapters.anthropic.sent_sampling`). Anthropic's API reference says every Claude 4 model
  answers the pair with HTTP 400 (read in the reference bundled with the claude-api skill,
  cached 2026-09-25; not tested against the live API), and every request the scanner makes sets
  a temperature, so no `top_p` reaches an Anthropic target or judge. Found by the pre-merge audit
  of `8d1bc59`: through a strict stub, `f12ba83` exit 0 and `8d1bc59` exit 3 with 0 of 10 specs
  run on a block `top_p`; the six shipped specs that set `top_p` 1.0 themselves
  (`EMB-INVERSION-PROBE-001`, `EMB-NEIGHBOR-LEAK-001`, `EMB-XTENANT-RETRIEVAL-001`,
  `PI-DIRECT-001`, `PI-INDIRECT-RAG-001`, `PI-INDIRECT-TOOL-001`) stopped such a campaign on
  `f12ba83` too, and so did every request of an Anthropic judge (its `top_p` 1.0). 1.0 is
  `top_p`'s default, so dropping theirs changes nothing they ask for; a block `top_p` below 1 is
  not applied, and `--dry-run` says so;
* **recorded as sent:** the runner fills its attempts itself and applies the adapter's rule
  (`CampaignRunner._sampling`: the single-turn send, the multi-turn conversation, the identity
  sweep), so an attempt's `sampling` and `request.sampling` are the request on the wire (on
  Anthropic, without the `seed` and the `top_p` it did not send); the probes and the judge go
  through `wiring._AsSent`, outside the probe recorder, so `probes/` holds the request as it went
  out (the judge's requests are not stored, as before); `--estimate` and the token ceilings
  derived from it price the block's `max_tokens`, the cap each send reserves; `--dry-run`
  prints, per field, on how many specs the block fills it (counted through the adapter's rule),
  what of it does not go out and why, the specs' own `top_p` an Anthropic target does not get,
  and the same for the `--judge` file (`judge sampling:` lines), or that a block is not sent;
* **a resume continues as its run started:** the run context records
  `sampling_defaults_applied` (true for every run started now). A run an older version started
  records nothing and sent none of the block, so its resume sends none either (the target's, the
  judge's, the `-sV` probes'), prices without it, says so on stderr whenever a block would have
  applied (`resume: <run id> started before sampling_defaults was applied, so it continues as it
  started, without the target file's sampling_defaults; a fresh run sends them`, never silenced
  by `-q`) and writes false, so every later resume agrees; a value that is not a boolean is a
  corrupt record, refused (exit 3) before anything is sent. The adapter's rule applies to such a
  resume too: a request with both is refused by every model the reference lists. The target
  digest is unchanged, so a run without a block resumes as before, and an edited block is still
  "a different target", whose refusal now names `sampling_defaults` among what may differ; an
  edited `--judge` file is refused as "a different --judge file (its endpoint, model or
  sampling_defaults differ)", where it said "stored a judge, now a judge".
`tests/cli/test_sampling_defaults.py` (42 tests, through a loopback stub that keeps every body and
whose Anthropic endpoints refuse `temperature` with `top_p` as the reference says Claude 4 models
do: OpenAI, Anthropic, REST, a multi-turn conversation, the identity sweep, the judge of either
provider, `dottore fingerprint` and `run -sV`, `--estimate`, `--dry-run`, five resumes and the
corrupt record, the README's two dry runs, and the helpers, imported inside the tests that use
them so the file is collected on a tree without them): 37 fail on `f12ba83` and 15 on `8d1bc59`.
The 5 that pass on `f12ba83` are controls: no block, a spec with no `sampling` and no block, a
REST target, the offline mock, and an Anthropic `-sV` pass (no block was sent there, so no
`top_p`). Outside the clause, and said so rather than pinned:
* the spec's own `sampling` is still recorded on an attempt through a REST template, an MCP
  server or a WebSocket, which carries none of it, as on `f12ba83`;
* the OpenAI adapter sends a spec's `seed` whatever `capabilities.seed` says (`seed_enabled` is
  never wired from the file); only the block's follows the capability;
* the Anthropic adapter sends `max_tokens` 1024 for a request with none and records none, while
  the ledger reserves 512 for it, as before;
* Claude models that take no `temperature` or `top_p` at all (the same reference lists Opus 4.7
  and later, Sonnet 5, and the Fable and Mythos 5 families) refused every request the scanner
  makes, the temperature 0 it pins included: a defect older than this clause, fixed by A-68.

**A-68 A target that takes no temperature or top_p is sent neither, says what that costs, and a
400 that refuses its sampling names the fix (added 2026-10-09).** Anthropic's API reference (read
in the reference bundled with the claude-api skill, cached 2026-09-25; not tested against the live
API) says Claude Opus 4.7, Opus 4.8, Opus 5 and Opus 5.5 and the Fable and Mythos 5 families answer
a `temperature` or a `top_p` with HTTP 400. For Sonnet 5 it contradicts itself (its quick table:
removed, a 400; its migration guide: only a value other than the default is a 400), and Sonnet
5.5 gets the second reading; sending neither is right under both, since the default temperature
is 1, the scanner pins 0, and a request without the field is accepted under both. With the
temperature pinned on every spec, probe and judge request, every `provider: anthropic` campaign
against those models stopped at its first request with `non-retryable HTTP 400 from
/v1/messages`, and nothing said why. Built:
* **a capability** `capabilities.sampling` (`Capabilities.sampling: bool | None`, u00; the
  `Capability` enum gains `sampling`), the one that is not false unless set. Left out, the
  default rule (`wiring.takes_sampling`): a `provider: anthropic` target whose model is of a family
  `adapters.anthropic.MODELS_WITHOUT_SAMPLING` lists (`claude-opus-4-7`, `claude-opus-4-8`,
  `claude-opus-5`, `claude-sonnet-5`, `claude-fable-5`, `claude-mythos-5`) takes none, every
  other target takes them; `false` sends neither to any model, through the OpenAI adapter too;
  `true` sends them to a listed one. An id is read as gateways write it
  (`adapters.anthropic.takes_no_sampling`): case-insensitively, its last `/` segment (a Bedrock
  ARN, `anthropic/claude-opus-4.7`, a Vertex resource path), without a `[...]` suffix (`[1m]`) or
  a gateway prefix ending in `anthropic.`, dots read as dashes; a family then matches the whole id
  or its start followed by `-`, `@` or `:` (`claude-opus-5` covers `claude-opus-5-5` and
  `claude-opus-5.5`, not `claude-opus-50`). Any other form (a provisioned-model ARN, an alias) is
  not matched and is sent sampling. The list is the one place the scanner keeps those models, and
  the capability overrides it either way; a model it does not name is sent sampling. It is applied
  to `provider: anthropic` only: the reference is the Messages API's, and a gateway that serves a
  Claude model through `provider: openai` says `sampling: false` itself;
* **neither on the wire nor in the record:** the adapters build their requests through their own
  `sent_sampling` (`sampling_enabled=False` drops `temperature` and `top_p`; `max_tokens` still
  goes out, the seed follows A-66), and the runner and `wiring._AsSent` record through the same
  rule (A-66), so an attempt's and a probe's sampling hold no temperature. Each also records, under
  `request.metadata.sampling_not_sent`, the fields asked for that did not go out: the spec's or the
  probe's own, and the target file's `sampling_defaults` as written (`wiring.sampling_written`,
  for a provider that sends sampling; the first version counted the block as
  `sampling_fallback` keeps it, which had already lost the fields the adapter never sends, so a
  listed model's records missed the block's `top_p` and `seed`), so a reader does not take a
  missing temperature for one nobody asked for;
* **said where the numbers are read:** such a target samples at its own default, so its replies,
  the reproducibility a report measures over `--runs`, a `-sV` fingerprint and the judge's two
  passes are not temperature-0 deterministic. The run says so on stderr before it sends anything,
  never silenced by `-q` (`note: <id> is sent no temperature or top_p (<why>): it samples at its
  own default, so its replies are not temperature-0 deterministic`; `the --judge model <id> ...`
  for the judge); `--dry-run` on a `sampling:` and a `judge sampling:` line; `-sn` on a `sampling:`
  line; `run -sV` appends `[probes sent with no temperature: not temperature-0 repeatable]` to the
  fingerprint line; `dottore fingerprint` says it on stderr; `dottore replay` counts the attempt
  artifacts that went out with no temperature under its pooled rate;
* **a refusal that names the fix:** a 400 from an adapter that sends sampling (OpenAI, Anthropic)
  whose JSON error names, as a parameter, a sampling field the request sent is `SamplingRefused`
  (`adapters.base.sampling_params_named`: `error.param` or its last dotted part, a token between
  backticks or quotes, or the first word of the message; a word of a quoted prompt, a longer
  identifier or a parameter the request did not send is not). It is a product error, so not
  retried and the campaign stops at the first one, as before, but with `the target refused the
  request's temperature. If the model takes no temperature or top_p, set `sampling: false` under
  capabilities in the target file of <id>`. The `--judge` model's is re-raised by
  `SemanticJudgeEvaluator`, so it stops the run the same way: the first version read it as an
  outage, and a refusing judge made every judged spec inconclusive and exited 0 without a word
  about the fix (29 refused judge requests in the pre-merge audit). The target's own error text is
  not quoted. The first version fired on any whole word `temperature`, `top_p` or `top_k` in the
  message (a moderation 400 quoting "the temperature of the room", a 400 naming only `top_k`);
* **resume:** declared, the capability is part of the target's digest, so adding it to the file of
  a halted run refuses the resume ("a different target"); left out, it is not (`shared.digest`
  drops `capabilities.sampling` when it is null, as it drops an absent `seeded_setup`), so every
  run stored before it keeps its digest. The run context records whether the live target and the
  judge were sent a temperature (`takes_sampling`, `judge_takes_sampling`, as resolved); a resume
  whose record differs from what this version decides (a run started before the record counts as
  sent, as every older version sent one) continues as it started when it keeps attempts
  (`wiring.with_takes_sampling`, for the adapters and the record only: the digest and the report
  keep the file as written), so one campaign is not half pinned and half unpinned, and is sent as
  this version decides when it keeps none; both said on stderr, and a record that is not a boolean
  is refused as corrupt. If the reference is right, an older run against a listed model stopped at
  its first request and kept nothing, so its resume sends no sampling; if a listed model did take
  the temperature, the run kept pinned attempts and its resume stays pinned. A run started by the
  first version of this clause (`7dd5ec1`, never released) recorded nothing and is read as pinned.
`tests/cli/test_models_without_sampling.py` (66 tests, through a loopback stub whose Anthropic
endpoints refuse any `temperature` or `top_p`, as the reference says those models do; the error
text is the stub's own) and `tests/adapters/test_sampling_refused.py` (21 tests, through respx):
63 and all 21 fail or do not collect on `00b2fca`, this branch's base (the 3 of the first that
pass there check that a non-boolean `sampling` is refused, which the base does as an unknown
key); on `7dd5ec1`, the first version, 18 and 17 fail (the 4 of the second that pass are 400s it
already left alone, and a request that sent no sampling). With the capability declared `true` on a
listed model, and with a model the list does not name, one request goes out and the refusal names
the fix; a refusing judge stops the run after one judge request; through `provider: openai` with
`sampling: false` the stub is sent no temperature; the probes, `dottore fingerprint`, an Anthropic
judge on a listed model, `--dry-run`, `-sn` and `replay` say it; `sampling_not_sent` lists the
block's fields on attempts and probes, a lone block `seed` included; the record of a run and
two resumes that continue as they started; the list is matched in both directions (34 ids);
the digest of a target that does not declare the capability is the one `00b2fca` computed.
Outside the clause, and said so rather than pinned:
* the HTML, SARIF and JUnit reports carry no run-level word for it; the JSON report carries it
  in each attempt's `request.metadata` and in the run's target (`capabilities.sampling` when
  declared);
* `top_k` is never sent by any adapter, so `sampling: false` has nothing to drop there;
* a model the list does not name costs one refused request before the operator declares the
  capability, and the list follows Anthropic's reference, not a call to the Models API.

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

**A-38 A CLI error names the operator's existing file, and reads the rest of the message as before
(added 2026-10-07).** Besides the existing part of an absolute path up to the first whitespace, a
quote, a bracket, a comma or a semicolon (main's rule, with main's `Path.exists` calls and no cap),
`_masked` keeps out of the entropy rule a path that exists written whole: absolute, or relative to
the working directory as one word; read directory by directory, so a directory holding a space or a
bracket is read whole; starting and ending between characters the entropy rule does not join into a
token, so every other token is judged exactly as before. Two kept parts that only touch are judged
apart. A kept text holding 8 consecutive characters of a registered credential prints as
`«REDACTED:credential»`, as every kept token does (§6), and a whole path holding one is not kept.
A report named after a commit SHA read `«REDACTED:high_entropy»` before a colon, relative, or under
a directory with a space, and `dottore diff` printed the key in an incomplete report's reason that
`calibrate` masked (audits of PR #61).
Three versions that kept more (the name an `OSError` quotes, the existing directories of a missing
path through a space, a `//` or a `/./`) printed keys that main masked and were withdrawn (OD-25;
pre-commit, delta and pre-merge audits). `diff`'s incomplete-report refusal goes through `_masked`.
The whole-path walk costs at most 1,024 filesystem lookups and 65,536 checks, and no walk starts
inside what another already read; main's rule walks each distinct token once and holds no path
between tokens (a 1 MiB message that cost 524,032 lookups costs 2,048; held, the paths took 1.3 GiB
where main took 21 MiB). Main's rule stopped at a cap printed a value main masked (audit of the
cap). Checked by `tests/cli/test_masked_paths.py`, and by a differential fuzz against main:
no key main masked printed, in 120,000 messages. Amended 2026-10-16 (A-83 item 5): the existing
part of a missing path is kept too where main's rule stopped short of it at a space or one of
`'"()[],;` in a directory's name, and nothing of a path holding `//` or `/./`; the rest is judged
from its `/` on, its token checked for a registered credential's part with the kept text.

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
  `true:` key as `1`), its control and format characters written out, as #51 writes them in every
  error (§6);
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
  `capabilities:` left empty by a lost indent) was still dropped without a word, and so was a
  `name`, `provider`, `endpoint`, `model`, `auth_ref` or `transport` that is not text: both are
  refused since A-53;
* a fleet entry's `capabilities` that is not a mapping, `null` included, was refused and still is,
  now in pydantic's words for a model (`Input should be a valid dictionary or instance of
  Capabilities`), where a target file reads `null` as none;
* what pydantic can read as a boolean is taken as read (`tools: 'off'` is false), as in A-45;
* an unknown key is printed as the location, as A-45 says of any key: one that is not text as
  pydantic renders it (`on:` as `1`, `off:` as `0`, `~:` as `None`), an empty key or one holding
  half a character (a lone surrogate) as `<root>` (the latter with `Input should be a valid
  string`), and control characters written out, as #51 writes them in every error (§6); a
  credential pasted as a key is masked as any error text is (a registered credential and the known
  key shapes first, then the entropy rule), and the entropy rule leaves a low-entropy one readable
  (about 1 in 20 random 64-hex keys, and the tests' repeated value);
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
an invocation fails it. 20 of its first 24 tests fail on `0501752`, and one of the two `--judge`
cases #66 adds fails without its room-check fix; the other four guard what did not
change (a campaign that recorded no planning mode may still drop `-sV` when the ceiling holds the
rest, and a resume refused for the wall-clock or the request ceiling leaves the journal as it found
it). Limits, written here rather than fixed in a test: the advice answers the check that refused, so
following "Resume with -sV" adds the probe pass, which a tight ceiling then refuses on its own (with
advice that goes through), and following "Resume without -sV, -A or --deep" under a ceiling that
does not hold the rest of the campaign halts (measured with 6 spent and 3 to send: at ceilings 6, 7
and 8), as any resume did on `0501752`; "whichever it ran with" asks the operator for what the run
store does not keep (one flag for the three); the advice reads the request axis only, so a campaign
halted on `--budget-tokens` is still told about requests, as on `0501752`; the estimate leaves out
retries (the multi-identity sweep was the other omission until A-34, u08, priced it; the check
subtracts a finished spec's sweep as `--estimate --resume` does), so a followed "drop -sV" at an
exact fit can still halt; with `--judge` the check takes off the judge's two requests for each
attempt the resume keeps of a spec that uses `semantic_judge`, as `--estimate --resume` does since
#66 (it priced the battery's whole judge share, so a "drop -sV" that fitted was not offered:
pre-merge audit of #66), and clamps the target's share and the judge's at zero each on its own, so
that one's surplus does not pay for the other's rest (`tests/core/test_authz_leak_corroboration.py`,
re-audit of #66); the test grammar does not read a piece written as a sentence of its own ahead of
the advice; the advice names `-sV` where the invocation said `-A`, which implies it; and the stored
mode is read by truthiness, as the planning-mode check reads it, so the advice and the check agree
on a value that is not a boolean.

The resume's pre-check writes its figures as the halt reason writes the figure that stopped a run
(#69, u08 A-6), with the same helper, `budgets.budget_figure`: grouped (`has already spent
123,456,789 of its 123,456,806-request ceiling, and -sV would send 18 more`), and from 10**18 as a
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

**A-53 A target file's top level holds only the keys its readers read, and text where they read
text; anything else is refused before anything is sent (added 2026-10-07; OD-31 decided).**
`load_target`, `target_uses_mock` and `load_mock_scenario` each took the keys they knew from the
file's top level with `raw.get(...)` and never looked at the rest, and `load_target` read a `name`,
`provider`, `endpoint`, `model`, `auth_ref` or `transport` that was not text as absent. So a
misspelled key was dropped without a word, and when it was the endpoint, or the endpoint was written
as a list, a live target had no endpoint and `target_uses_mock` sent the run to the offline mock: on
`2f6201a`, `run` of a live target with `endpont:` sent it nothing and scored the `bare` mock's
replies (one spec: inconclusive, exit 0; the full battery: a FAIL on `DOS-TOKEN-AMP-001` and a PASS
on `MCP-TOOLPOISON-001`, exit 1, as on `c3e70d8`), and its dry run said `authorized at` the scope's
base URL, with no word about the endpoint or the mock. A `capabilities:` whose children lost their
indent read as no capabilities with `tools`, `rag` and `memory` ignored at the top level: a `type:
model` target with all three planned 34 specs with 39 skipped for a capability, against 59 and 8,
and nothing named the keys. A model id YAML reads as a number (`model: 20240613`) was read as no
model. Now `_read_target_yaml`, which every reader goes through, checks the top level against
`_TargetFileTopLevel` and refuses, on one line in the A-45 form, `target file <path> failed
validation: endpont: Extra inputs are not permitted` (`model: Input should be a valid string`; a key
that is not text: `1: Keys should be strings`), never the value:
* the keys are the fields of `Target` (`id`, `type`, `name`, `provider`, `endpoint`, `model`,
  `auth_ref`, `capabilities`, `sampling_defaults`, `transport`, `command`, `seeded_setup` and,
  since #87 landed, `websocket`) and `mock_scenario`; the model is built from `Target`, and
  `_TEXT_FIELDS` is its `str | None` fields, so a field added there is a key the file may hold,
  as text when it is text, and a test checks that
  `load_target` hands every field of `Target` to it (a field it did not read would be accepted and
  dropped); another test passes each key through the check. The pre-merge audit found that a list
  kept by hand refused the `websocket` field #87 added: 35 tests failed on the two merged, none once
  the model was built from `Target`;
* `name`, `provider`, `endpoint`, `model`, `auth_ref` and `transport` are text (`StrictStr`, so
  `!!binary` bytes are refused too) or absent: the key with nothing after it, `null` or `~`,
  as before; an empty string is text, so `endpoint: ""` still routes to the mock; a number as
  `provider` or `transport`, which A-40 read as no provider (`5`, or one too long to write out),
  is refused as not text;
* every reader refuses a file this check refuses, with the same line, so `target_uses_mock` no
  longer routes such a file to the mock (a file `load_target` refuses for another reason, a bad
  `capabilities` say, is refused by `load_target` alone, which `run` and `fingerprint` call before
  they route); `dottore fleet` writes only these keys (a test runs it on both shipped fleets and
  loads what it writes).

`tests/cli/test_target_top_level_keys.py`: 43 of its 90 tests fail on `9b8b511`, this branch's base,
and so do A-40's two tests of a number as `provider` or `transport` in `test_huge_numbers.py`, which
expected exit 0 and now expect this refusal. Each fails on the old behavior (25 of the 43, and both
of A-40's, because the command exits 0; 17 because the reader does not raise; 1 because
`_TEXT_FIELDS` does not exist). Merged with #86 (A-51), two of its tests in
`test_operator_file_quoted_values.py` (a `provider` and `transport` that are integers, a `transport`
of aliases), which expected `target_uses_mock` to route the file to the mock, now expect this
refusal, still under A-51's bound (the value never written out), and the `provider` of aliases case
of a third, which measured only the memory, checks the refusal too. The other 47 guard what stays
(every legal key passes the check, a file with each key the manual lists loads, a null text field
is absent, `id` and `type` keep their own refusals) and that the redactor leaves each test value
readable, and one loads every target file
under `examples/`, `specs/` and `tests/` and every target block of the docs and man pages through
the three readers. Refusing is the owner's decision (OD-31), as the smallest reversible change: the
`_TargetFileTopLevel` check in `_read_target_yaml`, and the six `isinstance(..., str) else None`
reads of `load_target` and the `_lowered` reads of `target_uses_mock` (A-40) it made dead, which
come back with it. Outside the
clause, and said so rather than pinned:
* a misspelled value is still read as written, without a word: `provider: opnai` with an
  endpoint routes to the REST adapter (as the manual says of any provider but `openai`,
  `anthropic` and `mcp`), and a stdio MCP target, which has no endpoint, with `transport: stido`
  or `provider: mpc` runs on the offline mock, where the `mcp` suite's spec scores PASS with exit
  0 (measured here and on `2f6201a` alike): the outcome this clause closes for a key, left open
  for a value (closed for `provider` and `transport` by A-82, 2026-10-11);
* the keys inside a block are its reader's: a key `capabilities` does not know was dropped on
  `2f6201a` and is refused by A-50 since #78; `sampling_defaults` and `seeded_setup` already
  refuse theirs;
* `id` and `type` keep their own refusals, which quote what was written (A-45), and a file with
  an unknown key and no `id` is refused on the key;
* a key that only holds an anchor for a `<<` merge (`x-defaults: &d`, `.base: &b`) is a key like
  any other and is refused, though such a file loaded on `2f6201a`; a map merged inline (`<<:
  {...}`) still loads;
* a key is printed as the location, as A-45 says of any key: one that is not text as pydantic
  renders it (`on:` as `1`, `~:` as `None`, a `!!binary` key as `b'...'`, a number too long to
  write out as `<unprintable int object>`), an empty key, or one holding a lone surrogate, as
  `<root>`, its control and format characters written out since #51 (before, a line break in a key
  split the one line, and the second could start with anything), and a credential pasted as a key
  is masked only by the redactor's own rules;
* unknown keys are listed on the one line as `validation_problems` lists any block's problems
  since #76: the first 20, then `and N more`, each path cut at 300 characters (20,000 unknown keys
  give a line of 790 bytes for a file named `t.yaml`, where before #76 they gave 788,937 bytes in
  a 189 KB file);
* a run halted before this change with such a key resumes once the key is deleted (it was never
  read, so the target is the same: measured end to end, exit 0, still on the mock for a lost
  endpoint) and is refused as another target once the key is corrected to the one meant; that
  refusal's advice to restore the target as it was is followed by deleting the key, since the file
  as written no longer loads.

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
here, not tested. The path is absolute with no colon after it, so the CLI keeps it readable, a path
holding a space or one of `()[],;'"` too since #70 (A-38), which before cut it short
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
  different targets, quote the target ids and the spec id the reports hold; and a finding whose
  `spec_id` is not a spec id (#51) is refused as `the report <absolute path> holds '<id>', which is
  not a spec id; is this a run report?`, its control and format characters written out;
* a key a finding does not know is part of the place and goes through the CLI's redactor with the
  rest of the line: what the redactor recognises in it (an email, a known token format, a labelled
  secret, a run of high enough entropy) is masked, while a key of hex digits often is not, and the
  mask can take the `findings.0.` before it or the `: ` after it, while a short password-like key
  (`hunter2`) prints as written; it is printed as pydantic renders it, its control and format
  characters written out since #51 (before, a key holding a line break split the line), and cut
  past 300 characters since #76 (before, a key of 1 MiB printed 1 MiB);
* the finding that fails still builds all of its own errors before 20 are listed, as on the base
  (one finding with a million keys it does not have peaks over 1 GiB on both, by an amount that
  varies from run to run, and the base also printed 195 MB of error text);
* the wrapper that gives the index costs CPU on a valid report: 1.07 s against 1.00 s to load
  100,000 findings (best of 3), with the same peak memory;
* what pydantic can read is taken as read: `confirmed: "yes"` is true and `risk.impact: "2"` is 2;
* the labels file `calibrate` reads is not a report and keeps its own refusals.

**A-69 (u08's clause; this unit's half, added 2026-10-10, OD-41) The CLI says what the provider's
input filter refused, and does not call it a dead target.** A run whose every attempt the filter
refused is not `unreachable` (which means every attempt failed on transport or, since A-74, got a
reply that could not be read): the provider answered every request. It completed and exited by the
findings until A-79 (below), which makes it `filtered`, exit 3.
The terminal summary, under the coverage block (never silenced by `-q`), prints `Blocked by the
provider's input filter: <k> attempt(s) in <s> spec(s) never reached the model (<spec ids>); they
are inconclusive, not refusals by the model and not exploits` when `k` is not 0, and the `Not
exercised` line names the filter among its causes. A resume says how many of the attempts it keeps
the filter refused (`; <k> of them the provider's input filter refused, kept as blocked`) and does
not send them again; `--estimate --resume` counts them as done. The composition root's
`refused_request` (u09 A-67) reads a `ProviderFilterBlock` at any status, so the `-sV` benign
probe's failure is named `guardrail/guardrail_benign: ProviderFilterBlock`. Checked by
`tests/cli/test_provider_filter_campaign.py` and `tests/cli/test_input_filter_probe.py`.

**A-70 (u08's clause; this unit's half, added 2026-10-11, OD-42) The CLI never lets a reply the
provider's filter cut pass silently.** The terminal summary, under the coverage block (never
silenced by `-q`), prints `Cut by the provider's output filter: <k> attempt(s) in <s> spec(s) came
back cut or replaced (<spec ids>); the model may have written what the filter hid, so they are
inconclusive and need review, never a pass` and `Stopped by the provider's filter on a side it did
not report: <k> attempt(s) in <s> spec(s) (<spec ids>); inconclusive and need review, never a pass
(stop reason(s): <stops>)` when `k` is not 0, with `; a Bedrock guardrail reports the side when
guardrailConfig.trace is enabled` inside the bracket only when `guardrail_intervened` is among the
stops (it was printed for an Anthropic `refusal` with no usage too: pre-merge audit of `a55e953`,
M3),
and the `Not exercised` line names a stop on an unreported side among its causes. The exit code is
the findings', unchanged: `--fail-on` gates a `fail` only, and a spec with a cut attempt and no
fail is `inconclusive` (0 when nothing else trips the gate); a team that wants CI to stop on one
reads `summary.cut_by_provider_output_filter.attempts` from the JSON report. A resume says how many
of the attempts it keeps the filter cut or stopped (`; <k> of them the provider's filter cut or
stopped after the prompt, kept for review`), counted among the kept attempts only (a cut reply
stored without a verdict is sent again, and was counted as kept beside "will be sent again":
verification of `91845524`, finding 1), and does not send them again; `--estimate --resume`
counts them as done. `dottore replay` lists and counts them (u10). From a target file, the
providers whose stops are read are openai (Azure), anthropic and websocket: a `provider: rest`
target is the generic template, so Bedrock's and Gemini's shapes are library-only (u04). Checked
by `tests/cli/test_provider_output_filter_campaign.py`.

**A-72 (u06's clause; this unit's half, added 2026-10-11, OD-43) A target file may declare one of
its own granted tools not destructive, and the CLI shows it before anything is sent and refuses a
resume after a change.** `seeded_setup.granted_tools` entries are tool names, as before, or a
mapping `{name: <tool>, destructive: false}` that grants the tool and declares it not destructive
(`wiring._granted_tools`); `SeededSetup.not_destructive` holds the declared names, sorted. The
mapping holds `name` (text, not empty) and `destructive`, which must be the boolean `false`:
refused, naming the file and the entry (`'seeded_setup.granted_tools[<i>]'`) and never the value,
are a non-boolean (`must be false (a boolean), not str`; `int`, `null`: a scene's empty flag reads
as left out since the A-71 audit's M1, for packs written before the flag was checked, while this
entry is new and an empty `destructive:` in it is a declaration half written), `true` (a target file
may say its own tool destroys nothing; a spec's scene is where a tool is made destructive), any
other key (`unknown key(s) external; expected 'name' and 'destructive' (OD-43)`), a mapping without
`destructive` (a bare name is how a tool is only granted), a missing or empty name, one with a space
at either end (names are compared exactly, so it would declare a tool nobody calls), an entry that
is neither a name nor such a mapping, a declared name also mapped under `tools` ("only a tool the
deployment grants, outside every scene, may be declared not destructive"), and a declared name
granted twice. The keys of `seeded_setup` itself are unchanged, and so is A-53's top level: the
declaration lives on the grant. `--dry-run` and `-v` print, per target, ` operator: <tools> declared
not destructive by <target>'s target file (an operator declaration: seeded_setup.granted_tools,
OD-43); it clears tool_call's destructive check only, never for a tool of a spec's scene`, `-sn` the
same line indented under the target, both one line more per declared name no destructive verb is in
("the declaration changes nothing for it") and per declared name a verb is in that is not named like
a hand-off ("`<tool>`: declared not destructive over the destructive verb '<verb>' in its name and
not named like a hand-off (transfer_to_<agent>): no call to it is judged destructive, so make sure
it destroys nothing", the second look lint gives a scene's `destructive: false`), and per granted
name that is a selected spec's scene tool but for case or Unicode form, NFKC-normalized and case
folded ("`<name>`: granted[ and declared not destructive], and the scene tool '<scene tool>' of
<spec ids> differs from it only in case or Unicode form; names are compared exactly, so a call under
this name is the deployment's own tool there and that scene's word on its tool does not reach it:
make sure the two are not one tool", pre-merge audit of `ed381359`, L3), and the `-q` line of each
ends `, <k> tool(s) declared not destructive`. The terminal summary ends with `Operator declaration
(OD-43): <target>'s target file declares <tools> not destructive (seeded_setup.granted_tools); a
call to it was not judged destructive on <k> attempt(s) in <s> spec(s) (<ids>), each named in that
attempt's reasoning`. The run's integrity record holds the declaration (u10 half), and the target
digest holds it (u00 half), so a resume after a change is refused; when the stored and the current
declaration differ the refusal names them: `run '<id>' was made under another operator declaration
in its target file's seeded_setup.granted_tools: it declared '<tool>' not destructive and now
declares no tool (OD-43). It decides which destructive calls fail, so the two halves would be judged
two ways in one report. Restore the declaration as it was, or start a fresh run.` A run stored
before the record existed declared none and resumes without one. `dottore diff` reads a FIXED the
declaration may have made as `FIXED (operator declaration, OD-43)`, with a line naming those specs:
the current report has attempts of that spec the declaration changed (`Verdict.operator_cleared`),
or the two reports' summaries declare different tools not destructive (L2). Checked by
`tests/cli/test_operator_declaration_campaign.py` and the loader tests of
`tests/evaluators/test_operator_not_destructive.py`.

**A-74 (u08's clause; this unit's half, added 2026-10-11, OD-21; amended after the pre-merge audit
of `598f0858`) The CLI says how many replies it could not read, and a run that read nothing says
what to check.** The terminal summary, under the coverage block (never silenced by `-q`), prints
`Unreadable replies: <k> attempt(s) in <s> spec(s) (<spec ids>) got a reply that could not be read
as the provider's; inconclusive, never a pass: each keeps an excerpt for review under
request.metadata.unreadable_reply, and a resume sends them again` when `k` is not 0, and the `Not
exercised` line names such a reply among its causes. A run halted by the runner's stop prints
`error: run on <id> did not complete: aborted on UnreadableReplies: ...` through `for_terminal`, the
advice in it the adapter's own (an OpenAI chat completions URL and `provider: openai`; the Messages
API; the websocket block's paths; for a `provider: rest` target file, the generic template's `text`
and that a template is the Python API's, `cli.wiring.REST_TARGET_FILE_ADVICE`: it was told to check
a response template it cannot declare, LOW 2), and every report carries the state `aborted` with
that reason (exit 3). A run of fewer attempts that read nothing is `unreachable`
(`_unreachable_reason`): an attempt counts as unreadable by its verdict's reason or, without a
verdict, by the error's mark ` [unreadable_reply]` (`shared.unreadable`; it read the class name,
LOW 3); when every failed attempt is one, the reason reads `every one of the <n> attempt(s) got a
reply that could not be read as the provider's, so nothing was evaluated: <advice>. The first:
<error>`, the advice read from the attempt's `request.metadata.unreadable_reply`; with transport
failures among them, `failed on transport or (<k> of them) with a reply that could not be read as
the provider's`; with transport failures only, the reason is as before. A resume says how many it
sends again because they could not be read (`; <k> that could not be read will be sent again`,
LOW 1), and one that keeps none says so (`keeps none of the <n> attempt(s) it stored across <s>
spec(s) (none was answered, or failed in a way a retry would repeat)`; it said `keeps 0
attempt(s)`, verification of `07aa0b3a`, LOW 2). The report schema's `status` description names
`aborted` and the wider `unreachable`. Checked by `tests/cli/test_malformed_reply_campaign.py`.
**Amended 2026-10-11 after the audit of the scoring (LOW 1):** the note names each id it sends again
once, by the artifact that is its attempt (`shared.resend`, u08 A-74), and so counts what it keeps
(`blocked`, `trimmed`): it counted an id in every category one of its artifacts fell in, so an id
holding a reply stored without a verdict and that reply's unreadable re-send read `-1 that ended in
an environment error will be sent again; 1 that could not be read will be sent again; 1 answered but
not evaluated before the halt will be sent again`; it now reads
`1 that could not be read will be sent again` (`runner.unjudged_attempt_ids` reads the attempt too).
Checked by `tests/cli/test_resume_resend_scored.py`, failing on `de122e26`.

**A-79 (u08's clause; this unit's half, added 2026-10-11, the amendment to OD-41 and OD-42,
decided under the owner's delegation, best practice, revisable) A run the provider's filter
answered every time is not complete, and exits 3.** Until A-79 a run whose every attempt the
filter refused or cut was complete, every spec inconclusive, and exited 0: a fully filtered run
read green, and a target that wrote a filter's answer to every attack (Azure's 400 from any
adapter, an empty reply with a filter's stop) turned CI green with nothing evaluated (security
audit of 2026-10-11, MEDIUM 3: `JB-ROLEPLAY-001` and `PI-DIRECT-001`, 6 of 6 blocked, exit 0).
`_filtered_reason` (`cli/run.py`), read after `_unreachable_reason` for a target whose campaign
completed, makes it `filtered` when every attempt was refused, cut or stopped by the filter
(`blocked_by_provider_filter`, `cut_by_output_filter`, `filter_side_unknown` of
`shared.provider_filter`, by the verdict's reason) or got no reply that could be read, at least one
was the filter's, and none is a `fail` (a fail on a trace or on what came back was measured, and
decides). The run prints `error: run on <id> did not complete: every one of the <n> attempt(s) was
answered by the provider's filter[ or got no reply that could be read] (<k> refused by its input
filter, <k> cut or replaced by its output filter, <k> stopped by it on a side it did not report,
<k> failed before a reply could be read: the non-zero ones), so no reply the model wrote whole was
evaluated: the run measured the filter, not the model. To measure the model, run it where the
filter lets the attack prompts through; every such attempt is in the reports, none of them a pass`
through `for_terminal`, every report carries the state `filtered` with that reason, and the exit
code is 3 (A-9), as an unreachable target's. Every attempt, not a share: the share that settles a
spec (a pass needs more than half of its attempts) was the alternative, not taken, because it
would make a deployment whose filter refuses most of an attack battery, the filter working, an
error on every CI run, and a target that forges a filter's answer could stay under any share below
all. A partly filtered run keeps its exit code (the 8-of-14 run of A-69 still exits 0). The
report schema's `status` description names `filtered`. After the pre-merge audit of `a55710e9`:
when some attempts were not the filter's, the line adds the unreachable reason's advice for them,
`. The other <k> failed on transport: check the target file's endpoint, and that the target is
up. The first: <error>` (or, for replies it could not read, the adapter's own advice; LOW 1: 3
withheld and 4 transport failures were told only to find a deployment whose filter lets the
prompts through); the rule is `shared.provider_filter.filtered_run`, which `dottore replay`
applies too, one attempt per id, printing `run: filtered: the provider's filter answered every
attempt for the model (...)`, since the run store keeps no run state (LOW 5). A target file's top
level gains `filter_stops` (a `Target` field, so A-53's check reads it): for an `openai` or
`anthropic` target only, `[]` or the provider's own word, refused otherwise naming the file and
the field, never a value (`_filter_stops` in `cli/wiring.py`, which applies
`shared.filter_stops.target_filter_stops`, the rule the `Target` model applies to every other path
since the pre-merge audit of `10cb526b`, LOW; LOW 3, best-practice addition), and
`--dry-run`, `-v` and `-sn` print a `filters:` line for a file that declares it or a WebSocket
file's `response.filter_stops` (`_filter_stops_line`). For `[]` the line says what still reads:
`<id>'s target file declares filter_stops: [], so no HTTP 400 is read as its provider's filter and
a reply with text or a tool call is scored as the model's, whatever its stop; a reply with no text
and no tool call that ends on content_filter is still the filter's withheld one, never a pass`;
for an `anthropic` file the word is `refusal` and the HTTP 400 clause is left out, since that
adapter never reads one (pre-merge audit of `e1a8aacf`, LOW 4). Until the audit of `10cb526b`
(MEDIUM) it said every reply was the model's, and an empty `content_filter` passed
`PI-DIRECT-001` with exit 0 where the run without the declaration is `filtered`, exit 3. Checked by
`tests/cli/test_filter_stop_provenance_campaign.py` (44 tests; 40 fail on `de122e26`, 15 on
`10cb526b`, the auditor's d1 through the CLI for `openai` and `anthropic`, the plan line and the
model's refusals among them, and 7 on `e1a8aacf`: d1 with a zero-width space, a WebSocket turn
withheld after a blank delta through `execute_run` on `""`, `"  "` and a zero-width space, a
failed provider's lone error, the Anthropic plan line, and the plan line's new words, and 2 on
`3f7b1254`: harmful text in tag characters, undeclared and under `[]`, which the judge reads (6
requests, a fail that needs review, exit 0; `3f7b1254` never consulted it); the first
13: the two ways a run is filtered, an `openai` target's foreign stops, an `anthropic` target
answering Azure's 400, the judge's fail on cut text with and without `--include-needs-review`, a
WebSocket file's declaration and its refusal,
and three controls: a genuine Azure 400 on some prompts, a genuine Anthropic refusal before and
after output, the same text without a filter word; 9 fail on `de122e26`), and by the four tests of
`test_provider_filter_campaign.py` and `test_provider_output_filter_campaign.py` whose every
attempt was filtered, which now expect exit 3.

**A-78 (u01's clause; this unit's half, added 2026-10-11) The CLI masks the key formats last, and
refuses a credential under 8 characters before anything is sent.** `_masked` runs the late patterns
on each stretch of the message its entropy pass reads, after that pass, and keeps what it keeps (an
existing path, a carried digest, a spec file name) from them too: run over the whole message, as in
the first version of this half, they masked the UUID directory of an existing evidence root, which
`de122e26` printed as written (pre-merge audit of A-78, L5). Its two redactors run without them, so
`x_<key>` is masked as the token the entropy pass masks and a mask of a late type written in an
error is read as text, as before; without the UUID pattern its first redactor masks a number read
inside a UUID as `de122e26` did, so the paths left to keep are the same, and such a UUID in an error
shows as it did (one with no number in it is masked whole). `check_target_credential`, the
pre-flight of the target and the judge, refuses a credential shorter than 8 characters (a
`ValueError` with the adapters' message; not for a target the run routes to the offline mock, read
from the file it loaded, nor for a stdio MCP target), and `check_identity_credentials` refuses one
of a scope identity for each plan that sweeps identities, naming it, so `--dry-run`, `-sn` and
`--estimate` exit 3 as the run would; the first version checked the sweep's identities only at the
send, and its three pre-flight modes exited 0 for such a scope (L4). The stdio exemption asks for
`provider: mcp` as well as `transport: stdio` (`wiring._launched_locally`): only the MCP adapter
launches a local server, and an OpenAI target with that field passed the pre-flight and stopped at
the send (L4). `build_real_adapter` refuses it too; the identity sweep names the identity
(`live, identity 'second': the credential is shorter than 8 characters, ...`); and the judge raises
the adapters' `CredentialTooShort` rather than abstain, which made every judged spec inconclusive
and exited 0 without a word. Against a loopback stub on `de122e26` a 7-character key was sent with
every request, a judge's too (exit 0); now each case exits 3 with nothing sent. Checked by
`tests/cli/test_short_credential_cli.py` (17 tests, 14 fail on `de122e26` and 6 on `0b4b1f14`; the
2 of an offline mock failed on the first version of this half, which also read the target file
twice, breaking a piped `-t <(...)`) and `tests/cli/test_uuid_identifiers_readable.py` (4; 2 fail on
`de122e26` and 2 on `0b4b1f14`).

**A-80 A run checks its stores and its paths before it sends, and nothing but findings exits 1
(added 2026-10-12, CLI audit of `de122e26`; the stores' half is u10, the ledger's u08).**
Exit 1 means "findings below `--fail-on`", so a CI step that lets 1 through read a crashed scan as
a pass, and each of these crashed or misled after the traffic it could have refused before:

* **The run store.** A `--run-db` naming a directory, a file that is not SQLite or a path under a
  regular file, `replay --run-db <garbage>` (and `<directory>`, which warned and replayed without
  the manifest check), and some of several runs started together on a new store
  (`OperationalError: database is locked`: 5 of 6 in the audit, 1 and 2 of 18 in two
  re-measurements) ended in a traceback with exit 1, and with `-sV` the 18
  probes went out first: the store was first opened inside the per-target loop. Every mode checks
  both store paths read-only before anything else (`--dry-run`, `--estimate` and `-sn` included,
  which still write nothing); a sending run then opens the run store and proves each run's
  `attempts/` (and `probes/` with `-sV`) writable before its first request (`_open_stores`). The
  refusal is `error: cannot open the run store at <path>: <reason>` (exit 3); a sqlite3 error that
  reaches `run`, `fleet --run` or `replay` later is `error: the run store at <path> failed:
  <reason>` (exit 3). A lock another process holds is waited for in Python, 30 s in all, in tries
  of 0.1 s, so Ctrl-C and SIGTERM stop the wait at once (SQLite's own 30 s timeout slept in C and
  held them for about 32 s, pre-merge audit of `e6a1ab9b`, LOW 1); a wait past a second prints
  `note: waiting for the run store at <path>: another process holds its lock (up to 30 s; Ctrl-C
  stops the wait)` once per run and store (`cli.run.lock_waits_noted`, the callback the store
  layer is given; it was once per connection, so once per store operation, round-2 audit of
  `f51a7d07`, LOW 3), and one that runs out is `the run store at <path> stayed locked by another
  process for 30 s` (`cannot open the run store at <path>: another process held its lock for 30 s`
  when it is met opening the store), the store named once, mid-run included (u10's half).
* **The evidence root.** A `--evidence-root` that was a regular file was found by the first
  attempt's write, after its batch was paid for (125 requests, then `NotADirectoryError`, nothing
  stored, the requests counted against the resume's ceiling). It is `error: cannot write evidence
  under <root>: <reason>` (exit 3) before any send now.
* **Any exception no command handles.** The root group (`cli.app.OperationalErrorGroup`) turns it
  into exit 3 and one line, ``error: unexpected <Class>: <message> (an internal error, not a scan
  result; rerun as `dottore -v ...` for the traceback)``, the message through `_masked`; the
  traceback is printed only under `-v` (`dottore -v <command>`, or `run -v`, both counted flags),
  each line through `_masked`. The library's own errors are exit 3 too: `ClickException` and
  `FileError` (exit 1 by default) by class, as `UsageError` already was, and those of a click
  installed beside the vendored copy, which Typer does not catch and which only a plugin raises
  (read from `sys.modules` when one arrives; the CLI never imports that click, round-2 LOW 2),
  its `Abort` (`error: aborted`), and a `SystemExit` of 1, 2 or a text
  (`error: unexpected exit with status ...`; 0 and 3 up keep their code). A broken stdout pipe is
  exit 3 with `error: the output stream closed before the command finished (broken pipe)`, wherever
  it is met: in the command (the guard), in the root context's close callback, which reconfigures
  stdout and so flushes what was still buffered (`_restore_stream`), in rich, which answers it with
  `SystemExit(1)`, or around the root context, where help is printed and the library itself exited 1
  (`OperationalErrorGroup.main`, which also makes the library's `Aborted!` there exit 3); stdout is
  then pointed at the null device, so no later flush meets the pipe. The first version of this
  clause stopped at the guard, and the close callback's flush turned the 3 back into 1
  (`registry ls`, `lint`, `describe`, `coverage`, and a live scan with findings, which sent its
  requests and exited 1 with nothing said; pre-merge audit of `e6a1ab9b`, MEDIUM 2). Ctrl-C keeps
  its 130. `dottore lint` still exits 1 for lint findings, which are findings. This closes A-9 for
  the classes nobody listed: the handler tuples stay, and what they miss is no longer a
  traceback with exit 1.
* **The attempts ceiling.** A campaign of more than 20,000 attempts could never finish (no flag
  raised that ceiling); it is the request ceiling now (u08's half), and `--estimate` prints the
  ceilings, attempts included (`ceilings: <n> requests, <n> attempts (one per accepted request),
  ...`, one line per target when they differ), as the dry run's `budgets:` line does.
* **`--estimate -q`** printed nothing and exited 0. It prints one line, as `--dry-run -q` does:
  `estimate: <n> requests over <s> spec-runs across <t> target(s) at runs=<r>, ~<k> tokens`, then
  the judge requests, the `-sV` probes and what a resume already did when there are any.
* **A report never overwrites an input.** `-oJ scope.yaml -oH target.yaml` overwrote both with the
  reports. A report path is refused (exit 3, before anything is sent) when it is the `--scope`
  file, a target file, the `--judge` file, the fleet file of `fleet --run`, the run store or the
  `-wal`, `-shm` or `-journal` file beside it (by resolved path, so before the store exists too,
  for the path given and for the file a symlinked store names), or a file the spec loader read
  (`LoadResult.files`: each `pack.yaml`, spec and suite file and each media asset a spec inlined,
  checked once they are loaded, still before any send); an existing output is compared with each
  of them by device and inode, so a symlink, a hard link or another spelling on a case-insensitive
  volume is the same file. Every file under the spec path was protected at first, which refused
  the rerun of `run --spec-path . -oJ out.json` (round-2 audit of `f51a7d07`, LOW 1); before that
  the first version compared resolved paths with the spec roots, and
  `os.path.realpath` keeps the case it is given: `-oJ SPECS/attacks/AC-BFLA-001.yaml` beside
  `--spec-path specs` exited 2 and overwrote the spec on the macOS default volume, MEDIUM 1). A
  report inside a run directory of the evidence store (a directory under `--evidence-root` holding
  `attempts/` or `probes/`, or named after the run being resumed) is refused too: one written over
  an artifact made the next resume refuse the run as tampered (LOW 3).
* **One default spec path.** `fleet --run` read `specs/` in the working directory with no option
  to change it ("path not found: specs" anywhere but the repository root) and had no
  `--evidence-root`, `--run-db` or `-o*`. `run`, `fleet --run`, `registry ls`, `describe`,
  `coverage` and `render-media` read `wiring.default_spec_paths()`: `specs/` in the working
  directory when it is a directory, else the battery beside the installed package (a source
  checkout or an editable install; a wheel ships neither the battery nor the schemas), and say so
  on stderr when they fall back (`note: there is no specs/ directory here, so this reads the
  battery beside the installed package: <path> (pass --spec-path to read another)`). `dottore lint`
  does not fall back: falling back, it linted the built-in battery in a pack's own repository and
  printed "lint OK ... across 75 spec(s)", exit 0, over a broken spec of the pack (MEDIUM 3); with
  no path and no `specs/` here it refuses, exit 3, `error: spec path not found: specs. Pass the
  spec path to lint (dottore lint <dir>); ...` (the rule decided for this branch and
  `fix/cli-input-validation`, which keeps one refusal mechanism for missing spec paths). `fleet`
  takes `--spec-path`, `--evidence-root`, `--run-db` and `-oJ/-oH/-oS/-oX/-oA` with `run`'s meaning
  and, without `--run`, carries them into the `dottore run` line it prints. A spec path that does
  not exist is `error: spec path not found: <path>. Pass --spec-path <dir>; ...`, not "1 spec
  file(s) failed to load". Amended 2026-10-16 (A-84): the battery is inside the package, so a
  wheel has it too, and the note says `the built-in battery inside the installed package`;
  `specs/` here is still read whenever it is a directory, but at the root of this package's own
  checkout, whose `specs/` holds the unit contracts.

Checked by `tests/cli/test_run_store_errors.py` (36), `tests/cli/test_evidence_root_preflight.py`
(10), `tests/cli/test_attempt_ceiling.py` (12), `tests/cli/test_estimate_quiet.py` (2),
`tests/cli/test_report_paths_inputs.py` (19), `tests/cli/test_fleet_run_options.py` (13),
`tests/cli/test_broken_pipe.py` (9, each in a subprocess writing into a reader closed before it
starts), `tests/cli/test_guard_subclass.py` (30: the same exit codes through a subclass of
`OperationalErrorGroup` that overrides `main` and `invoke` and calls `super()`, the way another
root group composes with it, the group keeping no state; and the installed click's exceptions,
with the CLI run once with click made unimportable; and the classes Typer itself raises, through
real commands, caught as mapped) and `tests/store/test_store_open_errors.py` (19).

The classes the guard maps are found from Typer's public names, never from a private module of
it: `typer.Exit` and `typer.Abort`, which Typer catches, and `ClickException` and `UsageError` in
the ancestry of `typer.BadParameter`; a class that cannot be found fails the import. Looked up by
name in `typer._click.exceptions`, the `Abort` that Typer 0.27 moved to `typer.exceptions`
resolved to nothing and was quietly no longer mapped, so `Aborted!` exited 1 again on CI's Typer
0.27.3 (CI of #114). The suite passes on Typer 0.26.8 and 0.27.3.

**A-81 A resume is bound to the rules that judged its halted half (added 2026-10-12, CLI audit of
2026-10-11, H2; amended the same day after the pre-merge audit of `22269e0c`, and on 2026-10-13
after the second audit of `6de5780b`, deny by default).** A resume keeps the
attempts the halted half stored with the verdicts that half gave them, and judges only what it
sends. Nothing recorded which rules had judged the kept ones: the check bound the spec, target and
judge digests, the planning mode and `--runs`, and `--version` printed `0.1.0` on every commit.
Measured on `de122e26`: a run halted on `f12ba83` (`--spec PI-DIRECT-001 --spec SP-LEAK-001 --runs
2 --concurrency 1 --budget-requests 14 --judge ...`, against a stub that answers every request with
`finish_reason: content_filter` and a refusal text, and a judge that says `secure`) and resumed
with `--spec-path` at `f12ba83`'s specs kept 4 attempts judged `pass` by `f12ba83`'s rules beside 2
judged `cut_by_provider_output_filter` by OD-42's, and the summary said `Cut by the provider's
output filter: 6 attempt(s) in 2 spec(s) ... never a pass` and `replay` `6 of 10 attempt(s) the
provider's output filter cut or replaced`, although all 10 were cut. OD-16, OD-19, OD-21 and OD-41
are the same class.

* **A version of the rules.** `shared.judging_rules.JUDGING_RULES_VERSION` (an integer; `1` is the
  rules as of the merge that introduced the version) is bumped whenever a change can alter the
  verdict stored for an attempt: an evaluator, the combination rule (`shared.combination`), how a
  provider's stop reason, a filter block, an unreadable reply or an environment error is read (the
  adapters' reply mapping included), what the runner's `_evaluate` and the helpers it calls decide
  and note. A rule applied when a finding is scored from stored verdicts (the risk score, the band,
  confirmation, which copy of an attempt counts) needs no bump: a resume applies it to both halves
  alike. Neither does anything the other checks of A-24 bind (a spec's evaluator config is in its
  digest). `JUDGING_RULES_SINCE` is the day runs began to record their rules (version 1 took its
  value), the one place the docs name for it, and it stays when the version is bumped: every reader
  means that day (the refusal of a run that records no rules); a later version's day is its
  CHANGELOG line's (u08 A-85).
* **The code that judges, bound by its digest (deny by default).** `shared.judging_rules.
  judging_digest` is a SHA-256 over every file of the package but `ildottore.testing`, the one
  module `JUDGING_EXEMPT` names: Python sources normalized (comments, docstrings and blank lines
  left out by `tokenize` and `ast` positions, decorators kept; the same on 3.9, 3.12 and 3.14, CI
  runs 3.11), and the data files the package reads, byte for byte, chosen by suffix
  (`DATA_SUFFIXES`: `.yaml`, `.sql`, `.json`, `.j2`; a test checks that every non-Python file of the
  package has one), dotfiles and caches skipped. That is 171 files at landing (main at
  `a906cea9`): 165 of the 167 modules and 6 data files. It is computed from the installed package
  once per process (0.35 to 0.38 s on 3.12 and 3.14 and 0.74 s on 3.9, measured at landing over
  2.2 MB), recorded when a run starts (`context_json.judging_digest`, with each file's
  8-hex digest as `judging_files`), and a resume under another digest, or of a run that records the
  rules and no digest, is refused with no flag, naming both digests (carried by
  `cli.resume.ResumeRefused.digests`, so the error masking keeps them readable) and the files that
  differ, five at most. A package whose source cannot be read (a zip or frozen install) is refused
  at run start (`JudgingCodeUnreadable`, exit 3), never digested as nothing. So correctness does not
  depend on anyone bumping a version: a subclass override, a default, a decorator, the offline
  judge, a renderer and a module that does not exist yet are covered because nothing exempts them.
  **The exemption is proved, not claimed:** `tests/shared/test_judging_rules.py` checks that it is
  outside the import closure of the console entry point (`ildottore.cli.main`, which `dottore` and
  `dott` call) and that no covered module imports it by name (`import_module`, `__import__`). A
  module the entry point loads runs its top-level code in every run's process, so it is covered:
  the renderers, every command, `cli.app` and `cli.main`. **Decided, with the reason:** covering
  `cli.app` and `cli.main` means a resume across an edit of the help text is refused, which only
  happens across a code change, which deny by default refuses for nearly every other edit; leaving
  them out would leave an import-time side effect at the top of every run unbound. **Decided under
  the owner's delegation (best practice, 2026-10-13):** the first design listed the verdict code
  instead (an allow-list, `JUDGING_SOURCES`, with a walk of what each entry referred to), and two
  audits found verdict code it missed under an unchanged pin: four one-line edits (the pre-merge
  audit of `22269e0c`, H-1), then a default of the REST template no target file carries
  (`cli/wiring.py` builds `RestTemplate(path=...)`, every other field a default), a subclass's
  `filter_stops` override, the offline judge (`wiring.scenario_judge_adapter`; the audit measured
  33 of 75 specs turning from pass to fail when its hardened verdict was flipped) and a decorator,
  each reproduced end to end as a resume that mixed verdicts (the second audit of `6de5780b`). The
  third audit (of `1d3d65c7`) then found an import-time side effect in an exempt renderer
  (`cli/render.py` emptying `shared.provider_filter.FILTER_STOPS`, verdicts mixed) and a stray
  `.DS_Store` refusing every resume: hence the entry-point closure and the suffixes. Each of the
  auditors' mutations (a to j, the renderer side effects, a dynamic and a lazy import) now changes
  the digest, fails the pin and is refused by a resume (exit 3, 0 requests sent, the changed file
  named); a comment-only edit, a `.DS_Store` and a plain resume go through.
* **The interpreter.** A run records `python` (implementation and `major.minor`, as `CPython 3.14`)
  and a resume under another is refused with no flag: the standard library's regular expressions,
  JSON and Unicode tables read a reply too. The pydantic, httpx and websockets versions are recorded
  (`dependencies`), not compared.
* **The pin, for people.** The test pins the digest of each version, so a change to covered code
  fails it until the version is bumped (with its CHANGELOG line) or the same version is re-pinned
  with a reason. The pins are `PIN_HISTORY`, append-only, and frozen in
  `tests/shared/judging_pins.frozen`: the history must start with the frozen pins (at most one more,
  the pin being made), so an edit in place of a pin and `PINNED` together, which the second audit
  made and which passed, fails (MEDIUM 4). The test also checks that the current pin is the last
  line for its version, that versions run from 1, that a second line says `re-pin`, and that no
  code is pinned to two versions.
* **Plugins.** An evaluator a plugin registers (`dottore.evaluators` entry points) judges from
  outside the package. The run records those whose evaluator type a selected spec names
  (`evaluator_plugins`: `<name>=<object> (<distribution> <version>) sha256:<digest of its
  installed Python sources>`, sorted, masked with the fixed identity salt), so a change under the
  same version is caught, and a resume under others is refused, with no flag, naming both lists. A
  plugin no selected spec names decides nothing and is left out (MEDIUM 5: a resume was refused
  over one); a plugin that cannot be loaded is recorded, its type being unknown. Today the record
  is empty: a spec names a type of the schema's `EvaluatorType`, and a plugin may not reuse a
  built-in type (the registry refuses a duplicate).
* **Recorded when a run starts.** `context_json.judging_rules`, `judging_digest`, `tool_version`
  (the package that started the run, kept by its resumes) and `tool_versions` (every invocation's
  package, in order, appended as `mutator_orders`
  is). `dottore --version` prints `dottore <version> (judging rules
  <n>)`.
* **A resume under other rules is refused before anything is sent** (exit 3), older or newer,
  naming both versions, why and what to do: finish it with the version that started it, or start a
  fresh run. **A run that records no rules** was made by a version before the record (one from
  before `JUDGING_RULES_SINCE`) and is refused the same way, whatever its rules were. No flag waives
  it, `--resume-unverified` included, as for the target (A-24): what the report would publish is
  wrong, not unverified. `--dry-run --resume` and `--estimate --resume` refuse too. A record whose
  rules differ is refused for them first, before any other field is checked, so a newer run is not
  called corrupt over a field this version does not know (L-4); otherwise the rules are checked
  after the target id and the presence of the target digest, before the target digest's value,
  the judge, the planning mode, `--runs` and the battery: under other rules nothing the operator
  can restore makes the two halves one campaign. A version is written `v<version>`, and a stored
  one must have a PEP 440 shape (`store.run_sqlite.VERSION_SHAPE`), so it reads in clear through
  the error redactor whatever its shape: `1.2.3.4` was masked as an IPv4 address and `2026.10.12`
  as a phone number (L-5). `judging_rules` is bounded at 1,000,000.
* **Why not judge the kept replies again.** Checked first, as the better remedy: the stored replies
  are the redacted ones (DL2). Against the vulnerable mock, `SP-LEAK-001`'s failing reply is stored
  as `... Internal note (never disclose): «REDACTED:canary:…»_run-...` and
  `DL-SECRET-CANARY-001`'s as `... the stored API key: «REDACTED:labeled_secret:…»`: an evaluator
  that looks for the raw canary would pass both; no logprob is stored; and the judge would have to
  be asked again, which is traffic the resume did not plan. A re-judged report would be wrong in
  the direction that costs.
* **Landing.** Version `1` is the rules as of the merge that introduced it, whatever lands before:
  main was merged into the branch on 2026-10-14 (`d526747e`, five branches) with version 1
  re-pinned there provisionally, then again at landing on 2026-10-15 (`a906cea9`, the sixth),
  where `JUDGING_RULES_SINCE` took that day and the landing pin replaced the provisional one, in
  `PIN_HISTORY` and in the frozen file at the same place: the one pin replaced in place, since it
  never reached `main` and version 1 was unreleased. Nothing has to be listed: what landed before
  is covered by default.
* **Limits, said.** A version before this one does not read the record: it resumes a run this
  version started (mixing as before), and its rewrite of the context drops the record, so this
  version then refuses that run as an older one's. The package version is recorded, not compared:
  it said `0.1.0` across five changes of the rules, and a release that changes no rule must still
  resume.

Checked by `tests/cli/test_resume_judging_rules.py` (34: the record, `tool_version` kept and
`tool_versions` appended, older and newer rules refused naming both with nothing written, a run
with no record refused with and without `--resume-unverified`, exit 3 through the CLI for a resume,
`--dry-run` and `--estimate` with no part masked, a newer run refused for its rules over a field it
does not know, a selection key a later release adds left alone, eleven version shapes through the
error redactor, a corrupt stored version, an unshaped package version recorded as `unknown`, the
digest recorded, a resume under other code refused naming both digests in clear and with and
without `--resume-unverified`, a run with no digest refused, the plugins a spec names recorded and
a resume under others refused, only such a plugin recorded with its source digest and a change of
its code caught, no shipped spec able to name one, the changed files named (five at most), a
run under another interpreter refused, and `--version`) and
`tests/shared/test_judging_rules.py` (24: the pin, the history, the frozen pins, the exemption
outside the entry point's import closure and named by no dynamic import, every other file covered,
only the data suffixes the package reads, a default, the offline judge, a decorator, a runner
constant and a data file each changing the digest, a renderer's side effect too, a comment, a
dotfile or a stray file not, no source refused, the per-file digests, the cost, the
normalization).

**A-82 What the operator gives the CLI is a value the tool has, or it is refused before anything is
sent, naming the field and never a secret; and a check that checked nothing does not pass (added
2026-10-11, from the full CLI audit of `de122e26`, findings M4 to M9, L2, L4, L5, L7, L8 and L10;
amends u01, u02, u11 and u00 where noted).** Each item below was measured on `de122e26` by the
audit's harness (`scratch/audit-cli/`, `fuzz.py`, `fuzz2.py`, `fuzz3.py`, `stub.py`) and again on
this branch by `scratch/fixcli3/repro.sh`:

* **Usage errors (M7).** `dottore run --runs "$KEY"` printed click's `Invalid value for '--runs':
  'sk-ant-api03-...' is not a valid integer.` with the key in clear, and so did `-T`, `--rate`,
  `--timeout`, `--concurrency`, `--top-tests`, the `--budget-*` flags and `fleet --runs`: click
  printed the error before any of this tool's masking ran. `[project.scripts]` now points `dottore`
  and `dott` at `ildottore.cli.main:main`, which runs the command tree in click's non-standalone
  mode and prints the usage line, the help hint and `error: <message>` through `_masked`, exit 3;
  a bare `dottore` keeps printing the help with exit 3, `--help` and `--version` exit 0, another
  click error is printed masked, exit 3, an abort says `error: aborted`, exit 3 (A-80's closure of
  A-9, since the merge below; before it, its own code and 1), and Ctrl-C keeps 130. Typer's own
  exception hook (which can print a traceback's locals) is no longer on the console path. The
  in-process `app` is unchanged (A-80's `_click_errors_exit_3` sets the code). Every typed option of
  every command is tried with a key-shaped value, found by walking the command tree.
* **Credential variables (M4, M8).** `shared.credential_refs`: after `env://` a reference names an
  environment variable, `[A-Za-z_][A-Za-z0-9_]*` (POSIX's portable name), in a target file's
  `auth_ref` (`cli.wiring._check_env_reference`), a scope identity's (`policy.scope`,
  `_refuse_unnamed_variables`, u01's half) and a fleet's `api_key_env` (target and judge), refused
  without the value being quoted; `resolve_auth_ref` refuses such a reference built in code. A
  fleet `endpoint` with user info (`user:password@`) is refused before anything is written (it was
  copied into `base_url` in `scope.yaml` and into the target file). `env://NONE` is the one
  reference that names no credential: `resolve_auth_ref` returns `None` for it without reading a
  variable. A live `run` refuses, after the scope and credential authorization and before the
  resume block, the `-sV` pass and any traffic, a variable that is not set or holds only spaces:
  the target's `auth_ref`, the `--judge` model's when it is live, and each identity of the scope
  entry when it has two or more and a selected spec sweeps identities (`unset_credentials`), one
  phrase per variable (`target '<id>' auth_ref 'env://NAME' names the environment variable NAME,
  which is not set, so every request would go out without a credential; nothing was sent: <advice>`,
  exit 3); `fingerprint` refuses the same before its first probe. `--dry-run`, `--estimate` and
  `-sn` print it as a `warning:` on stderr and go on: the variable is the environment's, and a dry
  run on a machine without the key is how a pipeline is checked. Measured: `auth_ref:
  env://STUB_KEY_TYPO` against a loopback stub that answers 401 without a credential, dry run exit 0
  silent, run exit 3 `aborted on AdapterStatusError: ... non-retryable HTTP 401` after a request;
  now exit 0 with the warning, and exit 3 with the stub serving nothing. A target that takes no
  credential leaves `auth_ref` out; the examples' `env://NONE` in a scope identity keeps working.
* **Provider and transport (M5).** A-53's open item (a misspelled value): `provider` is one of
  `cli.wiring.TARGET_PROVIDERS` (`anthropic`, `mcp`, `openai`, `rest`, `websocket`) and
  `transport` one of `http` and `stdio`, read stripped and case-folded, refused when the file loads
  (`target file <path> has invalid provider '<value>'; expected one of ...`), and `stdio` is for
  `provider: mcp` only; an absent provider is still the REST adapter. `build_real_adapter` raises on
  an unknown provider instead of falling back to REST, and `dottore fleet` refuses one before it
  writes. Measured: `provider: skynet` on `/v1/chat/completions`, dry run exit 0 and three
  `{"prompt": ...}` bodies sent; a stdio MCP target with `provider: mpc` ran on the mock and passed.
* **Finite numbers (M6).** `Sampling` refuses a non-finite value however it is built
  (`allow_inf_nan=False`, u00's half), so a target file's `sampling_defaults` of `.nan` or `.inf`
  is refused (`'sampling_defaults' failed validation: temperature: Input should be a finite
  number`) where it loaded and reached the JSON report as bare `NaN` and `Infinity`; so do a
  fingerprint signature pack's centroids and weights and, built in code, a WebSocket block's
  `timeout_seconds` and `final_value` (the loader already refused those as values JSON cannot hold).
* **Spec paths (M9, L7; u02's half).** A search path that does not exist is `PATH_NOT_FOUND`, one
  that yields no spec and no suite file `NO_SPECS`, which names the YAML files in its
  subdirectories a loose tree does not read (a directory without a `pack.yaml` still reads its own
  `*.yaml` and `*.yml` only, docs/06 §2), and a loose tree that reads specs and leaves YAML below it
  gets the `FILES_NOT_READ` warning. `lint` exits 3 on either code (`cli.lint.EXIT_IO`), over 1;
  `run`, `registry ls`, `coverage` and `describe` refuse such a path (`a spec path gives nothing to
  <verb>: ...`, exit 3; `wiring.refuse_spec_paths_that_hold_nothing`), and `registry ls --suite
  nope` is refused as `run` and `coverage` refuse it. Measured: `lint sp` with the specs under
  `sp/attacks/` and no `pack.yaml`, `lint OK ... across 0 spec(s)` exit 0 (an invalid spec there
  included); an empty directory the same; `lint nonexistent` exit 1; `registry ls --spec-path
  nonexistent` and `coverage` of an empty path exit 0.
* **Collisions (L2; u02's half).** The loader records the file of each spec
  (`LoadedPack.spec_files`), `ID_COLLISION` names both files, and `run` refuses a spec id two
  loaded files declare, naming them, before anything is sent (`wiring.spec_id_collisions`); one file
  read twice (a spec path given twice, `specs` and `specs/attacks`) is no collision. Measured: the
  first file loaded won without a word, a `--spec-path` pack that redeclared a shipped id included.
* **Reports (L4, L5; u11's half).** `dottore diff` and `calibrate` read a JSON run report whose
  `schema_version` is `1` or `1.<minor>`, or a bare list of findings; one without `schema_version`,
  of another major version, a SARIF log and a document with no `findings` list are each refused on a
  line that says which (they were compared, and the SARIF log gave `error: 'findings'`).
  `report-1.0.schema.json` now constrains `run` (`run_id`, `targets` with `id` and `type`,
  `findings`, `summary`) and each finding (`definitions.finding`: `spec_id`, `target_id`, `status`,
  `risk` with its ranges and band, `confirmed`, attempts and evidence by what identifies them),
  types and values as the models enforce them and `additionalProperties` open, with the version
  note in its description; each of the 89 JSON reports the audit wrote with `f12ba833`,
  `6d5f7ae3` and `de122e26` validates (two kept as fixtures, `tests/fixtures/reports/`, the rest
  through `DOTTORE_REPORT_CORPUS`), and so does every report this build writes. `schema export`
  prints it (`--name report`, `reporting.report_schema`).
* **Versions (L7; u01's half).** A scope's `version` and a fleet file's are `1` or `1.<minor>`
  (`policy.scope.SCOPE_VERSION`); any text was read as this format.
* **Messages (L8).** A figure the tool prints is written with thousands separators (`-T`, the
  `--rate` and `--timeout` refusals, an integer a spec schema error opens with), which the redactor
  does not read as a phone number, and an `OSError` for a file name too long to open gives its
  length, not the name (`_masked`). The unknown-suite refusal has one wording
  (`flags.unknown_suite`), naming the resolved id only for an alias: after a name ending in
  `passwd`, `(resolved` read as the password of a label and was masked. `--timeout` is at least 1
  second and at most 86,400 (`MIN_TIMEOUT_S`, `MAX_TIMEOUT_S`; NaN and infinity refused); the
  per-attempt timeout raises `TimeoutError: no reply within the per-attempt timeout of <N> s`, and
  an exception with no message is written `<Class> (no detail given)` (`shared.error_text`, in the
  engine's attempt errors, the runner's abort reason and the adapters' last transport error):
  `--timeout 1e-300` ended a run `TimeoutError: ` with nothing after. `127.0.0.1`, one of the
  allowlist's own loopback hosts, is kept readable in a URL's authority (`_LOOPBACK_IN_URL`), unless
  a registered credential holds it.
* **Scaffolds (L10).** `new-spec --family` refuses a control or format character (Cc, Cf, Zl, Zp)
  and blank text, never echoing it, and writes any other value as a YAML string that reads back as
  written: a plain word as before, unless YAML 1.1 reads it as something else (`yes`, `null`,
  `123`, found by the self-review), which is quoted; nothing is created for a refused scaffold.

Tests (317 in 8 files after the three amendments below, one skipped without
`DOTTORE_REPORT_CORPUS`): `tests/cli/ test_usage_errors_masked.py`, `test_credential_variables.py`,
`test_provider_transport_values.py`, `test_non_finite_values.py`,
`test_spec_paths_that_hold_nothing.py`, `test_spec_id_collisions.py`,
`test_report_and_file_versions.py` and `test_cli_messages_read_right.py`; on `de122e26` 107 of the
135 in the five files that import there fail, and the other three import `shared.credential_refs`,
`shared.error_text` and `reporting.report_schema`, which `de122e26` does not have: with those three
added to it as this branch has them (the schema function reading `de122e26`'s own schema), 80 of
138 of their 182 fail (one skipped), so 245 of the 317 in all. Tests that pinned the old behaviour
now pin the new one: `test_real_target_routing` (an unknown provider routed to REST),
`test_commands` (an unknown suite listed nothing), `test_loader` and `test_pr45_followups` (a
missing path was a `PARSE_ERROR` and a warning), `test_audit_block6_cli_reports` (`--timeout`
wording) and the reports hand-built without `schema_version` in five test files, and
`test_authz_leak_corroboration` follows the reworded `env://NONE` comment of
`examples/scope.local.yaml`. Outside the clause, said rather than pinned: a literal key in a scope
identity's `auth_ref` is still loaded (it is refused when a target names it, and `vault://`
references stay a u01 shape); a target file's endpoint with user info is still read (its password
masked by value, SEC-02); `--rate inf` is still taken; a per-file read error in a spec tree
(permission, link loop) is still a `PARSE_ERROR`, exit 1.

Amended after the pre-merge audit of `f9dbed49` (2026-10-12), each its own commit:
* MEDIUM 1: the in-process `app` is a Typer subclass whose call runs `main()` (`app._MaskedTyper`),
  so a console script an older install generated (`from ildottore.cli.main import app;
  sys.exit(app())`, which `pip install -e` keeps across a pull) masks too: the audit's fuzz found
  60 usage-error cases leaking there and 0 through `main()`. `standalone_mode=False` keeps Typer's
  own call for an embedding caller, and `typer.testing.CliRunner`, which never calls `app`, is
  unchanged. The masking tests run through both entries and in a process of each kind, and no
  longer depend on the launcher's program name (LOW g: 10 of 23 failed under `python -m pytest`).
* MEDIUM 3 (pre-existing): a fleet `endpoint` whose query or fragment carries a credential (a
  parameter named like one, `?api_key=`, `#token=`, or a value or bare component the redactor would
  mask) or that `urlsplit` reads with no host (`https:/ops:<key>@host`, `https:\\ops:<key>@host`)
  is refused before anything is written, naming only a plain parameter name
  (`fleet._endpoint_holds_no_credential`); the docstring that said `_split` and `_scope_endpoint`
  refused such URLs was untrue and is gone. A query with no credential (`?api-version=...`) is kept.
* LOW a: `lint <path>` (its path findings, through `run_lint`'s `mask`), `describe <id>` and `schema
  export --name <name>` print what they echo through `_masked`. LOW b: the registry skips a second
  declaration from the same resolved file, so `lint sp sp` reports no `ID_COLLISION` (u02's half).
  LOW e: a file name too long to open is described by its length (`shared.files.read_failure`, in
  the scope and policy pack loaders and `_masked`): `--scope <5,000 digits>` printed
  `«REDACTED:phone»` twice. LOW f: the version refusals read `this build reads scope version 1:
  write version: "1.0" ("1" and "1.<minor>" are read too)`. LOW d: the report schema, the manual and
  u11 say a report written since `f12ba833` validates (a v0.1.0 report does not, as before). LOW h:
  `Sampling`'s docstring, the exported schema's description, is as before; the reason is a comment.
  LOW c: docs/06's provider sentence. The rerun of the audit's M7 fuzz found two more, fixed:
  `new-spec --stdout` printed a scaffold with any `--id` (a key included; only the written path
  checked its shape), and `--family <key>` printed the key into the scaffold: the id is checked on
  both paths, and a family the redactor would mask is refused, never shown (none of the 205 tags
  the shipped specs use is).
* `shared.credential_refs.unset_variable` takes the environment as an argument; the wiring passes
  `os.environ`, as it alone reads the environment.

Amended after the round-2 audit of `e1824e99` (2026-10-13, merge-ready, its LOWs fixed):
* LOW 1: `typer.main.get_command(app)()`, a parent group holding the command and `python -m typer`
  bypassed the masking, which lived in `cli.main.main` and a Typer subclass's call. The root
  command is `app._MaskedGroup` (Typer `cls=`): it masks a click exception in place where it
  raises it (`make_context`, `invoke`, `_mask_in_place`), so whoever prints it shows it masked,
  and run standalone it prints the plain usage block (`run_masked`). `_MaskedTyper` is gone;
  `pretty_exceptions_show_locals=False` keeps locals out of a traceback through Typer's hook.
* LOWs 2 to 4: `cli.key_shape` says what is shaped like a key: the redactor's credential formats
  (`redactor.credential_patterns`) or its entropy rule outside a hexadecimal id or a UUID, never
  its PII rules; and what names a credential: the whole name, normalised (decoded up to three
  times, stripped, `[]` dropped, camelCase split, case-folded), in `CREDENTIAL_NAMES`. A fleet
  endpoint is checked in its path segments and path parameters too. The audit's probe: all 32
  legitimate endpoints accepted (a tenant UUID, `proj_<hex>`, a hex trace id, `req_<hex>`, an
  email, `sort_key`, `session`, `max_token`, `use_auth` among them), all 35 hostile ones refused,
  nothing written or shown. `new-spec --family CVE-2021-44228` is accepted.
* LOW 5: a credential parameter is named as written (`FleetFileError.kept_names` keeps it through
  the CLI's mask: `'X-Amz-Credential'` read as high entropy), and a file name too long is `File
  name too long: a name of N characters` (it said `cannot read` of `-oJ`). LOW 6: `--spec-path`
  of a name no file system could hold is described by its length.
* Not fixed, said: a value of 8 to 64 hexadecimal digits, alone or after a short lowercase
  prefix (`ab_<40 hex>`, `req_<hex>`), and any low-entropy value, under a parameter name that is
  not a credential's (`?q=<hex>`, a path segment `/<40 hex>/`) is kept and written, since it
  cannot be told from a trace, request, tenant or account id; so is `new-spec --family <32 hex>`,
  written into the scaffold as asked, a hex id being no key.
* Embedding: a caller that takes the command (`typer.main.get_command(app)`) or holds it in a
  Typer group is supported. In a group of the installed `click` (not Typer's vendored copy),
  support is for usage errors only: the message is masked and its chained cause dropped, but that
  group does not catch the other copy's exception class, so it prints a traceback that ends on
  the masked message and exits with its own code; nothing else of this CLI's handling applies
  there.

Amended after the round-3 audit of `3321a786` (2026-10-13): `?<key>=1`, `#<key>=x` and `;<key>=x`,
refused at `e1824e99` and accepted by the round-2 rework, are refused again (a parameter name shaped
like a key, after the credential-name check); `CREDENTIAL_NAMES` gains application_key, app_key,
api_secret, oauth_token, oauth_signature, private_token, personal_access_token, sas_token,
x_goog_api_key, x_goog_signature, x_goog_credential, xapikey and xapi_key, accesskey, secretkey,
auth_key, authkey, hapikey, token_secret and passcode; and `_mask_in_place` clears `__cause__` and
sets `__suppress_context__`, so a group of the installed click no longer prints the raw
conversion error chained to a masked usage error.

Merge with `fix/cli-store-budgets-paths` (u12 A-80, which lands first), decided 2026-10-13 under
the owner's delegation (best practice), revisable:
* one root command class carries both behaviours: `_MaskedGroup(OperationalErrorGroup)`, which
  overrides only what masking needs and calls `super()` (an unexpected exception exits 3 on one
  masked line, its traceback only with `-v`, a broken pipe exits 3; a usage error is masked
  where it is raised);
* A-80's closure of A-9 decides the exit codes: `ClickException`, `FileError`, `Abort` and a
  stray `SystemExit` exit 3, and only lint's findings exit 1 (`run_masked` follows);
* one missing-spec-path mechanism, this clause's (`refuse_spec_paths_that_hold_nothing`, exit 3,
  `PATH_NOT_FOUND`), with A-80's wording (`spec path not found: ...`) when the path was the default
  one, and `lint` with no path and no `specs/` here strict (exit 3, never the installed battery);
  A-80's match on the text `path not found: ` goes once this mechanism covers its cases;
* `shared/models.py` keeps `allow_inf_nan=False` on `timeout_seconds`; `adapters/base.py`,
  `adapters/websocket.py` and `cli/wiring.py` keep both sides.

Merged 2026-10-14 with `fix/no-secret-in-fragments` (u01 A-77, `33782ad3`), which holds A-80
(`7cdd91a2`) and main `030b79e0` (u01 A-78, u04 A-78, u08 A-79), as decided above:
* `_MaskedGroup(OperationalErrorGroup)` is the root class; `run_masked`, `make_context` and `invoke`
  find the classes as A-80's guard does, from Typer's public names (`_typer_error`, `typer.Abort`),
  and this clause's lookup through `typer._click.exceptions` is gone: under Typer 0.27, which moved
  `Abort` to `typer.exceptions`, it let an `Abort` out of `run_masked` uncaught.
* `wiring.refuse_spec_paths_that_hold_nothing(..., default=True)` (no `--spec-path` given) says
  `spec path not found: <path>. Pass --spec-path <dir>; without it a run reads specs/ in the
  working directory, else the battery beside the installed package when that is a source
  checkout.` (`registry ls`, `describe` and `coverage` the same with their own way to pass one);
  `run` no longer matches the message's text, and `registry.PATH_NOT_FOUND_TEXT` is the one place
  that text is written. The loader's count of spec and suite files read is `spec_files_read`,
  beside A-80's `files` (every file read, a `pack.yaml` and a media asset included).
* u01 A-78's key formats widen `key_shape`: an Anthropic key (`sk-ant-...`) is now "a credential
  format", not "a high-entropy token"; a UUID stays an identifier (`credential_patterns()` leaves
  out A-78's UUID pattern, and `key_shape` reads the late formats through `without_entropy()`).
* A credential variable that is not set or holds only blanks is named by this clause's check
  (refused on a live run, a warning in a mode that sends nothing), not refused as a credential
  shorter than 8 characters (u04 A-78), whose pre-flight now skips it. u04 A-78's test of a
  `provider: openai` target with `transport: stdio` reads this clause's refusal of the file
  instead (M5): nothing is sent and no key is read.

**A-83 (this unit's and u01's, added 2026-10-16, the follow-ups the pre-merge audits of the train
of `de122e26` queued) Every text the CLI prints is masked as every other error is, a UUID
as the reports mask it, a path under a directory holding a space as one under any other, and an
exit whose code is no exit status is an internal error.** Seven items, each reproduced on
`7d01521f` before it was changed; u01's half (the redactor) is u01 A-83.

*1. The CHANGELOG.* The A-82 "Fixed" entry (CLI input validation) stated breaks in its body (a
click error and an abort exit 3, the report schema refuses a v0.1.0 report, `new-spec --family`
refuses a key shape) under a heading that named no reader; it now says "breaking for a CI gate, a
report checked against the exported schema and a `new-spec` call", with a bullet listing them.

*2. An exit code that is no exit status.* `run_masked` (A-82) read any code that was not an
integer as 0: a command raising `typer.Exit("<text>")` exited 0 with nothing said, where the tree
before A-82 (`d526747e`) exited 1 with the text in clear, as Python reads `sys.exit("<text>")`; a
bool exited 0 (Python reads `True` as 1), and a number past 255 reached `sys.exit`, which POSIX
cuts to its low 8 bits (256 is 0, a clean scan). Decided under the owner's delegation (best
practice, A-9), revisable: an exit status is `None` (0, as `sys.exit(None)`) or an integer from 0
to 255 (`cli.app._exit_status`); any other code is what no command of this tool raises, and 0 or
1 would read as a scan result, so it is said on the stray-exit line and exits 3, in `run_masked`,
in the root group's guard of a stray `SystemExit` and for a separately installed click's `Exit`.
Not taken: exit 1 for a text, Python's own rule (1 is findings below `--fail-on` here); keep 0
(a clean scan for an internal error); reading a bool as its integer (no command means one).
`tests/cli/test_exit_status.py` (42 tests, 26 fail on `7d01521f`): 15 codes through the console
entry point in a process of its own and through the test runner, typer 0.26.8 and 0.27.3.

*3. The stray-exit line, masked.* ``error: unexpected exit with status <code> (an internal error,
...)`` quoted the code raw since #114 (A-80): `SystemExit("<text>")` printed a registered credential
and a key in clear. A text code goes through `_masked` as itself and is then quoted; any other
code's `repr` does (`_say_unexpected_exit`; an unreadable `repr` is `<unprintable status>`). The
first version masked a text's `repr` too, which writes U+0000, U+0001, a newline and a tab as
escapes, so a registered credential split by one was text the redactor did not know and printed
whole: with U+0000 on `7d01521f` as here, with a newline as new on this branch, where main printed
nothing (pre-merge audit of A-83, MEDIUM 1). The four split forms are tested, as `SystemExit` and
as `typer.Exit` (8 cases, all fail on that version). A code that holds text but is none went
through `repr` still, so bytes with a NUL, a tuple with a newline and an exception with a tab
printed the split credential whole, as on main (round 2, LOW 1): bytes are read as Latin-1, a tuple
or a list as its items' texts, anything else as `str()`, the text masked and quoted, its type named
in front (`bytes 'halt «REDACTED:credential:...»'`); an integer or a bool is written as it is (3
cases, all fail on `85da7f8f`).

*4. A UUID in a CLI error.* The redactor masks a UUID whole (u01 A-78), but the CLI masks an error
in two passes, every rule but the entropy fallback first and the entropy fallback on what it does
not keep, and its first pass wrote the number rules' masks inside a UUID: `tenant
3f2a9c1d-6819-4748-9c2d-1234567890ab` printed `tenant
3f2a9c1d-«REDACTED:phone»«REDACTED:high_entropy:...»`, its first group in clear, and `tel +34 600
123 456` on the line before a UUID showed 7 of its
characters; a UUID no number rule reads was `«REDACTED:high_entropy:...»` where a report wrote
`«REDACTED:uuid:...»`. The two passes now share the redactor's stand-ins (`redactor.UuidCuts`,
u01 A-83): the first leaves them in its output, the second masks each UUID they are in whole with
the pieces main masked around it, as the redactor's entropy rule does, and any other as `uuid`
(`late=frozenset({"uuid"})`: `late` is a bool or a frozenset of types, never a string, whose
substrings a type test would match, LOW 4); the key formats still run after it, on what it
shows. What `_masked` keeps is
found with the stand-ins read back, so an existing path or a spec file name holding a UUID whose
groups a number rule reads is kept whole, as one holding any other UUID was since A-78 L5 (main
masked the number in it, so the path no longer existed). For 13 contexts of three UUIDs (digit
groups, all digits, none) the CLI's mask is the redactor's
(`tests/cli/test_uuid_in_cli_errors.py`, 45 tests, 36 fail on `7d01521f`). Not taken: reading the
first pass's stand-ins back as digits, which judged a token whole where main judged it in pieces
and showed a value glued before a cut UUID that main masked; typing every key format in the
entropy pass as a report does (`«REDACTED:openai_key»` where the CLI writes
`«REDACTED:high_entropy»`), which leaves a hex run inside a token-level JWT to a late pattern that
fails on the text when a letter outside ASCII follows (the reports have that gap, u01 A-83 *Not
covered*), so the CLI keeps masking the run.

*5. A path under a directory holding a space.* `_masked` keeps out of the entropy rule the part of
an absolute path that exists, read up to the first whitespace or one of `'"()[],;` (main's rule),
and a path that exists written whole (A-38). A missing file under a directory holding a space was
neither, so the entropy rule read every directory after the space with the missing name as one
token: with `TMPDIR` under "AI projects", 8 to 15 tests of the suite failed on `7d01521f`,
depending on the path (15 with this branch's, 12 with the auditor's; `cannot
write evidence under /Users/.../AI «REDACTED:high_entropy:...»: ... is not a directory`). The
whole-path walk now also reports the existing part of a path that does not exist, up to the last
name before a `/` that exists, a file's included, and it is kept when main's rule stopped short of
it at such a character in a name (`_whole_path_spans`). What follows is judged from its `/` on, as
main judges what follows the part it keeps, and the token there is checked with the kept text for
8 characters of a registered credential, which the pre-merge audit of A-38 found printed when that
token was judged alone
(`test_part_of_a_registered_credential_after_an_existing_directory_is_masked`).
A `//` or a `/./` in what main's rule would read of the path keeps nothing, and a `..` ends the
kept part: main's rule keeps nothing of such a path (`Path` drops the step, so no parent is a
prefix of the text), and kept, the existing part let 203 of 908 short names that main hid be
judged alone in the differential fuzz below. The name of a file that does not exist is judged as
text, as OD-25 decided. `tests/cli/test_paths_with_spaces.py` (32 tests, 21 fail on `7d01521f`):
each character main's rule stops at, eight names judged as under a directory without one, a key
as the name, a credential's part, the three steps, and the evidence-root refusal through the CLI.
`test_a_path_longer_than_path_max_is_not_walked` reads its token from a directory without a space,
which the cap it tests needs. Not taken: widening the entropy rule's path shape (`_PATH_SHAPED`) to
a name after `/_` or holding a capital, which would print every such token in every report too,
and no secret can be told from one by its shape; the filesystem says which directories exist.

*6. A message holding U+0000 or U+0001.* `_masked` runs its passes on the message read with them
dropped and with them made visible, and masks what either reading masks (`redactor.read_both_ways`,
as `redact_text` reads a text, u01 A-83): its entropy pass read only what its first pass gave it,
so the joined reading's glued tokens went unread. The cost to readability: an existing path written
right after a word a delimiter glues to it is masked with that word, as the joined reading reads
one token there (`abcdefgh\x00/usr/share/man/...` showed its directories on `7d01521f`); nothing
hidden shows (pre-merge audit of A-83, LOW 3). Its masks are placed back tolerantly (u01 A-83,
*Placing a reading back*): a later pass can rewrite an earlier one's mask, and placed strictly,
about 1% of the fuzz's messages were masked whole as `«REDACTED:fragment»`
(`tests/cli/test_masked_both_ways.py`, 5 tests).

*7. A credential as an endpoint URL's user.* A target file's endpoint registered its password for
masking by value (SEC-02) and nothing else, so a token written as the URL's user
(`https://<token>@host`, `https://<token>:@host`), which the HTTP client sends as Basic
credentials, was never masked by value: a reply quoting it kept it readable in the evidence and in
every report. `cli.wiring._endpoint_credentials` registers the password, or, when there is none or
it is empty, the user, each as written and percent-decoded (the value the client sends; a
`p%40ss` password was registered as written only). Beside a password the user is a name, which the
reports keep readable, as pip redacts a URL (`user:****@host`, but `****@host`). Against a loopback
stub echoing the credentials it was sent, through `run -oA`, 3 of
`tests/cli/test_endpoint_user_credential.py`'s 4 end-to-end cases fail on `7d01521f` (the password
case passes there too). Not covered: a user beside a non-empty password that is in fact the token
(`https://<token>:x-oauth-basic@host`, GitHub's form), and a user-only credential under 8
characters, which is not registered (the floor) and which the adapters, refusing a short password
(u04 A-78), do not refuse: refusing it would refuse `https://bob@host`. A consequence, found by
the pre-merge audit (MEDIUM 2): a user-only user info is the credential, so a target id holding
that user is masked in every report (`deploybot-prod` with `http://deploybot@host/...` reads
`«REDACTED:credential:...»-prod`), and `dottore diff` against a baseline written before refuses it
as another target (exit 3). Kept, as it fails closed; the CHANGELOG lists it as breaking (regenerate
such a baseline), and the MANUAL says a plain user name belongs beside a password or in
`auth_ref`.

*8. Two items found closed.* A run id of 12 decimal digits is drawn again (A-61, `new_run_id`),
and every exception class the package defines keeps its name through the redactor, a walk over
all of them (u01 A-63, `tests/policy/test_redactor_error_class_names.py`); both pass on
`7d01521f` and here.

*Measured.* The differential fuzz of `_masked` against `7d01521f`'s, in two processes on the same
messages (the A-78 auditors' grammar with paths under a tree on disk: directories with a space, a
bracket, a `_` after a `/`, a UUID whose groups a number rule reads; missing names of every shape;
registered credentials in 30% of the messages), three draws of 20,000: about 5,600 messages a draw
show a run of 8 characters that main hides. Each is shown by main itself on the same message with
every such directory replaced by a twin main's rule reads (no stop character, a UUID no number
rule reads), or by main's own report redactor (15), or is a documented key prefix before a
`hex_token` mask (2), which main's CLI prints too (`sk-proj-«REDACTED:hex_token»`); two more were
checked by hand: an `xoxe.` prefix the reports show too, and part of a registered credential
inside a path that main prints in the same path with another UUID. No message differs for any
other reason, and none is masked whole as `«REDACTED:fragment»`. Time: `_masked` on 20,000
messages without U+0000 or U+0001, 1.07 to 1.12 times main's (four measures, two before the last
fix); on the fuzz's messages, 9,889 of the 20,000 holding one, 1.8 times (two readings).

**A-84 The package carries what it reads, a refusal of an old path names the new one, and CI runs
the suite on the declared floors (added 2026-10-16, a follow-up of the audit train of `de122e26`;
ADR-0013).** The program read the built-in battery (`specs/pack.yaml`, `specs/attacks/` with one
audio asset, `specs/suites/`) and the attack-spec schema (`schemas/attack-spec.schema.json`) three
directories above the package (`cli/wiring.py:250`, `registry/schema.py:42`, `parents[3]`), the
repository root only in a checkout, and the wheel `pyproject.toml` selects (`packages =
["src/ildottore"]`) carried neither. Measured on `7d01521f`, a wheel built by that selection and
installed with `pip install --no-index --no-deps --target`, run from outside the checkout:
`registry ls` and `run --dry-run` exit 3 (`spec path not found: specs`), `lint <checkout>/specs`
exits 3 (`unexpected FileNotFoundError` on the schema). No job installed a declared lower bound:
every job installs the newest releases.

* **Inside the package, found one way.** The battery moves to `src/ildottore/battery/`, the schema
  to `src/ildottore/registry/schemas/attack-spec.schema.json`, as git renames; `specs/` keeps the
  unit contracts, and the three example files beside the battery move to `examples/`
  (`scope.example.yaml`, `fleet.example.yaml`, `target.example-openai.yaml`). One module,
  `shared/package_data.py`, finds both through `importlib.resources.files("ildottore")`
  (`BATTERY`, `ATTACK_SPEC_SCHEMA`, `wiring.PACKAGED_SPEC_PATH` is `BATTERY`), the same place for
  a source checkout, an editable install and a wheel. The hatch configuration does not change.
* **The default spec path, fail closed.** `specs/` in the working directory is read whenever it
  is a directory, as before (A-80), and refused, exit 3, when it holds nothing to read; with no
  `specs/` the built-in battery is read. The one exception is the root of this package's own
  checkout, whose `specs/` holds the unit contracts (`wiring.is_own_checkout`, by the checkout's
  shape: the battery at `<root>/src/ildottore/battery`, the working directory resolving to
  `<root>`, and `<root>/pyproject.toml`, a regular file read capped (a FIFO is never opened, round
  3), naming the project `ildottore`; the working
  directory at the battery's `parents[2]` alone was fooled by `pip install --target <dir>/deps`,
  which ran the built-in 75 from `<dir>` under a false note, round 2 of the audit, HIGH 1). The
  note says which (`there is no specs/ directory here` or `this is Il Dottore's own checkout,
  whose specs/ holds the unit contracts`, then `so this reads the built-in battery inside the
  installed package: <path> (pass --spec-path to read another)`), and with
  `GITHUB_ACTIONS=true` the same text follows as `::warning title=dottore spec path::`, the
  tool's own line, `%` escaped. Amended 2026-10-16 after the pre-merge audit (HIGH 2): the first
  build read a `specs/` with no YAML file as no `specs/` and scanned the battery in its place, so
  an empty `specs/attacks` beside a vulnerable mock exited 2 after 18 built-in specs and a `specs/`
  reaching its pack through a link exited 0 on all 75, where `7d01521f` exits 3; a default that
  swaps in another battery fails open. `lint` stays strict (A-80): with no path it reads `specs/`
  here only, so in the repository root it is a `NO_SPECS` error (exit 3, it exited 0 before) that
  names the battery's path. A name for the battery itself is OD-51.
* **An old path names the new one.** A path of the old layout is refused as before, exit 3, and
  the refusal adds `; it is now <path> (the built-in battery moved into the package)` (or `(the
  example files moved from specs/ to examples/)`; for a `specs/` that held the battery, `; the
  built-in battery it held moved into the package: it is now <path>`) when the new path exists in
  the same checkout (`shared.package_data.MOVED`, `moved_note`): the loader's `PATH_NOT_FOUND` and
  `NO_SPECS`, `shared.files.read_failure` (the scope file, a policy pack) and the CLI's text of a
  `FileNotFoundError` (a target file, a fleet file). The CI example of #118 (`--spec-path
  .ildottore/specs` on a checkout past this change) is refused that way. Nothing old is read in
  the new one's place, so what gates a pipeline never changes without a word.
* **The judging digest covers the battery.** Inside the package, the battery and the schema are
  data files of it (`.yaml`, `.json`), and `.wav` joins `DATA_SUFFIXES` for the audio asset: 264
  files where there were 171, 0.355 s against 0.378 s (Python 3.14, best of five). A resume after
  any byte of a built-in spec changed is refused, naming the file in clear (`ResumeRefused` carries
  the labels it names as `kept_names`, which the CLI's masking keeps, those this installation
  covers and those of the record shaped like a label; a battery label read as a secret in the
  first build, audit MEDIUM 1), where the spec digests forgive a description; a `--spec-path` pack
  stays bound by the spec digests alone. A run halted before this change is refused by a resume
  after it, as after any change of the code. No verdict changes, so `JUDGING_RULES_VERSION` stays 1,
  re-pinned with that reason.
* **CI.** Two jobs in `.github/workflows/ci.yml`, the existing two unchanged: `floors` pins every
  direct dependency (runtime and the `dev` extra) to the version after its `>=`
  (`scripts/dependency_floors.py`, which refuses a runtime dependency without a floor or with a
  specifier it does not read), installs with that constraints file on Python 3.11 and runs the
  suite; `package` installs hatchling and runs `tests/test_packaging.py`, which builds the wheel and
  the sdist, installs the wheel into a directory of its own and compares `--version`, `registry
  ls`, `schema export`, `run --dry-run` and the judging digest, from outside the checkout, with
  the checkout's (`DOTTORE_REQUIRE_HATCHLING=1` makes a missing backend fail there, never skip).
  Both pin actions by the major tag the existing jobs use (Dependabot keeps them current) and
  inherit `contents: read`. A scheduled run on the newest releases is not added: the PR jobs and
  ci.yml's weekly run already install them; what a schedule cannot fix is a PR failing for a
  release that is not in it, which is OD-49.

Alternatives not taken (ADR-0013): hatch `force-include` from the repository root (two places by
install kind, the `parents[3]` lookup kept for the checkout, and a judging digest that differs
between a wheel and its checkout); a symlink (no symlinks on a default Windows checkout); moving
`specs/` whole (it ships the contracts and moves the paths the method names); reading an old path
as the new one (silent); `uv pip install --resolution lowest-direct` for the floors (one more tool
in CI for what a 70-line script, tested offline, does).

Checks: `tests/test_packaging.py` (every file a load of the battery reads, and the schema, under
the package and bound by the judging digest, the selection and `.gitignore` able to drop none;
with hatchling, the real wheel and sdist), `tests/cli/test_battery_in_the_package.py` (the default
spec path, the repository root, each old path through the real CLI),
`tests/test_dependency_floors.py`, `tests/cli/test_resume_judging_rules.py` (a changed battery
file named in clear through the CLI), `tests/shared/test_protected_namespaces.py` (no model field
warns on the floor's pydantic: `WebSocketResponse.model_path`, which the `floors` job of #119 found
on 2.6.0, protects only `model_validate` and `model_dump`).
Both test files fail on `7d01521f`: `ildottore.shared.package_data` does not exist there.

**A-85 (u08's clause; this unit's half, added 2026-10-16, amended 2026-10-17).**
`JUDGING_RULES_VERSION` is 2, pinned by appended lines: a run halted under version 1 is refused by
its resume before anything is sent, naming both (`tests/cli/test_resume_judging_rules.py`, and
measured with a run halted on `7d01521f`), and `dottore --version` prints `dottore 0.1.0 (judging
rules 2)`. `JUDGING_RULES_SINCE` stays the day runs began to record their rules (the A-81 text
above says so). A scope with a weak identity canary exits 3 in every mode (u01's half), and
`dottore replay` marks a fail resting on a canary the request carries
(`tests/cli/test_scoring_followups_cli.py`).

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
- **OD-44** (2026-10-11): an MCP spec ran against any target, a chat model included. **Decided
  2026-10-11 under the owner's delegation (best practice, revisable), built.** This unit's half:
  the target loader (`wiring._mcp_capability`) sets `capabilities.mcp` when `provider` is `mcp`,
  refuses it declared `false` there, or `true` on a live target of another provider (the file and
  the field, never the value, as A-45), and lets an offline mock declare it; `dottore fleet`
  refuses `mcp` declared in an entry (`kind: mcp` makes an MCP server) before it writes, as A-50
  does an unknown key. The planner (u08) skips a spec that `requires: [mcp]` elsewhere; the dry run
  of `examples/target.local.yaml` plans 33 specs (34 before). Checks:
  `tests/cli/test_mcp_specs_need_an_mcp_target.py`. Alternative not taken: gate on `provider` in
  the planner directly.
- **OD-5** whether `--adaptive` defaults ON under `-sV`/`-A` or is opt-in (CLI mirrors engine
  default; propose opt-in for MVP‑1 to bound cost). **Decided 2026-10-11 under the owner's
  delegation (best practice), revisable: signed off as built**, no flag, `-sV`/`-A` imply
  adaptive ordering (see §4, `00-INDEX.md` and u08 §9, where the measured resume case and the
  alternatives are).
- Short alias `dott` alongside `dottore`: confirm both ship in `[project.scripts]` (propose yes).
  As built: both ship.
- `--compare` matrix output format for the terminal (propose compact table; JSON via `-oJ`).
- **OD-25** the name of a file that does not exist in a CLI error (a mistyped report named after a
  commit SHA): print it, or keep it masked. **Decided 2026-10-11 under the owner's delegation (best
  practice), revisable: kept masked, as built (2026-10-07, A-38)**, its existing directories printed
  up to the first whitespace, a quote, a bracket, a comma or a semicolon (since A-83 through such a
  character in a directory's name too, and none of a path holding `//` or `/./`). An error line
  reaches a
  terminal and a CI log, and a name given where a file belongs can be a secret pasted in the wrong
  argument: the redactor fails closed on a token it cannot tell from a key, and printing the name an
  `OSError` carries when it looks like a file's (an extension, a directory that exists) printed an
  `sk-ant-` key given as `<key>.json` and an Azure connection string in the pre-commit audit. The
  name is on the operator's own command line, so masking it costs them little. Not taken: print the
  directory and the extension and mask the stem unless it is a 40- or 64-hex run (a hex key typed as
  a path would then print); or print a name only when it is the command line's own argument (where a
  misplaced key sits). Reversing it widens `_whole_path_spans` in `cli/app.py` to a missing path's
  name; `tests/cli/test_masked_paths.py` pins the masking.

- **OD-20** (2026-10-07; **decided 2026-10-11 under the owner's delegation (best practice),
  revisable: escape it, built**): a JSON output printed to a CI log could still carry a runner's
  log command (`##[cmd]`, `##vso[`), because JSON keeps every value as it is (§6). Built: every
  JSON output writes the second `#` of `##<letters>[` as `\u0023` (`redactor.log_safe_json`,
  after `json.dumps` or pydantic's serializer): `lint --json`, `coverage --json`, `dottore
  fingerprint`, `schema export`, and the JSON and SARIF reports (`reporting/json_reporter.py`,
  `reporting/sarif_reporter.py`). Why: RFC 8259 §7 lets any character be written as `\u` and four
  hex digits, so every JSON reader parses the same value, and the output is safe wherever it is
  printed, which is the rule the text outputs already follow (the same `#`, written there as
  `\x23`); in a JSON text a `#` stands only inside a string and never right after an escaping
  backslash, so the rewrite touches nothing else. The cost: the bytes change where a value holds
  such a sequence (none of the shipped specs does), so a consumer that compares bytes rather than
  parsed values sees the escape. Not taken: A, leave it and tell the operator to write JSON to a
  file; B as first proposed, the `[` written as `\u005b`, equally lossless, but a second shape
  for one rule. Amended after the pre-merge audit of `598f0858`: the JUnit XML report follows the
  same rule (LOW 4), its `#` written `&#35;`, the character reference every XML parser reads as `#`
  (`ElementTree` writes a `#` only in text or an attribute value, where a reference is read), and a
  text with no `##` is returned as it is, unscanned (LOW 5). Not covered: the evidence store and the
  run store, the tool's own storage read back by `replay` and `--resume`, whose bytes are
  content-addressed and are not an output; the HTML report, a page for a browser, where a
  reference is not decoded inside a raw-text element (`<script>`, `<style>`). Reversal: drop the
  `log_safe_json` calls (seven, in `cli/app.py`, `cli/lint.py`, `cli/coverage.py` and the two
  reporters) and the `log_safe_xml` one (`reporting/junit_reporter.py`).
- **OD-23** (shared with u09, 2026-10-07): what `run -sV` / `-A` and `dottore fingerprint` do
  when one probe's reply comes back refused. Built reversibly as option A: the probe fails, a
  `warning:` line on stderr names it (never silenced by `-q`), the fingerprint line ends
  `[N of 18 probes got no usable reply]`, the run goes on and its exit is the attack's
  (`dottore fingerprint` exits 0 with the flag in its JSON, or 3 with an `error:` line when
  every probe was refused); before, exit 3 before any attack. A probe that gets no answer at
  all still exits 3 with its cause. Options, and why isolating every environment failure was
  withdrawn: u09 §9 and `00-INDEX.md`.
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
- **OD-31** (decided 2026-10-08 by the owner: refuse both, as built; A-53): whether a target file's
  top level refuses a key no reader reads and a `name`, `provider`, `endpoint`, `model`, `auth_ref`
  or `transport` that is not text, or keeps dropping them. Built: both refused before anything is
  sent, by every reader of the file. Alternatives: keep the silence (main until A-53: `endpont:`
  runs a live target on the offline mock and scores its replies); warn and go on (the warning goes
  where the run's output goes, and a CI log nobody reads runs on the mock just the same); refuse
  only the text fields that are not text and warn on an unknown key (an unknown key costs the same
  as a lost endpoint when it is the endpoint); accept a key that only holds an anchor under a prefix
  (`x-`, as Compose does). A file that loads on main and is refused now holds a key outside
  `Target`'s fields and `mock_scenario` (an anchor holder included), or one of those six fields as
  anything but text (a number, a boolean, a date, a list, a map, a set or bytes); no file of the
  repository does. Reversal: the `_TargetFileTopLevel` check in `_read_target_yaml`, the six
  `isinstance(..., str) else None` reads in `load_target` and the `_lowered` reads in
  `target_uses_mock`.
- **OD-39** (decided 2026-10-09 by the owner: apply it as a fallback; built, A-66): a target
  file's `sampling_defaults`, parsed and validated since #73 and #78 and applied to nothing.
  Decided: each field fills what the spec, the `-sV` probe or the judge leaves unset (the judge
  from its own file), sent where the adapter sends sampling (OpenAI; Anthropic without `seed`
  and with no `top_p` beside a temperature; a block `seed` only with `capabilities.seed: true`),
  recorded as sent, and a run started before it resumes without it. Alternatives not taken: drop
  the block (a file holding it refused or warned, as A-53 refuses an unknown key), or keep it
  parsed and unsent, as documented on `f12ba83`. Reversal: the `sampling_defaults` argument of
  `CampaignRunner`, `spec_sampling` and `fill_sampling` in `core/runner.py`, `sampling_fallback`
  in `cli/wiring.py` (the `fallback` half of `_AsSent`), the `apply_sampling_defaults` threading
  and the `sampling_defaults_applied` record in `cli/run.py` and `cli/resume.py`, and
  `tests/cli/test_sampling_defaults.py`; a run started with it then resumes with it unsent. The
  Anthropic rule (`sent_sampling`, the `sent_sampling` argument of `CampaignRunner`,
  `sent_sampling_for` and `_AsSent`'s `wire`) is a fix of its own and stays: without it a spec
  that sets `top_p` stops an Anthropic campaign, block or no block.
- **OD-37** (shared with u04; decided 2026-10-11 under the owner's delegation (best practice),
  revisable; built): `dottore fleet` refuses a WebSocket target entry, a `ws://` or `wss://`
  endpoint or `provider: websocket`, before it writes anything (exit 3), so it never writes a
  target file `run` refuses; until then it wrote `provider: rest` for a `wss://` endpoint. A
  WebSocket `judge:` block is accepted only with a matching hand-written `--judge` file, and no
  `judge.yaml` is written for it; without `--judge` it is refused. The reasoning, the
  alternative not taken (a `websocket:` block in a fleet entry, checked by `_websocket_spec`
  before writing) and the reversal are in u04 §9. Checked by `tests/cli/test_fleet_websocket.py`
  (20 tests: 16 of the first 17 failing on `6d5f7ae`, the 3 for a `--judge` file failing on
  `be3f2e71`).
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
- **OD-22** (shared with u02, A-33; decided 2026-10-11 under the owner's delegation (best
  practice), revisable: kept as built). This unit's half: `dottore run` refuses the run before
  anything is sent when a selected spec writes a regex that does not compile (exit 3, naming the
  spec and its first such pattern, a resume included), in `cli/run.py` (`_execute_run`, the
  `uncompilable_patterns` step). The lint code is u02's (u02 §9, `00-INDEX.md`).
- **OD-26** (shared with u01, A-43; decided 2026-10-07 by the owner). This unit's half: the
  commands read the scope, target, fleet and labels files up to 1 MiB, and `dottore fleet`
  refuses to write a file over the cap. Open, as the index says: the report JSON `dottore diff`
  and `calibrate` read (`cli/diff.load_findings`) and the evidence artifacts `dottore replay` and
  `run --resume` read are still read whole (u01 §9).
- **OD-27** (shared with u01, A-57; decided 2026-10-07). This unit's half: a scope or target id
  and an identity name of more than 128 characters are refused when the file is loaded, so no
  command prints a longer one (u01 §9).
- **OD-33** (shared with u01, A-56; decided 2026-10-07 by the conductor, confirmed by the owner).
  This unit's half: `dottore fleet` refuses two ids that differ only by case on every file
  system, so it never writes one `target-<id>.yaml` over another (u01 §9).
- **OD-46** (shared with u01; numbered 2026-10-12; open, owner to decide): a flag that loads a
  policy pack. No command calls `policy.packs.load_pack`, so the 8 specs that declare
  `requires_policy` never send from `dottore`, and OD-11 ties `--allow-pii-elicitation` to this
  flag. Recommended: one `run` option that loads a pack through that loader, printed in the plan
  and recorded with the run, landing with OD-11's flag (`00-INDEX.md`, `docs/12`).
- **OD-49** (shared with u14; numbered 2026-10-16, A-84; open, owner to decide): pin the
  dependency set the PR jobs install, and move the newest-release run to a schedule. Every job
  installs the newest release of every dependency (no lock file), so a release breaks the next PR
  whatever it changes: the train broke twice on typer 0.27.3 the day it came out. A-84 adds the
  `floors` job and leaves the existing jobs as they were. Recommended: a constraints file for the
  PR jobs (`pip install -c`, generated from `pyproject.toml` and bumped by Dependabot, whose pip
  ecosystem already runs weekly), plus a scheduled run with no constraints that installs the
  newest releases and reports a break the day it lands, as `audit.yml` does for regressions.
  Trade-off: an operator installs the newest releases, and a lock delays CI seeing what the
  operator sees until the scheduled run, a day at most. Alternatives: keep as is (a PR can fail
  for a release that is not in it); a lock file with hashes (`pip-compile --generate-hashes`),
  stronger supply-chain evidence for one more tool (`SUPPLY-CHAIN.md` notes no lock file).
- **OD-51** (numbered 2026-10-16, A-84; open, owner to decide): a name for the built-in battery on
  the command line, `--spec-path builtin`. With no `--spec-path` a command reads `specs/` when the
  working directory has one, and the battery otherwise, so a pipeline run from a repository that
  keeps a `specs/` of its own (OpenAPI files, say) cannot ask for the battery by name: it is
  refused (exit 3) or has to pass the battery's installed path. Recommended: a reserved
  `builtin` value of `--spec-path` (a directory literally named `builtin` then needs `./builtin`),
  printed as the battery's path in the plan and the note, and used by the CI example. Not built in
  A-84: a new public spelling deserves its own decision. Alternatives: a `--builtin` flag; leave
  the default as the only way.
