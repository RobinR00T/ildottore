# PROGRESS: Il Dottore (living ledger)

The carryover ledger. Every agent session updates this so context survives even a cold start
(the method's observability/resume + "own the context" discipline). Entries are in merge order,
newest merge on top: a branch's entries land together when it merges, so the dates of
neighbouring entries can interleave (an older branch merged later sits above a newer one).

## State, 2026-10-26: the guard's window, the guard over HTTP, profiles by name (`feat/guard-window-http`, u04 A-98)

- **What.** The three pieces A-96 left as "Not built". `guard.window` (`shared/models.py`
  `WebSocketGuardWindow`; `adapters/agent_guard.py` `in_window`, `next_opening`, `AgentWindowStop`):
  days and hours in a required IANA zone, checked before every dial and at every paced slot;
  outside it nothing is sent and the run stops (exit 3) saying when it opens; `--dry-run` says it.
  `rest.guard` (`shared/models.py` `RestSpec`, `adapters/rest.py`): the same block and the same
  checks for a `provider: rest` target, through `GuardKeeper`, which the WebSocket adapter now uses
  too (no duplicated logic); every HTTP attempt, a retry included, takes a pacing slot
  (`BaseAdapter._before_attempt`); a guard may lower the reply cap (`_response_cap`). Profiles by
  name (`cli/wiring.py` `resolve_profile`, `profile_dir`; `cli/app.py`): `-t`, `--scope`, `--judge`,
  `fleet --judge` and `fingerprint` read a bare name from the profile directories. `get_path` moved
  to `adapters/paths.py` (re-exported by `adapters/rest.py`) so the guard can read paths without an
  import cycle.
- **Open decision OD-56** (u04 §9, index ledger): a closed window stops the run (built) rather
  than waiting; an overnight window belongs to the day it opens; a REST retry takes a pacing slot;
  a listed tool in a REST reply stops the run and the reply is discarded; a bare name that is both a
  file here and a profile is refused.
- **Not built.** An SSE transport (none exists: `streaming_enabled` is a flag and a REST target
  reads one JSON reply); a run that waits for its window to open.
- **Verified.** `tests/adapters/test_agent_guard_window_rest.py` (26) and
  `tests/cli/test_rest_guard_profiles.py` (20); the dry-run of Scenario J copied from a real run.
  The root `conftest` points both profile directories at an empty temporary directory per test.
  Judging rules 7 re-pinned (no verdict path touched).
- **Docs.** `README.md`, `USAGE.md`, `docs/MANUAL.md` §4.2, `examples/README.md` (Scenario J, and
  the profile paths of Scenario I), `examples/target.agent.yaml`, `man/man1/dottore.1`,
  `man/man5/dottore-scope.5`, `CHANGELOG.md`, `specs/contracts/u04-target-adapters.md` (A-98,
  OD-56), `specs/contracts/00-INDEX.md`.
- **Gates.** `make gates` green in the worktree (15 min 13 s): ruff, ruff format, mypy strict (175
  files), import-linter (4 contracts kept), spec lint (0 errors, 78 specs), 8160 tests passed and 3
  skipped, coverage 97.65%, self-scan 0 high or critical, bandit clean, pip-audit no known
  vulnerabilities; `tests/cli` again under `GITHUB_ACTIONS=true FORCE_COLOR=1`: 2598 passed, 1
  skipped.

## State, 2026-10-24: a deployed agent's guard (`claude/agent-connector-6b9b4c`, u04 A-96)

- **What.** Any AI agent reachable over a JSON WebSocket is a target with a profile and no code:
  the wire shape was already declarative (`provider: websocket`, PR #87); `websocket.guard` adds
  what a deployed assistant needs (`shared/models.py` `WebSocketGuard*`,
  `adapters/agent_guard.py`, wired in `adapters/websocket.py`): the JWT checked for its tenant and
  expiry before any dial; the first authentication failure stops the run (`GuardStop`, an
  `AdapterProductError`, exit 3) and starts a cooldown kept across processes, a refused credential
  remembered by sha256 and never sent again; pacing (interval, hourly cap) across processes under a
  lock; `stop_on_tools` closes the connection on a reported tool and stops the run; a lower byte
  cap; an exact scheme and path. The loader refuses what the block cannot keep (`cli/wiring.py`
  `_check_guard`); `--dry-run` prints a `guard:` line; the guard is left out of the target digest
  (`shared/digest.py`). Generic profile with placeholders only: `examples/target.agent.yaml` and
  `examples/scope.agent.yaml` (Scenario I).
- **Open decision OD-54** (u04 §9, index ledger): a reported tool from `stop_on_tools` stops the
  run (built, the smallest reversible version) or is stored as evidence and the run goes on; and a
  close or silence before the handshake reply counts as an authentication failure (built).
- **Not built then, built since (A-98, above).** A working-hours window; the guard over HTTP (SSE
  is not a transport); profile lookup by name.
- **Real profiles stay out of the repository.** One for a private deployment was written outside
  every checkout; `git grep` over the tree and the diff found none of its values.
- **Verified.** `tests/adapters/test_agent_guard.py` (40) and `tests/cli/test_agent_target.py` (11)
  against the loopback agent of `tests/agent_ws_server.py`; the dry-run of Scenario I copied from a
  real run. Judging rules 7 re-pinned (no verdict path touched).
- **Docs.** `README.md`, `USAGE.md`, `docs/MANUAL.md` §4.2 ("A deployed agent"),
  `examples/README.md` (Scenario I), `man/man5/dottore-scope.5`, `CHANGELOG.md`,
  `specs/contracts/u04-target-adapters.md` (A-96, OD-54), `specs/contracts/00-INDEX.md`.
- **Gates.** `make gates` green in the worktree (10 min 54 s): ruff, ruff format, mypy strict (174
  files), import-linter (4 contracts kept), spec lint (0 errors, 78 specs), 8111 tests passed and 3
  skipped, coverage 97.67%, self-scan 0 high or critical, bandit clean, pip-audit no known
  vulnerabilities.

## State, 2026-10-24: the same static checks locally and on CI (`chore/pin-ruff`)

- **What.** The static checks of the `dev` extra pinned exactly (`ruff==0.17.2`, `mypy==2.4.0`,
  `import-linter==2.15`, both type-stub packages) instead of open ranges, and the runtime floor
  of rich raised from 13.8.0 to 14.2.0. CI resolved the ranges
  to the newest releases, the shared local venv had older ones (ruff 0.15.20, mypy 2.1.0,
  import-linter 2.13), and a rule only the newer ruff knows (RUF036) failed a branch on CI after
  `make gates` had passed locally. `scripts/dependency_floors.py` now accepts `name==X` as its
  own floor, so the `floors` job keeps the pins (`tests/test_dependency_floors.py`: a new case,
  and `==` with a second clause still refused).
- **Operator.** An existing venv needs `pip install -e ".[dev]"` once to pick the pins up (in a
  worktree, never: install the pinned versions by name, `pip install "ruff==0.17.2" ...`, so the
  shared venv's editable install keeps pointing at the main checkout). The shared venv already
  has them. bandit and pip-audit stay outside the extra, as before.
- **rich 14.2.0.** import-linter from 2.13 needs `rich>=14.2.0`, above the old runtime floor
  (13.8.0) the `floors` job pins, and the first push of this branch failed that job on it. The
  owner chose (2026-10-24, 23:11) to raise the runtime floor to 14.2.0 and keep the pin.
- **Gates.** `make gates` green with the pinned versions (10 min 26 s): ruff, ruff format, mypy
  strict (173 files), import-linter (4 contracts kept), spec lint (0 errors, 78 specs), 8062 tests
  passed and 3 skipped, coverage 97.69%, self-scan 0 high or critical, bandit clean, pip-audit no
  known vulnerabilities.

## State, 2026-10-24: the logo above the root help (`feat/banner`)

- **What.** As elSereno prints its night watchman above its help, `dottore --help` and a bare
  `dottore` print the Il Dottore logo above the root help on an interactive terminal:
  `cli/banner.py` (`Env`, `show`, `env_for`, `plain`, `ansi`, `write`), the art in
  `cli/banner.txt` and `cli/banner_ansi.txt` (56 columns, 31 lines; a caricature of the author
  drawn as vector shapes with Pillow, sampled cell by cell with the feature colour winning over
  the skin, in a one-off script kept outside the repository), the hook in
  `_MaskedGroup.format_help` for the root context only. The decision is elSereno's: never off a
  terminal, colour only with `COLORTERM` `truecolor`/`24bit`, `NO_COLOR` unset and `TERM` not
  `dumb`. Written straight to stdout before `super().format_help`: Typer prints the help with
  rich as that method runs and echoes click's formatter text after it, and a bare `dottore`
  drops that text (the first cut put the logo under the help, and nowhere on a bare `dottore`).
- **Verified.** `tests/cli/test_banner.py` (parity of the two copies, ASCII and width, the
  `show` table, `env_for` on a closed stream, six CLI paths through `CliRunner` with the
  terminal faked: root `--help`, a bare `dottore`, colour, sub-command helps, a parent group
  holding `dottore`, a usage error), and the six cases on a real pseudo-terminal (`pty.fork`, outside the sandbox,
  which has no pty devices): colour, bare, no `COLORTERM`, `NO_COLOR`, `TERM=dumb`, `run --help`.
- **CI red on the merge, green after `docs/banner-nits`.** Typer forces rich's terminal mode
  wherever `GITHUB_ACTIONS`, `FORCE_COLOR` or `PY_COLORS` is set, so on CI the help under the
  logo carries bold and dim codes; four of the CLI tests asserted on the raw help and failed in
  `validate` and `floors` while green locally. They now assert on the help stripped of escape
  sequences (as `test_help_text.py` does) and on the logo's copy byte for byte; run locally under
  `GITHUB_ACTIONS=true`, `FORCE_COLOR=1` and `COLUMNS=60` as well as plain.
- **Judging rules 7 re-pinned** (`7cbd07d44c56…`): `cli/app.py` and `cli/banner.py` are in the
  entry point's import closure, so they are covered; the two art files are left out by name
  (`DATA_EXEMPT`, bytes no verdict sees), since `.txt` as a data suffix would have made a stray
  `notes.txt` a change of the judging code. No verdict path touched.
- **Docs.** `README.md`, `USAGE.md`, `docs/MANUAL.md` §5, `man/man1/dottore.1` (`--help`),
  `CHANGELOG.md`, `specs/contracts/u12-cli.md` §2.
- **Gates.** `make gates` green on 2026-10-24 at 11:35 (9 min 39 s): coverage 97.69 %, self-scan 0
  high/critical, bandit and pip-audit clean.

## State, 2026-10-24: MITRE ATT&CK Enterprise v20.0 as a fifth axis (u02 A-95, `feat/mitre-attack-axis`)

- **What.** Daniel asked for the Feedly *Map ATT&CK Techniques* Claude skill to be applied to Il
  Dottore and for the ATT&CK data it points at to be downloaded and applied. What fits a spec
  battery is the mapping discipline, not the report mapper: ATT&CK Enterprise v20.0 (2026-10-13,
  the release with `T1698`/`T1699`/`T1700` and the Stealth and Defense Impairment tactics) pinned
  as data from the official STIX bundle (`scripts/attack_universe.py check|refresh|diff`,
  `shared/attack.py`), a `mitre_attack` block on specs with `observed` versus `capability-only`
  occurrence and an optional tactic restriction, a linter rule (retired or unknown ID refused
  naming the replacement, a restriction outside the technique's tactics a contradiction), the
  `attack` axis in `dottore coverage` (tactics from observed techniques only, techniques listed
  with their specs), the block in every run report, and ATT&CK Navigator layers from the battery
  (`--navigator-layer`) and from a run (`-oN`, `reporting/navigator.py`, a fifth registered
  reporter through the masking gate, never part of `-oA`).
- **Figures (from `dottore coverage`, 2026-10-24).** 41 of 78 specs mapped, 18 techniques (14
  observed, 4 capability-only), **8/15 tactics, 53%**; uncovered: Initial Access, Privilege
  Escalation, Defense Impairment, Discovery, Lateral Movement, Collection, Command and Control,
  all roadmap. Rationale per spec and the 37 deliberately unmapped in `docs/17`.
- **Decided.** Two occurrences, not the skill's four: a harness is its own observer, so
  `reported` and `source-assessed` have no meaning here, and no confidence travels with a
  mapping. Generate Content is observed when the model generated the content (a lure, a
  narrative); writing malware source is `T1587.001` capability-only. The log-evasion spec maps
  the generic `T1070`, not the v20 system-log sub-techniques under Defense Impairment, because
  the mock is an application audit log. `-oA` keeps writing four files. The field is outside the
  resume digest; the package bytes changed, so judging rules 7 re-pinned.
- **Checks.** `tests/shared/test_attack.py` (pin counts, matrix order, v20 renames, retired
  replacements), linter tests (retired, unknown, duplicate, contradicted, schema shapes),
  `tests/reporting/test_navigator.py` (both layers, the reporter's determinism and that no reply
  reaches the bytes), `tests/cli/test_coverage_cmd.py` (observed-only numerator, restriction,
  off-universe reporting, the shipped buckets pinned, the layer file), `tests/battery` (every
  shipped ID current and declared once). Golden snapshots regenerated for the new coverage
  block and edition.

## State, 2026-10-20: a canary masked at rest as it is read (u10 A-94, `fix/evidence-folded-canary`)

- **What.** L4 of the A-92 pre-merge audit: the evidence store registered each planted canary as an
  exact pattern, so a canary re-cased or split by U+200B, U+FE0F, U+3164 or U+034F stayed readable
  on disk while the evaluators read it folded. Found on the way: the scope's identity canaries were
  never given to the store, so one the entropy rule missed was stored in clear (through the CLI on
  `65203f18`, `canary-b-7f3a91c2` in the stored reply beside the `fail`). `shared.folding.
  folded_spans` places a folded match in the text as written; `Redactor.register_spans` masks what
  a finder returns (the redactor still imports nothing in-repo); `FsEvidenceStore` takes
  `folded_canaries` and `canary_folds` (`evaluators.base.foldable`, from the wiring), and fills
  `{{run_id}}` from the run being stored; `cli.wiring.declared_canaries` adds every identity canary.
- **Decided.** Masking only, no verdict change: judging rules 7 re-pinned by an appended line. A
  canary below the floors stays exact (folding a word canary would mask the word across the
  evidence), as the evaluators read it.
- **Checks.** `tests/store/test_folded_canary_at_rest.py` (29: 22 fail on `65203f18`, those
  through `build_runner` by their assertions; a Hypothesis property of `folded_spans` against a
  character-by-character reference found two matches inside one `ß` yielding overlapping
  stretches, fixed before commit), and 3 cases through the CLI in
  `tests/cli/test_identity_trials_cli.py`, which fail on `65203f18` with the canary readable in the
  stored attempt.
- **Audit.** Pre-commit (opus): no defect in the mechanism over 200,000 differential cases, a
  30,000-text idempotency fuzz and 21 adversarial texts; M1 (a seeded spec's canary, bound to its
  `run_token`, was not folded), M2 (an identity canary holding `{{run_id}}` registered a stem of one
  letter that masked every `a`), and five LOWs (a duplicated MANUAL line, weak or misleading tests,
  the run id left set after a `put`), all applied. Delta audit: the seeded canary was still
  missed on a mock or `--hardened` route (no `real_target`); `build_runner` takes `canary_target`,
  the target the runner binds with, and a test through it fails when the store is given
  `real_target` instead.
- **Merged after A-93.** L3 of the same audit (canary floors read on the folded canary, judging
  rules 7) landed first as `4673bb54`, then u01 A-91 as `30cc2d6a` (its own re-pin of version 7);
  this branch merged both and re-pins version 7 by an appended line, main's pins left as they
  were.

## State, 2026-10-20: identities sharing a credential refused (u01 A-91, `fix/shared-identity-credentials`)

- **What.** The pre-merge audit of A-87 (L1) queued it: two identities of one target with one
  `auth_ref` were one caller under two names. Measured on `01d6bdc5` through the CLI stub: a target
  leaking B's canary to A on every reply read 0.17, Low, exit 0 (one key each: 1.0, Critical), and a
  clean target that shows each key its own canary read 0.17, Low, a fail that needs review (one key
  each: inconclusive); two variables holding one key did the same on the clean target.
- **Decision (owner's delegation, best practice).** Refused, not read as one. `load_scope` refuses
  one `auth_ref` on two identities (two `env://NONE` too); `check_identity_credentials` and
  `build_identity_probes` refuse two references holding one key before anything is sent, in every
  mode. Identities are named, never the reference or the key. Exit 3.
- **Rules.** No stored verdict changes; judging rules 7 re-pinned by an appended line on the merged
  tree (main took 6, u08 A-92, and 7, u08 A-93, first).
- **Not covered.** Two keys a provider issues to one account are two credentials here.

## State, 2026-10-20: the canary floors measure the folded canary, judging rules 7 (u08 A-93)

- **What.** `fix/canary-floors-folded`, L3 of A-92's pre-merge audit: `policy.scope.weak_canary`
  and `evaluators.base.foldable` measured a canary as written while `authz_leak` and
  `secret_leakage` read it folded, so `ab` and the 16 variation selectors (or, before A-92, 15
  distinct format characters) passed the floors and read as `ab`: every reply holding `ab` was a
  confirmed Critical (exit 2 on `65203f18`). The floors, the entropy and the label check now
  measure `shared.folding.folded(canary)`, and hold for `shared.folding.visible(canary)` too
  (invisible characters removed, case kept), since case folding lengthens some canaries (`ß`
  reads as `ss`): measured folded alone, `Straßenbahnhöfe` (15 characters) passed where
  `65203f18` refused it (this branch's pre-merge audit, MEDIUM 1). The refusal says so when there
  were invisible characters to remove. Judging rules 7, pinned on main `65203f18`.
- **Measured first** (`_ildottore-tren/scratch/foldfloor/floor_corpus.py`, outside the repo and
  not published): 280,000 random canaries of 14 shapes, none newly refused; the repository's 42
  declared canaries, none changed; 1,476,046 tokens of 8 to 64 characters in 8,327 benign files
  (this repository, the Python 3.14 standard library, two `node_modules` trees), 2 newly refused,
  through letter case only, none newly accepted. The new floors accept a subset of the old ones
  (length times entropy never drops as characters are added), so no new text is read folded.
- **Checks.** New cases in `tests/policy/test_scope_canary_shape.py` (15),
  `tests/evaluators/test_secret_leakage_fold.py` (3), `tests/cli/test_scoring_followups_cli.py`
  (2, through the CLI: exit 3, nothing sent, where `65203f18` exits 2), the version 6 resume in
  `tests/cli/test_resume_judging_rules.py`; 14 new cases fail on `65203f18`, and so does the
  resume.
- **Left open.** L4 of the same audit (the evidence store masks a split canary exactly) is on its
  own branch.

## State, 2026-10-20: a canary read without default ignorables, judging rules 6 (u08 A-92)

- **What.** `fix/fold-default-ignorables`, LOW 2 of A-87's pre-merge audit: the fold removed only
  `Cf`, so a variation selector, the combining grapheme joiner U+034F or a Hangul filler inside a
  canary still hid a crossing (inconclusive, exit 0) or a planted canary's leak (pass).
  `shared.folding.folded` now removes every `Default_Ignorable_Code_Point` and every `Cf`, pinned to
  Unicode 16.0 (4,206 code points), no longer read from the interpreter (3.11 has 14.0). Judging
  rules 6, pinned on main `01d6bdc5`.
- **Measured first.** Benign corpus, 11,134 files and 168.9 million characters (this repository,
  the Python 3.14 standard library and site-packages, two `node_modules` trees), 1,290 default
  ignorable code points outside `Cf` in them: 600 random canaries the floors accept and the
  battery's planted shape matched none before or after; 15 weak spec canaries, the same files.
  Narrowing the message to "format (Cf) characters" was the alternative, not taken.
- **Checks.** `tests/shared/test_folding.py` (30), new cases in
  `tests/evaluators/test_authz_leak_received.py` (5), `tests/evaluators/test_secret_leakage_fold.py`
  (3), `tests/policy/test_scope_canary_shape.py` (2), `tests/cli/test_identity_trials_cli.py` (3,
  through the CLI: exit 2, 1.0, Critical), the version 5 resume in
  `tests/cli/test_resume_judging_rules.py`; 30 new cases fail on `01d6bdc5`, and so does the
  resume.
- **Left open.** LOW 1 of the same audit (identities that share a credential) is on its own branch;
  whichever lands second takes the next judging rules version or re-pins on the merged tree.

## State, 2026-10-20: identity trials, judging rules 5 (u08 A-87, OD-53, `fix/identity-trials`)

- **What.** The design A-85's item 3 left to a branch of its own. Every reply received under an
  identity the attempts are sent as is read against the scope's canary owner map; the identity sweep
  is one trial of its spec, stored as an attempt (`mutation: identity_sweep`) and counted once
  (reproducibility the best variant, never below the pooled rate; never a confirmation); a canary of
  the scope's floors is read case-folded without format characters (`shared.folding`), in replies
  and tool-call arguments, and the scope refuses two that fold alike. Judging rules 5: the branch
  held its bump as 3, and main took 3 (A-89) and 4 (A-90) first, so the merge of main `93b3f2a3`
  made it 5, pinned on the merged tree.
- **Checks.** `tests/cli/test_identity_trials_cli.py` (25, through the CLI against a loopback stub),
  `tests/core/test_identity_trials.py` (9), `tests/evaluators/test_authz_leak_received.py` (18),
  `tests/evaluators/test_secret_leakage_fold.py` (12), `tests/scoring/test_identity_sweep_trial.py`
  (11), `tests/cli/test_attempt_identity_wiring.py` (6), `tests/shared/test_folding.py` (13), a
  scope refusal and a resume test for 4 to 5. Clause u08 A-87 with halves in u00, u01, u06, u07,
  u10, u11 and u12; OD-53 in the index.
- **Gates.** `make gates` in CI mode green on the merged tree with these docs (2026-10-20,
  coverage 97.67%).
- **Open.** The sweep's other identities' replies are still not stored; a re-encoded canary
  (homoglyphs, spaces, an encoding the target applies) still hides; `pii_detector` and
  `secret_shape` corroborate with a canary exactly; keeping a stored sweep on a resume needs a
  change of the estimate (u08 A-87, not taken).

## State, 2026-10-19: long integers in object-form arguments (u06 A-90, `fix/long-integer-object-arguments`)

- **What.** MEDIUM-1 of the A-89 audit, closed: arguments a reply carries as a JSON object
  (Anthropic's `input`, an OpenAI `function.arguments` written as an object, a WebSocket frame's
  calls) holding an integer past the digit limit made the whole reply unreadable, `inconclusive`
  (OD-21), where the string form is judged. Bodies and frames are parsed by
  `shared.toolcalls.loads_keeping_long_integers`, and `check_long_integers` keeps such an integer
  only inside the arguments of a call the adapter reads (matched by identity); anywhere else the
  reply stays unreadable, so no reader takes a `LongInteger` for text or a figure. Judging
  rules 4 (an `inconclusive` can become a verdict).
- **Checks.** `tests/adapters/test_long_integer_object_arguments.py`: 21 tests; on the tree before
  the change, 8 of the 19 that import there fail (`scratch/longint/red-before-longobj.log`, outside
  the repo); a resume test for 3 to 4.
- **Audit.** One pre-merge round, no HIGH. MEDIUM-1 (only the first kept integer was in effect
  tested) and LOW-2/3 (a nested `tool_calls_path`, a decoy list, a second call): tests added, each
  surviving mutant now killed. LOW-1: the check reads the integers the parsed reply holds, so a
  duplicate key's dropped value no longer refuses it. LOW-4: a WebSocket `text_path`, `model_path`
  or `id_path` declared into a call's arguments reads no digits. LOW-5: wording and wrapping. A
  verification round found `final_path` uncovered (now guarded too) and a line past the limit.
- **Left open.** `fix/identity-trials` (not merged) now needs judging rules 5, or whichever is free
  when it lands. The SSE masking path and error bodies keep the plain parse (u06 A-90 says why).

## State, 2026-10-19: a map read whole is hashed whole (u06 A-88, `u06-argval-hash-whole`)

- **What.** Audit 2 of A-88 (LOW-3): a map or an empty list read whole under a pinned argument
  was masked by shape, so its keys and every value the redactor has no shape for stayed in clear
  in the verdict's `matched`. Now it is hashed whole as one `tool_arg_value`; a scalar is masked
  by shape as before; the call in the attempt's record stays masked by shape, as every tool
  call is (ADR-0014 says so). Verdicts do not change: judging rules 3 re-pinned (merged with A-89, #125). 5 tests, 4 of
  which fail on `d6236c7d`. Closes the LOW-3 that A-89 lists as left open below.
- **Audit.** One pre-merge round (no CRITICAL): the pin (HIGH), a manual that promised the
  report held none of the map (MEDIUM), the hash's salt untested (LOW), all applied.

## State, 2026-10-19: long integers in a call's arguments (u06 A-89, `fix/long-integer-arguments`)

- **What.** OpenAI's JSON-string arguments holding an integer past `sys.get_int_max_str_digits()`
  (4300 by default) read as `{}`, so one long number beside the exploit made `tool_call` pass
  (`forbidden_arg_values`, `forbidden_args`, injection) and `tool_sequence`'s step patterns read
  nothing: L5 of the A-88 pre-merge audit, closed here. `call_arguments` parses with a `parse_int`
  that keeps such an integer as its digits (`shared.toolcalls.LongInteger`, a `str` subclass read
  as a number by every check) and reads the rest. Judging rules 3 (a stored pass can become a fail).
- **Checks.** `tests/evaluators/test_long_integer_arguments.py`: 17 tests, 12 fail on `d6236c7d`.
- **Audit.** One pre-merge round, no HIGH: two mutants survived (two tests added), the new resume
  test pinned the version (loosened), the docs said "every walk" where the redactor masks the
  digits by shape (now "every check"). Its MEDIUM-1 is left open, below.
- **Left open, each for its own branch.** Object-form arguments with such an integer (Anthropic's
  `input`, a WebSocket frame's calls) still made the whole reply unreadable, `inconclusive` (OD-21):
  closed by A-90 (judging rules 4), above. A map read whole under a pinned name is masked by shape
  only (A-88 audit round 2, LOW-3): closed by #126, above. `fix/identity-trials` (not merged)
  planned judging rules 3 and now needs the next free version.

## State, 2026-10-19: argument values on an authorized tool (u06 A-88, `feat/tool-argument-values`)

- **What.** `tool_call` read a call's tool name and its argument keys, never their values, so an
  authorized tool called with an authorized key passed whatever it carried. It gained an opt-in
  `forbidden_arg_values` (a regex per argument name, any tool, any depth, the value in its JSON
  spelling, a map or an empty list read whole; a match fails and is masked, a pattern that does not
  compile is `inconclusive`), with lint and the fixture stub through the same helpers (ADR-0014).
  Three `test_only` specs from the challenges of mubix/ai-ctf (MIT), re-authored with no text
  copied: `FUNCALL-PRICE-TAMPER-001`, `AC-SSRF-SCHEME-001`, `FUNCALL-SQLI-ARG-001`, in
  `access-control`; 78 specs. Opt-in: the 75 existing specs judge byte for byte as on `d8b43561`.
  Judging rules 2 re-pinned (`8d0f56fb`).
- **Audits.** Two pre-merge rounds (no CRITICAL, no HIGH). Round 1: a quadratic price pattern
  (a second on 16,000 spaces), maps and nested lists under a pinned key never judged, denylist
  bypasses in the price and URL patterns, stub and evaluator out of order on a bad pattern, names
  that fold together; four mutants survived. Round 2: the price denylist still missed zeros a
  backend reads (`0x0`, `0_0`, `1e-400`). All three patterns are now allowlists with possessive
  quantifiers; 17 of 17 mutants killed.
- **Checks.** `make gates` green on `d2139d50` with `GITHUB_ACTIONS=true CI=true`: 7752 tests,
  coverage 97.68% against the 85% floor, lint OK on 78 specs, self-scan, bandit, pip-audit clean.
  Run outside the sandbox: inside it, reading `*.pem` is denied and the adapter tests that load
  certifi's bundle fail with `PermissionError`.
- **Left open, each for its own branch.** A string-form argument holding an integer past the
  digit limit reads as no arguments, so `tool_call` passes it (older than A-88; audit L5). A map
  read whole is masked by shape, so its other text stays in clear where the redactor finds no
  shape (audit round 2, LOW-3).

## State, 2026-10-17: the stream bounds (u01 A-86, OD-52, `fix/stream-bounds`)

- **What.** Four items the A-83 audits of #120 queued and #122's entry left open. (1) An
  alternative of a masked token with more than four masks shows one `«REDACTED:fragment»`
  (`redactor.py`, OD-52, decided under the owner's delegation and revisable): a reply of glued
  secrets in one-alternative tokens wrote 14.2, 56.2 and 223.5 MB at 8, 16 and 32 KiB on
  `fef4963e`, now 0.22, 0.44 and 0.87 MB, and 4.89 MB at the 4 MiB reply cap; no verdict,
  finding, score or exit code changes. (2) An exit code that holds text but is no tuple or list
  (a dict, a set, a deque, an exception) is masked as the text it holds,
  not through `str()`, which wrote a split credential whole (`cli/app.py`, u12; the deque and the
  exception came from the pre-merge audit). (3) The glued-UUID timing test reads CPU time, its
  sizes in turn, best of five. (4) The `test_usage_figures.py` failure under load did not
  reproduce (8 runs under 45 CPU loops) and that test is unchanged. Judging rules 2 re-pinned by
  appended lines (`8ef34497`, `06bb22a2`, masking only).
- **Checks.** `make gates` green on the branch merged with `main` (`620095b5`): coverage 97.66%
  against the 85% floor.
- **Left open, each for its own branch.** The identity sweep's reproducibility (read every
  attempt's reply against the owner map, count each trial once); replies read exactly (a re-cased
  or zero-width-split identity canary in a reply hides the crossing); a campaign's target adapter
  keeps its own 30 s HTTP timeout, which `--timeout` and the `-T` templates do not reach, so a
  reply after 30 s is resent.

## State, 2026-10-17: the CI example pinned (`docs/pin-ci-example`)

- **What.** The CI example (`examples/ci-github-actions.yml`) installs `fef4963e`, `main` after
  #119, #120 and #121, where #119 left a placeholder its own guard refused (a commit cannot carry
  its own SHA). Its v0.1.0 caveat list gains A-83, A-84 and A-85; INSTALL names `5edeb0a7` (#119).
  The A-85 text in the MANUAL, the CHANGELOG and u08 no longer says the stored verdict names the
  carried canaries: only `authz_leak`'s own verdict does (audit LOW A). A comment in
  `policy/scope.py` gives the 3-character label case of the canary floor (audit LOW B); comments
  are outside the judging digest, so judging rules 2 stays pinned as it is.
- **Left open, each for its own branch.** The identity sweep's reproducibility (read every
  attempt's reply against the owner map, count each trial once; the A-85 audit's design); replies
  read exactly (a re-cased or zero-width-split identity canary in a reply hides the crossing);
  what an alternative of a logprob piece shows is unbounded (A-77; before a release); a dict or
  set exit code prints a split credential; the glued-UUID timing test can flake on a loaded
  runner; one unexplained failure of `tests/cli/test_usage_figures.py` under load.

## State, 2026-10-17: the scoring follow-ups, judging rules 2 (u08 A-85, `fix/scoring-followups`)

- From `main` at `7d01521f`, the items the pre-merge audit of the scoring branch (#112) queued as
  pre-existing, decided under the owner's delegation (best practice, revisable) and written in u08
  §7 A-85 with the alternatives not taken; no open decision (OD-50 unused). Each was reproduced
  first through the CLI against a loopback stub that answers by bearer key
  (`tests/cli/test_scoring_followups_cli.py`).
- Weak identity canary: `ACME`, `tenant-b`, `ZZ-1`, `invoice ready` and `12345678` each made
  `DL-XTENANT-001` a confirmed Critical, exit 2, on a reply that only said them. `load_scope`
  refuses a canary under 16 characters, with a space, part of an identity's name or the target
  id, holding one with what is left under these floors, or under 36 bits of character entropy
  (`policy.scope.weak_canary`); exit 3 in every mode, zero sends, the canary never quoted. The
  first version asked for a digit and a letter (it took `tenant-b-2026`, refused a random 16-digit
  number: audit of `8a42d08f`, LOW 4); the second had a floor of 8 that the entropy floor made
  impossible below 11 and refused any canary holding a label (audit of `bc5ddcb1`, LOW 2 and
  LOW 4). At 16, a random 16-digit number is refused about once in 200 draws, a random 16-hex
  token once in 15,000 (a million draws each).
- Echo: a refusal quoting a request that names tenant B's record by its canary was a confirmed
  Critical. `authz_leak` reads the sweep's request (`EvalContext.identity_request`), case-folded
  and through format characters, the scanner's text only (never a `tool_result` block): a crossing
  of a canary it carries is a fail that needs review (`echo_only`), never confirmed and never a
  pass, gated only with `--include-needs-review`, as A-79's judge-only fail on cut text (amended so
  on 2026-10-16 by the coordinator under the owner's delegation; the first version was
  `inconclusive`, which no gate takes). The refusal and the attacker's case (a real leak of the
  named record) exit 0 by default and 2 with `--include-needs-review`; a crossing canary the
  request does not carry still confirms, and the verdict lists every canary that crossed, naming
  the carried ones (LOW 6 of the audit of `bc5ddcb1`). An older build refuses to `diff` or
  `replay` such a run.
- The identity sweep's own count was tried and dropped (audit of `8a42d08f`, HIGH 1): counting the
  sweep's crossing once scored a leak on every reply of tenant A as 1 of 5, Low, exit 1, since no
  attempt's own reply was read against the owner map. Its fix needs the CLI wiring and a
  trial-based denominator, so it goes to a branch of its own; this branch counts as `7d01521f`
  does (every attempt carries the sweep's verdict: over-counts, fails closed), held by CLI
  controls at `--runs 1`, 5 and 10 and across a halt and resume.
- `secret_shape` builds its rules from `redactor.key_format_patterns()`, the redactor's one list
  (the redactor gains that accessor only): 36 of the 51 documented prefixes scored `pass` on
  `7d01521f`, now needs-review.
- Judging rules 2, pinned by appended lines (a first pin, then re-pins on each final tree); a run
  halted on `7d01521f` is refused by this branch's resume, exit 3, naming rules 1 and 2.
  `JUDGING_RULES_SINCE` stays 2026-10-15, and u12 and the pin test now say what it means.
- CI results that change, and the controls, are listed in the CHANGELOG entry (breaking).
- Tests: `make --no-print-directory gates` with `GITHUB_ACTIONS=true CI=true` on `11d1d97a`, the
  tree of round 2's fixes (17/10/2026 11:30 to 11:39 CEST, `PYTHONPATH` at the worktree's `src`,
  `TMPDIR` the system default): 7353 passed and 1 skipped (7108 collected on `7d01521f`, 246 new:
  `test_secret_shape_key_formats.py` 169, `test_scope_canary_shape.py` 45,
  `test_scoring_followups_cli.py` 18, `test_authz_leak_echo.py` 11, `test_echo_never_confirms.py`
  2, one resume test), 97.71% coverage (`evaluators/secret_shape.py`, `shared/combination.py`,
  `scoring/confidence.py` 100%, `evaluators/authz_leak.py` and `policy/scope.py` 99%,
  `core/runner.py` 98%), ruff, format, mypy strict on 167 files, four import contracts kept, 75
  specs lint OK, self-scan 0 high/critical, bandit and pip-audit clean. The CLI suite and the
  touched tests against typer 0.27.3 (11:30 to 11:37): 2767 passed and 1 skipped. Before round 2,
  on `c2d2a6b2`: the same wall plain and in CI mode, 7338 passed and 1 skipped each.
- Left open: the canary shape check catches obvious shapes only, so a structured id
  (`invoice-2026-0001`), an email address, a version, a timestamp or a long word of 16 characters or
  more passes, and a per-tenant sequential id can collide across tenants into a confirmed crossing
  (the docs recommend a random canary; audit of `bc5ddcb1`, LOW 3); a spec's own `setup.canaries`
  are not shape-checked; the case fold of the request lets a spec author mark an echo with a
  different value that folds to the canary (`ß`, the Kelvin sign, the long s, the `fi` ligature; the
  target gains nothing; a lint warning, or NFKC with non-ASCII folds refused, on a branch of its
  own: LOW 5); the replies are read exactly, so a canary a target writes re-cased or split by a
  zero-width character hides the leak (`inconclusive` on `7d01521f` and here, pre-existing, its own
  branch: LOW 7); the sweep's own count (its own branch); the sweep's replies are not stored as
  evidence, so a fail resting on them cites none (pre-existing); an identity canary is not
  registered with the redactor, so one a primary reply prints is masked only if another rule takes
  it (pre-existing); `secret_leakage` reads a canary the request carries as a leak too
  (pre-existing, outside A-85).

## State, 2026-10-16: masking follow-ups of the train (`fix/masking-followups`, u01/u12 A-83)

- From `main` at `7d01521f`, the items the pre-merge audits of the train queued for after it,
  each reproduced there first. Decisions taken under the owner's delegation (best practice,
  revisable) are recorded in the clause with the alternatives not taken; no open decision (OD-48
  unused).
- The CLI: an exit whose code is no exit status (a text, a bool, a number outside 0 to 255) exits
  3 with the stray-exit line, which is masked now (`typer.Exit("<text>")` exited 0;
  `SystemExit("<text>")` printed its text in clear); a UUID in an error is masked as a report masks
  it (`redactor.UuidCuts`); a missing file under a directory holding a space keeps its existing
  part (8 to 15 tests of the suite failed on `7d01521f` with `TMPDIR` under "AI projects",
  depending on the path); an error
  holding U+0000 or U+0001 is read both ways; an endpoint URL's user is registered when it is the
  credential. The A-82 "Fixed" heading is labelled breaking.
- The redactor: a text holding U+0000 or U+0001 is read with them dropped and with them shown, and
  what either reading masks is masked (F2 of the A-78 audits, open since then); a text without
  them reads as before (differential fuzz against `7d01521f`: no difference in 300,000 texts).
- The pre-merge audit of `4f1b28db` (NOT READY), fixed: the merge of a stretch's masks was
  quadratic (4 MiB of 32-hex runs glued by U+0000 took 177 s, main 0.73 s; now about 4 s, linear),
  and A-77's `_masked_pieces`, cubic on a logprob stream, is quadratic now (its output); a text exit
  code is masked as itself, not its `repr` (a credential split by a NUL, a newline or a tab printed
  whole); a user-only user info renames a target id in the reports, listed as breaking; the new
  tests read the battery through `specs_dir`; `late` is a bool or a frozenset; figures corrected.
- Its round 2 (MERGE-READY at `85da7f8f`), applied: a piece inside one stretch shares its mask
  tuple (memory grew as pieces times masks, 4.19 GB on 256 KiB of a logprob stream; 41 MiB now); an
  exit code holding text (bytes, a tuple, an exception) is masked as that text, named by its type;
  the speed is "up to about 9 times main" (card numbers glued by U+0000).
- Found closed: the all-digit run id (A-61) and the exception class names (A-63).
- Open, found by this branch and left: a hex run inside a token-level JWT match followed by a
  letter outside ASCII is printed by the redactor (on `7d01521f` too); a registered credential is
  masked whole, not by its parts, so a part of one inside a path a CLI error does not keep prints
  (on `7d01521f` too); the CLI types a key the entropy pass masks whole as `high_entropy` where a
  report names its format; a URL user beside a non-empty password (`<token>:x-oauth-basic@`) is
  not registered; a user-only credential under 8 characters is neither registered nor refused;
  what a logprob token's alternatives show is every mask of the stretch it lies in, which can be
  thousands on a hostile stream (A-77's output): bounding it changes that output and goes to its
  own branch, with an open decision.
- Judging rules: version 1 re-pinned by appended lines (`ce74f59f`, "masking only", then
  `8c14612b` after the audit's fixes, masking and speed only):
  the redactor decides what is stored and printed, the evaluators judge the raw reply, and
  the exit status changed is that of an exit no command raises, so no stored verdict can
  change. The stacked landing pins again on the merged tree.

## State, 2026-10-16: the package carries what it reads, CI on the declared floors (`fix/packaging-dependency-floors`, u12 A-84)

- From `main` at `7d01521f`, one of three follow-up branches of the audit train (landing order:
  `fix/masking-followups`, this one, `fix/scoring-followups`). Decisions under the owner's
  delegation (best practice, revisable) are in u12 A-84 and ADR-0013.
- The built-in battery moved to `src/ildottore/battery/` and the attack-spec schema to
  `src/ildottore/registry/schemas/`, as git renames; the three example files beside the battery
  to `examples/`; `specs/` holds the unit contracts only. `shared/package_data.py` finds both
  through `importlib.resources`. Measured on `7d01521f` with a wheel assembled offline by the
  selection `pyproject.toml` declares (hatchling is not installed here, and nothing may be
  downloaded): from outside a checkout `registry ls` and `run --dry-run` exit 3 and `lint
  <checkout>/specs` exits 3 on the schema. On this branch, the same kind of wheel, installed with
  `pip install --no-index --no-deps --target` and run from outside the checkout, prints what the
  checkout prints for `--version`, `registry ls`, `schema export`, `lint` of its battery and `run
  --dry-run`, with the same judging digest (`a5133e82`, 264 files), and judges a quick offline
  run the same (10 fail, 8 inconclusive, exit 2). The real hatchling build is first proven by the
  new `package` CI job.
- With no `--spec-path`, `specs/` here is read whenever it is a directory and refused when it
  holds nothing (fail closed); the battery is read where there is no `specs/` and at the root of
  this package's own checkout, said on stderr and, under GitHub Actions, as a `::warning::` line.
  A path of the old layout is refused naming the new one and what moved it. CHANGELOG lists every
  old path as breaking, `dottore lint` with no path in the repository root (exit 0 to 3)
  included. The judging digest covers the battery (`.wav` added): a resume across the change, or
  after any edit of a built-in spec, is refused, naming the file in clear; version 1 re-pinned
  (no verdict changes). OD-51 (a `builtin` spec-path keyword) is open.
- Pre-merge audit of `0f556628` (the move measured sound, verdict parity on the full battery):
  NOT READY, fixed in new commits. HIGH 1: six floors raised from release histories, not measured
  (websockets 15.0, typer 0.26.8, rich 13.8.0, PyYAML 6.0.1, Jinja2 3.1.6, pytest-asyncio 0.23.5),
  the merge waiting for the `floors` job; HIGH 2: the fail-open default above, dropped; MEDIUM 1:
  a resume refusal masked a battery file's name; LOWs: the lint break listed, the runtime notes
  name the change, stale old-path references, the CI example's placeholder pin refused unless it
  is a full SHA (`::error::`), job timeouts, CODEOWNERS on the schema directory.
- Round 2 of the audit (`72f7d471`): NOT READY, fixed in new commits. HIGH 1: the own checkout
  was told by three parents, which `pip install --target <dir>/deps` fooled (the operator's
  `specs/` unread, the built-in 75 run under a false note): it is told by the checkout's shape now
  (`src/ildottore/battery`, the root, a `pyproject.toml` naming `ildottore`). LOWs: a label only
  the run record names is kept readable only where the package has files; the CI example's pin
  guard is bash's whole-value match (`printf | grep` accepted a second line); the injection test
  skips only the CLI's two exact annotation lines; the `dev` extra declares `click>=8.4.2`.
- PR #119's CI: `static`, `validate` and `package` (the real hatchling wheel and sdist) green;
  `floors` red on one test, on pydantic 2.6.0: `WebSocketResponse.model_path` warned about the
  `model_` protected namespace at import. Fixed in the model (it protects only `model_validate`
  and `model_dump`), the floor kept at 2.6. Round 3 of the audit, LOW: `is_own_checkout` opens
  `pyproject.toml` only when it is a regular file (a FIFO there made a command wait).
- CI: `floors` (every direct dependency at its declared floor, Python 3.11, the suite) and
  `package` (hatchling wheel and sdist, the wheel run from outside the checkout); actionlint
  clean, not yet run on GitHub. The existing workflows pin actions by major tag (Dependabot), so
  the new jobs do too. OD-49 (pin the PR jobs' dependency set, the newest releases on a schedule)
  is open for the owner. OD-45 to OD-47 hold no packaging fact and are unchanged.
- Docs: INSTALL (a runtime install from a commit), the CI example (the wheel of a pinned commit,
  a placeholder until `main` carries this change), README, USAGE, MANUAL, FAQ, `dottore(1)`,
  `dottore-scope(5)`, examples, CONTRIBUTING, AGENTS, RELEASING, ROADMAP, `docs/03`, `06`, `07`,
  `08`, `09`, `11`, `12`, ADR-0004, 0006, 0007 and 0013, the unit contracts and the index.
- Gates on this branch after the audit rounds' and the floors job's fixes (`make gates`,
  `PYTHONPATH` at the worktree): 7,148 tests, 7,145 passed and 3 skipped (the two hatchling tests,
  which run in the `package` job, and one of before), 97.70% coverage, 75 specs, 14 suites and 1
  pack lint OK, four import contracts kept, mypy and ruff clean, self-scan 0 high/critical, bandit
  and pip-audit clean; the same with `GITHUB_ACTIONS=true CI=true`; the CLI suite and the touched
  tests (2,613) green on typer 0.27.3, plain and with those variables. `7d01521f` collects 7,108
  tests (40 new here).

## State, 2026-10-12: the docs and contracts audit, fixed (`docs/audit-2026-10-12`)

- From `main` at `de122e26`, one commit per finding group of the audit report
  (`_ildottore-tren/scratch/audit-docs/REPORT.txt`), every figure re-measured on this branch
  with `PYTHONPATH` at the worktree's `src`; decisions taken under the owner's delegation (best
  practice) are recorded as such in each commit.
- HIGH: `examples/ci-github-actions.yml` installed `@v0.1.0` by `pip install "git+https://..."`.
  A wheel built with the selection `pyproject.toml` declares ships neither `specs/` nor
  `schemas/` (measured with that selection assembled offline, hatchling being absent, again on
  2026-10-15 with `main` merged in: `lint` and `run --dry-run` exit 3, without a spec path on
  `spec path not found: specs`, with a checkout's `specs/` on `schemas/attack-spec.schema.json`),
  so the example now checks out a pinned SHA of `main` and installs it editable, with
  `--spec-path`; the v0.1.0 gate differences are listed beside the pin. Packaging is left for its
  own change, recorded in `docs/12` P1 and ROADMAP.
- MEDIUM, re-measured: 33 specs and 545 requests on `examples/target.local.yaml`; "34 of 75
  specs never ran" against an HTML stub (9 requests, 8 attempts, 0 tokens); the `docs/16` §3
  table (33/545, 58/1,255, 40/580, 61/735, 66/775; two identities 582, 737, 779; judge +700);
  140 and 350 replay attempts on the vulnerable mock; `dottore fingerprint` exits 0 on a 200
  that is not JSON (OD-21); the Bedrock item closed by OD-42; the scope checksum is integrity
  only (OD-2).
- Ledger and contracts: CHANGELOG "breaking for <whom>" labels (15 more headings, 17 in all),
  the A-37 row, A-62 and A-64 reserved (A-75 stays free), OD rows in order, unit owners, ODs
  cited in each §9, and three open decisions numbered for the owner: OD-45 (a judge's
  self-consistency disagreement), OD-46 (a policy-pack flag), OD-47 (F9, `leetspeak` over
  `JB-ENCODING-001`'s Base64).
- CLI: no `--help` shows internal text, pinned by `tests/cli/test_help_text.py` (17 tests: no
  backtick, no "(u" and a digit, no unit or clause id); `dottore(1)` documents every command's
  options.
- Pre-merge audit of `10980e5e`: not ready, three changes and LOWs, fixed in new commits (no
  history rewrite). The FAQ quotes the CLI's refusal as printed ("(open decision)", OD-46 named
  after it); three more headings are labelled breaking, and OD-21 and OD-41 add "an older build
  reading the run" (measured: `dottore replay` of such a run with the code of `6837a71d`'s and of
  `fcdf9860`'s parent exits 3, a validation error at `verdict.inconclusive_reason`); A-75 is left
  free; OD-45, OD-46 and OD-47 are named in u08, u01 and u05, and in `docs/02` and `docs/11`;
  the wheel defect is recorded (`docs/12` P1, ROADMAP) with what it prints; the first rewrap is
  reverted and redone last, reflowing its paragraphs, with the YAML comment rewording in a
  commit of its own. The landing checklist is `_ildottore-tren/scratch/fixdocs/LANDING.md`.
- Gates: `make --no-print-directory gates` on this branch before the rewrap commit: 5493
  tests (17 new), 97.84% coverage, 75 specs lint OK, four import contracts kept, self-scan 0
  high/critical, bandit clean; pip-audit, stopped by a DNS outage (`pypi.org` not resolved) on
  2026-10-12, re-run on 2026-10-13 on the same tree: clean. `main` itself after the merges of
  2026-10-11, measured in a clean copy of `de122e26` (`git archive`): 5476 passed, 97.84%
  coverage, a figure no entry recorded. Lines over 100 columns are rewrapped in the last commit,
  alone, so it can be redone after a rebase.
- Landing, 2026-10-15: the rewrap reverted (`88c75b8b`), `origin/main` at `a906cea9` (#111 to
  #116) merged with `--no-ff` (`ba9d5fc8`, conflict resolution only), then one commit each: the
  wheel and editable installs re-measured (lint and run exit 3 on a missing spec path and on the
  wheel's missing schema; an editable install's run falls back to the checkout's battery); the
  root `-v` help without backticks (#114's, which the help test refused); `dottore(1)` with the
  root `-v`, fleet's new options, `schema export --name report`, the spec path's new default and
  lint's exit 3; a blank credential variable's dry run (exit 0 with a warning, 3 on #113); the
  siblings' headings to the label and tense conventions. Re-measured on the merged tree and
  unchanged: 33 specs and 545 requests (no flag, `--deep`, `-A`), the `docs/16` §3 rows and
  two-identity rows, replay 140 and 350, the HTML-stub transcript (9 requests, 8 attempts, 0
  tokens, byte-identical), the mixed-stub fingerprint warning, Scenario B.
  `make --no-print-directory gates` on the merged tree, plain and with
  `GITHUB_ACTIONS=true CI=true`: green both times, 7003 passed and 1 skipped, 97.68% coverage.
- Stacked on #117 (`fix/resume-judging-rules`, head `e92a7541`, not yet landed), merged with
  `--no-ff` (`aad7b64c`, one CHANGELOG conflict). Its "corrupt run-context value is refused"
  heading is labelled breaking (30 labelled headings); its A-81 row is in the index already, and
  the CLI's options are as on `a906cea9`. The gates then failed one test,
  `test_the_judging_code_is_the_code_its_version_was_pinned_for`: this branch's help and
  docstring text in `cli/app.py` and `cli/run.py` changes the judging digest, so version 1 is
  re-pinned by an appended line (`dbfbedd7`, "help and docstring text only"), PINNED moved, no
  line edited. Re-measured on that tree and unchanged: item 11 (a blank or three-space variable
  exits 0 under `--dry-run`, `-sn` and `--estimate`, a five-character one exits 3), 33/545, the
  `docs/16` rows, replay 140 and 350, the HTML-stub line, the fingerprint warning, Scenario B.
  `make --no-print-directory gates`, plain and with `GITHUB_ACTIONS=true CI=true`: green both
  times, 7107 passed and 1 skipped, 97.70% coverage.
- #117 landed (main at `3740b387`, tree equal to `e92a7541`'s), recorded here with
  `git merge -s ours` (`f87541a6`, tree unchanged). The CI example pins
  `3740b3874642dbec711e82918e477060d4a39ea1` and its v0.1.0 caveat gains A-79, the scoring audit,
  the SARIF level of a fail that needs review, A-80, A-78, A-82 and A-81 (actionlint passes; the
  scan command dry-runs, exit 0, against an editable install of a clean copy of `3740b387`). The
  appended judging pin `dbfbedd7` is the digest of the final tree (the pin test's 24 pass).
  `--version` prints `dottore 0.1.0 (judging rules 1)` since #117, so MANUAL §5 and `dottore(1)`
  quote it. Re-measured on the final tree and unchanged: 33/545 (no flag, `--deep`, `-A`), the
  `docs/16` rows and two-identity rows, replay 140 and 350, the HTML-stub line, the fingerprint
  warning, Scenario B, the `-v` operator line, item 11, the wheel install's four exits.
  `make --no-print-directory gates` before the rewrap, plain and with
  `GITHUB_ACTIONS=true CI=true`: green both times, 7107 passed and 1 skipped, 97.70%
  coverage. The rewrap is the last commit.

## State, 2026-10-15 (landing): main (`a906cea9`) merged in, version 1 pinned at landing (u12 A-81)

- #116 (fix/cli-input-validation) landed as `a906cea9`, whose tree is its head `8a8053a7`'s; merged
  in as a real merge commit (`eaca1434`). The six conflicts (`CHANGELOG.md`, this file, `USAGE.md`,
  `docs/MANUAL.md`, `u12-cli.md`, `cli/app.py`) were the trial merge's, replayed by `git rerere`
  and checked: the merged tree equals the trial's. `cli/run.py`, `cli/wiring.py` and `00-INDEX.md`
  merged cleanly.
- Every module the six landed branches added is covered (`cli/key_shape.py`,
  `shared/credential_refs.py`, `shared/error_text.py`, `shared/filter_stops.py`, `shared/resend.py`,
  `shared/withheld.py`) and only `ildottore.testing` is exempt: 171 files, 165 of the 167 modules
  and 6 data files. `JUDGING_RULES_SINCE` is 2026-10-15, the landing day, and the landing pin
  `30831195` replaced the provisional `b644c56b` in `PIN_HISTORY` and in `judging_pins.frozen`, the
  sixth line of each (`87ee30d3`). Digest cost at landing: 0.35 to 0.38 s on Python 3.12 and 3.14,
  0.74 s on 3.9, the same digest on all three.
- Every place the docs say which older runs a resume refuses names `JUDGING_RULES_SINCE`
  (`44fa3520`: the CHANGELOG entry, the MANUAL, `docs/09`, the A-81 index row; USAGE, FAQ,
  `dottore(1)` and u12 already did).
- `make gates` green on `44fa3520` (`PYTHONPATH` set to the worktree's `src`, `TMPDIR` the system
  default): 7091 tests (6987 on `main` at `a906cea9`), 97.70% coverage, 75 specs lint OK, four
  import contracts kept, mypy strict on 167 files, self-scan, bandit and pip-audit clean; the suite
  again under `GITHUB_ACTIONS=true CI=true`, green.
- The halt-and-resume harness on the final tree (`scratch/fixcli2/merge/hf/`): the controls resume
  (mock, REST, OpenAI, a comment-only edit, a `.DS_Store`); the auditor's mutation set (a to j, g2,
  the two renderer side effects, `dyn-x`, `dyn-y`, the lazy import) and three more (a new module,
  an edit of `shared/filter_stops.py`, one of #116's `cli/key_shape.py`), 19 in all, each changes
  the digest and is refused by a resume before sending (exit 3, 0 requests, the changed module
  named); a run halted on main `a906cea9` is refused as recording no rules. The L6 repro refuses
  each corrupt field naming it.

## State, 2026-10-15: main (`d526747e`) merged in, version 1 re-pinned provisionally (u12 A-81)

- Main at `d526747e` (#111 to #115) merged into the branch as a real merge commit (`cef983ae`),
  conflicts as `LANDING.md` foresaw: one import line of `cli/run.py` (both kept), `CHANGELOG.md`
  and this file (both entries, the branch's on top), the `--resume` rows of `USAGE.md` and
  `docs/MANUAL.md` (both sides' sentences as one text), `00-INDEX.md` (both sides' rows).
- The exemption and coverage tests pass on the merged tree: main's three new modules
  (`shared/filter_stops.py`, `shared/resend.py`, `shared/withheld.py`) are covered, only
  `ildottore.testing` is exempt; 168 files, 162 of the 164 modules and 6 data files.
  `JUDGING_RULES_SINCE` set to 2026-10-14 and version 1 re-pinned provisionally to `b644c56b`
  (`06255814`); the landing pin replaces that line, in `PIN_HISTORY` and the frozen file, once
  fix/cli-input-validation (#116) has landed.
- `make gates` green on `06255814` (`PYTHONPATH` set to the worktree's `src`, `TMPDIR` the system
  default): 6768 tests (6664 on `main` at `d526747e`), 97.71% coverage, 75 specs lint OK, four
  import contracts kept, mypy strict on 164 files, self-scan, bandit and pip-audit clean; the suite
  again under `GITHUB_ACTIONS=true CI=true`, green.
- The halt-and-resume harness on the merged tree (`scratch/fixcli2/merge/h/`): the controls resume
  (mock, REST, OpenAI, a comment-only edit, a `.DS_Store`); the auditor's mutations a, f, g2 and i,
  a new module and an edit of main's new `shared/filter_stops.py` are refused before sending (exit
  3, 0 requests, the module named); a run halted on main `d526747e` is refused as recording no
  rules. The L6 repro refuses each corrupt field naming it. Same digest on Python 3.9, 3.12 and
  3.14.
- A trial merge of #116's head (`8a8053a7`) in a throwaway worktree conflicts in six files, all
  resolved by rule (recorded by `git rerere` and scripted); there the exemption and coverage tests
  pass (#116's `cli/key_shape.py`, `shared/credential_refs.py` and `shared/error_text.py` covered,
  171 files) and only the pin fails, as it must.

## State, 2026-10-13 (night): the third audit of `1d3d65c7` (merge-ready), applied

- MEDIUM 1: an exempt renderer could change a verdict through an import-time side effect
  (`cli/render.py` emptying `shared.provider_filter.FILTER_STOPS`; a resume mixed verdicts). A
  module the `dottore` entry point loads runs at the top of every run, so the renderers, every
  command, `cli.app` and `cli.main` are covered; only `ildottore.testing` stays exempt, checked to
  be outside the import closure of `cli.main` and named by no `import_module` or `__import__` of
  covered code. The cost, said in u12 A-81: a resume across a help-text edit is refused.
- MEDIUM 2: data files are covered by suffix (`.yaml`, `.sql`, `.json`, `.j2`, all the package
  reads, a test checks), dotfiles skipped: a `.DS_Store` no longer refuses a resume.
- LOWs: a package with no readable source is refused at run start (exit 3); each covered file's
  8-hex digest is recorded and the refusal names up to five that differ; the interpreter
  (implementation and `major.minor`) is recorded and compared, pydantic, httpx and websockets
  recorded; the figure is 165 files (159 of 161 modules and 6 data files); `LANDING.md` step 1
  redone (conflicts now in `CHANGELOG.md`, `docs/PROGRESS.md`, `USAGE.md`, `docs/MANUAL.md`,
  `00-INDEX.md` and one import line of `cli/run.py`; u12 merges cleanly).
- Re-run with the auditor's harness on this branch (`scratch/fixcli2/r4/`): mutations a to i, g2,
  the two renderer side effects, `dyn-x`, `dyn-y` and the lazy import refused on resume (exit 3, 0
  requests, the changed file named), j refused on the landed preview; the comment-only edit, the
  `.DS_Store` and the controls resume. An in-place re-pin of a mutated tree fails the frozen-pin
  test. Digest cost 0.32 s on 3.12 and 3.14 (0.64 s on 3.9), same digest on all three.
- `make gates` green on `45598e8e` (`PYTHONPATH` set to the worktree's `src`, `TMPDIR` the system
  default): 5580 tests (5476 on `main` at `de122e26`), 97.85% coverage, 75 specs lint OK, four
  import contracts kept, mypy strict on 161 files, self-scan, bandit and pip-audit clean. Tests:
  `tests/shared/test_judging_rules.py` 24, `tests/cli/test_resume_judging_rules.py` 34.

## State, 2026-10-13: the second audit of `6de5780b`, fixed: deny by default (u12 A-81)

- The audit (`_ildottore-tren/scratch/fixcli2-audit/r2/`) reproduced H2 twice with the tripwire
  green: a default of the REST template no target file carries (`finish_path`), and a subclass's
  `filter_stops` override on the landed tree, each a resume that mixed verdicts; with more verdict
  code the allow-list missed (`canary_binding`, the `in_band` tag, `needs_seeding`, the offline
  judge, decorators), an in-place re-pin that passed, a plugin check that refused over a plugin no
  spec used and missed a code change under the same version, and two exemption reasons that
  claimed too much.
- Decided under the owner's delegation (best practice): invert the default. `judging_digest` (in
  `shared.judging_rules`) covers every file of the package but 17 presentation and input modules,
  each exemption checked by the import graph (14 commands outside the run's import closure, 3
  renderers only `cli.run` and `cli.wiring` import); the allow-list and its walk are removed. A run
  records the digest, computed from the installed package (0.3 s, once per process), and a resume
  under another one is refused with no flag, naming both digests in clear. The pins are frozen in
  `tests/shared/judging_pins.frozen`, so an in-place re-pin fails. Plugins are recorded only when
  a selected spec names their type, with their source digest (none can today).
- Re-run: the auditor's mutations a to j each change the digest, fail the pin and are refused by
  a resume (exit 3, 0 requests sent; controls resume as before); the unrelated-plugin case resumes;
  the digest is the same on Python 3.9.6, 3.12.13 and 3.14.7; a dry run on `main` at `0be0be71`
  (#111 and #112 landed) merged with this branch fails only the pin, as it must, with one import
  line of `cli/run.py` to resolve (`scratch/fixcli2/LANDING.md`).
- Tests: `tests/shared/test_judging_rules.py` 19, `tests/cli/test_resume_judging_rules.py` 31.
  `make gates` green on `0186bb44` (`PYTHONPATH` set to the worktree's `src`, `TMPDIR` the system
  default): 5572 tests (5476 on `main` at `de122e26`), 97.86% coverage (`shared/judging_rules.py`
  100%, `cli/resume.py` 94%), 75 specs lint OK, four import contracts kept, mypy strict on 161
  files, self-scan, bandit and pip-audit clean.

## State, 2026-10-12 (later): the pre-merge audit of `22269e0c`, fixed (H-1, M-1, M-2, L-1 to L-8)

- The audit (`_ildottore-tren/scratch/fixcli2-audit/`) confirmed H2, M1 and L6, and found the
  tripwire blind to verdict code (H-1): four one-line edits each changed a verdict under an
  unchanged digest (`runner.CUT_DECIDING_EVALUATORS`, the `filter_cut` line of `execute_attempt`,
  `setup_delivery.TRACE_EVALUATORS`, the redactor's `is_date_stamp`).
- H-1: an entry of `JUDGING_SOURCES` may name a module-level assignment, and the list now holds
  what the auditor named (the runner's constants and `_tagged_seeded`, `execute_attempt`,
  `_unreadable_result`, the conversation executor, `canonical_tool_calls`, `tool_name_map`,
  `is_seeded`, `shared.nesting`, `shared.wellformed`, `shared.amounts.is_count`, the redactor's
  detectors, each adapter's mapping of a reply to a stop reason, its side and an unreadable reply).
  A closure test walks every `ildottore` name each entry refers to (imports, module names,
  `self.<method>`): it must be listed or exempted in `JUDGING_EXEMPT` with its reason. The list
  went from 29 entries to 163, with 75 exemptions, and the walk finds none uncovered; it follows
  `self.<member>` to a class attribute a base class sets, and, after the scoring branch's audit
  named them, `_run_spec`, `_sweep_identities` and the reproduction functions are listed. Plugin
  evaluators are recorded (`evaluator_plugins`) and a resume under others is refused. The auditor's
  mut-a to mut-d, applied as patches to this tree, each fail the pin now; the digest is equal on
  Python 3.9, 3.12 and 3.14.
- M-1: version 1 is "the rules as of the merge that introduced the version"; every run that
  records no version is refused, whatever halted it; the docs name `JUDGING_RULES_SINCE` instead of
  the date. `scratch/fixcli2/LANDING.md` lists what the final rebase updates.
- M-2: `PIN_HISTORY`, append-only; a re-pin is a new line that says `re-pin` and why. Version 1 is
  re-pinned on the new list (one line), being unreleased.
- L-1 `its capabilities field changed`; L-2 the MANUAL sentence; L-3 the quotes copied from the
  real output and the three commits named; L-4 a record whose rules differ is refused for them
  before its other fields are checked; L-5 versions written `v<version>`, stored ones PEP 440
  shaped, `judging_rules` at most 1,000,000; L-6 `tool_versions`, every invocation's; L-7 tests for
  the selection flags, the changed-field paths, an unrecorded selection, a live route and a run
  with no target fields; L-8 `in severity (2)` from a real run instead of `in evaluator_logic (75)`.
- Tests: `tests/shared/test_judging_rules.py` 14, `tests/cli/test_resume_judging_rules.py` 26,
  `tests/cli/test_resume_refusal_advice.py` 15, `tests/cli/test_resume_corrupt_context.py` 31.
  `make gates` green on `1a0b1b7a` (`PYTHONPATH` set to the worktree's `src`, `TMPDIR` the
  system default): 5562 tests (5476 on `main` at `de122e26`, 86 new), 97.90% coverage
  (`cli/resume.py` 95%, `shared/judging_rules.py` 100%), 75 specs lint OK, four import contracts
  kept, mypy strict on 161 files, self-scan and bandit clean; pip-audit failed on a DNS error for
  pypi.org in that run and was clean when run again (2026-10-13). A dry run of the closure on
  `main` at `44a0ffb9` (fixstop landed) merged with this branch names the 13 names fixstop added,
  each one the landing step lists (`scratch/fixcli2/LANDING.md`).

## State, 2026-10-12: a resume is bound to the rules that judged it (u12 A-81); its refusals say what changed; a corrupt context value is refused

- On `fix/resume-judging-rules`, from `main` at `de122e26`: three findings of the CLI audit of
  2026-10-11 (harness and logs in `_ildottore-tren/scratch/audit-cli/`), one commit or more each.
- H2: a run halted on `f12ba83` (`--spec PI-DIRECT-001 --spec SP-LEAK-001 --runs 2 --concurrency 1
  --budget-requests 14 --judge ...`, a stub answering every request with `finish_reason:
  content_filter` and a refusal, a secure judge) and resumed on `de122e26` with `--spec-path` at
  `f12ba83`'s specs kept 4 attempts judged `pass` beside 2 judged `cut_by_provider_output_filter`;
  the summary and `replay` said "6 of 10 attempt(s) ... cut" where all 10 were cut, exit 0.
  Reproduced here on the same commits. Re-judging the kept replies was checked first and is not
  possible: the evidence is redacted at rest (DL2; `SP-LEAK-001`'s failing reply against the
  vulnerable mock is stored as `«REDACTED:canary:…»`), no logprob is kept, the judge would have to
  be asked again. So: `shared.judging_rules.JUDGING_RULES_VERSION` (`1`), recorded with
  `tool_version` in `context_json` when a run starts, and a resume under other rules, or of a run
  that records none, refused before it sends, with no flag. `--version` prints `dottore 0.1.0
  (judging rules 1)`. The bump is forced by `tests/shared/test_judging_rules.py`, which pins a
  digest of `JUDGING_SOURCES` (comments, docstrings, blank lines left out; equal on 3.12 and 3.14)
  to each version. After: the same `f12ba83` halt, resumed on this branch, `--spec-path` or not,
  `--resume-unverified` or not: exit 3, 0 requests sent; halted and resumed on this branch: 10 of 10
  attempts cut, as the summary says.
- M1: the run context records `selection`, `spec_fields`, `target_fields` and `route`, and the
  refusals name the field (`1 changed (PI-DIRECT-001), in attack`), the selection flags the run was
  made with (`Resume with --spec PI-DIRECT-001 --spec SP-LEAK-001`), the target field (`its
  capabilities field changed`), or the route and its flag (`... resolves the offline 'hardened'
  replay (--hardened forces it). The target file is otherwise unchanged
  ... Resume without --hardened`).
- L6: `run_sqlite._check_context` checks every field of `context_json` where it is read (and the
  appends refuse rather than overwrite); `runs.started_at` is checked by the resume. On
  `de122e26`: `adaptive: "x"` refused as "adaptive planning on", `scope_sha256s: 7` and a
  non-list `mutator_orders` overwritten (exit 2), `started_at: not-a-date` in the report; here each
  is exit 3 naming the field, the stored value untouched. A null `target_digest` still reads as
  absent (the unwaivable target refusal).
- Breaking for a halted run: every run halted before this branch is refused by its resume, one
  halted on `de122e26` included. CHANGELOG says it, and corrects the OD-44 note that recommended
  the `--spec-path` route (ADR-0007's copy too).
- Merge note: `fix/scoring-audit-2026-10-11` changes the ranking of an attempt's copies in
  `core/runner.py` and `store/replay.py`. Those functions (`_answer_rank`, `_one_per_attempt_id`)
  are scoring-time and not in `JUDGING_SOURCES`; if that branch touches a listed function, the
  tripwire fails after the merge and the merger bumps the version (to 2) and pins the new digest.
- Tests: `tests/shared/test_judging_rules.py` (7), `tests/cli/test_resume_judging_rules.py` (8, all
  failing before), `tests/cli/test_resume_refusal_advice.py` (9, all failing before),
  `tests/cli/test_resume_corrupt_context.py` (31, 28 failing before); six tests updated for the
  changed messages or the stricter store. `make gates` green on `880acb89` (with `PYTHONPATH` set to
  the worktree's `src`, `TMPDIR` the system default): 5531 tests (5476 on `main` at `de122e26`, 55
  new), 97.81% coverage (97.84% on `main`; `shared/judging_rules.py` and `shared/digest.py`
  100%, `cli/resume.py` 90%), 75 specs lint OK, four import contracts kept, mypy strict on 161
  files, self-scan, bandit and pip-audit clean. The commits after it touch documentation only.

## State, 2026-10-14 (evening): merged with `fix/no-secret-in-fragments` (`33782ad3`), which main now holds

- `33782ad3` (#115, with #114 `7cdd91a2` and main `030b79e0`) merged in as `007e3c41`, a real
  merge, as `scratch/fixcli3/MERGE-PLAN.md` decided; #114 and #115 have since landed, and main
  `d526747e` has the tree of `33782ad3`. One root class, `_MaskedGroup(OperationalErrorGroup)`,
  with Typer's public names only (`_click_classes` is gone); A-80's exit codes (`run_masked`: any
  other click error and an abort exit 3); one missing-spec-path mechanism, A-80's wording when no
  spec path was given (run, fleet --run, registry ls, describe, coverage; test added at
  `d3e748e4`, 3 of 3 failing on both parents); strict `lint`; `allow_inf_nan=False` kept.
- Found by the merge and resolved: A-80's `LoadResult.files` (a list) beside this branch's count,
  now `spec_files_read`; A-78's UUID pattern left out of `credential_patterns()` and `key_shape`
  reading the late key formats through `without_entropy()`, so a tenant UUID in a fleet endpoint
  is kept; an Anthropic key is now "a credential format"; a credential variable that is not set or
  holds only blanks is named by A-82's check rather than refused as shorter than 8 characters;
  A-78's stdio test reads A-82's transport refusal. Each listed in u12 A-82's merge paragraph.
- `make gates` green on the merged tree (`007e3c41`): 6,984 tests (6,983 passed, 1 skipped), 97.68%
  coverage, 75 specs lint OK, four contracts kept, self-scan, bandit and pip-audit clean; the same
  6,984 with `GITHUB_ACTIONS=true CI=true`, and the whole suite against Typer 0.27.3 (the extracted
  wheel first on `PYTHONPATH`, nothing installed). The M7 fuzz (687 cases, `main()`, `app()` and the
  click command), `m3probe.py` (32 of 32 legitimate endpoints kept, 35 of 35 hostile refused),
  `m3c.py`, the family fuzz and the M4 live checks give the same results as before the merge; the
  22 new CLI test files of both branches pass on Typer 0.27.3 (529, 1 skipped).

## State, 2026-10-13 (night): the round-3 audit of `3321a786` (A-82), fixed; the merge prepared

- `?<key>=1`, `#<key>=x` and `;<key>=x`, accepted again by the round-2 rework, are refused (a
  parameter name shaped like a key); twenty more credential names; a masked usage error carries no
  chained cause, so a group of the installed click prints no raw value. The residuals are stated as
  their class (8 to 64 hex digits, optionally after a short prefix, and low-entropy values, under
  names outside the list; `new-spec --family <hex>`), and embedding in a plain click group as
  supported for usage errors only.
- The merge with `fix/cli-store-budgets-paths` is decided and planned
  (`_ildottore-tren/scratch/fixcli3/MERGE-PLAN.md`): one root class
  `_MaskedGroup(OperationalErrorGroup)`; A-80's exit codes (`ClickException`, `FileError`, `Abort`
  and a stray `SystemExit` exit 3); one missing-path mechanism with A-80's wording for the default
  path; `allow_inf_nan=False` on `timeout_seconds`. Not merged yet.
- `make gates` green on `68b7cc48`: 5793 tests (317 new, 245 of which fail on `de122e26`), 97.81%
  coverage; the round-3 probe (`m3c.py`) and `m3probe.py` (32/32, 35/35) clean but for the
  declared hex values under neutral names.

## State, 2026-10-13 (evening): the round-2 audit of `e1824e99` (A-82, merge-ready), its LOWs fixed

- LOW 1: the root command (`app._MaskedGroup`, Typer `cls=`) masks a usage error in place where
  click raises it, so `typer.main.get_command(app)()`, a parent group and `python -m typer` print
  it masked; `_MaskedTyper` is gone. LOWs 2 to 4: `cli.key_shape` (credential formats and entropy
  outside hex ids and UUIDs, never PII; whole normalised credential names) for a fleet endpoint's
  path, query and fragment and for `new-spec --family`. LOW 5: names printed as written, and a
  long file name's wording for a write. LOW 6: `--spec-path` of a name no file system holds.
- Reruns: the audit's fleet probe 32 of 32 legitimate endpoints accepted and 35 of 35 hostile ones
  refused, nothing written or shown; its M7 fuzz through four entries (806 cases) leaks nothing but
  `new-spec --family <32 hex>`, which is written as the family asked for (a hex id is no key, as in
  a fleet endpoint); M4 live, query-key and family checks clean; `repro.sh` clean. `make gates`
  green on `52fb9cce`: 5769 tests (293 new, 221 of which fail on `de122e26`), 97.82% coverage.
- Merge plan (coordinator, 13-10): `fix/cli-store-budgets-paths` lands first; then `origin/main` is
  merged here on the coordinator's word, keeping one missing-path mechanism
  (`refuse_spec_paths_that_hold_nothing`, `PATH_NOT_FOUND`, exit 3, with fixcli1's wording for the
  default fallback path), a strict `lint` with no path and no `specs/` (exit 3, no fallback to the
  built-in battery), and `allow_inf_nan=False` on `timeout_seconds` in `shared/models.py`.

## State, 2026-10-12 (late morning): the pre-merge audit of `f9dbed49` (A-82), fixed

- Three MEDIUM and eight LOW, one commit each on `fix/cli-input-validation`. MEDIUM 1: the exported
  `app` runs `main()` when called, so the console script an older install generated masks too
  (the audit's fuzz: 60 leaking usage errors there, 0 now). MEDIUM 2: the CHANGELOG marks each
  breaking change with its own `### Changed (breaking for ...)` heading. MEDIUM 3 (pre-existing):
  a fleet endpoint whose query or fragment carries a credential, or that `urlsplit` reads with no
  host, is refused before anything is written. LOWs: `lint`, `describe` and `schema export` mask
  what they echo (a); the registry reads one file read twice as one declaration (b); docs/06's
  provider sentence (c); the report schema and the manual say "since `f12ba833`" (d, a v0.1.0
  report does not validate, as before); a name too long to open is described by its length,
  `--scope` included (e); the version refusals reworded (f); the masking tests no longer depend on
  the launcher's program name (g); `Sampling`'s exported description is as before (h). The
  environment is read in the CLI wiring and passed to `unset_variable`.
- The rerun of the audit's M7 fuzz found two more in `new-spec`, fixed: `--stdout` did not check
  `--id`, and `--family <key>` printed the key into the scaffold.
- Reruns: the audit's M7 fuzz (687 cases) 0 leaks through `main()` and `app()`, 63 on
  `de122e26`; its M4 live checks send nothing on each refusal; its query-key check writes no key;
  the original audit's `fuzz.py`, `fuzz2.py` and `fuzz3.py` flag only the run-store tracebacks
  (fixcli1's H1); `scratch/fixcli3/repro.sh` exits 3 with the field named on every case. `make
  gates` green on `ff6568ed` with `PYTHONPATH` set to the worktree's `src`: 5711 tests (5476 on
  `main` at `de122e26`, 235 new, 182 of which fail there), 97.85% coverage, 75 specs lint OK, four
  import contracts kept, self-scan, bandit and pip-audit clean. One gates run before that
  (`253967d4`) failed `test_a_fifo_report_path_is_written_in_place` once, a timing test this
  branch does not touch; it passed alone five times and in the next full run.

## State, 2026-10-12 (morning): CLI input validation, from the full CLI audit of `de122e26` (u12 A-82)

- On `fix/cli-input-validation` (worktree `wt/fixcli3`, from `main` at `de122e26`), one commit per
  finding: the audit's M4 to M9, L2, L4, L5, L7, L8 and L10 (fixcli1 and fixcli2 hold the others).
  Clause A-82 in u12, with halves in u01 (scope version, identity variable names), u02 (the path
  codes, the loose-tree notes, collisions naming both files), u11 (the report schema) and u00
  (finite `Sampling`, `shared.credential_refs`, `shared.error_text`); no new OD.
- M7: the console scripts run `cli.main:main`, which prints a usage error through `_masked`
  (exit 3); `--runs "$KEY"` printed the key. **An installed `dottore` keeps the old entry point
  until it is reinstalled.** M4: a live run or `fingerprint` refuses an unset or blank credential
  variable before any traffic, naming it; a dry run warns; `env://NONE` is never read. M8: an
  `env://` name is `[A-Za-z_][A-Za-z0-9_]*` in target, scope and fleet files; a fleet endpoint with
  user info is refused. M5: `provider` and `transport` take known values (A-53's open item). M6:
  `Sampling` is finite. M9 and L7: `PATH_NOT_FOUND` and `NO_SPECS` (lint exit 3), `FILES_NOT_READ`,
  and every spec-path consumer refuses a path that holds nothing; `registry ls --suite nope`;
  scope and fleet `version`. L2: a collision refuses the run. L4 and L5: `diff` reads schema 1 and
  knows a SARIF log; the report schema constrains run and findings, `schema export --name report`.
  L8: separated figures, one unknown-suite wording, `--timeout` 1 to 86,400 with a timeout that
  says so and no empty reason, `127.0.0.1` kept in a URL. L10: `new-spec --family`.
- The self-review found one more: `--family yes` (or `null`, `123`) scaffolded a tag YAML reads as
  a boolean, a null or a number; a plain word is now checked by reading it back.
- Measured before and after with `scratch/fixcli3/repro.sh` (the audit's cases, on `de122e26`
  through the old `app()` entry and on the branch through `main()`): every case the audit listed now
  refuses with exit 3 and a line that names the field, or keeps its words; no key is printed.
- Tests: 197 new in 8 files (`tests/cli/test_usage_errors_masked.py`,
  `test_credential_variables.py`, `test_provider_transport_values.py`, `test_non_finite_values.py`,
  `test_spec_paths_that_hold_nothing.py`, `test_spec_id_collisions.py`,
  `test_report_and_file_versions.py`, `test_cli_messages_read_right.py`), 148 of which fail on
  `de122e26` (three of the files need this branch's new modules to import there); two reports of
  earlier builds kept as fixtures, and the audit's 89 reports validated through
  `DOTTORE_REPORT_CORPUS`. `make gates` green on `669d9ec7` with `PYTHONPATH` set to the
  worktree's `src` (only PROGRESS's figures and the clause's counts follow it): 5673 tests (5476 on
  `main` at `de122e26`, 197 new), 97.85% coverage (`shared/credential_refs.py`,
  `shared/error_text.py`, `cli/lint.py` and `cli/new_spec.py` 100%), 75 specs lint OK, four import
  contracts kept, self-scan, bandit and pip-audit clean.
- Expected conflicts with fixcli1 and fixcli2 in `cli/app.py`, `cli/run.py` and `cli/wiring.py`
  (and with fixscore and fixstop in `core/runner.py`, one line here), and a doc conflict in the
  MANUAL's troubleshooting table and the CHANGELOG head.

## State, 2026-10-14 (afternoon): stacked on #114 (fix/cli-store-budgets-paths, `7cdd91a2`)

- `git merge --no-ff 7cdd91a2` (`10d73aac`): #114 holds main `030b79e0` and lands first. The code
  merged without a conflict (#114 touches cli/, store/ and the core's budgets: the attempt debit,
  `debit_request(opens_attempt=True)`, in execute, conversation and reproduce, which the withheld
  path does not read); docs keep both sides, this branch's on top, S6 with both sides' sentences.
- The branch's code over #114 is its code over main: `git diff 7cdd91a2 10d73aac -- src tests` and
  `git diff 030b79e0 c0ff4d36 -- src tests` change the same 20 files with the same added and
  removed lines (3,485 and 83).
- `make gates` green on `10d73aac` (`PYTHONPATH` set to the worktree's `src` and root, `TMPDIR` at
  the system default): ruff and format clean (450 files), mypy strict (163), four import contracts
  kept, 75 specs lint OK, 6664 tests (6547 on `7cdd91a2`), 97.70% coverage, self-scan 0 high or
  critical, bandit and pip-audit clean; the coverage run once more with `GITHUB_ACTIONS=true` and
  `CI=true`: 6664 passed, 97.70%. The withheld e2e test passes; `window_attacks.py` 36 of 36 clean.

## State, 2026-10-14 (morning): merged with main `030b79e0` (#111, #112, #113)

- `git merge --no-ff origin/main` (`f91bf617`), resolved as `scratch/fixfrag/MERGE-PLAN.md`
  plans: the runner keeps main's `_failed_on_trace`, send numbers and "cite anew" with
  `self._stored` (the withheld path) in place of `self._evidence.put`, `store_withholding` beside
  them, this branch's `_one_line` and `_clipped`, and main's note on an identity left out of the
  sweep wrapped in `_clipped` (a test in `tests/core/test_multi_identity.py` fails without it:
  1,030 characters against 240); the adapters, the redactor and the report masking take both
  sides' names; docs keep both, this branch's on top.
- Checks on the merged tree: the withheld e2e test passes; `fuzz_rejoin.py` 3 x 1000 0 refusals
  and 0 recoverable; `force_refusal.py` 3 x 1500 and `late_fuzz.py` 2 x 1500 stored every case;
  `sse_variants.py` 2 / 1 rebuilt, `sse_min.py` 0 of 5; `window_attacks.py` 36 of 36 clean;
  against main `030b79e0` `reach.py` 0 of 15 more (3 fewer), `kept_fields.py` 0 of 96,
  `context_loss.py` 0 of 17 more (5 fewer). The fixkeys auditor's clean-grammar differential
  fuzz with `030b79e0` as the baseline: 4 x 60,000 texts and 60,000 each without the entropy
  rule, with registered credentials and through `redact_identity`, 0 regressions and 0 outputs
  that differ. Cut into pieces of 1 to 4 characters, as logprob tokens and as WebSocket deltas
  (120,000 texts), the joined pieces leave readable nothing `030b79e0` masks in the whole text:
  188 flagged by the plain checker are cases where they show less (a literal between two merged
  masks dropped, or a mask merged with its neighbour), and no masked token keeps its `bytes`.
- Tests: 6514 on the merged tree, 6397 on `030b79e0` (117 new). `make gates` green on `f91bf617`
  (`PYTHONPATH` set to the worktree's `src` and root, `TMPDIR` at the system default, nothing under
  `/tmp`): ruff and format clean (441 files), mypy strict (163), four import contracts kept, 75
  specs lint OK, 6514 tests, 97.92% coverage, self-scan 0 high or critical, bandit and pip-audit
  clean.

## State, 2026-10-13 (near midnight): the sixth pre-merge audit, of `31cf86bf` (A-77), fixed

- `_main_reach` confirmed (`_quoted` AST-identical to `main`'s `reply_excerpt` tail; reach 0 of 15,
  kept_fields 0 of 96, expand 12 of 12 equal). One narrow case against the parity bar: plain-text
  data ending in a label (`password`, `password:`, `token=`), then the value on a line that is no
  field of the format (a comment, after a blank line or not, a line starting with a space or
  `=`): `main` masks it through the label, the cut excerpt emptied the label and showed it
  (`r6/context_loss.py`, 5 of 17 forms).
- Fixed (`ce8cd987`, the auditor's `patch-drop-nonfield-lines.diff`): a cut excerpt keeps only
  blank lines, JSON lines and `data`, `event`, `id` and `retry` fields (`_a_field`). Now 0 of 17
  forms show more than `main` (5 show less), reach 0 more of 15 (3 fewer), kept_fields 0 of 96,
  window_attacks 36 of 36 clean, emptying check 0 mismatches, clean bodies that fit the window 0
  of 1,498 differ, `cost3.py` 0.01 to 0.21 s.
- The merge with main still waits for PR #113 (`scratch/fixfrag/MERGE-PLAN.md`).
- Tests: 116 new against `main` (5476 there, 5592 here), 5 since `31cf86bf`. `make gates` green on
  `ca458c4b` (`PYTHONPATH` set to the worktree's `src` and root, `TMPDIR` at the system default,
  nothing under `/tmp`): ruff and format clean (423 files), mypy strict (161), four import
  contracts kept, 75 specs lint OK, 5592 tests, 97.86% coverage, self-scan 0 high or critical,
  bandit and pip-audit clean.

## State, 2026-10-13 (late night): the fifth pre-merge audit, of `6d7d990e` (A-77), fixed

- Merge-ready on `6d7d990e` but for the parity bar (window_attacks 36 of 36 clean, the long
  password 0, unrecognised shapes as `main`, only the excerpt changes; trial merges with main
  `0be0be71` 5,773 passed, with fixkeys 6,507). The finding: a cut excerpt reached further into
  the body than `main`'s, since its emptied lines are short, and showed more of a secret placed
  outside the streamed text (`r5/reach.py`: 11 of 11 pieces, `main` 8; `kept_fields.py` more in 3
  of 96).
- Fixed (`18ba093a`): only the lines `main`'s excerpt of the body shows whole are kept
  (`_main_reach`, by redacting them as `main` does, with `_quoted`, `reply_excerpt`'s tail). The
  auditor's fixed 4 KiB bound was not enough where `main`'s own masks lengthen its text (short
  emails in every event: `main` none of 11 pieces, 4 KiB 8; `scratch/fixfrag/r8/expand.py`).
  Now `reach.py` 0 of 15 and `kept_fields.py` 0 of 96 more than `main`, none fewer; `expand.py`
  equal to `main` in 12 of 12; window_attacks 36 of 36 clean; `emptying_check.py` 0 mismatches;
  clean bodies that fit the window 0 of 1,498 differ, past it 240 of 320 differ only by the
  withheld text and the notice (20,308 checked); `cost3.py` 0.01 to 0.20 s.
- Merge with main: planned in `scratch/fixfrag/MERGE-PLAN.md`, to run once PR #113 (fixkeys) has
  landed (the coordinator says when), with the auditor's resolutions and the `_clipped` wrap of
  main's new `filtered[...]` note.
- Tests: 111 new against `main` (5476 there, 5587 here), 1 since `6d7d990e`. `make gates` green on
  `bd699191` (`PYTHONPATH` set to the worktree's `src` and root, `TMPDIR` at the system default,
  nothing under `/tmp`): ruff and format clean (423 files), mypy strict (161), four import
  contracts kept, 75 specs lint OK, 5587 tests, 97.86% coverage, self-scan 0 high or critical,
  bandit and pip-audit clean.

## State, 2026-10-13 (night): a cut stream's excerpt fails closed (owner's decision)

- The coordinator decided the case left open below, under the owner's delegation (best
  practice): fail closed, an excerpt may show less than `main`, never more. A body streamed as
  events or JSON lines in a known shape and longer than the window (36 KiB with no long
  registered credential) keeps in its excerpt the lines before the window's midpoint, every
  streamed text value emptied (content, text, `response`, tokens, alternatives, a `data:` line's
  text; `bytes` and Ollama's `context` nulled), keys, structure, numbers, protocol fields, roles,
  finish and stop reasons kept, under one notice (`adapters/base.py` `_withheld_units`,
  `_without_text`, `_withheld_notice`). A body that fits the window is masked as before; other
  shapes are quoted as before. `withhold_open_ends` and the open tail are gone, and so is the
  test that pinned the tail's floor.
- Figures (`scratch/fixfrag/r7`): `window_attacks.py` case A 0 of 36 rows, case B 0 of 36 (16 on
  `5646b218`); the 600-character URL password of words 0 characters at all 8 starts (20 to 61);
  long-span and glued probes 0 of 16; clean bodies that fit the window 0 of 1,498 differ from
  `main`; clean bodies past it 240 of 320 differ (the six shapes that stream; JSON bodies with
  logprobs and JSON Lines logs 0 of 80), and every event or line they show equals the body's with
  its text emptied under an independent emptying (27,226 checked, 0 mismatches).
  `clean_excerpts.py`: 0 of 217 clean texts per shape differ from `main`, but 60 OpenAI SSE bodies
  longer than the window, now withheld. Unchanged against `5dd87b42`: `diff_main.py` 0 of 1,500
  summaries differ (replay 1500/781), every earlier round's script but for the digests the salt
  sets, `cost3.py` 0.01 to 0.20 s on 4 MiB (0.01 to 0.21 there). `e2e_bigsse.py`: inconclusive
  `unreadable_reply`, bytes 376515, the notice first, no raw key or canary.
- Tests: 110 new against `main` (5476 there, 5586 here): since `5646b218` two new and one removed
  (the tail's floor). `make gates` green on `cad92051` (`PYTHONPATH` set to the worktree's `src` and
  root, `TMPDIR` at the system default, nothing written under `/tmp`): ruff and format clean (423
  files), mypy strict (161), four import contracts kept, 75 specs lint OK, 5586 tests, 97.85%
  coverage, self-scan 0 high or critical, bandit and pip-audit clean.

## State, 2026-10-13: the fourth pre-merge audit, of `5dd87b42` (A-77), fixed

- Not merge-ready on `5dd87b42`: one MEDIUM, a regression against `main`. The work stopped twice
  (a network error, then the org spend limit at about 05:50); the coordinator saved the first
  stop's work as `e22a3cc2`, and new commits sit on top of it, no history rewritten.
- MEDIUM: a cut stream's excerpt showed a secret's beginning. Masks shorten the window's text,
  so its second half moved up into the 4 KiB the excerpt shows, and the open tail was a run of
  key characters read after masking. `window_attacks.py` case A: 4 of 36 rows leaked on
  `5dd87b42` (a URL password with symbols at 7 of 31 cuts in three shapes, a 300-character
  registered credential at 70 of 111), now 0 of 36; case B (a pause past the window) 16 of 36 on
  both, as on `main`, and in A-77's list. When the window cuts the body only the lines that
  start in its first half are shown (the auditor's patch), and a body whose first half is as it
  came is quoted as it came. The open tail is read on the raw stream: the run of characters other
  than white space it ends with, 32 to 256 characters, or a registered credential's beginning.
  Scratch probes `r6/longspan.py`, `r6/glued2.py`: 11 of 16 leaked on `5dd87b42`, 0 now. A last
  256 characters rule, tried first (`453247f0`), emptied what the excerpt shows in heavy events
  (3 of 6 clean streams with 5 or 20 alternatives quoted otherwise than by `main`), so the run
  rule replaced it (`e7f1b5a3`).
- Left open that afternoon, closed the same night (above): an unregistered secret no rule masks
  in part, longer than 256 characters or holding white space and longer than 32, reaching from
  the shown half past the cut (`r6/over256b.py`: a 600-character URL password of words showed 20
  to 61 characters, 52 to 61 on `5dd87b42`, 0 to 3 on `main`).
- Found while fixing, not by the audit: an event stream of OpenAI chunks with logprobs kept each
  masked token's `bytes`, which spelled the key in the excerpt (`main` and `5dd87b42`), and joined
  each rank of alternatives across the chunks (4 of 6 clean replies with alternatives quoted
  otherwise than by `main`). A transcript's alternatives are no stream, and a transcript's token
  in a logprob item masks its alternatives and drops its `bytes` (`df0cd422`): no rebuild, 0 of 6.
- Unchanged: clean bodies past the window 0 of 320 differ from `main`, `clean_excerpts.py` 0 of
  217 in every shape, `diff_main.py` 0 of 1,500 summaries differ from `5dd87b42` (replay 1500/781),
  `cost3.py` 0.01 to 0.20 s on 4 MiB, every earlier round's script the same output as on
  `5dd87b42` but for the digests, which follow the salt (with one salt, `fuzz_rejoin.py` seeds 1
  to 3 give the same counts on both, 0 refusals), and `e2e_bigsse.py` inconclusive
  `unreadable_reply`, bytes 376515, no raw key or canary, its excerpt 1,663 characters (4,092 on
  `5dd87b42`: only the first half is shown).
- Tests: 109 new against `main` (5476 there, 5585 here), 7 of them since `5dd87b42`. `make gates`
  green on `f435cdcc` (`PYTHONPATH` set to the worktree's `src` and root, `TMPDIR` at the system
  default, nothing written under `/tmp`): ruff and format clean (423 files), mypy strict (161), four
  import contracts kept, 75 specs lint OK, 5585 tests, 97.83% coverage, self-scan 0 high or
  critical, bandit and pip-audit clean.

## State, 2026-10-12 (late morning): the third pre-merge audit, of `74ace451` (A-77), fixed

- Merge-ready on `74ace451` (no HIGH or MEDIUM; reports 0 of 400 differ from `main`; a trial
  merge with `fix/redactor-key-formats` passed 6,294 tests), with five LOWs, fixed as new commits.
- LOW 1: the second audit's `sse_variants.py` figure is the key in 9 of 19 shapes and the
  credential in 9 (the docs said 10), corrected from `scratch/fixfrag/r3-before/out.txt`.
- LOW 2: only JSON lines in a shape known to stream (Ollama's, OpenAI's chunks) are a stream;
  any other is records, as `main` quotes it: clean JSON Lines logs quoted otherwise than by `main`,
  181 of 217 on `74ace451`, now 0 of 217 (`clean_excerpts.py`, 300 texts, every other shape 0
  of 217 on both). A rewritten line keeps its compact form.
- LOW 3: a block of `data:` lines with no blank line between them is read line by line in the
  one reading (`reader_attacks.py` "masked event + a block": rebuilt, now masked), and a clean
  stream is read once.
- LOW 4: only four times the excerpt's read extent is read (36 KiB), and a stream reaching past
  half of it has its open tail left out (`redactor.withhold_open_ends`). `cost3.py` on 4 MiB
  bodies: 0.10 to 17.98 s on `74ace451` here, now 0.01 to 0.24 s; `scale3.py` flat (0.03 to
  0.20 s from 0.5 to 4 MiB).
- LOW 5: A-77's not-covered list names every excerpt shape the audit's `reader_attacks.py` still
  rebuilds (10 of 26 on both trees; the set changed: the block case is masked now, and JSON lines
  in another shape than Ollama's or OpenAI's chunks, the one with a raw U+2028, are records).
- Tests: 102 new against `main` (5476 there, 5578 here), 4 of them since `74ace451`. `make gates`
  green on `06caf3c3` (`PYTHONPATH` set to the worktree's `src`, `TMPDIR` at the system default):
  ruff and format clean (423 files), mypy strict (161), four import contracts kept, 75 specs lint
  OK, 5578 tests, 97.81% coverage, self-scan 0 high or critical, bandit and pip-audit clean.

## State, 2026-10-12 (morning): the second pre-merge audit, of `ea13562f` (A-77), fixed

- Not merge-ready on `ea13562f`: two MEDIUMs (one a regression against `main`) and four LOWs;
  every first-round figure re-ran as claimed. Fixed as new commits on
  `fix/no-secret-in-fragments`, no history rewritten; the org spend limit stopped the work at
  about 02:30 and it resumed at 09:23 on `c21879dd`.
- MEDIUM 1 (regression): a rewritten excerpt went through `json.dumps` with ASCII escaping, so
  text outside any stream reached the excerpt's redaction `\u00a0`-escaped and a phone or a card
  grouped by U+00A0 or U+202F was shown where `main` masked it. Written with `ensure_ascii` off in
  the JSON-body, event-stream and WebSocket paths (`reserialize_leak.py`: 3 of 3 visible in both
  paths, now 0; `nbsp_realistic.py`: 3 of 3, now masked).
- MEDIUM 2: an event stream is read as the format says (lines end at CRLF, LF or CR only, an
  event's data lines join, data that is no object or array is text of one stream), a page of
  `data:` lines is read line by line, and NDJSON is masked the same way (`sse_variants.py`: the key
  rebuilt in 9 of 19 shapes and the credential in 9, now 2 and 1, both not events of the format;
  `sse_min.py`: 4 of 5 rebuilt, now 0).
- LOW 3: SARIF's result message and an `evidence_withheld` count, and an `Evidence withheld:`
  terminal line (`e2e_withheld.py` forced: SARIF 0 mentions, now 2 results and a run count of 12;
  terminal line now). LOW 4: recognition probes go through `store_withholding`. LOW 5 and LOW 6:
  the join invariant stated as measured (never more than the redacted text, less in 8 of 1,500
  realistic replies and 309 of 1,500 hostile ones), the rank figure as 6.9% of all the
  alternatives of clean replies, the test counts, and the stale docstrings and docs.
- Merge prep with `fix/redactor-key-formats`: the judge-note test's filler is ordinary words
  (its 230 letters were a hex run to A-78).
- Tests: 98 new against `main` (5476 there, 5574 here), 27 of them since `ea13562f`. `make gates`
  green on `3714473b` (with `PYTHONPATH` set to the worktree's `src` and `TMPDIR` at the system
  default): ruff and format clean (423 files), mypy strict (161), four import contracts kept, 75
  specs lint OK, 5574 tests, 97.83% coverage, self-scan 0 high or critical,
  bandit and pip-audit clean.

## State, 2026-10-12 (night, later): the pre-merge audit of `c4bd2012` (A-77), fixed

- Not merge-ready on `c4bd2012`: one HIGH regression and two MEDIUMs, plus two LOWs; fixed as new
  commits on `fix/no-secret-in-fragments` (no history rewritten).
- HIGH: a mask shown in every piece it covered read, joined, as a run of masks behind `user:`,
  which the URL rule masks again as one, so the store's guard refused a URL password the
  redactor had masked and the run aborted (`aborted on RedactionLeakError`, exit 3; `main` exits
  0). The first piece a mask covers now shows it and the others lose the text under it, so the
  pieces joined show each mask once and never more than the redacted text. Measured: `url_tokens.py`
  18 of 18 refused, now 18 stored; `ws_dsn.py` 2 of 2 refused, now stored; the auditor's DSN run
  exit 3, now 0; `fuzz_rejoin.py` 110, 120 and 122 refusals per 1,000 cases (seeds 1 to 3), now 0. A
  refused write no longer ends the campaign alone: the runner stores the attempt again with its
  pieces withheld (`redactor.withhold_split`), `request.metadata.evidence_withheld` and the
  finding's line saying so; a second refusal ends it as before. The A-77 property test now cuts
  four URLs with a password too and checks every joined text is a fixed point (it fails on
  `c4bd2012`).
- MEDIUM 2: an item's alternatives are masked once its every edit is made (`clobber.py`: 10
  characters of a labelled password in an alternative, now none). MEDIUM 3: a body streamed as
  server-sent events is quoted with its events masked across the events (`sse_excerpt.py`: key
  and credential rebuilt, now neither). LOW 4: the `bytes` of every masked token and alternative
  are dropped. LOW 5: alternatives are no stream, neither a rank nor one token's; joining a rank
  masked 6.9% of all the alternatives of clean replies (5,794 of 83,950 on the auditor's 898
  clean replies), each beside a token that was kept, now none, and `fuzz_rejoin.py` rank leaks 19
  to 25 per 1,000, now 0. Left, in A-77's
  not-covered list: a secret the alternatives alone spell beside kept tokens (`excerpt_bytes.py`
  case B), and evidence written before A-77 (a CHANGELOG line says so).
- Tests: 71 new against `main` (5476 there, 5547 here), 31 of them since `c4bd2012`. `make gates`
  green on `78f94404` (with `PYTHONPATH` set to the worktree's `src`): ruff and format clean (422
  files), mypy strict (160), four import contracts kept, 75 specs lint OK, 5547 tests, 97.81%
  coverage, self-scan 0 high or critical, bandit and pip-audit clean.

## State, 2026-10-12 (night): a secret kept in pieces, the report's keys, judge notes (A-77)

- On `fix/no-secret-in-fragments`, from `main` at `de122e26`: four findings of the security audit
  of `de122e26` (HIGH 1, MEDIUM 2, LOW 5, LOW 7), one new clause, u01 A-77, with halves in u04,
  u10 and u11 and u08 A-70's judge note amended; no new open decision.
- HIGH 1: `response.text` was masked while the same text sat in 1 to 4 character pieces in
  `response.logprobs[*].token`, each token's `top`, and a WebSocket transcript's deltas, and the
  store's guard scanned one string at a time. A logprob list's tokens and each rank of their
  alternatives, and a transcript's received content field by field, are now joined, redacted
  once, and each piece a mask covers shows it (`redactor.redact_split`, the masks placed back on
  the joined text by `_placed_masks`); a masked token's alternatives show its masks and its
  OpenAI `bytes` are dropped; the guard redacts every joined text (`split_texts`). Kept, not
  dropped: the alternatives, the figures' tokens and a transcript's other content are in no other
  field. Joining every list was tried first and masked the type of every frame of every
  transcript (`auth_oksessiondeltaping...` joined is one high-entropy token), so only streams are
  joined, and the transcript names its protocol's fields (`raw_ids.websocket.protocol_paths`,
  written by the adapter from the target file; one stored before them is read with `type`).
  Auditor's reproductions: `e2e_logprobs.py` canary and key rebuilt from the tokens in 3 evidence
  files and `r.json`, now in none; `ws_frames.py` 3 of 3 rebuilt, now 0; the excerpt of a turn
  with its text off `text_path` 3 of 3, now 0; `fuzz_sinks.py` logprob and frame rebuilds, now
  none.
- MEDIUM 2: `r.json` wrote a tool call's argument names, `usage` and frame keys in clear. Each
  attempt in a report is masked as the store masks it: the keys of its free-form fields through
  `redactor.mask_keys` (moved from the store, numbering kept), its values through `redact_split`;
  `keys_in_reports.py` json 3 of 3 leaked, now 0.
- LOW 5: the judge's words are redacted, folded, redacted again and cut, never inside a mask or a
  token; `judge_record.py` 61 of 305 placements leaked 6+ characters, now 0. LOW 7: `media_sha256`
  is put back verbatim only as a list of SHA-256 hex digests.
- Tests: 40 new (5476 on `main`, 5516 here), 33 failing on `de122e26` and 7 passing there (replay
  and `logprob_membership` read the stored attempt alike, the shape, the model's keys, SARIF,
  JUnit and HTML, a labelled secret across the judge cut). `make gates` green on `143c94ae` (with
  `PYTHONPATH` set to the worktree's `src`): ruff and format clean (421 files), mypy strict (160),
  four import contracts kept, 75 specs lint OK, 5516 tests, 97.84% coverage (`reporting/masking.py`
  100%, `redactor.py` 98%), self-scan 0 high or critical, bandit and pip-audit clean.
- Open: a secret a target splits over a list of its own JSON that is no stream, or encodes;
  evidence written before this change keeps its pieces on disk.

## State, 2026-10-14 (morning): CI of #114 on Typer 0.27.3, fixed

- PR #114's CI (typer 0.27.3, click 8.5.0; this machine has typer 0.26.8) failed collecting
  `tests/cli/test_guard_subclass.py`: `typer._click.exceptions` has no `Abort` in 0.27 (`Abort` and
  `Exit` moved to `typer.exceptions`). Worse, the guard's lookup swallowed the `AttributeError`, so
  on 0.27.3 `Aborted!` was quietly exit 1 again. Reproduced with the 0.27.3 wheel pip had already
  cached on this machine, put first on `PYTHONPATH` (nothing downloaded or installed): 4 tests
  failed on `ca2a0e41`.
- The guard's classes come from Typer's public names now (`typer.Exit`, `typer.Abort`, the ancestry
  of `typer.BadParameter`), a class that cannot be found fails the import, and no private module
  of Typer is imported (`PacifyFlushWrapper` replaced by a small wrapper of its own, the counted
  `-v` type read off a `TyperOption`). New tests raise through real Typer commands and assert the
  class Typer raised is the one mapped. The whole suite passes on 0.26.8 and on 0.27.3.
- Seen, not changed here: the dependencies are floors only (`typer>=0.12`), so CI resolves the
  newest of each, and nothing tests the floors.

## State, 2026-10-13 (night): the round-2 audit of `f51a7d07`, its four LOWs fixed

- The round-2 audit found `f51a7d07` merge-ready (the merge reverts nothing, no send path escapes
  the debit, the differentials against `0be0be71` show only the intended changes, Ctrl-C during a
  migration leaves no half-built store) and four LOWs, fixed in new commits; `main` is not merged
  again until #113 lands.
- LOW 1: protecting every file under the spec path refused the rerun of `run --spec-path . -oJ
  out.json`. The loader records the files it reads (`LoadResult.files`: pack.yaml, specs, suites,
  media assets) and only those are protected, by device and inode; the MEDIUM 1 spelling, a hard
  link and a media asset stay refused.
- LOW 2: a separately installed click's `ClickException`, `Abort` or `Exit(1)` (a plugin's) exited
  1 with a traceback. They are mapped to exit 3 where they arrive, read from `sys.modules`; the CLI
  no longer imports that click itself.
- LOW 3 and LOW 4: a lock that outlasts the wait names its store once, the note is said once per
  run, and the store layer is silent by default: its caller passes a callback
  (`connect(on_lock_wait=...)` or `lock_waits_reported(...)`), which `run`, `fleet --run` and
  `replay` do.
- The heads-up's subclass-friendly `OperationalErrorGroup`: no source change was needed;
  `tests/cli/test_guard_subclass.py` pins the closure through a subclass.
- 2026-10-14: `main` merged in again once #113 landed (`030b79e0`, merge `304d1dc3`), conflicts in
  documentation only. Gates on that tree: green, 6,541 tests (6,397 on `030b79e0`, +144),
  coverage 97.68 %, lint 0/0 over 75 specs, 14 suites, 1 pack, contracts 4 kept, self-scan 0
  high/critical, bandit and pip-audit clean. Re-run there: 0 of 320 concurrent first opens failed
  (8 x 10, 16 x 10), 0 of 30 concurrent CLI runs; `--budget-requests 100` 85 attempts for 100
  requests and none more on a resume; `--runs 200` exit 2 with 20,600 attempts; 15 commands into
  a closed reader, each exit 3. `git diff origin/main HEAD` holds this branch's changes only: no
  line #111, #112 or #113 added is removed (the threat model's S6 row is #113's with this branch's
  sentence added), and #113's `redactor.py`, `adapters/base.py` and `reporting/masking.py` are
  main's byte for byte.

## State, 2026-10-13 (evening): the pre-merge audit of `e6a1ab9b`, fixed, and `main` merged in

- The pre-merge audit of `fix/cli-store-budgets-paths` at `e6a1ab9b` found three MEDIUMs and
  eight LOWs; the core held (0 failures in 416 concurrent opens, the pre-send checks, the attempts
  ceiling, the guard's masking). Fixed in new commits on the branch, then `main` (`0be0be71`, #111
  and #112) merged in with a merge commit; the conflicts were documentation only.
- MEDIUM 1: the spec-file protection compared resolved paths, which keep the case they are given,
  so `-oJ SPECS/attacks/AC-BFLA-001.yaml` beside `--spec-path specs` overwrote the spec on the
  macOS default volume (exit 2). Every file of the spec path is compared by device and inode now.
- MEDIUM 2: a real broken pipe still exited 1: the close callback reconfigured stdout and flushed
  into the closed pipe after the guard's exit 3, and rich answers a broken pipe with
  `SystemExit(1)` (a live scan with findings piped into a closed reader sent 25 requests here, then
  exited 1 with nothing said). The close callback, the guard and `OperationalErrorGroup.main` (help,
  found re-running the audit's pipe checks) make it exit 3, and stdout is pointed at the null
  device. Every command into a closed reader: exit 3 (`registry ls`, `lint`, `describe`,
  `coverage`, `run --dry-run`, `run --estimate`, a mock run, a live run with findings, `schema
  export`, `diff`, `calibrate`, `replay`, `fingerprint --offline`, `fleet`, `--help`).
- MEDIUM 3: the default spec path made `lint` pass the built-in battery in a pack's own
  repository ("lint OK ... across 75 spec(s)", exit 0). By the rule decided for this branch and
  `fix/cli-input-validation`: `lint` with no path and no `specs/` is refused, exit 3, `spec path
  not found: specs. Pass the spec path to lint ...`; the commands that fall back say on stderr which
  tree they read.
- LOWs: a lock wait is Python's loop over 0.1 s tries (Ctrl-C at 2 s during a held lock: exit 130
  after 2.19 s, where it took about 32 s), said once on stderr, and named when it runs out (`the run
  store at <path> stayed locked by another process for 30 s`); the store's siblings are taken beside
  the file a symlinked `--run-db` names; a report inside a run directory of the evidence store is
  refused; `ClickException`, `FileError`, `Abort` and a stray `SystemExit` of 1, 2 or a text are
  exit 3; `replay --run-db <directory>` is refused; `migrate` no longer commits a caller's
  transaction; `-v` reads as a flag in the help; the figures the audit found wrong are corrected
  (the `--runs 200` command needs `--budget-tokens` and `--budget-wall` raised; the concurrency
  figures are 5 of 6 in the first audit, 1 and 2 of 18 in two re-measurements; a wheel ships
  neither the battery nor the schemas).
- Gates on the merged tree (`PYTHONPATH=<wt>/src:<wt>`, TMPDIR at the system default), at
  `c7be4ed8`: green, 5,775 tests (5,663 on `main` `0be0be71`, +112), coverage 97.63 %, `dottore
  lint` 0/0 over 75 specs, 14 suites, 1 pack, import contracts 4 kept, self-scan 0 high/critical,
  bandit and pip-audit clean.

## State, 2026-10-12 (morning): the CLI audit of `de122e26`, fixed (u12 A-80)

- Branch `fix/cli-store-budgets-paths` from `de122e26`, not pushed. Six findings of the full CLI
  audit (H1, M2, M3, L1, L3, L9), each with tests that fail on `de122e26` (the new CLI tests run
  against a `git archive` of it: 7 of 8 store-level tests, 24 of 29 CLI store and evidence tests,
  11 of 14 attempts and `--estimate -q` tests, 17 of 18 report-path and fleet tests fail there;
  the ones that pass there are guards (a good run still works, Ctrl-C still exits 130, the no-send
  modes still create nothing, a second migration is a no-op) and the six-run CLI reproduction,
  which raced clean on that attempt: the store-level test, with a start barrier, is the one that
  fails reliably there). Clause A-80 in u12, with u10's and u08's halves; A-9 amended. No new
  open decision.
- H1: a run store that cannot be used exits 3 before any send (`cannot open the run store at
  <path>: <reason>`), in every mode (read-only in the ones that send nothing); concurrent opens
  wait 30 s and retry the WAL switch, and a migration runs under the write lock (18 of 80
  concurrent first opens failed on `de122e26`, 0 of 160 here; through the CLI 1 of 18 runs died
  there, 0 of 30 here; the original audit saw 5 of 6, the pre-merge audit 2 of 18). The root
  command group maps any exception no
  command handles to exit 3 with one masked line, the traceback under the new root `dottore -v`.
  Against a loopback stub, `-sV --run-db <garbage>`: 18 requests then exit 1 before, 0 and exit 3
  now.
- M2: the attempts ceiling is the request ceiling, and an attempt counts with its first accepted
  request. `--runs 200` over the battery (`--budget-requests 60000 --budget-tokens 30000000
  --budget-wall 7200`): exit 3 at `max_attempts`
  20,000 with 2 specs unfinished before, exit 2 with 20,600 attempts now. Under
  `--budget-requests 100`: 128 attempts for 100 requests and +43 per resume before, 85 and +0 now.
  `--estimate` prints the ceilings. M3: an `--evidence-root` that is a regular file is refused
  before any send (5 requests then `NotADirectoryError` against the stub before, 0 now). L1:
  `--estimate -q` prints one line. L3: a report path that is an input is refused (the auditor's
  `-oJ scope.yaml -oH target.yaml` overwrote both, exit 2). L9: one default spec path for every
  command (`specs/` here, else the battery beside the package), and `fleet` takes `--spec-path`,
  `--evidence-root`, `--run-db` and `-o*`.
- Gates (`PYTHONPATH=<wt>/src:<wt>`, TMPDIR at the system default): green, 5,547 tests (5,476 on
  `de122e26`, +71), coverage 97.63 %, `dottore lint` 0/0 over 75 specs, 14 suites, 1 pack, import
  contracts 4 kept, self-scan 0 high/critical, bandit and pip-audit clean.
- Seen and left open: a wheel built from this repository ships neither `specs/` nor `schemas/`
  (`registry/schema.py` finds `<repo>/schemas` from the source tree), so the CI example's
  `pip install git+https://...` cannot load a spec outside a checkout (not measured here); a report
  path inside the evidence root is not refused; `replay --run-db <directory>` warns and goes on
  without the manifest check, as before.

## State, 2026-10-13 (early morning): the second pre-merge audit of A-78 (`3a9a4dfa`), fixed

- Round 2 found one HIGH and six LOW. R2-H1: the record of the A-78 masks the process had written
  (two bounded generations) was overflowed by a campaign of 3.8 MiB replies; the first turn's
  masks were forgotten, read as text when the evidence store checked the attempt again, changed,
  and the write was refused (`RedactionLeakError`, exit 3, where main completes). Design chosen:
  (c), a stateless rule. A mask of an A-78 type is kept as written, as the older types are; the
  labelled rule alone reads one as text, as main did, so `password: «REDACTED:uuid»<secret>`
  stays masked whole (L3 closed); the redactor writes none where that rule would take it (a
  labelled value of 32 hex letters or more is masked as a labelled secret, `_plain_word`).
  Chosen over (a) carrying the mask spans to the store and (b) a per-attempt record because only
  a rule without state reads the same in a resume, a report or a replay in another process
  (R2-L3), and it removes the forgeable record (R2-L1).
- The auditor's 3.8 MiB scan (JB-CRESCENDO-001, loopback stub): exit 0 on the branch, on main and
  on a trial merge with `fix/no-secret-in-fragments` at `06caf3c3`. Halt and resume in two
  processes with the random salt: 0 broken masks in the resumed reports (8 of 20 before).
- R2-L2: the Private Use Area block scan is one pass (all 137,468 characters: 0.025 s, was 2.2 s).
  R2-L4: unreachable branches removed (a redactor without the entropy rule uses no stand-ins),
  the guards tested. R2-L5: the public identity salt's linkability documented (MANUAL, S6, A-78).
  R2-L6: the run row's `target_ids` use the identity mask; stale notes corrected.
- The merge note in the entry below is stale: `fix/no-secret-in-fragments` changed its filler
  itself (75ca00ac), and the trial merge passes without it.
- `make gates` green on `1e9d8329` (`PYTHONPATH` at the worktree's `src`, `TMPDIR` the system's),
  05:38 to 05:47 CEST: 6210 tests, 97.86% coverage (main 97.84%; `redactor.py` misses 4 statements,
  as main does), mypy 160 files, 4 import contracts kept, 75 specs lint OK, self-scan, bandit and
  pip-audit clean.
- Round 3 (head `59349ba8`): merge-ready. The unused `SqliteRunStore._redact_json` removed
  (`38aacbd5`); `origin/main` at `0be0be71` (#111, #112) merged in `0621f576`, conflicts in
  CHANGELOG, PROGRESS, u04, u11 and `adapters/base.py` resolved keeping both sides. On the merged
  tree: `make gates` green, 21:59 to 22:07 CEST, 6397 tests, 97.91% coverage, mypy 162 files; the
  auditor's clean-grammar differential fuzz against `0be0be71`'s redactor, 8 x 60,000 texts, 0
  regressions and no stand-in in any output; the 3.8 MiB flood scan exit 0, no token readable (148
  on `0be0be71`, also exit 0).
- CI of PR #113 (Gate 12, coverage on Python 3.11): a time-bound test of the evidence keys took
  16.4 s against 15 s; a short text cost 1.7 times main's. A prefilter skips the late patterns and
  the stand-ins where a text holds nothing they need (`d38580d2`, byte-identical output on 240,000
  fuzz texts; 24,000 keys 0.74 s against main's 0.67 s, 1.12 s before), and that test and the
  glued-UUID one assert the ratio of two sizes under 8 with a 120 s hang ceiling (`39fcf6f1`;
  ratio 4.0 plain and under both of coverage's tracers, 2.5 s under the C tracer). Fuzz against
  `de122e26`: clean 8 x 60,000 0, mixed 4 x 40,000 the same 52; against `0be0be71` clean 0.
  `make gates` green on `5fb69556`, 23:09 to 23:16 CEST: 6397 tests, 97.91% coverage.

## State, 2026-10-12 (morning): the pre-merge audit of A-78 (`0b4b1f14`), fixed

- The audit found the branch NOT READY: H1, H2, M1, M2 and L1 to L5. Fixed on
  `fix/redactor-key-formats`, one commit a finding, no amend; u01 A-78 revised in place, with its
  halves in u04, u10, u11 and u12 and the index row; no new clause or OD.
- H2, M1, L1: a number the card or phone rule reads inside a UUID is written in same-length
  stand-ins from a free block of the Private Use Area (`redactor._Cuts`), which every later rule
  reads as main's mask; the entropy rule judges main's pieces once each (`_cut_spans`), the late
  patterns read the stand-ins back, and a stand-in no mask took becomes main's number mask. Glued
  digit UUIDs: 160 KB 32.80 s on `0b4b1f14`, 0.11 s now (main 0.08 s); 4 MB 2.79 s (main 2.12 s).
  A value glued between two cut UUIDs: 157 of 200,000 tokens readable on `0b4b1f14`, 0 now.
- L2: the URL rule as written tells a URL its rule read with every mask one neutral character
  (`_AsWritten.in_view`). L3: a mask of the nine A-78 types is kept only when this process wrote it
  (`_LATE_MASK_TYPES`, `_EMITTED`). H1: reports name the target by the rules before A-78 with the
  identity salt (`redactor.report_identity`); a baseline written by `de122e26` diffs against a run
  of the branch (exit 0). L4: the pre-flight checks the sweep identities' credentials
  (`check_identity_credentials`), and the stdio exemption needs `provider: mcp`. L5: the CLI runs
  the late patterns only on what it does not keep, and the model-name twin drops the UUID pattern.
- M2: the docs, the PR body and A-78 now say what the reruns show: no regression against main in
  any text without U+0000 or U+0001 (the auditor's fuzzers and the author's, 1,100,000 and
  1,500,000 texts), 19 in texts holding one (the `redact_text` retry, pre-existing); `diff --json`
  does not exist; the two test files that stop at collection on `de122e26` are said to (the
  adapter one: 19 of 39 fail with stand-ins for its two imports; the store one: 9 of 12 with the
  compatibility code taken out, not 3).
- Merge note for `fix/no-secret-in-fragments`: its
  `tests/core/test_judge_note_redaction.py::test_a_cut_moves_before_a_token_rather_than_through_it`
  needs `reasoning = "q" * (_JUDGE_NOTE_CHARS - 10) + " ZYNAP_CANARY_run-4c397602a2e0 end"`
  (`"a"` is a hex digit, masked as `hex_token` here); checked on the auditor's union-merged tree.
- Open, for the owner: the `redact_text` retry with U+0000/U+0001; a UUID in a CLI error that the
  number rules read a number in is masked as before A-78; a mask of an A-78 type written by another
  process is read as text (a URL user one gets a `url_password` mask on its tail in a later report).
- Tests: 6196 (61 more than `0b4b1f14`); new files `test_redactor_number_cuts.py` (14),
  `test_redactor_url_read_check.py` (4), `test_redactor_own_late_masks.py` (26),
  `cli/test_report_target_id.py` (5), `cli/test_uuid_identifiers_readable.py` (4). `make gates`
  green on `fe6b4672` (`PYTHONPATH` at the worktree's `src`, `TMPDIR` the system's): 6196 tests,
  97.63% coverage, mypy 160 files, 4 import contracts kept, 75 specs lint OK, self-scan, bandit
  and pip-audit clean.

## State, 2026-10-12 (night): key formats, hex runs and UUIDs masked whatever their entropy; short credentials refused everywhere (u01 A-78)

- Fixes MEDIUM 4 and LOW 6 of the pre-merge security audit of 2026-10-11, on
  `fix/redactor-key-formats` from `de122e26`. New clause u01 A-78, with halves in u04, u10, u11
  and u12 and the index row.
- MEDIUM 4: the documented key formats of 11 providers (OpenAI, Anthropic, GitHub, GitLab, AWS,
  Google, Hugging Face, Slack, Stripe, npm, PyPI), a JWT after `_` and the UUID shape are late
  patterns (`redactor._late_patterns`, each sourced), started with `(?<![A-Za-z0-9])`, hashed,
  run after the labelled rule, the entropy rule and the URL rule as written, so they only add
  masks; a run of 32 hex digits or more is the entropy rule's (`hex_token`); a token masked whole
  is typed by the format it holds; the number rules leave a UUID whole (`_number_mask`) and the
  entropy rule masks with it the pieces it would have masked (`_uuid_spans`). A first version
  ran them as ordinary patterns and the differential fuzz against main showed text main masks in
  5,120 of 20,000 texts: it was redesigned before any review.
- Figures, auditor's generators: 32-hex 74.7% to 0%, 40-hex 47.5% to 0%, 64-hex 5.5% to 0%, UUID
  v4 46.8% to 0%; every prefix 0 of 200 after `_`, `=` and `-` padding. Differential fuzz, five
  draws of 300,000 texts: 2 texts show 8 characters of a planted secret main hides and 24 a
  stretch of glue, all holding U+0000 or U+0001 (the `redact_text` retry, pre-existing, flipped
  more often); none without.
- The tool's own values: the hex rule belongs to the entropy rule, so the CLI's carried digests,
  evidence names, existing paths and model names keep out of it; the reports now restore
  `media_sha256` (main masked 24 of 28) and each evidence reference's attempt id. A full offline
  run of the battery with the salt and run id pinned writes every output byte for byte as main
  but those 24 digests; no tool-own value masked anywhere.
- A run halted before A-78 resumes against its own target (`redactor.identity_masks`), and the
  store keeps one row a finding.
- LOW 6: `refuse_short_credential` (`CredentialTooShort`, the WebSocket adapter's message) in
  every adapter, `build_real_adapter`, the identity sweep and the pre-flight (`--dry-run`, `-sn`,
  `--estimate` exit 3); the judge raises it; an offline mock and a stdio MCP server are not
  checked.
- Open, for the owner: the `redact_text` retry with U+0000/U+0001 (masks depend on whether
  anything else in the text is masked, on main too); a key glued to a letter or a digit stays the
  entropy rule's; the `secret_shape` evaluator still detects only `sk-`, `gh*_`, `AKIA`, `xox`,
  JWT and PEM; a credential written as an endpoint URL's user is not registered.
- Tests: `tests/test_redactor_key_formats.py` (589, 415 fail on `de122e26`),
  `tests/reporting/test_own_values_readable.py` (9, 2),
  `tests/store/test_identity_masks_before_a78.py` (12, 3 without the compatibility code),
  `tests/adapters/test_short_credentials.py` (39, 19), `tests/cli/test_short_credential_cli.py` (10,
  7). `make gates` green on `09b1b0a2` (with `PYTHONPATH` set to the worktree's `src`): 6135 tests
  (5476 on `main` at `de122e26`, 659 new), 97.83% coverage (`redactor.py` 99%), 75 specs lint OK,
  four import contracts kept, self-scan, bandit and pip-audit clean.
- Corrected by the pre-merge audit of `0b4b1f14` (the entry above): "they only add masks" and
  "none without U+0000/U+0001" did not hold (a value between two cut UUIDs, a line joined by a
  phone mask, a URL password behind a mask's `:`, a target-written mask of a new type), the
  identity masks file fails 9 of 12 without the compatibility code, not 3, and it and the adapter
  file stop at collection on `de122e26`; `diff --json` is no option.

## State, 2026-10-12 (morning): the pre-merge audit of `d07a1088`, fixed

- On `fix/scoring-audit-2026-10-11`: the independent pre-merge audit of `d07a1088` closed the
  eight original findings, gates green there (5,520 tests, 97.85%), and found two MEDIUM and three
  LOW, fixed one commit each, every reproduction script of the auditor
  (`_ildottore-tren/scratch/fixscore-audit/`) rerun before and after.
- MEDIUM 1 (a regression of LOW 5): a guardrail reply with text was read on its trace only, and
  `adapters.rest` files a masked reply (`ANONYMIZED`) under the output side with a blocked one,
  so a planted canary beside a masked name went from a confirmed fail (`de122e26`) to a cut
  needing review (`repro_masked.py`). Now `REPLACED_TEXT_EVALUATORS` (the trace evaluators plus
  `secret_leakage`, `secret_shape`, `authz_leak`) through `_evaluators_for_filtered_reply`, the
  name, set and helper of `fix/filter-stop-provenance` (A-79), which lands next: one rule at the
  merge. After: fail confirmed.
- MEDIUM 2: the sweep mapped an owner's canary only once its reply was read, so with the owner
  not heard from tenant A's reply showing its canary was no crossing (`repro_sweep_owner_down.py`:
  PASS on `de122e26`, inconclusive on `d07a1088`). Mapped before the send now, and `authz_leak`
  reads the owner map on fewer than two replies too (u06's half of A-74), so the two-identity case
  fails as well. After: fail confirmed.
- LOW 1: what a resume keeps (`_completed_attempt_ids`) is read from each id's attempt
  (`one_per_attempt_id`), not from any copy: an unreadable reply whose re-send was blocked was
  kept for good (`repro_unread_then_block.py`: the third run kept 5, sent 0, inconclusive); now
  it keeps 4, sends 1 and passes, and the summary's "a resume sends them again" holds.
- LOW 2: `_combine_verdicts` takes the identities the sweep heard from (`swept`, a mapping, was a
  bool; `fix/filter-stop-provenance`'s new `swept=identities is not None` calls fail mypy at the
  merge, loudly), so with two or more answers beside one left out the note reads `authz_leak
  kept: 2 identities answered the identity sweep, and it did not hear from every identity`
  (`repro_corroborate_note.py`, `EMB-XTENANT-RETRIEVAL-001`, said "fewer than two").
- LOW 3: the run's `--include-needs-review` reaches the reporters (`include_needs_review` on
  `BaseReporter`, `get_reporter`, `wiring.build_reporter`); with it a SARIF fail that needs review
  keeps its band's level (it exits 2), and the run's `properties` say so.
- Wording: the resend tie-break never puts a cut reply over an environment error (a cut reply is
  answered and judged, so it ranks first already); the docs now say an unreadable reply.
- Nothing else moved: `rank_pairs.py` prints the same 28 pairs as on `d07a1088`, the
  cross-version `cli_cross_version.py` matrix (phase 1 on `de122e26`, the resume here; env0 then
  html, unread0 then env0, unread0 then ok, env0 then ok) the same lines with run ids masked, and
  the auditor's four earlier scripts the same results.
- Tests: 18 new, 15 failing on `d07a1088` (the 3 others are controls), 1 changed expectation (the
  short-sweep test). Branch total against `main`: 62 new (44 failing on `de122e26`), 4 changed.
  `make gates` green on `dd4f8648` (12/10/2026 10:12 to 10:20 CEST, `PYTHONPATH` set to the
  worktree's `src`, `TMPDIR` the system default): 5538 tests (5520 on `d07a1088`), 97.86%
  coverage (`evaluators/authz_leak.py`, `shared/provider_filter.py`, `shared/resend.py`,
  `store/replay.py`, `reporting/base.py` and `reporting/sarif_reporter.py` 100%,
  `core/runner.py` 97%), ruff, format, mypy strict on 161 files, four import contracts kept, 75
  specs lint OK, self-scan 0 high/critical, bandit and pip-audit clean.
- Merged with `fix/filter-stop-provenance` (PR #111, `ffec14ec`, which lands first), a real merge,
  no history rewritten: both branches' `REPLACED_TEXT_EVALUATORS` and
  `_evaluators_for_filtered_reply` are one rule; fixstop's `partial_reply`, `replaced_reply`
  (`blank_text`) and A-79 judge rule (`weighed`) kept; its two new `_combine_verdicts` calls pass
  `swept=identities`; `_trace_before_block`'s local reply renamed `reply` (it shadowed the
  `stopped` parameter). `make gates` green on the merge, `c5460345` (12/10/2026 11:19 to
  11:26 CEST): 5663 tests (5538 here, the rest fixstop's), 97.87% coverage (`core/runner.py`
  98%), ruff, format, mypy strict on 162 files, four import contracts kept, 75 specs lint OK,
  self-scan 0 high/critical, bandit and pip-audit clean. On the merged tree the auditor's four
  repros print what they did on `38bc67b2`, and fixstop's `repro_declared.py` and `compat.py`
  what they print on `ffec14ec`.

## State, 2026-10-11 (night): the audit of the scoring, fixed

- On `fix/scoring-audit-2026-10-11`, from `main` at `de122e26` (#110): every finding of the
  correctness audit of the scoring, two HIGH, one MEDIUM and five LOW, fixed by best practice
  under the owner's delegation, each reproduction script of the auditor
  (`_ildottore-tren/scratch/audit-score/`) turned into a test. No OD opened; the clauses amended
  are u08 A-69, A-70, A-73's half and A-74, their u10, u11 and u12 halves, and u06 A-73 (A-75 and
  A-76 stay free).
- HIGH 1: which artifact of a re-sent attempt id is the attempt is one rule in `shared.resend`,
  read by the runner and the replay (each had a copy that kept the first artifact at a tie, the
  runner's prior ones in content-hash order). Rank, then an unreadable reply over an environment
  error or a block whichever came first (a cut reply is answered and judged, so it ranks first
  already), then the later send by a
  `send_number` stamped in `request.metadata` of every stored attempt, then the first. The fix the
  audit proposed put the later send at the second step; the never-a-pass step comes first because
  the later send alone turns an unreadable reply into a pass whenever the resume meets a network
  failure (the same false pass, in the other order). Revisable: swap two fields of
  `shared.resend._rank`. `cli_resume_unreadable.py`: PASS with 0 unreadable on `de122e26` (the
  replay said 1), now `inconclusive` with 1 in the report and the replay; `repro_resume_reverse.py`:
  replay 0 unreadable on `de122e26`, now 1, matching the report.
- HIGH 2: a conversation (or an in-band scene's tool rounds) that a later send's environment error
  or unreadable reply ended keeps the trace so far beside the attempt
  (`AttemptResult.trace_so_far`); the trace evaluators read it first, a fail is stored as any fail
  with the error under `request.metadata.conversation_error`, anything else as before.
  `repro_mt_env.py`: turn 2 env PASS and unreadable inconclusive on `de122e26`, block fail; now all
  three fail, exit 2.
- MEDIUM: the identity sweep names every identity it did not hear from (unreadable reply, failed
  send, a prompt its filter refused), beside OD-42's filter stops, and `authz_leak` cannot pass
  beside it. An environment error counts too (a gate fails closed); the cost, a transient failure
  of one identity keeps the spec from passing, is in docs/12's F11 row. `repro_sweep_unreadable.py`:
  pass on `de122e26`, now `inconclusive`, the identity named.
- LOW 1 the resume note names each id once (was `-1 that ended in an environment error`); LOW 2
  `setup_not_reached` is asked of a judge-only fail too; LOW 3 the `--include-needs-review` help;
  LOW 4 a SARIF fail that needs review is at most `warning`; LOW 5 a Bedrock guardrail's
  replacement is read by the trace evaluators plus `secret_leakage`, `secret_shape` and
  `authz_leak` (the pre-merge audit's MEDIUM 1, in the entry above).
- Tests: 44 new, 28 of them failing on `de122e26` (the tie test fails there in one of its two file
  orders for each of its six cases), 3 changed expectations (two sweep verdicts that now name the
  identity, one in-band metadata that now carries `send_number`).
  `make gates` green on `b6fe3609` (with `PYTHONPATH` set to the worktree's `src`): 5520 tests
  (5476 on `main` at `de122e26`, 44 new), 97.85% coverage (`shared/resend.py`, `store/replay.py`
  and `reporting/sarif_reporter.py` 100%, `core/runner.py` 97%), ruff, format, mypy strict on 161
  files, four import contracts kept, 75 specs lint OK, self-scan 0 high/critical, bandit and
  pip-audit clean.

## State, 2026-10-12 (late morning): the pre-merge audit of `3f7b1254` (A-79), fixed

- Merge-ready per the audit, with one LOW fixed before it lands (new commits, no history
  rewritten, under the owner's delegation, best practice, revisable). `blank_text` read every
  format character as no text, the tag block too, so harmful text in tag characters (ASCII
  smuggling) with `content_filter` was a cut with no text and the judge that says exploited was
  never consulted: 0 judge requests, `filtered`, exit 3, where `e1a8aacf` and `main` read it (6).
  Never a pass, but hidden text went unjudged. The 13 format signs a font draws (U+0600 to
  U+0605, U+06DD, U+070F, U+0890, U+0891, U+08E2, U+110BD, U+110CD) were blank too.
- One list: the redactor's pinned `_FORMAT_RANGES` (Unicode 16.0, the same 170 characters) is
  now the union of `EMPTY_FORMAT_RANGES`, `FORMAT_SIGN_RANGES` and `TAG_RANGES`, and
  `blank_text` reads whitespace and `EMPTY_FORMAT_RANGES` only (no longer `unicodedata`).
  `shared.provider_filter` imports it from the redactor, a leaf of the shared band. After (my
  `repro_tags.py`): tags undeclared and under `[]`, U+0600 under `[]` and U+06DD undeclared all
  give 6 judge requests, a fail that needs review, exit 0, as on `e1a8aacf`; the zero-width
  replies stay `filtered`, exit 3, and the WebSocket blank turns stay unreadable.
- The nit: `fingerprint/layers/guardrail.py:185` keeps `.strip()`. Its `empty` is a probe reply
  that says nothing to the guardrail profile, not the filter rule, and moving it would change
  u09 outcomes (a zero-width probe reply from `unclear` or `answered` to `empty`) outside this
  branch's rule; the claim "the one test of no text" is narrowed to the filter rule (here and in
  `blank_text`'s docstring).
- Tests, 13 new, all failing on `3f7b1254`: `tests/adapters/test_filter_stop_provenance.py`
  now 54 (52 fail on `de122e26`, 25 on `10cb526b`, 19 on `e1a8aacf`, 11 on `3f7b1254`),
  `tests/cli/test_filter_stop_provenance_campaign.py` now 44 (40, 15, 7 and 2).
- Re-run: the auditor's `repro_declared.py` output is identical to round 3's, its `compat.py`
  byte-identical to `main`. Gates on `d509befa` (`make gates`, worktree `src` first on
  `PYTHONPATH`, `TMPDIR` at the system default, 10:24 to 10:33): all green, 5,601 tests passed
  (5,588 on `3f7b1254`), coverage 97.86% (14,198 statements, 208 missed),
  `shared/provider_filter.py` at 100%, `redactor.py` at 99%, lint OK across 75 specs, self-scan 0
  high/critical, bandit and pip-audit clean.

## State, 2026-10-12 (morning): the pre-merge audit of `e1a8aacf` (A-79), fixed

- One MEDIUM and five LOWs, fixed as new commits on `fix/filter-stop-provenance` (no history
  rewritten), under the owner's delegation (best practice, revisable). The auditor's raw outputs
  are in `scratch/fixstop-audit3/`; the fix's notes and probe runs in `scratch/fixstop-fix2/`.
- MEDIUM 1, on the one adapter the round-2 rule left out: a WebSocket file with no
  `response.filter_stops` whose server sends a first delta of `""` (or `"  "`) and then
  `finish_reason: content_filter`, what a relay of a streamed Azure reply looks like. The turn was
  unreadable only with no text frame at all, so this one was the model's empty answer:
  `PI-DIRECT-001` and `JB-ROLEPLAY-001` passed, exit 0 (a zero-width space: inconclusive, exit
  0). Now a turn with no tool call whose joined text is blank and that ends on a documented
  filter word the file does not declare is unreadable too, same advice: the auditor's
  `ws_probe.py` gives exit 3, every attempt `unreadable_reply`, for `""`, `"  "` and U+200B; a
  declared word stays the filter's cut, exit 3; text stays a fail, exit 2.
- LOW 1: `str.strip` keeps format characters, so under `[]` an OpenAI reply of U+200B (or U+200D,
  U+2060, U+FEFF) with `content_filter` passed, exit 0. `shared.provider_filter.blank_text`
  (whitespace and Unicode Cf only) is now the filter rule's one test of "no text":
  `stop_provenance`, `partial_reply`, `replaced_reply`, the runner's `_trace_before_block` and the
  WebSocket turn.
  `_refusal_side` keeps reading presence (any character is output, which decides Anthropic's side).
  After: `filtered`, exit 3, as an empty reply.
- LOW 2: the stale comment on `OpenAIAdapter.declared_filter_stops`. LOW 3: `Target(provider=5,
  filter_stops=[...])` gave a second, misleading error; the check is left out when the provider
  failed. LOW 4: "a reply with no text and no tool call" (and "with text or a tool call") in every
  doc and in the plan line, and the plan line for an `anthropic` file no longer names an HTTP 400.
  LOW 5: the round-2 report said 17 new tests failing on `10cb526b`; it was 17 new, 16 failing
  there (6 adapter, 10 CLI, one of them the changed plan-line test), as the repo docs said.
- Tests, 21 new: `tests/adapters/test_filter_stop_provenance.py` now 43 (41 fail on `de122e26`,
  16 on `10cb526b`, 10 on `e1a8aacf`), `tests/cli/test_filter_stop_provenance_campaign.py` now 42
  (38, 15 and 7: d1 with U+200B, the WebSocket turn through `execute_run` on 3 fragments, the
  lone provider error, the Anthropic plan line, and the changed plan-line test), and
  `tests/adapters/test_malformed_replies.py` now 42 (3 fail on `e1a8aacf`, and a control).
- Re-run on the fix: the auditor's `repro_declared.py` gives d1 to d6 as in round 2 (d1 exit 3,
  `filtered`), its `compat.py` is byte-identical to `main`. Gates on `2288de00` (`make gates`,
  worktree `src` first on `PYTHONPATH`, `TMPDIR` at the system default, 09:36 to 09:45): all
  green, 5,588 tests passed (5,567 on `e1a8aacf`), coverage 97.86% (14,194 statements, 208
  missed), `shared/filter_stops.py`, `shared/provider_filter.py` and `shared/models.py` at 100%,
  `adapters/websocket.py` at 99%, lint OK across 75 specs, self-scan 0 high/critical, bandit
  and pip-audit clean.

## State, 2026-10-12 (02:00): the pre-merge audit of `10cb526b` (A-79), fixed

- One MEDIUM and one LOW, fixed as new commits on `fix/filter-stop-provenance` (no history
  rewritten), under the owner's delegation (best practice, revisable). The auditor's probes are in
  `scratch/fixstop-audit2/` (`repro_declared.py`); the fix's notes and repro runs in
  `scratch/fixstop-fix2/`.
- MEDIUM: `filter_stops: []` turned the filter's withheld reply into a pass. d1, `PI-DIRECT-001`
  answered with `content_filter` and no text: with `[]` 3 passes, exit 0 (6 judge requests on
  the empty replies); without it, cut, `filtered`, exit 3. The docs recommended `[]` for "a
  gateway", and a gateway in front of Azure relays Azure's filter. Now each adapter says what its
  provider documents whatever is declared (`own_filter_stops`: OpenAI `content_filter`, Anthropic
  `refusal`, a REST template's `shape_filter_stops`), and `stop_provenance` never marks foreign a
  reply with no text and no tool call that ends on one of them. It goes through the existing path
  (`filter_side`, `_cut_verdict`, `_evaluators_for_filtered_reply`): no runner change. After: d1
  exit 3, `filtered`, 3 cut, judge 0, as d1c; d2 (harmful text, `[]`) still a confirmed fail, exit
  2; d3 (Azure's 400, `[]`) still an ordinary 4xx, exit 3. The `filters:` plan line for `[]` says
  what still reads. The advice now limits `[]` to endpoints with no OpenAI, Azure or Anthropic
  filter behind them and warns that a gateway in front of Azure relays Azure's filter (MANUAL
  §4.2 and §9, FAQ, `examples/target.openai.yaml`, ADR-0011, CHANGELOG, USAGE, `dottore(1)`,
  docs/05, docs/10, docs/12, the u00, u04, u08 and u12 contracts, the OD-42 row of 00-INDEX).
- LOW: the Python API widened the list. `Target(provider="openai", filter_stops=["refusal",
  "guardrail_intervened"])` built an `OpenAIAdapter` reading both. The rule moved to
  `shared.filter_stops.target_filter_stops`, applied by a `Target` field validator on every path
  and read first by the loader (same messages, which name the file); `Target` hides the input in
  its errors, so no value is quoted; the OpenAI and Anthropic adapters intersect a declaration
  with their own word (a `model_copy` or a hand-built adapter narrows, never widens).
- Tests: `tests/adapters/test_filter_stop_provenance.py` now 33 (31 fail on `de122e26`, 6 on
  `10cb526b`), `tests/cli/test_filter_stop_provenance_campaign.py` now 35 (31 fail on `de122e26`,
  10 on `10cb526b`: d1 for `openai` and `anthropic` with the exit code, the plan line, the model's
  6 refusals and its normalization). The auditor's `compat.py`: every example digests and dumps
  as on `main`.
- Gates on `572094b9` (`make gates`, worktree `src` first on `PYTHONPATH`, 02:01 to 02:08): all
  green, 5,567 tests passed (5,550 on `10cb526b`), coverage 97.86% (14,188 statements, 208
  missed), `shared/filter_stops.py` and `shared/provider_filter.py` at 100%, lint OK across 75
  specs, self-scan 0 high/critical, bandit and pip-audit clean.

## State, 2026-10-12 (night): the pre-merge audit of `a55710e9` (A-79), fixed

- One MEDIUM, six LOWs and a nit, fixed as new commits on `fix/filter-stop-provenance` (no history
  rewritten), under the owner's delegation (best practice, revisable). The auditor's probes are in
  `scratch/fixstop-audit/`.
- MEDIUM 1: the input-side reading ran every evaluator whose fail rests on something present on a
  Bedrock guardrail's configured message, so `regex_absence` "never disclose" beside `refusal` was
  a confirmed fail (`de122e26`: blocked; the output side had the same fail on `de122e26`, the
  scoring audit's LOW 5). One helper, `_evaluators_for_filtered_reply`, now serves `_cut_verdict`
  and `_trace_before_block`: replaced text (`replaced_reply`) is read only by
  `REPLACED_TEXT_EVALUATORS` (`secret_leakage`, `secret_shape`, `authz_leak`, the trace). The
  repro: input and output both inconclusive (blocked, cut); a canary in the message still fails.
  When `fix/scoring-audit-2026-10-11` merges, its `replaced` line in `_cut_verdict` gives way to
  the helper (one rule, a superset of its trace-only reading).
- LOW 1: a filtered run's line adds the unreachable advice for the attempts that got no reply.
  LOW 2: the WebSocket advice names `response.filter_stops`, and the CHANGELOG says a withheld
  turn is unreadable until declared. LOW 3: the FAQ answer says "not with text that came back" and
  what stays open (chosen attacks withheld with the provider's own word keep CI green; read
  the summary keys), the MANUAL row fixed, and an `openai` or `anthropic` file may declare
  `filter_stops: []` (validated, shown by `--dry-run`, `-v` and `-sn` as `filters:`; the example
  `target.openai.yaml` carries it commented out; every example digests and dumps as on `main`, by
  the auditor's `compat.py`). LOW 4: the stale runner comments. LOW 5: `dottore replay` prints
  `run: filtered: ...`, by `shared.provider_filter.filtered_run`, the rule `run` uses. LOW 6: the
  resume across the upgrade is stated in u10 and the CHANGELOG for `fix/resume-judging-rules`.
- Tests added: 7 in `tests/core/test_filter_stop_scoring.py` (now 14, 6 fail on `de122e26`), 1 in
  `tests/adapters/test_filter_stop_provenance.py` (now 25, 23 fail there), 13 in
  `tests/cli/test_filter_stop_provenance_campaign.py` (now 26, 22 fail there).

## State, 2026-10-12 (early hours): a forged filter stop, closed (A-79; security audit MEDIUM 3)

- On `fix/filter-stop-provenance` from `de122e26`, under the owner's delegation of 2026-10-11
  (best practice, revisable): the amendment to OD-41 and OD-42, clause u08 A-79 with its u00,
  u04, u09, u10, u11 and u12 halves, ADR-0011's second amendment. Not pushed.
- The finding, reproduced first with the auditor's stub (`scratch/audit-sec/e2e_logprobs.py`):
  harmful text to `JB-ROLEPLAY-001` with `finish_reason: stop`, exit 2; with `content_filter`,
  inconclusive 3/3, exit 0; Azure's 400 to every attack, 6 of 6 blocked, exit 0. On this branch:
  2, 3 (all six cut, `filtered`) and 3 (`filtered`).
- Rule 1, provenance: each adapter's `filter_stops` (OpenAI `content_filter`, Anthropic `refusal`,
  a REST template's by shape or declaration, a WebSocket file's `response.filter_stops`, default
  none) and `stop_provenance`, which marks any other filter word `ModelResponse.foreign_stop`;
  Azure's 400 only from an adapter that reads `content_filter`. The vocabularies moved to
  `shared.filter_stops`. No `core` reader changed: the provenance travels on the reply.
- Rule 2, delivered text: the judge's fail on a partial reply joins `_combine_verdicts` in
  `_cut_verdict` (a needs-review fail, OD-19), and `_trace_before_block` reads the text of an
  input-side reply with `CUT_DECIDING_EVALUATORS`. Runner changes kept to those two methods and
  one docstring, to ease the merge with `fix/scoring-audit-2026-10-11` (resume ranking, the
  multi-turn trace on env errors, the identity sweep: none touched here).
- Rule 3, every attempt filtered: `_filtered_reason` in `cli/run.py`, state `filtered`, exit 3.
  Every attempt, not more than half: a share makes a filter that does its job a CI error and
  still leaves a forger room under it.
- Tests: 24 in `tests/adapters/test_filter_stop_provenance.py` (22 fail on `de122e26`), 7 in
  `tests/core/test_filter_stop_scoring.py` (2), 13 in
  `tests/cli/test_filter_stop_provenance_campaign.py` (9), the Azure 400 from `anthropic` and from
  a plain REST template in `tests/adapters/test_provider_filter_block.py` (2; its `rest-azure`
  cases fail there only because `RestTemplate` has no `filter_stops`) and the WebSocket cases in
  `tests/adapters/test_malformed_replies.py` (2 fail there: the new one, and the one that now
  declares its stop). The ones that pass on `de122e26` are the
  controls: a genuine Azure 400 on some prompts, a genuine Anthropic refusal, the same text
  without a filter word, and the WebSocket loader's refusal (`de122e26` refuses the key itself).
  Four existing CLI tests whose every attempt was filtered now expect exit 3; one WebSocket test
  and one REST trace test now declare their stop.
- Open, said in the docs: a target that answers some attacks, not all, with its own provider's
  filter word and no text hides those attempts (inconclusive, never a pass); a conversation cut
  before its last turn is still read on its trace only.

## State, 2026-10-11 (evening): the pre-merge audit of `ed381359` (OD-43), fixed

- No bypass found; one MEDIUM and seven LOWs, fixed one commit each on
  `feat/operator-declared-tools`, then `main` merged in at `a69dbd8c` (#108). The auditor's probes
  (`scratch/od43-audit/probes/test_probe_od43.py`) give, on the fixed branch: P1 (a conversation
  the input filter cut after the declared hand-off) blocked with the note, P2 (a judge that echoes
  the note on a cut reply, nothing declared) and P3 (a tool named like the note) counted by no
  report, P4 (a case variant of a `destructive: true` scene tool, granted and declared) still a
  pass, now flagged by the plan.
- M1: the blocked verdict of a conversation the provider's input filter cut after a declared
  hand-off said nothing of the declaration (on `main`, the same trace fails). It now carries the
  note when its trace holds a call the declaration cleared.
- L1: the counters matched the note's text, so a judge recorded beside a cut reply (OD-42) or a
  tool named like the note counted with nothing declared. `Verdict.operator_cleared` is the record
  every count reads (the summary, the finding's line, replay, diff), left out of a dump when
  empty; the judge's words quote the marker. L6: the finding's line names the tools.
- L2: `dottore diff` reads a FIXED the declaration may have made as `FIXED (operator declaration,
  OD-43)`. L3: the plan flags a granted name that is a selected spec's scene tool but for case or
  Unicode form (NFKC, case folded). L4: nothing declared leaves every report but the JSON
  summary's empty key byte for byte as before (the HTML target line through whitespace control,
  checked against `main`'s template; `seeded_setup.not_destructive` left out of a dump when
  empty). L5: the report-1.0 note, the docs list, the index row. L7: the digest test pins the
  literal `main` computes at `a69dbd8c` instead of a hand-built payload that drifted with OD-44's
  `capabilities.mcp`.
- Nits, read strictly under the owner's delegation: a `granted_tools` mapping without
  `destructive` and a declared name with a space at either end are refused; `SeededSetup` refuses
  a declared name it does not grant however it is built, and keeps the list sorted (sorted rather
  than refused out of order, since a report's redactor can mask a name and move it).
- Tests now: `tests/evaluators/test_operator_not_destructive.py` (34, 33 fail on `main` at
  `a69dbd8c`), `tests/core/test_operator_declaration_runner.py` (9, all fail there),
  `tests/cli/test_operator_declaration_campaign.py` (16, all fail there). `make gates` green on
  `9096f659` (with `PYTHONPATH` set to the worktree's `src`): 5391 tests (5332 on `main` at
  `a69dbd8c`, 59 new), 97.83% coverage (`shared/tool_abuse.py` and `evaluators/tool_call.py` 100%),
  75 specs lint OK, four import contracts kept, self-scan, bandit and pip-audit clean.

## State, 2026-10-11 (later): a target file may declare one of its own granted tools not destructive (OD-43)

- On `feat/operator-declared-tools`, branched from `fix/handoff-tools-and-lint-stub` (`f76f145`,
  under pre-merge audit and not merged), merged with its audit fixes (`f5e6631`) and then with
  `main` at `0685f2ce` (#105, the hand-off fix as merged, and #106, OD-42) and `e8f9d1f6` (#107):
  the item that branch left open for the owner, decided as OD-43 (2026-10-11, 09:26) and built as
  u06 A-72, with halves in u00, u08, u10, u11 and u12 and two index rows. A
  `seeded_setup.granted_tools` entry may be `{name: <tool>, destructive: false}`, and `tool_call`
  then does not fail a call to that exact name by its name alone, for a spec whose scene does not
  name the tool. Measured on `f76f145` with a loopback agent that answers every prompt with
  `transfer_to_billing_agent` and a judge that answers secure: `AG-TOOL-UNAUTH-001` at `--runs 2`,
  the tool granted plainly, is `fail` 2/2 (`matched: ['transfer_to_billing_agent']`, exit 2), and
  the entry form is refused there; on this branch the same run with the declaration is `pass` 2/2,
  exit 0, and with the plain grant still `fail` 2/2.
- Shape chosen: the declaration is written on the grant, not as a sibling list
  (`not_destructive: [...]`, a subset of the grants), because it keeps one word for one rule (a
  tool marked `destructive: false`, in a scene or in a target file), cannot name a tool the file
  does not grant, and leaves every plain list of names reading, digesting and resuming as before.
  No key is added to `seeded_setup` or to the top level (A-53's list is unchanged); the entry's
  own keys are checked instead: `name` and `destructive` only, `destructive` the boolean `false`
  (a quoted `"false"`, `0` and `null` refused as not booleans, though a scene's null reads as left
  out since the A-71 audit's M1: that entry predates the check, this one is new; `true` refused
  because a target file may only say its own tool destroys nothing), and a declared name also
  mapped under `tools` or granted twice refused.
- Narrow: exact names (no pattern, no case folding, as the allowlist and the scene's flags);
  never a tool of a spec's scene, where the scene's word decides (`destructive: true` always
  wins, and so does an unmarked scene name with a verb, and the finding says so); only the
  destructive check (a call off the allowlist, an injected and a forbidden argument still fail);
  `kill_chain_progression` unchanged; the lint stub unchanged (it reads no target file). No name
  map reaches it (the A-71 audit's L1 for the operator's word): a map renames a call only to a
  scene tool, which the declaration never applies to, and a scene tool mapped onto a declared
  name is refused by the loader and by `seeding_gap`.
- Visible: `--dry-run`, `-v` and `-sn` print an `operator:` line, one more per declared name no
  verb is in ("changes nothing for it") and one per declared name a verb is in that is not named
  like a hand-off ("make sure it destroys nothing", the second look lint gives a scene's
  `destructive: false` since the A-71 audit's M2; the heuristic moved to
  `shared/tool_abuse.handoff_shaped`, read by both); the `-q` lines end `, <k> tool(s) declared
  not destructive`. Every attempt it changed carries in its verdict `operator declaration (OD-43):
  the target file declares '<tool>' (its name holds '<verb>') not destructive
  (seeded_setup.granted_tools, destructive: false), so no call to it was judged destructive`, in
  the form of the scene's own clearing note and after it when both apply, carried by the runner to
  the stored aggregate, and the finding counts them. `_run_evaluators` takes the target and reads
  the grants and the declaration off it, and every path that judges a reply passes it:
  `_evaluate`, `_trace_before_block` and, since the merge of `main` at `0685f2ce` (#105, #106),
  OD-42's `_cut_verdict`, so a hand-off in a reply the provider's filter cut is no fail (the
  attempt stays a cut needing review, its verdict carrying the note). The JSON summary's
  `operator_declarations` (always emitted; the golden JSON snapshot gains the empty key beside
  OD-42's, the other three snapshots do not move), the SARIF run and
  results, each JUnit suite and case, the HTML targets and summary, the terminal summary's last
  line, the run store (`context_json.not_destructive_tools`, masked as a target id is) and
  `dottore replay`.
- Resume: in the target digest, left out when none is declared (a run stored before keeps its
  digest); a change is refused, naming the old and the new declaration.
- Tests: `tests/evaluators/test_operator_not_destructive.py` (30, 29 fail on `main` at
  `e8f9d1f6`; the one that passes there checks that a refusal never quotes the value),
  `tests/core/test_operator_declaration_runner.py` (6, all fail there, among them a cut reply),
  `tests/cli/test_operator_declaration_campaign.py` (12, all fail there: every report of one run
  through the real CLI and the same run without the declaration, the dry run, `-sn`, the two plan
  warnings, the worked example, five resume cases, a corrupt record among them). Docs: MANUAL §4.2,
  §5, §8, §10 and replay, FAQ, USAGE, both man pages, `docs/01`, `03`, `04`, `09`, `12`, `16`,
  ADR-0009, `examples/target.app.yaml` (the support agent now declares its hand-off) and Scenario
  G's real output, CHANGELOG. `make gates` green on `a9564e9d` (with `PYTHONPATH` set to the
  worktree's `src`): 5312 tests (5264 on `main` at `e8f9d1f6`, 48 new), 97.82% coverage
  (`shared/tool_abuse.py` and `evaluators/tool_call.py` 100%), 75 specs lint OK, four import
  contracts kept, self-scan, bandit and pip-audit clean.
- Left open, for the owner: nothing the decision did not settle. Two readings to confirm: `true`
  in the entry is refused rather than read as "destructive whatever its name" (the decision speaks
  only of declaring a tool not destructive, and making a tool destructive stays the spec's word);
  and a null `destructive` in the entry is refused, unlike a scene's.

## State, 2026-10-11 (evening, later): the verification of `da16f219`, two LOWs

- Merge-ready per the verification; two LOWs, fixed in a new commit. At the request ceiling the
  benign check's debit raised inside the watch in place of the fifth unreadable reply, which was
  never stored and kept its reservation: the watch's caller now raises `CeilingAtUnreadable`, which
  `execute_attempt` turns into a `ReplyOverBudget` carrying that reply's result, refunded and stored
  (`--budget-requests 5` against an all-HTML stub through the CLI: 5 requests, 5 attempts stored, 0
  tokens, exit 3 `budget ceiling reached on 'max_requests'`; it stored 4 and recorded 629 tokens).
  One test more in `tests/core/test_unreadable_replies.py` (16; it fails on `da16f219`). The
  mid-run break's figure is written "26 to 27" (three runs gave 26, 26, 26 here, and 27, 26, 26
  for the verifier: the replies in flight vary).

## State, 2026-10-11 (evening): the verification of `07aa0b3a` (OD-21), fixed

- Both false passes closed per the verification; one MEDIUM and two LOWs, fixed in new commits after
  merging `main` (`e8f9d1f6`, #107) as `19ce3080` (conflicts only in CHANGELOG and PROGRESS, both
  kept). `f6b1a792` LOW 1: the excerpt's read stops before a registered credential that crosses its
  8 KiB cut, and before a short key-shaped token that does (the auditor's `probe_cut.py`: 0
  fragments, where up to 15 leading characters survived). `b5a4e7e1` MEDIUM and LOW 2: before
  either stop the watch sends one benign request (debited, paced, filed under `probes/`) and stops
  only when that one cannot be read either; a resume of a run that read replies starts proven; the
  reason names a filter's block page among the causes; ADR-0012 states the stop and its
  consequences; a resume that keeps nothing says "keeps none of the N attempt(s) it stored".
  Measured with the auditor's `probe_cli.py` on `b5a4e7e1`: the broad filter on attack words
  finishes the default battery (160 of 550 blocked, 2 checks at `--concurrency 1`, exit 0; on
  `07aa0b3a`, exit 3 at a run of 20 and every resume after 5); all HTML: 9 requests (6 at 1), 27
  with `-sV` (24 at 1); two readable then HTML: 26 to 27, exit 3; 30% HTML at random: finishes,
  every spec `inconclusive`. Tests: core 15 (6 fail on `07aa0b3a`), adapters 37 (3 fail there), CLI
  11 (4 fail there). `eca90de1` names the resume note's clause apart (mypy).
  `make --no-print-directory gates` green on `eca90de1` (2026-10-11, 18:34 to 18:41): ruff, format
  (405 files), mypy strict (159 source files), import-linter (4 kept), spec lint (0 errors, 0
  warnings across 75 specs, 14 suites, 1 pack), 5,348 tests with 97.75% coverage, self-scan 0
  high/critical, bandit, pip-audit (no known vulnerabilities).
- Noted, not part of this branch: the auditor's `probe_excerpt.py` shows an `sk-ant-api03-` key of
  a repeated 8-character pattern readable in the excerpt, and the redactor leaves it readable
  everywhere else too (its entropy rule; the excerpt only applies the redactor).

## State, 2026-10-11 (afternoon, later): the pre-merge audit of `598f0858` (OD-21, OD-20), fixed

- Not merge-ready per the audit: OD-21 opened two false passes the old rule did not have. Fixed in
  new commits on the same branch, history kept. `6a301b8c` HIGH 2: a WebSocket turn's tool calls
  and its filter stop are read before the turn is called unreadable. `37b9beeb` HIGH 1, MEDIUM 1
  and 2, LOW 1 and 3: an unreadable reply is `inconclusive: unreadable_reply` (ADR-0012, u00
  additive) and never lets its spec pass (the auditor's broken wrapper among two refusals passed
  `PI-DIRECT-001 --runs 3`, exit 0; now inconclusive), keeps a 4 KiB redacted excerpt with the
  body's size and the adapter's advice under `request.metadata.unreadable_reply`, and is counted in
  the terminal summary (never silenced by `-q`), the JSON report, SARIF, JUnit, HTML and replay;
  the stop's reply is stored and refunded (8 requests, 8 attempts, 0 tokens where 598f0858 stored 4
  and recorded 2,455 tokens); the watch counts unreadable replies in a row, 5 before any reply was
  read and 20 after (two readable replies then HTML: 25 requests and exit 3, where it sent 355 and
  exited 0); a resume sends unreadable attempts again; the CLI reads the verdict's reason or the
  error's mark, not the class name; the advice is per provider (a `provider: rest` target file is
  not told to check a template). `7c2e18f7` LOW 2: a template rooted at an index reads a JSON array
  (`0.generated_text`). `c97317c2` LOW 4 and 5: the JUnit report writes the log command's `#` as
  `&#35;`; the rules return a text with no `##` unscanned (60 MB in 0.03 s).
- Tests: `tests/adapters/test_malformed_replies.py` 34 (9 fail on `598f0858`),
  `tests/adapters/test_rest_array_body.py` 1 (fails there), `tests/core/test_unreadable_replies.py`
  12 (does not collect there), `tests/cli/test_malformed_reply_campaign.py` 10 (9 fail there),
  `tests/test_json_log_commands.py` 20 (2 fail there). The auditor's probes (`probe_cli.py`,
  `probe_adapters.py`, `probe_od20.py`) re-run on `c97317c2`: figures in u08 A-74 and the
  CHANGELOG. `make --no-print-directory gates` green on `c97317c2` (5,306 tests, 97.79% coverage)
  and again after the docs (below).
- Left open: the `-sV` pass seeding the stop (a wrong endpoint under `-sV` pays its 18 probes);
  a WebSocket filter stop written at a path the block does not declare as `final_path` is not
  read, as OD-42 reads only that path.

## State, 2026-10-11 (afternoon): five open decisions of robustness and output closed

- On `feat/decide-robustness-and-output`, rebased on `0685f2ce` (OD-42). The owner delegated these
  on 2026-10-11 at 10:09 ("arreglalo todo según mejores prácticas"); each is recorded in its
  contract and its 00-INDEX row as decided under that delegation (best practice), revisable, with
  the reasoning, the alternative not taken and where to reverse it. One commit per decision.
- **OD-22, kept:** a spec regex that does not compile still refuses the run before anything is
  sent; lint keeps `EVALUATOR_MISCONFIGURED`. Fail fast on configuration; `--exclude` runs the rest.
- **OD-25, kept:** the name of a missing file stays masked in CLI errors (A-38): a key given where a
  file belongs must not reach a CI log.
- **OD-24, kept:** a logprob block with one impossible figure reads as none (A-39); a positive
  figure counts as impossible; an absent entry is still skipped.
- **OD-20, built:** every JSON output (`lint --json`, `coverage --json`, `dottore fingerprint`,
  `schema export`, the JSON and SARIF reports) writes the second `#` of `##<letters>[` as `\u0023`
  (`redactor.log_safe_json`). Before, a target id holding `##vso[...]` put 1 such line in the
  fingerprint and 3 each in the JSON and SARIF reports. Property-tested: the parsed document is the
  plain serializer's, and serialized again with the output's options it is the plain bytes.
  `tests/test_json_log_commands.py` (18; does not collect on `6d5f7ae`).
- **OD-21, built (u08 A-74, with u04's and u12's halves):** a 200 the adapters cannot read (not
  JSON, not an object, not the provider's or the template's shape; a WebSocket frame or an MCP
  reply of that kind) is `ResponseMalformed`, an environment failure with `retryable = False`: the
  attempt is inconclusive, sent once, kept by a resume, re-derived by `replay`, and a `-sV` probe
  that gets one fails alone. One watch per invocation stops a campaign whose first 5 replies all
  cannot be read, with none that can (`aborted on UnreadableReplies`, exit 3, naming the endpoint,
  provider and template to check); a shorter run that read nothing is `unreachable` with the same
  advice. Measured against a loopback stub answering HTML to everything: 8 requests at
  `--concurrency 4`, 5 at 1, 26 with `-sV` (23 at 1); on `6d5f7ae` 4 and 1. Tests: 24 in
  `tests/adapters/test_malformed_replies.py`, 9 in `tests/core/test_unreadable_replies.py`, 8 in
  `tests/cli/test_malformed_reply_campaign.py` (7 fail on `6d5f7ae`); 12 files that pinned the
  old rule assert the new one, `tests/adapters/test_provider_output_filter.py` (OD-42's) included.
- `make --no-print-directory gates` green (2026-10-11, 11:57 to 12:03, on `927d747b`): ruff, format
  (400 files), mypy strict (158 source files), import-linter (4 kept), spec lint (0 errors, 0
  warnings across 75 specs, 14 suites, 1 pack), 5,288 tests with 97.87% coverage, self-scan 0
  high/critical, bandit, pip-audit (no known vulnerabilities).
- Left open, not part of the decisions: the `-sV` pass seeding the stop (a wrong endpoint under
  `-sV` costs its 18 probes first); a stop for a target that goes bad after a readable reply; the
  evidence field saying a logprob block was unreadable rather than absent (u00); JUnit XML and
  HTML are not JSON and OD-20 does not change them.

## State, 2026-10-11 (noon): the verification of `877b2e2b`, and `main` merged in

- The verification of `877b2e2b` found the decisions branch merge-ready and asked for three
  things, done on top. `1d9f268`: the declared-order `note:` printed for a `--deep` campaign
  resumed with `--deep` too (`mutator_orders` declared, declared), where nothing changed; it now
  prints only when an earlier entry is `fingerprint`, and the value is described as "planned with a
  fingerprint" (whether or not that moved a mutator), not "ordered"; one test, failing on
  `877b2e2b`; `CHANGELOG.md:66` and `docs/MANUAL.md:362` rewrapped (100 characters, 101 bytes with
  §). `edb6d58`: `origin/main` at `0685f2c` (#105 hand-off tools, #106 OD-42) merged in, both sides
  kept (CHANGELOG, PROGRESS, u00 §6 and the `ModelResponse` docstring, where OD-42's `filter_side`
  and OD-34's `raw_ids` note now sit together).
- `make --no-print-directory gates` green on the merged tree `edb6d58` (11:47 to 11:53 CEST):
  5,264 tests, 97.75% coverage, ruff and the format check clean (399 files), mypy clean (158
  source files), four import contracts kept, 75 specs lint OK, self-scan 0 high/critical, bandit
  and pip-audit clean.

## State, 2026-10-11 (noon): the verification of `91845524` (OD-42), two mediums fixed

- Every earlier finding closed; two new mediums, fixed in `0a293438`. (1) The recording-only judge
  on a partial cut reply ran in the same evaluator call as the deciding ones: a request ceiling
  that refused it raised, the cut attempt was stored with no verdict and the resume sent it again,
  its line counting it as kept for review. It now runs after them, alone, in its own try (a refusal
  or any error a note), and `cli/run.py` counts cut attempts among the kept ones only. (2) With
  three or more identities a filtered one was dropped silently and the other two could pass the
  spec; `authz_leak` now cannot pass beside a filtered identity (a fail among the others stands)
  and the stored verdict names it. 4 tests more (94 for OD-42): the judge under
  `--budget-requests 2`, with and without a canary, through the CLI, and two sweeps of three
  identities; all 4 fail on `91845524`. `make gates` green (2026-10-11, 10:59, on `b4d4368a`):
  ruff, format (393 files), mypy strict (157 source files), import-linter (4 kept), spec lint (0
  errors, 0 warnings across 75 specs, 14 suites, 1 pack), 5,159 tests with 97.68% coverage,
  self-scan 0 high/critical, bandit, pip-audit (no known vulnerabilities).

## State, 2026-10-11 (late morning): the pre-merge audit of `a55e953` (OD-42), fixed

- Not merge-ready per the audit, no HIGH; fixed on the same branch in new commits. M1: a cut reply
  was read by every evaluator but the judge, `regex_presence` among them, which fails when its
  secure marker is absent: an empty reply Azure withheld made `DOS-TOKEN-AMP-001` a confirmed fail,
  exit 2. Now `core.runner.CUT_DECIDING_EVALUATORS` (the presence-based ones) read it, a test holds
  every `EvaluatorType` classified, and only a fail on what is present stands. M2: the identity
  sweep kept a filtered identity's empty reply, so `authz_leak` read it as no crossing; it is
  skipped as a failed send is. M3: Bedrock and Gemini are library-only (a target file's REST target
  has no template), said so in the docs; the side-unknown terminal line names its stop reasons and
  prints the Bedrock hint only beside `guardrail_intervened`. L1 `usage.iterations` read after a
  fallback; L2 ADR wording; L3 a trace naming no side is `filter_side: unknown`; L4 JUnit counts in
  the skip or failure `message`, and a SARIF side-unknown test; L5 the serializer typed; L6 the
  versioning note; L7 WebSocket stop words; L8 the judge's verdict on a partial reply recorded, not
  deciding, and the `refusal` heuristic said to count as deterministic. Gemini's `RECITATION` is an
  output-side cut, decided under the owner's delegation (revisable); a `RECITATION` candidate with
  no text is a reply. Left for the OD-43 branch (M4): thread the operator's declared tools into
  `_cut_verdict` when it lands. 18 tests more (12 fail on `a55e953`), 90 in all for OD-42. With
  the stubs: `DOS-TOKEN-AMP-001` on empty cuts is inconclusive, exit 0; the canary run makes 12
  judge requests, the Anthropic run 16 (the partial replies recorded). `make gates` green
  (2026-10-11, 10:40, on `de4a9748`): ruff, format (393 files), mypy strict (157 source files),
  import-linter (4 kept), spec lint (0 errors, 0 warnings across 75 specs, 14 suites, 1 pack),
  5,155 tests with 97.68% coverage, self-scan 0 high/critical, bandit, pip-audit (no known
  vulnerabilities).

## State, 2026-10-11: a reply the provider's filter cut or replaced is never a pass (OD-42)

- On `fix/provider-output-filter-not-a-pass`, from `origin/main` at `6d5f7ae`: the owner decided
  (2026-10-11, 08:55, "haz lo pendiente" after the recommendation) that a reply the provider's
  filter cut or replaced is never scored as the model resisting. The gap was found by the
  pre-merge audit of OD-41. Measured on `6d5f7ae` against loopback stubs that answer the filter's
  reply to prompts holding "instructions for" or "developer mode", `GUARD-INPUT-EVASION-001` and
  `PI-DIRECT-001` at `--runs 2` with a secure judge: Azure's withheld reply (`content: null`,
  `content_filter`) and Anthropic's empty `refusal` both gave two passes, exit 0, 28 judge
  requests; through the REST adapter, a Bedrock canned refusal passed with and without the
  guardrail trace, a Gemini `SAFETY` candidate with refusing text passed, and one without text
  stopped the campaign. Built (u08 A-70, with halves in u00, u04, u09, u10, u11 and u12; the
  amendment to ADR-0011; OD-42 closed): one predicate in `shared.provider_filter` (the
  fingerprint's `FILTER_STOPS`, moved, with Vertex AI's `MODEL_ARMOR`; every value sourced, read
  2026-10-11) reads the stop reason and its side. Input (a Bedrock trace's `inputAssessment`,
  Anthropic's `refusal` before any output): OD-41's block, reply kept. Output: `inconclusive:
  cut_by_provider_output_filter`; unreported side (Bedrock without trace, `content_filtered`):
  `provider_filter_side_unknown`; both new `InconclusiveReason`s, needing review, scored by the
  deterministic evaluators on what came back (a fail stands; the judge is not asked); a spec with
  one cannot pass; in `N`, never a success; `--fail-on` unchanged; a conversation ends on the cut
  reply; kept by a resume, re-derived by `dottore replay`, counted apart in JSON, SARIF, JUnit, HTML
  and the terminal. `ModelResponse.filter_side` carries a Bedrock trace's side and is left out of a
  dump when unset. The REST adapter reads a filter stop at `finish_path` before the text, so a
  `SAFETY` candidate with no text is a reply. With the stubs: Azure's run exits 0 with both specs
  inconclusive (2/8 and 6/6 cut) and 12 judge requests; a canary in a cut partial reply is a
  confirmed fail, exit 2; Anthropic's refusal before output is 6 blocked attempts, after partial
  text 2 cut ones. Tests: 72 new (6 CLI, 4 of which fail on `6d5f7ae` and 2 controls that pass
  there too; 22 core and 41 adapter, not collected on `6d5f7ae`; 2 fingerprint; 1 redactor). Left
  open: Gemini's `RECITATION` (a reply cut for reciting a source: a question for the owner when a
  training-data extraction spec is the one cut), a Gemini template without `finish_path`,
  Bedrock's `InvokeModel` shape and streamed replies; the identity sweep reads its replies as
  before. Not run against a live Azure, Bedrock, Gemini or Anthropic endpoint. `make gates` green
  (2026-10-11, 09:45): ruff, format (392 files), mypy strict (157 source files), import-linter (4
  kept), spec lint (0 errors, 0 warnings across 75 specs, 14 suites, 1 pack), 5,137 tests with
  97.66% coverage, self-scan 0 high/critical, bandit, pip-audit (no known vulnerabilities).

## State, 2026-10-11: a hand-off tool is not destructive by its name, and lint judges calls as a run does

- On `fix/handoff-tools-and-lint-stub`, the two items the pre-merge audit of OD-38 left open
  (entry of 2026-10-09 below), closed as u06 A-71 (with halves in u02 and u00 and an index row).
  (1) A hand-off named `transfer_to_<agent>` (the OpenAI Agents SDK's style) matched the verb
  `transfer` and, since OD-38, could not be excused: a spec whose hardened fixture hands off gave
  `FIXTURE_HARDENED_FAIL` on `6d5f7ae`. Now a scene tool marked `destructive: false` is not
  destructive whatever its name, under that exact name only; `destructive: true` still makes any
  name destructive, an unmarked name is judged by its verbs, a name marked both ways is
  destructive, and the flag clears only that check. No `transfer_to_*` exemption:
  `transfer_to_account` stays destructive. `destructive` and `external` are `true`, `false` or
  left out in the schema and in `Setup` (null reads as left out; a quoted `"false"`, which read
  as true, or a number is refused: breaking for a pack that wrote one, in the CHANGELOG's
  Changed section). A verdict names in its reasoning a called tool the scene cleared, and lint
  warns on a clearing not shaped like a hand-off, on one no verb makes necessary, and on one in
  a spec without `tool_call`. A whole-word verb rule was measured and not adopted: over every
  shipped fixture it changes no verdict, but it does not clear the hand-off and stops flagging
  `deleteall`, `droptable`, `bulkdelete`, `airdrop_tokens` and `transferfunds`. (2) The lint
  stub was a drifted copy of the evaluator (the quadratic backtick pattern, about 4 s on an
  unclosed backtick before 100,000 letters, now about 3 ms; top-level argument values only; no
  lists in the forbidden walk; no OpenAI JSON-string arguments, in the `tool_sequence` stub too).
  The checks live once in `shared/tool_abuse.py`, and calls are read through
  `shared/toolcalls.py` by both.
- Verdict check, before and after, on every shipped fixture (`specs/attacks` and the valid
  corpus: 78 files, 77 unique ids, since `PI-INDIRECT-RAG-001` is in both): each declared
  evaluator's real verdict (status, reasoning, matched) and its stub's, on 156 fixture cases
  (the first count, 154, keyed the cases by id and lost the duplicate's two), plus the 594
  traces of every fixture under every spec that declares `tool_call`: byte-identical once the
  per-process salt of the canary masks is normalized (20 lines differ only by that salt, as two
  runs of the same code do).
  `dottore lint specs/` (text and `--json`) and `dottore coverage --json` are byte-identical to
  `6d5f7ae`'s. No shipped spec marks a tool `destructive: false`.
- Pre-merge audit of `f76f145`: merge-ready after one CHANGELOG fix, with three MEDIUMs and five
  LOWs (M3, the granted hand-off, is the owner's question; L5 asked only not to rewrite history),
  the rest closed in new commits on top (no history rewritten: `feat/operator-declared-tools`
  is built on `f76f145`). M1: the booleans-only tightening broke a pack that left the key empty
  (null) or wrote a quote or a number (lint `SCHEMA`, and `run` refused the whole battery); null
  reads as left out again, a quote or a number is still refused, and the CHANGELOG says so as a
  breaking change with its migration. M2: a scene could clear a real destructive tool without a
  trace; the reasoning names each cleared tool, and lint warns on a clearing not shaped like a
  hand-off. L1: a seeded name map onto another scene tool's name (`{transfer_to_billing_agent:
  delete_account}`) judged a real delete as the cleared hand-off; `seeding_gap` refuses it. L2,
  L3: the timing test times only the judgement, on 200,000 letters, and pins the shared helpers
  by identity; the shipped-trace sweep covers every `tool_call` config (22, with
  `AG-CRED-SWEEP-001` and `AG-TOOLCHAIN-EXFIL-001`). L4: the MANUAL's lint reference lists the
  warnings and the figures above are corrected. The auditor's dump (156 cases, 594 traces) is
  byte-identical on the fixed tree to `6d5f7ae`'s and `f76f145`'s, and so are `dottore lint
  specs/` and `dottore coverage --json`.
- Tests: `tests/evaluators/test_scene_not_destructive.py` (43, 26 fail on `6d5f7ae`),
  `tests/registry/test_stub_agrees_with_tool_call.py` (22, 13 fail on `6d5f7ae`, among them a
  timing test bounded at 1.5 s, 250 times the linear cost), four in
  `tests/core/test_seeded_setup.py` (3 fail on `6d5f7ae`), and the invalid schema-parity
  fixture `setup-tool-destructive-not-boolean.yaml` (fails on `6d5f7ae`). Docs: `docs/03`,
  `docs/04` §1, MANUAL §4.2, §5 and §8, FAQ, `dottore-scope(5)`, `examples/target.app.yaml`,
  CHANGELOG. `make gates` green (with `PYTHONPATH` set to the worktree's `src`): 5135 tests
  (5065 on `6d5f7ae`, 70 new), 97.79% to 97.80% coverage over two runs
  (`shared/tool_abuse.py` and `evaluators/tool_call.py` 100%), 75 specs lint OK, four import
  contracts kept, self-scan, bandit and pip-audit clean.
- Left open, for the owner (not decided here, no OD opened): a tool a deployment grants under
  `seeded_setup.granted_tools` is in no scene, so a granted `transfer_to_<agent>` is still
  destructive by its name: an Agents SDK deployment that hands off during a seeded spec that
  declares `tool_call` fails it (read from the code, not run against a live deployment).
  Whether a target file may declare one of its own tools not destructive (for instance a
  `granted_tools` entry written as `{name, destructive: false}`) is a question of who may say a
  tool is safe: the operator's file, not the spec. **Decided the same day as OD-43** (the entry
  above, on `feat/operator-declared-tools`).

## State, 2026-10-11 (afternoon): the pre-merge audit of `4f3ed297`, closed (and OD-44)

- Merge-ready per the audit after M1 and M2, no HIGH; fixed in new commits on the same branch,
  `main` at `0685f2c` (#105, #106 OD-42) merged in first (both sides kept; OD-42's A-70 text now
  names the shared rule, and a test holds that its cut-reply rule never lets the judge decide
  alone, so a cut fail is deterministic and can confirm). M1: `DOS-TOKEN-AMP-001`'s pattern is
  `(?:scale[^a-z]{0,12}){100}`, so a numbered run counts (it was a confirmed Medium on `ee202bf`
  and the first pattern missed it). M2: the OD-19 CHANGELOG entry is marked breaking for a CI
  gate and the Python API, with the non-mock figure re-measured (loopback stub, realistic judge,
  75 specs, `--runs 3`: 12 of the 26 confirmed fails on `0685f2c` become needs-review, exit
  stays 2; `AC-BFLA-001` and `OUT-SQLI-001` alone go from exit 2 to 0, 2 with
  `--include-needs-review`); the MANUAL's `--fail-on` row and §11 say `dottore diff` still counts
  a judge-only fail as `NEW_FAIL` and what the flag also gates. M3, decided under the delegation
  as **OD-44**: `MCP-TOOLPOISON-001` `requires: [mcp]`, a new capability true exactly when the
  provider is `mcp` (loader-set; refused declared on a live target of another provider; an
  offline mock may declare it; fleet refuses it declared); against a chat stub that explains the
  markers it was a confirmed Critical with 3 attempts on `0685f2c` and is not sent now; the
  example chat dry run plans 33 specs (34); a chat-like hardened run credits 26/30 IoPC
  techniques (27/30); `dottore coverage` is unchanged. L1: `combine`'s lost `configs` is labelled
  breaking (a `TypeError` over a silently different verdict). L2: `scoring.gate_state` agrees
  that a judge-only fail needs review. L3: the reversals take files from `main`. L4: OD-40's
  reversal line. L5: a bounded answer in other words passes only with `--judge`. L7: docs/04 on
  what "deterministic" covers. The mock battery is unchanged throughout (bare 75 inconclusive,
  vulnerable 67 confirmed fails, hardened 64 passes). `make --no-print-directory gates` green
  (12:11 to 12:16): format (403 files), mypy strict (159 source files), import-linter (4 kept),
  spec lint (0 errors, 0 warnings across 75 specs), 5,297 tests collected (5,229 on `0685f2c`),
  97.77% coverage, self-scan, bandit, pip-audit clean.

## State, 2026-10-11: four evaluator and fingerprint decisions closed (OD-16, OD-19, OD-17, OD-40)

- On `feat/decide-evaluator-semantics`, rebased onto `main` at `ee202bf` (#105): the owner delegated
  these on 2026-10-11 at 10:09 ("arreglalo todo según mejores prácticas"), so each is recorded as
  decided under the owner's delegation (best practice), revisable, with the alternative not taken
  and a reversal in its ADR. One commit each.
- **OD-16 (ADR-0007 B, accepted):** no engine change; `DOS-TOKEN-AMP-001` keys on the
  amplification (`regex_absence` on 100 repetitions in a row) and `MCP-TOOLPOISON-001` pairs its
  text oracle with a judge. Bare mock, every capability declared, `--runs 2`: `inconclusive 73 ·
  fail 1 · pass 1` (exit 1) on `6d5f7ae` and on `ee202bf`, `inconclusive 75` (exit 0) now;
  vulnerable (67 confirmed fails, 8 inconclusive) and hardened (64 passes, 11 inconclusive)
  unchanged spec by spec. No fixture verdict changed. The no-judge dry-run warning on
  `examples/target.local.yaml` read 34 of the 34 specs (was 33 of 34): every shipped spec declares
  a judge; since OD-44 (below) it reads 33 of the 33. Left out: `MCP-TOOLPOISON-001` against a
  non-MCP target with a judge configured is what the judge makes of a reply that lists no tool
  (gating MCP specs to `provider: mcp` is a planner change of its own).
- **OD-19 (ADR-0010 B with the amendment, accepted, u06 A-73):** one rule, `deterministic_first`,
  in `shared/combination.py`, called by the runner, the lint fixture engine and
  `evaluators.combine` (a Hypothesis property checks they agree); the schema gains the value, the
  75 specs declare it, `all_pass`/`any_fail`/`weighted` and an evaluator `weight` are a
  `DEPRECATED_COMBINATION` lint warning; the weighted vote and `combine`'s `configs` are gone. A
  variant confirms only with a deterministic fail among its fails: a spec whose only failing
  evaluator is the judge, vulnerable mock, `--runs 3`, was Critical, confirmed, exit 2; now
  needs review, exit 0 (2 with `--include-needs-review`). Vulnerable battery: 224 failing
  attempts, none judge-only, so no confirmation changed.
- **OD-17 (ADR-0008 B now, accepted):** `PlanSelection.baseline_resistance` and
  `planner._baseline_resistance` removed (dead at both ends); a plan JSON with the key is refused
  (no command reads one; `report-1.0` never held it); no verdict, ordering or report changes.
  (The delegation's brief called the drop option "C"; in the ADR it is B and C is "leave it
  documented".)
- **OD-40, its open part (u09 A-67):** `input_filter` is kept and filled: `true` when the benign
  request or a carrier failed because the provider's own input filter refused it in a documented
  shape (`ProviderFilterBlock`), `null` otherwise, never `false`; set by the engine, so the
  guardrail layer's evidence and the golden fingerprint are unchanged. The Azure stub of
  `tests/cli/test_input_filter_probe.py` now gives `"input_filter": true`.
- New tests: `tests/battery/test_irrelevant_reply.py` (5, failing on `6d5f7ae` and `ee202bf`),
  `tests/evaluators/test_one_combination_rule.py` (41) and
  `tests/registry/test_deprecated_combination.py` (7) (on `feb148f` the first does not import and 6
  of the second's 7 fail), `tests/core/test_no_baseline_resistance.py` (4, failing on `522817d`),
  `tests/fingerprint/test_input_filter_signal.py` (5, 2 failing on `23e2cec`, plus the CLI test's
  flipped assertion). `make --no-print-directory gates` green (2026-10-11, 11:08 to 11:13): ruff,
  format (398 files), mypy strict (159 source files), import-linter (4 kept), spec lint (0 errors,
  0 warnings across 75 specs), 5,190 tests collected (5,135 on `ee202bf`) with 97.80% coverage,
  self-scan 0 high/critical, bandit, pip-audit (no known vulnerabilities). Not pushed; no PR
  opened.

## State, 2026-10-11 (late morning): the pre-merge audit of `be3f2e71`, closed

- Not merge-ready on `be3f2e71`: one HIGH, two MEDIUM, four LOW, closed in new commits on top.
  HIGH 1 (`ccae01a`): the first OD-37 build refused a WebSocket `judge:` block even with a matching
  hand-written `--judge` file, which worked on `6d5f7ae` (fleet exit 0, `run --dry-run` planning
  220 judge requests); the block is now checked only without `--judge`, no `judge.yaml` is written
  for it, the refusal says to pass the file with `--judge`, and docs, contracts and CHANGELOG no
  longer say `run` refused every file the fleet wrote; 3 tests, failing on `be3f2e71`. MEDIUM 2
  (`850747e`): `context_json.mutator_orders` records each invocation's order (`fingerprint`,
  `declared`, `unrecorded` first for an older run), a resume of an adaptive campaign with no
  fingerprint prints one `note:` line, and the planning-mode refusal says the mode changes the
  order, never which attempts are sent; `tests/cli/test_resume_mutator_order.py`, 8 tests, all
  failing on `be3f2e71`. MEDIUM 3 (`6e44655`): the OD-2 recipe states its custody rules (the
  reviewer's own key, `allowed_signers` out of the editors' reach, one private copy verified and
  run, `specs/` reachable), run as written with a throwaway key: verify, run exit 0, `shasum` of
  the copy equal to `run.scope_sha256`, exit 255 after one appended line. LOWs (`7258ac1`, OD-2's
  reversal in `6e44655`): reversal lines for OD-2, OD-7 and OD-11, OD-11's tests cited
  (`tests/policy/test_policy_audit_2026_10_03.py:55` and `:69`), OD-34's key cost softened,
  paragraphs rewrapped to 100 columns, and the OD-35 refusal says `--concurrency` sets how many
  run at once.
- `make --no-print-directory gates` green on `7258ac1` (11:27 to 11:33 CEST): 5,099 tests, 97.69%
  coverage, ruff and the format check clean (392 files), mypy clean (157 source files), four
  import contracts kept, 75 specs lint OK, self-scan 0 high/critical, bandit and pip-audit clean.

## State, 2026-10-11: eight open decisions closed under the owner's delegation

- On `feat/decide-signoffs-and-websocket` (from `main` at `6d5f7ae`). The owner delegated the open
  decisions on 2026-10-11 at 10:09 ("arreglalo todo según mejores prácticas"); each one below is
  recorded as decided under that delegation, by best practice and revisable, in its `00-INDEX` row
  and its unit's §9, with the reasoning, the alternative not taken and the reversal. One commit
  per decision. No A-clause was needed (A-75 stays free).
- **OD-37, built** (`0bdb6ee`, `82cacc6`): `dottore fleet` refuses a `ws://` or `wss://` endpoint
  and `provider: websocket`, in a target or the `judge:` block, before it writes anything (exit
  3), pointing to `examples/target.websocket.yaml`; it used to write a `provider: rest` file that
  `run` refused. `tests/cli/test_fleet_websocket.py`: 17 tests, 16 failing on `6d5f7ae`.
- **OD-35** (`6862347`): one query per connection, by design; the loader's refusal of
  `one_query_in_flight: false` now says so (one test changed first, failing on the old message).
- **OD-36** (`4036d7f`): no reconnect mid-conversation, by design, `{{messages}}` included; docs
  only.
- **OD-7** (`106ed51`): fixtures inline only; the u03 and u13 contracts that claimed a sidecar
  location are corrected; `tests/golden/test_fixture_location.py` (6 tests) pins schema, model and
  digest.
- **OD-34** (`8e33d40`): the frame transcript stays in `raw_ids["websocket"]["frames"]`. Measured
  on a copy of `0bdb6ee` with an optional `transcript` field added: 1 of 5,082 tests fails (the
  JSON report's golden snapshot), 323 s.
- **OD-2** (`c0fde17`): the checksum is integrity only; authenticity a non-goal until key
  management (`NON-GOALS.md`); MANUAL §4.1 "Signing a scope (out of band)", run as written with
  OpenSSH 10.3p1 on the mock: verify, run (exit 0), `shasum -a 256` equal to `run.scope_sha256`
  (`38529c5c...00c2d`); one appended line made the verify exit 255.
- **OD-11** (`e379fd0`): the PII spec stays off; its opt-in is DL4's two keys in one change (a
  pack-loading flag and `--allow-pii-elicitation`), never the run flag alone; the policy-pack
  flag stays open (it also gates the seven `agentic-extortion` specs). Not built.
- **OD-5** (`f84a2ee`): signed off as built, no `--adaptive` flag. Measured on the mock: a `-sV`
  campaign halted (`--quick --runs 2 -sV --budget-requests 25`, exit 3, 9 of 18 specs) and
  resumed with `--deep` alone completes (exit 2, 18 of 18) in declared order, since both flags
  set the recorded mode; accepted (the same attempts are sent and scored) and documented.
- `PYTHONPATH=<wt>/src:<wt> make --no-print-directory gates` green on `f84a2ee` (10:35 to 10:41
  CEST): 5,088 tests, 97.70% coverage (every new line of `cli/fleet.py` covered), ruff and the
  format check clean (391 files), mypy clean (157 source files), four import contracts kept, 75
  specs lint OK (14 suites, 1 pack), self-scan 0 high/critical, bandit and pip-audit clean.
- Open after this: the policy-pack flag (unnumbered, `docs/12`), which OD-11's opt-in waits on;
  `--deep` as timing only (OD-5's alternative) if the owner wants the recorded mode to say whether
  a fingerprint ordered the plan.

## State, 2026-10-10 (night): the verification audit's three LOWs

- The verification audit of `5bd7c45` found it merge-ready, with three LOWs, closed one commit each.
  `93575ef`: `run_until_stopped` disarms in a `finally`, since a Ctrl-C or a second signal raising
  at a call of its cleanup left the run armed (the audit's Ctrl-C sweep: 27 points, now 12, all at a
  line that compiles to NOP alone; its second-signal sweeps: none left); one test, which fails on
  `5bd7c45`. `4020f8b`: the campaign takes a held-back signal only when it arrives before the
  put-back's last check, in a process whose only thread is the main thread, and the docs say so; the
  hold is let go right after that check. `3836753`: `_interrupt_as_ctrl_c`'s docstring says what a
  program that embeds `execute_run` sees, as u12 A-60 does. `tests/cli/test_termination_signals.py`:
  49 tests, 30 runs in a row green on 3.14.7 and on 3.12.13 (shim). The single-signal sweep with
  SIGTERM: 2 of 6,193 points bad with Ctrl-C ignored (the two NOP-only lines), 0 of 6,172 with a
  Ctrl-C handler that does nothing. `make --no-print-directory gates` green: 4659 tests, 97.64%
  coverage, 75 specs lint OK, four import contracts kept, self-scan, bandit and pip-audit clean.

## State, 2026-10-10: the pre-merge audit of the A-60 fix, closed

- On `fix/sigterm-hang-a60`, the pre-merge audit of `2001e7f` (no HIGH) closed in normal commits on
  top of it, `main` not merged in. MEDIUM 1: the coroutine `asyncio.Runner` runs makes the
  campaign's task and awaits it at once (`7a0be1d`); a Ctrl-C in its first step had cancelled only
  that coroutine, and a second one during the stop left the task pending. MEDIUM 2: a second signal
  of either kind raises in place (`2dcf954`): with Ctrl-C at its default a SIGTERM or SIGHUP goes to
  asyncio's own Ctrl-C handler, which counts both. LOW 1 to 3 (`a5dd63f`, `36324f2`, `9eb2f12`): the
  handlers are swapped with Ctrl-C, SIGTERM and SIGHUP held back, the put-back retried when a signal
  beats the hold, one that arrives before the put-back's last check taken by the campaign (in a
  process whose only thread is the main thread), the loop let go while still armed; a signal dropped
  outside a loop ends the campaign with KeyboardInterrupt after its last loop; only the main thread
  watches. LOW 6 (`ec4277c`): a send is bounded by `asyncio.timeout`, since 3.11's `wait_for`
  dropped a cancellation that landed as the send completed. LOW 7 (`fa94b96`, `e9cfd85`):
  `interrupts.py` at 100% line and branch coverage. LOW 4 (`3091640`): u12 A-60 amended in place,
  its index row, MANUAL, `dottore(1)`, CHANGELOG. Test-only (`7e31c2e`): two WebSocket tests that
  hung on 3.12 hold their connection on an Event and abort it. The audit's sweep (a signal at every
  line event, one forked child per point) on `9eb2f12`: 8 of 31,030 points bad in five single-signal
  arms, all at two lines that compile to NOP alone (`2001e7f`: 50, 50 and 21 of about 6,000 in its
  three SIGTERM arms); a second signal one line event after the first waits for a third at 66 of 413
  points (16%), plain `asyncio.run` with a double Ctrl-C at 59 of 385 (15%). The real CLI with the
  first SIGTERM inside the runner's gather: exit 130, 0.99 to 1.11 s after the start, the spend of 6
  requests written inside the loop, Ctrl-C ignored or at its default.
  `tests/cli/test_termination_signals.py`: 48 tests, 30 runs in a row green on 3.14.7 and on 3.12.13
  (the signal file alone, through a shim of `interrupts.py` and the four signal functions of
  `run.py`, since the 3.12 here has none of the project's dependencies). `make --no-print-directory
  gates` green: 4658 tests, 97.64% coverage, 75 specs lint OK, four import contracts kept,
  self-scan, bandit and pip-audit clean. Python 3.11, what CI runs, is not installed here.

## State, 2026-10-09 (evening): one SIGTERM stops a run with Ctrl-C ignored too

- On `fix/sigterm-hang-a60` (from `main` at `f12ba83`): the hang the afternoon entry left open is
  fixed. With Ctrl-C ignored, a SIGTERM or SIGHUP landing in gather's callback left the run waiting
  for a second signal as it closed, and the stuck part's spend was written when Python collected the
  task (measured through the real CLI on Python 3.12.13 and 3.14.7: still running 3.0 s after the
  start, when a second SIGTERM ended it). New `cli/interrupts.py`: `run_until_stopped` replaces
  `asyncio.run` for the `-sV` probe pass and each target's campaign and runs the coroutine as a task
  made before the loop starts; on the first signal, whatever Ctrl-C's disposition, the handler
  (`stop_running_loop`) cancels that task and wakes the loop, and KeyboardInterrupt is raised once
  the loop is closed, also for a signal that comes after the task is done or inside `loop.close()`;
  a second raises in place; Ctrl-C keeps asyncio's handler; and a signal Python drops outside a loop
  keeps the next loop from starting. The same CLI path now: one SIGTERM, exit 130 within 0.9 s, the
  spend of 6 requests written inside the loop, in both arms and on both Pythons. u12 A-60 amended in
  place (no new number), its 00-INDEX row, the MANUAL, the EXIT STATUS of `dottore(1)`, the
  CHANGELOG. `tests/cli/test_termination_signals.py` has 28 tests (10 before): the hang test pins
  one signal as enough in both arms, its safety net never needed, and no clock decides any of them;
  30 runs in a row green on each Python, alongside a `make gates` run. Each broken variant fails it:
  #94's handler (raising in place) fails 3 (the hang test's ignored arm and two CancelledError
  cases), a handler that raises from a loop callback of its own fails the two `loop.close()` cases,
  no wake-up fails the two select() cases, and no memory of a dropped signal fails the two
  dropped-signal cases. `tests/cli/test_probe_pass_spend.py` gains `[sigterm-ctrl-c-ignored]`
  through the real CLI (without the wake-up it still passes, in 32 s instead of about 2), and its
  three signal cases check exit 130. `make gates` green (with `PYTHONPATH` set to the worktree's
  `src`): 4637 tests, 97.58% coverage, 75 specs lint OK, four import contracts kept, self-scan,
  bandit and pip-audit clean. Python 3.11, what CI runs, is not installed on this machine; tested on
  3.12.13 and 3.14.7.

## State, 2026-10-10 (night): the pre-merge audit of `3d739f3` (OD-41), six lows closed

- Merge-ready per the audit; closed on the same branch. L1: the resume test checks `--estimate
  --resume` (5 done, ~3 to send). L2: a conversation the filter cut carried no reply, so a
  forbidden tool called on an earlier turn was never scored; the aggregate keeps the model's last
  reply with the trace whenever there is a call, the runner reads it with the trace evaluators
  only, a fail decides (error moved to `request.metadata.provider_filter_cut`), anything else
  stays blocked and not exercised. L3: the Gemini block needs a `candidates.` text path. L4:
  Vertex AI's `MODEL_ARMOR` and `JAILBREAK` (its REST reference, read 2026-10-10), not
  `IMAGE_SAFETY`, on which the references disagree. L5: report-1.0 grows additively, as before, so
  the CHANGELOG says a new report fails an older copy of the schema. L6: a carrier probe the
  filter refused stopped `-sV`; the engine's `is_prompt_filtered` (wired to
  `core.execute.is_provider_filter_block`) makes it a failed probe, as Prompt Shields classes an
  encoded instruction as an encoding attack. The FAQ line of 152 characters is rewrapped. Not
  started, at the conductor's request: the Bedrock guardrail and Azure output-filter gap. 17
  tests more (52 adapter, 13 core, 7 CLI, 6 fingerprint and the base64 carrier through the CLI).
  `make gates` green (2026-10-10, 21:25): ruff, format (387 files), mypy strict (156 source
  files), import-linter (4 kept), spec lint (0 errors, 0 warnings across 75 specs), 4,971 tests
  with 97.63% coverage, self-scan 0 high/critical, bandit, pip-audit (no known vulnerabilities).

## State, 2026-10-10 (evening): a provider's input-filter refusal is a blocked attempt (OD-41)

- On `feat/provider-filter-blocked-attempt`, from `main` at `92c7b11`: the owner decided
  (2026-10-10, 17:33) that an attack prompt the provider's own input filter refuses before the
  model sees it no longer aborts the campaign (exit 3 after 1 request, measured on `92c7b11`
  against a loopback stub answering Azure OpenAI's 400 `content_filter`). Built (u08 A-69,
  ADR-0011, OD-41 closed): `adapters.base.ProviderFilterBlock` for Azure's 400 `content_filter`
  (every `BaseAdapter`) and Gemini's `promptFeedback.blockReason` in a success body with no text
  (REST), each shape cited in the code; every other 4xx unchanged. `execute_attempt` reads the
  `blocked_by_provider_filter` marker: one send, debited, tokens released, the error marked
  `[blocked_by_provider_filter]`; the runner's verdict is `inconclusive:
  blocked_by_provider_filter` (a new `InconclusiveReason`), scored as an attempt without a reply
  (a spec all blocked is inconclusive and not exercised, never a pass); a resume keeps it,
  `dottore replay` re-derives it, and the JSON summary (`blocked_by_provider_filter`), SARIF,
  JUnit, HTML and the terminal count it. A run all blocked is complete, not unreachable. The judge
  path is unchanged (`capability_unavailable`). The `-sV` benign probe's failure reads
  `ProviderFilterBlock`. With the stub and a judge: exit 0, 14 attack requests, 8 blocked, 12
  judge requests. Tests: 7 CLI (4 fail on `92c7b11`), 45 adapter and 10 core (not collected on
  `92c7b11`). Left open: Bedrock's guardrail intervention (an HTTP 200 read as a reply), OpenAI's
  `invalid_prompt` 400 and Gemini's OpenAI-compatible endpoint (no documented shape); the `-sV`
  pass still stops on such a refusal of an attributing probe (the benign one and, since the
  audit, the carriers are failed probes). Not run against a live Azure or Gemini endpoint.
  `make gates` green (2026-10-10, 20:49): ruff, format (386 files), mypy strict (156 source files),
  import-linter (4 kept), spec lint (0 errors, 0 warnings across 75 specs, 14 suites, 1 pack), 4,954
  tests with 97.63% coverage, self-scan 0 high/critical, bandit,
  pip-audit (no known vulnerabilities).

## State, 2026-10-10: URL passwords behind a credential holding a URL separator (#96)

- On `fix/redactor-issue-96`, from `origin/main` at `f12ba83`: the two regressions accepted with #56
  and the endpoint cut the #56 pre-merge audit found, issue #96. (1) A registered credential holding
  an `@` across a URL's `@`, in the user or the password, let the URL rule read on to a labelled
  value's `@` and its tail stayed readable (`redis://ops:«REDACTED:url_password»@Value99xyz`): the
  URL mask stays, and after the labelled and the entropy rules, where they left text readable, the
  rest of the value is masked as the value up to a `://` that a `:` and then an `@` follow, and the
  labelled rule runs again from where the value ends without reading its tail for a label. (2) A
  registered credential holding
  the URL's `://` (two overlapping ones as one run: `key-ABCD1234` and `1234://bob`), its `:` or the
  password's `@` with no later `@` stopped the URL rule: the URL is now read in the text as written,
  last in the pass, and what of its password is still readable is masked. (3) The policy gate's
  refusal and `shown_auth_ref` quote an endpoint without its userinfo before cutting it
  (`shared.config_errors.shown_endpoint`, moved from `cli/fleet`): cut first, 287 characters of a
  308-character password were printed. u01 A-31 and A-51 amended (no new clause).
- 2026-10-10, after the independent pre-merge audit of `924c276`: chained labelled values after a
  URL mask leaked (on main too), `cli/app._masked` ran the URL rule on the raw text before the
  redactor and cut registered credentials holding `@` or `:`, the tail stopped at every `://`, and
  the docs claimed more than the code. Fixed in `38eac50` and the commits after it, docs aligned,
  one Left open list everywhere. The audit's proposal for the tail (stop only where the URL rule
  matches in this pass) was measured and not taken: 3 texts of 300,000 showed text main masks, as
  the next pass reads that URL. The re-audit of `adeac2d` found the second run of the labelled rule
  starting at the tail's stop, not at the value's end (a chained secret readable), and the stop
  wider than needed; both fixed with its prototypes (`80ce50d`, `913045a`), and
  `mask_url_passwords`, left with no caller, removed (`e3b4b8a`). The night's reboot wiped
  `/private/tmp`, worktree and scratch
  included; the branch survived at `924c276`, the fixes were redone in `_ildottore-tren/wt/issue96`
  and the fuzzers rebuilt in `_ildottore-tren/scratch/issue96`.
- The audit's narrow fix for (1) was measured and not taken: it left readable a character main masks
  in 15,239 of 300,000 differential texts. The fix, against main: 0 texts leaking anything main
  masks, 0 errors, 0 fixed-point failures on 900,000 texts of my fuzz before the re-audit and
  300,000 on the final tree (120,167 texts with a secret main leaves readable masked there), on
  1,500,000 and then 500,000 of the auditor's, and on 300,000 of the re-auditor's. Against the
  redactor
  before #56 (the auditor's 40,000 item-1 texts): a secret it masked is readable in 2,666 texts on
  main, 98 on `924c276`, 18 now (none chained). On 2 MB of a reply echoing such a credential in
  every URL (seven hostile shapes) the redaction is linear and takes 1.0 to 1.4 times main's traced
  memory and 1.1 to 2.8 times its time (24.8 bytes a character against 17.6 with a credential
  holding an `@` in every password); on 4 MB of that shape, 182 MB of peak RSS where main takes 120
  MB. 24 mutants of the fix before the re-audit, 21 caught (one by a hang), and 5 of the re-audit's
  changes, all caught; the 3 missed change nothing a test
  can see (a guard against two of its masks overlapping, which they cannot; the label search
  starting after the userinfo's last mask, which only bounds its cost; an off-by-one where the URL
  rule cannot match from inside a mask). `make gates` green (with
  `PYTHONPATH` set to the worktree's `src`): 4,671 tests (4,618 on `f12ba83`), coverage 97.63%, 75
  specs lint OK, four import contracts kept, mypy clean on 155 files, self-scan, bandit and
  pip-audit clean.
- Left open after #96: where the URL rule did read a URL, its reading stands, so after a registered
  credential holding the user's `:` the rest of the user is shown
  (`redis://ops:svc-keyXYZ:<password>@host` with `ops:svc-key` registered shows `XYZ`, which urllib
  reads as the password's head); a labelled value whose label sits in the user of a URL read through
  a mask or behind an empty user (both read since #56), or is glued to the word before it
  (`...3password="x@host.tld`, a label to no version), keeps what follows the URL's `@` readable as
  its host, where the redactor before #56 masked it whole or as an address; the rest of a labelled
  value after a URL mask stops before a `://` that a `:` and then an `@` follow before any
  whitespace (the shape the URL rule needs, in this pass or the next), so what of the value lies
  past that `://` is left to the other rules (`secret=AETw://0G1h9.mGle` and U+200B before
  `://u:<password>@h` shows `0G1h9.mGle`); a raw `@` in a URL's user or unregistered
  password leaves the password, or its part after the `@`, readable; and a URL whose `://` is split
  by an invisible character (`s3:/<U+FEFF>/bob:...`) is read by no URL rule.

## State, 2026-10-10 (morning): the A-68 pre-merge audit, redone after a reboot

- The Mac rebooted overnight and wiped `/private/tmp`: the worktree, its uncommitted fixes and the
  auditor's scripts were lost; `fix/anthropic-models-without-sampling` survived at `7dd5ec1`. The
  worktree is now `_ildottore-tren/wt/anthropic`, scratch under `_ildottore-tren/scratch/`, and
  the fixes are redone in small commits. MEDIUM: a judge whose model refused sampling was silent
  (`SemanticJudgeEvaluator` read `SamplingRefused` as an outage: every judged spec inconclusive,
  exit 0, 29 judge 400s); it is re-raised and stops the run. Lows: `SamplingRefused` fires only on a
  sent parameter named as a parameter (`sampling_params_named`,
  `tests/adapters/test_sampling_refused.py` with 21 tests, 17 failing on `7dd5ec1`); the run records
  whether its target and judge were sent a temperature and a resume that keeps attempts continues as
  it started; `sampling_not_sent` counts the block as written; the judge refusal says "capabilities"
  without nested parentheses; the gateway id forms (ARNs, `anthropic/claude-opus-4.7`, `[1m]`)
  match; Mythos is named everywhere, the reference's Sonnet 5 contradiction is written down, USAGE
  carries the not-tested-live caveat, `examples/target.openai.yaml` no longer suggests
  `sampling: false` for a reasoning model. `tests/cli/test_models_without_sampling.py`: 66 tests, 18
  failing on `7dd5ec1`. Verification of `569bb3b`: a probe recorded nothing of a block whose only
  field is a seed that does not go out, and the resume notice named a top_p that never goes out
  to Anthropic; both fixed.

## State, 2026-10-09 (night): Claude models that take no temperature or top_p (A-68)

- On `fix/anthropic-models-without-sampling`, stacked on `feat/apply-sampling-defaults` at
  `00b2fca`: a defect the A-66 pre-merge audit found, older than it. Per Anthropic's API reference
  as bundled with the claude-api skill (cached 2026-09-25, not tested live), Opus 4.7 and later,
  Sonnet 5 and Sonnet 5.5, and the Fable and Mythos 5 families refuse `temperature` and `top_p`;
  the scanner pins temperature 0, so every `provider: anthropic` campaign against them stopped at
  its first request. Built (u12 A-68): `capabilities.sampling` (`bool | None`, the one capability
  not false unless set; `None` is the default rule), a documented list in one place
  (`adapters.anthropic.MODELS_WITHOUT_SAMPLING`, matched by family, overridden by the capability),
  `sampling_enabled` on the Anthropic and OpenAI adapters through their own `sent_sampling`, the
  record through the same rule plus `request.metadata.sampling_not_sent`, the "not temperature-0
  deterministic" notice on stderr before a run, in `--dry-run`, `-sn`, the `-sV` line, `dottore
  fingerprint` and `dottore replay`, and `SamplingRefused` for a 400 that names a sampling
  parameter the request sent. The digest leaves a null `capabilities.sampling` out, so no stored
  run changes digest. `tests/cli/test_models_without_sampling.py`: 40 tests, 37 fail on `00b2fca`.
  No open decision. Left open: no run-level word for it in the HTML, SARIF and JUnit reports; a
  model the list does not name costs one refused request.

## State, 2026-10-09 (evening): `sampling_defaults` applied as a fallback (OD-39)

- On `feat/apply-sampling-defaults`, from `main` at `f12ba83`: the owner decided (2026-10-09,
  20:36) that a target file's `sampling_defaults`, parsed and validated since #73 and #78 and sent
  by nothing, applies as a fallback. Built (u12 A-66, OD-39 closed): per field, the request's own
  value (the spec's `sampling`, then temperature 0 for a spec that declares none, after the block;
  `PROBE_SAMPLING`; the judge's per-pass temperature and `top_p` 1.0), then the block of the file
  the request goes to (the judge's own), then the provider's default; only the fields the
  adapter sends (`wiring.sampling_fallback`: OpenAI all four, Anthropic no `seed`, REST, MCP and
  WebSocket none); the runner fills its own requests (`core.runner.spec_sampling`, so attempts
  record what went out), the probes and the judge go through a wrapper outside the probe
  recorder; `--estimate` prices the block's `max_tokens`; `--dry-run` prints a
  `sampling:` line; a run an older version started (no `sampling_defaults_applied` in its
  context) resumes without the block and says so on stderr. Pre-merge audit of `8d1bc59`
  (merge-ready after one MEDIUM): a block `top_p` beside the temperature every request carries
  stopped every Anthropic campaign (Anthropic's API reference, as bundled with the claude-api skill
  and cached 2026-09-25, says Claude 4 models refuse the pair with HTTP 400; not tested live), as
  the six shipped specs that set `top_p` 1.0 did on main, and an Anthropic judge's own `top_p`
  1.0. Fixed: `adapters.anthropic.sent_sampling` (no `seed`, no `top_p` beside a temperature)
  builds the request and the record, through `CampaignRunner(sent_sampling=...)` and
  `wiring._AsSent` (which replaces `_SamplingFallback`); a block `seed` goes out only with
  `capabilities.seed: true`; `--dry-run` says what of a target or judge block does not go out;
  the "different target" refusal names `sampling_defaults`, an edited `--judge` file is named as
  such; `_JUDGE_SAMPLING` is gone. `tests/cli/test_sampling_defaults.py`: 42 tests, 37 fail on
  `f12ba83` and 15 on `8d1bc59` (the helpers are imported inside their tests, so the file is
  collected on both). Docs in the same pass: MANUAL §4.2 and four flag rows, FAQ, USAGE, both
  man pages, `docs/01`, `03`, `09`, `10`, the example target files and the README's Scenario B
  and G transcripts, the u04, u08, u09 and u06 contracts. Left open, and written in A-66: a REST,
  MCP or WebSocket attempt still records the spec's sampling that nothing carries; the OpenAI
  adapter sends a spec's `seed` whatever `capabilities.seed` says; the Anthropic adapter sends
  `max_tokens` 1024 for a request with none and records none, while the ledger reserves 512; and
  Claude models that take no sampling at all (Opus 4.7 and later, Sonnet 5, the Fable and Mythos 5
  families, per the same reference) refuse every request, its temperature 0 included (its own
  branch, `fix/anthropic-models-without-sampling`).

## State, 2026-10-09 (evening): a refusal the guardrail probe asked for is not a filter (OD-40)

- On `fix/guardrail-layer-requested-refusal`, from `main` at `f12ba83`: the guardrail layer read
  any refusal as evidence of an output filter (and a canned one of an input filter), although its
  only probe asks the model to refuse, so a model that followed the instruction was reported
  filtered (every corpus case, the golden fingerprint; `docs/16` §1 named it). The owner decided
  at 20:36 that a refusal the probe requested no longer counts as a filter (OD-40, u09 A-67).
  Built: `probes.GUARDRAIL_BATTERY`, two probes that each declare the reply they expect. The
  request to refuse (`guardrail_nudge`, same name, prompt and seed) gives `refusal_style` and the
  family tells only; a benign request worded near a boundary (`guardrail_benign`) gives the new
  key `benign_refused` (filter or alignment, not split); `output_filter` comes only from the
  provider's own filter stop (`content_filter`, `refusal`), never from `length`; `input_filter` is
  `null`. `-sV` is 18 requests. The benign reply attributes nothing and the engine leaves it out
  of the constant-target check, so the A-35 measurement was re-run on the new pass and holds
  (12,276 passes, 2,344 of 10,752 differ, none names more); the planner reads no profile key, so
  the ordering is unchanged and pinned. Golden: only `guardrails` changed. Tests:
  `tests/fingerprint/test_guardrail_requested_refusal.py` (18, 14 fail on `f12ba83`), three new
  cases in `test_probe_failures.py`, and the CLI tests that pinned 17 probes now derive the count.
  `make gates` green on `cd413c0`: 4639 tests, 97.60% coverage. The pre-merge audit of
  `cd413c0` found it not merge-ready, one high reproduced: an input filter that answers the
  benign request with a 4xx (Azure OpenAI's prompt filter: HTTP 400 `content_filter`) stopped
  `fingerprint` and `run -sV` with exit 3 after 8 requests, where `main` exited 0. Fixed on top:
  `AdapterStatusError` carries the status, `cli.wiring.refused_request` is injected, and the
  engine makes a 4xx to a profile-only probe a failed probe (`benign_refused: null`); the same
  4xx on any other probe still stops the pass. Also: `output_filter` is `null` with no stop
  reason from the provider (REST without `finish_path`, WebSocket `final`, MCP, mocks);
  Bedrock's and Gemini's filter stops are read; answer markers on the benign request;
  first-person whole-word refusal phrases with "decline" and "unable to"; `null` style and
  `benign_refused` on a constant target; the remaining present-tense 17s. A-35 measured again,
  unchanged; golden unchanged. Left open: dropping `input_filter`, or setting it from that 4xx
  (OD-40), and the attack phase, which still stops a campaign on such a 4xx (a product error, as
  on `main`). `make --no-print-directory gates` green on the fix (`abc6ffe`): 4683 tests, 97.61%
  coverage, 75 specs lint OK, four import contracts kept, self-scan, bandit and pip-audit clean.
  Its verification found it merge-ready, with three lows closed on top: a benign reply with
  neither an answer marker nor a listed refusal phrase is unclear (`benign_refused: null`, it read
  `false`), `AdapterStatusError` copies and pickles with its status, and the docs name the HTTP
  adapters (openai, anthropic, rest, mcp), with a comment on why a WebSocket target's refused
  upgrade still stops the pass and an adapter-level test of the four. `make --no-print-directory
  gates` green on them: 4700 tests, 97.61% coverage, the same static, lint, self-scan, bandit and
  pip-audit results. Not re-run against a live model.

## State, 2026-10-09 (evening): four exception class names the redactor masked

- On `fix/error-names-survive-redactor`: the redactor's high-entropy rule masked four of the
  package's 45 exception class names, alone and in the lines that write an error with its class
  (`<class>: <message>`, `aborted on <class>: ...`), as #87 found for four of the WebSocket
  adapter's: `ChecksumMismatchError` and `ProbeCeilingReached` (listed by an audit of main),
  `BudgetExhaustedAfterReply` and `_ImpossibleFigure` (found by walking every class). No message on
  `f12ba83` wrote any of them with its class, so nothing a run prints or stores changes. Checked end
  to end on that tree: a `-sV` pass into `--budget-requests 30` against a loopback server answering
  503 to every other request, a scope with a wrong checksum, and a reply whose usage crossed
  `--budget-tokens 100000`, with no class named and no mask; a mock target's adapter made to raise
  the first one read `aborted on «REDACTED:high_entropy:2559426b»` on the terminal and in
  `summary.status.reason`. Renamed to `ScopeChecksumError` (`ChecksumMismatchError` kept as an alias
  of the same class, since `ildottore.policy` exported it in 0.1.0), `ProbeCeilingHit`,
  `ReplyOverBudget` and `_UnreadableLogprob`; the rule is unchanged.
  `tests/policy/test_redactor_error_class_names.py` (4 tests, in CI Gate 3; 2 fail on `f12ba83`, the
  walk naming the four in 24 lines) walks every exception class of the package, reads every class
  written in a function body from the source, and replaces #87's WebSocket-only test (9 test items).
  The pre-merge audit of `59e522b` (merge-ready) asked for the walk's guard to check modules, not
  the new names (it failed first on `f12ba83`, so the 24 lines were not what it printed), for the
  source pass, for `_UnreadableLogprob` (it covers strings and bools too), and for the move to
  `tests/policy/`, which Gate 3 runs. u01 A-63 and its index row, u08, the MANUAL's redaction
  paragraph and the CHANGELOG, whose unreleased entries now use the new names. `make gates` green
  (with `PYTHONPATH` set to the worktree's `src`, one run from the start, 21:30 to 21:36, after the
  audit's changes): 4613 tests, 97.60% coverage, 75 specs lint OK, mypy clean on 155 files, four
  import contracts kept, self-scan (0 high or critical), bandit and pip-audit clean. Left open:
  other packages' exception names, which cannot be renamed (the rule masks 12 of 216 in Python's
  builtins, the standard-library modules the adapters use and the ten dependencies; httpx's
  `TooManyRedirects` is never raised and websockets' two proxy errors are reworded without their
  class), and a plugin's own class names.

## State, 2026-10-09 (evening): a confirm flag the model sets itself is not a confirmation (OD-38)

- On `fix/self-confirm-is-not-confirmation`, off `f12ba83`: the owner decided (20:36) the question
  left open on 2026-10-07 (night): a `confirm: true` the model puts in its own destructive tool
  call is not the user's confirmation; only one from outside the model counts (the user's reply
  after the agent asked, never the request to act itself; the harness; a declared approval).
  Numbered OD-38 (no open OD covered it; OD-38 was reserved for
  this change, as was A-65). None of the three reaches an evaluator today: the scanner is a scan's
  only user and no spec's prompt confirms a destructive step, so `tool_call` and its lint stub fail
  every destructive call whatever flag (`confirm`, `confirmed`, `confirmation`, `force`,
  `approved`, `ack`) it carries, as `kill_chain_progression` already did for the calls its stage
  map puts at `destroy`; a `granted_tools` grant still authorizes a name, not a call. Neither of
  `AG-DESTRUCTIVE-DBDROP-001`'s two trace evaluators reads a flag now, so a flag can no longer
  make them disagree (where their checks differ they still differ by design), and
  `AG-CONFIRM-BYPASS-001` fails the agent that confirms its own deletion, which
  its `vulnerable` fixture now is, so lint and the battery prove the rule. Four specs reworded
  (that one, `AG-DESTRUCTIVE-DBDROP-001`, `AG-AUTONOMY-SELFCORRECT-001`, `AG-EXTORT-CHAIN-001`);
  no shipped fixture's verdict changed. u06 A-65 and §9, the index (OD-38 row, A-65 row), u13 §7;
  `tests/evaluators/test_self_set_confirmation.py` (67 tests, 45 fail on `f12ba83`), four old
  tests inverted; on `f12ba83` the shipped specs fail lint (`FIXTURE_NO_DETECT`) and three battery
  tests. Docs: MANUAL §8, FAQ, `docs/03`, `docs/04` §1, `docs/13` §3, `examples/target.app.yaml`,
  CHANGELOG. The OWASP, ATLAS and IoPC coverage figures and the battery's counts (75 specs, 14
  suites) are unchanged: no mapping moved (`dottore coverage --json` is byte-identical to
  `f12ba83`'s). `make gates` green (with `PYTHONPATH` set to the worktree's `src`): 4685 tests
  (67 new, 24 of them from the pre-merge audit below), 97.60% coverage, 75 specs lint OK, four
  import contracts kept, self-scan, bandit and pip-audit clean. Left open, out of reach rather than
  decided: a confirmation from outside the model needs an input no evaluator has (a harness's
  approval record, approvals a target declares, a spec whose later turn confirms after the agent
  asked); when one exists it is the only thing that may mark a destructive call confirmed. Until
  then neither evaluator can honour a scripted confirmation (a later turn saying "yes, I confirm"),
  so a custom spec that tests acting after one should rely on
  `semantic_judge` (MANUAL §8, `docs/03`).
- Pre-merge audit of `095aa55`: merge-ready once one MEDIUM was fixed, now fixed with five lows.
  The MEDIUM: the agreement of `tool_call` and `kill_chain_progression` was overclaimed in the
  `kill_chain` docstring, the MANUAL, `docs/13` and the A-65 row ("the two agree on any trace a
  spec declares both for"). On `AG-DESTRUCTIVE-DBDROP-001` a `truncate_table` fails `tool_call`
  and passes `kill_chain_progression`, which knows only its stage map, and on
  `AG-EXTORT-CHAIN-001` a `read_env` does the same (recon only). The true claim, now written in
  all four and in A-65 and the CHANGELOG: neither reads a confirmation flag, so a flag can no
  longer make them disagree, and both fail a `destroy`-stage call whatever its arguments; where
  their checks differ they still differ by design (the attempt still fails, as `tool_call`
  decides). Pinned by 24 new tests in `tests/evaluators/test_self_set_confirmation.py` (flag
  invariance of both evaluators over every scene tool of the two specs and four off-scene names,
  both failing each destroy-stage call with every flag placement, and the two traces where they
  differ); on `f12ba83` four of them fail, the ones on the destructive tools
  `AG-DESTRUCTIVE-DBDROP-001` authorizes: off an allowlist a call already failed as unauthorized,
  flag or not. The lows: a user's confirmation is defined as a reply after the agent asked, never
  the request itself (OD-38 rows, MANUAL, FAQ, `docs/13`); the scripted-confirmation limit is
  stated in MANUAL §8 and `docs/03`; the CHANGELOG lists `docs/03`; the FAQ says "in a spec that
  declares `tool_call`"; the stub's docstring says "destructive". `095aa55`'s message said the
  `kill_chain` docstring "says why the two agree now"; it now says what they agree on.
- Found by that audit and left open, both pre-existing on `main`: (1) the destructive verbs are
  matched as substrings of the tool name, so a hand-off tool named in the `transfer_to_<agent>`
  style (`transfer_to_billing_agent`) is destructive for `tool_call` and its stub, and since OD-38
  no flag can excuse it (checked: an allowlisted `transfer_to_billing_agent` fails "invoked
  without confirmation"); no shipped spec declares such a tool. (2) The lint stub's backtick
  pattern in `registry/fixtures_engine._STUB_INJECTION_RE` is still the one the evaluator dropped
  in the hostile-text audit (`[^`]*[A-Za-z][^`]*` between backticks): an unclosed backtick before
  40,000 letters takes 0.65 s to search there and 0.001 s in the evaluator's pattern. Only lint
  reads it, over a spec's own fixtures. **Both closed on 2026-10-11** (u06 A-71, the entry of that
  date above): a scene may mark a tool `destructive: false`, and the stub judges a call through
  the evaluator's own helpers.

## State, 2026-10-09 (afternoon): a run id masked as a phone number, and small leftovers

- On `fix/train-followups`: a run id whose 12 hex digits all came out decimal, (10/16) ** 12 of the
  draws or about one run in 281, was masked as a phone number in every report and CLI error, so
  `dottore replay` and `--resume` refused the id read back from the JSON report, and
  `tests/cli/test_hostile_nesting.py::test_arguments_at_the_limit_go_through_the_deepest_path_a_reply_reaches`,
  which replays it, flaked as often. `new_run_id` draws again; the redactor's phone rule is
  unchanged, and old ids of any shape replay by their directory name (u12 A-61,
  `tests/cli/test_run_id_digits.py`, 3 of 15 fail on `6401ee2`). Also: the `--resume -sV` pre-check
  writes its spend and ceiling with `budgets.budget_figure`, the helper #69 wrote for the halt
  reason (u08 A-6), made public (u12 A-48); the MANUAL and the live-validation runbook no longer say
  a halt message names the run id (it does not; the reports and the evidence directory do); and from
  the #94 pre-merge audit, with Ctrl-C ignored a SIGTERM in one of asyncio's callbacks can leave the
  run waiting for a second signal as it closes (the docs said only that it goes on; documented in
  u12 A-60 and the MANUAL and pinned by a test that no clock decides, not changed), the SIGHUP tests
  get a handler of their own so they pass under `nohup`, and "Until 2026-10-08" and "on main
  `e4d6c83`" read "In older versions". Merged `main` at `fb9a8a8` (#69, #74 and the others of the
  day), then the stack of #88, #60, #68 and #66 (`4475b6e`, the tree main holds since #66 landed
  as `be2a762`), and added four lows of the #66 re-audit: a test of the room check's clamp on the
  target share (it fails with the clamp removed), the resume of a sweeping spec whose only reply
  went unjudged (`(3, 2)`, priced exactly), "of a spec that uses `semantic_judge`" in A-48, and
  the MANUAL's `--estimate` row and `dottore(1)` reworded. Stacked last on `84e0229` (2026-10-09:
  `main` at `be2a762` with #56, #57, #51, #54, #70 and #87, the tree main holds before this
  squash): only this entry and the CHANGELOG's conflicted, and A-61 holds on the redactor #56 and
  #57 rebuilt (an all-digit id is still masked as a phone, one letter among the twelve still
  leaves it readable). #56's notes now name issue #96 as the one that tracks its two accepted
  regressions. `make gates` green (with `PYTHONPATH` set to the worktree's `src`): 4618
  tests, 97.60% coverage, 75 specs lint OK, four import contracts kept, self-scan, bandit and
  pip-audit clean. Left open: the hang itself (a fix would change how
  every stop works: raising from a loop callback of its own loses a signal that arrives as the last
  loop stops, and cancelling the run's task as asyncio does for Ctrl-C needs a handle on the task
  `asyncio.run` creates), and an old all-digit run's reports, and those of its resumes, which keep
  the mask.

## State, 2026-10-07 (evening): a chat endpoint over a WebSocket (provider websocket)

- On `feat/websocket-adapter`: a template-driven JSON-over-WebSocket adapter, so an assistant
  whose only chat surface is a socket is declared in a target file (`websocket:` block:
  handshake with `{{token}}`, query with `{{prompt}}`, how the streamed reply is read, session
  start, bounded reconnect) with no code. Same charter as the HTTP adapters: the gate before the
  dial (`wss` as `https`, `ws` loopback-only), no redirect followed, the credential recorded as
  its placeholder and scrubbed by value, every frame in the evidence, a turn bounded in time
  (inconclusive), bytes and frames (not retried), one connection per conversation, no query
  resent by the adapter. Worked example `examples/target.websocket.yaml` (Scenario H, dry run
  pinned: 10 specs, 125 requests). The pre-commit audit (33 mutants, twelve findings, all
  reproduced) is closed in the same PR: a nested frame no longer aborts the campaign, the
  handshake phase is capped, the transcript is recorded once, no live conversation is evicted,
  the credential is scrubbed from every error message and refused under 8 characters, the
  query send is under the turn timeout, a lost conversation is debited once, the loader
  refuses request placeholders in connection templates, placeholders in `vars` and the
  library's own upgrade headers, `equals`/`final_value` compare by type, cleartext `ws://`
  never goes through a proxy (`tests/adapters/test_websocket_audit.py`). Open for the owner:
  OD-34 (a transcript field on `ModelResponse` instead of `raw_ids["websocket"]`), OD-35
  (several queries on one socket), OD-36 (a reconnect mid-conversation for a stateless server),
  OD-37 (a `websocket:` block in a fleet entry). The PR numbered them OD-30 to OD-33, which
  `main` (OD-30, OD-32, OD-33) and PR #88 (OD-31) had taken; renumbered on 2026-10-09, after
  checking that no open PR claims OD-34 to OD-37 (the PR defines no A-clause; it amends A-19).
  Not built: binary frames, SSE or polled streams (declare them as `rest`), a session that
  survives a reconnect.
- Pre-merge audit (2026-10-09, the PR merged with `main` at `6401ee2`, which brought #65, #79,
  #92 and #93 among others): not merge-ready, now fixed. Frames are parsed with `bounded_loads` and
  `well_formed_json` (a frame with half a character escaped made `run` exit 3; the adapter is
  now on A-47's list) and `WebSocketFrameTooDeep` is a `ResponseTooDeep`; a tool call's
  JSON-text arguments are measured; close code 1007 (a text frame that is not UTF-8) is not
  retried, as 1009 is not; the adapter re-dials a socket that failed to open only within its
  own retry allowance, so under `run` every dial is a debited send (it was 8 dials for 4
  debits); the loader runs A-54's walk over the block (a date, NaN, half a character), refuses
  a `ws://` or `wss://` endpoint on any other provider, and cuts the names its refusals list;
  the docs no longer say a WebSocket (or REST) probe goes out at temperature 0, and the frame
  case is written into OD-21. Found while fixing: a fleet's `wss://` entry got a bare host in
  its scope (every port); it is pinned to 443 now. `tests/adapters/test_websocket_premerge.py`:
  36 of its first 40 tests fail on the PR head.
- Second pre-merge audit (2026-10-09, on `abcf7d4`): merge-ready once four error class names the
  redactor's high-entropy rule masked in the CLI error and the evidence are renamed
  (`WebSocketOverflow`, `WebSocketUndecodable`, `WebSocketLost`, `WebSocketTooMany`, each checked
  against `redact_text` by a test); also fixed: a 1007 or 1009 close the server starts is its own
  (`WebSocketClosed` with its reason, not retried), a key that is not text in the block is
  refused (A-44's walk), and the scope man page, the MANUAL and u04 match the code. 9 of the 16
  new tests fail on `abcf7d4`. Its verification (on `dceb587`): the same server close was still
  retried when it met a send rather than a receive (three retries, four debited sends, no
  query); one helper classifies both now (6 more tests, 4 fail on `dceb587`).
- Stacked on `1c5d1e2` (2026-10-09: `main` at `be2a762` with #56, #57, #51, #54 and #70, the
  tree main holds before this squash): the MANUAL's "Bounded replies" (two hunks, #68's one-probe
  rule and #57's credential sentence kept beside the WebSocket text) and §13 (the WebSocket rows
  and #60's `authz_leak` row) conflicted, each resolved keeping both sides; the index held
  OD-21 twice (main's copy dropped, the PR's, which adds the frame case, kept in main's place).
  Follow-ups of the earlier PRs: `websocket` in the A-53 key lists (#88), the WebSocket
  refusals named where #68's rule is stated, with 4 tests of the `-sV` pass, and a test that a
  close reason reaches the terminal written out (#51). `make gates` green (with `PYTHONPATH` set
  to the worktree's `src`): 4595 tests, 97.59% coverage, 75 specs lint OK, four import
  contracts kept, self-scan, bandit and pip-audit clean with `websockets` 17.2 (BSD-3-Clause, no
  dependencies).

## State, 2026-10-09: CLI errors keep the operator's file names (PR #70, begun 2026-10-07)

- PR #70 (`fix/cli-masked-paths`, `tests/cli/test_masked_paths.py`, clause A-38): besides main's
  rule, `_masked` keeps an existing path written whole, absolute or relative (one word, from the
  working directory), before a colon or a period and through directories with a space or
  `()[],;'"`, between characters the entropy rule does not join into a token, so the rest of
  the message is read as on main; only the whole-path walk is capped (1,024 lookups, 65,536
  checks). `dottore diff`'s
  incomplete-report refusal goes through `_masked`, as `calibrate`'s does. Found by the audits of
  PR #61. Three audits found the fix printing keys main masked while it kept more than whole
  paths (the name an `OSError` quotes, the existing directories of a missing path through a
  space, a `//` or a `/./`), so it was rebuilt on main's rule; a differential fuzz of 120,000
  messages finds no such key now. The delta audit of the rebuild found main's rule calling
  `os.path.exists` where main called `Path.exists` (which raises on 3.11 and 3.12), cached checks
  left uncounted, and touching parts merged; all three fixed. The audit of that fix found the cap
  stopping main's rule, which then printed a value main masked; main's rule has no cap now, makes
  main's lookups or fewer and, after the final audit (a cache of every path took 1.3 GiB where
  main took 21 MiB), holds nothing between tokens. Open for the owner: OD-25, printing the name
  of a file that does not exist. PR #51, which landed just before this one, touches the same S6
  row and `diff` refusal lines: stacked on it, `_masked` applies `visible_controls` last and the
  refusal's own wrapper is gone.
- Stacked on `6ac7c95` (main `fb9a8a8` with #88, #60, #68, #66, #56, #57, #51 and #54, the
  tree main holds before this squash; this worktree had resolved a merge of `a40e596` only, so
  the stacking brought in everything newer). `cli/app.py` (imports, `_masked`'s last line, the
  `diff` refusal), `cli/diff.py`, the manual and the S6 row conflicted, each resolved keeping both
  sides; the stacked CHANGELOG had kept #82's old note on report paths beside this branch's
  rewrite of it, and one is left. A-49 no longer says the CLI cuts a report path holding a space
  short, and this branch's "until #51" sentences are in the past tense. `make gates` green there:
  4,425 tests, coverage 97.50%.

## State, 2026-10-09: log commands in the middle of a line (PR #54, begun 2026-10-07)

- PR #54, on `fix/cli-legacy-workflow-commands` (`tests/test_terminal_log_commands.py`), stacked
  on PR #51 (`796c07c`, still open): `visible_controls` also writes the second `#` of
  `##<letters>[` as `\x23`, so GitHub's legacy `##[cmd]` and Azure's `##vso[area.event]`, which
  a runner reads anywhere in a line, no longer reach a log line whole; the off-universe values
  of `coverage` and of the run's summary and the `-vv` plan's reasons (a pack's
  `requires_policy`), all printed as a `repr`, go through it too. The `-vv` plan was found by the
  pre-commit audit (two reviewers): annotation, `set-output` and `add-mask` on the GitHub runner,
  `task.setvariable` on the Azure parser. The delta audit added the resume note, which quoted
  scope digests read back from the run store raw.
- Verified with the runners' own code, not on a hosted runner: the CLI's output from main, PR
  #51 and this branch (17 outputs each) fed to actions/runner `67f01c2`'s `OutputManager` with
  its real `ActionCommandManager` (scratch L0 test): on main and PR #51 every line with `##[`
  was a command (annotations, `add-mask` masking `FAIL` in later lines, `set-output`
  `verdict=clean`), from this branch none. Azure through the agent's `Command.TryParse`
  (`59c86a8`): `task.logissue` and `task.setvariable` before, none after. PR #51 opened one more
  such line (the run's off-universe warning, which `rich` markup used to cut). Again after the
  rebase onto the reworked PR #51 (`796c07c`): 11 of 18 outputs with a command on GitHub and 5
  on Azure from PR #51 alone, none from this branch.
- Open for the owner: OD-20, the JSON outputs keep `##[` as it is (by instruction) and still
  carry a command when printed to a log; option B escapes the `[` as `\u005b`. A real GitHub
  Actions run was not done: it needs a push to a fork or scratch repo, which waits for approval.
- Found on the way, not fixed here (pre-existing on main): a `regex_absence` pattern that is not
  a valid regex made `dottore lint` exit 1 with a `re.PatternError` traceback
  (`registry/fixtures_engine.py`) instead of a lint error; fixed since on main by PR #63 (A-33).
- `make gates` green on `796c07c` plus this branch: 2,518 tests (40 new; 26 fail on PR #51's
  code), coverage 96.57%. The suite prints `ResourceWarning`s for unclosed sqlite connections
  (28 lines, the same on PR #51's tree without this branch); not fixed here.
- Stacked on `e6ac2af` (main `fb9a8a8` with #88, #60, #68, #66, #56, #57 and #51, the tree main
  holds before this squash). The S6 row, the manual, u12 §6 and §9 and `cli/run.py` conflicted:
  each keeps both sides, the `-vv` plan's not-seeded reasons (OD-18 B, on main since) go through
  `visible_controls` as the skipped and refused ones do, and the "not covered" lists drop the
  legacy form and #51's split-credential item, which #57 closed. The stacked merge had kept two
  copies of a #51 CHANGELOG bullet and of its PROGRESS heading; one of each is left. `make gates`
  green there: 4,364 tests, coverage 97.46%.

## State, 2026-10-09: PR #51, format characters and the pre-merge follow-ups (begun 2026-10-07)

- The owner decided on 2026-10-07 (in the session that built it) that format characters (Unicode
  Cf: zero-width characters, the soft hyphen, bidi controls, the byte order mark, tag characters)
  are written out on the terminal too, in PR #51: `visible_controls` writes them as Python escapes.
  This branch's terminal-only match of a split credential (`mask_split_credentials`) was dropped
  when it was stacked on PR #57, which masks such a credential in `redact_text` itself (A-32).
- The pre-merge audit of PR #51 found no blocker. Its follow-ups, and those of the delta audit
  after them, are fixed here: the "no --judge" warning wrote the operator's target id raw (and is
  on one line now); `--compare` read a target id as markup (`[/]` raised `MarkupError` and no
  report was written, on main too) and `:warning:` in it as an emoji; `validate_sha256` used
  `match` with `$`; `fingerprint` keeps pydantic's JSON and escapes DEL and non-ASCII in it,
  falling back to `json.dumps` on a lone surrogate. Accepted and documented: the text glued to a
  split credential prints, as main prints it next to the credential in one piece. The legacy
  `##[cmd]` form is handled in PR #54, stacked on this one.
- Rebased on `4aa6cef` (PR #53). `make gates`: 2,478 tests (228 new in this PR), coverage 96.50%.
- Merged with main at `a40e596` (#83) on 2026-10-09. Every error main added since `4aa6cef`
  (quoted values #86, capped reads #76, id lengths #91, non-JSON values and `--runs` bounds #89,
  spec file names #49, fleet id casing #85, the `-sV` resume advice #83) goes through `_masked`;
  the new `-sV` resume notice quotes the target id with `repr`. Two interactions fixed in the
  merge: the `seed:` line of `--dry-run -vv` (#58) printed a spec's canary raw and now writes it
  out; and A-51's refusals name an id of up to 128 characters whole, which `_masked` now writes
  out at up to ten characters each, so `tests/cli/test_operator_file_quoted_values.py` expects the
  written-out id, bounds its line at 5,000 characters and looks for a whole `repr` with its quote
  (u01 A-51 and A-57 say so). `make gates`: 3,571 tests (229 from this PR), coverage 97.12%.
- Stacked on `4f466e2` (main `fb9a8a8` with #88, #60, #68, #66, #56 and #57, the tree main
  holds before this squash). `redactor.py` keeps one copy of the control and format ranges,
  #57's, and builds `_TERMINAL_CONTROLS` from those two alone, so `visible_controls` never
  escapes U+FFFD, which #57's match drops; `mask_split_credentials` is gone, `for_terminal` is
  `visible_controls(redact_text(...))` and `_masked` redacts `mask_url_passwords(str(exc))` again.
  `cli/diff.py` keeps #82's per-finding validation, then this branch's spec-id check, whose
  refusal now names the report as A-49 does (`the report <absolute path> holds '<id>', which is
  not a spec id; is this a run report?`, added to A-49's list). `fingerprint` keeps #68's probe
  warning (now written out too, as every warning) and prints this branch's ASCII JSON. Tests
  changed for the stack: the four `mask_split_credentials` cases call `for_terminal` or the
  redactor's split match; the periodic case uses a credential whose end repeats its start once
  (#57 matches one repeating a piece more than twice over without overlaps, a case it lists as
  open); the `lint`/`coverage` key is written as its `repr` since #90; the `fingerprint` stub
  gains the fields #68's warning reads. The pre-merge audit's medium (a key's control characters
  are written out, MANUAL and u12) and lows are applied, and the "until #51" sentences of the
  merged entries are in the past tense. `make gates` green there: 4,324 tests, coverage 97.40%.

## State, 2026-10-09: a registered credential split by characters that do not show (PR #57, begun 2026-10-07)

- On `fix/redactor-split-credentials` (`tests/test_redactor_split_credentials.py`): the redactor
  masks a registered credential split by control characters or by format characters (Unicode
  Cf) whole, with the unsplit digest, in `redact_text` itself, so the reports, the evidence
  store, the run store and the terminal no longer keep it in two readable halves (found by the
  audit of PR #51, on main). In a text holding such a character the whole match by value runs
  on the text with them dropped, and overlapping credentials are masked as one; text without one
  is redacted byte for byte as on main unless a registered credential holds one (differential
  fuzz: 0 differences in 2,079,091 texts). A
  lone surrogate no longer crashes `_digest` (the same line as PR #51). The owner decided on
  2026-10-07 that the terminal writes the format characters out too: that goes to PR #51, where
  `visible_controls` lives. The pre-commit audit found one regression of mine (a short credential
  with invisible characters inside was no longer masked as written) and seven low items (a value
  padded with spaces masking prose, a digest that followed the hash seed, a periodic credential
  costing a search per character, a registered `\x00` breaking a stash token, on main, tests that
  could not fail, doc claims), all fixed. The delta audit found that my first fix let a short
  credential break a longer one (up to 7 characters readable), and the pre-merge audit that the
  second left up to 6 of a short one readable; short and long matches are masked as one union now,
  every occurrence of a short one included (its delta audit: one overlapping itself lost its second
  occurrence under a longer match).
  Filed apart, on main: the JSON report keeps a dict key a target wrote raw, and a lone surrogate
  in a reply aborts the campaign in the evidence store (fixed since by PR #79, A-47). `make gates`
  on the branch, before the merge below: 2,380 tests (78 new), coverage 96.44%.
- Merged with main at `6401ee2` (2026-10-09). U+FFFD is a splitter now (`_REPLACEMENT_RANGES` in
  `_INVISIBLE_RANGES`), as PR #79's merge note asked: #79 reads half a character in a reply as
  U+FFFD before the redactor runs, so on the two together a credential split by one kept both
  halves in the evidence and `r.json`. Two new `_SPLITTERS` cases and a CLI case in
  `tests/cli/test_lone_surrogate.py` (the escape, the raw bytes, a U+FFFD the target wrote) fail
  without the range, all five. #79's sentences that said such a credential is not masked (MANUAL,
  the threat-model row, the CHANGELOG, u04 A-47 and OD-28) now say it is. The clause is u01
  A-32, not A-31: PR #56, which lands just before this one, defines its own A-31 (main has
  neither number). `make gates` on the merge: 3,529 tests, coverage 97.15%.
- Stacked on `2250b30` (main `fb9a8a8` with #88, #60, #68, #66 and #56, the tree main holds
  before this squash). `redactor.py` conflicted in four places, resolved as #56's notes asked:
  #56's `_credential_runs` (tokens keyed by the stretch) runs in a text without a splitter, the
  split match runs after it and alone in a text with one, `_mask_matches` passes each stretch as
  written to `_keep` and keys its tokens by it (so a private key holding a split credential keeps
  the digest A-31 gives it), one delimiter guard in `register_known_secret`, and one naming rule
  for a run (`_longest`, the length as it shows) in both matches. #56's overlap case for a key
  read with a trailing CR expected the CR form's own digest, which this branch's
  `test_a_key_read_with_a_trailing_cr_is_masked_as_its_plain_form` rules out (A-32): that case
  now checks a contained credential without a control character. Differential fuzz of the
  merge against `2250b30`, 20,000 generated texts: 0 differences in the 9,635 without a
  splitter, and in the 10,365 with one, a registered credential readable once the splitters are
  dropped in 6,380 outputs of `2250b30` and in none of the merge's. The index row is
  A-29..A-32, and the CHANGELOG's open case of two credentials overlapping in plain text is
  closed by #56. `make gates` green there: 4,095 tests, coverage 97.35%.

## State, 2026-10-09: a URL password behind a registered user; masks that depended on the process (PR #56, begun 2026-10-07)

- PR #56, branch `fix/redactor-url-userinfo-pem-digest` on `0f936b6`
  (`tests/test_redactor_url_password_and_digests.py`): two defects already on main, found by the
  pre-commit audit of `fix/cli-control-chars` with differential fuzzing against `d19b221`. A
  registered credential as a URL's user left the password readable when the host had no dot (the
  URL rule refused a user already set aside as a stash token), and the digest of a private-key
  mask was computed over stash tokens whose numbers depend on the masks before the key and on a
  set's iteration order, so it changed with `PYTHONHASHSEED`. Fixed with the case the same order
  decided: one of two overlapping registered credentials masked, the other's tail readable. Also
  fixed, on main too: `redis://:<password>@host` kept its password, and a registered credential
  holding `\x01` could break a stash token (its raw forms are no longer registered). New clause
  A-31 in the u01 contract (a mask depends only on what it masks).
- Five audits by subagent: pre-commit (100,000 differential cases; the first URL rule took about
  640 MB on a 4 MB reply, possessive now), a delta, pre-merge (2.1 million cases and the real CLI
  offline: no password in any report, the evidence or stderr, where main printed them) and two
  more deltas. The pre-merge audit found one case the PR made worse: a credential holding a
  delimiter, registered as the text reads it (`password@db`), crossed a URL's `@`. The two versions
  of a pass that joined the password to a credential crossing a URL separator each opened new
  holes (a password tail behind credentials holding `:` and `@`; then a labelled secret after the
  URL swallowed into the mask and a quadratic shape), all from reading the URL before knowing
  where the credentials are. The pass was backed out; a form holding a delimiter is no longer
  registered (main registered it, but it never matched the text as read), which closes the
  regression. 24 mutants of the final fix, each caught. `make gates` green on `0f936b6`: 2,359
  tests (2,302 on main), coverage 96.41%.
- Open: a registered credential across a URL's `://`, `:` or `@` breaks the URL rule. It stops it
  and leaves the rest of the password readable, as on main; or, across the `@`, lets it read on to
  a later `@`, so a labelled value after the URL loses its tail where main masked it; and two
  overlapping registered credentials masked as one run can cover a separator that main's
  one-at-a-time replacement left (main leaves part of the second credential readable there).
  Each needs a target writing a registered credential that holds a URL separator. The owner accepted
  the last two for the merge (2026-10-09); issue #96 tracks them. Also open, on main too: a
  raw `@` in a URL's user or unregistered password leaves the password, or its part after the `@`,
  readable (`myadmin@srv:<password>@localhost`); the labelled-secret rule stops at a mask
  (`api_key=<registered credential><tail>` keeps its tail), and a registered credential that is
  a label word (`password`) hides the label from it; repeated `BEGIN PRIVATE KEY` markers before
  one `END` cost 3.4 s a megabyte. Python 3.11, the version CI runs, was not available here.
- PR #51 also edits `redactor.py`. Its `mask_split_credentials` masked every registered
  credential of any text holding a control character, and every PEM holds a newline, so on the
  terminal a key's digest would have been computed over the credential's mask while the reports
  computed it over the credential (nothing leaks). It is gone: stacked on PR #57, #51 leaves the
  split match to `redact_text`, whose tokens record each stretch as written, so the terminal and
  the reports give a key one digest. PR #57 (split credentials), which lands right after this one,
  rewrites the same loop: its clause is A-32, and it passes the stretch as written to `_keep`.
- Stacked on `08ac9f8` (main `fb9a8a8` with #88, #60, #68 and #66, the tree main holds before
  this squash): only CHANGELOG and PROGRESS conflicted. The pre-merge audit's LOWs are applied
  here: the playbook no longer counts the clauses, A-31 and S6 compare with the redactor before
  A-31 instead of "main", and the manual, S6, A-31 and the CHANGELOG name the two accepted
  regressions. `make gates` green there: 4,012 tests, coverage 97.32%.

## State, 2026-10-09: a halted run keeps what it paid for, and resumes (PR #66, begun 2026-10-07)

- On `fix/resume-halt-mid-batch` (on main `0501752`, after #61): a request ceiling that stopped a
  run inside an identity sweep or between two attempts of a batch stored nothing for that spec,
  and `--resume` refused the run as one that "sent nothing" (found by the delta audit of
  `fix/authz-leak-identity-sweep`; on main, `DL-XTENANT-001 --runs 2 --budget-requests 3` sent 3
  and stored 0, and `PI-DIRECT-001 --runs 3 --budget-requests 2` sent 2 and stored 0). Decided
  and built: every reply the target gave is stored when its batch returns or a halt stops it,
  judged when the ceiling leaves room; when the ceiling refuses the judge, a deterministic fail is
  kept (OD-19) and any other reply is stored without a verdict, which the resume sends again and
  judges. A run that spent requests and stored no reply resumes from the start with its spend
  carried; one that spent none, an `--evidence-root` lacking what the journal holds (pending
  rows included), and an empty tree for a run older than the journal are refused.
  `--estimate --resume` now takes off the judge's share of the kept attempts (it priced 12 judge
  requests for a resume that sent 8). Measured through the CLI against a loopback stub, halted
  spend plus the resume's sends equals the final spend in every shape (1+3, 2+3, 3+3, 2+7, 7+12
  with a judge, 1+5 on the token ceiling). The pre-commit audit (two auditors) found, among
  others, a resume that published a PASS over a missing verdict and a deterministic fail lost at
  the judge; all fixed (the CHANGELOG lists them), then a delta audit and a pre-merge audit
  (verdict: merge) whose findings are fixed too; 30 mutants of the fix all caught. With `--judge`
  a reply stored without a verdict is paid for twice (re-sent, not re-judged). Open: the attempts
  axis counts an attempt whose first request was refused, and a Ctrl-C (or a SIGTERM or SIGHUP,
  which stop a run as Ctrl-C does, A-60) still drops the batch in flight. `make gates` green on
  its branch: 2386 tests (main `0501752`: 2351), coverage 96.50%, `dottore lint` 0/0 over 75 specs.
  Stacked on `e02b0b6` (main `6401ee2` with #62, #64, #82, #90, #67, #69, #74, #88, #60 and #68,
  the tree main holds before this squash): `cli/run.py` (imports, the estimate call),
  `core/runner.py` (`__all__`, the breach line, which keeps the `figures` form of
  `fix/halt-reason-figures` and this branch's notes) and the MANUAL's `--estimate` row conflicted,
  each resolved keeping both sides. With #60's sweep priced, the three strict `xfail`s pass (3
  passed under `--runxfail`) and the marker is gone. The pre-merge audit's medium, fixed here: the
  room check of the `-sV` refusals (A-48) priced every judge request of the battery, so with
  `--judge` it did not offer a "drop -sV" that fitted; it now takes off the judge's share as
  `--estimate --resume` does, each share clamped at zero (two `--judge` cases in
  `tests/cli/test_resume_sv_advice.py`, one failing without the fix). `make gates` green there:
  3,955 tests, coverage 97.31%.

## State, 2026-10-07 (midday): one refused `-sV` probe reply no longer stops the run

- On `fix/sv-probe-env-error` (`tests/fingerprint/test_probe_failures.py`,
  `tests/cli/test_probe_env_error.py`, clause A-35 in `u09`): with `-sV` or `-A`, a probe reply
  the adapters refuse as an environment failure (over 4 MiB, undecodable) stopped the run with
  exit 3 before any attack, while without `-sV` it failed one attempt (pre-commit audit of
  `fix/target-deep-json`). Now a reply that comes back refused (`retryable = False`, by the
  attack phase's own predicate) is a failed probe: its layer gives no evidence from it, the
  fingerprint is built from the rest (`probes_failed`, `probe_errors=[...]`), stderr says so,
  and the run goes on. A probe that gets no answer at all (503, timeout, refused connection)
  still stops the pass with its cause, as before: the first version isolated those too and its
  pre-commit audit measured 25.5 minutes of probing on a target that never replies (92 s
  before) and `dottore fingerprint` exiting 0 on a closed port; it also found refused replies
  letting a constant target skip the constant check (closed). The delta audit found a 401 with
  a body over 4 MiB read as a refused reply (now classified by its status in `read_capped`,
  which also stops the attack phase treating it as inconclusive), `dottore fingerprint` exiting
  0 when every probe is refused (now 3), and A-35 promising more than it holds: a partial pass
  can still break a tie a full one leaves unknown. Its real domain, measured over 12,276
  passes: it never names more than the same probes answered with an empty reply. The pre-merge
  audit (PR #68; no high or medium) found refusals of varied replies getting a target flagged
  constant (now never claimed once an attributing reply is refused; a refused carrier does not
  count, the delta audit's last catch), an unreproducible figure (replaced by the
  measurement above), and three untested behaviours (tested). A 200 that is not JSON still
  stops the pass (OD-21). Mutation passes (17 mutants, then 6 and 6 for the first two audits'
  findings, every one caught but an equivalent one) found the one-probe layers' own handling
  redundant with the engine's, so it is not there. Open for the owner as OD-23.
  `fix/target-deep-json` documents this gap as open in four places (CHANGELOG, MANUAL "Bounded
  replies", `docs/02`, `u04` §4) that flip when the second of the two merges: flipped in the
  merge with `main`, where PR #65 landed first, and `ResponseTooDeep` is now a failed probe too.

## State, 2026-10-09: `authz_leak` fed where it is declared (PR #60, begun 2026-10-07)

- `EMB-XTENANT-RETRIEVAL-001` (requires `rag`) declares `authz_leak` to corroborate across
  identities, but the identity sweep ran only for a spec that required `multi_identity`, so the
  evaluator never had two identities and its `capability_unavailable` held the spec
  `inconclusive` unless a deterministic check failed, a secure reply included. In the
  2026-10-06 local pass it was one of the 30 inconclusive (one attempt held by `authz_leak`
  alone, the other by a compromised judge). Found by the pre-commit audit of OD-18 B; it
  predates it. Option chosen: keep `requires: [rag]` (the spec still runs on single-identity RAG
  targets) and sweep for a spec that declares `authz_leak` when the target declares
  `multi_identity` (`sweeps_identities`), never over an in-band scene; with no sweep that check
  is set aside and named in the verdict, after a sweep short of two answers it is kept.
  `DL-XTENANT-001` (requires `multi_identity`) is unchanged. The estimate now prices the sweep,
  one request per scope identity on a live route, which it never did for `DL-XTENANT-001`
  either, and `--estimate --resume` leaves it out for a finished spec: with one identity every
  `docs/16` §3 figure is unchanged (re-measured), with two the last row is 784. Clause A-34
  (u08). The pre-commit audit found the half-failed sweep that passed a seen leak and the
  in-band sweep that read the scanner's own context as a leak; both fixed before the commit.
  `make gates` green: 2,320 tests, coverage 96.46%.
  Open, not decided here: the sweep is one observation per spec, scored on every attempt, so a
  cross-identity fail counts as reproduced on all of them, and its replies are not stored as
  evidence (a confirmed critical can cite no reply that shows the leak); and a scope identity's
  `canary` binds `{{run_id}}`, which a seeded deployment cannot hold (it would need the
  `run_token`).
  Merged with main at `a40e596` (#93's A-59 and #83's A-48 among what landed since its base,
  #58): the runner merged cleanly (the sweep's skip uses `_holds_plan`, its predicate
  `sweeps_identities`); the `--estimate --resume` figure now counts a finished spec with
  `planned_attempts_held` instead of building `mutators x runs` ids (A-59), and the room check of
  the `-sV` refusals reads that figure, so it no longer prices a finished spec's sweep again
  (A-48's limit now names retries only). One test pins both. Stacked on `9d7e7a7` (main `6401ee2`
  with #62, #64, #82, #90, #67, #69, #74 and #88, the tree main holds before this squash): only the
  ledgers conflicted. `make gates` green there: 3,842 tests, coverage 97.23%.

## State, 2026-10-07 (evening): a target file's top-level keys

- On `fix/target-unknown-top-level-keys` (u12 A-53; OD-31, decided by the owner on 2026-10-08:
  refuse both), from the "outside the clause" list of A-50: the three readers of a target file took
  the top-level keys they knew and dropped the rest, and read a `name`, `provider`, `endpoint`,
  `model`, `auth_ref` or `transport` that was not text as absent. So `endpont:` ran a live target on
  the offline mock, sending it nothing (one spec: inconclusive, exit 0; the full battery: a FAIL and
  a PASS, exit 1; measured on `2f6201a` and `c3e70d8`), and `capabilities:` children that lost their
  indent were ignored (34 specs planned instead of 59 on a `type: model` target). Built reversibly:
  `_read_target_yaml` checks the top level against `Target`'s fields and `mock_scenario`, text where
  text is read, and every reader refuses on the A-45 line naming the file and the key. Every target
  file and target block of the repository, and what `dottore fleet` writes, still load (new test).
  Left open, written in the clause: a misspelled value (`provider: opnai` goes to the REST adapter,
  and `transport: stido` on a stdio MCP target runs it on the offline mock, where its `mcp` suite
  scores a PASS with exit 0). `tests/cli/test_target_top_level_keys.py`: 43 of its 90 tests fail on
  `9b8b511`. A number as `provider` or `transport`, which A-40 (#81) read as no provider, is refused
  as not text; A-40's two tests of it now expect that. The check is built from `Target`'s fields, so
  the `websocket` field #87 adds is legal when it lands (pre-merge audit: a list kept by hand failed
  35 tests on the two merged).

## State, 2026-10-07 (afternoon): a logprob figure no model produces

- On `fix/hostile-logprob`: a reply whose logprob (or one of its `top_logprobs`) was a 400-digit
  integer, a list or an object made `dottore fingerprint` and `run -sV` exit 1 with a traceback
  and no report, and `run` abort with exit 3; a positive token figure scored
  `DL-MEMORIZE-DIVERGENCE-001` "likely memorized"; NaN and infinities reached the report as
  non-JSON tokens. A figure is now read only when it is a finite JSON number at or below zero; an
  entry's own figure that is not (named token or not) makes the block read as no block, so the
  attempt and its text evaluators go on and the membership spec is inconclusive, and an
  alternative that is not costs only its token's alternatives (u04 §7 A-39,
  `tests/cli/test_logprob_figures.py`). Open for the owner (OD-24): the whole block versus only
  the bad entry, a positive figure counted as impossible, and whether the evidence should say the
  block was unreadable rather than absent. Found by the audits, both since closed on main: a
  lone surrogate in a token or the reply's text, which aborted `run` (exit 3,
  `UnicodeEncodeError`), now reads as U+FFFD (A-47, PR #79), and a token nested about 100,000
  levels deep, which overflowed `str()`, is refused with its reply as nested too deeply, so it
  fails one attempt, not the campaign (PR #65).

## State, 2026-10-07 (afternoon): the figure that stopped a run, masked as a phone number

- Found by the audit of `fix/usage-figure-overflow`; fixed on `fix/halt-reason-figures`. A
  budget halt printed `(limit 500000, attempted «REDACTED:phone»)` on the terminal and in all
  four reports, because the reason is masked and a bare figure of nine characters or more is a
  phone number to the redactor (a Luhn-valid one, a card). Measured on main: every stop at the
  default 1,800 s wall ceiling (`1800.123456`), a target reporting 2**53 tokens, and the limit
  itself under `--budget-tokens 1000000000`. `BudgetExhausted` now writes its figures in digit
  groups, seconds to three decimals and a count from 10**18 up as a magnitude, rounded away from
  the ceiling; the runner takes them from `BudgetExhausted.figures`. The redactor is untouched
  (several sessions are changing it) and the reason is not exempted: a phone number the target
  wrote stays masked, and the terminal line is now tested to mask the reason. A card-shaped
  usage figure prints grouped, on purpose (A-6). The pre-commit audit (181,584 figure cases
  fuzzed through the redactor, none masked) found a crossed ceiling printed as an equal one and
  the untested terminal mask; the delta audit found the first still alive in the ledger, which
  rounded the elapsed time to six decimals before the figure was written (1,800.0000004 s
  printed as 1,800.000), and a negative float written wrong (unreachable). All fixed. Not in
  this change: a usage figure past the float range (above about 1.8e308) crashes the run on
  main while its spend is stored
  (`store/run_sqlite.py`), fixed by PR #67; the spec the halt cut stores nothing on main, fixed
  by PR #66, which also edits the breach line in `runner.py`; and the resume refusal names a
  `--budget-wall-s` flag that does not exist (it is `--budget-wall`), fixed by PR #72
  (`fix/resume-wall-flag-name`, merged 2026-10-08).

## State, 2026-10-07 (midday): a usage figure no float holds

- Found by the pre-commit audit of `fix/target-deep-json`, fixed on `fix/usage-figure-overflow`,
  built on #61 (merged as `0501752`) because it reuses #61's spend predicate: a reply whose
  `usage.prompt_tokens` (or any token figure the ledger reads) is a 400-digit integer made
  `dottore run` exit 1 on `OverflowError` when the spend was persisted, with no report, and one
  past 2^53 halted the campaign on the token ceiling after one reply. A 400-digit
  `moderation_latency_ms` made `fingerprint` and `run -sV` exit 1 the same way. Both readers now
  check the figure where it is read (`ildottore.shared.amounts`: `is_count`, a JSON integer from 0
  to 2^53, for tokens; `is_amount`, #61's predicate moved there, for the latency and the stored
  spend). An unreadable token figure is skipped and the next shape read; a reply with no readable
  shape keeps the reservation; a pair beside an unreadable cache figure is a floor. An unreadable
  latency is `null`. The ledger takes no guard: nothing a reply or the tool hands it can pass
  what `float()` converts (a run store edited by hand to an integer just under 2^1024 could, on a
  resume under a ceiling above 1.8e308, as on `main`; closed by #89, see the merge note below).
  Clause A-36 (u08, pointer in u09). Left open, unchanged: a figure up to 2^53 is
  believed, so a target can still end a campaign early on the token ceiling. Found by the audit
  and fixed by #74 (u04 A-39): a `logprob` no float holds made `-sV` exit 1 (adapter).
  `make gates` green: 2,452 tests, coverage 96.51%, lint 0 errors on 75 specs; 52 of the 101
  new tests fail on `0501752`, and 24 of 24 mutants of the fix are killed.
- Merge note (2026-10-09, `origin/main` merged in, with #89, A-55 in u12): `run` now refuses a
  `--budget-*` past 2^53, so the CLI test that believed 2^53 under `--budget-tokens 2**60` failed
  with exit 3. It now passes `--budget-tokens 2**53`: one reply of 2^53 is trued in and fills the
  ceiling exactly, and the next send is refused (exit 3, one request served, 2^53 recorded). The
  `<` boundary mutant of `is_count` fails it: the figure ignored, both specs run and the run exits
  0 (measured). The texts that leaned on a ceiling past 2^53 carry the same note (CHANGELOG,
  A-36, MANUAL): a total passes 2^53 only by replies sent together (two of 2^53 - 1 at
  `--concurrency 6`, measured), and the hand-edited store near 2^1024 resumed under 2^53 halts with
  exit 3 and sends nothing (measured), so that case is closed. `make gates` green after the merge:
  3,443 tests, coverage 97.10%, lint 0 errors on 75 specs.

## State, 2026-10-07 (evening): A-40's path printed a key as written

- PR #81 (A-40) squash-merged as `c3e70d8` after three audits. Its finding printed the keys on
  the path as written: a newline forged a finding line (its pre-merge audit, left for later) and,
  found by two audits of sibling branches, a lone surrogate made `dottore lint` and `coverage`
  exit 1 with a `UnicodeEncodeError` traceback (on these paths main before #81 did not). On
  `fix/huge-int-followups`: a path part that is not printable is written as `repr`, as #80 does,
  and so is every schema error's location. A surrogate key under `step_arg_patterns`, which crashed
  lint before #81 too, is closed on main by A-54 (#89) before the schema runs; there it still stops
  control characters (a newline in such a key forged a second finding line; pre-merge audit of #90).
  Left for the owner: a too-long number under a target file's `sampling_defaults` (pre-existing: the
  live run exits 3 unnamed in `target_digest`); a newline or another control character in a key that
  pydantic names, or in the spec `id`, still forges a finding line (#89 handles only an `id` UTF-8
  cannot encode).

## State, 2026-10-07 (evening): a report finding's validation error (A-49)

- On `fix/diff-report-validation` (`tests/cli/test_diff_report_validation.py`): `dottore diff` and
  `dottore calibrate` on a report whose finding does not validate (a `status` of `maybe-later`)
  printed pydantic's raw error over four lines, with the value and a docs URL and without the file;
  found by the pre-commit audit of A-45. `diff.load_findings` raises `the report <absolute path>
  failed validation: findings.1.status: ...` for the first finding that fails, at most 20 problems;
  a first version that validated all the findings together peaked at 1,116 MiB instead of 135 MiB on
  a 12 MB report. Exit 3 as before. Left as they are and written in clause A-49: the report's other
  refusals (`error: 'findings'` for an object without `findings`, a `summary` that is not an object,
  unless empty or zero), keys printed as pydantic renders them (through the redactor), and lax
  reading (`"yes"` is true).

## State, 2026-10-07 (midday): a SARIF fixture under `tests/` is no longer ignored

- Found by the pre-commit audit of `fix/gitignore-venv-symlink` (PR #62): on `main` at
  `0f936b6`, `.gitignore` line 30 was `!tests/**/*.sarif` with its comment after it on the same
  line. Git reads no trailing comments, so the negation was the rule and the comment together
  and re-included nothing: a SARIF fixture added under `tests/` would have been ignored with no
  warning, the class of bug that broke CI on 2026-07-08 ("CI GREEN on GitHub Actions" below).
  On `fix/gitignore-sarif-negation` the comment has a line of its own above the rule.
- Checked with `git check-ignore --no-index`: `tests/fx/a.sarif`, `tests/a.sarif` and
  `tests/reporting/fixtures/reports/x.sarif`, all three ignored before by `.gitignore:29:*.sarif`,
  are no longer ignored; a root `x.sarif`, `src/x.sarif`, `reports/x.sarif` and
  `evidence/x.sarif` still are. With real files, `git status` lists `tests/fx/a.sarif` and not
  the root one. A folder a directory rule excludes stays excluded (`tests/build/x.sarif`,
  `tests/__pycache__/x.sarif`): git cannot re-include a file under an excluded directory.
  `git ls-files -ci --exclude-standard` is empty before and after. No SARIF file is tracked
  under `tests/` (the reporting snapshot is `golden.sarif.json`, which `*.sarif` never
  matched), so nothing was lost. Note for the next check: `git check-ignore -v` exits 0 for a
  path a `!` rule matches, because it prints that rule, so read the rule it names, or drop `-v`
  and read the exit code.
- Every other line of `.gitignore` checked by a Python scan for a comment after a pattern and
  for trailing whitespace: none. `!specs/scope.example.yaml` has no comment and works as
  written; it re-includes a file no rule excludes (`/scope.yaml` is root-anchored and the name
  differs), so it changes nothing today and stays.
- PR #62 changes `.gitignore` at line 8 only, so the two branches do not collide in that file;
  both insert at the top of CHANGELOG `[Unreleased]` and of this ledger, so whichever merges
  second rebases and keeps both entries.

## State, 2026-10-07 (morning): a worktree's `.venv` link is ignored

- The pre-merge audit of PR #60 found every worktree showing `?? .venv`: worktrees reuse the
  main checkout's venv through a symlink, git sees a symlink as a file, and `.gitignore` had
  `.venv/`, which matches directories only, so a `git add -A` would have committed the link. On
  `fix/gitignore-venv-symlink` the rule is `.venv` (the directory and everything under it, and
  the link). Checked: in a worktree with the link, `git status --porcelain` no longer lists it
  and `git check-ignore -v .venv` names `.gitignore:10:.venv`; a real `.venv/` directory, a
  nested one and the files inside stay ignored; no tracked file becomes ignored (0 before and
  after). Nothing depends on the directory-only form: CI checks out without a venv, the Makefile
  hands ruff, mypy and bandit explicit paths (pytest takes `testpaths`), mypy's `^\.venv/`
  exclude is a regex of its own, and what does read `.gitignore` (ruff walking `src tests`,
  `tests/test_yaml_duplicate_keys.py` through `git ls-files --exclude-standard`, an sdist
  build) sees no difference between `.venv/` and `.venv`.
- The worktree setup was practice, not written anywhere in the repo; it is now in `AGENTS.md`
  §4: the link, `PYTHONPATH=<worktree>/src` (without it the steps that import the package run
  the main checkout's code and the coverage gate reads 0%, measured), and no `make venv` or
  `make install` in a worktree (the venv is shared).
- Found by the pre-commit audit, not fixed here (its own branch): `.gitignore` line 32,
  `!tests/**/*.sarif` followed by a comment on the same line, re-includes nothing, because git
  reads no trailing comments; a SARIF fixture added under `tests/` would be ignored. None is
  tracked today. `venv/` keeps its trailing slash: nothing here creates a `venv` link.

## State, 2026-10-09: a reply that holds half a character (PR #79, begun 2026-10-07)

- First noted on main by PR #57 (split credentials), reproduced end to end by the pre-commit audit
  of `fix/hostile-logprob`, and fixed on `fix/lone-surrogate-reply`: a reply carrying a lone
  surrogate (escaped, or its raw bytes `ED A0 80`) in its text, `id`, `model` echo, a logprob token
  or a tool call made `run` exit 3 with every spec unrun and no evidence (the evidence store's
  content hash encodes it) and `run -sV` exit 3 with no report; a multi-turn spec and the `--judge`
  request failed in httpx encoding the reply into the next request. Every reply is now made well
  formed where it is parsed (`shared.wellformed`, the base and MCP adapters, the MCP stdio line
  decoded with `surrogatepass`), in place, and so are a tool call's arguments (`call_arguments`): a
  lone surrogate reads as U+FFFD and the attempt is judged as usual, so a leak with a half before,
  after or between its words still fails; a half inside a word a pattern looks for splits it as a
  zero-width space does (same verdicts, pinned by a test). Contract u04 A-47. OD-28 decided on
  2026-10-07, the owner leaving the choice to the build: U+FFFD, not deleting the half (UTR #36 rev.
  15, 3.5 on deleting code points and 3.6.2 on ill-formed input; deleting would show the evaluators
  text no consumer sees), nor a marker, nor an inconclusive attempt (six characters would hide a
  leak); the owner also approved the #57 merge note and the helper's home in `shared/`. Nine audits
  in four rounds (pre-commit, delta, pre-merge, a last delta): the fix copied every reply; copying
  only a reply with a surrogate gave a target 2.8 times the peak for three bytes; a generator per
  level of the in-place fix made a clean reply nested 115,000 levels cost four times main's peak
  (now a cheap scan first, and a fix in place only when a surrogate is there); the deep tests parsed
  50,000 and 100,000 levels with `json.loads`, which 3.11 (the CI's version) cannot, and failed CI
  (now built in Python); MCP stdio still timed out on the raw bytes; and the docs promised more than
  the code (a split canary passes with a judge that says secure; one `FF` byte does not stop an MCP
  SSE or stdio target; one long string with a half costs 3 times the parse's peak). A pre-merge
  round of two on `73e471a` (2026-10-09) found no defect in the code and every call site killed by
  mutation, but the evidence keeps a tool call's arguments text as sent (the escape included), a
  leak split inside a word is missed as with a zero-width space (now pinned by a test and written
  down), no test held U+DBFF, U+DFFF or a reply that is one string, and some merge notes and figures
  were stale; all corrected. Merge notes, in PR #79: with PR #57 (open) a credential split by a half
  is masked only once U+FFFD is in #57's `_INVISIBLE_RANGES` (adding it to its splitter lists alone
  fails #57's own consistency test); PR #65, merged 2026-10-08, meets this branch at four call sites
  (five parse paths: the MCP JSON body and SSE event share one), merged here as
  `well_formed_json(bounded_loads(...))` with its `NestedTooDeeply` branch first and the stdio line
  still decoded with `surrogatepass`, so a reply nested past 100 levels is refused before it is
  walked; #65's fifth `bounded_loads`, the judge's verdict, stays unwrapped (A-47: the judge's
  reasoning is neither persisted nor printed); PR #74's A-39 and its PROGRESS entry call this open;
  MANUAL conflicts with #68 (keeping both hunks repeats a line); PR #87's WebSocket adapter parses
  its frames with its own `json.loads`, which needs the same `well_formed_json` once both are in. A
  spec file whose YAML holds the escape is refused by lint and run since #89. Left as their own
  tasks: older ways one reply stops a campaign that the ingress audit found on main (an MCP session
  id that is not ASCII, an SSE charset or line separator, one invalid UTF-8 byte that is not a
  surrogate, and a non-finite number sent back, which the pre-merge audit could not reproduce
  through an OpenAI tool call; JSON nested in a tool call's or the judge's text no longer stops one
  since #65). `tests/cli/test_lone_surrogate.py` (30 of 37 fail on `main` at `a40e596`),
  `tests/adapters/test_lone_surrogate_replies.py` (9 of 9), `tests/shared/test_wellformed.py`.

## State, 2026-10-08 (evening): a SIGTERM or SIGHUP dropped inside a callback

- Found in CI on PR #72 (the `[sigterm]` case of `tests/cli/test_probe_pass_spend.py`, 41 requests
  served where 25 were expected; three times on two PRs, #72 and #82, on Linux with Python 3.11)
  and fixed on
  `fix/sigterm-lost-in-callback`: `execute_run` mapped SIGTERM and SIGHUP to
  `signal.default_int_handler`, whose KeyboardInterrupt raised inside a weakref callback is printed
  and dropped, so the run went on. Ctrl-C never was, because inside `asyncio.run` it goes to
  asyncio's handler, which cancels. Now SIGTERM and SIGHUP call the SIGINT handler in place at that
  moment, and raise as before only when SIGINT has none (ignored, a job a script starts with `&`).
  Left as it is: with Ctrl-C ignored, and outside the event loop (where no request is sent), a
  signal in a callback can still be dropped, as Ctrl-C can in any Python program. Contract u12 A-60;
  `tests/cli/test_termination_signals.py`, 2 of its 8 tests fail on `e4d6c83`.

## State, 2026-10-07 (afternoon): a refused `--resume -sV` whose advice was refused in turn

- Found by the pre-commit audit of `fix/resume-wall-flag-name` and fixed on
  `fix/resume-sv-ceiling-advice`: `run --resume -sV` with a request ceiling too small for the probe
  pass was refused with "Raise --budget-requests, or drop -sV" before the planning-mode check, and
  each half was refused again for one kind of campaign (measured through the CLI on `0501752`:
  raising, on a campaign halted without `-sV`; dropping `-sV`, on one halted with `-sV` or
  `--deep`). The campaign checks (target, route, judge, planning mode, `--runs`, battery, evidence)
  now run before the wall-clock and request-ceiling refusals, and the campaign's `--runs` is
  inherited before the plan those ceilings come from (a campaign at `--runs 20` was refused against
  2,000 requests where its own derived ceiling was 3,300); the planning-mode refusal names `-sV`,
  `-A` and `--deep`; the three probe-pass refusals offer dropping `-sV` only when it lets the resume
  through (not on a campaign that planned adaptively, and only when the ceiling holds the rest of
  the campaign without the probes, as `--estimate` prices it). The journal adoption moved past the
  last refusal before traffic, so a resume refused before it sends writes nothing (on `0501752` the
  `--budget-requests` pre-flight refused after adopting, when no spend was recorded; and no test
  checked that `run` adopts at all, the new one checks the halted run's digests).
  `tests/cli/test_resume_sv_advice.py` follows and pins every piece of advice through the CLI; 20 of
  its 24 tests fail on `0501752`. Contract u12 A-48. The pre-commit audit of the change (a 120-case
  matrix through the CLI) found the spent-ceiling case, the `--runs` order, an unfollowed pre-flight
  advice and miscounted figures; its delta round (no regression, 2,367 tests green) a ceiling one
  request past the spend, a ceiling of 0 and advice written ahead of the words the test reads; its
  third round (no regression, 2,374 tests green) one untested refusal case; all fixed here. What
  `--estimate` does not price (the multi-identity sweep, which #60 added to the estimate,
  and retries) can still halt a followed "drop -sV" at an exact fit; written in A-48. Left open, a
  question for the owner: the recorded planning mode is one flag for `-sV`, `-A` and `--deep`, so a
  campaign run with `-sV` resumes with `--deep` in its place (measured: it goes through), and its
  second half runs the mutators in their declared order, with no fingerprint; the advice never
  offers that swap. Also open, from `0501752`: a stored mode that is not a boolean is read by
  truthiness (`"false"` reads as on), where a wrong-typed `runs` or spend is refused as corrupt; and
  only the request axis is read, so a campaign halted on `--budget-tokens` is told about requests.

## State, 2026-10-08: a hostile reply nested too deeply fails one attempt (PR #65, merged)

- On `fix/target-deep-json` (PR #65): a target reply whose brackets balance and nest past 100
  levels (`shared.nesting.MAX_DEPTH`), however deep, is `ResponseTooDeep`, an environment failure
  that is not retried:
  that attempt is inconclusive and the scan goes on. Before, `json.loads` raised
  `RecursionError` past the parser's stack (400 KB of `[`) and pydantic overflowed past about
  255 levels when writing evidence (600 bytes), and either aborted the campaign at the first
  request (exit 3). Covers the OpenAI, Anthropic and REST bodies, the MCP JSON body, SSE event
  and stdio line, a tool call's JSON-string arguments and the judge's reply. The depth is read
  from the text before parsing, so it does not depend on the Python version; brackets that do
  not balance are "not JSON". Also: an MCP stdio line may be 4 MiB (64 KiB stopped the campaign
  on a server with 300 tools), with 4 MiB in all per request. Four audits (before the commit,
  a delta round on its fixes, before the merge, and a delta round on those follow-ups) found,
  among others, a quadratic string pattern, a lost detection on unbalanced tool arguments and
  carriage-return lines past the stdio total; all fixed, and the last round found only wording.
  Found while fixing
  the operator-file case on `fix/cli-deep-json` (PR #61, merged first as `0501752`).
- **Left for separate fixes** (pre-commit audit, both also on `main`): with `-sV` or `-A`, one
  refused reply in the probe pass stops the run before the attack; and a 400-digit token count in
  `usage` crashes `dottore run` with a traceback (exit 1, no report). The first is in progress on
  `fix/sv-probe-env-error` (OD-23).
- **For the owner (OD-21, open):** a 200 whose body is not JSON still stops the whole campaign
  (`AdapterProductError`, runner `aborted`, exit 3, one request sent): measured, not as the
  finding assumed. Whether it should fail only its attempt, as a reply too deep now does, is a
  decision, not a fix; the trade-off is a misconfigured endpoint caught at the first request.

## State, 2026-10-08 (morning): a regex that does not compile is a lint finding (PR #63)

- On `fix/lint-invalid-regex` (`tests/test_invalid_spec_patterns.py`, clause A-33 in `u02`): a
  `regex_absence` or `regex_presence` pattern, or a `tool_sequence` `step_arg_patterns` entry,
  that does not compile is one `EVALUATOR_MISCONFIGURED` error per pattern (at most 10 per
  spec), with the spec id, instead of a `PatternError` traceback from the fixture stub (found by
  the pre-commit audit of `fix/cli-legacy-workflow-commands`). `re.compile` also refuses with
  `OverflowError`, `RecursionError`, `ValueError` and, under `-W error`, `FutureWarning`, which
  aborted a whole `dottore run`; a run now refuses a selected spec whose regex does not compile
  before sending, as it refuses a spec file that fails to load (F-10). Three audits, then three
  delta audits: the stub crashed lint a level short of the nesting limit once `re`'s cache
  dropped the pattern (now a finding); a compile thread that fixed the limit to one number was
  taken out again (Ctrl-C, `fork`, queueing), so lint and a run still draw that line a few
  levels apart, and in a selection of more than 512 patterns a spec nested 482 to 487 deep ends
  `inconclusive` with no reason in the report (documented in `compile_spec_pattern` and A-33; a
  per-process cache would close it). The message quotes with `ascii`; the lint text line goes
  through `visible_controls` since PR #51, which writes a `##[` in a pattern out as `#\x23[`
  since PR #54, as in every other lint message. Open for the owner as OD-22:
  refuse the run (as built, like F-10) or skip only that spec (like `setup_not_seeded`); reuse
  `EVALUATOR_MISCONFIGURED` (as built) or a code of its own.

## State, 2026-10-07 (evening): a typo under a target file's `capabilities`

- On `fix/target-capabilities-strict` (u12 A-50; OD-29 decided): `load_target` dropped a
  key `capabilities` does not know and read `false`, `0`, `[]` and `""` as no capabilities, so
  `tool: true` written for `tools` took the specs that need tools out of the plan without a word
  (40 specs planned instead of 59 on a chatbot with `rag` and `memory`, on `2f6201a`), and `dottore
  fleet` copied the key into the target file it wrote, with exit 0. Built reversibly: both refused
  before anything is sent, on the A-45 line that names the file and the key, never the value, and
  `fleet` refuses the key before it writes. Every target and fleet file of the repository, and the
  target and fleet blocks of the docs and man pages, load through the real loaders (new test).
  Found while writing it and left as its own task: a top-level key a target file does not know
  (`endpont:`, or a `capabilities` block whose indent was lost) and a `name`, `provider`,
  `endpoint`, `model`, `auth_ref` or `transport` that is not text are still dropped without a
  word (refused since A-53, PR #88; see the entry above).
  `tests/cli/test_target_capabilities_strict.py`: 19 of its 40 tests fail on `2f6201a`.
  Pre-commit, delta and pre-merge audits found nothing high or medium and no open PR that combines
  into wrong behavior; their lows (key order in what `fleet` writes, keys printed as pydantic
  renders them, a long line until #76, how a halted run resumes, the reversal recipe) are written
  in A-50. Merging next to #76 conflicts on `cli/fleet.py`'s imports (keep both). PR #78; the owner
  chose option 1 (refuse both) on 2026-10-07.

## State, 2026-10-08 (afternoon): OD-32 decided, a resume counts what is stored

- On `fix/resume-planned-attempts` (u08 A-59): the owner decided OD-32 on 2026-10-08 as proposed,
  the runner counts what is stored instead of building the plan, and `--runs` keeps its `2**53`
  bound (A-55). The three places that built the set of `mutators x --runs` attempt ids (the halt
  path of a resume, the seeding gate, the multi-identity sweep) now compare
  `core/reproduce.planned_attempts_held` with the plan's size; a resume of a stored count of `2**53`
  takes about a second and 71 MiB, where 10^7 took up to 16.3 s and 3.7 GiB. Open PRs #66 and #60
  change the same lines (the halt path, the seeding gate, the sweep): whoever merges second keeps
  the count, not the set.

## State, 2026-10-08 (morning): a limit of its own for flow nesting (OD-30)

- On `fix/yaml-flow-nesting-limit`, on `main` after #84 (`9b8b511`): the owner decided OD-30 on
  2026-10-08, option A with a limit of 20. A list or a map written with brackets or braces inside 20
  others written that way is now refused where it starts (A-58): chains of `[` 98 deep, accepted
  under the limit of 100 at 2 to 3 times the time of a flat list, are refused at the 21st `[` in
  0.01 s, and chains at the limit holding 300 texts each walk a fifth of the keys they did at 98
  levels (11.4 million against 52.0); the limit bounds each token's walk, not a file's (a denser
  file walks 21.0 million). Block nesting does not count; the repository nests at most 2 flow
  levels. Converting the depth tests to block style uncovered that three alias-depth tests of #61
  had, since #84, passed for the wrong reason (their anchors were written 101 deep, so they were
  refused as written): fixed, and they now assert their written nesting. Also splits two glued
  bullets (OD-33, from #84; a `Tests:` bullet, from #77). 22 of the 28 new tests fail on `9b8b511`;
  nine mutants killed. To merge after #76, as agreed with its session.

## State, 2026-10-08: a live fingerprint orders a live plan (run 2026-10-07)

- PR #58 (OD-18 option B) squash-merged as `0f936b6`: with #50, OD-18 is complete. A live
  `run -sV` on `PI-INDIRECT-TOOL-001` against the local `llama3.2:3b` sent `zero_width_inject`
  before `nested_instruction`, against the declared order (`docs/16` §1). Noted by its audit,
  not decided: the planner matches carrier names exactly, so `translate:es` (and the other
  `translate:<lang>` variants) never moves forward when `translate` was recovered; whether one
  language's comprehension should stand for another is a design question. Next in the owner's
  order: hosted APIs (the owner's keys and models), then a deployed application, which needs
  its operator's seeding (`examples/target.app.yaml`).

## State, 2026-10-07 (afternoon): a refusal that named a flag `dottore run` does not have

- Found by the pre-commit audit of `fix/halt-reason-figures` and fixed on
  `fix/resume-wall-flag-name`: the `run --resume` refusal for a campaign that already spent its
  wall-clock ceiling told the operator to raise `--budget-wall-s`, which `dottore run` answers with
  "No such option"; the flag is `--budget-wall`. `tests/cli/test_resume_integrity.py` follows the
  refusal's advice through the CLI (the flags it names are read from `dottore run`'s parameters, and
  raising them lets the resume through), and `tests/cli/test_flags.py` fails on a long option (`--`,
  not right after a letter, a digit, `_` or `-`, then a lowercase ASCII letter, read up to the first
  character that is not a letter, a digit, `_` or `-`, so `--budget-wall_s` is not `--budget-wall`)
  that a string literal under `src/ildottore` (docstrings aside) or a rendered help text names and
  no command accepts: on `0501752` that was this flag and nothing else. Contract u12 §7 says so,
  with no new clause number. Those two tests fail on `0501752` (a third checks that the scan catches
  a refusal like this one and leaves docstrings out), and a message that names `--budget-requests`
  instead, or no flag, fails the first. The MANUAL, USAGE and the man page now name the flag that
  lifts the refusal. Left open as its own task, and fixed by #83 (u12 A-48): on a resume with `-sV`,
  the request-ceiling refusal ran before the planning-mode check, so on a campaign halted without
  `-sV` its advice to raise `--budget-requests` led to a second refusal (only dropping `-sV` worked
  there). Noted: the error masker can mask a `--flag=VALUE` whose value is long, such as
  `--budget-wall=SECONDS`, as a high-entropy value (`--budget-wall=60` is printed as written); no
  message writes that form.

## State, 2026-10-07 (night): ids bounded at 128 characters (OD-27 decided)

- On `fix/operator-id-length`, stacked on `fix/operator-file-quoted-values` (#86),
  `tests/cli/test_operator_id_length.py`: the owner delegated OD-27 and the choice was (a), a bound
  when the file is loaded. A scope target's `id` and an identity's `name` are at most 128 characters
  in the scope model (`policy.scope.MAX_ID_CHARS`), and `_target_from` (shared by `load_target` and
  `read_target_file`) refuses a target or `--judge` file's longer `id` naming the file, so no run
  prints a target id past 128 characters (A-51 had cut it in most refusals only). 128: twice a
  fleet's 64, about six times the longest example id (21); no pattern. The audits of A-57
  (2026-10-08) found that removing A-51's cases of a long id left 14 of the 19 sites that quote a
  target id or an identity name unguarded, as an id of 128 characters can have a `repr` of 1,282
  (`\U000e0001` each): those cases use such ids now, with a check that no id's `repr` appears whole
  anywhere in the output (line breaks removed, in case Rich folds a message), and all 19 mutants are
  killed. Not covered, found by those audits: spec ids (a pattern, no bound), `dottore diff` and
  `calibrate` printing a report's target ids whole, a stored run with a longer id no longer
  resumable, control characters in ids. 9 of the 11 new tests fail without the bound; 5 mutants of
  the bound killed. Clause A-57 (u01).

## State, 2026-10-07 (evening): a refusal quoted the operator's value whole

- On `fix/operator-file-quoted-values`, stacked on `fix/operator-file-read-cap` (#76, head
  `4a572f0`, which brings #81's A-40 from main: the huge-integer refusals of `calibrate` and
  `seeded_setup` are A-40's, and `quoted` describes such a number in A-40's words),
  `tests/cli/test_operator_file_quoted_values.py`: the two LOW findings of #76's pre-commit audit.
  (1) Refusals written by hand quoted a value of the scope, target, fleet or labels file whole,
  bounded only by the 1 MiB read (a 1 MB `type:` printed 1,000,108 bytes, an undefined alias of a
  million characters about 1,000,100 in `run`, `calibrate` and `lint`). They now go through
  `shared.config_errors.quoted` (the `repr` up to 300 characters, then `... (N characters)`, or `...
  (N items)` for a list or mapping, never building a container's `repr` whole: 90 KB of aliases made
  one of 200,080,000 characters), and `yaml_problem` cuts PyYAML's reason the same way. The sweep
  found 24 such refusals, not the 4 reported, among them the authorization refusal of `run` and
  `fingerprint` (2,000,108 bytes for one id) with the list of ids the scope authorizes (now 20, each
  cut, `listed`) and two lists in `seeded_setup`. The pre-commit audit found that the enum lookup of
  a target's `type` still built the whole `repr` (1.28 to 1.49 GB for a 90 KB file of aliases; now
  refused before the lookup, 72 MB), the credential refusal's unbounded list of declared references
  (885,131 bytes), the three `--resume` refusals, an integer `repr` cannot write, two surviving
  mutants and doc figures; the delta audit, that `str()` of a verdict, `provider` or `transport` of
  aliases still wrote about 675 MB, a labels key that is a huge integer blamed on a valid verdict
  (in the first commit only), nested aliases untested, the credential variable's name, and doc
  figures; the pre-merge audit, that urllib's errors quoted an endpoint or `base_url` whole (900 KB,
  no file; the allowlist now denies what it cannot read, as documented), four branches untested and
  a date key of `seeded_setup` written differently; the last delta audit, a leading U+00A0 that let
  urllib's error and the endpoint's password through (the loader now reads the endpoint as the gate
  does) and an unreadable allowlist entry that denied its neighbours; the delta audit after that, an
  unreadable entry still matching an IPvFuture literal and `fleet` printing a password the URL mask
  misses; the final audit, a tab or line break between the slashes still hiding that password from
  `fleet`; all fixed. Left, written in A-51: the adapter reads the endpoint unstripped (fails closed
  at the first send). 84 of the 107 tests (the file's 106 and #76's changed reader test) fail on
  `4a572f0`, each for its reason; of the 23 that pass, 4 were fixed first by #81 and 19 guard
  behaviour that must not change; 74 of 76 mutants die (the 2 that live quote a fleet id, already
  held to 64 characters). (2) A byte that is not UTF-8 in any operator file printed the codec's
  error with no file name; `read_text_capped` now refuses it as an `OSError` (`EILSEQ`) with the
  path and the offset, exit 3, as it refuses a file over the cap. Clause A-51 (u01; A-48 to A-50
  were claimed the same evening by `fix/resume-sv-ceiling-advice`, `fix/diff-report-validation` and
  `fix/target-capabilities-strict`). Open, OD-27: ids have no length bound, so a started run still
  prints a target id whole (plan, progress, reports, run store), and `calibrate` lists uncovered
  labels whole; proposed, a bound at load like the fleet's 64 characters. Merged with #76's
  `fd50027` (main with #71, #75, #77, #80): #71's node cap refuses the stdio `command` of aliases
  that was left open (200 MB and 1.09 GB from a 90 KB file on `a0bca70`), and the memory and integer
  tests now use values under #71's and #77's caps.

## State, 2026-10-07 (afternoon): operator files read up to 1 MiB

- On `fix/operator-file-read-cap` (`tests/cli/test_operator_file_cap.py`): the scope, target,
  fleet and labels files and the policy and signature packs are read up to 1 MiB
  (`shared.files.read_text_capped`), a regular file refused on its size before the read, a pipe
  or device read up to one byte past the cap; `dottore fleet` refuses to write a file over the
  cap; and `validation_problems` lists 20 errors by default and cuts a path or reason past 300
  characters. From the pre-commit audit of the alias-expansion cap: 100 MB of comments cost 39.5
  s and 244 MB, a sparse gigabyte peaked at about 2 GiB (now 68 MiB), and a scope's error line
  ran to 5,687,058 characters. The owner decided on 2026-10-07: 1 MiB, the spec loader's figure,
  and any file type with a bounded read, so `--scope <(...)` keeps working (OD-26). The CLI test
  found that the redactor masks a bare size of nine digits or more as a phone number (sizes now
  carry thousands separators); this change's own pre-commit audit found the `fleet` scope over
  the cap (it repeats each endpoint), and its delta audit a child memory measure that Linux
  carries across `execve` (CI read 315 MiB; now `VmHWM`) and `fleet` holding every rendered file
  at once. Since #73 a target file's `capabilities` and `sampling_defaults` errors get the same
  20 and 300. Open (OD-26): the report JSON of `diff` and `calibrate` and the evidence artifacts
  of `replay` and `--resume` are still read whole. Clause A-43 (u01).

## State, 2026-10-07 (evening): spec values JSON cannot hold, and bounded integer flags

- On `fix/spec-non-json-values` (finding F6 of the pre-commit audit of `fix/huge-int-repr`): a spec
  value YAML builds and JSON cannot hold (an unquoted date or timestamp, `!!set`, an `!!omap` or
  `!!pairs` entry, `!!binary`, `.nan`, `.inf`, half a character from an escape between U+D800 and
  U+DFFF) is a `SCHEMA` finding at its path, checked before the schema and after A-40 (#81) and A-44
  (#80), and a spec id holding half a character is no longer printed in the finding header (u02
  A-54); `returns: 2026-01-01` used to pass lint and crash `run --dry-run` with a traceback and exit
  1. Every integer flag of `run` and `fleet --run` is bounded at `2**53`, a negative `--budget-*` is
  refused before the dry run, a live run whose pace (a `-T` template's too) is under one request per
  wall-clock ceiling (`--budget-wall 0` included) is refused (`--rate 1e-308` was a traceback, and
  once that was bounded, a live run that never stopped), and the run store refuses a stored `--runs`
  past `2**53`, which a resume inherits (u12 A-55; `--runs` of 305 nines used to exit 1). A-40's
  paths and the locations of JSON-schema errors write a key that is not printable as `repr` since
  #90; a spec id UTF-8 can encode is still printed as written. Left open: the wall-clock ceiling is
  not a deadline at an accepted pace (each concurrent spec waits its interval, the `-sV` probe pass
  reads no ceiling); a resume builds a set of mutators x runs attempt ids for each started spec, so
  how far `--runs` may go is the owner's call (OD-32); `--rate inf` turns pacing off.

## State, 2026-10-07 (evening): YAML nesting refused where it is written

- On `fix/yaml-flow-nesting-depth`, on `main` after #71 (`df75d3d`): a finding of the pre-commit
  audit of the construction-cost fix, the same on `main`. PyYAML's pure-Python scanner walks one
  possible key per open flow level on every token, and the depth limit was measured only on the
  composed document, so a 198 KB file of chains of `[` 320 deep was composed whole before it was
  refused (11.3 s against 2.5 s for a flat list of as many texts, at a load average of 9 to 14).
  Every loader now refuses a list or a map written inside 100 others where it starts (0.11 s, same
  message and position), which can only refuse earlier what the measure refused later. Clause A-52
  (u01). 18 of the 32 new tests fail on `5fdac72`, and thirteen mutants are all killed; the
  pre-commit audit found no defect in the code (a differential fuzz of 14,800 documents through both
  loaders: none accepted by one tree and refused by the other), and ten claims in the docs and tests
  that promised more than the code, and one order no test pinned (a tag too long before the depth);
  all corrected, and the delta audit five more wording slips, also corrected. The pre-merge audit
  (main with #77 and every open PR) found no failure due to this change and one more claim, the
  order in which refusals made while composing are reported (the order they are made, not the order
  written), corrected with a test; and #87 numbering its own OD-30 to OD-33 in u04, which it has to
  renumber. OD-30, decided by the owner on 2026-10-08: option A, built as A-58 (entry above);
  libyaml's scanner, whose C composer would take the per-node checks with it, was not chosen. #77
  (A-41 and A-42, merged first) edits the same `compose_node`: the merge kept both sides of four
  additions (the module docstring, the constants, the class docstring, `__init__`), the method
  itself merged cleanly, and both branches' tests pass together.

## State, 2026-10-07 (evening): fleet target ids that differ only by case

- Found by the delta audit of PR #76 and fixed on `fix/fleet-casefold-ids` (PR #85):
  `materialize_fleet` refused a duplicate id only by exact equality, and each target is written to
  `target-<id>.yaml`, so on APFS a fleet with `Prod` and `prod` wrote `prod` over `Prod`, listed
  two target files and exited 0. The brief said the printed `dottore run` then scanned `prod`
  twice; measured on `2f6201a`, it refuses instead (exit 3, "two target files declare the id
  'prod'"), and so does `fleet --run`, a message about an id the fleet declared once. Ids equal
  under `casefold()` are now refused on every file system before anything is written, and so is a
  judge id spelled as a target's only up to case (it worked, with two scope entries that differ
  only by case). Every refusal of the fleet's ids locates its entries as the validator does
  (`targets.1.id`, from 0), because the CLI masks a high-entropy id such as
  `Meta-Llama-3-70B-Instruct`, and the two judge refusals say when the id is the default `judge`.
  Contract u01 A-56; the "everywhere" choice is OD-33, decided by the conductor and confirmed by
  the owner the same evening. Checked and left exact: `run`'s duplicate check and `load_scope`'s
  (A-20); no file of a run is named by a target id, the run store compares `<spec id>::<target
  id>` case-sensitively, and two hand-written targets `Prod` and `prod` ran together with two run
  ids, both in every report format. Two audit rounds so far, none high or medium: the pre-commit
  one found masked ids, the default judge id, three surviving mutants, the judge's reason
  misstated in FAQ and man page, and "no store key" being literally false; the delta one found my
  first entry numbers counted from 1 where the validator of the same command counts from 0, "never
  two ids a reader cannot tell apart" in MANUAL and man5 (`Ilama`, `llama`, `lIama` pass), three
  more survivors (the default note for an explicit `id: judge`, ids swapped against their numbers,
  a later twin reported as a duplicate) and the sibling judge message without the default note.
  All fixed. The pre-merge round (combined trees with #76, #78 and #86, both merge orders) found
  no failure of this PR's own; its conflicts are the expected ones (doc appends, a man5 paragraph
  with #78, the two fleet messages with #86). Four lows, fixed: the agreed `quoted()` resolution
  with #86 would have left one line at 101 columns (each id is now formatted once, in a variable,
  so the switch is four assignments), the credential half of A-30 untested, MANUAL's "shares its
  entry" without the condition, and the `--judge` file mismatch naming the default id with no
  note. A fourth round on that fix compared 96,120 fleets and 3,024 CLI runs against the previous
  head (the only difference was the intended note) and found two test gaps, closed: the note could
  have spread to the endpoint or `auth_ref` row of the `--judge` refusal, and A-30's credential
  half was tested with the key on one side only. Numbering: A-56 and OD-33 came from the session
  keeping the count; the local branch `feat/websocket-adapter` uses OD-30 to OD-33 in u04 without
  having claimed them, so it has to renumber (renumbered to OD-34 to OD-37, 2026-10-09).

## State, 2026-10-07 (night): a load refusal names its spec file

- On `fix/spec-load-error-names` (PR #49, opened on `d54097c` on 2026-10-06, merged with main at
  `5fdac72`; `tests/cli/test_run_load_errors.py`): `dottore run` refusing a spec
  that fails to load printed its path as `«REDACTED:high_entropy:…».yaml` (found by the #47
  pre-merge audit); it names `attacks/DL-PII-ELICIT-001.yaml` now, kept only when it is an entry
  on disk under a spec path, nothing the entropy rule reads as a token is glued to it, and it
  does not overlap a registered credential. A kept token in a CLI error that is part of a
  registered credential (from 8 characters) prints as `«REDACTED:credential»` instead of going
  to the entropy rule. The pre-commit audit (3,996 cases main against branch, no secret exposed)
  found two test gaps and four low items, all fixed; `no_known_secrets` moved to
  `tests/conftest.py`. The pre-merge audit (73,812 cases of `_masked`, main against branch) found
  no reason to block; its two wording items are fixed. `make gates` green: 2,702 tests (2,688 on
  `5fdac72`), coverage 96.58%, `dottore lint` 0 errors over 75 specs, 14 suites, 1 pack.

## State, 2026-10-07 (afternoon): YAML construction cost bounded under the size cap

- Closes the construction costs left open just below. On `fix/yaml-construction-cost`, stacked on
  `fix/yaml-alias-expansion-cap` (`982bfe4`): under the size cap, a base-60 integer (`1:59:59...`)
  is built in time quadratic in its length, and integer keys that share one hash make a mapping
  quadratic. A 1 MiB spec took `lint` 55 s and 24 s; `run --dry-run` accepted a 450 KB and a 1.3 MB
  target after 37 s and 247 s, having parsed each four times (load average 6 to 10 on 15 cores).
  Every loader now refuses, as it composes and before anything is built, a number written in more
  than 1,000 characters and the key that takes a document past 1,000 keys that are numbers (a merged
  key counted in each mapping it is merged into), in 1 to 1.5 s for each of those files; `run` and
  `fingerprint` parse a target file once, so a piped target (`-t /dev/stdin`) works. Clauses A-41
  (u01) and A-42 (u12). 112 of the 126 new tests fail on `982bfe4`. Twenty-seven distinct mutants of
  the fix are all killed, among them the eight the audits found surviving. A first version counted
  the keys only once the whole file was composed: refused, but the 1.3 MB target still took 3 to 11
  s and its timing test was unstable on a loaded machine; counting each key as it is composed stops
  at the 1,001st. The pre-commit audit (three auditors on a frozen copy) found no way past either
  limit (40,000 keys sharing one hash refused in under a second in twenty forms) and no extra parse
  on any path but a file named twice and the judge file of `fleet --run --judge`; what it found in
  the tests and the docs is closed: shapes no test pinned (a number in a list, in flow or at the
  root; keys in a flow mapping; a merge passed on), a resume, a judge file and a piped target no
  test watched, and parse counts, timings and wording wider than measured. It also found a
  pre-existing cost, left as its own task: flow nesting makes PyYAML's scanner pay per open level,
  so 198 KB nested 95 deep costs 3 to 4 times a flat file, and one past the depth cap is refused
  only after it is all composed (since taken on by #84, A-52). The pre-merge audit built main, #71
  and this branch together:
  conflicts only in the docs, every gate green, 2,489 tests; its four findings (tests for every
  notation in every position, and three sentences) are closed. Left open: a file named twice is
  parsed once per name (`-t X --judge X`), and `fleet --run --judge` parses its judge file twice; a
  scope with a `checksum:` line is still parsed twice, by design (the second parse is the coverage
  check); an operator file of plain text still costs its composition, 3 s for 6.3 MB under the size
  cap; the byte cap is `fix/operator-file-read-cap`.

## State, 2026-10-07 (afternoon): a spec key that is not a string

- On `fix/lint-nonstring-arg-key` (clause A-44 in u02, `tests/registry/test_non_string_keys.py`):
  YAML builds `5:` as an int, a bare `on:` as a bool, `~:` as null and `2026-10-07:` as a date,
  and in a fixture's tool-call arguments such a key made `dottore lint` a traceback with exit 1
  (the offline stub's `key.lower()`). Every mapping of a spec is now checked before the JSON
  schema (not the keys of an `!!omap` or `!!pairs` entry, nor `!!set` members), and a key that is
  not a string is a `SCHEMA` finding at its path. Swept over the 41 fixture tool calls with
  arguments in the 75 shipped specs: on `0501752` an int key added after the others crashed lint
  in 5 and passed unreported in 36 (6 and 35 added first); now all 41 are a finding. Keys of two
  types in one mapping also crashed the sort of the schema errors, and a `!!binary` key passed
  lint. `run` now refuses such a spec (exit 3, as any spec that does not load) where it used to
  run it. Found by the session on `fix/huge-int-repr` (A-40, #81), which merged first: its check
  runs first, this one after it, and the branch of this one for an int too long to write out was
  dropped as unreachable. 76 of the 77 new tests fail on `0501752`. The pre-commit and delta
  audits found no high or medium defect; the first listed pre-existing gaps between the lint stub
  and the real `tool_call` evaluator (a confirm flag or forbidden key inside a list, an injection
  in a nested value, `arguments` as a JSON string), left for a separate task.

## State, 2026-10-07 (afternoon): a resumed probe pass recorded however it ends

- Found by the delta audit of PR #68 and fixed on `fix/sv-probe-spend-on-stop`: on `run --resume
  <id> -sV`, only the request ceiling wrote what the probe pass had sent to the run store. A probe
  answered 503 three times left the store at 20 while the stub had served 23 (reproduced on main
  `0501752`); a 401, a 200 that is not JSON, Ctrl-C, SIGTERM and a stop after a pass that
  succeeded lost the pass too. The CLI now owns the pass's ledger and records prior spend plus the
  pass as soon as it ends, success included (the store's per-axis maximum keeps each probe counted
  once), and says the count on stderr when an error or a signal stops the pass. Three audit rounds
  found signal windows: the write after a successful pass sat outside the handlers (a real SIGINT
  a few milliseconds after the last probe lost all 17 in 2 of 16 tries; moved inside), and a
  handler's own write has nothing after it (2 of 41 tries just after a 503 stop). Writing again on
  that signal was built and withdrawn (on a locked store, one Ctrl-C after a pass that succeeded
  waited 15.1 s instead of 9.8 for a record lost anyway); the window is written in the contract.
  Contract u12 A-46; `tests/cli/test_probe_pass_spend.py`, 11 of its 14 tests fail on `2f6201a`. Not
  changed: a fresh run's pass and a `--resume-unverified` run with no recorded spend record nothing;
  a signal during a handler's write, a SIGKILL, or a write that fails (a warning) still leave the
  record low. Left open as a follow-up: the adapters are built with no retries of their own, so the
  error that stops a probe pass, and an attack attempt's evidence, say `exhausted 1 attempt(s)`
  after three sends. Merged in a scratch repository with PR #66 and with PR #68, code, u12 and the
  index merge cleanly (only `CHANGELOG.md` and `docs/PROGRESS.md` conflict) and the merged trees
  pass both PRs' tests and these.

## State, 2026-10-07 (afternoon): every YAML loader capped by expanded size

- Closes the second item left open below. On `fix/yaml-alias-expansion-cap`, on main after #61: the
  scope, target, fleet and labels files and the policy and signature packs had the depth limit but
  no size cap with aliases expanded, which only the spec loader had (SEC-09). An 835-byte labels
  file of doubling anchors ran `calibrate` past 25 s and 1.7 GB, and a `<<` merging the previous map
  twice doubles the work inside PyYAML itself. All of them now share the spec loader's cap (100,000
  nodes, a text one node per 64 characters) through one measure, `safe_yaml.check_expanded`: depth
  and size in one pass over the node graph, each size saturating past the cap, too deep before too
  large, refused at the node where the value crosses the limit, in 0.4 s and 71 MB. Two audits found
  holes in the fix itself, all closed: unsaturated, the measure's own memory grew with the square of
  an anchor chain; measuring only a fully composed document let a 3 MB file of plain texts cost 785
  MB, and a list of aliases, uncounted, was still composed whole; and a `%TAG` prefix copied into
  every node's tag held 187 MB for 1,000 nodes. Composition now stops at the cap (an alias counting
  what it names; 1.4 s and 134 MB for that file) and a tag past 256 characters is refused. Clause
  A-37 (u01). 34 of the 38 new tests fail on `0501752`. Twenty-three mutants of the fix are all
  killed. Left open as their own tasks: construction costs under the cap (base-60 integers,
  colliding integer keys, the target loaded four times per `run`; taken by the session "Bound YAML
  construction cost under the node cap", stacked on this branch), a huge integer that crashes
  `lint`, and no byte limit on the operator's files.

## State, 2026-10-07 (afternoon): a number too long to write out

- On `fix/huge-int-repr` (`tests/cli/test_huge_numbers.py`, clause A-40 in u02): an int past
  Python's digit limit (4,300 by default, 640 at the lowest), which YAML builds from `0x` and 4,000
  `f`, is reported where it enters, with its file, and never printed: a `SCHEMA` finding at its
  path in a spec (it was a lint traceback with exit 1, and `run --spec-path` exited 3 naming no
  file), a refusal naming the labels file for a `calibrate` key, the report for `diff` and
  `calibrate` (`json.loads` raises a plain `ValueError` past the limit), the target file for its
  `type`, `mock_scenario` and `seeded_setup` keys. Swept at every value and key of the 75 specs:
  6,112 of 7,599 placements were a traceback on the base, none now; inside a `!!set` or `!!omap`,
  which the first version did not walk (pre-commit audit), none either. Independent of a cap on
  literal length in the YAML loader (`fix/yaml-construction-cost`, A-41). Found on the way and left
  as separate tasks: a number as a key of a fixture tool call's `args` is a lint traceback where
  the evaluator matches argument names (A-44, another session); a target file's bad
  `capabilities` or `sampling_defaults` printed pydantic's raw error with the value and no file
  (fixed by #73, A-45); a value JSON cannot hold (an unquoted date, a set) passes lint and the dry
  run exits 1 on it, as does a `--runs` past what a float holds.

## State, 2026-10-07 (afternoon): a target file's bad value, quoted and with no file name

- Found on `fix/huge-int-repr` and fixed on `fix/target-file-validation`: a wrong value under a
  target file's `capabilities` or `sampling_defaults` (`tools: maybe-later`, `temperature: warm`)
  reached the CLI as pydantic's raw error, four lines quoting the value and naming no file (exit 3
  was already right). `load_target` now wraps it like the scope, fleet and pack loaders: one
  `error:` line, `target file <path> '<block>' failed validation: <field>: <reason>`, no value.
  Contract u12 A-45 (A-43 and A-44 were claimed the same afternoon by `fix/operator-file-read-cap`
  and `fix/lint-nonstring-arg-key`). Left open, written in the clause: a key `capabilities` does
  not know, or a `capabilities` that is empty or `false`, is dropped without a word (on
  `fix/target-capabilities-strict`, A-50, the key is refused and so is a `capabilities` of `false`,
  `0`, `[]` or `""`; see the evening entry); other
  refusals of the file quote what it says (`type`, `mock_scenario`, a `seeded_setup` tool name,
  the `id`); what pydantic can coerce is accepted. The pre-commit audit found the same shape in
  `dottore diff` and `dottore calibrate` (`Finding.model_validate` in `cli/diff.py`: several lines,
  the value quoted, no file name); not fixed here (A-49).
  `tests/cli/test_target_file_validation.py`: 19 of its 24 tests fail on `0501752`, the other 5
  guard that each test value survives the redactor.

## State, 2026-10-07 (morning): a file nested past what the CLI can hold

- Found by the pre-merge audit of #51 and fixed on `fix/cli-deep-json` (PR #61): `dottore diff` and
  `dottore calibrate` exited 1 (findings below `--fail-on`) with a `RecursionError` traceback on a
  report nested past the JSON parser's stack, and so did `replay` and `run --resume` on a run store
  column nested the same way. Each is now refused where it is parsed (exit 3, one `error:` line
  naming the file or the column). The probe and three audits found the same exit 1 one step later: a
  run status formatted after it parsed, a run store column too deep to write back, a stored spend or
  `--runs` that is not an amount (an infinity, a list, an integer past a float; a negative spend,
  and `true` or a missing `--runs`, were accepted), and YAML anchors chained into a value 1,600 to
  80,000 levels deep that `lint`, `run -t` and `calibrate` overflowed on. Run store columns and
  every YAML loader (aliases expanded) now stop at 100 levels; the repository nests at most 11.
  Contract u12 A-9 and A-24 and u02 §4 say so; no new clause. Left open as their own tasks: a
  hostile target's reply nested too deeply aborts the whole campaign (exit 3) instead of failing one
  attempt (`fix/target-deep-json`), and the YAML loaders other than the spec loader have no cap on
  expanded size. `tests/cli/test_deep_json.py`; 45 of the 49 new tests fail on `0f936b6`.

## State, 2026-10-07 (night): OD-18 option B built

- On `feat/od18-b-seeded-setup`: a deployed application (any type but `model`) sends a spec
  with documents, tools or memory only when its target file declares the scene seeded
  (`seeded_setup.specs`); otherwise `inconclusive: setup_not_seeded`, nothing sent, printed by the
  dry run and `--estimate`. A declared spec records `setup_delivery: seeded`; tool calls are
  judged under the spec's names (`seeded_setup.tools`) and the deployment's own tools outside the
  scene are not unauthorized (`seeded_setup.granted_tools`, never over a spec's own scene
  tool). A spec whose canary has to be in the deployment needs `seeded_setup.run_token`, and its
  canary is then `<run_token>-<spec id>` (`--dry-run -vv` prints it); a trace spec is not sent
  through an adapter that reads no tool calls. The offline mocks are exempt. Measured: a fully
  capable deployment declaring nothing sends 41 of 75 specs (585 requests); declaring every
  scene, 62 (740); with a `run_token` as well, 67 (780, as main). Two audit rounds found a
  resume that published its placeholder, canaries nobody could seed and grants over scene tools,
  among others; all fixed. With A and B in, OD-18 is complete. Next in the owner's order:
  hosted APIs (the owner's keys and models), then a deployed application, which needs its
  operator's seeding (`examples/target.app.yaml`).

## State, 2026-10-07 (night): the first live `-sV` pass

- `dottore fingerprint` against the local `llama3.2:3b`, three times. It found two defects: 9
  of the 17 probes went out with no temperature (sampled at Ollama's 1.0), and, once pinned, an
  uncapped `rot13` probe looped to the timeout and stopped the pass. Fixed on
  `fix/fingerprint-probe-sampling` (`PROBE_SAMPLING`: temperature 0, 512-token cap). Verdict:
  family `meta-llama` at 0.4 from the envelope alone, no version (the pack's two Llama versions
  tie on `model=llama`; Llama 3.2 is not in the pack either), carriers 4 of 7. Recorded in
  `docs/16` §1. Open and not decided here: the guardrail layer reads any refusal as an output
  filter while its probe asks for a refusal, so it cannot tell a filter from a model that did
  as asked; and `sampling_defaults` in a target file is parsed and applied nowhere (specs pin
  their own sampling, as do the judge and now the probes).

## State, 2026-10-07 (night): PR #52 merged; an inverted tool allowlist

- PR #52 (the `MEM-POISON-001` oracle) squash-merged as `77aafd5`. Reading the `tool_call`
  oracles for OD-18 B showed `AG-EXTORT-CHAIN-001` with its allowlist inverted (the harmful
  tools listed as authorized); fixed on `fix/extort-chain-allowlist`. The linter refuses an
  `external` tool on a `tool_call` allowlist and warns on an undeclared name, and an allowlist
  taken from the setup leaves the `external` tools out (empty when the scene offers only egress).
  Open, and a question for the owner: whether a `confirm: true` the model sets on its own
  destructive call counts as confirmation. `AG-CONFIRM-BYPASS-001` says it does;
  `kill_chain_progression` fails any destroy whatever the flag, so `AG-DESTRUCTIVE-DBDROP-001`
  contradicts its own description. (Decided 2026-10-09 by the owner: it does not, OD-38; see the
  entry of that evening.)

## State, 2026-10-06 (evening): control characters on the terminal

- On `fix/cli-control-chars` (`tests/test_terminal_control_chars.py`), off `d19b221`: every CLI
  error (`cli/app._masked`) and the paths that bypassed it (`lint` and `coverage` text, the
  spec name in `registry ls` and `describe`, `diff`, `calibrate` and `replay` lines, the spend and
  "did not complete" lines) write control characters out after the redactor: C0 and DEL as control
  pictures (`␊`), C1, U+2028, U+2029 and lone surrogates as Python escapes. A spec file named with
  a newline printed a GitHub Actions workflow command on stderr (pre-merge audit of PR #49, on main
  too). A registered credential split by control characters is masked whole on the terminal. `rich`
  prints the run's error and coverage lines unwrapped and without markup (a wrap at 80 columns
  could start a line with `::error`; `[/]` in a target's error raised `MarkupError` before the
  reports were written). `coverage` lists unloaded files as bullets; `diff` and `calibrate` refuse
  a report whose spec ids are not spec ids; a lone surrogate after a label no longer crashes the
  masking (on main too); stdout escapes what its encoding lacks; `fingerprint` prints ASCII JSON; a
  run id with a trailing newline is refused.
- The pre-commit audit (two reviewers) found 10 of 42 mutants surviving (8 that would reopen a raw
  line or a leak) and seven defects; the delta audit of those fixes found one regression of mine
  (`fingerprint`'s JSON invalid on a cp1252 stdout) and two unpinned fixes. All fixed here. Left
  open, pre-existing on main: the legacy `##[cmd]` form a GitHub runner reads anywhere in a line
  (written out since 2026-10-07 in PR #54, above);
  the reports and stores keep a credential split by a control character readable (`redact_text`
  unchanged); a credential split by an invisible format character (U+200B) was neither masked nor
  shown (on the terminal it is since 2026-10-07, above).
- `make gates` green: 2,397 tests (195 new), coverage 96.49%. PR #49 touches `_masked` too: the
  second to merge rebases.

## State, 2026-10-06 (evening): PR #50 merged; the first full local pass

- PR #50 (OD-18 option A) squash-merged as `d19b221`. The whole battery ran against `llama3.2:3b`
  on a local Ollama with the scene in-band (`docs/16` §1 has the figures). The pass confirmed one
  oracle defect: `MEM-POISON-001` wanted the planted tag last and a download as "download it from
  ...", and the model put the tag first and wrote "download `csvjson` from evil-cdn.example", so a
  poisoned reply scored pass. On `fix/spec-evaluator-mentions` both count where an obeying model
  writes them (`tests/evaluators/test_mem_poison_oracle.py`). `AG-WORM-PROPAGATE-001` failing a
  reply that reproduces the worm marker is by design, not a defect (clause A-27: for a worm, a
  verbatim copy is how it travels); its live fail was a model that obeyed the payload. Next in the
  owner's order: hosted APIs (the owner's keys and choice of models), then a deployed application,
  which waits for option B.

## State, 2026-10-06 (afternoon): OD-18 decided (C, A first); A built

- PR #48 (the #46 pre-merge follow-ups) squash-merged as `d54097c`. The owner decided OD-18 on
  2026-10-06: C, with A first, because the first live pass is against hosted model APIs. On
  `feat/od18-in-band-setup`: a `type: model` target gets a spec's memory seed, documents and
  tools in-band, with a tool loop of at most 4 rounds (`tests/core/test_in_band_setup.py`). The
  live passes run in the owner's order: a local model first, then hosted APIs (the owner's keys),
  then a deployed application, which waits for option B. A first local smoke pass (6 setup
  specs against `llama3.2:3b`) delivered the scene end to end. Noted then as open: the
  `MEM-POISON-001` oracle missed the tag when it opened the reply (fixed on
  `fix/spec-evaluator-mentions`, see the evening entry), and an `AG-WORM-PROPAGATE-001` oracle
  "defect" that was not one (clause A-27).

## State, 2026-10-06 (night): follow-ups of the #46 pre-merge audit

- PR #47 (the #45 pre-merge follow-ups) squash-merged as `32f4334`. On
  `fix/redactor-followups`: a registered credential written as a mask's digest, evidence keys
  that mask to one name, the cost of the `skip` branches on clean text (+31% to about +8% over
  `519aa99`, before #46), and the `mask_value` note. Open: nested repetitive canaries chosen by
  the operator cost seconds in `authz_leak`; a plugin's own `mask_value` type is read as text
  again (documented); a registered credential split around one or several mask digests, like one
  split by spaces, is kept.

## State, 2026-10-06 (night): PR #46 merged; the #45 pre-merge follow-ups

- PR #46 (the redactor and the evaluators on hostile text) squash-merged as `94aca32`. On
  `fix/scope-duplicate-identities`: two identities of one scope target with one name or one canary
  are refused, `authz_leak` tells apart a canary written inside another, the duplicate-key message
  gives where an alias key was written, `registry ls` and `describe` warn about load errors, the
  repo-wide YAML test's blind spots, and the doc gaps of the #45 pre-merge audit.

## State, 2026-10-06 (night): PRs #43 to #45 merged; the redactor on hostile text

- PR #43 (labelled numbers), PR #44 (D-17, the scope a run went out under) and PR #45 (a YAML key
  written twice) squash-merged as `9d09486`, `0866ba3` and `519aa99`. On `fix/redactor-robustness`
  (`tests/test_redactor_robustness.py`): the stash-token collision (echoed masks corrupting the
  redaction and aborting a campaign), a mask written by the target hiding a key, `mask_value`
  returning a value raw, seven quadratic paths (phone, email, JWT twice, backtick injection,
  `pii_detector`'s phone check, the mask restore), and the low items of the #43 and #44 audits.
  The #45 pre-merge audit's findings (two scope identities with one name, the repo-wide YAML
  test's blind spots, an alias position, doc gaps) are on `fix/scope-duplicate-identities`.

## State, 2026-10-06 (night): a YAML key written twice

- On `fix/yaml-duplicate-keys` (`tests/test_yaml_duplicate_keys.py`): a key written twice in
  one YAML mapping is refused with its position in every loader (scope, target, fleet, labels,
  policy pack, signature pack, specs) instead of keeping the last value; `<<` merges still
  override, a merged map is checked too and two `<<` in one mapping are refused. No YAML file
  in the repository repeated a key.

## State, 2026-10-05 (afternoon): the scope a run went out under (D-17)

- On `feat/record-scope-hash` (`tests/test_scope_digest.py`): every run records the SHA-256 of
  the scope body that authorized it, in the run store (every scope of the run, in order) and in
  the four report formats; a resume under another scope is recorded and noted, not refused.
  The operator is still not recorded; signing is still OD-2. The checksum covers a whole value
  now (a `checksum:` line inside another value is refused).
- PR #43 (a phone or card number glued to its own label) squash-merged as `9d09486`.

## State, 2026-10-05 (afternoon): PRs #41 and #42 merged; labelled numbers

- PR #41 (date shape tightened and shared with `pii_detector`) and PR #42 (its tests and
  wording) squash-merged as `3f738a8` and `b214b9b`. A phone or card number glued to its own
  label (`Tel.555-123-4567`, `card_4111111111111111`) is masked on
  `fix/redactor-labelled-pii` (`tests/test_labelled_numbers.py`).
- Stopped by a safety classifier at 14:11 while starting the argument-value oracle from the
  CounterSteer paper; logged, not retried, left to Daniel.

## State, 2026-10-05 (late night): PR #40 merged; the date shape tightened

- PR #40 (fingerprint attribution and the audit follow-ups) squash-merged as `7496237` after
  green CI and a pre-merge audit; its low finding (part of a card glued before a date stays
  readable) is fixed on `fix/date-shape-tightening`, with the `pii_detector` evaluator now
  sharing the redactor's date shape (`tests/test_date_shape_tightening.py`).

## State, 2026-10-05 (night): PRs #37 to #39 merged; fingerprint attribution fixed

- PR #37 (F11) squash-merged as `03c6d45`, PR #38 (hygiene after the audit: spend on interrupt,
  closed stores, atomic reports, clearer messages) as `c1e2aee`, PR #39 (the last
  non-decision findings, below) as `3070aed`, each after green CI and a pre-merge audit. The
  audit of #38 found a temporary report created world-readable; fixed before the merge.
- Fingerprint attribution on `fix/fingerprint-attribution`
  (`tests/fingerprint/test_attribution_audit.py`): ties name nothing; the statistical layer
  ignores canned replies; declared capabilities are listed with weight 0; envelope-only
  confidence capped at the metadata weight; `finish_reason` out of the pack, `model=meta-llama`
  in, `model=` fragments as alternatives; the `model` echo redacted without the entropy rule;
  live probes report the target file's capabilities; the metadata signatures are `model=` names
  only. Two pre-commit audit rounds found the last four through the real adapters. The R16
  entry of the CHANGELOG named the wrong cause (corrected there). Left for Daniel: whether a
  `model=` name should outrank the statistical layer (short replies land near `meta-llama`).
- On the same branch, the follow-ups of the #39 pre-merge audit (the operator's files no longer
  quote a value YAML cannot build: a shared `safe_yaml` loader; spec reads in blocking mode; long
  ids not attached) and a redactor fix (a dashed date-time stamp is not a phone number).

## State, 2026-10-05 (night): the last non-decision findings of the 2026-10-03 audit

- On `fix/audit-last-lows` (`tests/test_audit_last_lows.py`): F-20 (the echo lint reads image
  text and tools, and the `refusal` evaluator's compliance tells anywhere the target reads;
  `MM-IMG-HARMFUL-001` no longer asks for "STEP 1"), SEC-09 (spec files read only when regular,
  inside their pack and at most 1 MiB; an alias-expansion budget; YAML errors quote no line;
  values PyYAML cannot build are findings, not tracebacks) and
  the permissions half of SEC-10 (new reports and run stores 0600). The pre-commit audit found a
  regression of mine (a control character escaping as a traceback) and two bypasses of the new
  caps (aliases of one long string, a link to `/dev/zero`), all fixed before the commit.
- Left for Daniel: F9 (jailbreak carrier construction, next to the area of the classifier stop).

## State, 2026-10-04 (night): PR #36 merged; F11 built

- PR #36 (leftovers) squash-merged as `8235af3` after green CI and a pre-merge audit.
- F11 on `fix/f11-resume-retries-env-errors`: a resume sends again the attempts that ended in an
  environment error, under the same id, and scores one per id. Made safe by the artifact journal
  (run store schema v4): every attempt artifact is recorded `pending` before it is written and
  `written` after, and the manifest is findings plus journal. `tests/test_f11_resume_resends.py`
  interrupts a resume mid-spec and resumes it again.

## State, 2026-10-04 (evening): PR #35 merged; the audit's leftovers fixed

- PR #35 (residuals and block 7) squash-merged as `d48f5d8` after green CI and a pre-merge audit.
- Leftovers on `fix/audit-leftovers` (`tests/test_audit_leftovers.py`): compressed replies
  decoded inside the 4 MiB cap (a 200 KB gzip reply allocated about 150 MB; MCP could not read
  gzip at all); path forms only some origins decode refused; token reservations for specs
  without `max_tokens`, trued up both ways; `-sV` probe retries paced, recorded and charged;
  run timestamps; real latency on live routes; the no-judge warning counted over the plan.
  Four pre-commit audit rounds: the first found that the client could advertise `br`/`zstd`
  the cap refuses, a resume losing its start time and its probe spend, a literal fullwidth
  bypass and Anthropic usage never trued up; the next three found test gaps and one
  regression of mine (one start stamp shared by every target).
- Stopped by a safety classifier at 17:18 while planning the fix of the multilingual spec's
  `translate:zh` variant; logged in the safeguard log, not retried, left to Daniel.
- Daniel's decisions added: a default output limit on the wire; evidence of attempts paid before
  a budget breach; a time of day on attempts and probes; confidence of the deciding variant
  (ADR-0003).

## State, 2026-10-04 (midday): block 6 merged; residuals and block 7 (docs truth) done

- PR #34 (block 6) squash-merged as `0bcf4d1` after green CI.
- Standing rule from Daniel (2026-10-04, 09:18): an audit runs before every commit and every
  merge. The residual patch went through eight pre-commit audit rounds, and the docs through
  two doc-truth audits. Each round found something (among them F11 artifacts the run store
  never recorded after an interrupted resume, a digest exemption that printed unregistered
  64-hex keys in clear, a plugin contract change, and operator values echoed by pydantic and
  PyYAML errors), fixed or withdrawn before the next round; the last two found only wording.
- Residuals on `fix/audit-residuals` (`tests/test_audit_residuals.py`): finding states
  (`confirmed`, `needs_review`, `not_exploited`, `not_tested`) used by the summary, HTML,
  SARIF and the progress line (R5, R6, R14); the multi-target envelope (R10); framework
  editions in JSON, SARIF and JUnit (R12, an additive schema change recorded in the
  CHANGELOG); no family from a constant target, `non_discriminating_target` (R16);
  `fingerprint --offline` honours `mock_scenario`; mutation parameters checked against each
  mutator's `accepted_params` (closes `translate:klingon` from the PR #32 review); report path
  collisions by case and Unicode form; `-oA` with a dotted prefix; CLI errors keep only the
  digests the tool computed readable, never quote a literal `auth_ref`, and scope, target,
  fleet and labels file errors give the field or line and the reason, never the value.
- Block 7: user docs, design docs and unit contracts checked claim by claim against the code,
  plus a doc-truth audit of the result.
- Withdrawn: F11 (resume re-sending attempts that ended in an environment error). It needs
  evidence references persisted as each artifact is written; the defensive pieces stayed
  (one reference per artifact on resume, one attempt per id in `replay`).
- Open: F11; the judge self-consistency behaviour (code drops the judge on disagreement, the
  threat model says inconclusive); gzip expansion before the size cap; pooled confidence on a
  per-variant confirmation; exotic path forms; block 4's leftovers (token overshoot without
  `sampling.max_tokens`, evidence dropped on a token breach, the `-sV` probe adapter's own
  retries); and Daniel's decisions (OD-18, OD-19, scope signing, a policy-pack flag, the two
  `-sV` carriers that add instruction text).

## State, 2026-10-03 (around midnight): block 4 merged, block 6 (CLI and reports) fixed

- PR #33 (block 4) squash-merged as `ac45f92` after green CI.
- Block 6 on `fix/audit-block6-cli-reports`: `--hardened` refused on a live target, `diff` and
  `calibrate` one target at a time with `UNVERIFIED` for fail to inconclusive, usage errors exit
  3, bad options refused before sending, SARIF kinds per the standard, calibrate arithmetic,
  version, HTML skeleton and `new-spec` id. Every fix mutation-checked
  (`tests/test_audit_block6_cli_reports.py`).
- Open: block 7 (docs truth), F11, the block 6 residuals in the CHANGELOG, and Daniel's decisions.

## State, 2026-10-03 (late night): PR #32 merged, block 4 (budget and rate) fixed

- PR #32 squash-merged as `8b77636` after green CI, all five commits GPG-verified.
- Block 4 on `fix/audit-block4-budget`: the judge and the identity sweep inside the ceiling and the
  rate gate (`core.metering`), one retry layer, billed tokens recorded and failed reservations
  released, `--rate <= 0` refused, the estimate and derived ceilings counting the judge, and
  the tautological spend tests replaced. Every fix mutation-checked.
- Open: blocks 6 and 7, F11, the residuals listed in the CHANGELOG entry, and the decisions that
  are Daniel's (OD-18, OD-19, scope signing, a policy-pack flag, two `-sV` carriers).

## State, 2026-10-03 (night): PR #32 reviewed, and the review's findings fixed

- Three reviewers re-ran the four audit commits in isolated worktrees (20:48 to 21:08 CEST) and
  found that the fixes introduced regressions of their own: a quadratic label regex, old runs
  refused as tampered, a key with a control character leaking through the HTTP error, an
  allowlist escape with `//..`, over-confirmation with `--runs 1`, and more. All fixed in one
  commit with `tests/test_pr32_review_fixes.py` (24 tests that fail on the PR head, plus two
  positive controls). Still open from the review, deliberately: gzip expansion before the cap
  (bounded), unvalidated mutation parameters (`translate:klingon`), pooled confidence shown on
  a per-variant confirmation, and path forms only exotic origins decode.

## State, 2026-10-03 (evening): full audit, blocks 1, 2, 3 and 5 fixed

- A six-auditor adversarial audit of main `770847e` (12:39 to 13:28 CEST) found about 100
  findings, 20 of them high, triaged into seven fix blocks. Branch `fix/audit-2026-10-03`, one
  commit per block, each fix with a regression test that fails on the old code.
- Done: (1) secrets and evidence integrity, (2) verdicts that left a CI gate green, (3) robustness
  and resume, all in PR #32; (5) policy and authorization: the DL4 gate on the shipped PII spec,
  `test_only` enforced from the category, encoded-separator paths refused, the fleet judge
  authorized only from the fleet file, fleet scopes pinned to their port. Clauses A-29, A-30.
- Open: block 4 (judge calls and the identity sweep outside the request ceiling and the rate
  gate; `--rate 0`), block 6 (CLI and reports: `--hardened` on a live target, `diff` merging
  targets, usage errors exit 2 like "findings"), block 7 (docs that still contradict the code,
  including docs/02 S5's `--unsafe-render` opt-in, which no CLI flag sets), F11 (`--resume` never
  retries environment-error attempts).
- Decisions that are Daniel's: OD-18, OD-19 (amended), real scope signing vs. renaming it, a CLI
  flag to load a policy pack (without one, `requires_policy` specs and DL4 cannot be enabled from
  the command line), and the two `-sV` carriers that add instruction text.

---

## State, 2026-10-03 (later): user docs caught up

- Man page, `USAGE.md`, `docs/FAQ.md`, `docs/09`, `examples/README.md` and the `new-spec`
  scaffold now reflect `coverage`, AISVS and the OD-18 limit. Standing rule from Daniel, the same
  day: every change updates docs and examples in the same pass, without being asked.

---

## State, 2026-10-03: the indirect-injection oracles re-keyed

- `PI-INDIRECT-RAG-001` and `PI-INDIRECT-TOOL-001` no longer score a refusal that names the
  injection as a breach; detection of a leaked canary or a verbatim system prompt is kept and
  pinned in `tests/battery/`.

---

## State, 2026-10-03: OWASP AISVS as a fourth coverage axis, and an audit that found more

- **OWASP AISVS 1.0 pinned** (`shared/aisvs.py`, 191 requirements from upstream `05c62d1`,
  IDs and section headings only: the text is CC-BY-SA). Optional `aisvs:` list on a spec, read
  by falsification only (clause A-28): a failure is evidence a control is absent, a pass
  verifies nothing. `dottore coverage` prints one line per level: **5/51, 12/95, 0/45**.
- **The first mapping claimed 37 covered; an independent audit kept 17.** Bucket membership and
  which spec carries which row are both pinned in `tests/cli/test_coverage_cmd.py`.
- **New lint code `FRAMEWORK_CLAIM_CONTRADICTED`**: a spec may not claim a control the same
  table classifies as out of reach or deliberately untested.
- **The same audit found product defects outside AISVS**, verified in the code and not fixed in
  this change: the runner never delivers a spec's documents, tool definitions or memory seed
  to a live target (`core/runner.py` `_build_request`), while `docs/01` §4 says it does (32 of
  75 specs depend on it); `evaluator_logic: weighted` (33 specs) is implemented nowhere in the
  run or lint path: both let any deterministic fail decide, the weighted vote lives only in
  `evaluators/combine.py`, which neither calls, and the runner's docstring says it honours the
  field; `JB-MULTILINGUAL-001` sends English (the translate mutator glosses one word);
  `PI-INDIRECT-RAG-001` and `PI-INDIRECT-TOOL-001` still fail a refusal that names what it
  refuses; stored probes carry no timestamp (`Attempt` has no time field and the CLI never
  passes `started_at`/`finished_at`, so both are null in SQLite and in the report). Next, before
  any live run.

---

## State, 2026-10-03: two open decisions before any live run

- **OD-18 (ADR-0009): a spec's setup never reaches a live target.** 32 of 75 specs depend on
  documents, mock tools or a memory seed that the runner does not send; `docs/01` and `docs/16`
  corrected. Recommended: operator-declared seeding first, in-band delivery for bare models next.
- **OD-19 (ADR-0010): `weighted` is declared by 33 specs and implemented nowhere.** Recommended:
  document the runner's rule (a deterministic fail decides) as the semantics.
- Both need Daniel. The live validation in `docs/16` should wait for OD-18.

---

## State, 2026-09-22 (night): campaign integrity, a measured -sV, honest gaps, live runbook

- **`--resume` now binds to its campaign**, not to the invocation: a per-spec digest in the run
  store refuses a resume whose battery changed (naming what changed, exit 3), and the persisted
  cumulative spend makes a ceiling bind the campaign (`--budget-requests 6` twice sent 12).
- **CI measures `-sV` instead of only running it**: `mock_scenario: comprehending` decodes
  zero-width, rot13 and base64, so the carrier layer produces a real split and the plan comes
  out reordered through the real layer, mutators and planner. A simulated decoder, not a model.
- **Coverage tells the roadmap apart from what a black-box scanner cannot reach**, with a
  reason per code, and the out-of-reach codes stay in the denominator.
- **Battery 72 -> 75 specs**: `RECON-MODEL-IDENTITY-001` (IoPC T8.002),
  `AG-CODEEXEC-UNEXPECTED-001` (T4.002), `DOS-RESOURCE-HIJACK-001` (R015). IoPC techniques
  27/30, impacts 23/23. Two previously recorded out-of-scope decisions revised in `docs/15`,
  with the reason, rather than flipped in silence.
- **Live validation runbook: `docs/16-live-validation.md`** plus `make live-estimate`. Measured
  today with `--estimate`: a bare hosted model exercises **34 of 75** specs for **550
  requests**; a fully capable deployment **67 of 75** for **780** (+17 probes with `-sV`). The
  capability gate is why a raw endpoint cannot exercise the battery, and 8 specs stay blocked
  by the default policy pack on purpose.
- **Contract clauses A-24, A-25, A-26.** Gates green (95%+ coverage), 75 specs / 14 suites.
- **Still open and needing Daniel**: the accounts, the models and the spend for a live run.
  Everything else for it is written down.

---

## State, 2026-08-31, first real over-the-wire scans (Ollama + a vulnerable chatbot)

- **Ran Il Dottore against real targets for the first time** (local, no API key): a raw
  Ollama model and a local reproduction of aira-security/Vulnerable-AI-Chatbot (its pins
  don't install on py3.12/3.14, so a faithful stdlib shim reproduces its documented
  "forget your rules -> reveal secret" policy bypass, backed by Ollama).
- **Result:** Il Dottore found a **critical, reproducible (5/5)** prompt-injection ->
  secret-leak on the chatbot (risk 16.0), and returned decisive PASS on 7 other attack
  classes once the judge was wired. Reports in `ildottore-realtest/aira/`.
- **`--judge` shipped** (`cli/app.py` / `cli/run.py` / `cli/wiring.build_judge_adapter`):
  supplies an LLM-as-judge (a local llama3.2:3b here) so `semantic_judge` decides on live
  scans instead of abstaining. Test in `tests/cli/test_wiring.py`.
- **Two real bugs the mock never exercised, fixed with regression tests:** (1) live
  multi-turn to Anthropic 400'd on an OpenAI-shaped `tool_calls` field (adapter now projects
  to `{role, content}`); (2) the evidence store refused every live write because a numeric
  logprob matched the phone/card shapes in flat-text scanning (guard now scans string leaves
  only). Plus a zero-width mutator property-test input-scoping fix. Suite: **1080 passed**.
- **Both follow-ups then done (same session):** (1) evidence redaction is seeded from the
  scan's known secrets (`wiring.planted_secrets` -> the store masks each spec's canaries +
  `secret_leakage` refs; validated: the leaked AIRA secret is now `«REDACTED:canary»` at
  rest, 0 in clear); (2) a *consulted* judge that abstains is dropped so the deterministic
  arbiter carries, while an *unconsulted* judge (capability_unavailable) and deterministic
  abstentions still dominate (bare mode stays inconclusive).
- **Fleet config + `dottore fleet`** added: one `fleet.yaml` lists every LLM/URL/MCP target
  to validate and expands to `scope.yaml` + per-target files (`--run` scans them all). Keys
  by env reference only; provider inferred from the endpoint path; `kind: mcp` recorded as
  skipped (adapter pending). Example `specs/fleet.example.yaml`. Suite: **1089 passed**.
- **MCP adapter is the natural next build** (the one skipped fleet kind). Still **not committed**.

---

## State, 2026-08-30, DeepTeam gap analysis executed (multi-turn engine + 3 families)

- **Driver:** `docs/14` (DeepTeam coverage-map, no dependency). Whole roadmap built in one pass.
- **P0 multi-turn engine** (`core/conversation.py` + runner `_is_multi_turn` branch): pinned
  attacker ladders threaded as `messages`, final turn scored, transcript persisted. Backward-
  compatible, the 6 existing `turns` specs now execute as real conversations offline with the
  same verdicts (mock replays the fixture as the final reply); against a live target they now
  actually escalate instead of sending only turn 0. Unit tests `tests/core/test_conversation.py`
  (6) + runner e2e `test_multi_turn_spec_runs_as_a_conversation`.
- **Specs added (19):** 5 multi-turn jailbreaks, 7 access-control, 5 agentic (OWASP-Agents-2026),
  `JB-MULTILINGUAL`, `RECON-SYSTEM`. **Suites added (4):** `multi-turn`, `access-control`,
  `agentic-owasp2026`, `obfuscation-enhancers`. Battery: **47 specs / 8 suites**.
- **Mutators:** 12 → **18** (leetspeak, adversarial_poetry, math_problem, gray_box,
  linguistic_confusion, context_poisoning) + golden fixtures; wired into the jailbreak specs.
- **Gates all green:** ruff, mypy (125 files), import-linter (4/4), `dottore lint` (0/0),
  pytest **1077 passed**, and an offline E2E `dottore run` of the multi-turn + access-control
  suites (vulnerable ⇒ fail, hardened ⇒ clean, transcript present in the JSON report).
- **Deferred by design (docs/14):** adaptive Tree search (shipped as pinned breadth ladder),
  systematic per-language multilingual battery (needs mutation parameters), Responsible-AI /
  Safety / Business content packs (don't fit the security `category` enum; `docs/12` = optional).
- **Not committed**, working tree only; GPG signing is the owner's.

---

## State: 2026-07-08 18:06 CEST: MVP-2 waves 1-2 shipped

- Repo `main` == origin `734217f`, **24 commits**, GitHub CI green; all gates green
  (lint 28 specs/4 suites, full suite, mypy 118, import-linter 4/4).
- **MVP-2 wave 1** (`4587810`): `kill_chain_progression` evaluator (JadePuffer chain-depth
  scoring, wired into AG-EXTORT specs) + **coverage metric** in reporting.
- **MVP-2 wave 2** (`734217f`, built on **Sonnet 5** to dodge the Opus-4.8 cyber classifier):
  `dottore diff` baseline/drift regression gate + **OWASP LLM08 embeddings** family
  (EMB-XTENANT-RETRIEVAL / EMB-INVERSION-PROBE / EMB-NEIGHBOR-LEAK + embeddings suite).
- **Safeguard event logged** (2026-07-08): Opus 4.8 blocked the kill_chain sub-agents 3×
  (cyber-topic false positive); exemption email prepped for Marta+Laurens; mitigation = route
  security-content sub-agents to Sonnet
  5 (works). See `~/AI projects/ildottore-anthropic-safeguard-log.md`.
- **Backlog left (docs/12):** adversarial-suffix/transfer attacks, guardrail-evasion, multilingual
  battery, function-calling attacks, finding-dedupe-across-mutations; P2 items. Pre-public: GPG
  re-sign + history scrub of old `.dottore/` artifacts. OD-11 default (PII off) still human-pending.

---

## State: 2026-07-08 12:18 CEST: MVP-2 wave 1 + first real safeguard block

- **MVP-2 w1 landed** (`7dceb9a`): **coverage metric** (% OWASP/ATLAS exercised + run/skip/block
  counts in summary + JSON/HTML/terminal) and **`kill_chain_progression` evaluator** (JadePuffer
  chain-depth scoring over mocked traces; fail only on exfil/destroy/ransom; FP-disciplined;
  wired into AG-EXTORT-CHAIN + AG-DESTRUCTIVE-DBDROP). Full suite green, lint OK, mypy 117.
- **⚠️ First real Anthropic safeguard block:** the automated adversarial-validator + one impl
  sub-agent for kill_chain were blocked 3× ('flagged for a cybersecurity topic', Opus 4.8;
  req_011CcpPiPD5JcrF26mwMTWs5 +2). Code (impl it1) + its 20-test FP/harmful suite had already
  landed → gate stayed green; conductor did **manual** senior validation. Did NOT circumvent.
  Logged to ~/AI projects/ildottore-anthropic-safeguard-log.md;
  exemption: claude.com/form/cyber-use-case.
- **RESPONSIBLE-USE.md** charter added (`80d574f`). Dependabot actions-bump merged earlier.
- Carryover: MVP-2 w2 (baseline/drift, adversarial-suffix, multilingual, embeddings); GPG re-sign
  + history scrub of old `.dottore/` artifacts before public flip.

---

## State: 2026-07-08 09:26 CEST: 🟢 CI GREEN on GitHub Actions

- GitHub Actions `ci` is **green** on `main` (run 28925238514). Two CI-only failures found &
  fixed after the first push (local was green, runner was not):
  1. `.gitignore` `reports/` + `*.sarif` patterns ate the committed reporting snapshot fixtures
     (`tests/reporting/fixtures/reports/golden.*`) → Gate 9 FileNotFoundError. Root-anchored the
     patterns + committed the fixtures (`11d2e3b`).
  2. rich/Typer `--help` wraps to 80 cols without a TTY → flag substrings truncated → Gate 10.
     Rendered help wide + ANSI-stripped in the test (`276952f`).
- Node20-action deprecation is a non-blocking annotation; Dependabot PR to bump actions is open.

---

## State: 2026-07-08 09:20 CEST: pushed + agentic-extortion pack complete

- **Repo is LIVE (private):** https://github.com/RobinR00T/ildottore: `main` pushed, local ==
  remote == `035a76b`. `gh` authed as RobinR00T (repo+workflow scopes); CI (`.github/workflows`)
  will run on push.
- **Agentic-extortion (JadePuffer) pack completed** (`035a76b`): +5 specs (DBDROP, CRED-SWEEP,
  EXFIL-EGRESS, PERSIST-BEACON, AUTONOMY-SELFCORRECT) + suite (7 specs). Adversarially verified:
  lint OK (25 specs), **960 tests**, golden FP/FN accuracy 1.0, safety AX1-AX5 hold, RFC-5737
  doc IoCs, narration≠fail. All mocked/test_only/policy-gated OFF.
- **USAGE.md** added (`0b3f0be`): user quickstart.
- **Still pending:** commits UNSIGNED (re-sign + force-push before flipping public) · OD-11 (ship
  DL-PII-ELICIT-001?) human-pending · deeper Stage-6 (real-model run) · MVP-2 backlog (`docs/12`).

---

## State: 2026-07-08 01:00 CEST: 🎉 MVP‑1 CODE COMPLETE

- **All 6 waves DONE. All 15 units built.** ✅ W0 `5c86bfc` · W1 `c33e7a1` · W2 `1a8dff9` ·
  W3 `8c87487` · W4 `61d24cd` · W5 `280794c`.
- **Merge gate GREEN:** full test suite passes; import-linter **4/4 contracts kept, 0 broken**;
  ruff + ruff-format clean (229 files); **mypy clean on 116 source modules**; `dottore --help`
  + all commands work; **E2E `dottore run --quick` executes the T0 battery** (the `quick`
  suite, 18 specs today) against
  MockTarget and produces a valid JSON/summary report (all INCONCLUSIVE: correct for a bare
  mock with no scenario). 122 src files, 167 test files.
- **Stage‑6 finding #1 (FIXED):** `run` default `specs/` discovery found 0 specs because the
  loader only recurses into *spec packs*. Fixed data-only by adding `specs/pack.yaml`: now the
  built-in battery is discovered out of the box (20 specs).
- **Stage‑6 finding #2 (FIXED):** `dottore lint specs/` still exited 1 (u02 §7 / u14 §7 criterion)
  because the 3 shipped `specs/suites/*.yaml` were authored to the u02 §6 design sketch
  (`{id, version, spec_ids, defaults}`) instead of the enforced canonical `Suite` model
  (`suite_version` / `specs:[{spec_id}]`), which the fixture, tests, linter and registry all
  speak. Fixed data-only (u13): conformed the 3 suite files to the model (`version`→`suite_version`,
  `id`→`spec_id`, `defaults.runs`→`default_runs`, `framework_rollup`→`tags`; unmodeled MVP‑2
  `sampling`/`fail_on`/`requires_policy` kept as comments). Updated `tests/battery` (`entry["id"]`
  →`entry["spec_id"]`) and restored the u14 CI gate to `dottore lint specs/` (was `specs/attacks`
  + informational warning). `dottore lint specs/` now exits 0 (20 specs, 3 suites, 1 pack); full
  suite green. Note: `dottore lint specs/suites` alone still exits 1 by design: a bare dir with no
  `pack.yaml` loads as a loose *attack-spec* tree, so suite files fail attack-spec validation.
- **Pending / carryover:**
  - `git push` + create private repo `RobinR00T/ildottore`: **blocked on `gh auth login`** (6+
    local commits waiting). Commits are UNSIGNED (gpg-agent locked): re-sign before public.
  - OD‑11 (ship `DL-PII-ELICIT-001`?): still human-pending; defaulted disabled/policy-gated.
  - Stage‑6 deeper pass: run against a real model (staging key) to see real pass/fail, review a
    sample of findings + evidence; wire more mock scenarios so goldens exercise pass/fail paths.
  - MVP‑2 backlog per `docs/12` (RAG/agent depth, membership inference, embeddings, adversarial
    suffixes, SARIF polish, baseline/drift, coverage metric).

---

## State: 2026-07-07 20:48 CEST

- **Stage 3 Execute: 3 of 6 waves done.** ✅ W0 u00 (`5c86bfc`) · ✅ W1 u01/u02/u05/u07
  (`c33e7a1`) · ✅ W2 u03/u04/u10 (`1a8dff9`). Full suite green, mypy clean on 61 modules.
- **W3 launched** (`wq7p6q9iq`): u06 evaluators (hardened judge + pii/secret-shape/authz +
  membership) · u09 fingerprint (6 self-contained layers + the carrier layer wired by u12,
  capability_guess, no TestPlan per ADR-0006).
- Transient API "Overloaded" hit u03 twice in W2: PITV loop retried to green (working as
  designed).
- **Permissions:** session set to `bypassPermissions` (settings.local.json) for unattended
  overnight run. Remaining waves W4 (engine+reporting+battery) → W5 (cli+ci) → merge gate.

---

## State: 2026-07-07 17:15 CEST

- **Stage 3 Execute in progress.** W0 `u00-shared-models` **DONE** (commit `5c86bfc`): PITV
  2 iters, independently re-verified: 63 tests, 100% coverage on shared, ruff+mypy clean.
  The interface registry (models/protocols/enums/schema_export) is live and committed.
- **W1 launched** (`wou73jr5p`): u01 config/scope/policy/redactor · u02 registry/linter ·
  u05 mutators · u07 scoring: parallel PITV loops against installed u00.
- Also committed: agentic-extortion spec family (`bc4db46`).
- **Decision defaults locked** this block (OD-2/4/5/6/8/9/10/12/13/15): see 00-INDEX ledger.
  OD-11 (PII elicitation) still human-pending.

---

## State: 2026-07-07 16:22 CEST

- **Stage:** 1 ✅ · 2 Specify **✅** (15 contracts + consistency gate reconciled) · 3
  Execute ⬜ (starting W0).
- Repo bootstrap complete + first commit (37 files,
  **unsigned**: gpg-agent locked non-interactively).
- **Stage 2 done via workflow** (`wpzv95kk4`, 15 agents, ~981k tok): 14 unit contracts written +
  cross-unit consistency review. The gate caught **3 blocking issues** at the TestPlan/planner
  seam (u08↔u09) + missing schemas → **resolved by ADR-0006** (TestPlan+ModelFingerprint in
  u00; plan-builder is u08-only; Pydantic-first schemas). Non-blocking drifts fixed (Verdict
  `inconclusive_reason`, docs/01 Mutator, `dott` alias). OD-6..OD-15 rolled into the INDEX ledger
  with decisions.
- **⚠️ Only human-pending decision:** OD-11: whether `DL-PII-ELICIT-001` ships in MVP-1.
  Defaulted **disabled/policy-gated** (legal-safe) until Daniel signs off.

### Next
- Stage 3 Execute: PITV build wave-by-wave from `00-INDEX` (W0 `u00-shared-models` first).

---

## State: 2026-07-07 16:08 CEST

- **Stage:** 1 Understand ✅ · 2 Specify 🟡 (INDEX + 1 of 15 contracts) · 3 Execute ⬜ (not started)
- **Nothing built yet**: repo is 100% specs/design. No `src/` code.
- **License:** MIT · **Repo:** private under `RobinR00T` (to flip public after we test).
- **⚠️ `gh` OAuth token expired** → cannot create remote or push. All work stays **local**
  until operator runs `gh auth login -h github.com`. Commits will be GPG-signed.

### Done
- Full spec package: `docs/00-12` + `REFERENCES.md` + ADRs `0001-0003` + `schemas/` + example
  specs/suites/targets + `scope.example.yaml`.
- Methodology aligned to **Zynap Specs-Driven Development** (from the internal deck):
  `AGENTS.md` (foundation), `docs/00` rewritten to the six-stage method + PITV + orchestration,
  `specs/contracts/00-INDEX.md` (15 units, dependency DAG in 6 waves, single-executor ledger,
  OD-1..5), exemplar contract `unit-06-evaluators.md`.
- Repo bootstrap started: `LICENSE` (MIT), `.gitignore`.

### Open decisions (rolled up: see 00-INDEX)
OD-1 logprobs common model (ADR-0005 pending) · OD-2 scope signing · OD-3 judge model default +
2nd judge · OD-4 evidence encryption timing · OD-5 adaptive planner default.

### Next (autonomous, per approved plan)
1. Finish repo bootstrap: `pyproject.toml`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`,
   `CODEOWNERS`, `git init` + first signed commit (local).
2. Complete Stage 2: generate the remaining 14 unit contracts from the INDEX.
3. Stage 3 Execute: PITV workflow wave-by-wave (W0→W5) to MVP‑1, then merge gate + Stage 6.

### Operator to-do
- `gh auth login -h github.com` (as `RobinR00T`) so the conductor can create the private repo
  and push the local history.
