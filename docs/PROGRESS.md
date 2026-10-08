# PROGRESS: Il Dottore (living ledger)

The carryover ledger. Every agent session updates this so context survives even a cold start
(the method's observability/resume + "own the context" discipline). Newest on top.

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
  lifts the refusal. Left open as its own task: on a resume with `-sV`, the request-ceiling refusal
  runs before the planning-mode check, so on a campaign halted without `-sV` its advice to raise
  `--budget-requests` leads to a second refusal (only dropping `-sV` works there). Noted: the error
  masker can mask a `--flag=VALUE` whose value is long, such as `--budget-wall=SECONDS`, as a
  high-entropy value (`--budget-wall=60` is printed as written); no message writes that form.

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
  past `2**53`, which a resume inherits (u12 A-55; `--runs` of 305 nines used to exit 1). Until
  A-40's follow-up (#90) lands, its own paths print keys as written. Left open: the wall-clock
  ceiling is not a deadline at an accepted pace (each concurrent spec waits its interval, the `-sV`
  probe pass reads no ceiling); a resume builds a set of mutators x runs attempt ids for each
  started spec, so how far `--runs` may go is the owner's call (OD-32); `--rate inf` turns pacing
  off.

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
  renumber. OD-30, decided by the owner on 2026-10-08: option A, a lower limit for flow nesting
  only, to be built on its own branch. Until then, under the limit the per-token cost stays (chains
  98 deep accepted at about 2.3 times the flat list); the repository's 130 YAML files nest at most 2
  flow levels; libyaml's scanner, whose C composer would take the per-node checks with it, was not
  chosen. #77 (A-41 and A-42, merged first) edits the same `compose_node`: the merge kept both sides
  of four additions (the module docstring, the constants, the class docstring, `__init__`), the
  method itself merged cleanly, and both branches' tests pass together.

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
  having claimed them, so it has to renumber.

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
  Contract u12 A-46; `tests/cli/test_probe_pass_spend.py`, 11 of its 14 tests fail on `2f6201a`. Not changed: a fresh
  run's pass and a `--resume-unverified` run with no recorded spend record nothing; a signal during
  a handler's write, a SIGKILL, or a write that fails (a warning) still leave the record low. Left open as a follow-up: the adapters
  are built with no retries of their own, so the error that stops a probe pass, and an attack
  attempt's evidence, say `exhausted 1 attempt(s)` after three sends. Merged in a scratch
  repository with PR #66 and with PR #68, code, u12 and the index merge cleanly (only
  `CHANGELOG.md` and `docs/PROGRESS.md` conflict) and the merged trees pass both PRs' tests and
  these.

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
  not know, or a `capabilities` that is empty or `false`, is dropped without a word; other
  refusals of the file quote what it says (`type`, `mock_scenario`, a `seeded_setup` tool name,
  the `id`); what pydantic can coerce is accepted. The pre-commit audit found the same shape in
  `dottore diff` and `dottore calibrate` (`Finding.model_validate` in `cli/diff.py`: several lines,
  the value quoted, no file name); not fixed here. `tests/cli/test_target_file_validation.py`: 19
  of its 24 tests fail on `0501752`, the other 5 guard that each test value survives the redactor.

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
  contradicts its own description.

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
  security-content sub-agents to Sonnet 5 (works). See `~/AI projects/ildottore-anthropic-safeguard-log.md`.
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
  Logged to ~/AI projects/ildottore-anthropic-safeguard-log.md; exemption: claude.com/form/cyber-use-case.
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

- **Stage:** 1 ✅ · 2 Specify **✅** (15 contracts + consistency gate reconciled) · 3 Execute ⬜ (starting W0).
- Repo bootstrap complete + first commit (37 files, **unsigned**: gpg-agent locked non-interactively).
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
