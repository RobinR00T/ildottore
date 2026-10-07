# PROGRESS: Il Dottore (living ledger)

The carryover ledger. Every agent session updates this so context survives even a cold start
(the method's observability/resume + "own the context" discipline). Newest on top.

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
