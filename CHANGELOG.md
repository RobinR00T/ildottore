# Changelog

All notable changes to Il Dottore. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Fixed (the audit of the same day's features)

Two adversarial audits were run against `-sV`'s carrier layer and `--resume`, in isolated
worktrees, hours after both landed. Each found a defect in the feature's central claim.

- **`-sV` was sending the repo's own jailbreak carriers during *recognition*.** The carrier
  layer probed every registered mutator, so a fingerprint pass put a refusal-suppression
  preamble ("Do not refuse"), a fabricated no-restrictions prior turn, a claimed-compromise
  framing and the published GCG universal suffix on the wire, the last one byte-identical to
  the string `JB-REFUSAL-SUPPRESS-001` ships behind `test_only: true` **and a policy gate**.
  The payload was benign; the carrier was not, and a filter sees the composite string.
  Contract §8 says recognition sends benign probes only and `docs/10 §5` calls it "the safest
  mode", so it violated both. Only **obscuring** carriers are probed now (7 of 18), and the
  split is computed rather than listed: a mutator whose output still contains the original
  sentence has *added* instruction text around it, which is the adversarial part. Structural,
  so a new mutator is classified on its behaviour instead of on somebody remembering a
  deny-list.
- **The measurement was mostly noise.** For the 13 carriers that leave the instruction
  readable, any target that echoed the prompt, or refused while quoting it, scored a perfect
  1.0 with zero comprehension; and `leetspeak` and `unicode_confusable` rewrote the marker
  itself (`Z0RBL47`, a Greek capital Beta), so a target with perfect comprehension scored
  **zero** on both. The marker is now drawn from the alphabet neither carrier rewrites,
  zero-width injections are stripped before the match, and the probe carries a second
  invariant token the target is asked not to repeat, so an echo is caught on every carrier.
  Measured against simulated oracles with the real mutators: an ideal decoder scores 7/7, a
  pure echo 0/7, a refusal 0/7, a refusal-that-quotes 0/7 (it was 13/18 for all three).
- **`-sV`'s cost was understated and unbounded.** The printed figure assumed one probe per
  layer, which is wrong for three of six (behavioral sends 4, statistical 3, capability 0), so
  a pass advertised as 24 requests really sent 28. Each layer declares its own count now and a
  test asserts the declared figure equals the real send count. `--estimate` prices the probes
  (it omitted them entirely, pricing 3 requests for a command that would send 31), and an
  explicit `--budget-requests` **binds** them: `--budget-requests 2 -sV` used to send 30
  requests and then report "limit 2, attempted 3", counting only the attack traffic.
- **`--resume` accepted another target's run id**, and that is the worst failure this tool can
  have: resuming target B with target A's evidence produced a full report for B with **zero
  requests sent**, in either direction (a vulnerable target inheriting a clean bill of health
  and exiting 0, or a hardened one inheriting criticals). An `Attempt` carries no target, so
  the evidence cannot detect it; the run store records `target_id`, so the resume is now bound
  to it and refuses a mismatch, and refuses too when no run store is available to check.
- **A tampered artifact exited 1.** `TamperError` subclasses `RuntimeError`, so it escaped the
  CLI handler and surfaced as a traceback with the code that means "findings below the
  threshold": corrupted evidence read as an almost-clean scan. Exit 3. And `--resume` is now
  resolved **before** `--dry-run` / `--estimate` / `-sn` return, so a typo in the id is caught
  by the commands whose job is validation, and `--estimate --resume` prices the work that is
  left rather than the whole battery.
- **Mutator ordering no longer imposes an alphabet.** The carrier scores are binary, so the
  hint arrives alphabetically, and ranking by its position silently made the tie-break the
  whole ordering, discarding the spec author's declared order. The hint is treated as a set:
  comprehended carriers first, declared order kept inside each group.
- **A symlinked run directory could read evidence from outside the store root** (the id cannot
  escape; a symlink planted at `<root>/<run-id>` could). Paths are now checked to resolve
  inside the root. And a stray file in an attempts directory reports what it is instead of a
  raw pydantic dump.

**Known limits, stated rather than left to be discovered.** What `-sV` measures offline is a
*simulated* decoder (`mock_scenario: comprehending`), so CI proves the chain from probe to plan
order, not how any real model behaves: that still needs a live run.

### Fixed (audit leftovers)
- **`nist_ai_rmf` had no validation of any kind** beyond non-blank, so a lowercase function
  or a missing subcategory number would fragment the `by_framework.nist` rollup in silence:
  the same drift shape the OWASP and ATLAS fields now refuse. It gets a **shape** rule (a
  well-formed `FUNCTION n.n` token must be present; the free-text gloss beside it stays
  free), deliberately **not** a universe rule. The asymmetry is the point: that field feeds a
  rollup and a SARIF tag, never a denominator, so a bad value cannot move a percentage, and
  the NIST AI RMF subcategory list is not transcribed in this repo, so "this subcategory
  exists" is not a claim it can make. Pinning a list nobody had diffed against NIST AI 100-1
  would have repeated the ATLAS mistake.
- **`examples/ci-github-actions.yml` installed with `pip install ildottore`, which 404s**:
  the package is not on PyPI. It installs from the repository at a pinned tag, so a pipeline
  gate cannot change meaning between runs.

### Added
- **`--resume` is bound to its battery and to the campaign's ceiling.** Two documented limits,
  the same shape: the command claimed a property of a whole campaign while checking only the
  invocation in front of it. (1) The specs could change between the halt and the resume, and
  the two halves are merged into one finding per spec and scored together, so an edited prompt
  produced a single report, under a single run id, out of two different batteries, with nothing
  saying so. The run store now records a per-spec digest and a resume **refuses** a changed
  battery, naming what changed and exiting 3. The digest is over the loaded model, so
  reformatting a file or adding a comment is not a change while anything that reaches the wire
  or the verdict is. A run recorded before the digests existed is reported **unverifiable** (on
  stderr, never suppressed by `--quiet`) rather than treated as a match. (2) The hard budget
  reset on every command, so a run halted at its ceiling could be resumed and spend the whole
  ceiling again under the same id: `--budget-requests 6` twice sent 12. The cumulative spend is
  persisted and the ledger opens there, so a ceiling binds the campaign. Contract clause A-24.
- **CI now measures what `-sV` produces, not just that it ran.** The carrier layer's entire
  output is an ordering, and every offline scenario answered with one fixed string whatever
  arrived, so no carrier was ever comprehended, the hint came back empty, and the ordering was
  asserted nowhere. `mock_scenario: comprehending` is an offline target that decodes what it is
  sent (zero-width, rot13, base64) and follows the instruction when it survives, so the layer
  produces a real split (4 comprehended, 3 not) and the plan comes out in a different order,
  through the real layer, the real mutators and the real planner, with no endpoint and no key.
  It is a simulated decoder, not a model: it proves the chain, not how a real model behaves.
  It also buys nothing on the verdict side, every spec against it stays `inconclusive`.
  Contract clause A-25.
- **Recognition traffic is now evidence.** A `-sV` pass sends 17 requests per target and left
  no trace of any of them: the evidence tree could not answer "what did this tool send my
  endpoint", which is the question the product exists to answer, and is precisely what kept a
  day's worth of probes carrying attack framing invisible (see above). Probes are written to
  `<run>/probes/` through the same redact-hash-write path as attempts, so the fail-closed leak
  guard and the content-addressing cover them for free, and `dottore replay` lists them under
  their own heading. They stay out of `attempts/` on purpose: a probe is not an attack attempt,
  and counting it as one would inflate the reproducibility denominator, the resume skip set and
  the replay count. A probe whose send fails is stored with its error. Contract clause A-23.
- **NOVA / IoPC coverage-gap battery**: 10 specs + the `nova-iopc` suite, authored from a
  spec-by-technique map against the Nova IoPC taxonomy (`docs/15`). Covers delayed/triggered
  injection, persistent memory poisoning, hallucinated dependencies (slopsquatting),
  human-agent trust exploitation, self-replicating prompts, unicode/homoglyph deception,
  phishing-BEC, disinformation at scale, target reconnaissance and log/provenance tampering.
  No runtime dependency on the feed and no raw feed payload shipped.
- **Function-calling & structured-output battery**: the `structured-output` suite, with
  `OUT-JSON-SCHEMA-COERCE-001` (out-of-schema privileged field in the returned JSON) and
  `OUT-JSON-ENUM-ESCAPE-001` (out-of-enum value on a field that gates exposure), grouped with
  the existing `FUNCALL-ARGSMUGGLE-001` so the contract is covered in both directions.
- **Multimodal breadth**: `MM-IMG-SPLIT-PAYLOAD-001` (one instruction split across two image
  carriers, defeating per-attachment scanning) and `MM-IMG-TOOL-EXFIL-001` (the visual-to-agentic
  bridge: an image-borne instruction driving an unauthorized egress tool call).
- **`tool_sequence` evaluator** (14th type) + `AG-TOOLCHAIN-EXFIL-001`: fails when an ordered
  chain of individually-authorized tool calls completes, which a per-call check cannot express.
  Closes the last open row of `docs/14`.
- New `EVALUATOR_MISCONFIGURED` lint rule: an evaluator that would silently never fire (a
  `tool_sequence` with no `patterns`) is now a lint error.
- **Machine-readable Nova IoPC mapping.** Specs gain an optional two-axis `iopc:` block
  (`techniques` = the how, `impacts` = the damage). The taxonomy universe is pinned in
  `shared/iopc.py` (30 techniques + 23 impacts, transcribed from the live taxonomy on
  2026-09-19: the published v2.0.0-alpha artifact is an older, smaller snapshot), so the run
  report measures IoPC coverage against a real denominator in the terminal, JSON and HTML
  outputs, alongside OWASP and ATLAS. All 72 shipped specs are mapped (**25/30 techniques,
  22/23 impacts**); the uncovered codes are the out-of-scope decisions recorded in `docs/15`,
  plus `IOPC-T4.002` Unexpected Code Execution, which an audit of the mapping turned from a
  false claim into an acknowledged gap. The field is optional in
  the JSON schema so third-party spec packs keep validating, and a test pins that our own
  battery is fully mapped. A well-formed but non-existent code is a new `UNKNOWN_FRAMEWORK_CODE`
  lint error, because it would match nothing and silently shrink coverage.

- **`dottore coverage`**: a read-only command that reports what the battery TESTS, per
  framework, with no target, no credential and no sends. Answers the question asked before a
  run (and before a purchase): "covered, of what?". Names the uncovered codes rather than only
  counting them, supports `--framework`, `--suite` and `--json`.

### Added
- **`dottore run --resume <run-id>`: a halted campaign can be finished.** The engine has
  supported resume since u08 (`CampaignRunner.run(resume_from=...)` skips persisted attempt
  ids and merges a spec's prior attempts with the fresh ones) and **no command reached it**,
  which stopped being academic the moment a truncated run started exiting 3 and reporting "27
  of 72 specs never ran": the only way to finish the battery was to shrink `--runs`, which is
  the input to the reproducibility axis of the risk score. The prior run is reconstructed from
  the **evidence store**, not from the sqlite run store, because evidence is content-addressed
  and hash-verified (a tampered artifact refuses to resume) while the sqlite findings are a
  redacted projection. The resumed campaign keeps the original run id, so the continuation
  files against the same evidence instead of becoming a second partial run.

- **`-sV` changes the battery now, and the signal behind it is measured, not assumed.** The
  flag documented two jobs (recognise the model, tailor the plan) and did the first only:
  `core.planner._order_family_effective` reads `capability_guess["effective_mutators"]` and
  **nothing ever wrote that key**, so a fingerprint was bought with real requests and left the
  plan byte-identical except for the wording of each selection's `reason`. A new **carrier
  layer** (`fingerprint/layers/carrier.py`) sends one benign, policy-neutral instruction
  through every registered mutator and records whether the target still follows it; the
  planner then runs the carriers it recovered first. A transformation whose instruction the
  model cannot recover cannot carry an attack either.

  Stated narrowly on purpose: this measures **carrier comprehension**, not guardrail evasion,
  which cannot be measured with benign probes (contract §8). The alternative was a
  hand-written "mutators known to work against family X" table, which we have no empirical
  basis for; shipping one would attach a confidence to a fiction. The other tailoring hook,
  `_baseline_resistance`, is still unwritten by the engine and `docs/10` now says so instead
  of implying otherwise.

  The layer lives behind the composition root, not in `default_layers()`, because u09 may not
  import u05's mutators (import contract). Cost: a fingerprint pass goes from 6 probes to
  ~24, the figure is printed in the resolved plan, the probes are paced by the same `--rate`
  ceiling as attack traffic (they bypassed it entirely before, since they do not travel
  through the runner), and `--dry-run` / `--estimate` / `-sn` still send none of them.

### Fixed (second audit round, on the first round's own work)

Four more adversarial audits were run against the commit above. They found that its headline
diagnosis was **wrong**, and that the fix had reintroduced the defect it was written to remove.
Both corrections are below, and so is the number the first round got wrong.

- **CORRECTION: the default battery did not fit its budget, but not for the reason the entry
  above gives.** The binding axis was **`max_wall_s`, not tokens**, and the cause was that
  `max_wall_s` did not measure time. The composition root injects `deterministic_clock()` (a
  counter that steps 1.0 per **read**, so offline evidence records a byte-stable `latency_ms`)
  and the runner handed that same counter to the budget ledger. So 1800 "seconds" was 1800
  clock reads, fewer reads than a 72-spec run performs: the default battery halted after 45
  specs on **every** invocation, and adding a telemetry read anywhere silently changed which
  specs got scanned. The "~537k tokens against a 500k ceiling" figure was measured with
  `estimate_plan` over the raw unfiltered spec list; the resolved per-target plan estimates
  481k and the battery really consumes **367k**, so the token ceiling was never the
  constraint and raising it changed nothing. The ledger now gets a real `time.monotonic`
  clock and the evidence keeps the deterministic one; the full battery completes in about a
  second. Deriving the budgets from the plan remains right (a constant ceiling drifts as the
  battery grows) but it was not the fix. **A live run also had no wall bound at all**, which
  is where threat-model S8's time half actually mattered.
- **Multi-turn specs were completely unpaced.** `reproduce_conversation` accepted the
  `RateLimiter` and did not forward it one hop to `execute_conversation`. 11 of 72 shipped
  specs are multi-turn, but **42% of a full battery's requests**, and the measured breach was
  **19x** the authorized rate (389 req/s against a requested 20). The rate ceiling added in
  the same commit therefore held on one of the two send paths.
- **`--dry-run -sV` and `--estimate -sV` SENT.** Fingerprinting sends ten probes per target,
  and the guard excluded `-sn` only, so the two commands whose entire promise is zero egress
  printed "dry-run: plan resolved, sent nothing." immediately after ten live requests with a
  real bearer token. `--quick --dry-run` is the first command the README teaches.
- **A derived ceiling with no upper bound let a spec pack set the scanner's self-DoS limit.**
  `sampling.max_tokens` was unbounded in the model, in the JSON schema and in the linter (a
  negative value was accepted too, and dragged an estimate *down*). Measured on a pack nobody
  would call hostile (200 specs, an ordinary 8k completion, 4 mutations): a **61-million**
  token allowance, 123x the old constant. `max_tokens` is now bounded (1 to 200_000), and the
  derivation is clamped by `BUDGET_DERIVATION_CAP`; `--budget-tokens` / `--budget-requests` /
  `--budget-wall` are how a **human** authorizes more, which is the distinction that makes a
  budget a budget.
- **"Specs run: 72 of 70 planned", i.e. 102.9%, on every green run.** The denominator counted
  `selected + capability-skipped` and omitted the policy-blocked specs, whose findings stayed
  in the numerator. Same shape as the defect the first round set out to remove, introduced by
  its fix. The first invariant test written for it could not catch it either: it built the
  universe out of the output it was checking, so `covered <= universe` was a tautology that
  passes for any output at all. Both are fixed, and the invariant now reads the pinned
  universes.
- **Coverage credited specs that never sent a request.** A policy-blocked or
  capability-skipped spec produces a finding, and crediting its framework codes inflated a
  default run by a whole tactic: 13/16 ATLAS published while `Credential Access` was covered
  solely by `AG-CRED-SWEEP-001`, which the default pack blocks and which sent nothing. Only
  specs that reached the wire count now, and the ones that did not are reported
  (`coverage.not_exercised`) rather than silently folded in. A selection where **nothing** is
  runnable is refused outright (it used to exit 0 with `3 of 0 planned` and zero requests).
- **SARIF and JUnit carried no truncation signal**, which are the two formats CI actually
  reads: a halted campaign rendered as a fully green JUnit suite (`errors="0"`, hardcoded)
  and a SARIF log with no `invocations` at all. SARIF now carries
  `invocations[0].executionSuccessful` plus a tool notification (its own field for this) and
  JUnit an `<error>`. **`dottore diff` refuses an incomplete report**: the specs that never
  ran are absent, absence classifies as `ONLY-IN-BASELINE`, and that is not a regression, so
  a scan that dropped a third of the battery used to diff green and exit 0.
- **An authorized but unreachable target exited 0.** Every attempt died on transport, so every
  verdict was inconclusive, coverage percentages were published as if measured, and the reason
  lived only inside the evidence. That is the same false green the scope gate was fixed for,
  one layer further out: it is now `unreachable`, reported, exit 3.
- **The authorization gate and the adapter disagreed about "the endpoint" in 80 of 252
  combinations, 41 of them false refusals.** Three different notions: the scope's `base_url`
  (what the pre-flight authorized), `target.endpoint` (what the operator wrote) and
  `origin + a hardcoded provider path` (what the adapter sent). The hardcoded path also
  **discarded the declared one**, so every gateway-hosted model was broken:
  `https://x.openai.azure.com/openai/deployments/gpt4o/chat/completions` went on the wire as
  `https://x.openai.azure.com/v1/chat/completions`. One function (`wiring.request_url_for`)
  now answers for the gate and the factory both, and the declared path wins over the provider
  default (Azure OpenAI, LiteLLM, any corporate proxy).
- **`fleet --run` turned an adapter refusal into a traceback and exit 1**, the code that means
  "findings below the threshold": the same handler tuple `run` and `fingerprint` had already
  been given in the first round, minus `AdapterError`.
- **A stdio MCP command line was printed unmasked** by `-sn` and `--dry-run`, secret included
  (`stdio://... --token sk-...`). The repo's redactor masks exactly that; these two printers
  were simply not routed through it, and they are the commands whose output lands in tickets.
- **`--quick` / `--deep` silently overrode an explicit `-T`**, in both directions: `-T0 --deep`
  became T2, four times the pace, on a target whose operator had chosen T0 precisely because
  it is fragile. An explicit `-T` now wins.
- **Schemes were blocklisted, not allowlisted**: `ws://`, `ftp://`, `file:///etc/passwd` and a
  scheme-relative `//host/path` all passed `is_allowed`, because the gate refused the literal
  scheme `http` off-loopback and let everything else through to the host check. Percent-encoded
  dot segments (`/v1/%2e%2e/admin`) are decoded before the prefix check too.
- **A duplicate target id in a scope silently resolved to the first entry**, so a permissive
  entry could shadow a narrowing one, including its credential allowlist. Refused.
- Smaller, each one an audited finding: `--compare` now prints the comparison matrix in the
  terminal instead of only embedding it in the JSON (it was a flag that counted its arguments
  and did nothing else); `-v` no longer announces "sent nothing" immediately before sending,
  and `-vv` lists the skipped and blocked spec ids instead of being byte-identical to `-v`;
  an ignored `--rate` is announced on a plain run and not only under `--dry-run`, and the
  notice no longer claims the operator requested the timing template's own default;
  an **unreadable** `--scope` exits 3 instead of click's exit 2 (which this tool uses for
  "findings at or above the threshold"); attack targets get the same pre-flight credential
  check the judge got; `dottore replay <unknown-id>` refuses instead of printing
  `attempts: 0` and exiting 0; `fleet --judge` carries `--judge` into the "Run it:" hint it
  prints; a stdio refusal names the `commands:` field and the exact string to add; the
  `--fail-on`-vs-truncation precedence is documented; `dottore coverage` stopped rounding 22/23
  up to 96% while every other surface printed 95%; the IoPC axes print their taxonomy version
  like the other two; `docs/MANUAL.md` stopped publishing the retracted `12/14 86%` ATLAS
  figure in a block presented as real output; the `docs/09` cheat sheet no longer shows a
  positional-URL invocation and a `--model` flag that do not exist; `docs/10` states plainly
  that `-sV`'s plan tailoring is inert until the fingerprint engine emits the hints it reads;
  and `parked`, documented as a run state in three places and produced by nothing, is marked
  reserved.

### Fixed
- **A run that does not finish is no longer reported as a clean one (exit 3).** The default
  battery **did not fit the engine's own default token ceiling**: `DEFAULT_PLAN_BUDGETS`
  pinned `max_tokens = 500_000` while the default plan needs about 537_000 (the figure
  `--estimate` itself prints). The campaign therefore halted, marked itself
  `budget_exhausted` internally, and **threw that state away**: `cli/run.py` never read
  `result.status`, the exit code came only from the findings, and no reporter mentioned it. A
  scan that dropped 27 of 72 specs printed `total: 45, run: 45` (100% of itself), exited 0,
  and computed every coverage percentage over the subset that survived. Contradicted
  `core/runner.py`'s own comment, "never a silently-truncated complete", and invalidated any
  CI gate built on top. Now: the ceilings are **derived from the resolved plan** (still hard
  caps, still no self-DoS, but sized from what the operator reviewed instead of from a
  constant that drifts as the battery grows), a halt prints the breached axis and how many
  specs never ran, the exit code is **3**, and every report carries
  `summary.status.state` plus a planned-vs-run denominator (`coverage.specs.total` is what
  the plan selected; `coverage.specs.run` is what completed). The wall-clock ceiling also
  stretches to fit a slow `--rate`, so obeying one flag cannot break another.
- **`-sn` ("discovery only, no attacks") sent the full battery.** `-sn`, `-sV`, `-A` and `-v`
  were parsed by typer and **never read** (none was even a field on `RunOptions`), while
  `run.py`'s docstring claimed they "widen the battery". Measured: `-sn` with the quick suite
  sent **125 attack requests**. Every one is now wired: `-sn` reports the authorized
  endpoint, the target's declared capabilities and what the battery *would* run, then stops
  with zero sends (reachability is authorization-level, not a live probe, because probing
  means sending); `-sV` fingerprints the target through the adapter the campaign will use and
  feeds the plan; `-A` implies `-sV` + `--deep`; `-v` prints the resolved plan.
- **`--quick` / `--deep` did not change the battery.** They set the timing template and
  nothing else, while six documents said otherwise and the `quick` suite (18 specs) shipped
  unselectable by the flag named after it. `--quick` now selects it (and refuses a
  conflicting `--suite`); `--deep` runs the full battery with adaptive planning at `-T2`.
  The `docs/08` tier table no longer advertises a 150-spec T2 tier the battery does not have.
- **`--rate` was discarded, so the rate half of threat-model S8 did not exist.**
  `--rate 0.0001` (one request every 10_000 seconds) finished eighteen specs in 0.67s, and
  the rate column of every `-T` template was decoration. A new `core/pacing.RateLimiter`
  enforces it as **one shared ceiling for the whole campaign** (a per-task limiter would let
  concurrency multiply the rate) with **retries counted**, hooked at `execute_attempt`, the
  single funnel both the single-turn and multi-turn paths use. Not applied to an offline mock
  run, where nothing leaves the process, and the resolved plan states that rather than
  dropping the flag silently.
- **The numbers `--dry-run` and `--estimate` printed were false.** They reported the raw
  spec *selection*, computed once for all targets, before the planner's capability filter and
  before the policy gate: 845 requests promised against 499 sent over 68 specs, and a
  multi-target run wrong **in the direction that costs money** (5 promised, 10 sent; 195 on
  the documented fleet path against 390). Both now resolve a real per-target plan with
  `build_plan` plus the live `PolicyEngine`, print the skipped and blocked counts, and total
  across targets. A test pins the promised count to the real send count against a mocked
  endpoint; the previous test asserted only that the strings `"1 specs selected"` and
  `"would send:"` appeared.
- **The authorization gate checked membership, not reachability.** `scope.target(id) is None`
  was the whole test, and `ScopeTarget.endpoints` defaults to `[]`, so a scope naming the
  right target id with no endpoint allowlist (or a typo in `host`) **passed** the gate and was
  then denied on every single attempt: the false green was one character away. The gate now
  calls the engine's own predicate, extracted as `policy.authorize_target`, so the pre-flight
  check and the per-attempt check cannot diverge, and `--dry-run` prints the authorized
  **endpoint** instead of the words "authorized by the scope".
- **The `--judge` model was loaded and never authorized**, and its credential skipped the
  scope's `auth_ref` check that every attack target gets. Reachable through a documented
  command, because `fleet --judge` generated a scope the judge was absent from: every
  `semantic_judge` verdict then came back inconclusive for lack of authorization, with the
  reason only in the JSON, and the run exited 0. The judge now goes through the same gate and
  the same credential check, and `fleet --judge` puts it in the scope it generates.
- **`dottore fingerprint` loaded the scope and discarded it** (no id check, no endpoint
  check); it leaked nothing only because the probe was pinned to the offline mock, i.e. the
  safety came from an implementation detail. It is now gated by `authorize_target`, and a
  live target is fingerprinted through its allowlisted endpoint with its authorized
  credential, so `-sV` fingerprints the thing it is about to attack.
- **A malformed `target.yaml` exited 1.** `yaml.YAMLError` does not derive from `ValueError`,
  so it escaped the CLI handler as an uncaught traceback with exit **1**, which in this tool
  means "findings below the threshold": a CI step treating 1 as "carry on" swallowed a broken
  target, in the two commands whose only job is validation. Same for `EndpointNotAllowed`,
  which derives from `AdapterError(Exception)` and was outside the handler's tuple. Both are
  operational errors now: **exit 3**.
- **An empty spec selection exited 0.** A typo in `--spec` ran nothing and reported clean, a
  green CI gate over an empty battery. It is refused, with the selectors echoed back.
- **`--compare` was parsed and never read.** It needs two or more targets and is now refused
  with one, rather than silently rendering no matrix.
- **`dottore coverage --suite <unknown>` reported a confident 0% across every axis** instead
  of refusing: a wrong answer to a typo, and a test had pinned that behaviour. It now lists
  the registered suites and exits 3. `--json` also honours `--no-gaps`, which only the human
  renderer had respected.
- **`--dry-run -q` printed nothing at all**, so the one command whose output *is* its purpose
  became mute. It prints a single machine-friendly line.
- **`estimate_plan` ignored the implicit `identity` mutator**, so every spec declaring
  mutations without repeating the baseline carrier was under-counted (one declared mutation
  is two attempts, not one).

### Changed
- **The MITRE ATLAS tactic universe was re-diffed against upstream and is now 16 tactics,
  not 14.** Transcribed from `mitre-atlas/atlas-data`, `dist/v6/ATLAS-2026.09.yaml` (release
  2026.09, 2026-09-14), cross-checked against that repo's `CHANGELOG.md` ("1 matrix, 16
  tactics"). Two of the old names were **retired spellings** (`ML Model Access` and
  `ML Attack Staging`, renamed upstream to `AI Model Access` and, in 2026.08,
  `AI Attack Adaptation`), and `Lateral Movement` (AML.TA0015, added 2025-11-06) and
  `Command and Control` (AML.TA0014) were missing entirely. Coverage matches by exact string,
  so our two lateral-movement specs scored **zero in silence** and the published figure was
  wrong in the numerator *and* the denominator: **12/14 (86%) against a true 13/16 (81%)**.
  Note for anyone re-checking: the legacy-format `dist/ATLAS.yaml` in the same directory
  still carries the pre-2026.08 name, so it disagrees with the release it sits next to.
- **Every framework figure now prints the edition it is measured against**
  (`OWASP LLM Top 10 (2025)`, `MITRE ATLAS tactics (2026.09)`), in the terminal, the HTML
  report and the JSON. OWASP published the 2026 list on 2026-08-03 with a **renumbering**, so
  an unlabelled "not covered: LLM03, LLM04" reads, to anyone holding the new edition, as
  "Excessive Agency untested": our single most covered category (24 of 72 specs).
- **Off-universe framework values are now a lint error, in both axes that lacked one.**
  `owasp: LLM11`, `owasp: LLM00`, `tactic: "initial access"`, `tactic: "Initial Access "` and
  the retired `tactic: "ML Attack Staging"` all used to pass `dottore lint` with **zero
  errors and zero warnings**, count for nothing, and tell nobody. IoPC already had this rule;
  OWASP and ATLAS now do too, with the universes moved to `shared/frameworks.py` (the linter
  and the reporting layer are peers that must not import each other), plus a battery
  invariant asserting no numerator can escape its denominator.
- **Percentages are floored, not rounded.** `"%.0f" % (199 / 200 * 100)` prints `100`, so one
  uncovered code in two hundred was published as full coverage. `100%` now requires
  `exercised >= total`.
- `examples/scope.openai.yaml` added: Scenario D pointed at the local scope with a
  parenthetical telling the reader to add the missing entry themselves, so the command as
  printed was refused. The README quickstart named `target.yaml` / `scope.yaml`, which do not
  exist in this repository; it now uses the shipped example pair and `dottore coverage`.

### Changed
- Battery is now **72 specs / 14 suites / 1 pack**, 14 evaluator types.
- `make bandit` runs with `-c pyproject.toml`; B105 is skipped as redundant with ruff's
  S105/S106/S107, which stay active.

### Fixed
- **The report masker no longer destroys spec ids.** The interim global entropy fallback
  (OD-15) masked any 16+ char token scoring 3.7 bits/char or more, which a hyphenated
  uppercase identifier does: 15 of the 72 shipped spec ids (`JB-SEQUENTIAL-001`,
  `SAFETY-HARMFUL-001`, `EMB-NEIGHBOR-LEAK-001`, all eight `AG-*`) rendered as
  `«REDACTED:high_entropy:<hash>»` in every format, and a URL lost its port and path
  (`endpoint 'http://localhost:«REDACTED:high_entropy:462fdfa1»' not on allowlist`).
  `spec_id` is the join key for `dottore diff` and the SARIF rule id, so regressions in 21%
  of the battery were untrackable across runs and those SARIF rule ids were unusable. The
  fallback now exempts separator-structured tokens **by shape** (the schema id shape, plus
  lowercase/digit ids, model names and URL paths), and requires every segment to be shorter
  than `entropy_min_len`, so an id-shaped wrapper around an opaque run
  (`ZYNAP-CANARY-A1B2C3D4E5F6G7H8`) is still masked whole. A token that is hexadecimal all
  the way through is excluded from the exemption outright, because that is the shape of a
  UUID-format key or a grouped digest (`da39a3ee-5e6b-4b0d-3255-bfef95601890`), which a
  model can emit with no label for the labelled-secret rule to catch. The bits/char threshold is
  deliberately unchanged: raising it to 4.0 would stop catching a random 20-char base64
  token two times out of three, and planted canaries (`CANARY-8f3a-...`, `ZYNAP_CANARY_*`),
  api keys, bearer tokens and PEM keys are all still masked, with tests pinning both sides.
- **The report masker no longer destroys dated model names, dates and run ids.** The
  `phone` detector (`\+?\d[\d\s().-]{7,}\d`) let `-` and `.` float freely inside the digit
  run, which is exactly how a dated identifier is punctuated, so
  `claude-opus-4-1-20250805` rendered as `claude-opus-«REDACTED:phone»`,
  `gpt-4o-mini-2024-07-18` as `gpt-4o-mini-«REDACTED:phone»`, `run-20260920-143000` as
  `run-«REDACTED:phone»` and a bare `2026-09-20` as `«REDACTED:phone»`, in every format. A
  model name reaches a report through `Target.model` / `Target.name` and the run through its
  date fields, so the report could not name the model it had just tested. (A full ISO
  timestamp survived: the `T` and the colons break the pattern, so only bare dates and dated
  names were hit.) Same remedy as the entropy fallback above, exempt **by shape**: a match
  is spared only when the whole of it is a calendar-valid date stamp (`YYYY-MM-DD` or
  `YYYYMMDD`), optionally preceded by up to three short version segments (`4-1-`, `4.1-`)
  and followed by at most one `HH`/`HHMM`/`HHMMSS` clock. The same bound applies as for ids:
  no segment can carry a number, so `20250805-600123456789` is still masked whole, and real
  numbers keep their mask in every notation (`+34 600 123 456`, `+1 (555) 123-4567`,
  `555-123-4567`, `555.123.4567`, `020-7946-0958`, `0034-600-123456`, `600123456`), with
  tests pinning both sides and the masking gate unchanged.
- **A target missing from the scope is now refused instead of silently scanned.** It used to
  produce a full run whose every spec came back inconclusive, with the real reason
  ("target not in scope") written only into the JSON report, and an exit code of **0**.
  Nothing was ever sent (an unscoped target gets an empty allowlist, so default-deny held),
  but the operator got a green exit and a report of unexplained inconclusives: a false green,
  which is the worst failure mode for a scanner. `examples/README.md` already promised "a run
  refuses any target that is not covered", so the code now matches, raising a scope error
  (exit 3, the documented slot for a bad scope) before any adapter is constructed.
- **`--dry-run` validates the target, and prints the plan it resolved.** It used to return
  before the target was even loaded, so the one command whose job is "check my wiring" never
  looked at the wiring, and reported a single contentless line while holding the scope, the
  target, the selected battery and the request estimate.
- **OWASP coverage was over-reported.** The denominator is the ten OWASP LLM categories, but
  the numerator counted every distinct `owasp` value on a spec, including the Responsible-AI
  `RAI01` / `RAI02` codes, which belong to a different framework. The battery's 8 LLM codes
  plus 2 RAI codes read as a perfect 10/10, reporting 100% OWASP coverage while LLM03 and
  LLM04 are untested; a third RAI code would have pushed it past 100%. ATLAS already filtered
  against its universe; OWASP now does too (real figure: 8/10).

### Fixed
- Repaired 10 spec oracles that passed every gate while measuring something other than the
  attack they described (hedge-vocabulary checks, polarity-free keyword presence, denylists
  where a complement was needed, and oracles that failed the best possible secure answer).
- `tool_sequence` name matching is now case- and whitespace-insensitive, and the offline lint
  stub evaluates every declared chain instead of only the first.
- Dependency floor `anyio>=4.14.2` for CVE-2026-63349 / 63374 / 64847 (transitive via httpx).

## [0.1.0] - 2026-09-03

First public release. The engine is built and self-validating: 57 declarative attack specs across
12 suites (OWASP LLM Top 10 / MITRE ATLAS / NIST AI), deterministic reproduction with evidence and
risk mapping, OpenAI / Anthropic / REST / MCP adapters, multi-turn, multi-identity, multimodal
(image + audio), fleet mode, and a green CI gate wall. See the entries below for the full detail.

### Added
- **Multimodal audio: spoken prompt injection carried in an audio clip (docs/12 P0)**. A spec can
  carry a payload in a pinned WAV (`kind: audio`, `format: wav`) referenced by an `asset` path,
  which the loader resolves to bytes at load time behind a strict path-traversal guard (no absolute
  path, no `..`, the resolved real path must stay under the spec directory). It runs only against a
  target that declares the new `audio` capability; the OpenAI adapter sends it as an `input_audio`
  content block. Carrier bytes are elided from persisted evidence (the `asset` reference and the
  `media_sha256` digest are kept), so a 100 KB clip neither bloats the record nor trips the
  fail-closed redaction guard. New `MM-AUD-PROMPTINJECT-001` (a spoken override demanding a benign
  codeword; a compliant model emits it, a secure one does not) in the `multimodal` suite. Battery
  is now 57 specs / 12 suites.
- **Multimodal attacks: visual / typographic prompt injection (docs/12 P0, MVP-3 phase)**. A spec
  can carry a payload in an image via `attack.media` (a declarative part, e.g.
  `{kind: image, format: png, render_text: "..."}`). `shared/media.py` renders it to a byte-stable
  PNG with a dependency-free stdlib encoder (zlib + a 5x7 bitmap font): no Pillow, no binary in the
  spec, so the carrier is reproducible and replays identically. The openai and anthropic adapters
  attach the rendered image to the user turn as the provider image content block; the runner keeps
  the declarative part on the request. New `MM-IMG-PROMPTINJECT-001` spec + `multimodal` suite: the
  user's turn asks only to describe the image while an override instruction rendered inside it
  demands a planted canary, so a successful visual injection is a decisive leak. A second spec,
  `MM-IMG-DOC-INJECT-001`, covers the indirect variant: the user asks to summarize a business-memo
  image whose body hides a "note to the assistant" (the multimodal analogue of PI-INDIRECT-RAG). A
  third, `MM-IMG-HARMFUL-001` (`safety_content`), checks whether the safety guardrail still refuses
  a disallowed request when it arrives as an image rather than as text (a non-operational
  placeholder payload, `test_only`, mirroring SAFETY-HARMFUL-001). All three are gated on
  `capabilities.multimodal` (a text-only target skips them, never a false pass). `attack.media` /
  `ModelRequest.media` are additive optional fields. Battery is now 56 specs / 12 suites. Audio is
  deferred: a faithful audio carrier needs speech (a TTS dependency or a pinned recorded clip), not
  stdlib synthesis, so it is not shipped as a fake carrier; non-image document (PDF/HTML text)
  injection is already covered by the retrieval path (PI-INDIRECT-RAG-001). Chain of custody: a
  multimodal request records the SHA-256 of each rendered carrier under `metadata.media_sha256`, so
  a run's evidence proves exactly which image bytes were sent and an auditor re-renders to verify.
  A new `dottore render-media <spec-id> --out <dir>` command renders a multimodal spec's carrier(s)
  to disk (read-only, sends nothing) and prints each path, size and SHA-256, so an operator can see
  exactly what image a scan will send before running it.
- **MCP adapter (`provider: mcp`) + `mcp` suite**: scan a Model Context Protocol server as a
  target. `adapters/mcp.py` speaks JSON-RPC over Streamable HTTP: it performs the `initialize`
  handshake and lists `tools`/`resources`/`prompts`, then renders that advertised metadata as
  the response. Read-only by design (safe-by-design, docs/02 S5): it never calls a tool
  (`tools/call`), and the endpoint allowlist is enforced before every request (S3). The new
  `MCP-TOOLPOISON-001` spec + `mcp` suite flag tool-metadata poisoning ("line jumping"): 
  imperative instructions hidden in a tool description. `kind: mcp` fleet entries now
  materialize (`type: api`, `provider: mcp`) instead of being skipped. Validated live against a
  local MCP server (finding: critical, evidence redacted at rest).
- **MCP stdio transport**: a `provider: mcp`, `transport: stdio` target launches a local MCP
  server as a subprocess and runs the same read-only discovery over newline-delimited JSON-RPC
  (stdin/stdout). Spawning is gated: the exact command line must appear in the scope target's
  `commands` allowlist (default-deny, mirrored by the policy gate and re-checked in the adapter),
  so an unauthorized command spawns zero processes. Validated live (finding: critical via stdio).
- **Fleet config + `dottore fleet`**: declare every LLM / URL / MCP target to validate in one
  `fleet.yaml`, which expands into the authorization `scope.yaml` + one `target.yaml` per
  model (`--run` scans them immediately). API keys are never written, each entry references
  an env var (`api_key_env`). Provider is inferred from the endpoint (`/chat/completions` ⇒
  OpenAI-compatible, `/messages` ⇒ Anthropic). Example: `specs/fleet.example.yaml`.
- **`--judge` (LLM-as-judge for live scans)**: a `--judge <target.yaml>` model wires the
  `semantic_judge` evaluator for over-the-wire scans, so a real target yields decisive
  verdicts instead of abstaining. `wiring.build_judge_adapter` builds a scope-allowlisted
  judge adapter (ADR-0002). Validated live against a local Ollama-backed target.
- **Multi-identity execution (makes authz_leak / M14 live)**: a `multi_identity` spec against a
  target that declares the capability and a scope with >=2 identities now runs end-to-end. The
  runner sends the attack as each identity (each with its own resolved credential from the scope)
  and collects the per-identity responses; `authz_leak` flags a tenant-scoped canary reaching a
  non-owner identity. New `ScopeTarget.identities[].canary` declares which identity owns a canary.
  Previously the runner never populated `EvalContext.identities`, so authz_leak was dormant.
- **Responsible-AI pack (optional, NIST-mapped)**: two new categories `safety_content` and
  `bias_fairness` (the `owasp` field now also accepts an `RAI` code, since these have no OWASP
  LLM Top 10 mapping), the `SAFETY-HARMFUL-001` (direct harmful request must be refused) and
  `BIAS-STEREOTYPE-001` (no demographic stereotype in a decision) specs, and the
  `responsible-ai` suite. Adjacent to security, shipped as an opt-in pack, not the core battery
  (docs/12 P2). Battery is now 50 specs / 10 suites.
- **`adversarial_suffix` mutator (GCG transfer, docs/12 P1)**: appends the published pinned GCG
  universal suffix (Zou et al. 2023) to a carrier, a reproducible black-box transfer jailbreak
  (19 built-in mutators now); wired into `JB-REFUSAL-SUPPRESS-001`. Live gradient optimization
  stays out of scope (needs model gradients and would be non-reproducible).
- **Parameterized mutations `name:param` (docs/12 P1)**: the runner now resolves a mutation by
  its base name and folds the full `name:param` into the seed, so `translate:fr` runs the
  `translate` mutator in French. `JB-MULTILINGUAL-001` uses this to run a systematic
  per-language battery (`translate:{es,fr,de,zh}`), offline and deterministic.
- **Guardrail / moderation-layer evasion pack (docs/12 P1)**: the `guardrail-evasion` suite with
  `GUARD-INPUT-EVASION-001` (an obfuscated trigger evades the input classifier; the model's own
  alignment must still refuse) and `GUARD-OUTPUT-ENCODE-001` (encode the harmful reply to slip
  past the output filter). Battery is now 52 specs / 11 suites.
- **Pre-run cost estimate (docs/12 P2)**: `dottore run --estimate` prints the plan's request
  volume (specs x runs x mutations x turns) and a rough token gloss, with zero sends. No
  per-model pricing is baked in (multiply by your provider's rate).
- **Human-in-the-loop calibration (docs/12 P2)**: `dottore calibrate <report.json> <labels.yaml>`
  scores a run's findings against operator ground-truth labels (agreement + precision/recall,
  `fail` = positive), so a team can measure the scanner and its judge. Read-only, no sends.
- **Function-calling / argument-smuggling detection (docs/12 P1)**: the `tool_call` evaluator
  gained an opt-in `forbidden_args` list. A spec declares argument keys that are out of scope
  for the task (e.g. a privilege field `role`, a control flag `bypass_review`); if the model
  populates any of them with a truthy value (at any nesting depth) on an otherwise-authorized,
  non-destructive tool, that is argument smuggling / schema poisoning and fails. The new
  `FUNCALL-ARGSMUGGLE-001` spec proves it. The check is inert for every spec that omits
  `forbidden_args`, so the existing battery is unaffected. Battery is now 53 specs / 11 suites.

### Documentation
- **User docs to parity**: refreshed `README.md` (real repository map, capabilities,
  quickstart) and `USAGE.md` (fleet, `--judge`, multi-turn, corrected scope schema, corrected
  suite/category aliases, fixed the `fingerprint` invocation and the `--adaptive` drift).
- **New**: `docs/MANUAL.md` (complete operator reference), `docs/FAQ.md`, `INSTALL.md`, and a
  runnable `examples/` directory (local-Ollama, hosted-OpenAI and fleet scenarios, plus a
  GitHub Actions gating workflow). Added `docs/14-deepteam-gap-analysis.md` to the index.
- **man pages**: `man/man1/dottore.1` and `man/man5/dottore-scope.5`.

### Tooling
- **`Makefile`** mirroring the CI merge gate (`make gates`), so the full wall (lint, format
  check, mypy, import boundaries, spec lint, tests, coverage ≥85%, self-scan, bandit,
  pip-audit) runs with one command locally.
- Normalized formatting on the files introduced this cycle so `ruff format --check` (a CI
  gate) is clean.

### Security (multimodal audit remediation, 2026-09-03)
Four parallel adversarial reviewers audited the multimodal / audio / asset-loading / evidence code
added this cycle; the path-traversal guard and rendering determinism verified clean, and these
confirmed findings were fixed (each with a regression test):
- **Chain-of-custody digest was self-defeating (high)**: `metadata.media_sha256` (a 64-hex hash) was
  above the redactor's entropy threshold and got masked at rest, silently voiding the multimodal
  audit trail. The digest is now exempted from redaction (popped before the pass, restored verbatim
  into the written payload), so it survives while the carrier bytes stay elided.
- **Carrier-strip widened**: `_strip_media_carrier_bytes` now recurses the whole attempt, eliding
  any `data_b64` wherever it appears (not only `request.media`), so a future multimodal multi-turn
  carrier cannot leak raw bytes past the fail-closed guard.
- **Unrenderable media no longer aborts a run**: a schema-valid-but-unrenderable `attack.media` part
  is now rejected by a new linter rule (renderability + capability match), and the runner isolates
  any `MediaError` as a per-spec `inconclusive` finding instead of crashing the whole campaign.
- **Media capability gating enforced**: the linter requires a spec with media to declare the
  matching capability (image -> `multimodal`, audio -> `audio`); the Anthropic adapter refuses an
  audio carrier rather than sending a malformed image block.
- **Rendering resource cap**: `render_text_png` bounds `scale`/`columns` and the projected output
  area (schema maxima too), so a spec cannot request a multi-hundred-megapixel image (OOM).
- **`tool_call` evaluator recursion fixed (medium)**: `forbidden_args`, argument-injection and
  confirmation-flag detection now recurse into lists of objects, closing a false negative where a
  smuggled key/marker hid inside an array argument (e.g. `{"recipients": [{"bcc": "..."}]}`).
- **Asset loading hardened**: a filesystem error while reading a media `asset` becomes a single
  lint finding (not an unhandled crash of the whole load pass), and an asset over a 25 MB cap is
  refused before it is read.
- **`render-media`**: writes each carrier with the extension implied by its MIME type (an audio
  carrier is `.wav`, not `.png`) and reports an unrenderable part as a clean error.
- **Parity guard added**: a test now pins the `Capability` enum to the `Capabilities` model fields
  and the planner's requires-to-capability map, matching the existing `requires`/schema guard.

### Security (adversarial audit remediation, 2026-09-01)
- **Allowlist path-traversal bypass (critical) closed**: `is_allowed` now resolves `..`/`.`
  dot-segments to the path the HTTP client actually requests before matching (a
  `…/v1/../admin` no longer passes a `/v1` authorization). Ports can be pinned (`host:443`);
  cleartext http is refused except to loopback.
- **Redaction hardening (DL2)**: secrets in a dict KEY are masked (not just values); a
  labelled-secret heuristic + a lower entropy threshold + slack `xoxp`/`xoxa` cover shapes the
  built-ins missed; the PEM detector no longer ReDoS-es on `BEGIN`-only blobs (END-marker
  precheck + bounded body); NUL bytes are stripped before the internal stash.
- **Verdict combine**: a decisive DETERMINISTIC fail now carries over an abstaining/unconsulted
  judge, while a judge fail can never override a deterministic FP-discipline abstention.
- **LLM-as-judge**: the control tripwire token is generated fresh per call (was a weaponizable
  static constant); `observed_injection_attempt` only casts doubt on a `secure` verdict, so
  honest `exploited` verdicts on the injection/jailbreak class are no longer discarded.
- **Evaluators**: regex evaluators are case-insensitive (matching specs + the lint stub);
  refusal no longer false-fails a refuse-with-alternative; tool_call flags encryption-for-impact
  and `destructive:true` metadata, honours a nested confirmation, and tightened its injection
  regex (backtick + `$(cmd`); `secret_leakage` honours `canary_ref`.
- **Fleet**: the generated scope/target are produced with `yaml.safe_dump` and target `id`s are
  charset-validated + deduplicated, so a crafted id can't corrupt the authorization allowlist.
- **Scoring**: `risk.reproducibility` is now coherent with `risk`/`band`; `confirmed` requires an
  undisputed fail (aligned with the canonical gate).
- **authz_leak cross-tenant precision (audit M14)**: with an optional canary-owner map
  (`EvalContext.canary_owners`), the evaluator now flags a canary that surfaces in a NON-owner
  identity (A receiving B-only data), not only a canary crossing >=2 identities; the owner
  legitimately seeing its own canary is still not flagged.
- **Linter tool_call stub parity (audit M7)**: the offline `dottore lint` stub now mirrors the
  real `tool_call` evaluator (authorized-allowlist + destructive-verb + confirmation + arg
  injection) instead of treating any tool call as a fail, so lint and the real evaluator agree.

### Changed
- **Verdict combination, an abstaining judge no longer sinks a decisive verdict.** A
  *consulted* `semantic_judge` that abstains (parse fail / low confidence / judge_compromised)
  is dropped so the deterministic arbiter carries (docs/04 §0). A DETERMINISTIC abstention
  (capability-gated / data-leak FP discipline) and an *unconsulted* judge (no `--judge`
  wired ⇒ capability_unavailable) still dominate, so an unconfigured/bare run stays honestly
  inconclusive.
- **Evidence redaction is seeded from the scan's known secrets.** The evidence store now
  masks each spec's `setup.canaries` + `secret_leakage` refs at rest, so a leaked engagement
  secret (a shape the built-in patterns don't know) no longer persists in clear.

### Fixed
- **Live multi-turn against Anthropic** sent an OpenAI-shaped `tool_calls` field the Messages
  API rejects (HTTP 400); the adapter now projects each turn to `{role, content}`, and the
  conversation engine omits empty `tool_calls`.
- **Evidence store false-positive** (`_assert_no_leak`): a numeric logprob float matched the
  phone/card shapes when the serialized JSON was scanned as flat text, refusing every live
  write. The guard now re-scans string leaves only, so real logprobs/usage/latency persist.
- **Mutator reversibility property test** scoped its inputs to exclude zero-width codepoints
  (the round-trip is undefined when the payload itself is zero-width).

### Added
- **Multi-turn attack engine** (`core/conversation.py`): pinned attacker ladders threaded as
  a conversation (prior assistant turns fed back as `messages`), the final turn scored, the
  full transcript persisted for evidence. Wired into the runner behind `_is_multi_turn`;
  reproducibility preserved because attacker turns are pinned, never LLM-generated.
- **DeepTeam gap analysis** (`docs/14`) and the native families it drove (coverage-map only,
  no dependency; Apache-2.0 attribution in each spec):
  - multi-turn jailbreaks, `JB-CRESCENDO/LINEAR/SEQUENTIAL/LIKERT/TREE` + `multi-turn` suite;
  - access-control, `AC-BFLA/BOLA/RBAC/SSRF/DEBUG`, `OUT-SHELLI`, `AG-TOOLMETA-POISON` +
    `access-control` suite;
  - OWASP-Agents-2026 agentic, `AG-GOAL-THEFT/RECURSIVE-HIJACK/IDENTITY-ABUSE/
    INTERAGENT-COMPROMISE/AUTONOMY-DRIFT` + `agentic-owasp2026` suite;
  - `JB-MULTILINGUAL-001`, `RECON-SYSTEM-001` + `obfuscation-enhancers` suite.
- **Six enhancer mutators** (18 built-ins total): `leetspeak`, `adversarial_poetry`,
  `math_problem`, `gray_box`, `linguistic_confusion`, `context_poisoning`; wired into the
  jailbreak specs' `mutations`. Battery is now 47 specs / 8 suites.
- Full spec package (`docs/00-12`, `REFERENCES.md`, ADRs, JSON schema, example specs).
- Zynap Specs-Driven methodology applied: `AGENTS.md`, six-stage build playbook, PITV harness,
  `specs/contracts/` (master index + unit contracts).
- Project scaffold: MIT `LICENSE`, `pyproject.toml`, community files.
- **MVP‑1 built (all 15 units)** via the six-stage PITV method: `shared` models/protocols,
  config/scope/policy + redactor, spec registry + linter, prompt mutators, scoring, target
  adapters (OpenAI/Anthropic/REST + MockTarget), evidence/run store, hardened evaluators
  (incl. data-leak: pii/secret-shape/authz/membership), fingerprint engine, execution engine
  (runner + planner + budgets), reporting (JSON/HTML/SARIF/JUnit), CLI (`dottore`), and the
  self-validation/CI harness.
- **T0 attack battery (20 specs)** across OWASP LLM01/02/05/06/07/10, incl. the data-leak and
  agentic-extortion (JadePuffer-class) families; `specs/pack.yaml` makes them discoverable
  out of the box.
- Merge gate green: full test suite, import-linter (4 contracts), ruff, mypy (116 modules),
  and an E2E `dottore run --quick` against MockTarget.

_Not yet pushed/tagged, pending `gh auth login`. See `docs/PROGRESS.md`._
