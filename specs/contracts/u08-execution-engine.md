# u08-execution-engine.md

> **RECONCILIATION (ADR-0006: authoritative).** This unit is the **sole owner of the
> plan-builder**: `core/planner.py :: build_plan(specs, fingerprint: ModelFingerprint | None,
> capabilities) -> TestPlan`. `TestPlan` is defined in `shared.models` (u00), not here: import
> it. Use the canonical `TestPlan` shape from ADR-0006 §3 (per-spec `mutators` +
> `baseline_resistance`; `adaptive`; `fingerprint_ref`; `budgets`). Adaptive planning is
> implied by `-sV` and `-A` (OD-5 as built: there is no `--adaptive` flag; `--deep` also sets
> adaptive mode, which orders nothing without a fingerprint). u09 does not build plans.

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. This is the **orchestrator** -
the HARD unit that wires the whole middle tier into a campaign. Read `AGENTS.md` + `docs/01
§4-§5` + `docs/10` + `docs/08` + `shared/` before implementing.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/core/`: `runner.py` (campaign orchestration), `planner.py`
  (fingerprint-adaptive `TestPlan`), `budgets.py` (hard token/request/time caps),
  `suite.py` (suite→spec resolution), `execute.py` (per-attempt send + retry/rate-limit/
  timeout), `reproduce.py` (N-run aggregation), `__init__.py`.
- **MUST NOT touch:** `shared/`, `adapters/`, `evaluators/`, `scoring/`, `mutators/`,
  `policy/`, `store/`, `fingerprint/`, `reporting/`, `cli/`, any spec YAML or `schemas/`.
  Consumes all of these through **interfaces only** (injected at the composition root, u12).

## §2 Intended behavior
Drive `docs/01 §4` for a whole campaign: resolve a suite to a spec set, gate each (target,
spec, endpoint) tuple through the Policy Engine, capability-gate against the target's
`Capabilities`, mutate → execute N times with pinned sampling + retry/rate-limit/timeout,
hand attempts to the Evaluator pipeline, aggregate reproducibility, and persist attempts
(Evidence) + findings (Run): emitting nothing itself (reporting is u11). When `-sV` adaptive
mode is on, first consume a `ModelFingerprint` (u09) and emit an explicit reviewable
`TestPlan` (which specs, why, which skipped and why: **no silent caps**, `docs/10 §3`).
Enforce **hard budgets** (tokens/requests/wall-clock, adaptive-attempts per `docs/08 §1`);
budget breach ⇒ stop-&-escalate, not a masked partial. Checkpoint by `run_id` so a campaign
resumes, never restarts from zero (`AGENTS.md §5`). Reproducibility is the product thesis:
`repro = successful_attacks / N`, raw per-attempt outcomes stored so a reader recomputes it.

## §3 Dependencies & interface contracts
Depends on u00,u01,u02,u04,u05,u06,u07: all via `shared.protocols` / `shared.models`, never
concretes:
- `TargetAdapter` (u04): `send(ModelRequest)->ModelResponse`, `capabilities()->Capabilities`.
- `Evaluator` (u06) pipeline + `combine` (spec `evaluator_logic`; as built the runner applies its
  own fixed rule and does not read the field, OD-19); `Mutator` (u05); `RiskScorer`
  (u07); `EvidenceStore.put` + `RunStore.save_run/save_finding` (u10).
- Policy Engine (u01): scope/allowlist/policy-pack gate + `redactor`. Spec Registry (u02):
  suite resolution + loaded `AttackSpec`s. Fingerprint (u09) supplies `ModelFingerprint` for
  the planner (injected: planner does not run the fingerprint battery itself).
- Consumes `shared.models.{AttackSpec, Target, Capabilities, TestRun, Attempt, Verdict,
  Finding, RiskScore, ModelFingerprint}`; produces `TestPlan` (new shared model, §6) + `TestRun`.

## §4 Known constraints: KEEP / DECIDE
- KEEP: policy gate is **first** and mandatory (`docs/01 §4.1`); refuse-fail-closed →
  `blocked_by_policy`. Missing capability ⇒ `inconclusive: capability_unavailable`, never a pass.
  (As built the capability filter comes first: `build_plan` skips a spec whose `requires` the
  target does not declare, and only the selected specs reach `PolicyEngine.check` in
  `_run_spec`; the CLI preview in `resolve_target_plans` uses the same order. Nothing is sent
  either way, but a spec that is both capability-gated and policy-gated reports
  `capability_unavailable`, not `blocked_by_policy`, on a target without the capability.)
- KEEP: pin sampling (temperature/top_p/seed-if-supported) per attempt; record request/response
  ids + full sampling config; seed variants by `(spec.id, variant.name)` (`docs/01 §3-§5`).
  (Since 2026-10-09, OD-39 and u12 A-66: `CampaignRunner(sampling_defaults=...)` takes what of
  the target file's `sampling_defaults` the adapter sends, as the composition root passes it, and
  `spec_sampling` fills each field the spec leaves unset from it, before temperature 0 for a spec
  that declares no `sampling`; `CampaignRunner(sent_sampling=...)` is the adapter's own rule for
  what of it goes out (Anthropic: no `seed`, no `top_p` beside a temperature), applied before the
  attempt is recorded, so the record is what was sent. The single-turn send, the multi-turn
  conversation and the identity sweep all take both. Since u12 A-68 the rule can drop the
  temperature and the top_p of a target that takes no sampling, and every stored attempt lists
  what its spec asked for and did not go out under `request.metadata.sampling_not_sent`
  (`SAMPLING_NOT_SENT`, `unsent_fields`).)
- KEEP: **env vs product failure** (`AGENTS.md §2`): rate-limit/timeout/5xx ⇒ retry w/ backoff
  then skip-as-`inconclusive`; a real exploited response ⇒ `fail`. Never mask a defect as a flake.
- KEEP: budgets are hard ceilings; adaptive/escalation attempts count against them; on breach
  → circuit-breaker halt + partial `TestRun` marked `budget_exhausted` (no silent truncation).
- KEEP: asyncio concurrency (bounded semaphore); no Celery/RQ in MVP‑1 (`docs/00 §8`).
- DECIDE (OD-5): adaptive planner default-ON with `-sV`, or opt-in? Ship `-sV`=adaptive,
  `--no-adaptive`=full suite (`docs/10 §3`); default-on-with-`-sV` proposed, human sign-off.
  Resolved as built (`00-INDEX.md` OD-5): `-sV` and `-A` imply adaptive ordering; neither
  `--adaptive` nor `--no-adaptive` exists on the CLI; the pass-through is the default without a
  fingerprint (`build_plan(adaptive=False)`), and adaptive only reorders mutators.

## §5 Implementation plan (each step its own commit, green before next)
1. `budgets.py`: `BudgetLedger` (tokens/requests/wall-clock/attempts), thread-safe debit, breach
   → `BudgetExhausted`. Unit-tested in isolation.
2. `suite.py`: resolve suite id (`owasp:llm`, presets `docs/08 §6`) → ordered `AttackSpec` set.
3. `planner.py`: `build_plan(specs, fingerprint|None, capabilities)` → `TestPlan`: capability
   filter, family-effective mutator weighting, baseline expectations, explicit skip reasons
   (`docs/10 §3`); `--no-adaptive` = pass-through (benchmark parity). As built the planner
   orders mutators by carrier comprehension only; the family weighting and baseline
   expectations are not implemented (OD-17), and there is no `--no-adaptive` flag.
4. `execute.py`: single-attempt send with retry/backoff/rate-limit/timeout; classify env-error
   vs product-signal; record `Attempt` (masked via redactor before evidence write).
5. `reproduce.py`: run one (spec,variant) N times, aggregate `repro` + per-attempt raw.
6. `runner.py`: the loop: policy-gate → setup → mutate → reproduce → evaluate/combine → score
   → persist; checkpoint/resume by `run_id`; bounded-concurrency scheduler + circuit-breaker.
   (As built: plan-time capability filter → policy gate → mutation checks (an unregistered
   mutator or a parameter the mutator does not accept sends nothing for that spec) → mutate →
   reproduce → evaluate/combine → score → persist. Setup is materialized in-band for a
   `type: model` target only, OD-18 option A (ADR-0009): memory seed as saved memory after the
   system prompt, documents
   before the first attacker turn, tool definitions on every send, and a tool loop of at most 4
   rounds per turn inside the conversation engine, each round a send under the budget and the
   pacer; the final turn's scored text is the text of all its rounds; the attempt's request
   records `setup_delivery`, `tool_rounds` and the tools. A round is answered only when every
   call names a declared tool, there are at most 16 and their arguments fit 64 KB. An adapter
   that cannot carry tool definitions, or that sends no system prompt for a memory seed, makes
   such a spec `inconclusive` (`setup_not_delivered`) with no send. A
   spec whose untrusted content is only a tool's result, judged by no trace evaluator, whose model
   called none of those tools and whose evaluators did not fail, is `inconclusive`
   (`setup_not_reached`), and the summary does not count it as exercised. Against any other
   target type, OD-18 option B: a spec with setup is `inconclusive` (`setup_not_seeded`) before
   the scene, with no send, when `setup_delivery.seeding_gap` names a reason (not declared in
   `seeded_setup.specs`; a per-run canary in the scene and no `run_token`; two of its scene tools
   under one deployment name; asked of the spec before its canary is bound), or
   `setup_delivery.trace_gap` (a trace spec through an adapter without `returns_tool_calls`)
   does, unless the adapter is an offline mock (`offline_mock`). A sent one binds `{{run_id}}` to
   `<run_token>-<spec id>` when its canary has to be seeded, records `setup_delivery: seeded`
   and `seeded_tools`,
   and its response is renamed through `seeded_setup.tools` (per spec) before the evaluators,
   which receive `seeded_setup.granted_tools` in their context; a seeded tool-carrier spec whose
   reply shows no call to that tool is `setup_not_reached`. On resume, a spec the gate stops
   that the stored run already sent is scored from its attempts when it holds all of them, and
   otherwise kept as evidence, inconclusive, with nothing more sent.)

## §6 Data/wire shapes
`TestPlan = {plan_ref: str, target_id: str, adaptive: bool, fingerprint_ref: str|None,
selected: [{spec_id, reason, mutators: [str], baseline_resistance: float|None}],
# NOTE (2026-09-23, OD-17): `baseline_resistance` is dead at both ends today. No fingerprint
# layer writes the `guardrails` key it is read from, and nothing in src/ reads the field it is
# written to. It is in the shape, and in this contract, as if it flowed. Decide before a
# reader is written against it.
skipped: [{spec_id, reason}], budgets: {max_tokens, max_requests, max_wall_s, max_attempts}}`
- reviewable, persisted with the run (validates vs the test-plan schema, which is generated on
  demand by `dottore schema export --name test-plan` and not committed under `schemas/`,
  OD-14). (As built the `TestPlan` is not persisted: it lives in the `CampaignResult` of one
  invocation. What the run store keeps is the integrity context: spec digests, target digest,
  judge digest, run count and planning mode.)
`Attempt` carries `{sampling: {temperature, top_p, seed?}, provider_request_id,
provider_response_id, outcome, env_error?}`. `TestRun.status ∈ {complete, budget_exhausted,
parked}`; `repro` per finding = `successful_attacks / N`. Nothing emitted here: reporters (u11)
read the persisted `TestRun`/`Finding`s. Redactor masks before any evidence/store write.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/core -q` green; coverage ≥ 90% for `src/ildottore/core/` (HARD unit, above the
  85% floor).
- **Determinism replay** (`docs/07`, `docs/01 §5`): same suite + same target (mock, u03) + same
  seed ⇒ **identical finding set** and identical `TestPlan`; `tests/core/test_determinism.py`
  asserts byte-stable plan + finding ids across two runs.
- **Budget gates:** property tests (Hypothesis) prove no run exceeds any of tokens/requests/
  wall-clock/attempts; breach ⇒ `TestRun.status == budget_exhausted` with partial persisted, not
  raised-away. `tests/core/test_budgets.py`. (Amended 2026-10-07: the partial includes every
  reply the target gave. `reproduce` and `reproduce_conversation` fill the caller's list as each
  attempt completes, so the answers a batch had when a debit was refused, a product error was
  raised, or a reply's own usage crossed the token ceiling (`ReplyOverBudget`, which carries it,
  through a conversation too when that reply was its last; named so the redactor keeps it, u01
  A-63) are evaluated and stored before the halt goes on. They were dropped with the exception,
  and the resume sent them and paid for them again. An evaluator whose request the ceiling
  refuses (the judge) is recorded as not consulted: a deterministic fail decides without it
  (OD-19) and is stored, its reasoning naming the evaluator not consulted (only the aggregate is
  stored, and it was silent: delta audit); otherwise the reply is stored without a verdict. If
  that was the campaign's last
  attempt, the campaign is complete: every verdict is decided and nothing more is sent. A product error sets the campaign's abort before the
  batch's replies are evaluated, so no spec starts while they are judged, and an evaluator's own
  error during that evaluation is quoted in the halt's reason, not swallowed by it. A conversation
  the halt stops mid-way has no reply to score and is not stored; its turns are in the spend, as
  are an identity sweep's, whose replies a finished run does not store either. A Ctrl-C still
  drops the batch in flight. `tests/core/test_halt_keeps_answers.py`.)
- **Policy gate:** out-of-allowlist / policy-forbidden spec ⇒ `blocked_by_policy` attempt, zero
  adapter `send` calls (asserted via mock adapter call-count). `tests/core/test_policy_gate.py`.
- **Capability gating:** target without `tools`/`rag`/`multi_identity`/`logprobs` ⇒
  `inconclusive: capability_unavailable` for the gated specs, never `pass`.
- **Adaptive plan:** given a fixture `ModelFingerprint`, `planner` drops inapplicable specs and
  logs every skip with a reason; `--no-adaptive` runs the full set. Golden `TestPlan` fixture in
  `tests/fixtures/plans/`. (As built: the planner drops a spec only for a capability the target
  file does not declare, never because of the fingerprint, and records the reason; a
  fingerprint only reorders each spec's mutators by carrier comprehension. There is no
  `--no-adaptive` flag: the non-adaptive pass-through, `build_plan(adaptive=False)`, is what a
  run without `-sV`, `-A` or `--deep` gets, and `--deep` without `-sV` is adaptive with nothing
  to order by.)
- **Env-vs-product:** injected rate-limit/timeout ⇒ retry-then-`inconclusive`; injected exploited
  response ⇒ `fail`. `tests/core/test_retry_classification.py`.
- **Resume:** kill mid-run, resume by `run_id` ⇒ no duplicate attempts, no re-sent completed
  specs. `tests/core/test_resume.py`. (As built since 2026-10-04, F11: an attempt that ended in an
  environment error is not complete and is sent again under its id; the finding scores one
  attempt per id, the answered one, and cites every artifact. `tests/test_f11_resume_resends.py`
  interrupts resumes on purpose. Since 2026-10-07 a reply stored without a verdict is not
  complete either: it is sent again, and of one id's artifacts the scored one is answered and
  judged, else any with a verdict (an environment error's inconclusive), else a bare reply, so
  a failed re-send is never scored as if that attempt had not been sent (pre-commit audit: it
  published a PASS from the one verdict left). A prior holding every planned id is a finished
  spec only when each has a verdict (`_settled_attempt_ids`). A run that spent requests and
  stored no attempt resumes from nothing, u12 A-24.)
- `ruff check`, `ruff format --check`, `mypy src/ildottore/core` clean; `lint-imports` green
  (core imports interfaces only: asserted).

**A-4 The wall budget MUST measure time (added 2026-09-22).** The composition root injects a
deterministic counter as the runner's clock so OFFLINE evidence records a byte-stable
`latency_ms` (a live route gets `time.monotonic` since 2026-10-04: the counter made a 1 ms
loopback reply read 2000.0 ms). That counter was also handed to the budget ledger, so `max_wall_s` counted clock
**reads**: 1800 "seconds" was fewer reads than a 72-spec run performs, the default battery
halted after 45 specs on every invocation, adding a telemetry read anywhere changed which specs
were scanned, and a **live** run had no time bound at all. The ledger takes a real monotonic
clock; the evidence keeps the deterministic one; a test asserts the two are not the same object.

**A-5 Every send passes the rate gate, asserted at the sink.** `--rate` is enforced for
single-turn **and** multi-turn paths and counts retries. The limiter reached
`reproduce_conversation` and was not forwarded one hop, so 42% of a full battery's requests ran
unpaced at 19x the authorized rate while the flag looked wired. A cross-cutting parameter is
asserted by counting calls at the point of use, never by reading the call site. Amended
2026-10-03 (audit F-4, F10): the count is now taken through `CampaignRunner.run` for single-turn,
multi-turn and identity sends, not at two leaf functions, and a campaign's adapters retry
nothing themselves, so the runner's retries are the only ones and each passes the gate
(`tests/test_audit_block4_budget.py`).

**A-6 A campaign that did not finish says why.** `CampaignResult` carries the breached axis,
its ceiling and how many specs never ran. A bare state word is not a reason: a spec that never
ran leaves no trace in the finding list, so nothing downstream can reconstruct it. Amended
2026-10-07: **the reason's figures survive the redactor that masks it.** The terminal and every
report mask the reason, and a bare figure of nine characters or more is a phone number to the
redactor (a Luhn-valid one of 13 to 19 digits, a card), so every stop on the default 1,800 s
wall ceiling printed `attempted «REDACTED:phone»`, as did a target reporting 2**53 tokens. The
figures come from `BudgetExhausted.figures` (digit groups, seconds to three decimals, a count
from 10**18 up as a magnitude), never formatted at the call site, and a shortened figure is
rounded away from the ceiling (the attempted figure up, the limit down), so a crossed ceiling
never reads as an equal one; the ledger hands over the elapsed time unrounded, or
`round(elapsed, 6)` puts it back on the ceiling first. The redactor is not relaxed for the
reason and the terminal line is tested to mask it (removing that mask left the suite green
until the pre-commit audit). The one value the grouping lets through on purpose is the figure
itself: a target can report a card-shaped usage figure, and it prints grouped, because showing
it is the point.
`tests/core/test_halt_figures.py` (property tests over every count below 10**18, over elapsed
times and over the rounding direction) and `tests/cli/test_halt_figures_cli.py`.

**A-36 A figure the target reports is checked where it is read (added 2026-10-07).** A reply's
`usage` is the target's JSON, and a JSON number has no bound. A 400-digit `prompt_tokens` was
trued into the ledger and `dottore run` exited 1 on `OverflowError` when the store persisted the
spend through `float()`, with no report written; a figure past `2**53` was believed and halted
the campaign on the token ceiling after one reply. `_reported_total` now reads a figure only
when `shared.amounts.is_count` holds: a JSON integer from 0 to `2**53`, past which a float no
longer holds every integer (the spend is persisted as a float), and far beyond any one bill. An
unreadable figure
is skipped as an absent one, so the next shape is read; a sum past `2**53` is no usage; with no
readable shape the reservation stands. A prompt-cache figure is summed only into a pair, and one
that is there and unreadable makes the pair a floor: trued up to, never down. (Before, one that
was not a non-negative integer was read as 0 and trued the reservation down past tokens the reply
says it billed; read as no usage, the first version of this clause, it kept a 513-token
reservation below a pair of 100,005: pre-commit audit.) The
ledger takes no guard of its own: nothing a reply or this tool hands it can grow past what
`float()` converts (a reservation is bounded by `MAX_SAMPLING_TOKENS` and the request's own text,
a clamp by the ceiling, a reply's figure by `is_count`, and a resume from the largest float, the
most this tool wrote before #89, goes past it by a few replies' worth, which `float()` rounds). A
run store edited by hand was the exception: the store's `is_amount` accepts an integer up to
`2**1024 - 2**970 - 1`, past the largest float, and a resume from it under a token ceiling above
1.8e308 added tokens until `float()` raised (exit 1, the same on the base). The bound is per
figure: a campaign's total can pass `2**53`, and the store then rounds it (by 2 tokens in 5.4e16,
measured before #89), it does not fail. Merge note (#89, A-55 in u12): every token ceiling is now
at most `2**53`, so a total passes it only by what replies sent together add once it is crossed
(two replies of `2**53 - 1` at `--concurrency 6`, measured after the merge), and the hand-edited
store, resumed under `2**53`, halts on the ceiling with exit 3 and sends nothing (measured after
the merge): that exception is closed. One reply of `2**53` fills the largest ceiling, which is how
the CLI test below believes it. The `-sV` guardrail layer reads `moderation_latency_ms`
through `is_amount` for the same reason (`fingerprint` and `run -sV` exited 1 the same way; u09).
Not claimed: a figure up to `2**53` is believed, as a provider's bill is, so a target can still
report more than it used and halt the campaign on the token ceiling, or less and free its
reservation; that trust is unchanged. Nor does it cover a reply's `logprob`, which the adapter
reads: u04 A-39 does (found by this clause's audit, fixed by PR #74).
`tests/cli/test_usage_figures.py` (through the CLI, both directions),
`tests/core/test_usage_figures.py` (each shape at the boundary, the reading order, the floor),
`tests/shared/test_amounts.py`.

**A-34 An evaluator a spec declares is fed where the target can feed it, and one that only
corroborates cannot decide by its absence (added 2026-10-07).** `EMB-XTENANT-RETRIEVAL-001`
requires `rag` and declares `authz_leak` "for cross-identity corroboration when >=2 identities
are scoped". The identity sweep ran only for a spec that required `multi_identity`, so that
`authz_leak` never had two identities to compare, and its `capability_unavailable` held the spec
`inconclusive` on every target unless a deterministic check failed, a secure reply included. The
golden harness drives only `evaluators[0]`, so lint never saw it. Now `sweeps_identities` sends
the attack as each scope identity for a spec that requires `multi_identity` and, when the target
declares `multi_identity`, for one that declares `authz_leak`; never over an in-band scene
(OD-18 A), which hands every identity the same scene, another tenant's document included. With
no sweep behind it, an `authz_leak` on a spec that does not require two identities is set aside
and named in the verdict; after a sweep that got fewer than two answers it is kept (the identity
that answered may have shown a leak), and alone it still decides. The estimate prices the
sweep, one send per scope identity (two or more) on a live route, from the same predicate,
which it had never done for `DL-XTENANT-001` either, and `--estimate --resume` does not count it
for a spec the runner will not sweep again. Two pre-commit audit findings shaped the last three
rules: a half-failed sweep set the check aside and passed a leak it had seen, and an in-band
sweep read the scanner's own context as a cross-tenant leak.
`tests/core/test_authz_leak_corroboration.py` asserts each rule against the real specs, the
sends counted at the identities' adapters, the resume figure and the dry run's printed figure.
Merged after A-59: that resume figure is a fourth place asking whether a spec's stored attempts
hold its plan, and it counts them with `planned_attempts_held` as the runner does (it built the
`mutators x runs` ids, which grows without end at the `2**53` a run accepts); the room check of the
`-sV` refusals (u12 A-48), which prices the rest as `--estimate --resume` does, reads the same
figure, so it no longer prices a finished spec's sweep again. A test pins both.

**A-59 A prior's attempts are checked against the plan without building the plan (added
2026-10-08).** Three places (a fourth, the `--estimate --resume` figure, A-34) ask whether a
started spec's stored attempts hold every planned attempt (each mutation, `n` times): the halt path
of a resume, which publishes a finished spec's prior finding; the seeding gate, which scores a prior
that holds its plan and says how much of it was sent otherwise; and the multi-identity sweep,
skipped when every attempt is stored. Each built the set of `mutators x n` attempt ids and tested
inclusion, so the work grew with `--runs`, not with what was stored. With the `2**53` that `run`
and the run store accept (A-55, u12), a resume of a run whose
count was edited to 10^7 took 3.5 s and 1.3 GiB with one spec started, 16.3 s and 3.7 GiB with two,
and one of `2**53 + 1` was still growing at 3.7 GB after 4.5 minutes on `2f6201a` (OD-32, decided by
the owner on 2026-10-08: the runner counts what is stored, and `--runs` keeps its bound). So
`core/reproduce.planned_attempts_held` counts the planned attempts in a stored set by reading it
once, accepting an id only in the exact form `attempt_id_for` writes (this spec's prefix, a planned
mutation, an index of ASCII digits without a leading zero inside the plan), so a corrupt store's id
is ignored, never fatal. An index wider than the plan's last one is passed over before it is
converted: 10,000 stored indexes of 4,300 digits cost 4 s per check, and now 0.05 s. A run count
the interpreter cannot write out (past its digit limit; only a library caller can pass one, as
`run` and the run store stop at `2**53`) takes that limit as the widest index, keeps that cost, and
does not count a longer index, which `attempt_id_for` could not write either. The three places
compare the count with the plan's size, `len(set(mutators)) x n` (the sweep only when something is
planned, as before; a negative `n`, which only a library caller can pass, plans nothing, as
before). A set smaller than the plan is answered without reading it, since the sweep's is the
run-wide set of every spec. The gate's message prints both counts with thousands separators, which
also stops the report redactor masking a count of 9 digits or more as a phone number, as it did on
`76de469`. The work follows the stored attempts: a resume of a stored count of 10^6, 10^7, 10^8 or
`2**53` took 0.7 to 1.0 s and 71 MiB, with one spec started or with two. The pre-commit audit found
no verdict that changed on 200 combinations of specs, `n` and ceilings, nor a count that differed
from the set's on 60,000 inputs. The delta audits found no verdict that changed from the CLI; what
they found is fixed here: the negative `n`, the cost of a wide index, the widest index one digit
off at 10, 100 or 1,000 (untested until then), a test that read the environment's digit limit, and
wording that claimed more than the counters see. Checked by `tests/core/test_planned_attempts.py`
(29 tests, 19 failing on `76de469`: 15 because the count is not there, 2 because the runner's
predicate is not, and 2 because the runner built more than 10,000 ids, counted and stopped there
instead of growing; the 10 that pass pin what is unchanged: a gated prior holding its plan, with a
mutation listed twice too, scored as before, and the sweep skipped only when every attempt of this
spec is stored, not another spec's, and run when nothing is planned) and by
`tests/cli/test_resume_integrity.py`, where a halted run resumed with the largest stored count
builds no planned id (failing on `76de469` the same way). The counters watch `attempt_id_for` under
the runner's name and in its module, so a plan built another way (an f-string, an alias) is not
counted there; the equivalence and verdict tests still pin the answer. Every targeted mutant dies
but four equivalent ones, which give the same counts: dropping the early answer (it only costs the
read), dropping the `runs <= 0` return or making it `runs < 0`, and reading the widest index from
`runs` instead of `runs - 1`. With the halted-run rule (u12 A-24, merged after this clause), the
set the halt path and the seeding gate count is the stored attempts that have a verdict
(`_settled_attempt_ids`), and the sweep's is the set a resume keeps, which leaves out a reply
stored without one; the gate's message still counts every stored attempt as sent. The priors of
`tests/core/test_planned_attempts.py` carry a verdict on each reply, as the runner stores them,
and one more test there pins a prior holding its plan with one reply not judged: kept, not scored,
and counted without building the plan.

**A-69 An attack prompt the provider's own input filter refused is blocked, not a halt (added
2026-10-10, OD-41, ADR-0011).** Azure OpenAI's prompt filter answers a prompt it blocks with HTTP
400 and the error code `content_filter`; the adapters read every non-retryable 4xx as a product
error, and the runner stopped the campaign on the first one. Against a loopback stub that answers
that body to prompts holding "instructions for" or "developer mode", `run --spec
GUARD-INPUT-EVASION-001 --spec PI-DIRECT-001 --runs 2` exited 3 after one request on `92c7b11`
("aborted on AdapterStatusError: azure: non-retryable HTTP 400 from /v1/chat/completions; 2 of 2
specs never ran or did not finish"). The owner decided on 2026-10-10 at 17:33 that such an attempt
is recorded as blocked by the provider's filter and the campaign goes on. The criterion:
- recognised only in a shape a provider documents, by the adapter that reads the bytes (u04): an
  HTTP 400 whose `error.code` is exactly `content_filter` (Azure OpenAI; any adapter built on
  `BaseAdapter`, so openai, anthropic and rest; not MCP, which sends no prompt), and a success body
  with no text at a REST template's path whose `promptFeedback.blockReason` is `SAFETY`, `OTHER`,
  `BLOCKLIST` or `PROHIBITED_CONTENT` (Gemini). Each raises `ProviderFilterBlock`, an
  `AdapterProductError` with the status, the provider's code and the marker
  `blocked_by_provider_filter = True`; every other 4xx stays an `AdapterStatusError` and stops the
  campaign exactly as before (another code at 400, the Azure body at 403 or 422, `content_filtered`
  at 400, a body that is not JSON);
- `execute_attempt` reads the marker before the environment question: the attempt has no
  `response`, its `error` is `ProviderFilterBlock: <message> [blocked_by_provider_filter]`, it is
  not retried (the same prompt is refused the same way), the send stays on the request ledger and
  its token reservation is released (no completion was produced), and the result is
  `filter_blocked`; a conversation stops at the turn the filter refused, blocked the same way;
- the runner's verdict is `inconclusive` with `inconclusive_reason: blocked_by_provider_filter`
  and confidence 0, without an evaluator (ADR-0011): not the model's refusal, not an exploit. The
  spec-level rule is the one an environment error follows (F8): any `fail` is a `fail` (needing
  review unless a variant failed on every attempt, which a blocked attempt in it prevents); a
  `pass` needs a strict majority of the attempts to have passed; otherwise `inconclusive`. A
  spec whose every attempt was blocked is therefore `inconclusive`, Info, never a pass of the
  model, and not exercised (u11). Reproducibility counts a blocked attempt in `N` and never as a
  success (`scoring.risk` requires no error), and `--fail-on`, which gates only a `fail`, neither
  trips nor clears on one. The finding's reasoning adds `; <k>/<n> blocked by the provider's input
  filter before the model saw them` when `k` is not 0;
- a resume keeps a blocked attempt (`_completed_attempt_ids`, by the verdict's reason or, without
  a verdict, by the error's mark) and does not send it again; `resume_progress` counts it as kept,
  and so does `--estimate --resume`;
- the judge path is unchanged: a judge request its provider's filter refuses raises in the judge's
  adapter and the evaluator reads it, as any `AdapterError`, as an unusable judge
  (`capability_unavailable`), which keeps the attempt `inconclusive` unless a deterministic
  evaluator fails; the attack prompt reached the model, so the attempt is not
  `blocked_by_provider_filter`, and the campaign goes on, as on `92c7b11`;
- the identity sweep, which sends through the identities' adapters directly, drops an identity
  whose send raised, this one included, as before.
With the stub: exit 0 after 14 attack requests, 8 of them blocked (both identity attempts of
`GUARD-INPUT-EVASION-001` and the 6 of `PI-DIRECT-001`), and 12 judge requests; `GUARD` passes
(6 of 8 attempts reached the model and held), `PI-DIRECT-001` is inconclusive, 6 of 6 blocked.
Checked by `tests/core/test_provider_filter_block.py` (9 tests: one send, the ledger, a true
marker only, a conversation, the four spec-level cases, a resume and an attempt stored without a
verdict), `tests/adapters/test_provider_filter_block.py` (45, u04) and
`tests/cli/test_provider_filter_campaign.py` (7, through the real CLI: the campaign, a run whose
every attempt was blocked is complete and not unreachable, three other 4xx that still stop it, a
resume halted by `--budget-requests 5` that counts the two blocked sends, keeps them and says so,
`dottore replay`, and the judge). The first two files do not collect on `92c7b11` (no
`ProviderFilterBlock`); in the third, 4 fail there and the 3 other-4xx cases pass, pinning what
did not change; the judge test fails there only on the summary key it reads. Not re-run against a
live Azure endpoint.

## §8 Out of scope / forbidden
- MUST NOT import adapter/evaluator/scorer/store **concretes**: interfaces only; composition is
  u12. `lint-imports` enforces.
- MUST NOT run the fingerprint probe battery (that's u09): only consume a `ModelFingerprint`.
- MUST NOT implement scoring/banding (u07), evaluator logic (u06), report rendering (u11),
  mutation transforms (u05), or the spec schema (u02/u13).
- MUST NOT perform real destructive actions or exfiltration; tools are mocked/dry-run, canaries
  planted; MUST NOT print/persist raw secrets/PII (redactor only). MUST NOT commit/push.
- Not its call: OD-5 adaptive default · judge model (OD-3) · evidence encryption (OD-4).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-5** adaptive planner default-ON with `-sV` vs opt-in (proposed: `-sV`⇒adaptive on,
  `--no-adaptive` escape hatch for benchmark parity). Resolved as built: `-sV`/`-A` imply
  adaptive ordering, no flag either way (`00-INDEX.md`).
- Default N for reproducibility (propose 5, per `docs/01 §5`) and default per-campaign hard
  budgets (tokens/requests/wall-clock): surfaced in `config.py` (u01), confirmed by human.
- Concurrency degree (bounded semaphore default) vs provider rate-limit headers: propose adaptive
  from observed 429s, capped by config.
- **OD-41** (2026-10-10): a provider's input filter that refuses an attack prompt before the
  model sees it (Azure OpenAI's HTTP 400 `content_filter`) stopped the whole campaign, exit 3 after
  one request. **Decided by the owner, 2026-10-10 17:33:** the attempt is recorded as blocked by
  the provider's filter and the campaign goes on. Built as §7 A-69: `inconclusive:
  blocked_by_provider_filter` (ADR-0011), scored as an attempt without a reply, not retried, kept
  by a resume, counted in every report. Left open, not part of the decision: a Bedrock guardrail
  intervention (an HTTP 200 whose output is the guardrail's message, read as a reply), OpenAI's
  `invalid_prompt` 400 (in forum reports, not in its error-code reference) and Gemini's
  OpenAI-compatible endpoint, for want of a documented shape; and the `-sV` pass, which still stops
  on such a refusal of any probe but the benign one (u09 A-67). Owner: human.
