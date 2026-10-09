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
  raised-away. `tests/core/test_budgets.py`.
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
  interrupts resumes on purpose.)
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
ran leaves no trace in the finding list, so nothing downstream can reconstruct it.

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
most this tool writes, goes past it by a few replies' worth, which `float()` rounds). A run store
edited by hand is the exception, not closed here: the store's `is_amount` accepts an integer up to
`2**1024 - 2**970 - 1`, past the largest float, and a resume from it under a token ceiling above
1.8e308 adds tokens until `float()` raises (exit 1, the same on the base). The bound is
per figure: a campaign's
total can pass `2**53` after many large replies, and the store then rounds it (by 2 tokens in
5.4e16, measured), it does not fail. The `-sV` guardrail layer reads `moderation_latency_ms`
through `is_amount` for the same reason (`fingerprint` and `run -sV` exited 1 the same way; u09).
Not claimed: a figure up to `2**53` is believed, as a provider's bill is, so a target can still
report more than it used and halt the campaign on the token ceiling, or less and free its
reservation; that trust is unchanged. Nor does it cover a reply's `logprob`, which the adapter
reads (u04) and which still crashes `-sV` the same way (found by this clause's audit, open).
`tests/cli/test_usage_figures.py` (through the CLI, both directions),
`tests/core/test_usage_figures.py` (each shape at the boundary, the reading order, the floor),
`tests/shared/test_amounts.py`.

**A-59 A prior's attempts are checked against the plan without building the plan (added
2026-10-08).** Three places ask whether a started spec's stored attempts hold every planned attempt
(each mutation, `n` times): the halt path of a resume, which publishes a finished spec's prior
finding; the seeding gate, which scores a prior that holds its plan and says how much of it was sent
otherwise; and the multi-identity sweep, skipped when every attempt is stored. Each built the set of
`mutators x n` attempt ids and tested inclusion, so the work grew with `--runs`, not with what was
stored. With the `2**53` that `run` and the run store accept (A-55, u12), a resume of a run whose
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
`runs` instead of `runs - 1`.

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
