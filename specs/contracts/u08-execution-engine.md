# u08-execution-engine.md

> **RECONCILIATION (ADR-0006: authoritative).** This unit is the **sole owner of the
> plan-builder**: `core/planner.py :: build_plan(specs, fingerprint: ModelFingerprint | None,
> capabilities) -> TestPlan`. `TestPlan` is defined in `shared.models` (u00), not here: import
> it. Use the canonical `TestPlan` shape from ADR-0006 §3 (per-spec `mutators` +
> `baseline_resistance`; `adaptive`; `fingerprint_ref`; `budgets`). Adaptive planning is
> **opt-in** in MVP-1 (`--adaptive`); `-sV` only fingerprints (OD-5). u09 does not build plans.

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
- `Evaluator` (u06) pipeline + `combine` (spec `evaluator_logic`); `Mutator` (u05); `RiskScorer`
  (u07); `EvidenceStore.put` + `RunStore.save_run/save_finding` (u10).
- Policy Engine (u01): scope/allowlist/policy-pack gate + `redactor`. Spec Registry (u02):
  suite resolution + loaded `AttackSpec`s. Fingerprint (u09) supplies `ModelFingerprint` for
  the planner (injected: planner does not run the fingerprint battery itself).
- Consumes `shared.models.{AttackSpec, Target, Capabilities, TestRun, Attempt, Verdict,
  Finding, RiskScore, ModelFingerprint}`; produces `TestPlan` (new shared model, §6) + `TestRun`.

## §4 Known constraints: KEEP / DECIDE
- KEEP: policy gate is **first** and mandatory (`docs/01 §4.1`); refuse-fail-closed →
  `blocked_by_policy`. Missing capability ⇒ `inconclusive: capability_unavailable`, never a pass.
- KEEP: pin sampling (temperature/top_p/seed-if-supported) per attempt; record request/response
  ids + full sampling config; seed variants by `(spec.id, variant.name)` (`docs/01 §3-§5`).
- KEEP: **env vs product failure** (`AGENTS.md §2`): rate-limit/timeout/5xx ⇒ retry w/ backoff
  then skip-as-`inconclusive`; a real exploited response ⇒ `fail`. Never mask a defect as a flake.
- KEEP: budgets are hard ceilings; adaptive/escalation attempts count against them; on breach
  → circuit-breaker halt + partial `TestRun` marked `budget_exhausted` (no silent truncation).
- KEEP: asyncio concurrency (bounded semaphore); no Celery/RQ in MVP‑1 (`docs/00 §8`).
- DECIDE (OD-5): adaptive planner default-ON with `-sV`, or opt-in? Ship `-sV`=adaptive,
  `--no-adaptive`=full suite (`docs/10 §3`); default-on-with-`-sV` proposed, human sign-off.

## §5 Implementation plan (each step its own commit, green before next)
1. `budgets.py`: `BudgetLedger` (tokens/requests/wall-clock/attempts), thread-safe debit, breach
   → `BudgetExhausted`. Unit-tested in isolation.
2. `suite.py`: resolve suite id (`owasp:llm`, presets `docs/08 §6`) → ordered `AttackSpec` set.
3. `planner.py`: `build_plan(specs, fingerprint|None, capabilities)` → `TestPlan`: capability
   filter, family-effective mutator weighting, baseline expectations, explicit skip reasons
   (`docs/10 §3`); `--no-adaptive` = pass-through (benchmark parity).
4. `execute.py`: single-attempt send with retry/backoff/rate-limit/timeout; classify env-error
   vs product-signal; record `Attempt` (masked via redactor before evidence write).
5. `reproduce.py`: run one (spec,variant) N times, aggregate `repro` + per-attempt raw.
6. `runner.py`: the loop: policy-gate → setup → mutate → reproduce → evaluate/combine → score
   → persist; checkpoint/resume by `run_id`; bounded-concurrency scheduler + circuit-breaker.

## §6 Data/wire shapes
`TestPlan = {plan_ref: str, target_id: str, adaptive: bool, fingerprint_ref: str|None,
selected: [{spec_id, reason, mutators: [str], baseline_resistance: float|None}],
skipped: [{spec_id, reason}], budgets: {max_tokens, max_requests, max_wall_s, max_attempts}}`
- reviewable, persisted with the run (validates vs `schemas/test-plan.schema.json`).
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
  `tests/fixtures/plans/`.
- **Env-vs-product:** injected rate-limit/timeout ⇒ retry-then-`inconclusive`; injected exploited
  response ⇒ `fail`. `tests/core/test_retry_classification.py`.
- **Resume:** kill mid-run, resume by `run_id` ⇒ no duplicate attempts, no re-sent completed
  specs. `tests/core/test_resume.py`.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/core` clean; `lint-imports` green
  (core imports interfaces only: asserted).

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
  `--no-adaptive` escape hatch for benchmark parity).
- Default N for reproducibility (propose 5, per `docs/01 §5`) and default per-campaign hard
  budgets (tokens/requests/wall-clock): surfaced in `config.py` (u01), confirmed by human.
- Concurrency degree (bounded semaphore default) vs provider rate-limit headers: propose adaptive
  from observed 429s, capped by config.
