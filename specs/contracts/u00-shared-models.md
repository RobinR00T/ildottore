# u00-shared-models.md

> **RECONCILIATION (ADR-0006 - authoritative over any text below).** This unit also owns
> `TestPlan` and `ModelFingerprint` in `shared.models` (add both to §3/§6), plus
> `shared/schema_export.py` that generates the `suite`/`pack`/`test-plan` JSON schemas from the
> Pydantic models (Pydantic-first; only `attack-spec.schema.json` is hand-authored). `Verdict`
> carries `inconclusive_reason: InconclusiveReason|None` (closed StrEnum:
> `capability_unavailable | blocked_by_policy | judge_compromised`, extensible via ADR).
> `ModelFingerprint.capability_guess` (not `.capabilities`) - distinct from the `Capabilities`
> enum. Canonical `TestPlan` shape is in ADR-0006 §3.

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/01 §3`
+ `docs/03-05` + `docs/10` + `schemas/attack-spec.schema.json` + ADR-0005 before implementing.
This is the **root** of the DAG (W0): every other unit codes against what this file defines, so
its interfaces are program-level frozen contracts - a change here is an index-ledger open decision,
never a unit-local edit.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/shared/` - `models.py` (dependency-free Pydantic v2 models),
  `protocols.py` (the 7 `Protocol`s), `enums.py` (StrEnums), `__init__.py` (re-exports).
- **MUST NOT touch:** any other package (`policy/`, `adapters/`, `evaluators/`, `core/`,
  `scoring/`, `store/`, `reporting/`, `registry/`, `cli/`, `mutators/`, `fingerprint/`),
  `docs/`, `schemas/`, spec YAML. `shared` imports **nothing** from this repo (leaf of the
  import graph); stdlib + `pydantic` only.

## §2 Intended behavior
Provide the stable, dependency-free type layer for the whole build: (a) Pydantic v2 models that
**mirror `schemas/attack-spec.schema.json`** and the runtime objects in `docs/01 §3`; (b) the 7
runtime `Protocol`s; (c) the shared StrEnums. Models are the wire/persistence shapes; protocols
are the seams `core` codes against (interfaces only - no concretes). Verdict polarity is fixed
repo-wide and encoded here: **`pass` = secure, `fail` = exploited** (`docs/04 §0`). `AttackSpec`
must round-trip any schema-valid YAML and reject any schema-invalid one (schema is the oracle).

## §3 Dependencies & interface contracts
- **Depends on:** none (W0 root).
- **Provides (the interface registry, `docs/01 §3`, `00-INDEX`):**
  - `shared.models`: `AttackSpec, Target, Capabilities, ModelRequest, ModelResponse,
    TokenLogprob, Attempt, EvalContext, Verdict, RiskScore, Finding, Evidence, EvidenceRef,
    TestRun, ModelFingerprint`.
  - `shared.protocols`: `TargetAdapter, Evaluator, Mutator, RiskScorer, EvidenceStore,
    RunStore, Reporter` (signatures verbatim from `docs/01 §3`; `Mutator` per `docs/03 §4`).
  - `shared.enums`: `Category, Severity, TargetType, Capability, VerdictStatus, EvaluatorType,
    EvaluatorLogic, ReportFormat, Band`.
- `TokenLogprob` + `ModelResponse.logprobs` follow **ADR-0005** exactly (see §6).

## §4 Known constraints - KEEP / DECIDE
- KEEP: `AttackSpec` field set, enums and constraints are **1:1 with the JSON Schema** (id
  pattern `^[A-Z]+(-[A-Z0-9]+)+$`, `spec_version ^\d+\.\d+$`, `impact/exploitability` 1-4,
  `confidence_threshold`/`confidence` ∈ [0,1], `runs` 1-50); `model_config = ConfigDict(extra="forbid")`
  mirrors `additionalProperties:false`. A schema/model drift is a test failure, not a choice.
- KEEP: `VerdictStatus = {pass, fail, inconclusive}`, polarity `pass=secure`/`fail=exploited`.
- KEEP: models are **frozen** (`frozen=True`) and JSON-serializable; no methods with behavior,
  no I/O, no LLM calls, no business logic (banding lives in u07, not here - expose `Band` enum
  values only, not the mapping).
- KEEP: `logprobs` absent ⇒ `ModelResponse.logprobs is None` (ADR-0005); `Capabilities.logprobs`
  reports availability. No provider-specific fields (byte offsets dropped in MVP-1).
- KEEP: `inconclusive` reason strings (`capability_unavailable`, `blocked_by_policy`,
  `judge_compromised`) are a typed literal/enum on `Verdict`, not free text (`docs/01 §4`).
- DECIDE (OD-1, ADR-0005 Accepted): `TokenLogprob.top` shape - kept as `list[tuple[str,float]]|None`
  per ADR; flag if any adapter needs richer.

## §5 Implementation plan (each step its own commit, green before next)
1. `enums.py` - all StrEnums; values byte-identical to the schema `enum`s and `docs/04-05`.
2. `models.py` part A - leaf models: `TokenLogprob`, `ModelRequest`, `ModelResponse`,
   `Capabilities`, `Target`, `Evidence`, `EvidenceRef`, `RiskScore`.
3. `models.py` part B - `AttackSpec` (+ nested `Setup`, `Attack`, `EvaluatorConfig`, `Scoring`,
   `Fixtures`) mirroring the schema; `Verdict`, `Attempt`, `EvalContext`, `Finding`, `TestRun`,
   `ModelFingerprint`.
4. `protocols.py` - the 7 `Protocol`s (`@runtime_checkable`), signatures from `docs/01 §3`.
5. `__init__.py` re-exports; write the schema-parity + round-trip tests (§7).

## §6 Data/wire shapes
- `TokenLogprob = {token: str, logprob: float, top: list[tuple[str,float]] | None}` (ADR-0005).
- `ModelResponse = {text: str, tool_calls: list[dict], logprobs: list[TokenLogprob] | None,
  finish_reason: str | None, raw_ids: dict, usage: dict | None}`.
- `Verdict = {status: VerdictStatus, confidence: float[0,1], reasoning: str, matched: list[str],
  evaluator_type: str, inconclusive_reason: InconclusiveReason | None}` (`docs/04 §1-§3`).
- `AttackSpec` = every field/constraint in `schemas/attack-spec.schema.json` (`docs/03 §2`),
  including `fixtures.{vulnerable,hardened}` with `expect_verdict` literals `fail`/`pass`.
- `RiskScore = {impact:1-4, exploitability:1-4, reproducibility:float[0,1], score:float, band:Band}`
  (`docs/05 §2-§3`; the model carries the value, u07 computes it).
- `ModelFingerprint` mirrors the `docs/10 §2` JSON (family/version guesses+confidence,
  capabilities, guardrails, evidence[], spoofing_flags, recommended_plan_ref).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/shared -q` green; **coverage ≥ 90%** for `src/ildottore/shared`.
- **Schema-parity gate** (`tests/shared/test_schema_parity.py`): every schema-valid fixture in
  `tests/fixtures/specs/valid/*.yaml` parses into `AttackSpec`; every one in
  `.../invalid/*.yaml` raises `pydantic.ValidationError`. `AttackSpec` field names/enums are
  asserted equal to the parsed `schemas/attack-spec.schema.json` (no drift) - including
  `additionalProperties:false` ⇔ `extra="forbid"`.
- **Round-trip:** `AttackSpec.model_validate(y).model_dump(mode="json")` re-validates against the
  JSON Schema (`jsonschema`), byte-stable on re-dump.
- **Property test (Hypothesis):** generated in-range `RiskScore`/`Verdict`/`ModelResponse`
  round-trip JSON; out-of-range (impact=5, confidence=1.2, bad id pattern) rejected.
- **ADR-0005:** test that `logprobs=None` is valid and `logprob`/`top` shapes match; a
  `ModelResponse` with omitted logprobs dumps `logprobs: null`.
- **Protocol conformance:** a dummy class satisfying each `Protocol` passes `isinstance`
  (`@runtime_checkable`); signatures match `docs/01 §3` (verified via `inspect`).
- `ruff check src/ildottore/shared tests/shared` + `ruff format --check` clean; `mypy
  src/ildottore/shared` clean (strict); `lint-imports` green - **`shared` imports nothing
  in-repo** (import-linter independence contract).

## §8 Out of scope / forbidden
- MUST NOT import any other `ildottore` package or any provider SDK / httpx / Jinja / Typer.
- MUST NOT implement behavior: no scoring/banding math (u07), no evaluation (u06), no I/O,
  no adapter concretes, no redaction logic (u01) - only the shapes those units fill.
- MUST NOT diverge from `schemas/attack-spec.schema.json`; the schema stays the source of truth
  (if a field is genuinely missing, that is a schema change + ADR, not a silent model addition).
- MUST NOT relax `frozen`/`extra="forbid"` to make a downstream unit compile.

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-1 (ADR-0005, Accepted):** `TokenLogprob.top` stays `list[tuple[str,float]]|None`; reopen
  only if u04 finds a provider needing byte offsets / richer top-k.
- Whether `inconclusive_reason` is a closed `StrEnum` or an open `str` - propose closed enum
  seeded with `{capability_unavailable, blocked_by_policy, judge_compromised}`, extensible via ADR.
- Whether `ModelFingerprint` lives in `shared.models` (proposed, since u09 + u08 planner both
  consume it) or moves to `fingerprint/` - propose shared (it is a cross-unit wire shape).
