# u00-shared-models.md

> **RECONCILIATION (ADR-0006: authoritative over any text below).** This unit also owns
> `TestPlan` and `ModelFingerprint` in `shared.models` (add both to §3/§6), plus
> `shared/schema_export.py` that generates the `suite`/`pack`/`test-plan` JSON schemas from the
> Pydantic models (Pydantic-first; only `attack-spec.schema.json` is hand-authored). `Verdict`
> carries `inconclusive_reason: InconclusiveReason|None` (closed StrEnum:
> `capability_unavailable | blocked_by_policy | judge_compromised`, extensible via ADR; ADR-0011
> added `blocked_by_provider_filter` on 2026-10-10, OD-41, u08 A-69, and its amendment
> `cut_by_provider_output_filter` and `provider_filter_side_unknown` on 2026-10-11, OD-42, A-70;
> ADR-0012 added `unreadable_reply` the same day, OD-21, u08 A-74).
> `ModelFingerprint.capability_guess` (not `.capabilities`): distinct from the `Capabilities`
> enum. Canonical `TestPlan` shape is in ADR-0006 §3, without the per-spec
> `baseline_resistance`, removed on 2026-10-11 (OD-17, ADR-0008 option B: no layer wrote it,
> nothing read it; `PlanSelection` forbids unknown keys, so a plan JSON that still carries it is
> refused, and no command reads one).
>
> **OD-44 (decided 2026-10-11 under the owner's delegation).** `Capabilities` gains `mcp: bool =
> False` (the target is an MCP server: its provider is `mcp`, set by the target loader, u12), and
> `Capability` and `RequiresCapability` gain `mcp`, as the spec schema's `requires` enum does.
> `shared/digest.target_digest` leaves `capabilities.mcp` out when it is false or set by the
> provider, as it leaves an undeclared `sampling` out, so a run stored before resumes.
>
> **OD-19 (decided 2026-10-11 under the owner's delegation, u06 §7 A-73).** `EvaluatorLogic`
> gains `deterministic_first`, the name of the one combination rule, and
> `DEPRECATED_EVALUATOR_LOGIC` holds the other three, which load and run it. The rule is
> `shared/combination.py` (`combine_verdicts`, `decided_by_judge_alone`, `JUDGE_ONLY_FAIL`): a
> pure function over `Verdict`s, here by exception to §8 for the same reason as
> `shared/patterns.py` and `shared/provider_filter.py`, since the three units that must apply it
> one way cannot import each other (`core` imports only `shared`, `registry` may not import
> `evaluators`).

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/01 §3`
+ `docs/03-05` + `docs/10` + `schemas/attack-spec.schema.json` + ADR-0005 before implementing.
This is the **root** of the DAG (W0): every other unit codes against what this file defines, so
its interfaces are program-level frozen contracts: a change here is an index-ledger open decision,
never a unit-local edit.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/shared/`: `models.py` (dependency-free Pydantic v2 models),
  `protocols.py` (the 7 `Protocol`s), `enums.py` (StrEnums), `__init__.py` (re-exports).
- **MUST NOT touch:** any other package (`policy/`, `adapters/`, `evaluators/`, `core/`,
  `scoring/`, `store/`, `reporting/`, `registry/`, `cli/`, `mutators/`, `fingerprint/`),
  `docs/`, `schemas/`, spec YAML. `shared` imports **nothing** from this repo (leaf of the
  import graph); stdlib + `pydantic` only.

## §2 Intended behavior
Provide the stable, dependency-free type layer for the whole build: (a) Pydantic v2 models that
**mirror `schemas/attack-spec.schema.json`** and the runtime objects in `docs/01 §3`; (b) the 7
runtime `Protocol`s; (c) the shared StrEnums. Models are the wire/persistence shapes; protocols
are the seams `core` codes against (interfaces only: no concretes). Verdict polarity is fixed
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

## §4 Known constraints: KEEP / DECIDE
- KEEP: `AttackSpec` field set, enums and constraints are **1:1 with the JSON Schema** (id
  pattern `^[A-Z]+(-[A-Z0-9]+)+$`, `spec_version ^\d+\.\d+$`, `impact/exploitability` 1-4,
  `confidence_threshold`/`confidence` ∈ [0,1], `runs` 1-50); `model_config = ConfigDict(extra="forbid")`
  mirrors `additionalProperties:false`. A schema/model drift is a test failure, not a choice.
- KEEP: `VerdictStatus = {pass, fail, inconclusive}`, polarity `pass=secure`/`fail=exploited`.
- KEEP: models are **frozen** (`frozen=True`) and JSON-serializable; no methods with behavior,
  no I/O, no LLM calls, no business logic (banding lives in u07, not here: expose `Band` enum
  values only, not the mapping).
- KEEP: `logprobs` absent ⇒ `ModelResponse.logprobs is None` (ADR-0005); `Capabilities.logprobs`
  reports availability. No provider-specific fields (byte offsets dropped in MVP-1).
- `Capabilities.sampling: bool | None` (added 2026-10-09, u12 A-68, additive): whether the target
  takes a `temperature` and a `top_p`. The one capability that is not false unless set: `None` is
  the composition root's default rule (a known-model list for `provider: anthropic`, else true).
  The target digest leaves it out when `None`, so digests of targets that do not declare it are
  unchanged; the `Capability` enum gains `sampling`, kept 1:1 with the model.
- KEEP: `inconclusive` reason strings (`capability_unavailable`, `blocked_by_policy`,
  `judge_compromised`) are a typed literal/enum on `Verdict`, not free text (`docs/01 §4`).
- DECIDE (OD-1, ADR-0005 Accepted): `TokenLogprob.top` shape: kept as `list[tuple[str,float]]|None`
  per ADR; flag if any adapter needs richer.

## §5 Implementation plan (each step its own commit, green before next)
1. `enums.py`: all StrEnums; values byte-identical to the schema `enum`s and `docs/04-05`.
2. `models.py` part A: leaf models: `TokenLogprob`, `ModelRequest`, `ModelResponse`,
   `Capabilities`, `Target`, `Evidence`, `EvidenceRef`, `RiskScore`.
3. `models.py` part B: `AttackSpec` (+ nested `Setup`, `Attack`, `EvaluatorConfig`, `Scoring`,
   `Fixtures`) mirroring the schema; `Verdict`, `Attempt`, `EvalContext`, `Finding`, `TestRun`,
   `ModelFingerprint`.
4. `protocols.py`: the 7 `Protocol`s (`@runtime_checkable`), signatures from `docs/01 §3`.
5. `__init__.py` re-exports; write the schema-parity + round-trip tests (§7).

## §6 Data/wire shapes
- `TokenLogprob = {token: str, logprob: float, top: list[tuple[str,float]] | None}` (ADR-0005).
- `ModelResponse = {text: str, tool_calls: list[dict], logprobs: list[TokenLogprob] | None,
  finish_reason: str | None, raw_ids: dict, usage: dict | None}`, and since OD-42 (u08 A-70)
  `filter_side: "input" | "output" | "unknown" | None`: the side the provider's own trace says its
  filter acted on, for a reply that filter stopped (`unknown`: a trace that names neither; only the
  REST adapter sets it, from a Bedrock Converse guardrail trace, u04). It is the one field a dump
  leaves out when it is `None` (a `model_serializer`), so every reply without it is stored, reported
  and hashed byte for byte as before; `logprobs: null` is still dumped (ADR-0005). `raw_ids` holds
  what a transport returns beyond those fields, scalars at the top (a provider's request id, its
  model echo) and a transport's record under its own key: the WebSocket adapter's frame transcript
  is `raw_ids["websocket"]["frames"]`, not a field of its own (OD-34, decided 2026-10-11 under the
  owner's delegation, revisable; reasoning in u04 §9). A reader of the scalars skips a nested value
  (the fingerprint's envelope layer does).
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
  asserted equal to the parsed `schemas/attack-spec.schema.json` (no drift): including
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
  src/ildottore/shared` clean (strict); `lint-imports` green: **`shared` imports nothing
  in-repo** (import-linter independence contract).
- **A-71 (u06's clause; this unit's half, added 2026-10-11):** `Setup.tools` refuses a tool
  whose `destructive` or `external` is a string or a number, as the schema's
  `setup.tools.items.properties` now does (`type: [boolean, null]`; a quoted `"false"` is truthy,
  so it read as true; `tests/fixtures/specs/invalid/setup-tool-destructive-not-boolean.yaml`).
  Null reads as left out: refusing it too broke a pack that left the key empty (pre-merge audit
  of `f76f145`, M1). `shared/tool_abuse.py`
  holds what `tool_call` judges in one call (the allowlist a scene resolves to, the destructive
  verbs and the scene's `destructive` flags, the injection markers and their walk, the
  forbidden-argument walk), because the evaluator and the linter's stub must give one verdict and
  may not import each other; stdlib only, like `shared/patterns.py` (A-33) and
  `shared/refusal_tells.py` (A-27) before it. The verdict stays with u06 and u02: these are the
  predicates both apply, the one kind of behaviour this unit holds despite §8, as with A-33 and A-27.
- **A-72 (u06's clause; this unit's half, added 2026-10-11, OD-43):** `SeededSetup` gains
  `not_destructive`, the granted tools the target file declares not destructive, empty by
  default: a validator refuses a name not in `granted_tools` however the setup is built and keeps
  the list sorted and once each (sorted, not refused out of order, since a report's redactor can
  mask a name and move it), and a serializer leaves it out of a dump when empty, as `ModelResponse`
  leaves out an unset `filter_side` (A-70). `EvalContext` gains `not_destructive_tools`, which the
  runner fills from it, and `Verdict` gains `operator_cleared`, the called tools only the
  declaration kept from being judged destructive, left out of a dump when empty, which every
  count reads instead of the note's text (pre-merge audit of `ed381359`, L1); behaviour-free, as
  every model here. `shared/tool_abuse.py`
  gains the predicates both the evaluator and the runner apply (`operator_cleared`: declared,
  granted and in no scene of the spec; `operator_cleared_calls`: of those, the ones a call made and
  a verb or the scene's flag would make destructive) and the note every changed verdict carries
  (`OPERATOR_DECLARATION`, `operator_note`), so the evaluator's verdict, the runner's aggregate and
  the reports' counts read one rule, and `handoff_shaped`, the hand-off heuristic lint applies to
  a scene's `destructive: false` (moved here from `registry/linter.py`) and the plan to a target
  file's declaration. `shared/digest.target_digest` leaves `not_destructive` out of
  the seeded block when it is empty, so a target that declares none keeps the digest it had
  before the field existed (`tests/evaluators/test_operator_not_destructive.py`).

**A-82 (u12's clause; this unit's half, added 2026-10-11) A sampling value is finite, and two
helpers the CLI audit asked for.** `Sampling` refuses a value that is not finite however it is
built (`allow_inf_nan=False`): a target file's `sampling_defaults` took `.nan` and `.inf`, which
reached the JSON report as bare `NaN` and `Infinity` (CLI audit M6); a spec's schema check refused
them first already (A-54). `WebSocketResponse` refuses a non-finite `timeout_seconds` and
`final_value` built in code. `shared.credential_refs` says what an `env://` reference may name
(`ENV_NAME`, `NO_CREDENTIAL`, and `unset_variable`, which looks in the environment its caller
passes: only the CLI's wiring reads the process's), `shared.error_text` writes an exception as one
line that is never an empty reason (`<Class> (no detail given)`), and `shared.files.read_failure`
describes a file name too long to open by its length. `Sampling`'s docstring, the exported
schema's description, is unchanged; the reason is a comment. Checked by
`tests/cli/test_non_finite_values.py`, `tests/cli/test_credential_variables.py` and
`tests/cli/test_cli_messages_read_right.py`.

## §8 Out of scope / forbidden
- MUST NOT import any other `ildottore` package or any provider SDK / httpx / Jinja / Typer.
- MUST NOT implement behavior: no scoring/banding math (u07), no evaluation (u06), no I/O,
  no adapter concretes, no redaction logic (u01): only the shapes those units fill.
- MUST NOT diverge from `schemas/attack-spec.schema.json`; the schema stays the source of truth
  (if a field is genuinely missing, that is a schema change + ADR, not a silent model addition).
- MUST NOT relax `frozen`/`extra="forbid"` to make a downstream unit compile.

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-1 (ADR-0005, Accepted):** `TokenLogprob.top` stays `list[tuple[str,float]]|None`; reopen
  only if u04 finds a provider needing byte offsets / richer top-k.
- Whether `inconclusive_reason` is a closed `StrEnum` or an open `str`: propose closed enum
  seeded with `{capability_unavailable, blocked_by_policy, judge_compromised}`, extensible via ADR.
  (Built closed; ADR-0011 added `blocked_by_provider_filter`, 2026-10-10: a prompt the provider's
  own input filter refused before the model saw it, OD-41; its amendment added
  `cut_by_provider_output_filter` and `provider_filter_side_unknown`, 2026-10-11: a reply the
  provider's filter cut or replaced, and one it stopped on a side it did not report, OD-42; ADR-0012
  added `unreadable_reply`, 2026-10-11: a success reply the adapter could not read as the
  provider's, OD-21, u08 A-74, with `shared/unreadable.py`, which reads it from a stored attempt:
  the verdict's reason, else the error's mark ` [unreadable_reply]`, and names the
  `request.metadata` key `unreadable_reply` under which the attempt keeps a bounded excerpt.)
- Whether `ModelFingerprint` lives in `shared.models` (proposed, since u09 + u08 planner both
  consume it) or moves to `fingerprint/`: propose shared (it is a cross-unit wire shape).
