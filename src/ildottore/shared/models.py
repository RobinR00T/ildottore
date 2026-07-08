"""Dependency-free Pydantic v2 models for Il Dottore.

These mirror ``schemas/attack-spec.schema.json`` (author-facing spec format) and the
runtime wire/persistence shapes in ``docs/01 §3``, ``docs/04-05``, ``docs/10`` and
ADR-0005/0006. Models are frozen and JSON-serializable; they carry **no behavior** —
no scoring math (u07), no evaluation (u06), no I/O. ``extra="forbid"`` mirrors the
schema ``additionalProperties: false`` (contract §4 KEEP).
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from ildottore.shared.enums import (
    Category,
    EvaluatorLogic,
    EvaluatorType,
    InconclusiveReason,
    RequiresCapability,
    ScanBand,
    Severity,
    TargetType,
    VerdictStatus,
)

# --- shared field constraints (schema §properties) ---------------------------------

# id pattern ^[A-Z]+(-[A-Z0-9]+)+$ ; spec_version ^\d+\.\d+$ ; owasp ^LLM\d{2}$
_ID_PATTERN = r"^[A-Z]+(-[A-Z0-9]+)+$"
_SPEC_VERSION_PATTERN = r"^\d+\.\d+$"
_OWASP_PATTERN = r"^LLM\d{2}$"

Unit = Annotated[float, Field(ge=0.0, le=1.0)]  # confidence / reproducibility in [0,1]
Score1to4 = Annotated[int, Field(ge=1, le=4)]  # impact / exploitability 1..4

# Free-shaped JSON object (schema uses untyped ``object`` items for these fields).
JsonDict = dict[str, object]


class _Frozen(BaseModel):
    """Base: frozen, forbid unknown fields (mirrors ``additionalProperties: false``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class _SchemaMirror(_Frozen):
    """Base for models that mirror ``schemas/attack-spec.schema.json`` 1:1.

    The hand-authored JSON Schema types every optional field with its bare type and
    **no null union** (e.g. ``test_only: boolean``, ``attack.carrier: string``). A plain
    Pydantic dump emits ``null`` for every unset optional, which then fails validation
    against that schema ("None is not of type ..."). These models therefore default
    ``exclude_none=True`` on dump so that the acceptance criterion — running
    ``AttackSpec.model_validate(y).model_dump(mode="json")`` **verbatim** (no explicit
    ``exclude_none``) — produces schema-valid, byte-stable JSON. Runtime wire models keep
    plain ``_Frozen`` (null-preserving) because ADR-0005 mandates ``logprobs: null`` be
    present when absent.
    """

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs: Any) -> str:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(**kwargs)


# =============================================================================
# AttackSpec + nested models — 1:1 with schemas/attack-spec.schema.json
# =============================================================================


class MitreAtlas(_SchemaMirror):
    """``mitre_atlas`` — required ``tactic``, optional ``technique``."""

    tactic: str
    technique: str | None = None


class Setup(_SchemaMirror):
    """Declarative ``setup`` block (all fields optional per schema)."""

    documents: list[JsonDict] | None = None
    tools: list[JsonDict] | None = None
    memory_seed: list[JsonDict] | None = None
    system_prompt: str | None = None
    canaries: list[str] | None = None


class Attack(_SchemaMirror):
    """``attack`` — at least one of ``user_prompt`` / ``carrier`` / ``turns``."""

    user_prompt: str | None = None
    carrier: str | None = None
    turns: list[str] | None = None

    def model_post_init(self, _context: object) -> None:
        # Schema anyOf: [user_prompt] | [carrier] | [turns].
        if self.user_prompt is None and self.carrier is None and self.turns is None:
            raise ValueError("attack requires at least one of: user_prompt, carrier, turns")


class EvaluatorConfig(_SchemaMirror):
    """One entry in ``evaluators`` — required ``type`` (contract naming)."""

    type: EvaluatorType
    patterns: list[str] | None = None
    rubric: str | None = None
    canary_ref: str | None = None
    weight: float | None = None


class Scoring(_SchemaMirror):
    """``scoring`` — author-supplied impact/exploitability + confidence threshold."""

    impact: Score1to4
    exploitability: Score1to4
    confidence_threshold: Unit


class Sampling(_SchemaMirror):
    """Pinned sampling params (``sampling``)."""

    temperature: float | None = None
    top_p: float | None = None
    seed: int | None = None
    max_tokens: int | None = None


class Budget(_SchemaMirror):
    """Hard caps (``budget``) — mandatory for ``availability_cost`` specs."""

    max_tokens: int | None = None
    max_requests: int | None = None
    timeout_s: int | None = None


class SetupDoc(_SchemaMirror):
    """A single declarative setup document (loosely typed; runner materializes it)."""

    model_config = ConfigDict(extra="allow", frozen=True)

    id: str | None = None
    type: str | None = None
    content: str | None = None
    content_template: str | None = None


class FixtureCase(_SchemaMirror):
    """One golden fixture (``fixtures.vulnerable`` / ``fixtures.hardened``)."""

    response: str
    tool_calls: list[JsonDict] | None = None
    expect_verdict: VerdictStatus


class Fixtures(_SchemaMirror):
    """``fixtures`` — self-proving canned responses (``docs/03 §1``).

    ``vulnerable.expect_verdict`` is literally ``fail``; ``hardened`` is ``pass``.
    """

    vulnerable: FixtureCase
    hardened: FixtureCase

    def model_post_init(self, _context: object) -> None:
        if self.vulnerable.expect_verdict is not VerdictStatus.FAIL:
            raise ValueError("fixtures.vulnerable.expect_verdict must be 'fail'")
        if self.hardened.expect_verdict is not VerdictStatus.PASS:
            raise ValueError("fixtures.hardened.expect_verdict must be 'pass'")


class AttackSpec(_SchemaMirror):
    """A declarative, versioned attack test — mirrors the JSON Schema exactly."""

    id: str = Field(pattern=_ID_PATTERN)
    spec_version: str = Field(pattern=_SPEC_VERSION_PATTERN)
    name: str = Field(min_length=3)
    category: Category
    owasp: str = Field(pattern=_OWASP_PATTERN)
    mitre_atlas: MitreAtlas
    nist_ai_rmf: str
    severity: Severity
    target_type: TargetType
    requires: list[RequiresCapability]
    description: str
    preconditions: list[str] | None = None
    setup: Setup | None = None
    attack: Attack
    mutations: list[str] | None = None
    expected_secure_behavior: list[str] = Field(min_length=1)
    evaluators: list[EvaluatorConfig] = Field(min_length=1)
    evaluator_logic: EvaluatorLogic | None = None
    scoring: Scoring
    runs: Annotated[int, Field(ge=1, le=50)] | None = None
    sampling: Sampling | None = None
    budget: Budget | None = None
    test_only: bool | None = None
    requires_policy: list[str] = Field(default_factory=list)
    fixtures: Fixtures
    tags: list[str] | None = None


# =============================================================================
# Runtime wire shapes — docs/01 §3, docs/04, ADR-0005
# =============================================================================


class Capabilities(_Frozen):
    """Target-declared capability flags (``docs/01 §3``; ``TargetAdapter.capabilities()``)."""

    tools: bool = False
    rag: bool = False
    memory: bool = False
    streaming: bool = False
    seed: bool = False
    logprobs: bool = False
    multi_identity: bool = False
    multimodal: bool = False


class Target(_Frozen):
    """A target under test (id + type + declared capabilities).

    ``provider``/``endpoint``/``model``/``auth_ref``/``sampling_defaults`` are the
    optional **live-target** fields a real ``target.yaml`` declares (``docs/09``,
    ``specs/targets/example-openai.yaml``) so the u12 composition root can route a
    non-mock target to the correct over-the-wire adapter (u04) without a second
    parse of the file. ``auth_ref`` is a reference (e.g. ``env://NAME``), never an
    inline secret (S6); it is resolved to a value only at send time, in ``cli``.
    All five stay ``None`` for a mock/offline target (contract §4 KEEP: additive,
    optional fields — no change to existing mock behavior).
    """

    id: str
    type: TargetType
    capabilities: Capabilities = Field(default_factory=Capabilities)
    name: str | None = None
    provider: str | None = None
    endpoint: str | None = None
    model: str | None = None
    auth_ref: str | None = None
    sampling_defaults: Sampling | None = None


class TokenLogprob(_Frozen):
    """Provider-neutral token logprob (ADR-0005).

    ``top`` stays ``list[tuple[str, float]] | None`` (OD-1); byte offsets dropped MVP-1.
    """

    token: str
    logprob: float
    top: list[tuple[str, float]] | None = None


class ModelRequest(_Frozen):
    """A single request to a ``TargetAdapter`` (``docs/01 §3``)."""

    prompt: str | None = None
    messages: list[JsonDict] | None = None
    system_prompt: str | None = None
    tools: list[JsonDict] | None = None
    sampling: Sampling | None = None
    identity: str | None = None  # for multi_identity authz specs
    metadata: JsonDict | None = None


class ModelResponse(_Frozen):
    """A target response (``docs/01 §3``, contract §6).

    ``logprobs is None`` when the target lacks the logprobs capability (ADR-0005).
    """

    text: str
    tool_calls: list[JsonDict] = Field(default_factory=list)
    logprobs: list[TokenLogprob] | None = None
    finish_reason: str | None = None
    raw_ids: JsonDict = Field(default_factory=dict)
    usage: JsonDict | None = None


class Verdict(_Frozen):
    """Evaluator output (``docs/04 §1-§3``, contract §6).

    ``inconclusive_reason`` is set only when ``status == inconclusive``.
    """

    status: VerdictStatus
    confidence: Unit
    reasoning: str
    matched: list[str] = Field(default_factory=list)
    evaluator_type: str
    inconclusive_reason: InconclusiveReason | None = None

    def model_post_init(self, _context: object) -> None:
        if self.status is VerdictStatus.INCONCLUSIVE and self.inconclusive_reason is None:
            # Reason recommended but not mandated; keep permissive for aggregate verdicts.
            return
        if self.status is not VerdictStatus.INCONCLUSIVE and self.inconclusive_reason is not None:
            raise ValueError("inconclusive_reason is only valid when status is 'inconclusive'")


class EvidenceRef(_Frozen):
    """A reference to a stored evidence artifact (``EvidenceStore.put`` return)."""

    run_id: str
    attempt_id: str
    uri: str
    sha256: str | None = None


class Evidence(_Frozen):
    """Per-verdict evidence bundle (``docs/04 §5``); values masked by the redactor."""

    attempt_id: str
    evaluator_type: str
    inputs_seen: JsonDict = Field(default_factory=dict)
    matched: list[str] = Field(default_factory=list)
    judge_prompt: str | None = None
    judge_raw_output: str | None = None
    judge_parsed: JsonDict | None = None
    reasoning: str | None = None


class EvalContext(_Frozen):
    """The input an ``Evaluator`` sees (``docs/01 §3`` / ``docs/04``).

    Carries the spec, the request/response pair under evaluation and the specific
    evaluator config. Behavior-free (the evaluator, u06, does the work).
    """

    spec: AttackSpec
    request: ModelRequest
    response: ModelResponse
    config: EvaluatorConfig
    canaries: list[str] = Field(default_factory=list)
    identities: dict[str, ModelResponse] | None = None  # for authz_leak (multi_identity)


class Attempt(_Frozen):
    """One (mutated) attack execution against a target (``docs/01 §4``)."""

    attempt_id: str
    spec_id: str
    mutation: str = "identity"
    request: ModelRequest
    response: ModelResponse | None = None
    verdict: Verdict | None = None
    sampling: Sampling | None = None
    latency_ms: float | None = None
    error: str | None = None


class RiskScore(_Frozen):
    """Two-axis risk (``docs/05 §2-§3``). The model carries the value; u07 computes it."""

    impact: Score1to4
    exploitability: Score1to4
    reproducibility: Unit
    risk: Annotated[float, Field(ge=0.0, le=16.0)]
    band: ScanBand
    confidence: Unit


class Finding(_Frozen):
    """A scored, evidenced result for one spec against one target."""

    spec_id: str
    target_id: str
    status: VerdictStatus
    risk: RiskScore
    confirmed: bool
    attempts: list[Attempt] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    reasoning: str | None = None


class TestRunSummary(_Frozen):
    """Aggregated run counts (``docs/05 §4``)."""

    __test__ = False  # not a pytest test class

    by_status: dict[str, int] = Field(default_factory=dict)
    by_band: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    total: int = 0


class TestRun(_Frozen):
    """A full campaign of one suite against one or more targets."""

    __test__ = False  # not a pytest test class

    run_id: str
    suite_ref: str | None = None
    targets: list[Target] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: TestRunSummary = Field(default_factory=TestRunSummary)
    started_at: str | None = None
    finished_at: str | None = None


# =============================================================================
# Fingerprint + TestPlan — ADR-0006, docs/10
# =============================================================================


class FingerprintGuess(_Frozen):
    """A probabilistic guess with confidence (``docs/10 §2``)."""

    guess: str
    confidence: Unit
    cutoff_hint: str | None = None


class FingerprintEvidence(_Frozen):
    """One weighted signal contributing to a fingerprint verdict (``docs/10 §2``)."""

    layer: str
    signal: str
    weight: float


class ModelFingerprint(_Frozen):
    """Output of the fingerprint engine (``docs/10 §2``, ADR-0006 §4).

    ``capability_guess`` (a free-shaped probe result: json_mode/vision/max_context…)
    is intentionally distinct from the target-declared ``Capabilities`` enum.
    """

    target_id: str
    family: FingerprintGuess
    version: FingerprintGuess | None = None
    capability_guess: JsonDict = Field(default_factory=dict)
    guardrails: JsonDict = Field(default_factory=dict)
    evidence: list[FingerprintEvidence] = Field(default_factory=list)
    spoofing_flags: list[str] = Field(default_factory=list)
    recommended_plan_ref: str | None = None


class PlanSelection(_Frozen):
    """A selected spec in a ``TestPlan`` (ADR-0006 §3; per-spec mutators/baseline)."""

    spec_id: str
    reason: str
    mutators: list[str] = Field(default_factory=list)
    baseline_resistance: float | None = None


class PlanSkip(_Frozen):
    """A skipped spec + reason (nothing is silently dropped — ``docs/10 §3``)."""

    spec_id: str
    reason: str


class PlanBudgets(_Frozen):
    """Plan-level budgets (ADR-0006 §3)."""

    max_tokens: int | None = None
    max_requests: int | None = None
    max_wall_s: int | None = None
    max_attempts: int | None = None


class TestPlan(_Frozen):
    """Canonical adaptive test plan (ADR-0006 §3; built by u08 ``core/planner.py``)."""

    __test__ = False  # not a pytest test class

    plan_ref: str
    target_id: str
    adaptive: bool
    fingerprint_ref: str | None = None
    selected: list[PlanSelection] = Field(default_factory=list)
    skipped: list[PlanSkip] = Field(default_factory=list)
    budgets: PlanBudgets = Field(default_factory=PlanBudgets)
