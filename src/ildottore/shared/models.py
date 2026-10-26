"""Dependency-free Pydantic v2 models for Il Dottore.

These mirror ``registry/schemas/attack-spec.schema.json`` (author-facing spec format) and the
runtime wire/persistence shapes in ``docs/01 §3``, ``docs/04-05``, ``docs/10`` and
ADR-0005/0006. Models are frozen and JSON-serializable; they carry **no behavior** -
no scoring math (u07), no evaluation (u06), no I/O. ``extra="forbid"`` mirrors the
schema ``additionalProperties: false`` (contract §4 KEEP).
"""

from __future__ import annotations

import math
import re
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_validator,
    model_serializer,
    model_validator,
)

from ildottore.shared.enums import (
    AttackOccurrence,
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
from ildottore.shared.filter_stops import documented_stops, target_filter_stops

# --- shared field constraints (schema §properties) ---------------------------------

# id pattern ^[A-Z]+(-[A-Z0-9]+)+$ ; spec_version ^\d+\.\d+$ ; owasp ^LLM\d{2}$
_ID_PATTERN = r"^[A-Z]+(-[A-Z0-9]+)+$"
#: The spec id shape, for the readers of a stored report (``dottore diff`` and ``calibrate``).
SPEC_ID_PATTERN = _ID_PATTERN
_SPEC_VERSION_PATTERN = r"^\d+\.\d+$"
# OWASP LLM Top 10 code, or an RAI code for the Responsible-AI pack (docs/12 P2), which has
# no OWASP-security mapping. The `nist_ai_rmf` field carries its primary framework mapping.
_OWASP_PATTERN = r"^(LLM|RAI)\d{2}$"

Unit = Annotated[float, Field(ge=0.0, le=1.0)]  # confidence / reproducibility in [0,1]
Score1to4 = Annotated[int, Field(ge=1, le=4)]  # impact / exploitability 1..4

# Free-shaped JSON object (schema uses untyped ``object`` items for these fields).
JsonDict = dict[str, object]


class _Frozen(BaseModel):
    """Base: frozen, forbid unknown fields (mirrors ``additionalProperties: false``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class _SchemaMirror(_Frozen):
    """Base for models that mirror ``registry/schemas/attack-spec.schema.json`` 1:1.

    The hand-authored JSON Schema types every optional field with its bare type and
    **no null union** (e.g. ``test_only: boolean``, ``attack.carrier: string``). A plain
    Pydantic dump emits ``null`` for every unset optional, which then fails validation
    against that schema ("None is not of type ..."). These models therefore default
    ``exclude_none=True`` on dump so that the acceptance criterion - running
    ``AttackSpec.model_validate(y).model_dump(mode="json")`` **verbatim** (no explicit
    ``exclude_none``) - produces schema-valid, byte-stable JSON. Runtime wire models keep
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
# AttackSpec + nested models - 1:1 with registry/schemas/attack-spec.schema.json
# =============================================================================


class MitreAtlas(_SchemaMirror):
    """``mitre_atlas`` - required ``tactic``, optional ``technique``."""

    tactic: str
    technique: str | None = None


# The IoPC code shapes, mirrored from ``registry/schemas/attack-spec.schema.json``.
# ANCHOR NOTE, do not "fix" this to match the JSON file: pydantic validates with rust-regex,
# where ``$`` already means end-of-haystack, while the JSON schema is validated by Python
# ``jsonschema`` (``re``), where ``$`` also matches BEFORE a trailing newline and therefore
# needs ``\Z``. Same intent, different anchor, because the engines differ.
_IOPC_TECHNIQUE_PATTERN = r"^IOPC-T[1-9][0-9]*\.[0-9]{3}$"
_IOPC_IMPACT_PATTERN = r"^IOPC-R[0-9]{3}$"
# OWASP AISVS requirement IDs (``shared.aisvs``), same anchor note as above.
_AISVS_PATTERN = r"^v1\.0-C[1-9][0-9]?\.[1-9][0-9]?\.[1-9][0-9]?$"


class IoPC(_SchemaMirror):
    """``iopc`` - Nova IoPC taxonomy mapping, on two axes (``docs/15``).

    ``techniques`` is the *how* (``IOPC-T<family>.<nnn>``), ``impacts`` is the *damage*
    (``IOPC-R<nnn>``). Both optional so a spec can map on either axis, but the shipped battery
    is required to carry at least one (pinned by a test, not by the schema, so third-party
    spec packs are not broken by the field's arrival).
    """

    techniques: list[Annotated[str, Field(pattern=_IOPC_TECHNIQUE_PATTERN)]] | None = None
    impacts: list[Annotated[str, Field(pattern=_IOPC_IMPACT_PATTERN)]] | None = None


# A MITRE ATT&CK technique ID (``shared.attack``), same anchor note as above.
_ATTACK_TECHNIQUE_PATTERN = r"^T[0-9]{4}(\.[0-9]{3})?$"
# An Enterprise tactic shortname as the STIX bundle writes it (``command-and-control``).
_ATTACK_TACTIC_PATTERN = r"^[a-z]+(-[a-z]+)*$"


class AttackTechniqueMapping(_SchemaMirror):
    """One ``mitre_attack.techniques`` entry: a technique ID, how the spec exercises it, and
    optionally which of the technique's tactics the claim is restricted to (``shared.attack``)."""

    id: str = Field(pattern=_ATTACK_TECHNIQUE_PATTERN)
    occurrence: AttackOccurrence
    tactics: list[Annotated[str, Field(pattern=_ATTACK_TACTIC_PATTERN)]] | None = None


class MitreAttack(_SchemaMirror):
    """``mitre_attack`` - MITRE ATT&CK Enterprise mapping (``docs/17``).

    Optional so third-party packs keep validating. ``domain`` is ``enterprise`` only today: the
    pin is derived from the Enterprise bundle, and a Mobile or ICS ID would validate against
    nothing. An ID outside the pin, a retired one, or a tactic the technique does not sit under
    is a lint error, not a silent zero.
    """

    domain: Literal["enterprise"] = "enterprise"
    techniques: list[AttackTechniqueMapping] = Field(min_length=1)


#: The flags of a scene tool the evaluators read, each a boolean or null when present: a quoted
#: ``"false"`` is truthy, so it read as ``true``, and ``0`` or ``1`` say nothing a boolean does
#: not (u06 A-71). Null (a key left empty) reads as absent, as it always did. Mirrors the
#: schema's ``setup.tools.items.properties``.
_TOOL_FLAGS: tuple[str, ...] = ("destructive", "external")


class Setup(_SchemaMirror):
    """Declarative ``setup`` block (all fields optional per schema)."""

    documents: list[JsonDict] | None = None
    tools: list[JsonDict] | None = None
    memory_seed: list[JsonDict] | None = None
    system_prompt: str | None = None
    canaries: list[str] | None = None

    @field_validator("tools")
    @classmethod
    def _tool_flags_are_booleans(cls, tools: list[JsonDict] | None) -> list[JsonDict] | None:
        for index, tool in enumerate(tools or []):
            for flag in _TOOL_FLAGS:
                value = tool.get(flag)
                if value is not None and not isinstance(value, bool):
                    raise ValueError(
                        f"setup.tools[{index}].{flag} must be true or false (or left out), "
                        f"not {type(value).__name__}"
                    )
        return tools


class Attack(_SchemaMirror):
    """``attack``: at least one of ``user_prompt`` / ``carrier`` / ``turns``.

    ``media`` is an additive, optional multimodal carrier (``docs/12`` MVP-3): a list of
    declarative parts (e.g. ``{"kind": "image", "format": "png", "render_text": "..."}``) rendered
    deterministically at send time (``shared.media``). It accompanies ``user_prompt`` (the text
    turn) rather than replacing it, and only runs against a target that declares the ``multimodal``
    capability (the planner gates it like ``multi_identity``).
    """

    user_prompt: str | None = None
    carrier: str | None = None
    turns: list[str] | None = None
    media: list[JsonDict] | None = None

    def model_post_init(self, _context: object) -> None:
        # Schema anyOf: [user_prompt] | [carrier] | [turns]. `media` is an add-on carrier, not one
        # of the anyOf alternatives, so it never satisfies the "at least one" requirement alone.
        if self.user_prompt is None and self.carrier is None and self.turns is None:
            raise ValueError("attack requires at least one of: user_prompt, carrier, turns")


class EvaluatorConfig(_SchemaMirror):
    """One entry in ``evaluators`` - required ``type`` (contract naming)."""

    type: EvaluatorType
    patterns: list[str] | None = None
    forbidden_args: list[str] | None = None
    # ``tool_call`` only: a regex per argument name (case-insensitive, at any depth of any call).
    # A value written under that name that matches is the exploit, whatever the tool and the key
    # say: a total of zero on a checkout, a ``file://`` URL on an authorized fetch, an id that is
    # not a number (u06 A-88).
    forbidden_arg_values: dict[str, str] | None = None
    # ``tool_sequence`` only: per-step argument constraint, keyed by the step's tool name. A
    # step then counts ONLY when the tool was called AND one of its argument values matches the
    # regex, which is what separates a malicious egress from a benign one.
    step_arg_patterns: dict[str, str] | None = None
    rubric: str | None = None
    canary_ref: str | None = None
    weight: float | None = None


class Scoring(_SchemaMirror):
    """``scoring`` - author-supplied impact/exploitability + confidence threshold."""

    impact: Score1to4
    exploitability: Score1to4
    confidence_threshold: Unit


#: Bound on a spec's requested completion length. Unbounded until 2026-09-21, in the model,
#: in the JSON schema and in the linter, which mattered once the run budgets started being
#: derived from the plan: a spec declaring ``max_tokens: 10_000_000`` handed the campaign a
#: 75-million-token ceiling, i.e. a third-party spec pack could set the scanner's own
#: self-DoS limit. A negative value was accepted too, and dragged a pack's estimate DOWN.
#: 200k is above every provider's output limit today and far below anything dangerous.
MAX_SAMPLING_TOKENS = 200_000


class Sampling(_SchemaMirror):
    """Pinned sampling params (``sampling``)."""

    # The docstring is the exported schema's description, so the reason stays here: a value that
    # is not finite is refused however the model is built (u12 A-82, CLI audit M6). A spec's
    # schema check refused `.nan` and `.inf` first (A-54); a target file's `sampling_defaults`
    # did not, and they reached the JSON report as bare `NaN` and `Infinity`, and the wire.
    model_config = ConfigDict(allow_inf_nan=False)

    temperature: float | None = None
    top_p: float | None = None
    seed: int | None = None
    max_tokens: Annotated[int, Field(ge=1, le=MAX_SAMPLING_TOKENS)] | None = None


class Budget(_SchemaMirror):
    """Hard caps (``budget``) - mandatory for ``availability_cost`` specs."""

    max_tokens: Annotated[int, Field(ge=1, le=MAX_SAMPLING_TOKENS)] | None = None
    max_requests: Annotated[int, Field(ge=1, le=100_000)] | None = None
    timeout_s: Annotated[int, Field(ge=1, le=86_400)] | None = None


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
    """``fixtures`` - self-proving canned responses (``docs/03 §1``).

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
    """A declarative, versioned attack test - mirrors the JSON Schema exactly."""

    id: str = Field(pattern=_ID_PATTERN)
    spec_version: str = Field(pattern=_SPEC_VERSION_PATTERN)
    name: str = Field(min_length=3)
    category: Category
    owasp: str = Field(pattern=_OWASP_PATTERN)
    mitre_atlas: MitreAtlas
    #: MITRE ATT&CK Enterprise techniques this spec exercises, each with how (``shared.attack``).
    mitre_attack: MitreAttack | None = None
    nist_ai_rmf: str
    iopc: IoPC | None = None
    #: OWASP AISVS 1.0 requirement IDs whose control a FAIL of this spec is evidence against.
    #: Falsification only: a PASS never verifies a control (``shared.aisvs``).
    aisvs: list[Annotated[str, Field(pattern=_AISVS_PATTERN)]] | None = None
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
# Runtime wire shapes - docs/01 §3, docs/04, ADR-0005
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
    audio: bool = False
    # Whether the target takes a `temperature` and a `top_p` (u12 A-68). The one capability that
    # is not false unless set: ``None`` (not declared) is the default rule, under which they are
    # sent except to a model ``adapters.anthropic.MODELS_WITHOUT_SAMPLING`` lists; ``False`` sends
    # neither to any model, ``True`` sends them to a listed one too.
    sampling: bool | None = None
    # Whether the target is an MCP server (OD-44, decided 2026-10-11 under the owner's
    # delegation): true exactly when its ``provider`` is ``mcp``, which the target loader sets;
    # an offline mock may declare it, a live target of another provider may not. A spec that
    # reads the MCP adapter's rendering of a server's advertised surface requires it, so it is not
    # sent to a chat model as a prompt.
    mcp: bool = False


class SeededSetup(_Frozen):
    """What the operator has seeded into a deployed application (OD-18 option B, ADR-0009).

    ``specs`` names the specs (ids or ``fnmatch`` globs) whose documents, tools and memory the
    operator has put into the deployment. ``tools`` maps a spec's tool name to the name the
    deployment calls it, so a call under the deployment's own name is judged as the spec's tool.
    ``granted_tools`` names the deployment's own tools outside any spec's scene (a search, an
    escalation), which it may call without that being an unauthorized call; what such a call
    carries is still judged, and a name that is one of a spec's own scene tools is not granted
    for that spec. ``run_token`` replaces ``{{run_id}}`` in a seeded spec: the operator seeds the
    scene before the run, so its canary cannot carry the per-run id. ``canary_prefix`` (u08
    A-100, OD-58), which needs ``run_token``, replaces ``{{canary_prefix}}`` in those canaries;
    left out, the prefix is derived from the binding (``shared.canary.derived_prefix``), as
    stable as the token. Unset, it is left out of a dump, as ``not_destructive`` is.

    ``not_destructive`` names the granted tools the operator's file declares not destructive,
    each written there as a ``granted_tools`` entry ``{name: <tool>, destructive: false}``
    (owner decision OD-43, u06 A-72): a hand-off such as ``transfer_to_billing_agent`` is then
    not failed by its name alone. Always a subset of ``granted_tools`` (refused otherwise,
    however the setup is built), kept sorted and once each, by exact name; it clears only
    ``tool_call``'s destructive check, never for a tool of a spec's own scene, and every report
    and the run store say it was declared. Empty, it is left out of a dump, so a report of a
    target that declares nothing is byte for byte what it was before the field existed.
    """

    specs: list[str] = Field(default_factory=list)
    tools: dict[str, str] = Field(default_factory=dict)
    granted_tools: list[str] = Field(default_factory=list)
    run_token: str | None = None
    not_destructive: list[str] = Field(default_factory=list)
    canary_prefix: str | None = None

    @field_validator("not_destructive")
    @classmethod
    def _sorted_once(cls, names: list[str]) -> list[str]:
        # Sorted here rather than refused out of order: a report's redactor masks a name that
        # reads as a secret, which can change where it sorts in the masked copy it validates.
        return sorted(set(names))

    @model_validator(mode="after")
    def _declared_are_granted(self) -> SeededSetup:
        stray = sorted(set(self.not_destructive) - set(self.granted_tools))
        if stray:
            raise ValueError(
                "seeded_setup.not_destructive names a tool not in granted_tools: "
                f"{', '.join(stray)}; only a granted tool may be declared not destructive"
            )
        return self

    @model_validator(mode="after")
    def _prefix_with_a_token(self) -> SeededSetup:
        if self.canary_prefix is not None and not self.run_token:
            raise ValueError(
                "seeded_setup.canary_prefix needs seeded_setup.run_token: it replaces "
                "{{canary_prefix}} only in the canaries the run token binds"
            )
        return self

    @model_serializer(mode="wrap")
    def _without_an_empty_declaration(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        """The dump as before OD-43 (and A-100) when the file declares neither field."""

        dumped: dict[str, Any] = handler(self)
        if not dumped.get("not_destructive"):
            dumped.pop("not_destructive", None)
        if dumped.get("canary_prefix") is None:
            dumped.pop("canary_prefix", None)
        return dumped


class WebSocketExpect(_Frozen):
    """A predicate over one received frame: the value at ``path`` equals ``equals``.

    With ``equals`` left out, the frame satisfies it when ``path`` is present (not null).
    """

    path: Annotated[str, Field(min_length=1)]
    equals: str | int | float | bool | None = None


class WebSocketHandshake(_Frozen):
    """The first frame sent after the socket opens, and what its reply must say.

    ``send`` is a JSON template: static fields plus ``{{token}}`` (the credential ``auth_ref``
    resolves to, inserted in memory at send time and recorded as the placeholder) and any
    ``{{name}}`` declared under ``websocket.vars``.
    """

    send: JsonDict
    expect: WebSocketExpect | None = None


class WebSocketMessage(_Frozen):
    """The frame that carries one query: a JSON template with ``{{prompt}}`` in it."""

    send: JsonDict


class WebSocketResponse(_Frozen):
    """How a streamed reply is read: where the text is, what ends the turn, what to ignore.

    ``final_value`` left out means the turn ends on the first frame where ``final_path`` is
    present. ``ignore_types`` names the values of ``type_path`` that are discarded (pings,
    typing indicators). ``error_path`` present in a frame makes the attempt inconclusive.
    ``tool_calls_path`` is read only when declared: without it the adapter reads no tool calls,
    and a seeded spec judged on its tool trace is not sent (OD-18 B).
    """

    # `model_path` starts with `model_`, which pydantic before 2.10 protects by default and warns
    # about at import, on every command (the `floors` CI job, pydantic 2.6.0: a subprocess printed
    # the warning before its output; u12 A-84). Only the two prefixes 2.10 protects are protected
    # here, so every supported pydantic is quiet and `model_validate*`/`model_dump*` stay guarded.
    model_config = ConfigDict(protected_namespaces=("model_validate", "model_dump"))

    text_path: Annotated[str, Field(min_length=1)]
    final_path: Annotated[str, Field(min_length=1)]
    final_value: str | int | float | bool | None = None
    type_path: Annotated[str, Field(min_length=1)] = "type"
    ignore_types: list[str] = Field(default_factory=list)
    error_path: Annotated[str, Field(min_length=1)] | None = None
    tool_calls_path: Annotated[str, Field(min_length=1)] | None = None
    usage_path: Annotated[str, Field(min_length=1)] | None = None
    model_path: Annotated[str, Field(min_length=1)] | None = None
    id_path: Annotated[str, Field(min_length=1)] | None = None
    timeout_seconds: Annotated[float, Field(gt=0.0, le=600.0, allow_inf_nan=False)] = 30.0
    #: The stop reasons the endpoint writes at ``final_path`` when a provider's filter acted on
    #: the reply (u04 A-79, the amendment to OD-42): each one a provider documents for its own
    #: filter (``shared.filter_stops``), in the spelling the endpoint sends. None by default: a
    #: socket's final value is the operator's wire shape, and a filter word there is read as the
    #: filter's only when the file says the endpoint relays one.
    filter_stops: list[str] = Field(default_factory=list)

    @field_validator("final_value", mode="before")
    @classmethod
    def _final_value_is_finite(cls, value: object) -> object:
        """A NaN never equals a frame's value, so the turn would wait out its timeout; an
        infinity is no JSON number a server writes (u12 A-82, CLI audit M6)."""

        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("final_value must be a finite number when it is a number")
        return value

    @field_validator("filter_stops")
    @classmethod
    def _documented_filter_stops(cls, value: list[str]) -> list[str]:
        """Each one a provider documents for its own filter, trimmed and in lower case, once."""

        return sorted(documented_stops(value))

    @model_validator(mode="after")
    def _filter_stops_need_a_read_final_value(self) -> WebSocketResponse:
        """A turn that ends on ``final_value`` always stops with it: no filter stop is read."""

        if self.filter_stops and self.final_value is not None:
            raise ValueError(
                "response.filter_stops needs final_value left out: a turn ends on the frame where "
                "final_path equals final_value, so that value is the only stop it can read"
            )
        return self

    @model_serializer(mode="wrap")
    def _without_undeclared_filter_stops(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        """The dump as before A-79 when the file declares no filter stop."""

        dumped: dict[str, Any] = handler(self)
        if not dumped.get("filter_stops"):
            dumped.pop("filter_stops", None)
        return dumped


class WebSocketSession(_Frozen):
    """A conversation's start: a frame sent once per connection, after the handshake.

    ``one_query_in_flight`` is the only policy: one query at a time per connection, one
    connection per conversation. ``false`` (several queries multiplexed on one socket, which
    needs a correlation id) is refused by the loader, by design (OD-35, decided 2026-10-11).
    """

    start: JsonDict | None = None
    expect: WebSocketExpect | None = None
    one_query_in_flight: bool = True


class WebSocketReconnect(_Frozen):
    """How many more times a connection that fails to open is tried (bounded)."""

    max_attempts: Annotated[int, Field(ge=0, le=5)] = 1


class WebSocketGuardEndpoint(_Frozen):
    """The scheme and exact path the endpoint must have: the loader refuses any other.

    ``ws``/``wss`` for a ``websocket.guard``, ``http``/``https`` for a ``rest.guard`` (u04 A-98);
    a scheme of the other transport never matches the endpoint, so the loader refuses it.
    """

    scheme: Literal["ws", "wss", "http", "https"] | None = None
    path: Annotated[str, Field(min_length=1, pattern=r"\A/")] | None = None


class WebSocketGuardAuth(_Frozen):
    """What an authentication failure looks like, and how long the agent is left alone after.

    An upgrade refused with HTTP 401 or 403, and a handshake reply that does not satisfy
    ``handshake.expect``, are failures whatever this block says; ``failure_codes`` adds the values
    an error frame carries at ``code_path`` (in the handshake or in a turn) that mean the same.
    """

    code_path: Annotated[str, Field(min_length=1)] | None = None
    failure_codes: list[Annotated[str, Field(min_length=1)]] = Field(default_factory=list)
    cooldown_seconds: Annotated[float, Field(ge=0.0, le=86400.0, allow_inf_nan=False)] = 120.0

    @model_validator(mode="after")
    def _codes_need_a_path(self) -> WebSocketGuardAuth:
        """A code is read at ``code_path``: one without the other reads nothing."""

        if bool(self.failure_codes) != (self.code_path is not None):
            raise ValueError("guard.auth.failure_codes and guard.auth.code_path go together")
        return self


class WebSocketGuardToken(_Frozen):
    """What the credential must say before it is sent, read from its JWT payload unverified.

    ``tenant`` (a value, or ``{{name}}`` from ``websocket.vars``) must be the value of the first
    of ``tenant_claims`` the token carries, and the token must have an ``exp`` at least
    ``min_lifetime_seconds`` away. ``reply_tenant_path`` is where the handshake reply names the
    tenant it authenticated: when present there, it must be the same one.
    """

    tenant: Annotated[str, Field(min_length=1)]
    tenant_claims: Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)]
    reply_tenant_path: Annotated[str, Field(min_length=1)] | None = None
    min_lifetime_seconds: Annotated[float, Field(ge=0.0, le=86400.0, allow_inf_nan=False)] = 30.0


class WebSocketGuardPacing(_Frozen):
    """The pace of queries to the agent, kept across processes in the guard's state file."""

    min_interval_seconds: Annotated[float, Field(ge=0.0, le=3600.0, allow_inf_nan=False)] = 0.0
    max_per_hour: Annotated[int, Field(ge=1, le=100000)] | None = None


class WebSocketGuardStopOnTools(_Frozen):
    """The tool or agent names that, reported by the target at ``path`` in any frame of a turn,
    close the connection at once."""

    path: Annotated[str, Field(min_length=1)]
    names: Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)]


#: The days a ``guard.window`` names, Monday first (``datetime.weekday()`` order).
GUARD_DAYS: tuple[str, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_CLOCK = re.compile(r"\A([01]\d|2[0-3]):([0-5]\d)\Z")


def _clock_minutes(value: str, *, end: bool) -> int:
    """``HH:MM`` as minutes after midnight; ``24:00`` only as an end (the end of the day)."""

    if end and value == "24:00":
        return 24 * 60
    match = _CLOCK.match(value)
    if match is None:
        raise ValueError(f"{value!r} is not a time of day written HH:MM (00:00 to 23:59)")
    return int(match.group(1)) * 60 + int(match.group(2))


class WebSocketGuardWindow(_Frozen):
    """When the agent may be queried: the days and the hours of a rules-of-engagement window.

    ``timezone`` is an IANA zone (``Europe/Madrid``, ``UTC``), always written: the operator's
    clock and the agent's may not agree, and a window read in the wrong zone sends traffic hours
    outside it. ``days`` lists day names (``mon`` .. ``sun``) or ranges of them (``mon-fri``,
    never wrapping past ``sun``). ``start`` is inclusive and ``end`` exclusive, ``HH:MM``;
    ``end`` may be ``24:00``. An ``end`` earlier than ``start`` is a window across midnight that
    opens on each listed day and closes the next morning. Outside it nothing is sent (u04 A-98).
    """

    timezone: Annotated[str, Field(min_length=1)]
    days: Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)]
    start: Annotated[str, Field(min_length=1)]
    end: Annotated[str, Field(min_length=1)]

    @field_validator("timezone")
    @classmethod
    def _an_iana_zone(cls, value: str) -> str:
        """A zone the tz database names; ``local`` and offsets are not zones."""

        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"{value!r} is not an IANA time zone (Europe/Madrid, UTC)") from exc
        return value

    @field_validator("start", "end", mode="before")
    @classmethod
    def _a_quoted_time(cls, value: object) -> object:
        """YAML 1.1 reads an unquoted ``19:00`` as the number 1140: say so rather than guess."""

        if isinstance(value, int) and not isinstance(value, bool):
            raise ValueError(
                f"read as the number {value}: write the time quoted, as '19:00' (unquoted, "
                "YAML reads a time after 09:59 as a count of minutes)"
            )
        return value

    @field_validator("days")
    @classmethod
    def _known_days(cls, value: list[str]) -> list[str]:
        """Each entry a day name or a range of them, read in lower case."""

        for entry in value:
            parts = entry.strip().lower().split("-")
            if len(parts) > 2 or any(part not in GUARD_DAYS for part in parts):
                raise ValueError(
                    f"{entry!r} is not a day ({', '.join(GUARD_DAYS)}) or a range of them (mon-fri)"
                )
            if len(parts) == 2 and GUARD_DAYS.index(parts[0]) > GUARD_DAYS.index(parts[1]):
                raise ValueError(f"the range {entry!r} wraps past sun; list it as two entries")
        return value

    @model_validator(mode="after")
    def _a_real_window(self) -> WebSocketGuardWindow:
        """Both times read, and a window that is not empty."""

        if _clock_minutes(self.start, end=False) == _clock_minutes(self.end, end=True):
            raise ValueError("guard.window.start and guard.window.end are the same time")
        return self

    @property
    def weekdays(self) -> frozenset[int]:
        """The listed days as ``datetime.weekday()`` numbers."""

        found: set[int] = set()
        for entry in self.days:
            parts = entry.strip().lower().split("-")
            first, last = GUARD_DAYS.index(parts[0]), GUARD_DAYS.index(parts[-1])
            found.update(range(first, last + 1))
        return frozenset(found)

    @property
    def start_minutes(self) -> int:
        """``start`` as minutes after midnight."""

        return _clock_minutes(self.start, end=False)

    @property
    def end_minutes(self) -> int:
        """``end`` as minutes after midnight (1440 for ``24:00``)."""

        return _clock_minutes(self.end, end=True)


class WebSocketGuard(_Frozen):
    """The ``guard`` block of a deployed agent: what keeps a scan polite and contained.

    Read under ``websocket.guard`` and, for a ``provider: rest`` target, under ``rest.guard``
    (u04 A-98). Every part is optional. With the block present, an authentication failure stops
    the run and the agent is left alone for ``auth.cooldown_seconds``, in this process and in the
    next one (the guard's state file, which keeps the sha256 of a refused credential, never the
    value); with a ``window``, nothing is sent outside it.
    """

    endpoint: WebSocketGuardEndpoint | None = None
    auth: WebSocketGuardAuth = Field(default_factory=WebSocketGuardAuth)
    token: WebSocketGuardToken | None = None
    pacing: WebSocketGuardPacing | None = None
    window: WebSocketGuardWindow | None = None
    stop_on_tools: WebSocketGuardStopOnTools | None = None
    max_response_bytes: Annotated[int, Field(ge=1)] | None = None


class RestSpec(_Frozen):
    """The ``rest:`` block of a ``provider: rest`` target: today its ``guard`` alone (u04 A-98).

    The reply shape of a target file's REST target is the generic one (the text at ``text``);
    this block adds what a deployed agent behind plain HTTP needs, the same ``guard`` a
    WebSocket target declares. An HTTP 401 or 403 is an authentication failure; ``auth.code_path``
    and ``stop_on_tools.path`` are read in the JSON reply body.
    """

    guard: WebSocketGuard | None = None


class WebSocketSpec(_Frozen):
    """The ``websocket:`` block of a ``provider: websocket`` target (``docs/MANUAL.md`` §4.2).

    A JSON-over-WebSocket chat endpoint has no standard wire shape, so the operator declares
    it: the handshake, the query frame, how the streamed reply is read, the session start and
    the reconnect cap. ``headers`` go on the HTTP upgrade request (``{{token}}`` allowed);
    ``vars`` are plain values the templates may reference as ``{{name}}``, never secrets.
    """

    message: WebSocketMessage
    response: WebSocketResponse
    handshake: WebSocketHandshake | None = None
    session: WebSocketSession = Field(default_factory=WebSocketSession)
    reconnect: WebSocketReconnect = Field(default_factory=WebSocketReconnect)
    headers: dict[str, str] = Field(default_factory=dict)
    vars: dict[str, str] = Field(default_factory=dict)
    guard: WebSocketGuard | None = None


class Target(_Frozen):
    """A target under test (id + type + declared capabilities).

    ``provider``/``endpoint``/``model``/``auth_ref``/``sampling_defaults`` are the
    optional **live-target** fields a real ``target.yaml`` declares (``docs/09``,
    ``examples/target.example-openai.yaml``) so the u12 composition root can route a
    non-mock target to the correct over-the-wire adapter (u04) without a second
    parse of the file. ``auth_ref`` is a reference (e.g. ``env://NAME``), never an
    inline secret (S6); it is resolved to a value only at send time, in ``cli``.
    All five stay ``None`` for a mock/offline target (contract §4 KEEP: additive,
    optional fields - no change to existing mock behavior).
    """

    # A refusal never quotes what was written (A-53): pydantic's own text would, after the
    # message, and a Target carries an endpoint that may hold a password.
    model_config = ConfigDict(hide_input_in_errors=True)

    id: str
    type: TargetType
    capabilities: Capabilities = Field(default_factory=Capabilities)
    name: str | None = None
    provider: str | None = None
    endpoint: str | None = None
    model: str | None = None
    auth_ref: str | None = None
    sampling_defaults: Sampling | None = None
    # MCP transport selector (provider "mcp"): "http" (default, over the wire) or "stdio" (a
    # local server launched as a subprocess). ``command`` is the argv for the stdio case; it
    # is spawned only if the scope's target authorized that exact command line.
    transport: str | None = None
    command: list[str] | None = None
    # OD-18 option B: what a deployed application's operator has seeded (``None``: nothing).
    seeded_setup: SeededSetup | None = None
    # The wire shape of a ``provider: websocket`` target (``None`` for every other provider).
    websocket: WebSocketSpec | None = None
    # A ``provider: rest`` target's guard (u04 A-98; ``None`` for every other provider).
    rest: RestSpec | None = None
    # The provider filter stops an ``openai`` or ``anthropic`` target's adapter reads, when its
    # file says (u04 A-79): ``[]`` for an endpoint that speaks the provider's API and has no such
    # filter behind it, so its stops on a reply with text or a tool call, and Azure's HTTP 400,
    # are not read as a filter's (an empty reply on the provider's own word still is). ``None``:
    # the provider's own. Its own word or nothing, checked here for every path (below) and by the
    # loader first (``cli.wiring``, which names the file); left out of a dump when ``None``.
    filter_stops: list[str] | None = None

    @field_validator("filter_stops")
    @classmethod
    def _the_providers_own_filter_stops(
        cls, value: list[str] | None, info: ValidationInfo
    ) -> list[str] | None:
        """The provider's own word, or nothing, trimmed, in lower case and sorted (u04 A-79).

        ``shared.filter_stops.target_filter_stops``, the loader's rule: until the pre-merge audit
        of ``10cb526b`` (LOW) only the loader applied it, so ``Target(provider="openai",
        filter_stops=["refusal", "guardrail_intervened"])`` built an adapter that read those two
        as OpenAI's filter. ``provider`` is declared above, so it is validated before this; when
        it failed, it is not in ``info.data`` and this check is left out, so its own error is the
        only one (pre-merge audit of ``e1a8aacf``, LOW 3: a second, misleading one said the field
        was for an openai or anthropic target).
        """

        if value is None or "provider" not in info.data:
            return value
        return sorted(target_filter_stops(info.data["provider"], value))

    @model_serializer(mode="wrap")
    def _without_an_undeclared_filter(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, Any]:
        """The dump as before A-79 when the file does not declare ``filter_stops``."""

        dumped: dict[str, Any] = handler(self)
        if dumped.get("filter_stops") is None:
            dumped.pop("filter_stops", None)
        return dumped


class TokenLogprob(_Frozen):
    """Provider-neutral token logprob (ADR-0005).

    ``top`` stays ``list[tuple[str, float]] | None`` (OD-1); byte offsets dropped MVP-1.
    """

    token: str
    logprob: float
    top: list[tuple[str, float]] | None = None


class ModelRequest(_Frozen):
    """A single request to a ``TargetAdapter`` (``docs/01 §3``).

    ``media`` carries the declarative multimodal parts verbatim from ``attack.media`` (additive,
    optional). It stays declarative on the request so a stored run re-renders to identical bytes
    on replay; the adapter renders each part (``shared.media``) into the provider image block.
    """

    prompt: str | None = None
    messages: list[JsonDict] | None = None
    system_prompt: str | None = None
    tools: list[JsonDict] | None = None
    sampling: Sampling | None = None
    identity: str | None = None  # for multi_identity authz specs
    media: list[JsonDict] | None = None  # for multimodal specs (declarative parts)
    metadata: JsonDict | None = None


class ModelResponse(_Frozen):
    """A target response (``docs/01 §3``, contract §6).

    ``logprobs is None`` when the target lacks the logprobs capability (ADR-0005). ``raw_ids``
    holds what a transport returns beyond these fields: scalars at the top (a request id, a model
    echo) and a transport's record under its own key, such as the WebSocket frame transcript in
    ``raw_ids["websocket"]["frames"]`` (OD-34: no field of its own, decided 2026-10-11), beside
    the frame fields its target file declares as the protocol's, ``protocol_paths`` (A-77).

    ``filter_side`` is the side the provider's own trace says its filter acted on, for a reply
    stopped by that filter (OD-42, u00 and u08 A-70): ``input`` (the prompt was blocked),
    ``output`` (the model's reply was), or ``unknown`` (a trace that names neither). Only the
    REST adapter sets it, from a Bedrock Converse guardrail trace; every other reply leaves it
    ``None`` and ``shared.provider_filter`` reads the side from the stop reason. A ``None`` is
    left out of a dump, so a reply without one is stored, reported and hashed byte for byte as
    before the field existed.

    ``foreign_stop`` is ``True`` when ``finish_reason`` is some provider's filter word that the
    target's own provider does not document, or its target file does not declare (u00 and u04
    A-79, the amendment to OD-42): ``refusal`` from an OpenAI-compatible endpoint, say. The
    adapter that read the reply sets it (``shared.provider_filter.stop_provenance``); the stop is
    kept as sent, as evidence, and read as an ordinary one, so the reply is the model's answer.
    ``False`` is left out of a dump, so every other reply is stored, reported and hashed as before.
    """

    text: str
    tool_calls: list[JsonDict] = Field(default_factory=list)
    logprobs: list[TokenLogprob] | None = None
    finish_reason: str | None = None
    raw_ids: JsonDict = Field(default_factory=dict)
    usage: JsonDict | None = None
    filter_side: Literal["input", "output", "unknown"] | None = None
    foreign_stop: bool = False

    @model_serializer(mode="wrap")
    def _without_unset_filter_side(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """The dump as before OD-42 when no trace said which side a filter acted on, and as
        before A-79 when the stop is not another provider's filter word."""

        dumped: dict[str, Any] = handler(self)
        if dumped.get("filter_side") is None:
            dumped.pop("filter_side", None)
        if not dumped.get("foreign_stop"):
            dumped.pop("foreign_stop", None)
        return dumped


class Verdict(_Frozen):
    """Evaluator output (``docs/04 §1-§3``, contract §6).

    ``inconclusive_reason`` is set only when ``status == inconclusive``.

    ``operator_cleared`` names the called tools only the target file's declaration kept from
    being judged destructive (OD-43, u06 A-72): ``tool_call`` sets it on its verdict and the
    runner on the attempt's aggregate, beside the note in ``reasoning``, and the reports count
    from it, never from the text, which a judge or a tool's name can echo. Empty, it is left out
    of a dump, so every other verdict is stored, reported and hashed byte for byte as before.

    ``echo_only`` marks a fail that rests only on a canary the identity sweep's request carries
    (u08 A-85): the reply may only quote the request, or may hold the other identity's data, so
    the fail is reported, counted and gated with ``--include-needs-review``, and never confirms a
    finding on its own, as a fail the judge alone reported (u08 A-79). ``authz_leak`` sets it,
    the aggregate keeps it when every deterministic fail it combined has it. ``False`` is left
    out of a dump, as an empty ``operator_cleared`` is, so every other verdict is stored,
    reported and hashed as before.
    """

    status: VerdictStatus
    confidence: Unit
    reasoning: str
    matched: list[str] = Field(default_factory=list)
    evaluator_type: str
    inconclusive_reason: InconclusiveReason | None = None
    operator_cleared: list[str] = Field(default_factory=list)
    echo_only: bool = False

    @model_serializer(mode="wrap")
    def _without_an_empty_clearing(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """The dump as before OD-43 and A-85 when neither field says anything."""

        dumped: dict[str, Any] = handler(self)
        if not dumped.get("operator_cleared"):
            dumped.pop("operator_cleared", None)
        if not dumped.get("echo_only"):
            dumped.pop("echo_only", None)
        return dumped

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
    # Optional canary -> owning identity map (audit M14): lets authz_leak flag a canary that
    # surfaces in a NON-owner identity's response (A receiving B-only data), not just a canary
    # that crosses >=2 identities. Empty = fall back to the strict >=2-crossing check.
    canary_owners: dict[str, str] = Field(default_factory=dict)
    # The request the identity sweep sent each identity (u08 A-85): what the scanner put in front
    # of every one of them, so ``authz_leak`` can tell a canary a reply echoes from that request
    # from one it received. ``None`` when nothing was swept.
    identity_request: ModelRequest | None = None
    # The scope identities the reply under evaluation was received as (u08 A-87): set on every
    # attempt of a spec the identity sweep compares, so ``authz_leak`` reads that attempt's own
    # reply against ``canary_owners`` (the attempts are sent with the target file's credential,
    # which the scope must give one of its identities); empty when that credential is none of
    # theirs. ``None`` for the sweep's own comparison of every identity's reply, or no sweep.
    reply_identities: list[str] | None = None
    # Tool names a seeded deployment grants beyond the spec's scene (OD-18 B,
    # ``seeded_setup.granted_tools``): a call to one is not unauthorized. Empty off a deployment.
    granted_tools: list[str] = Field(default_factory=list)
    # The granted tools the operator's target file declares not destructive (OD-43,
    # ``SeededSetup.not_destructive``): read by ``tool_call`` only, and only for a name granted
    # and in no scene of this spec. Empty off a deployment.
    not_destructive_tools: list[str] = Field(default_factory=list)


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
    # SHA-256 of the scope.yaml body (its checksum line aside) that authorized this invocation,
    # so a report says which authorization record it ran under (threat model S4, audit D-17).
    scope_sha256: str | None = None


# =============================================================================
# Fingerprint + TestPlan - ADR-0006, docs/10
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
    """A selected spec in a ``TestPlan`` (ADR-0006 §3; its per-spec mutators).

    ``baseline_resistance`` was removed on 2026-10-11 (OD-17, ADR-0008 option B, decided under
    the owner's delegation): no fingerprint layer wrote the map it was read from and nothing read
    the field, so every plan said ``null``. It comes back with the layer that measures it.
    """

    spec_id: str
    reason: str
    mutators: list[str] = Field(default_factory=list)


class PlanSkip(_Frozen):
    """A skipped spec + reason (nothing is silently dropped - ``docs/10 §3``)."""

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
