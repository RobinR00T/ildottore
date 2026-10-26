"""Generic REST adapter over ``httpx`` (u04, contract §5 step 4).

The long-tail escape hatch (ADR-0002): a declarative request/response template
maps a provider-neutral :class:`~ildottore.shared.models.ModelRequest` onto an
arbitrary JSON REST endpoint and pulls the answer back out with a small dotted
JSON-path extractor (list indices supported, e.g. ``choices.0.text``).

Defaults are deliberately conservative: ``logprobs=None`` and ``seed=False``
(contract §5 step 4) - the long tail rarely exposes either, and we never
fabricate them. Auth is **header-only** in MVP-1 to shrink the secret-leak
surface (contract §9); query/body-templated tokens are deferred pending sign-off.

A deployed agent behind plain HTTP declares ``rest.guard`` in its target file, the block a
WebSocket target declares under ``websocket.guard`` (u04 A-98): the same
:class:`~ildottore.adapters.agent_guard.GuardKeeper` checks the endpoint, the credential, the
window and the cooldown before any request, paces every request (a retry included), reads an
HTTP 401 or 403 and a listed error code as an authentication failure, and stops the run on a
listed tool the reply reports.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx

from ildottore.adapters.agent_guard import AgentGuardState, GuardKeeper
from ildottore.adapters.base import MAX_RESPONSE_BYTES, BaseAdapter, ResponseMalformed
from ildottore.adapters.paths import get_path
from ildottore.shared.filter_stops import (
    BEDROCK_FILTER_STOPS,
    GEMINI_FILTER_STOPS,
    NO_FILTER_STOPS,
    documented_stops,
    normalized_stop,
)
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse, WebSocketGuard
from ildottore.shared.provider_filter import INPUT_SIDE, OUTPUT_SIDE, UNKNOWN_SIDE

__all__ = ["RestAdapter", "RestTemplate", "get_path"]

#: The ``PromptFeedback.blockReason`` values both references say blocked the prompt (OD-41):
#: ``SAFETY``, ``OTHER``, ``BLOCKLIST`` and ``PROHIBITED_CONTENT`` in the Gemini API reference
#: (ai.google.dev/api/generate-content, read 2026-10-10) and in Vertex AI's, whose
#: ``BlockedReason`` adds ``MODEL_ARMOR`` ("The prompt was blocked by Model Armor") and
#: ``JAILBREAK`` ("The prompt was blocked as a jailbreak attempt")
#: (docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/GenerateContentResponse,
#: read 2026-10-10). Not ``IMAGE_SAFETY``: Vertex calls it a prompt unsafe for image generation,
#: the Gemini API "Candidates blocked due to unsafe image generation content", and the two do not
#: agree that the prompt was refused; nor either spelling of the unspecified value.
_GEMINI_PROMPT_BLOCKS: frozenset[str] = frozenset(
    {"SAFETY", "OTHER", "BLOCKLIST", "PROHIBITED_CONTENT", "MODEL_ARMOR", "JAILBREAK"}
)
#: Where every Gemini text path starts: ``GenerateContentResponse.candidates`` (both references).
_GEMINI_TEXT_ROOT = "candidates."

#: Amazon Bedrock Converse's stop reason sits at the body's root, beside its guardrail trace
#: (OD-42): the API reference's response syntax, ``stopReason`` and ``trace.guardrail``
#: (docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html, read 2026-10-11).
#: The trace is read only for a template whose ``finish_path`` is this, so a key of that name in
#: another body is not taken for Bedrock's.
_CONVERSE_STOP_PATH = "stopReason"
_GUARDRAIL_INTERVENED = "guardrail_intervened"
#: Where each policy of a ``GuardrailAssessment`` lists what it found, every entry with an
#: ``action`` (the API reference's ``GuardrailAssessment`` and the types it names, read
#: 2026-10-11): ``GuardrailContentFilter``, ``GuardrailTopic``, ``GuardrailCustomWord``,
#: ``GuardrailManagedWord`` and ``GuardrailContextualGroundingFilter`` take ``BLOCKED | NONE``;
#: ``GuardrailPiiEntityFilter`` and ``GuardrailRegexFilter`` take ``ANONYMIZED | BLOCKED | NONE``.
#: The user guide's example of a blocked prompt is ``inputAssessment.<id>.topicPolicy.topics[]``
#: with ``"action": "BLOCKED"`` (docs.aws.amazon.com/bedrock/latest/userguide/
#: guardrails-use-converse-api.html). ``automatedReasoningPolicy`` findings carry no action and
#: are not read.
_GUARDRAIL_POLICIES: tuple[tuple[str, str], ...] = (
    ("contentPolicy", "filters"),
    ("topicPolicy", "topics"),
    ("wordPolicy", "customWords"),
    ("wordPolicy", "managedWordLists"),
    ("sensitiveInformationPolicy", "piiEntities"),
    ("sensitiveInformationPolicy", "regexes"),
    ("contextualGroundingPolicy", "filters"),
)
#: A prompt the guardrail blocked; a reply it blocked or masked (``ANONYMIZED`` rewrote what the
#: model wrote, so the reply is not wholly the model's). A masked prompt is not a blocked one:
#: the model answered it, so with nothing else in the trace the side stays unreported.
_INPUT_ACTIONS: frozenset[str] = frozenset({"BLOCKED"})
_OUTPUT_ACTIONS: frozenset[str] = frozenset({"BLOCKED", "ANONYMIZED"})


@dataclass(frozen=True)
class RestTemplate:
    """Declarative request/response mapping for a generic REST endpoint.

    * ``path`` - endpoint path appended to ``base_url``.
    * ``prompt_field`` - dotted location in the request body to inject the prompt
      (default ``prompt``). System prompt goes to ``system_field`` if set.
    * ``text_path`` - dotted path to the answer text in the response.
    * ``finish_path`` / ``id_path`` / ``usage_path`` - optional response paths.
    * ``static_body`` - fields merged into every request (e.g. ``model``).
    * ``static_headers`` - headers merged into every request.
    * ``filter_stops`` - the stop reasons the endpoint writes at ``finish_path`` when a
      provider's filter acted (u04 A-79), each one a provider documents
      (``shared.filter_stops``). Left ``None``, the template's shape says: one in Bedrock
      Converse's (``finish_path`` ``stopReason``) reads Bedrock's, one in Gemini's (``text_path``
      under ``candidates.``) Gemini's and Vertex AI's, any other none. A filter word the template
      does not read is an ordinary stop (``ModelResponse.foreign_stop``), except its shape's own
      word on a reply with no text, which is that filter's withheld reply whatever is declared
      (:attr:`shape_filter_stops`; pre-merge audit of ``10cb526b``, MEDIUM).
    """

    path: str = "/"
    prompt_field: str = "prompt"
    system_field: str | None = None
    text_path: str = "text"
    finish_path: str | None = None
    id_path: str | None = None
    usage_path: str | None = None
    static_body: Mapping[str, Any] = field(default_factory=dict)
    static_headers: Mapping[str, str] = field(default_factory=dict)
    filter_stops: frozenset[str] | None = None

    def __post_init__(self) -> None:
        # Each one a provider documents, trimmed and in lower case: a typo would leave a filter
        # unread, and a word with no source would have no side (u04 A-79).
        if self.filter_stops is not None:
            object.__setattr__(self, "filter_stops", documented_stops(self.filter_stops))

    @property
    def reads_filter_stops(self) -> frozenset[str]:
        """The stops this template reads as its provider's filter (u04 A-79)."""

        if self.filter_stops is not None:
            return self.filter_stops
        return self.shape_filter_stops

    @property
    def shape_filter_stops(self) -> frozenset[str]:
        """The stops of the provider whose shape the template has, whatever it declares.

        Bedrock's for a ``finish_path`` of ``stopReason``, Gemini's and Vertex AI's for a
        ``text_path`` under ``candidates.``, none otherwise (u04 A-79).
        """

        if self.finish_path == _CONVERSE_STOP_PATH:
            return BEDROCK_FILTER_STOPS
        if self.text_path.startswith(_GEMINI_TEXT_ROOT):
            return GEMINI_FILTER_STOPS
        return NO_FILTER_STOPS


@dataclass
class RestAdapter(BaseAdapter):
    """Template-driven generic REST target (long-tail; ADR-0002)."""

    template: RestTemplate = field(default_factory=RestTemplate)
    # Capabilities are driven entirely by config (contract §5 step 4). Defaults
    # are the conservative long-tail baseline: nothing declared present.
    tools_enabled: bool = False
    rag_enabled: bool = False
    memory_enabled: bool = False
    streaming_enabled: bool = False
    seed_enabled: bool = False
    logprobs_enabled: bool = False
    multi_identity_enabled: bool = False
    multimodal_enabled: bool = False
    #: What to check when no reply reads as the template's, set by whoever built the adapter: a
    #: target file declares no template, so it is not told to check one (OD-21 audit, LOW 2).
    advice: str | None = None
    #: The target file's ``rest.guard`` (u04 A-98), and where it keeps its state, the wall clock
    #: it reads and the sleep it paces with (the last three injected by the tests).
    guard: WebSocketGuard | None = None
    guard_state_dir: Path | None = None
    clock: Callable[[], float] = time.time
    pause: Callable[[float], Awaitable[None]] = asyncio.sleep

    _keeper: GuardKeeper | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.guard is not None:
            url = self._full_url()
            state = AgentGuardState(self.id, url, self.guard, self.guard_state_dir, self.clock)
            tenant = None if self.guard.token is None else self.guard.token.tenant
            self._keeper = GuardKeeper(
                self.id,
                url,
                self.guard,
                state,
                tenant,
                self.clock,
                closed="the run stops after this reply (stopping cannot undo a step already "
                "started)",
            )

    # --- the guard (agent_guard.GuardKeeper, shared with the WebSocket adapter) ------------

    async def send(self, request: ModelRequest) -> ModelResponse:
        """The base send loop, after the guard's checks when the target file declares one.

        The allowlist still runs first: a refused URL reaches neither the guard's state file nor
        the network.
        """

        if self._keeper is not None:
            self._check_allowlist(self._full_url())
            self._keeper.check_before_dial(self.api_key)
        return await super().send(request)

    async def _before_attempt(self) -> None:
        """Pace each request the guard declares a pace for (a retry takes a slot too)."""

        if self._keeper is not None:
            wait = self._keeper.state.reserve()
            if wait > 0.0:
                await self.pause(wait)

    @property
    def _response_cap(self) -> int:
        """The guard's ``max_response_bytes``, when it sets one below the adapter's cap."""

        if self._keeper is None:
            return MAX_RESPONSE_BYTES
        return self._keeper.max_bytes(MAX_RESPONSE_BYTES)

    def _handle_final_response(
        self, response: httpx.Response, raw: bytes, *, body: Mapping[str, Any] | None = None
    ) -> ModelResponse:
        """The guard reads the reply first: an HTTP 401 or 403, or a body carrying a listed
        error code, is an authentication failure; a success body naming another tenant, or a
        tool ``stop_on_tools`` lists, stops the run. Then the base reads it as before."""

        keeper = self._keeper
        if keeper is not None:
            if response.status_code in (401, 403):
                raise keeper.auth_failed(self.api_key, f"HTTP {response.status_code}", refused=True)
            payload = _json_object(raw)
            if payload is not None:
                keeper.check_auth_code(self.api_key, payload)
                if response.is_success:
                    keeper.check_reply_tenant(
                        payload, where="the reply", then="the run stops and the reply is not read"
                    )
                    keeper.check_tools(payload)
        return super()._handle_final_response(response, raw, body=body)

    @property
    def _endpoint_path(self) -> str:
        return self.template.path

    @property
    def filter_stops(self) -> frozenset[str]:
        """The template's (:attr:`RestTemplate.reads_filter_stops`; u04 A-79).

        A target file's ``provider: rest`` target has the generic template, with no
        ``finish_path``, so it reads none: its replies carry no stop at all.
        """

        return self.template.reads_filter_stops

    @property
    def own_filter_stops(self) -> frozenset[str]:
        """The stops of its template's shape (:attr:`RestTemplate.shape_filter_stops`)."""

        return self.template.shape_filter_stops

    @property
    def unreadable_advice(self) -> str:
        """What to check when no reply reads as the template says (OD-21, u08 A-74)."""

        if self.advice is not None:
            return self.advice
        return (
            "check the endpoint and the template's text_path "
            f"({self.template.text_path!r}): the reply's text is read there"
        )

    #: A REST template reads no tool calls from a reply (``tool_calls`` is always empty), so a
    #: seeded spec judged on its tool trace is not sent through it (OD-18 B).
    returns_tool_calls = False

    @property
    def carries_system_prompt(self) -> bool:
        """True when the template has a field for the system prompt (OD-18 memory seed)."""

        return self.template.system_field is not None

    def capabilities(self) -> Capabilities:
        return Capabilities(
            tools=self.tools_enabled,
            rag=self.rag_enabled,
            memory=self.memory_enabled,
            streaming=self.streaming_enabled,
            seed=self.seed_enabled,
            logprobs=self.logprobs_enabled,
            multi_identity=self.multi_identity_enabled,
            multimodal=self.multimodal_enabled,
        )

    def _prompt_text(self, request: ModelRequest) -> str:
        """Pick the prompt text to inject (explicit ``prompt`` wins)."""

        if request.prompt is not None:
            return request.prompt
        if request.messages:
            last = request.messages[-1]
            content = last.get("content") if isinstance(last, Mapping) else None
            if isinstance(content, str):
                return content
        return ""

    def _build_request(self, request: ModelRequest) -> tuple[dict[str, Any], dict[str, str]]:
        body: dict[str, Any] = dict(self.template.static_body)
        body[self.template.prompt_field] = self._prompt_text(request)
        if self.template.system_field is not None and request.system_prompt is not None:
            body[self.template.system_field] = request.system_prompt

        headers: dict[str, str] = {"content-type": "application/json"}
        headers.update(self.template.static_headers)
        # Header-only auth injection (MVP-1, contract §9).
        if self.api_key is not None:
            headers["authorization"] = f"Bearer {self.api_key}"
        return body, headers

    def _prompt_blocked(self, payload: Mapping[str, Any]) -> tuple[str, str] | None:
        """Gemini's prompt block, when a Gemini template's text path finds no text (OD-41).

        The shape, sourced: the Gemini API reference, ``GenerateContentResponse``
        (ai.google.dev/api/generate-content, read 2026-10-10): ``promptFeedback`` "Returns the
        prompt's feedback related to the content filters", and ``PromptFeedback.blockReason``
        "If set, the prompt was blocked and no candidates are returned"; Vertex AI's reference
        says the same of its ``promptFeedback``: it is sent only in the first stream chunk, and
        only when no candidates were generated because of content violations. A blocked prompt is
        a success body with no candidate, so the text path a Gemini template points at
        (``candidates.0.content.parts.0.text``) is absent and the reply was a product error that
        stopped the campaign.

        Recognised: a template whose ``text_path`` starts at ``candidates.``, where both
        references put the text (any other template is not reading a Gemini body, and a
        ``promptFeedback`` key in its reply is not Gemini's, pre-merge audit of ``3d739f3``, L3);
        no text at that path; and a ``blockReason`` in :data:`_GEMINI_PROMPT_BLOCKS`. Anything
        else is a body with no text at the path, a :class:`ResponseMalformed` (it was a product
        error until OD-21). A body with text is a reply whatever else it holds.
        """

        if not self.template.text_path.startswith(_GEMINI_TEXT_ROOT):
            return None
        # A template that reads none of Gemini's filter stops does not speak its filter's
        # vocabulary, and its prompt block is not read either (u04 A-79).
        if not self.filter_stops & GEMINI_FILTER_STOPS:
            return None
        if get_path(payload, self.template.text_path) is not None:
            return None
        reason = get_path(payload, "promptFeedback.blockReason")
        # A string first: the body is the target's, and a list there is unhashable.
        if not isinstance(reason, str) or reason not in _GEMINI_PROMPT_BLOCKS:
            return None
        return "promptFeedback.blockReason", f"promptFeedback.blockReason {reason}"

    @property
    def reads_array_body(self) -> bool:
        """A template whose ``text_path`` starts at an index reads a JSON array (Hugging Face's
        Inference API answers ``[{"generated_text": ...}]``; pre-merge audit of 598f0858, LOW 2)."""

        return self.template.text_path.split(".", 1)[0].lstrip("-").isdigit()

    def _parse_array_response(self, payload: list[Any]) -> ModelResponse:
        return self._parse_body(payload)

    def _parse_response(self, payload: Mapping[str, Any]) -> ModelResponse:
        return self._parse_body(payload)

    def _parse_body(self, payload: Any) -> ModelResponse:
        """The reply read at the template's paths, from an object or, rooted at an index, an
        array (``get_path`` indexes a list)."""

        finish_reason = None
        if self.template.finish_path is not None:
            candidate = get_path(payload, self.template.finish_path)
            if isinstance(candidate, str):
                finish_reason = candidate

        text = get_path(payload, self.template.text_path)
        if (
            text is None
            and normalized_stop(finish_reason) in self.filter_stops | self.own_filter_stops
        ):
            # The provider's filter stopped the reply and left no text (OD-42): a Gemini candidate
            # stopped with ``SAFETY`` can come without its text (Vertex AI's reference, on
            # ``FinishReason`` ``SAFETY``: "When streaming, the content field is empty if
            # content filters block the output", read 2026-10-11). It was a product error that
            # stopped the campaign; it is a reply with no text and that stop reason, which the
            # runner never reads as the model's answer. Read at ``finish_path`` only, as before,
            # and only for a stop the template reads (u04 A-79), or its shape's own word, which on
            # a reply with no text is the filter's whatever is declared: another is no text.
            text = ""
        if text is None:
            raise ResponseMalformed(
                f"{self.id}: response missing text at path {self.template.text_path!r}; "
                "not evaluated"
            )
        if not isinstance(text, str):
            raise ResponseMalformed(f"{self.id}: response text is not a string; not evaluated")

        ids: dict[str, Any] = {}
        if self.template.id_path is not None:
            id_value = get_path(payload, self.template.id_path)
            if id_value is not None:
                ids["id"] = id_value

        usage = None
        if self.template.usage_path is not None:
            usage_value = get_path(payload, self.template.usage_path)
            if isinstance(usage_value, Mapping):
                usage = dict(usage_value)

        return ModelResponse(
            text=text,
            tool_calls=[],
            # Long tail: no logprobs by default (contract §5 step 4).
            logprobs=None,
            finish_reason=finish_reason,
            raw_ids=self._redact_ids(ids),
            usage=usage,
            filter_side=self._guardrail_side(payload, finish_reason),
        )

    def _guardrail_side(
        self, payload: Mapping[str, Any], finish_reason: str | None
    ) -> Literal["input", "output", "unknown"] | None:
        """The side a Bedrock guardrail trace says it blocked, or ``None`` (OD-42, u04 A-70).

        Bedrock Converse answers a guardrail's intervention with HTTP 200, ``stopReason``
        ``guardrail_intervened`` and the guardrail's configured message as the output, for a
        blocked prompt and a blocked reply alike ("Include a guardrail with the Converse API",
        read 2026-10-11). With ``guardrailConfig.trace`` enabled the body carries
        ``trace.guardrail``: ``inputAssessment`` (guardrail id to an assessment) and
        ``outputAssessments`` (guardrail id to a list of them). An output assessment that
        blocked or masked something is the output side, whatever the input one says: the model
        wrote a reply. Otherwise an input assessment that blocked something is the input side.
        A trace that names neither (a masked prompt alone, say) is ``unknown``, and no trace is
        ``None``: the runner reads both as a side the provider did not report, and the evidence
        says which of the two it was (pre-merge audit of ``a55e953``, L3).

        Read only for a template whose ``finish_path`` is the Converse root ``stopReason``.
        """

        if self.template.finish_path != _CONVERSE_STOP_PATH:
            return None
        stop = normalized_stop(finish_reason)
        if stop != _GUARDRAIL_INTERVENED or stop not in self.filter_stops:
            return None
        trace = get_path(payload, "trace.guardrail")
        if not isinstance(trace, Mapping):
            return None
        outputs = trace.get("outputAssessments")
        if isinstance(outputs, Mapping) and any(
            _acted(assessment, _OUTPUT_ACTIONS)
            for listed in outputs.values()
            if isinstance(listed, Sequence) and not isinstance(listed, (str, bytes))
            for assessment in listed
        ):
            return OUTPUT_SIDE
        inputs = trace.get("inputAssessment")
        if isinstance(inputs, Mapping) and any(
            _acted(assessment, _INPUT_ACTIONS) for assessment in inputs.values()
        ):
            return INPUT_SIDE
        return UNKNOWN_SIDE


def _json_object(raw: bytes) -> Mapping[str, Any] | None:
    """The body as a JSON object for the guard to read; ``None`` for anything else.

    A body that is no JSON, no object or nested past the parser's depth is left to the base
    reader, which classifies it as it always has.
    """

    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, Mapping) else None


def _acted(assessment: object, actions: frozenset[str]) -> bool:
    """True when one entry of a ``GuardrailAssessment``'s policies took one of ``actions``."""

    if not isinstance(assessment, Mapping):
        return False
    for policy, key in _GUARDRAIL_POLICIES:
        entries = get_path(assessment, f"{policy}.{key}")
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            continue
        for entry in entries:
            action = entry.get("action") if isinstance(entry, Mapping) else None
            # A string first: the body is the target's, and a list there is unhashable.
            if isinstance(action, str) and action in actions:
                return True
    return False
