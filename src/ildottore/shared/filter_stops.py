"""The stop reasons each provider documents for its own filter, and who may send them (A-79).

OD-42 read a reply's stop reason against every provider's filter vocabulary at once, from any
adapter: an OpenAI-compatible target that answered ``refusal`` (Anthropic's), ``SAFETY``
(Gemini's) or ``guardrail_intervened`` (Bedrock's) had its reply scored as a filter's cut, and a
judge's verdict on harmful text it wrote was recorded without deciding. A target controls its own
stop reason, so the security audit of 2026-10-11 (MEDIUM 3) found that any target could hide a
judged exploit behind one. Since the amendment to OD-42 (decided 2026-10-11 under the owner's
delegation, best practice, revisable), a stop is a filter's only when it is in the vocabulary of
the provider the target speaks: each adapter says which (``filter_stops``), and a filter stop
outside it is kept as sent and read as an ordinary stop (``ModelResponse.foreign_stop``).

Here, apart from :mod:`ildottore.shared.provider_filter`, so that ``shared.models`` can validate
a target file's declaration against the same values without importing the module that reads the
replies (which imports ``shared.models``). Every value is compared trimmed and in lower case,
whichever adapter carries it as ``finish_reason``: the OpenAI and Anthropic adapters pass the
provider's value through, a REST template reads it at its ``finish_path``, a WebSocket target at
its final frame's path. Each is sourced; the documentation was read on 2026-10-11 unless a line
says otherwise.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Final

__all__ = [
    "ANTHROPIC_FILTER_STOPS",
    "BEDROCK_FILTER_STOPS",
    "FILTER_STOPS",
    "GEMINI_FILTER_STOPS",
    "NO_FILTER_STOPS",
    "OPENAI_FILTER_STOPS",
    "PROVIDER_FILTER_STOPS",
    "documented_stops",
    "normalized_stop",
    "own_filter_stops_of",
    "target_filter_stops",
]

#: OpenAI's and Azure OpenAI's. OpenAI API reference, the Completions object,
#: ``choices[].finish_reason`` (developers.openai.com/api/docs/api-reference/completions/
#: object): "content_filter if content was omitted due to a flag from our content filters".
#: Microsoft Learn, "Content filtering for Microsoft Foundry Models (classic)", "Content
#: filtering scenarios" (learn.microsoft.com/en-us/azure/foundry-classic/foundry-models/concepts/
#: content-filter, updated 2026-09-08): a prompt it filters is an HTTP 400 (OD-41), and
#: "Non-streaming completions calls don't return any content when the content is filtered", with
#: ``finish_reason`` ``content_filter``; "In rare cases with longer responses, a partial result can
#: be returned". So on a 200 it is the reply. The same word is the error code of Azure's 400, which
#: an adapter reads only when it reads this stop (``adapters.base``).
OPENAI_FILTER_STOPS: Final = frozenset({"content_filter"})

#: Gemini API reference, ``GenerateContentResponse``, ``FinishReason``
#: (ai.google.dev/api/generate-content): SAFETY "The response candidate content was flagged for
#: safety reasons"; BLOCKLIST "Token generation stopped because the content contains forbidden
#: terms"; PROHIBITED_CONTENT "Token generation stopped for potentially containing prohibited
#: content"; SPII, the same for "Sensitive Personally Identifiable Information". A prompt Gemini
#: blocks has no candidate at all (``promptFeedback``, OD-41), so a candidate's stop is about what
#: the model generated. Vertex AI's reference, ``FinishReason`` (docs.cloud.google.com/vertex-ai/
#: generative-ai/docs/reference/rest/v1/GenerateContentResponse): MODEL_ARMOR "The model response
#: was blocked by Model Armor". Gemini's RECITATION, "The response candidate content was flagged
#: for recitation reasons" (Gemini API reference), "the content may be a recitation from a
#: source" (Vertex AI's): not a safety filter but a filter on what the model generated, and a
#: training-data extraction spec is about exactly such a reply, so it is a cut like the others:
#: decided under the owner's delegation on 2026-10-11 (OD-42), revisable. A cut, not a fail:
#: ``verbatim_overlap`` still fails when enough of the text came back.
#:
#: Not read, for want of a source that makes them a filter on either side: Gemini's LANGUAGE,
#: OTHER ("Unknown reason"), the IMAGE_* values (image generation, which no spec asks for),
#: ESCALATION ("Request was filtered by an escalation rule", with no word on what was filtered)
#: and PUP_LIMITED_DISABLED (the account, not the content).
GEMINI_FILTER_STOPS: Final = frozenset(
    {"safety", "blocklist", "prohibited_content", "spii", "model_armor", "recitation"}
)

#: Anthropic's ``refusal``: "Refusals and fallback" (platform.claude.com/docs/en/build-with-claude/
#: refusals-and-fallback): "A refusal is a successful HTTP 200 response with stop_reason:
#: "refusal"" from the safety classifiers that "can decline a request"; "A refusal can arrive
#: before any output, or mid-stream after partial output". Which side it acted on is read from the
#: reply (``shared.provider_filter``).
ANTHROPIC_FILTER_STOPS: Final = frozenset({"refusal"})

#: Amazon Bedrock Converse: the API reference (docs.aws.amazon.com/bedrock/latest/APIReference/
#: API_runtime_Converse.html) lists ``guardrail_intervened`` and ``content_filtered`` among the
#: ``stopReason`` values, and the user guide, "Include a guardrail with the Converse API"
#: (docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-converse-api.html), says a
#: guardrail that "detects blocked content" sets ``stopReason`` to ``guardrail_intervened`` and
#: returns "The blocked content text that you have configured in the guardrail" as the output,
#: whether it blocked the prompt or the reply. ``content_filtered`` is listed and not described
#: anywhere AWS publishes that OD-42 found, so its side is unknown.
BEDROCK_FILTER_STOPS: Final = frozenset({"guardrail_intervened", "content_filtered"})

#: What an adapter honours when its provider documents no filter stop, or its target file
#: declares none: a ``provider: rest`` target file (no ``finish_path``, so no stop is read), a
#: WebSocket target file without ``response.filter_stops``, the MCP adapter.
NO_FILTER_STOPS: Final = frozenset[str]()

#: Every stop reason some provider sets when its own filter declined, cut or replaced the reply.
#: ``length`` and ``max_tokens`` (a reply cut at its token cap) are not among them.
FILTER_STOPS: Final = (
    OPENAI_FILTER_STOPS | GEMINI_FILTER_STOPS | ANTHROPIC_FILTER_STOPS | BEDROCK_FILTER_STOPS
)


#: The filter stops each ``provider`` of a target file reads by default, for the two whose file
#: may narrow them with a top-level ``filter_stops`` (u04 A-79): its own word, or nothing. A
#: declaration never takes the word from a reply with no text and no tool call, which is the
#: filter's withheld one (``shared.provider_filter.stop_provenance``). A WebSocket target declares
#: its stops in its block, and a REST one reads none.
PROVIDER_FILTER_STOPS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {"openai": OPENAI_FILTER_STOPS, "anthropic": ANTHROPIC_FILTER_STOPS}
)


def normalized_stop(stop: str | None) -> str:
    """``stop`` as every reader compares it: trimmed and in lower case (``""`` for none)."""

    return (stop or "").strip().lower()


def documented_stops(values: Iterable[object]) -> frozenset[str]:
    """``values`` as stops an adapter honours, each one a provider documents for its filter.

    A declaration (a REST template's ``filter_stops``, a WebSocket target file's
    ``response.filter_stops``) names the stop reasons its endpoint sends when a filter acted, in
    the spelling it sends them; they are compared trimmed and in lower case. A value that is not
    text, or not one of :data:`FILTER_STOPS`, is refused: its side would have no source, and a
    typo would leave a filter unread without a word (u04 A-79).
    """

    honoured: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("a filter stop must be text")
        stop = normalized_stop(value)
        if stop not in FILTER_STOPS:
            raise ValueError(
                "a filter stop must be one a provider documents for its own filter: "
                + ", ".join(sorted(FILTER_STOPS))
            )
        honoured.add(stop)
    return frozenset(honoured)


def own_filter_stops_of(provider: object) -> frozenset[str]:
    """The words a target of ``provider`` may list in its top-level ``filter_stops`` (u04 A-79).

    :data:`PROVIDER_FILTER_STOPS`'s, for an ``openai`` or ``anthropic`` target (compared trimmed
    and in lower case). Any other provider takes no such declaration and is refused; the message
    names the field, never a value (A-53), and its reader adds where it was written.
    """

    lowered = provider.strip().lower() if isinstance(provider, str) else ""
    own = PROVIDER_FILTER_STOPS.get(lowered)
    if own is None:
        raise ValueError(
            "'filter_stops' is for a provider: openai or anthropic target; a websocket target "
            "declares its stops under websocket.response.filter_stops, and a rest target reads none"
        )
    return own


def target_filter_stops(provider: object, values: Iterable[object]) -> frozenset[str]:
    """``values``, a target's top-level ``filter_stops``, as its adapter reads them (u04 A-79).

    Trimmed and in lower case, each one ``provider``'s own word (:func:`own_filter_stops_of`):
    the declaration may only narrow what the adapter reads, to its own word or to nothing, never
    widen it to another provider's. One rule for every path a ``Target`` is built by: the target
    file's loader and the Python API (pre-merge audit of ``10cb526b``, LOW:
    ``Target(provider="openai", filter_stops=["refusal"])`` built an adapter that read
    ``refusal`` as OpenAI's filter). Refused in words that name the field and the provider's own
    word, never a value; ``[]`` is for an endpoint with no provider filter behind it (a gateway in
    front of Azure relays Azure's, MEDIUM of the same audit).
    """

    own = own_filter_stops_of(provider)
    try:
        stops = documented_stops(values)
    except ValueError:
        stops = frozenset({""})
    if not stops <= own:
        raise ValueError(
            f"'filter_stops' may list only the provider's own filter stop "
            f"({', '.join(sorted(own))}), or nothing ([]) for an endpoint with no provider "
            "filter behind it"
        )
    return stops
