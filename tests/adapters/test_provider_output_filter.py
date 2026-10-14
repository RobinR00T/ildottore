"""The adapters carry a provider's filter stop through, and the REST adapter reads its side (OD-42).

Each shape is the provider's documented one (sourced in ``shared.provider_filter`` and
``adapters.rest``, read 2026-10-11): Azure OpenAI's withheld reply (HTTP 200, ``content: null``,
``finish_reason: content_filter``), Anthropic's ``stop_reason: refusal`` with an empty ``content``
and its ``usage``, Gemini's candidate ``finishReason: SAFETY`` without text, Bedrock Converse's
``stopReason: guardrail_intervened`` with and without ``trace.guardrail``. The side is decided by
``shared.provider_filter.filter_side``, which is tested here on what each adapter returns.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
import respx

from ildottore.adapters import (
    AnthropicAdapter,
    OpenAIAdapter,
    ResponseMalformed,
    RestAdapter,
    RestTemplate,
    RetryConfig,
)
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import ModelRequest, ModelResponse
from ildottore.shared.protocols import TargetAdapter
from ildottore.shared.provider_filter import (
    FILTER_STOPS,
    describe_filter_stop,
    filter_side,
    filter_stop,
    is_filter_stop,
)

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)


def _send(adapter: TargetAdapter, url: str, body: dict[str, Any]) -> ModelResponse:
    async def go() -> ModelResponse:
        with respx.mock:
            respx.post(url).mock(return_value=httpx.Response(200, json=body))
            return await adapter.send(ModelRequest(prompt="hello"))

    return asyncio.run(go())


def _rest(template: RestTemplate) -> RestAdapter:
    return RestAdapter(
        id="rest",
        base_url="https://llm.example.com",
        allowlist=EndpointAllowlist([Endpoint(host="llm.example.com", path_prefixes=["/x"])]),
        template=template,
        retry=_FAST,
    )


_CONVERSE = RestTemplate(
    path="/x",
    prompt_field="input",
    text_path="output.message.content.0.text",
    finish_path="stopReason",
)
_GEMINI = RestTemplate(
    path="/x",
    prompt_field="input",
    text_path="candidates.0.content.parts.0.text",
    finish_path="candidates.0.finishReason",
)


def _converse(stop: str, trace: object = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "output": {"message": {"role": "assistant", "content": [{"text": "Blocked."}]}},
        "stopReason": stop,
    }
    if trace is not None:
        body["trace"] = {"guardrail": trace}
    return body


def _assessment(policy: str, key: str, action: str) -> dict[str, Any]:
    return {policy: {key: [{"action": action}]}}


# --- Azure OpenAI and Anthropic: the stop reason passes through ----------------------------------


def test_azures_withheld_reply_is_an_empty_text_with_its_stop_reason() -> None:
    adapter = OpenAIAdapter(
        id="openai",
        base_url="https://x.openai.azure.com",
        allowlist=EndpointAllowlist([Endpoint(host="x.openai.azure.com", path_prefixes=["/v1"])]),
        api_key="sk-fake-000000000000000000000000",
        model="gpt-4o-mini",
        retry=_FAST,
    )
    body = {
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": None},
                "finish_reason": "content_filter",
                "content_filter_results": {"violence": {"filtered": True, "severity": "high"}},
            }
        ]
    }
    response = _send(adapter, "https://x.openai.azure.com/v1/chat/completions", body)
    assert (response.text, response.finish_reason) == ("", "content_filter")
    assert response.filter_side is None
    assert filter_side(response) == "output"
    assert describe_filter_stop(response) == "stop reason content_filter"


@pytest.mark.parametrize(
    ("content", "usage", "side"),
    [
        ([], {"input_tokens": 412, "output_tokens": 0}, "input"),
        ([{"type": "text", "text": "Here is the first"}], {"output_tokens": 5}, "output"),
        ([], {"input_tokens": 412, "output_tokens": 37}, "output"),
        ([], None, "unknown"),
    ],
    ids=["before-any-output", "after-partial-text", "tokens-without-text", "no-usage"],
)
def test_anthropics_refusal_is_read_by_whether_any_output_came_first(
    content: list[dict[str, Any]], usage: dict[str, Any] | None, side: str
) -> None:
    adapter = AnthropicAdapter(
        id="anthropic",
        base_url="https://api.anthropic.com",
        allowlist=EndpointAllowlist([Endpoint(host="api.anthropic.com", path_prefixes=["/v1"])]),
        api_key="sk-ant-fake-0000000000000000000000",
        model="claude-opus-5-5",
        retry=_FAST,
    )
    body: dict[str, Any] = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "content": content,
        "stop_reason": "refusal",
        "stop_details": {"type": "refusal", "category": "cyber", "explanation": "declined"},
    }
    if usage is not None:
        body["usage"] = usage
    response = _send(adapter, "https://api.anthropic.com/v1/messages", body)
    assert response.finish_reason == "refusal"
    assert filter_side(response) == side


# --- Gemini, through a REST template ------------------------------------------------------------


@pytest.mark.parametrize(
    "stop", ["SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "MODEL_ARMOR", "RECITATION"]
)
def test_a_gemini_candidate_stopped_by_its_filter_without_text_is_a_reply(stop: str) -> None:
    """On main a candidate with no text was a product error, which stopped the campaign.
    ``RECITATION`` too, since the owner's delegated decision of 2026-10-11 (OD-42)."""

    response = _send(
        _rest(_GEMINI), "https://llm.example.com/x", {"candidates": [{"finishReason": stop}]}
    )
    assert (response.text, response.finish_reason) == ("", stop)
    assert filter_side(response) == "output"


def test_a_gemini_candidate_without_text_and_another_stop_is_still_a_malformed_reply() -> None:
    """Not a filter's stop: a body with no text at the template's path, which fails its attempt
    as a ``ResponseMalformed`` since OD-21 (decided 2026-10-11; a product error before)."""

    for stop in ("STOP", "LANGUAGE", "OTHER", "MAX_TOKENS"):
        with pytest.raises(ResponseMalformed, match="response missing text"):
            _send(
                _rest(_GEMINI),
                "https://llm.example.com/x",
                {"candidates": [{"finishReason": stop}]},
            )


def test_a_template_without_a_finish_path_reads_no_stop_as_before() -> None:
    template = RestTemplate(path="/x", prompt_field="input", text_path=_GEMINI.text_path)
    body = {"candidates": [{"finishReason": "SAFETY", "content": {"parts": [{"text": "partial"}]}}]}
    response = _send(_rest(template), "https://llm.example.com/x", body)
    assert (response.text, response.finish_reason) == ("partial", None)
    assert filter_side(response) is None
    with pytest.raises(ResponseMalformed):
        _send(
            _rest(template),
            "https://llm.example.com/x",
            {"candidates": [{"finishReason": "SAFETY"}]},
        )


# --- Bedrock Converse, through a REST template --------------------------------------------------


@pytest.mark.parametrize(
    ("trace", "side"),
    [
        (None, "unknown"),
        ({"inputAssessment": {"g": _assessment("topicPolicy", "topics", "BLOCKED")}}, "input"),
        ({"inputAssessment": {"g": _assessment("wordPolicy", "customWords", "BLOCKED")}}, "input"),
        (
            {"inputAssessment": {"g": _assessment("contentPolicy", "filters", "BLOCKED")}},
            "input",
        ),
        (
            {"outputAssessments": {"g": [_assessment("contentPolicy", "filters", "BLOCKED")]}},
            "output",
        ),
        (
            {
                "outputAssessments": {
                    "g": [_assessment("sensitiveInformationPolicy", "piiEntities", "ANONYMIZED")]
                }
            },
            "output",
        ),
        (
            {
                "outputAssessments": {
                    "g": [_assessment("sensitiveInformationPolicy", "regexes", "BLOCKED")]
                }
            },
            "output",
        ),
        (
            {
                "outputAssessments": {
                    "g": [_assessment("contextualGroundingPolicy", "filters", "BLOCKED")]
                }
            },
            "output",
        ),
        (
            {
                "outputAssessments": {
                    "g": [_assessment("wordPolicy", "managedWordLists", "BLOCKED")]
                }
            },
            "output",
        ),
        (
            # Both: the model wrote a reply, so the output side, whatever the input says.
            {
                "inputAssessment": {"g": _assessment("topicPolicy", "topics", "BLOCKED")},
                "outputAssessments": {"g": [_assessment("topicPolicy", "topics", "BLOCKED")]},
            },
            "output",
        ),
        (
            {
                "inputAssessment": {
                    "g": _assessment("sensitiveInformationPolicy", "piiEntities", "ANONYMIZED")
                }
            },
            "unknown",
        ),
        ({"inputAssessment": {"g": _assessment("topicPolicy", "topics", "NONE")}}, "unknown"),
        ({"inputAssessment": "not an object", "outputAssessments": ["nor this"]}, "unknown"),
        (
            {"inputAssessment": {"g": {"topicPolicy": {"topics": [{"action": ["BLOCKED"]}]}}}},
            "unknown",
        ),
        ("a string", "unknown"),
    ],
    ids=[
        "no-trace",
        "input-topic",
        "input-word",
        "input-content",
        "output-content",
        "output-pii-masked",
        "output-regex",
        "output-grounding",
        "output-managed-word",
        "both",
        "input-masked-only",
        "input-none",
        "malformed",
        "unhashable-action",
        "trace-not-an-object",
    ],
)
def test_a_bedrock_guardrail_trace_says_which_side_it_blocked(trace: object, side: str) -> None:
    response = _send(
        _rest(_CONVERSE), "https://llm.example.com/x", _converse("guardrail_intervened", trace)
    )
    assert (response.text, response.finish_reason) == ("Blocked.", "guardrail_intervened")
    assert filter_side(response) == side
    # The reply says whether a trace was there (L3 of the pre-merge audit of a55e953).
    if isinstance(trace, dict):
        assert response.filter_side == side
    else:
        assert response.filter_side is None


def test_the_guardrail_trace_is_read_only_beside_bedrocks_stop_reason() -> None:
    """A trace in a body whose stop is not ``guardrail_intervened``, or one read by a template
    whose finish path is not the Converse root, is not Bedrock's: no side is taken from it."""

    output = {"outputAssessments": {"g": [_assessment("contentPolicy", "filters", "BLOCKED")]}}
    plain = _send(_rest(_CONVERSE), "https://llm.example.com/x", _converse("end_turn", output))
    assert plain.filter_side is None and filter_side(plain) is None
    other = RestTemplate(
        path="/x",
        prompt_field="input",
        text_path="output.message.content.0.text",
        finish_path="meta.stopReason",
    )
    body = {
        **_converse("guardrail_intervened", output),
        "meta": {"stopReason": "guardrail_intervened"},
    }
    elsewhere = _send(_rest(other), "https://llm.example.com/x", body)
    assert elsewhere.filter_side is None
    # A template in neither Bedrock's nor Gemini's shape reads no provider's filter stop unless it
    # declares one (u04 A-79): Bedrock's word there is an ordinary stop, kept as sent.
    assert elsewhere.foreign_stop is True and filter_side(elsewhere) is None
    declared = RestTemplate(
        path="/x",
        prompt_field="input",
        text_path="output.message.content.0.text",
        finish_path="meta.stopReason",
        filter_stops=frozenset({"guardrail_intervened"}),
    )
    stopped = _send(_rest(declared), "https://llm.example.com/x", body)
    assert stopped.filter_side is None and not stopped.foreign_stop
    assert filter_side(stopped) == "unknown"


def test_content_filtered_has_no_side_bedrock_documents() -> None:
    response = _send(_rest(_CONVERSE), "https://llm.example.com/x", _converse("content_filtered"))
    assert filter_side(response) == "unknown"
    assert describe_filter_stop(response) == "stop reason content_filtered"


# --- the predicate itself -----------------------------------------------------------------------


def test_the_filter_stops_are_the_sourced_ones() -> None:
    assert (
        frozenset(
            {
                "content_filter",
                "refusal",
                "guardrail_intervened",
                "content_filtered",
                "safety",
                "prohibited_content",
                "blocklist",
                "spii",
                "model_armor",
                "recitation",
            }
        )
        == FILTER_STOPS
    )


@pytest.mark.parametrize(
    "stop",
    [None, "", "stop", "end_turn", "length", "max_tokens", "STOP", "LANGUAGE", "OTHER", "final"],
)
def test_a_stop_that_is_no_filters_is_none(stop: str | None) -> None:
    response = ModelResponse(text="", finish_reason=stop)
    assert filter_stop(response) is None
    assert filter_side(response) is None
    assert not is_filter_stop(stop)


def test_a_filter_stop_is_read_trimmed_and_in_any_case() -> None:
    assert (
        filter_stop(ModelResponse(text="", finish_reason="  Content_Filter ")) == "content_filter"
    )
    assert is_filter_stop(" SAFETY")


def test_a_side_on_the_reply_is_only_read_beside_a_filter_stop() -> None:
    """``filter_side`` set on a reply that stopped normally says nothing: no filter stopped it."""

    assert (
        filter_side(ModelResponse(text="x", finish_reason="end_turn", filter_side="output")) is None
    )


@pytest.mark.parametrize(
    ("usage", "side"),
    [
        ({"output_tokens": 0, "iterations": [{"type": "message", "output_tokens": 0}]}, "input"),
        (
            {
                "output_tokens": 0,
                "iterations": [
                    {"type": "message", "input_tokens": 412, "output_tokens": 37},
                    {"type": "fallback_message", "input_tokens": 412, "output_tokens": 0},
                ],
            },
            "output",
        ),
        ({"iterations": [{"type": "message", "output_tokens": 0}]}, "input"),
        ({"iterations": [{"type": "message", "output_tokens": "many"}]}, "unknown"),
        ({"output_tokens": 0, "iterations": "not a list"}, "input"),
    ],
    ids=["all-before-output", "an-earlier-attempt-wrote", "iterations-only", "unreadable", "bad"],
)
def test_a_refusal_after_a_server_side_fallback_reads_every_attempts_output(
    usage: dict[str, Any], side: str
) -> None:
    """With ``fallbacks``, the top-level usage is the last attempt's and ``usage.iterations``
    records each (Anthropic, "Refusals and fallback"): an earlier attempt that wrote output and
    was declined is the output side (pre-merge audit of a55e953, L1)."""

    response = ModelResponse(text="", finish_reason="refusal", usage=usage)
    assert filter_side(response) == side


def test_the_evidence_says_whether_a_guardrail_trace_was_there() -> None:
    masked = {
        "inputAssessment": {
            "g": _assessment("sensitiveInformationPolicy", "piiEntities", "ANONYMIZED")
        }
    }
    with_trace = _send(
        _rest(_CONVERSE), "https://llm.example.com/x", _converse("guardrail_intervened", masked)
    )
    without = _send(
        _rest(_CONVERSE), "https://llm.example.com/x", _converse("guardrail_intervened")
    )
    assert describe_filter_stop(with_trace) == (
        "stop reason guardrail_intervened; the guardrail trace names no blocked prompt and no "
        "blocked or masked reply"
    )
    assert describe_filter_stop(without) == (
        "stop reason guardrail_intervened; no guardrail trace in the reply"
    )
