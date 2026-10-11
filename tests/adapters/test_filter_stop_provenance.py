"""A stop reason is a filter's only from the provider that documents it (u04 A-79).

Security audit of 2026-10-11, MEDIUM 3: ``shared.provider_filter`` read every provider's filter
vocabulary from every adapter, so an OpenAI-compatible target that answered ``refusal``
(Anthropic's), ``SAFETY`` (Gemini's) or ``guardrail_intervened`` (Bedrock's), or a WebSocket
target whose final frame said ``content_filter``, had its reply scored as a filter's cut and a
judged exploit in it recorded without deciding. The amendment to OD-42 (decided 2026-10-11 under
the owner's delegation, best practice, revisable): each adapter reads its own provider's words
only (OpenAI's ``content_filter``, Anthropic's ``refusal``, a REST template's by its shape or its
declaration, a WebSocket target file's ``response.filter_stops``, default none), and marks any
other filter word ``foreign_stop``: kept as sent, read as an ordinary stop.

Every test here but the controls fails on ``main`` (``de122e26``).
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
import respx
from pydantic import ValidationError

from ildottore.adapters import (
    AnthropicAdapter,
    OpenAIAdapter,
    ResponseMalformed,
    RestAdapter,
    RestTemplate,
    RetryConfig,
)
from ildottore.fingerprint.layers.guardrail import reply_outcome
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import ModelRequest, ModelResponse, WebSocketResponse
from ildottore.shared.protocols import TargetAdapter
from ildottore.shared.provider_filter import FILTER_STOPS, filter_side, filter_stop

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)
_HARMFUL = "Sure, here's how: step 1, cut the backup battery."


def _send(adapter: TargetAdapter, url: str, body: dict[str, Any]) -> ModelResponse:
    async def go() -> ModelResponse:
        with respx.mock:
            respx.post(url).mock(return_value=httpx.Response(200, json=body))
            return await adapter.send(ModelRequest(prompt="hello"))

    return asyncio.run(go())


def _openai(declared: frozenset[str] | None = None) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="openai",
        base_url="https://gw.example.com",
        allowlist=EndpointAllowlist([Endpoint(host="gw.example.com", path_prefixes=["/v1"])]),
        model="m",
        retry=_FAST,
        declared_filter_stops=declared,
    )


def _anthropic(declared: frozenset[str] | None = None) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="anthropic",
        base_url="https://api.anthropic.com",
        allowlist=EndpointAllowlist([Endpoint(host="api.anthropic.com", path_prefixes=["/v1"])]),
        model="claude-stub",
        retry=_FAST,
        declared_filter_stops=declared,
    )


def _rest(template: RestTemplate) -> RestAdapter:
    return RestAdapter(
        id="rest",
        base_url="https://llm.example.com",
        allowlist=EndpointAllowlist([Endpoint(host="llm.example.com", path_prefixes=["/x"])]),
        template=template,
        retry=_FAST,
    )


def _openai_body(text: str | None, finish: str) -> dict[str, Any]:
    return {
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14},
    }


def _anthropic_body(text: str, stop: str) -> dict[str, Any]:
    return {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}] if text else [],
        "stop_reason": stop,
        "usage": {"input_tokens": 5, "output_tokens": 9 if text else 0},
    }


_OPENAI_URL = "https://gw.example.com/v1/chat/completions"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_GEMINI = RestTemplate(
    path="/x",
    prompt_field="input",
    text_path="candidates.0.content.parts.0.text",
    finish_path="candidates.0.finishReason",
)
_CONVERSE = RestTemplate(
    path="/x",
    prompt_field="input",
    text_path="output.message.content.0.text",
    finish_path="stopReason",
)
#: An OpenAI-compatible gateway reached through a REST template: no provider's shape of its own.
_GATEWAY = RestTemplate(
    path="/x",
    prompt_field="input",
    text_path="choices.0.message.content",
    finish_path="choices.0.finish_reason",
)


# --- OpenAI and Anthropic: their own word, and no other provider's ------------------------------


@pytest.mark.parametrize(
    "stop", ["refusal", "SAFETY", "guardrail_intervened", "content_filtered", "RECITATION"]
)
def test_another_providers_filter_word_from_an_openai_target_is_an_ordinary_stop(
    stop: str,
) -> None:
    response = _send(_openai(), _OPENAI_URL, _openai_body(_HARMFUL, stop))
    assert response.finish_reason == stop, "kept as the target sent it"
    assert response.foreign_stop is True
    assert filter_stop(response) is None and filter_side(response) is None
    assert response.model_dump()["foreign_stop"] is True, "stored with the reply, for review"


@pytest.mark.parametrize("stop", ["content_filter", "SAFETY", "guardrail_intervened"])
def test_another_providers_filter_word_from_an_anthropic_target_is_an_ordinary_stop(
    stop: str,
) -> None:
    response = _send(_anthropic(), _ANTHROPIC_URL, _anthropic_body(_HARMFUL, stop))
    assert response.foreign_stop is True
    assert filter_side(response) is None


def test_control_each_providers_own_word_is_still_its_filters() -> None:
    """OD-42 as built for a genuine stop: Azure's withheld reply, Anthropic's refusal."""

    azure = _send(_openai(), _OPENAI_URL, _openai_body(None, "content_filter"))
    assert filter_side(azure) == "output"
    assert "foreign_stop" not in azure.model_dump(), "stored byte for byte as before"
    refused = _send(_anthropic(), _ANTHROPIC_URL, _anthropic_body("", "refusal"))
    assert filter_side(refused) == "input"
    partial = _send(_anthropic(), _ANTHROPIC_URL, _anthropic_body("Here is the first", "refusal"))
    assert filter_side(partial) == "output"


def test_control_an_ordinary_stop_is_not_marked() -> None:
    response = _send(_openai(), _OPENAI_URL, _openai_body("hello", "stop"))
    assert not getattr(response, "foreign_stop", False)
    assert "foreign_stop" not in response.model_dump()


# --- a declaration that leaves the provider's own word out (pre-merge audit of 10cb526b) ------
#
# MEDIUM: ``filter_stops: []`` made Azure's withheld reply (no content, ``content_filter``) the
# model's empty answer, so ``PI-DIRECT-001`` passed and the run exited 0, where without the
# declaration it is cut, ``filtered``, exit 3. A gateway in front of Azure relays that reply. A
# reply with no text and no tool call that ends on the provider's own word is now the filter's
# whatever is declared; one with text or a tool call is the model's, as declared.

_NONE: frozenset[str] = frozenset()


@pytest.mark.parametrize("text", [None, "", "  \n"])
def test_an_empty_reply_on_openais_own_word_is_the_filters_whatever_is_declared(
    text: str | None,
) -> None:
    withheld = _send(_openai(_NONE), _OPENAI_URL, _openai_body(text, "content_filter"))
    assert withheld.foreign_stop is False, "10cb526b: foreign, scored as an empty answer"
    assert filter_side(withheld) == "output", "as without the declaration: the filter's cut"
    assert "foreign_stop" not in withheld.model_dump()


def test_an_empty_refusal_from_an_anthropic_target_is_the_filters_whatever_is_declared() -> None:
    refused = _send(_anthropic(_NONE), _ANTHROPIC_URL, _anthropic_body("", "refusal"))
    assert refused.foreign_stop is False
    assert filter_side(refused) == "input", "as without the declaration: a block"


def test_under_the_declaration_a_reply_with_text_or_a_tool_call_is_still_the_models() -> None:
    cut = _send(_openai(_NONE), _OPENAI_URL, _openai_body(_HARMFUL, "content_filter"))
    assert cut.foreign_stop is True and filter_side(cut) is None
    called = _openai_body(None, "content_filter")
    called["choices"][0]["message"]["tool_calls"] = [
        {"id": "c1", "type": "function", "function": {"name": "send_email", "arguments": "{}"}}
    ]
    acted = _send(_openai(_NONE), _OPENAI_URL, called)
    assert acted.tool_calls and acted.foreign_stop is True and filter_side(acted) is None
    partial = _send(_anthropic(_NONE), _ANTHROPIC_URL, _anthropic_body(_HARMFUL, "refusal"))
    assert partial.foreign_stop is True and filter_side(partial) is None


def test_another_providers_word_on_an_empty_reply_stays_ordinary() -> None:
    """Only the provider's own word: an empty ``refusal`` from an ``openai`` target is not."""

    for declared in (None, _NONE):
        empty = _send(_openai(declared), _OPENAI_URL, _openai_body(None, "refusal"))
        assert empty.foreign_stop is True and filter_side(empty) is None


def test_a_gemini_template_that_declares_none_reads_its_own_word_on_an_empty_reply() -> None:
    """The same rule for a REST template's shape: 10cb526b read the reply as unreadable."""

    template = RestTemplate(
        path=_GEMINI.path,
        prompt_field=_GEMINI.prompt_field,
        text_path=_GEMINI.text_path,
        finish_path=_GEMINI.finish_path,
        filter_stops=frozenset(),
    )
    url = "https://llm.example.com/x"
    withheld = _send(_rest(template), url, {"candidates": [{"finishReason": "SAFETY"}]})
    assert (withheld.text, withheld.foreign_stop) == ("", False)
    assert filter_side(withheld) == "output"
    written = {"candidates": [{"finishReason": "SAFETY", "content": {"parts": [{"text": "x"}]}}]}
    assert _send(_rest(template), url, written).foreign_stop is True


def test_an_adapter_never_reads_another_providers_word_whatever_it_is_given() -> None:
    """Pre-merge audit of ``10cb526b``, LOW: a declaration built past the ``Target`` model's check
    (an adapter made by hand, a ``model_copy``) narrows what the adapter reads, never widens it."""

    from ildottore.cli.wiring import build_real_adapter
    from ildottore.shared.enums import TargetType
    from ildottore.shared.models import Target

    assert _openai(frozenset({"refusal", "guardrail_intervened"})).filter_stops == _NONE
    widened = _anthropic(frozenset({"content_filter", "refusal"}))
    assert widened.filter_stops == frozenset({"refusal"})
    copied = Target(id="t", type=TargetType.CHATBOT, provider="openai").model_copy(
        update={"filter_stops": ["refusal"]}
    )
    adapter = build_real_adapter(copied, EndpointAllowlist([]), api_key=None)
    assert adapter.filter_stops == _NONE  # type: ignore[attr-defined]
    forged = _send(_openai(frozenset({"refusal"})), _OPENAI_URL, _openai_body(_HARMFUL, "refusal"))
    assert forged.foreign_stop is True and filter_side(forged) is None


# --- REST: the template's shape, or its declaration --------------------------------------------


def test_a_rest_template_in_no_providers_shape_reads_no_filter_stop() -> None:
    body = _openai_body(_HARMFUL, "content_filter")
    response = _send(_rest(_GATEWAY), "https://llm.example.com/x", body)
    assert response.foreign_stop is True and filter_side(response) is None
    # With no text and an undeclared word, the body has nothing at the template's text path.
    with pytest.raises(ResponseMalformed, match="response missing text"):
        _send(_rest(_GATEWAY), "https://llm.example.com/x", _openai_body(None, "content_filter"))


def test_a_rest_template_that_declares_a_stop_reads_it() -> None:
    declared = RestTemplate(
        path=_GATEWAY.path,
        prompt_field=_GATEWAY.prompt_field,
        text_path=_GATEWAY.text_path,
        finish_path=_GATEWAY.finish_path,
        filter_stops=frozenset({" Content_Filter "}),
    )
    assert declared.filter_stops == frozenset({"content_filter"}), "trimmed and in lower case"
    withheld = _send(
        _rest(declared), "https://llm.example.com/x", _openai_body(None, "content_filter")
    )
    assert (withheld.text, withheld.foreign_stop) == ("", False)
    assert filter_side(withheld) == "output"


def test_gemini_and_bedrock_templates_read_their_own_providers_words_only() -> None:
    gemini = _send(
        _rest(_GEMINI),
        "https://llm.example.com/x",
        {"candidates": [{"finishReason": "content_filter", "content": {"parts": [{"text": "x"}]}}]},
    )
    assert gemini.foreign_stop is True
    safety = _send(
        _rest(_GEMINI), "https://llm.example.com/x", {"candidates": [{"finishReason": "SAFETY"}]}
    )
    assert filter_side(safety) == "output", "control: Gemini's own"
    converse = {
        "output": {"message": {"role": "assistant", "content": [{"text": _HARMFUL}]}},
        "stopReason": "refusal",
    }
    foreign = _send(_rest(_CONVERSE), "https://llm.example.com/x", converse)
    assert foreign.foreign_stop is True and filter_side(foreign) is None
    converse["stopReason"] = "guardrail_intervened"
    own = _send(_rest(_CONVERSE), "https://llm.example.com/x", converse)
    assert filter_side(own) == "unknown", "control: Bedrock's own, no trace"


def test_a_gemini_template_that_declares_no_gemini_stop_reads_no_prompt_block() -> None:
    template = RestTemplate(
        path=_GEMINI.path,
        prompt_field=_GEMINI.prompt_field,
        text_path=_GEMINI.text_path,
        finish_path=_GEMINI.finish_path,
        filter_stops=frozenset(),
    )
    body = {"promptFeedback": {"blockReason": "SAFETY"}}
    with pytest.raises(ResponseMalformed, match="response missing text"):
        _send(_rest(template), "https://llm.example.com/x", body)


@pytest.mark.parametrize("value", ["stop", "content-filter", "", 3])
def test_a_rest_template_refuses_a_stop_no_provider_documents(value: object) -> None:
    with pytest.raises(ValueError, match="filter stop must be"):
        RestTemplate(filter_stops=frozenset({value}))  # type: ignore[arg-type]


def test_a_target_files_rest_target_reads_no_stop() -> None:
    from ildottore.cli.wiring import build_real_adapter
    from ildottore.shared.enums import TargetType
    from ildottore.shared.models import Target

    target = Target(
        id="t",
        type=TargetType.MODEL,
        provider="rest",
        endpoint="https://llm.example.com/x",
        model="m",
    )
    allow = EndpointAllowlist([Endpoint(host="llm.example.com", path_prefixes=["/x"])])
    adapter = build_real_adapter(target, allow, api_key=None)
    assert adapter.filter_stops == frozenset()  # type: ignore[attr-defined]


# --- WebSocket: what the target file declares, none by default ---------------------------------


async def test_a_websocket_reply_with_an_undeclared_filter_word_is_an_ordinary_stop() -> None:
    from tests.adapters.test_malformed_replies import _ws_turn

    frames = [{"type": "delta", "delta": {"text": _HARMFUL}}, {"finish_reason": "content_filter"}]
    response = await _ws_turn(frames, final_path="finish_reason", final_value=None)
    assert (response.text, response.finish_reason) == (_HARMFUL, "content_filter")
    assert response.foreign_stop is True and filter_side(response) is None
    declared = await _ws_turn(
        frames, final_path="finish_reason", final_value=None, filter_stops=["content_filter"]
    )
    assert not declared.foreign_stop and filter_side(declared) == "output"


def test_a_websocket_target_file_refuses_a_stop_no_provider_documents() -> None:
    with pytest.raises(ValidationError, match="filter stop must be one a provider documents"):
        WebSocketResponse(text_path="t", final_path="f", filter_stops=["moderated"])


def test_a_websocket_target_file_refuses_filter_stops_beside_a_final_value() -> None:
    with pytest.raises(ValidationError, match="needs final_value left out"):
        WebSocketResponse(
            text_path="t", final_path="f", final_value="done", filter_stops=["content_filter"]
        )


def test_a_websocket_declaration_is_normalized_and_left_out_of_a_dump_when_empty() -> None:
    declared = WebSocketResponse(text_path="t", final_path="f", filter_stops=["SAFETY", "safety "])
    assert declared.filter_stops == ["safety"]
    assert "filter_stops" not in WebSocketResponse(text_path="t", final_path="f").model_dump()


# --- the fingerprint reads the same provenance -------------------------------------------------


def test_the_fingerprint_does_not_call_a_foreign_stop_a_filter() -> None:
    stop = sorted(FILTER_STOPS)[0]
    claimed = ModelResponse(text="ok", finish_reason=stop, foreign_stop=True)
    assert reply_outcome(claimed) != "filtered"
    assert reply_outcome(ModelResponse(text="ok", finish_reason=stop)) == "filtered"


def test_a_websocket_targets_advice_names_the_filter_declaration() -> None:
    """Pre-merge audit of a55710e9, LOW 2: a file written before A-79 whose server ends a withheld
    turn on ``content_filter`` now gets unreadable replies (a run of them is unreachable), and
    the advice it is given must name the field that fixes it."""

    from ildottore.adapters import WebSocketAdapter
    from tests.adapters.test_websocket import _spec

    adapter = WebSocketAdapter(
        id="ws", url="ws://127.0.0.1:9/ws/chat", allowlist=EndpointAllowlist([]), spec=_spec()
    )
    assert "response.filter_stops" in adapter.unreadable_advice
