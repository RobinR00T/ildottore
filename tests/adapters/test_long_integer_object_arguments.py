"""Arguments a reply carries as an object read an integer past the digit limit too (u06 A-90).

A-89 read a call's JSON-string arguments holding an integer longer than ``int`` converts
(``sys.get_int_max_str_digits``, 4300 by default). Arguments written as a JSON object are parsed
with the reply itself: Anthropic's ``tool_use`` ``input``, OpenAI's ``function.arguments`` written
as an object, a WebSocket frame's calls. There the same integer made the whole reply unreadable,
``ResponseMalformed``, not evaluated (OD-21), so the verdict on one logical call depended on the
provider's wire shape (MEDIUM-1 of the pre-merge audit of A-89). The reply is now parsed keeping
such an integer as a :class:`~ildottore.shared.toolcalls.LongInteger`, and only inside the
arguments of a call the adapter reads: anywhere else (the text, an id, a stop reason, the usage)
the reply stays unreadable, since a ``LongInteger`` is a ``str`` and a field read as text would
take its digits for the model's words.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest
import respx
from websockets.asyncio.server import ServerConnection

from ildottore.adapters import (
    AnthropicAdapter,
    OpenAIAdapter,
    ResponseMalformed,
    RestAdapter,
    RestTemplate,
    RetryConfig,
)
from ildottore.evaluators.tool_call import ToolCallEvaluator
from ildottore.policy import EndpointAllowlist
from ildottore.shared.enums import EvaluatorType, VerdictStatus
from ildottore.shared.models import EvaluatorConfig, JsonDict, ModelRequest, ModelResponse
from ildottore.shared.toolcalls import (
    LongInteger,
    call_arguments,
    check_long_integers,
    loads_keeping_long_integers,
)
from tests.adapters.test_websocket import _adapter, _spec
from tests.adapters.test_websocket_audit import _query_server
from tests.evaluators.conftest import make_ctx, make_spec

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)
#: The interpreter's floor for the limit: the smallest integer past it is 641 digits.
_LIMIT = 640
_LONG = "9" * (_LIMIT + 1)
#: Written where the long integer goes: ``json.dumps`` refuses to write one past the limit.
_MARK = "@LONG@"
_TOOL = "place_order"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"


@contextmanager
def _digit_limit(limit: int) -> Iterator[None]:
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(limit)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


@pytest.fixture(autouse=True)
def _low_limit() -> Iterator[None]:
    with _digit_limit(_LIMIT):
        yield


def _text(payload: Any) -> str:
    """``payload`` as JSON with every ``"@LONG@"`` written as the long integer, unquoted."""

    return json.dumps(payload).replace(f'"{_MARK}"', _LONG)


def _anthropic_body(**block: object) -> JsonDict:
    tool_use: JsonDict = {"type": "tool_use", "id": "toolu_1", "name": _TOOL, "input": {}}
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": "Placing it."}, {**tool_use, **block}],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


def _openai_body(arguments: object, content: object = None) -> JsonDict:
    call = {"id": "call_1", "type": "function", "function": {"name": _TOOL, "arguments": arguments}}
    message = {"role": "assistant", "content": content, "tool_calls": [call]}
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


async def _send(adapter: Any, url: str, text: str) -> ModelResponse:
    with respx.mock:
        respx.post(url).mock(
            return_value=httpx.Response(
                200, content=text.encode(), headers={"content-type": "application/json"}
            )
        )
        response: ModelResponse = await adapter.send(ModelRequest(prompt="x"))
    return response


def _anthropic(allowlist: EndpointAllowlist) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="a",
        base_url="https://api.anthropic.com",
        allowlist=allowlist,
        api_key="sk-ant-fake-0000000000000000000000",
        model="claude-3-5-sonnet-20241022",
        retry=_FAST,
    )


def _openai(allowlist: EndpointAllowlist) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="o", base_url="https://api.openai.com", allowlist=allowlist, retry=_FAST
    )


async def _status(call: JsonDict, **config: object) -> VerdictStatus:
    spec = make_spec(evaluator_type=EvaluatorType.TOOL_CALL, setup_tools=[{"name": _TOOL}])
    cfg = EvaluatorConfig(type=EvaluatorType.TOOL_CALL, patterns=[_TOOL], **config)
    spec = spec.model_copy(update={"evaluators": [cfg]})
    ctx = make_ctx(tool_calls=[call], config=cfg)
    verdict = await ToolCallEvaluator().evaluate(ctx.model_copy(update={"spec": spec}))
    return verdict.status


# --- Anthropic: ``tool_use`` ``input`` is an object ------------------------------------------


async def test_anthropic_input_with_a_long_integer_is_read_and_judged(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    """The finding: this reply raised ``ResponseMalformed`` and the attempt was not evaluated."""

    body = _text(_anthropic_body(input={"role": "admin", "pad": _MARK}))
    response = await _send(_anthropic(anthropic_allowlist), _ANTHROPIC_URL, body)

    args = call_arguments(response.tool_calls[0])
    assert args["role"] == "admin"
    assert isinstance(args["pad"], LongInteger) and args["pad"] == _LONG
    assert response.text == "Placing it."
    assert await _status(response.tool_calls[0], forbidden_args=["role"]) is VerdictStatus.FAIL
    response.model_dump_json()  # the evidence store writes it: a str, so it serializes


async def test_anthropic_long_integer_nested_in_a_list_of_the_input_is_read(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    body = _text(_anthropic_body(input={"items": [{"qty": _MARK}], "total_cents": 0}))
    response = await _send(_anthropic(anthropic_allowlist), _ANTHROPIC_URL, body)

    assert call_arguments(response.tool_calls[0])["total_cents"] == 0
    zero = {"total_cents": r"^\s*0+\s*$"}
    status = await _status(response.tool_calls[0], forbidden_arg_values=zero)
    assert status is VerdictStatus.FAIL


@pytest.mark.parametrize(
    "where",
    [
        "the usage",
        "a text block",
        "the call's own id",
        "the input itself",
        "a block that is not a tool call",
    ],
)
async def test_anthropic_long_integer_outside_a_calls_input_is_still_unreadable(
    anthropic_allowlist: EndpointAllowlist, where: str
) -> None:
    """A ``LongInteger`` is a ``str``: read as the text, it would be the model's words."""

    payload = _anthropic_body(input={"q": "x"})
    content: list[JsonDict] = payload["content"]  # type: ignore[assignment]
    if where == "the usage":
        payload["usage"] = {"input_tokens": 10, "output_tokens": _MARK}
    elif where == "a text block":
        content[0]["text"] = _MARK
    elif where == "the call's own id":
        content[1]["id"] = _MARK
    elif where == "the input itself":
        content[1]["input"] = _MARK
    else:
        content.append({"type": "server_tool_result", "input": {"pad": _MARK}})
    with pytest.raises(ResponseMalformed, match=r"not valid JSON: .*digits"):
        await _send(_anthropic(anthropic_allowlist), _ANTHROPIC_URL, _text(payload))


# --- OpenAI: ``function.arguments`` written as an object --------------------------------------


async def test_openai_object_arguments_with_a_long_integer_are_read(
    openai_allowlist: EndpointAllowlist,
) -> None:
    body = _text(_openai_body({"total_cents": 0, "pad": _MARK}))
    response = await _send(_openai(openai_allowlist), _OPENAI_URL, body)

    args = call_arguments(response.tool_calls[0])
    assert args["total_cents"] == 0 and isinstance(args["pad"], LongInteger)


async def test_openai_content_that_is_a_long_integer_is_not_read_as_text(
    openai_allowlist: EndpointAllowlist,
) -> None:
    """``content`` must be a string: a ``LongInteger`` is one, so it is refused before."""

    body = _text(_openai_body({"q": "x"}, content=_MARK))
    with pytest.raises(ResponseMalformed, match=r"not valid JSON: .*digits"):
        await _send(_openai(openai_allowlist), _OPENAI_URL, body)


# --- REST: the template reads no tool calls --------------------------------------------------


async def test_rest_long_integer_is_still_unreadable(rest_allowlist: EndpointAllowlist) -> None:
    adapter = RestAdapter(
        id="r",
        base_url="https://llm.example.com",
        allowlist=rest_allowlist,
        api_key="tok-fake-000000000000000000",
        template=RestTemplate(path="/generate", prompt_field="input", text_path="output.answer"),
        retry=_FAST,
    )
    body = _text({"output": {"answer": _MARK}})
    with pytest.raises(ResponseMalformed, match=r"not valid JSON: .*digits"):
        await _send(adapter, "https://llm.example.com/generate", body)


# --- WebSocket: a frame's calls at ``response.tool_calls_path`` -------------------------------


def _frames_server(*frames: str) -> Any:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        for frame in frames:
            await connection.send(frame)

    return _query_server(on_query)


async def test_websocket_frame_call_with_a_long_integer_is_read() -> None:
    call = {"name": _TOOL, "arguments": {"role": "admin", "pad": _MARK}}
    frames = (
        _text({"type": "delta", "delta": {"text": "ok"}}),
        _text({"type": "done", "tool_calls": [call]}),
    )
    spec = _spec(response={"tool_calls_path": "tool_calls"})
    with _frames_server(*frames) as server:
        response = await _adapter(server, spec).send(ModelRequest(prompt="hi"))

    args = call_arguments(response.tool_calls[0])
    assert args["role"] == "admin" and isinstance(args["pad"], LongInteger)
    assert await _status(response.tool_calls[0], forbidden_args=["role"]) is VerdictStatus.FAIL


@pytest.mark.parametrize("declared", [True, False])
async def test_websocket_long_integer_outside_a_frames_calls_is_still_unreadable(
    declared: bool,
) -> None:
    """In the text, or in calls the block declares no path for, the frame stays unreadable."""

    call = {"name": _TOOL, "arguments": {"pad": _MARK}}
    if declared:
        frames = (_text({"type": "delta", "delta": {"text": _MARK}}), _text({"type": "done"}))
        spec = _spec(response={"tool_calls_path": "tool_calls"})
    else:
        frames = (
            _text({"type": "delta", "delta": {"text": "ok"}}),
            _text({"type": "done", "tool_calls": [call]}),
        )
        spec = _spec()
    with _frames_server(*frames) as server, pytest.raises(ResponseMalformed, match="digits"):
        await _adapter(server, spec).send(ModelRequest(prompt="hi"))


# --- the check itself ------------------------------------------------------------------------


def test_the_same_digits_outside_the_arguments_are_refused_by_identity() -> None:
    """The text and an argument hold the same digits: the one in the text is still refused."""

    payload, kept = loads_keeping_long_integers(
        _text({"text": _MARK, "calls": [{"name": _TOOL, "input": {"pad": _MARK}}]})
    )
    assert len(kept) == 2 and kept[0] == kept[1]
    with pytest.raises(ValueError, match="digits"):
        check_long_integers(kept, payload["calls"])
    check_long_integers(kept[1:], payload["calls"])


def test_a_reply_with_no_long_integer_keeps_none() -> None:
    payload, kept = loads_keeping_long_integers(_text({"n": 1, "pad": int("9" * _LIMIT)}))

    assert kept == [] and payload == {"n": 1, "pad": int("9" * _LIMIT)}
