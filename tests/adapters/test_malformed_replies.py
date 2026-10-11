"""A success reply the adapter cannot read fails its attempt, not the campaign (OD-21, u04).

Decided 2026-10-11 under the owner's delegation (best practice), revisable. A 200 whose body is
not JSON (brackets that do not balance, an integer of more than 4,300 digits, bytes that are not
text included), not a JSON object, or not the shape the provider or the template declares, and a
WebSocket frame that is binary, not JSON or not an object, or a turn whose frames carry no text,
was an ``AdapterProductError`` and the runner stopped the whole campaign on the first one: one
hostile ``<html>`` reply ended a scan after 1 request (measured on ``main`` at ``6d5f7ae`` through
the CLI, ``tests/cli/test_malformed_reply_campaign.py``). Now each is a ``ResponseMalformed``: an
environment failure that is not retried (``retryable = False``), as a reply nested too deeply is
(#65), carrying the ``malformed_reply`` marker the runner's stop reads (u08 A-74: a campaign whose
first five replies all are unreadable stops, so a wrong endpoint is not an all-inconclusive run).

What stays a product error: a non-retryable 4xx, a JSON-RPC ``error`` an MCP server answers, a
handshake reply that does not satisfy ``expect``: the target answered in its own shape and said no.
"""

from __future__ import annotations

import copy
import json
import pickle
from typing import Any

import httpx
import pytest

from ildottore.adapters import (
    AdapterEnvError,
    AdapterProductError,
    AdapterStatusError,
    MCPAdapter,
    ResponseMalformed,
    RetryConfig,
)
from ildottore.adapters.anthropic import AnthropicAdapter
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.adapters.rest import RestAdapter, RestTemplate
from ildottore.core.execute import default_is_env_error, is_unreadable_reply
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.shared.models import ModelRequest

_FAST = RetryConfig(max_retries=2, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0)
_ALLOW = EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])])


def _client(body: bytes, sends: list[int], status: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sends.append(1)
        return httpx.Response(status, content=body, headers={"content-type": "application/json"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _openai(body: bytes, sends: list[int], status: int = 200) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        api_key="k",
        model="m",
        retry=_FAST,
        client=_client(body, sends, status),
    )


def _anthropic(body: bytes, sends: list[int]) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        api_key="k",
        model="m",
        retry=_FAST,
        client=_client(body, sends),
    )


def _rest(body: bytes, sends: list[int]) -> RestAdapter:
    return RestAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        template=RestTemplate(path="/generate", prompt_field="input", text_path="output"),
        retry=_FAST,
        client=_client(body, sends),
    )


def _is_one_attempt_failure(error: BaseException) -> None:
    """What the runner and the probe pass read: env, not retried, unreadable."""

    assert isinstance(error, ResponseMalformed)
    assert isinstance(error, AdapterEnvError)
    assert not isinstance(error, AdapterProductError)
    assert default_is_env_error(error) is True
    assert getattr(error, "retryable", True) is False
    assert is_unreadable_reply(error) is True
    assert str(error).endswith("; not evaluated")


_NOT_JSON = {
    "html": b"<html><body>Service portal</body></html>",
    "empty": b"",
    "unbalanced": b'{"choices":[{"message":{"content":"hi"}}],"x":' + b"[" * 120,
    "huge integer": b'{"choices":[{"message":{"content":"hi"}}],"n":' + b"7" * 5000 + b"}",
    "not text": b'{"choices": "\xff"}',
}


@pytest.mark.parametrize("case", sorted(_NOT_JSON))
async def test_a_body_that_is_not_json_fails_one_attempt_and_is_sent_once(case: str) -> None:
    sends: list[int] = []
    with pytest.raises(ResponseMalformed, match="not valid JSON") as raised:
        await _openai(_NOT_JSON[case], sends).send(ModelRequest(prompt="hi"))
    _is_one_attempt_failure(raised.value)
    assert sends == [1]


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ([1, 2, 3], "not an object"),
        ({"object": "error"}, "has no choices"),
        ({"choices": []}, "has no choices"),
        ({"choices": ["x"]}, "choice is not an object"),
        ({"choices": [{"text": "hi"}]}, "no message object"),
        ({"choices": [{"message": {"content": ["a", "b"]}}]}, "content is not a string"),
    ],
)
async def test_json_that_is_not_the_openai_shape_fails_one_attempt(body: Any, match: str) -> None:
    sends: list[int] = []
    with pytest.raises(ResponseMalformed, match=match) as raised:
        await _openai(json.dumps(body).encode(), sends).send(ModelRequest(prompt="hi"))
    _is_one_attempt_failure(raised.value)
    assert sends == [1]


async def test_json_that_is_not_the_anthropic_shape_fails_one_attempt() -> None:
    with pytest.raises(ResponseMalformed, match="no content array") as raised:
        await _anthropic(b'{"type": "message"}', []).send(ModelRequest(prompt="hi"))
    _is_one_attempt_failure(raised.value)


@pytest.mark.parametrize(
    ("body", "match"),
    [({"result": "hi"}, "missing text at path"), ({"output": 3}, "text is not a string")],
)
async def test_json_that_is_not_the_template_s_shape_fails_one_attempt(
    body: Any, match: str
) -> None:
    with pytest.raises(ResponseMalformed, match=match) as raised:
        await _rest(json.dumps(body).encode(), []).send(ModelRequest(prompt="hi"))
    _is_one_attempt_failure(raised.value)


async def test_a_refusal_in_the_target_s_own_shape_stays_a_product_error() -> None:
    """A 4xx is the endpoint saying no: it stops the campaign as before (not part of OD-21)."""

    sends: list[int] = []
    with pytest.raises(AdapterStatusError) as raised:
        await _openai(b"<html>forbidden</html>", sends, status=403).send(ModelRequest(prompt="x"))
    assert not isinstance(raised.value, ResponseMalformed)
    assert is_unreadable_reply(raised.value) is False
    assert default_is_env_error(raised.value) is False


def test_the_class_survives_copy_and_pickle_and_keeps_its_marker() -> None:
    error = ResponseMalformed("t1: success response was not valid JSON: x; not evaluated")
    for clone in (copy.copy(error), pickle.loads(pickle.dumps(error))):  # noqa: S301
        assert type(clone) is ResponseMalformed
        assert str(clone) == str(error)
        assert is_unreadable_reply(clone) is True


@pytest.mark.parametrize("marker", [1, "yes", None, False])
def test_only_a_true_marker_reads_as_unreadable(marker: object) -> None:
    error = AdapterEnvError("x")
    error.malformed_reply = marker  # type: ignore[attr-defined]
    assert is_unreadable_reply(error) is False


# --- MCP: the JSON body, the SSE event and the JSON-RPC shape --------------------------------


def _mcp(answer: Any) -> MCPAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        rpc = json.loads(request.content)
        if "id" not in rpc:  # notifications/initialized
            return httpx.Response(202)
        return answer(rpc)

    return MCPAdapter(
        id="mcp-test",
        base_url="https://api.example.test/mcp",
        allowlist=_ALLOW,
        retry=_FAST,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        (
            lambda _rpc: httpx.Response(200, content=b"<html>not mcp</html>"),
            "was not valid JSON",
        ),
        (
            lambda _rpc: httpx.Response(
                200, content=b"event: ping\n\n", headers={"content-type": "text/event-stream"}
            ),
            "carried no data event",
        ),
        (
            lambda rpc: httpx.Response(200, json={"jsonrpc": "2.0", "id": rpc["id"]}),
            "returned no result object",
        ),
    ],
)
async def test_an_mcp_reply_that_is_not_json_rpc_fails_one_attempt(answer: Any, match: str) -> None:
    with pytest.raises(ResponseMalformed, match=match) as raised:
        await _mcp(answer).send(ModelRequest(prompt="hi"))
    _is_one_attempt_failure(raised.value)


async def test_a_json_rpc_error_the_server_answers_stays_a_product_error() -> None:
    def answer(rpc: dict[str, Any]) -> httpx.Response:
        error = {"code": -32600, "message": "invalid request"}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rpc["id"], "error": error})

    with pytest.raises(AdapterProductError, match="MCP initialize error") as raised:
        await _mcp(answer).send(ModelRequest(prompt="hi"))
    assert not isinstance(raised.value, ResponseMalformed)


# --- WebSocket: a turn with no text is a reply when it carries calls or a filter's stop -------
# (pre-merge audit of 598f0858, HIGH 2: "no frame carried text" was raised before the turn's tool
# calls and the final frame's stop were read, so a destructive call was never evaluated and a
# filter's cut was not OD-42's.)


async def _ws_turn(frames: list[dict[str, Any]], **response: object) -> Any:
    from websockets.asyncio.server import ServerConnection

    from tests.adapters.test_websocket import _adapter, _spec
    from tests.ws_raw_servers import HandlerServer, Log, auth_then, send_json

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        for frame in frames:
            await send_json(connection, frame)

    async def handler(connection: ServerConnection, log: Log) -> None:
        await auth_then(connection, log, on_query)

    with HandlerServer(handler) as server:
        adapter = _adapter(server, _spec(response=response))  # type: ignore[arg-type]
        return await adapter.send(ModelRequest(prompt="hi"))


async def test_a_websocket_turn_with_a_tool_call_and_no_text_is_a_reply() -> None:
    call = {"name": "drop_database", "arguments": {"name": "prod"}}
    response = await _ws_turn(
        [{"type": "done", "tool_calls": [call]}], tool_calls_path="tool_calls"
    )
    assert response.text == ""
    assert [c["name"] for c in response.tool_calls] == ["drop_database"]


async def test_a_websocket_turn_its_filter_stopped_with_no_text_is_a_reply() -> None:
    from ildottore.shared.provider_filter import filter_side

    response = await _ws_turn(
        [{"type": "end", "finish_reason": "content_filter"}],
        final_path="finish_reason",
        final_value=None,
    )
    assert (response.text, response.finish_reason) == ("", "content_filter")
    assert filter_side(response) == "output"


async def test_a_websocket_turn_with_neither_text_nor_calls_nor_a_filter_stop_is_unreadable() -> (
    None
):
    with pytest.raises(ResponseMalformed, match="carried text") as raised:
        await _ws_turn([{"type": "done", "other": 1}], tool_calls_path="tool_calls")
    _is_one_attempt_failure(raised.value)


# --- what an unreadable reply keeps for review (pre-merge audit of 598f0858, HIGH 1) --------


async def test_the_error_keeps_a_bounded_redacted_excerpt_of_the_body() -> None:
    from ildottore.adapters.base import UNREADABLE_EXCERPT_BYTES

    secret = "AKIAIOSFODNN7EXAMPLE"
    body = ("<html>login " + secret + " " + "é" * 6000 + "</html>").encode()
    with pytest.raises(ResponseMalformed) as raised:
        await _openai(body, []).send(ModelRequest(prompt="hi"))
    excerpt = raised.value.excerpt
    assert excerpt is not None and excerpt.startswith("<html>login ")
    assert secret not in excerpt and "REDACTED:aws_access_key" in excerpt
    assert len(excerpt.encode("utf-8")) <= UNREADABLE_EXCERPT_BYTES
    assert raised.value.size == len(body)


async def test_a_shape_error_keeps_the_body_too() -> None:
    with pytest.raises(ResponseMalformed, match="has no choices") as raised:
        await _openai(b'{"object": "error", "message": "quota"}', []).send(ModelRequest(prompt="x"))
    assert raised.value.excerpt == '{"object": "error", "message": "quota"}'


@pytest.mark.parametrize(
    ("build", "said"),
    [
        (lambda body: _openai(body, []), "an OpenAI chat completions URL"),
        (lambda body: _anthropic(body, []), "Anthropic Messages API"),
        (lambda body: _rest(body, []), "the template's text_path ('output')"),
    ],
    ids=["openai", "anthropic", "rest"],
)
async def test_the_advice_names_what_to_check_for_each_adapter(build: Any, said: str) -> None:
    with pytest.raises(ResponseMalformed) as raised:
        await build(b"<html></html>").send(ModelRequest(prompt="hi"))
    assert said in (raised.value.advice or "")


def test_a_target_file_rest_target_is_not_told_to_check_a_template_it_cannot_declare() -> None:
    """Pre-merge audit of 598f0858, LOW 2: a target file's `provider: rest` target reads the
    generic template (text at `text`); a template is the Python API's, so the advice says so."""

    from ildottore.cli import wiring
    from ildottore.shared.models import Target

    target = Target(id="r", type="chatbot", provider="rest", endpoint="https://api.example.test/x")
    adapter = wiring.build_real_adapter(target, _ALLOW, api_key=None)
    advice = adapter.unreadable_advice  # type: ignore[attr-defined]
    assert "text at `text`" in advice and "response template" not in advice


def test_the_class_keeps_its_excerpt_and_advice_through_copy_and_pickle() -> None:
    error = ResponseMalformed("t1: x; not evaluated", excerpt="<p>", size=3, advice="check it")
    for clone in (copy.copy(error), pickle.loads(pickle.dumps(error))):  # noqa: S301
        assert (clone.excerpt, clone.size, clone.advice) == ("<p>", 3, "check it")
