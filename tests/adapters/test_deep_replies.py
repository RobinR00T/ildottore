"""A target reply nested too deeply fails its attempt, not the campaign (2026-10-07).

``json.loads`` raises ``RecursionError``, not a ``ValueError``, on a document nested past the
parser's stack, so a 200 reply of ``[`` 200,000 levels deep (about 400 KB, under the 4 MiB cap)
escaped the handler that classifies a malformed body and the runner aborted the whole campaign.
A reply the parser does accept could be just as fatal later: 300 levels (about 600 bytes) parsed
and then overflowed pydantic's serializer when the evidence was written. Either way the reply is
refused here as an environment failure that is not retried, as a reply over the size cap is: the
attempt is inconclusive and the campaign goes on.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from ildottore.adapters import AdapterEnvError, MCPAdapter, RetryConfig
from ildottore.adapters.anthropic import AnthropicAdapter
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.adapters.rest import RestAdapter, RestTemplate
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.shared.models import ModelRequest

#: Past the parser's stack on every supported Python (3.14 accepts about 116,000 levels).
PARSER_OVERFLOW = 200_000
#: Accepted by the parser on every supported Python, and fatal to what came after it.
PARSED_TOO_DEEP = 300

_FAST = RetryConfig(max_retries=2, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0)
_ALLOW = EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])])


def _nested(levels: int) -> str:
    return "[" * levels + "]" * levels


def _serve(body: bytes, sends: list[int]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sends.append(1)
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _openai(body: bytes, sends: list[int]) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        api_key="k",
        model="m",
        retry=_FAST,
        client=_serve(body, sends),
    )


def _anthropic(body: bytes, sends: list[int]) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        api_key="k",
        model="m",
        retry=_FAST,
        client=_serve(body, sends),
    )


def _rest(body: bytes, sends: list[int]) -> RestAdapter:
    return RestAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=_ALLOW,
        template=RestTemplate(
            path="/generate", prompt_field="input", text_path="output", id_path="request_id"
        ),
        retry=_FAST,
        client=_serve(body, sends),
    )


#: A valid reply per adapter, with ``{deep}`` where a hostile target nests its value: a field
#: the adapter keeps (an id, the usage, a tool call's input), so the value reaches the evidence.
_SHAPES: dict[str, tuple[Any, str]] = {
    "openai id": (
        _openai,
        '{"choices":[{"message":{"role":"assistant","content":"hi"}}],"id":{deep}}',
    ),
    "openai usage": (
        _openai,
        '{"choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"x":{deep}}}',
    ),
    "anthropic tool input": (
        _anthropic,
        '{"content":[{"type":"text","text":"hi"},'
        '{"type":"tool_use","id":"t","name":"f","input":{"a":{deep}}}]}',
    ),
    "rest id": (_rest, '{"output":"hi","request_id":{deep}}'),
}


@pytest.mark.parametrize("levels", [PARSER_OVERFLOW, PARSED_TOO_DEEP])
@pytest.mark.parametrize("shape", sorted(_SHAPES))
async def test_a_reply_nested_too_deeply_is_a_failure_of_its_attempt(
    shape: str, levels: int
) -> None:
    build, template = _SHAPES[shape]
    sends: list[int] = []
    body = template.replace("{deep}", _nested(levels)).encode()
    with pytest.raises(AdapterEnvError, match="nested more than") as caught:
        await build(body, sends).send(ModelRequest(prompt="hi"))
    assert caught.value.is_env_error is True  # type: ignore[attr-defined]
    assert caught.value.retryable is False  # type: ignore[attr-defined]
    assert sends == [1], "not retried: it would come back as deep"


@pytest.mark.parametrize("levels", [PARSER_OVERFLOW, PARSED_TOO_DEEP])
async def test_tool_call_arguments_nested_too_deeply_inside_their_string(levels: int) -> None:
    """OpenAI carries a call's arguments as a JSON string, which the outer parse never opens."""

    arguments = json.dumps("{" + '"a":' + _nested(levels) + "}")
    body = (
        '{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":'
        '[{"id":"c1","type":"function","function":{"name":"f","arguments":' + arguments + "}}]}}]}"
    ).encode()
    sends: list[int] = []
    with pytest.raises(AdapterEnvError, match="nested more than"):
        await _openai(body, sends).send(ModelRequest(prompt="hi"))
    assert sends == [1]


async def test_the_limit_is_the_documented_depth_and_a_real_reply_is_far_inside_it() -> None:
    from ildottore.shared.nesting import MAX_DEPTH

    def reply(levels: int) -> bytes:
        # The reply object is level 1, so a value of N - 1 levels makes a reply N deep.
        return (
            '{"choices":[{"message":{"content":"hi"}}],"x":' + _nested(levels - 1) + "}"
        ).encode()

    sends: list[int] = []
    assert (await _openai(reply(MAX_DEPTH), sends).send(ModelRequest(prompt="hi"))).text == "hi"
    with pytest.raises(AdapterEnvError, match=f"nested more than {MAX_DEPTH} levels"):
        await _openai(reply(MAX_DEPTH + 1), sends).send(ModelRequest(prompt="hi"))
    # A real reply with logprobs, the deepest shape a provider sends, nests 9 levels.
    logprobs = {"content": [{"token": "hi", "logprob": -0.1, "top_logprobs": [{"bytes": [104]}]}]}
    real = {"choices": [{"message": {"content": "hi"}, "logprobs": logprobs}]}
    sent = await _openai(json.dumps(real).encode(), sends).send(ModelRequest(prompt="hi"))
    assert sent.text == "hi"


@pytest.mark.parametrize("levels", [101, 20_000, PARSER_OVERFLOW])
async def test_unclosed_brackets_are_not_json_whatever_the_python(levels: int) -> None:
    """Measured on the text, so the parser never decides: 20,000 unclosed ``[`` were "not JSON"
    on 3.14 and a stack overflow on 3.12 (pre-commit audit, F2). They cannot be JSON, so they
    are a malformed body on every Python, as any other (open decision OD-21)."""

    from ildottore.adapters import AdapterProductError

    body = ('{"choices":[{"message":{"content":"hi"}}],"x":' + "[" * levels).encode()
    sends: list[int] = []
    with pytest.raises(AdapterProductError, match="do not balance"):
        await _openai(body, sends).send(ModelRequest(prompt="hi"))
    assert sends == [1]


@pytest.mark.parametrize("arguments", ["[" * 101, "{'a': " + "[" * 101 + "}"])
async def test_tool_call_arguments_that_are_not_json_are_judged_as_before(arguments: str) -> None:
    """Brackets that do not balance cannot parse into a deep value: the call reads as one with
    no arguments, as it did on main, and is judged by its name. Refused as too deep, 101 ``[``
    turned a call to a forbidden tool from a fail into an inconclusive (delta audit)."""

    from ildottore.shared.toolcalls import call_arguments

    body = json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "type": "function",
                                "function": {"name": "send_email", "arguments": arguments},
                            }
                        ],
                    }
                }
            ]
        }
    ).encode()
    response = await _openai(body, []).send(ModelRequest(prompt="hi"))
    assert [call["function"]["name"] for call in response.tool_calls] == ["send_email"]
    assert call_arguments(response.tool_calls[0]) == {}


async def test_a_reply_that_is_not_json_is_still_a_product_defect() -> None:
    """Unchanged: only the nesting moved. A non-JSON success body still raises the defect."""

    from ildottore.adapters import AdapterProductError

    with pytest.raises(AdapterProductError, match="not valid JSON"):
        await _openai(b"<html>not json</html>", []).send(ModelRequest(prompt="hi"))


# --- MCP: the JSON body, the SSE event and the stdio line ---------------------------------


def _mcp(handler: Any) -> MCPAdapter:
    return MCPAdapter(
        id="mcp-test",
        base_url="https://api.example.test/mcp",
        allowlist=_ALLOW,
        retry=_FAST,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


@pytest.mark.parametrize("levels", [PARSER_OVERFLOW, PARSED_TOO_DEEP])
@pytest.mark.parametrize("sse", [False, True])
async def test_an_mcp_reply_nested_too_deeply_fails_the_attempt(sse: bool, levels: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        rpc = json.loads(request.content)
        if "id" not in rpc:  # notifications/initialized
            return httpx.Response(202)
        deep = (
            ('{"jsonrpc":"2.0","id":' + str(rpc["id"]) + ',"result":{"serverInfo":{"name":')
            + _nested(levels)
            + "}}}"
        )
        if sse:
            return httpx.Response(
                200, content=f"data: {deep}\n\n", headers={"content-type": "text/event-stream"}
            )
        return httpx.Response(200, content=deep, headers={"content-type": "application/json"})

    with pytest.raises(AdapterEnvError, match="nested more than") as caught:
        await _mcp(handler).send(ModelRequest(prompt="hi"))
    assert caught.value.retryable is False  # type: ignore[attr-defined]


_STDIO_SERVER = """\
import sys, json
mode, n = sys.argv[1], int(sys.argv[2])
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if mode == "deep":
        result = '{"serverInfo":{"name":' + "[" * n + "]" * n + "}}"
    elif mode == "junk":  # n bytes of stray lines before the reply, 1 MiB each
        for _ in range(n // 1048576):
            print("x" * 1048576, flush=True)
        result = json.dumps({"serverInfo": {"name": "late"}})
    elif mode == "tools":
        tools = [{"name": "tool_%d" % i, "description": ("Reads record %d. " % i) * 20}
                 for i in range(n)]
        result = json.dumps({"serverInfo": {"name": "wide"}, "tools": tools})
    else:
        result = json.dumps({"serverInfo": {"name": "x" * n}})
    print('{"jsonrpc":"2.0","id":%d,"result":%s}' % (msg["id"], result), flush=True)
"""


def _stdio(tmp_path: Path, mode: str, n: int) -> MCPAdapter:
    script = tmp_path / "mcp_server.py"
    script.write_text(_STDIO_SERVER, encoding="utf-8")
    cmd = (sys.executable, str(script), mode, str(n))
    return MCPAdapter(
        id="stdio-mcp",
        base_url="stdio://local",
        allowlist=EndpointAllowlist([]),
        transport="stdio",
        command=cmd,
        authorized_commands=(" ".join(cmd),),
        retry=RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=60.0),
    )


@pytest.mark.parametrize("levels", [PARSER_OVERFLOW, PARSED_TOO_DEEP])
async def test_an_mcp_stdio_line_nested_too_deeply_fails_at_once(
    tmp_path: Path, levels: int
) -> None:
    """Refused at once, not skipped as a stray non-JSON line until the timeout."""

    with pytest.raises(AdapterEnvError, match="nested more than"):
        await _stdio(tmp_path, "deep", levels).send(ModelRequest(prompt="hi"))


async def test_an_mcp_stdio_line_longer_than_64_kib_is_read(tmp_path: Path) -> None:
    """300 ordinary tools on one line (about 120 KB): the 64 KiB default of ``readline``
    raised a ValueError there, and the runner stopped the campaign (pre-commit audit)."""

    response = await _stdio(tmp_path, "tools", 300).send(ModelRequest(prompt="hi"))
    assert "Tools (300):" in response.text


async def test_an_mcp_stdio_line_over_the_reply_cap_is_too_large(tmp_path: Path) -> None:
    from ildottore.adapters.base import MAX_RESPONSE_BYTES

    with pytest.raises(AdapterEnvError, match="exceeded") as caught:
        await _stdio(tmp_path, "long", MAX_RESPONSE_BYTES).send(ModelRequest(prompt="hi"))
    assert caught.value.retryable is False  # type: ignore[attr-defined]


async def test_what_one_mcp_stdio_request_reads_is_capped_as_a_whole(tmp_path: Path) -> None:
    """Stray lines before the reply count: 63 lines of 4 MiB took 80 s and 419 MB per attempt
    and still passed (delta audit)."""

    from ildottore.adapters.base import MAX_RESPONSE_BYTES

    with pytest.raises(AdapterEnvError, match="exceeded") as caught:
        await _stdio(tmp_path, "junk", MAX_RESPONSE_BYTES + 1048576).send(ModelRequest(prompt="hi"))
    assert caught.value.retryable is False  # type: ignore[attr-defined]
    # Stray lines within the cap are skipped, as before.
    response = await _stdio(tmp_path, "junk", 2 * 1048576).send(ModelRequest(prompt="hi"))
    assert "MCP server: late" in response.text
