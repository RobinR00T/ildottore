"""Every adapter reads a lone surrogate in a reply as U+FFFD, where the reply is parsed (A-47).

A reply body can escape half a character in any JSON string, or carry it as the raw bytes
``ED A0 80``. Each adapter used to hand it on as a lone surrogate, and the first UTF-8 writer
downstream (the evidence store, httpx, sqlite) raised and aborted the campaign. The CLI tests
(``tests/cli/test_lone_surrogate.py``) show it end to end for the OpenAI shape; these check
OpenAI's adapter on its own (an escape and the raw bytes) and the other ways in: Anthropic, the
REST template, MCP over HTTP (JSON and SSE) and over stdio, and a tool call's arguments read by
``call_arguments``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from ildottore.adapters import (
    AnthropicAdapter,
    MCPAdapter,
    OpenAIAdapter,
    RestAdapter,
    RestTemplate,
    RetryConfig,
)
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import ModelRequest, ModelResponse
from ildottore.shared.toolcalls import call_arguments

from .conftest import load_cassette

#: The JSON escape for U+D800, six characters, built so no tool decodes it on the way in.
_HIGH = chr(92) + "ud800"
_R = chr(0xFFFD)
_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)
_MARK = "@HALF@"


def _body(payload: Any, raw: bytes | None = None) -> bytes:
    """``payload`` as JSON with every ``_MARK`` written as the escape, or as ``raw`` bytes."""

    text = json.dumps(payload).replace(_MARK, _HIGH)
    if raw is None:
        return text.encode()
    return json.dumps(payload).encode().replace(_MARK.encode(), raw)


def _well_formed(response: ModelResponse) -> str:
    """The response as UTF-8 JSON (raises on a lone surrogate, as every writer of it did)."""

    return response.model_dump_json()


async def _send(adapter: Any, url: str, body: bytes) -> ModelResponse:
    with respx.mock:
        respx.post(url).mock(
            return_value=httpx.Response(
                200, content=body, headers={"content-type": "application/json"}
            )
        )
        response: ModelResponse = await adapter.send(ModelRequest(prompt="x"))
    return response


async def test_openai_reads_a_lone_surrogate_in_text_id_and_model(
    openai_allowlist: EndpointAllowlist,
) -> None:
    payload = load_cassette("openai", "tool_call")["json"]
    payload["id"] = "chatcmpl-" + _MARK
    payload["model"] = "gpt-4o" + _MARK
    payload["choices"][0]["message"]["content"] = "I cannot " + _MARK + " do that."
    adapter = OpenAIAdapter(
        id="o", base_url="https://api.openai.com", allowlist=openai_allowlist, retry=_FAST
    )
    response = await _send(adapter, "https://api.openai.com/v1/chat/completions", _body(payload))

    _well_formed(response)
    assert response.text == "I cannot " + _R + " do that."
    assert response.raw_ids["model"] == "gpt-4o" + _R


async def test_openai_reads_the_raw_bytes_of_a_surrogate(
    openai_allowlist: EndpointAllowlist,
) -> None:
    """``json.loads`` decodes bytes with ``surrogatepass``: ``ED A0 80`` is a second way in."""

    payload = load_cassette("openai", "tool_call")["json"]
    payload["choices"][0]["message"]["content"] = "I cannot " + _MARK + " do that."
    adapter = OpenAIAdapter(
        id="o", base_url="https://api.openai.com", allowlist=openai_allowlist, retry=_FAST
    )
    body = _body(payload, raw=b"\xed\xa0\x80")
    assert b"\xed\xa0\x80" in body
    response = await _send(adapter, "https://api.openai.com/v1/chat/completions", body)

    _well_formed(response)
    assert response.text == "I cannot " + _R + " do that."


async def test_anthropic_reads_a_lone_surrogate_in_text_and_tool_input(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    payload = load_cassette("anthropic", "messages_tool_use")["json"]
    for block in payload["content"]:
        if block.get("type") == "text":
            block["text"] = "Let me " + _MARK + " check."
        if block.get("type") == "tool_use":
            block["input"] = {"q" + _MARK: "v" + _MARK}
    adapter = AnthropicAdapter(
        id="a",
        base_url="https://api.anthropic.com",
        allowlist=anthropic_allowlist,
        api_key="sk-ant-fake-0000000000000000000000",
        model="claude-3-5-sonnet-20241022",
        retry=_FAST,
    )
    response = await _send(adapter, "https://api.anthropic.com/v1/messages", _body(payload))

    dumped = _well_formed(response)
    assert "Let me " + _R + " check." in response.text
    assert ("q" + _R) in json.loads(dumped)["tool_calls"][0]["input"]
    assert call_arguments(response.tool_calls[0]) == {"q" + _R: "v" + _R}


async def test_rest_reads_a_lone_surrogate_on_its_text_path(
    rest_allowlist: EndpointAllowlist,
) -> None:
    payload = load_cassette("rest", "generic_ok")["json"]
    payload["output"]["answer"] = "Generic " + _MARK + " reply."
    payload["request_id"] = "req-" + _MARK
    adapter = RestAdapter(
        id="r",
        base_url="https://llm.example.com",
        allowlist=rest_allowlist,
        api_key="tok-fake-000000000000000000",
        template=RestTemplate(
            path="/generate", prompt_field="input", text_path="output.answer", id_path="request_id"
        ),
        retry=_FAST,
    )
    response = await _send(adapter, "https://llm.example.com/generate", _body(payload))

    _well_formed(response)
    assert response.text == "Generic " + _R + " reply."


def test_a_tool_calls_arguments_text_reads_as_well_formed() -> None:
    """OpenAI's arguments are JSON text inside the reply: the escape survives the reply's parse
    as six characters and turned into half a character only when ``call_arguments`` opened it."""

    arguments = json.dumps({"to": "x"}).replace("x", _HIGH)
    assert chr(92) in arguments
    call = {"id": "c1", "function": {"name": "send", "arguments": arguments}}
    assert call_arguments(call) == {"to": _R}


# --- MCP -------------------------------------------------------------------------------------

_MCP_URL = "https://mcp.example.com/mcp"


def _mcp_allow() -> EndpointAllowlist:
    return EndpointAllowlist([Endpoint(host="mcp.example.com", path_prefixes=["/mcp"])])


def _mcp_reply(request: httpx.Request, *, sse: bool) -> httpx.Response:
    """Answer the MCP handshake and lists, with half a character in a tool description."""

    rpc = json.loads(request.content)
    method = rpc.get("method")
    if method == "notifications/initialized":
        return httpx.Response(202)
    result: dict[str, Any] = {method.split("/")[0]: []} if method else {}
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "srv" + _MARK}}
    elif method == "tools/list":
        result = {"tools": [{"name": "read" + _MARK, "description": "Read " + _MARK + " a file."}]}
    text = json.dumps({"jsonrpc": "2.0", "id": rpc.get("id"), "result": result})
    text = text.replace(_MARK, _HIGH)
    if sse:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, text=f"data: {text}\n\n"
        )
    return httpx.Response(200, headers={"content-type": "application/json"}, text=text)


async def _mcp_http(*, sse: bool) -> ModelResponse:
    adapter = MCPAdapter(id="m", base_url=_MCP_URL, allowlist=_mcp_allow(), retry=_FAST)
    with respx.mock:
        respx.post(_MCP_URL).mock(side_effect=lambda request: _mcp_reply(request, sse=sse))
        response: ModelResponse = await adapter.send(ModelRequest(prompt="x"))
    return response


async def test_mcp_over_http_reads_a_lone_surrogate_in_the_catalogue() -> None:
    response = await _mcp_http(sse=False)
    _well_formed(response)
    assert "Read " + _R + " a file." in response.text
    assert "read" + _R in response.text


async def test_mcp_over_sse_reads_a_lone_surrogate_in_the_catalogue() -> None:
    response = await _mcp_http(sse=True)
    _well_formed(response)
    assert "Read " + _R + " a file." in response.text


_STDIO_SERVER = """\
import sys, json
HALF = chr(92) + "ud800"
RAW = sys.argv[1] == "raw"
for line in sys.stdin:
    msg = json.loads(line)
    m, i = msg.get("method"), msg.get("id")
    if m == "notifications/initialized":
        continue
    if m == "initialize":
        r = {"protocolVersion": "2025-06-18", "serverInfo": {"name": "stdio-mcp"}}
    elif m == "tools/list":
        r = {"tools": [{"name": "read_file", "description": "Read @HALF@ a file."}]}
    else:
        r = {m.split("/")[0]: []}
    out = json.dumps({"jsonrpc": "2.0", "id": i, "result": r})
    if RAW:  # the raw UTF-8 bytes of U+D800, not its escape
        sys.stdout.buffer.write(out.encode().replace(b"@HALF@", bytes([0xED, 0xA0, 0x80])) + b"\\n")
        sys.stdout.buffer.flush()
    else:
        print(out.replace("@HALF@", HALF), flush=True)
"""


@pytest.mark.parametrize("form", ["escape", "raw"])
async def test_mcp_over_stdio_reads_a_lone_surrogate_in_the_catalogue(
    tmp_path: Path, form: str
) -> None:
    """Escaped, the line parsed and the half reached the evidence; as raw bytes, the strict
    decode of the line raised, the line was skipped as stray output and the call timed out."""

    script = tmp_path / "server.py"
    script.write_text(_STDIO_SERVER, encoding="utf-8")
    cmd = (sys.executable, str(script), form)
    adapter = MCPAdapter(
        id="s",
        base_url="stdio://local",
        allowlist=EndpointAllowlist([]),
        transport="stdio",
        command=cmd,
        authorized_commands=(" ".join(cmd),),
        retry=RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=10.0),
    )
    response = await adapter.send(ModelRequest(prompt="x"))

    _well_formed(response)
    assert "Read " + _R + " a file." in response.text
