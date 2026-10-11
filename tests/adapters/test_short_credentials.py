"""A credential shorter than 8 characters is refused by every adapter before any request (A-78).

Pre-merge security audit of 2026-10-11, LOW 6. The redactor masks a registered credential by
value only from 8 characters (``redactor._KNOWN_MIN_LEN``): a shorter one is not registered, so
a target echoing it put it in the evidence and in every report. The WebSocket adapter refused one
before any dial since its own pre-commit audit (F5); the HTTP adapters (OpenAI, Anthropic, REST,
MCP over HTTP) registered nothing and sent it, the ``auth_ref`` key and a password in the
endpoint URL alike. They refuse it now, with the WebSocket adapter's message.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from ildottore.adapters import AdapterProductError, MCPAdapter, RetryConfig
from ildottore.adapters.anthropic import AnthropicAdapter
from ildottore.adapters.base import MIN_CREDENTIAL_LEN, refuse_short_credential
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.adapters.rest import RestAdapter, RestTemplate
from ildottore.adapters.websocket import MIN_CREDENTIAL_LEN as WS_MIN_CREDENTIAL_LEN
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.shared.models import ModelRequest

_FAST = RetryConfig(max_retries=0, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0)
_ALLOW = EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])])
_OPENAI_OK = {
    "id": "x",
    "model": "m",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
}
_ANTHROPIC_OK = {"id": "x", "model": "m", "content": [{"type": "text", "text": "ok"}]}
_MESSAGE = (
    "t1: the credential is shorter than 8 characters, which the redactor cannot mask by value; "
    "nothing was sent"
)


def _client(body: dict[str, Any], sends: list[httpx.Request]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        sends.append(request)
        return httpx.Response(200, json=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _openai(key: str | None, sends: list[httpx.Request], base: str) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="t1", base_url=base, allowlist=_ALLOW, api_key=key, model="m", retry=_FAST,
        client=_client(_OPENAI_OK, sends),
    )  # fmt: skip


def _anthropic(key: str | None, sends: list[httpx.Request], base: str) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="t1", base_url=base, allowlist=_ALLOW, api_key=key, model="m", retry=_FAST,
        client=_client(_ANTHROPIC_OK, sends),
    )  # fmt: skip


def _rest(key: str | None, sends: list[httpx.Request], base: str) -> RestAdapter:
    return RestAdapter(
        id="t1", base_url=base, allowlist=_ALLOW, api_key=key, model="m", retry=_FAST,
        template=RestTemplate(path="/generate"), client=_client({"text": "ok"}, sends),
    )  # fmt: skip


ADAPTERS: dict[str, Callable[[str | None, list[httpx.Request], str], Any]] = {
    "openai": _openai,
    "anthropic": _anthropic,
    "rest": _rest,
}


def test_the_floor_is_the_redactors_and_the_websocket_adapters() -> None:
    from ildottore import redactor

    assert MIN_CREDENTIAL_LEN == redactor._KNOWN_MIN_LEN == WS_MIN_CREDENTIAL_LEN == 8


@pytest.mark.parametrize("name", sorted(ADAPTERS))
@pytest.mark.parametrize("key", ["", "k", "tok4567", "  short"])
async def test_a_short_key_is_refused_before_any_request(name: str, key: str) -> None:
    sends: list[httpx.Request] = []
    adapter = ADAPTERS[name](key, sends, "https://api.example.test")
    with pytest.raises(AdapterProductError) as info:
        await adapter.send(ModelRequest(prompt="hi"))
    assert str(info.value) == _MESSAGE
    assert sends == []


@pytest.mark.parametrize("name", sorted(ADAPTERS))
@pytest.mark.parametrize("key", [None, "tok45678", "a-much-longer-test-key"])
async def test_no_key_or_one_of_8_characters_or_more_is_sent(name: str, key: str | None) -> None:
    sends: list[httpx.Request] = []
    adapter = ADAPTERS[name](key, sends, "https://api.example.test")
    await adapter.send(ModelRequest(prompt="hi"))
    assert len(sends) == 1


@pytest.mark.parametrize("name", sorted(ADAPTERS))
@pytest.mark.parametrize(
    "userinfo",
    [
        "ops:pw12345",  # 7 characters
        "ops:%41%42%43%44%45",  # 15 as written, 5 once decoded
    ],
)
async def test_a_short_password_in_the_endpoint_is_refused(name: str, userinfo: str) -> None:
    sends: list[httpx.Request] = []
    adapter = ADAPTERS[name](None, sends, f"https://{userinfo}@api.example.test")
    with pytest.raises(AdapterProductError, match="shorter than 8 characters"):
        await adapter.send(ModelRequest(prompt="hi"))
    assert sends == []


@pytest.mark.parametrize("name", sorted(ADAPTERS))
@pytest.mark.parametrize("userinfo", ["ops:pw123456", "tok-as-the-user:", "ops"])
async def test_a_long_or_empty_password_in_the_endpoint_is_sent(name: str, userinfo: str) -> None:
    """An empty password is no credential: ``https://<token>:@host`` sends a user only."""

    sends: list[httpx.Request] = []
    adapter = ADAPTERS[name](None, sends, f"https://{userinfo}@api.example.test")
    await adapter.send(ModelRequest(prompt="hi"))
    assert len(sends) == 1


async def test_the_mcp_adapter_refuses_a_short_key_before_the_handshake() -> None:
    sends: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sends.append(request)
        body = json.loads(request.content or b"{}")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body.get("id"), "result": {}})

    adapter = MCPAdapter(
        id="t1",
        base_url="https://api.example.test/mcp",
        allowlist=_ALLOW,
        api_key="tok4567",
        retry=_FAST,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AdapterProductError) as info:
        await adapter.send(ModelRequest(prompt="hi"))
    assert str(info.value) == _MESSAGE
    assert sends == []


def test_the_message_never_holds_the_credential() -> None:
    with pytest.raises(AdapterProductError) as info:
        refuse_short_credential("t1", "Zq8!pL2", "https://ops:Xy7%40w@api.example.test")
    for value in ("Zq8!pL2", "Xy7%40w", "Xy7@w"):
        assert value not in str(info.value)
