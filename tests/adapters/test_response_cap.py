"""A target reply larger than the cap is refused unread (audit 2026-10-03, SEC-07)."""

from __future__ import annotations

import httpx
import pytest

from ildottore.adapters.base import MAX_RESPONSE_BYTES, AdapterEnvError
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.shared.models import ModelRequest


def _adapter(body: bytes) -> OpenAIAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    return OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def test_a_reply_over_the_cap_is_an_environment_failure_not_a_verdict() -> None:
    oversized = b'{"choices":[{"message":{"content":"' + b"A" * (MAX_RESPONSE_BYTES + 1) + b'"}}]}'
    with pytest.raises(AdapterEnvError, match="exceeded"):
        await _adapter(oversized).send(ModelRequest(prompt="hi"))


async def test_a_normal_reply_still_parses() -> None:
    body = b'{"choices":[{"message":{"content":"hello"}}]}'
    response = await _adapter(body).send(ModelRequest(prompt="hi"))
    assert response.text == "hello"
