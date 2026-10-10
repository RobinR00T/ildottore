"""A non-retryable HTTP status reaches the caller as ``AdapterStatusError`` (u09 §7 A-67).

The HTTP adapters (openai, anthropic, rest, mcp) raise it on a non-retryable 4xx: an
``AdapterProductError``, so the attack phase stops on it as before, that carries the status,
so the composition root can tell a request the endpoint refused (Azure OpenAI's prompt filter
answers a blocked prompt with HTTP 400) from the rest. A WebSocket target's refused upgrade is not
one: it refuses the connection, not a prompt.

The error is copied and pickled like any other: ``status_code`` is a required keyword, and the
default ``BaseException`` reduction rebuilt it from its message alone, so ``copy.copy`` and
``pickle.loads`` raised ``TypeError`` (verification of ``abc6ffe``, 2026-10-09).

Since OD-41 (2026-10-10) Azure's prompt-filter body at 400 is a ``ProviderFilterBlock`` instead
(``tests/adapters/test_provider_filter_block.py``), so the body here is a plain bad request.
"""

from __future__ import annotations

import copy
import pickle
from collections.abc import Callable

import httpx
import pytest
import respx

from ildottore.adapters import (
    AdapterProductError,
    AdapterStatusError,
    AnthropicAdapter,
    MCPAdapter,
    OpenAIAdapter,
    RestAdapter,
    RestTemplate,
    RetryConfig,
)
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import ModelRequest
from ildottore.shared.protocols import TargetAdapter

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)


def _openai() -> TargetAdapter:
    return OpenAIAdapter(
        id="openai",
        base_url="https://api.openai.com",
        allowlist=EndpointAllowlist([Endpoint(host="api.openai.com", path_prefixes=["/v1"])]),
        api_key="sk-fake-000000000000000000000000",
        model="gpt-4o-mini",
        retry=_FAST,
    )


def _anthropic() -> TargetAdapter:
    return AnthropicAdapter(
        id="anthropic",
        base_url="https://api.anthropic.com",
        allowlist=EndpointAllowlist([Endpoint(host="api.anthropic.com", path_prefixes=["/v1"])]),
        api_key="sk-ant-fake-0000000000000000000000",
        model="claude-3-5-sonnet-20241022",
        retry=_FAST,
    )


def _rest() -> TargetAdapter:
    return RestAdapter(
        id="rest",
        base_url="https://llm.example.com",
        allowlist=EndpointAllowlist(
            [Endpoint(host="llm.example.com", path_prefixes=["/generate"])]
        ),
        template=RestTemplate(path="/generate", prompt_field="input", text_path="output"),
        retry=_FAST,
    )


def _mcp() -> TargetAdapter:
    return MCPAdapter(
        id="mcp",
        base_url="https://mcp.example.com/mcp",
        allowlist=EndpointAllowlist([Endpoint(host="mcp.example.com", path_prefixes=["/mcp"])]),
        retry=_FAST,
    )


_ADAPTERS: dict[str, tuple[Callable[[], TargetAdapter], str]] = {
    "openai": (_openai, "https://api.openai.com/v1/chat/completions"),
    "anthropic": (_anthropic, "https://api.anthropic.com/v1/messages"),
    "rest": (_rest, "https://llm.example.com/generate"),
    "mcp": (_mcp, "https://mcp.example.com/mcp"),
}


@pytest.mark.parametrize("status", [400, 403, 422])
@pytest.mark.parametrize("name", sorted(_ADAPTERS))
async def test_a_non_retryable_4xx_is_a_status_error_with_its_status(
    name: str, status: int
) -> None:
    build, url = _ADAPTERS[name]
    body = {"error": {"code": "invalid_request_error", "message": "bad request"}}
    with respx.mock:
        respx.post(url).mock(return_value=httpx.Response(status, json=body))
        with pytest.raises(AdapterStatusError) as raised:
            await build().send(ModelRequest(prompt="How do I kill a Python process?"))
    assert raised.value.status_code == status
    # Still a product error everywhere it was one.
    assert isinstance(raised.value, AdapterProductError)
    assert f"HTTP {status}" in str(raised.value)


def test_a_status_error_survives_copy_and_pickle() -> None:
    error = AdapterStatusError("t: non-retryable HTTP 400 from /v1", status_code=400)
    # The bytes are the test's own, so loading them trusts nothing from outside.
    pickled = pickle.loads(pickle.dumps(error))  # noqa: S301
    for clone in (copy.copy(error), copy.deepcopy(error), pickled):
        assert type(clone) is AdapterStatusError
        assert clone.status_code == 400
        assert clone.args == error.args
        assert str(clone) == str(error)
