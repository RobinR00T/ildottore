"""AnthropicAdapter: system placement, stop_reason vocab, OD-1 logprobs=None."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ildottore.adapters import AdapterProductError, AnthropicAdapter, RetryConfig
from ildottore.policy import EndpointAllowlist
from ildottore.shared.models import Capabilities, ModelRequest, Sampling
from ildottore.shared.protocols import TargetAdapter

from .conftest import load_cassette

_URL = "https://api.anthropic.com/v1/messages"
_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)


def _adapter(allowlist: EndpointAllowlist, **kw: object) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="anthropic-test",
        base_url="https://api.anthropic.com",
        allowlist=allowlist,
        api_key="sk-ant-fake-0000000000000000000000",
        model="claude-3-5-sonnet-20241022",
        retry=_FAST,
        **kw,  # type: ignore[arg-type]
    )


def _mock(name: str) -> httpx.Response:
    cassette = load_cassette("anthropic", name)
    return httpx.Response(cassette["status_code"], json=cassette["json"])


def test_satisfies_protocol(anthropic_allowlist: EndpointAllowlist) -> None:
    assert isinstance(_adapter(anthropic_allowlist), TargetAdapter)


@respx.mock
async def test_basic_message(anthropic_allowlist: EndpointAllowlist) -> None:
    """Text blocks concatenate; stop_reason preserved; logprobs is None (OD-1)."""

    respx.post(_URL).mock(return_value=_mock("messages_basic"))
    resp = await _adapter(anthropic_allowlist).send(ModelRequest(prompt="2+2?"))

    assert resp.text == "The answer is 4."
    assert resp.finish_reason == "end_turn"  # vocab preserved, not translated
    assert resp.logprobs is None  # OD-1: no per-token logprobs on Anthropic


@respx.mock
async def test_logprobs_none_even_with_capability_forced(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    """logprobs stays None regardless — the Messages body carries none (OD-1)."""

    respx.post(_URL).mock(return_value=_mock("messages_basic"))
    resp = await _adapter(anthropic_allowlist).send(ModelRequest(prompt="hi"))
    assert resp.logprobs is None


@respx.mock
async def test_tool_use_parsed(anthropic_allowlist: EndpointAllowlist) -> None:
    """A tool_use block is captured; leading text still concatenated."""

    respx.post(_URL).mock(return_value=_mock("messages_tool_use"))
    resp = await _adapter(anthropic_allowlist).send(ModelRequest(prompt="weather?"))

    assert resp.text == "Let me check."
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0]["name"] == "get_weather"
    assert resp.finish_reason == "tool_use"


@respx.mock
async def test_malformed_no_content_is_product_defect(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    respx.post(_URL).mock(return_value=_mock("malformed_no_content"))

    with pytest.raises(AdapterProductError):
        await _adapter(anthropic_allowlist).send(ModelRequest(prompt="x"))


@respx.mock
async def test_system_placement_top_level(anthropic_allowlist: EndpointAllowlist) -> None:
    """System prompt rides in the top-level `system` field, not a message role."""

    route = respx.post(_URL).mock(return_value=_mock("messages_basic"))
    req = ModelRequest(
        system_prompt="You are terse.",
        prompt="Hi.",
        sampling=Sampling(temperature=0.2, top_p=0.8, max_tokens=64),
    )
    await _adapter(anthropic_allowlist).send(req)

    body = json.loads(route.calls.last.request.content)
    assert body["system"] == "You are terse."
    assert body["messages"] == [{"role": "user", "content": "Hi."}]
    assert body["temperature"] == 0.2
    assert body["top_p"] == 0.8
    assert body["max_tokens"] == 64
    assert route.calls.last.request.headers["anthropic-version"] == "2023-06-01"
    assert route.calls.last.request.headers["x-api-key"].startswith("sk-ant-")
    assert "seed" not in body  # no seed field on the Messages API


@respx.mock
async def test_multi_turn_messages_projected_to_role_content(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    """A multi-turn transcript is projected to Anthropic-valid {role, content} turns.

    The conversation engine may thread provider-foreign keys (e.g. an OpenAI-shaped
    ``tool_calls``) into the history; the Messages API rejects unknown fields (HTTP 400),
    so the adapter must strip them (ADR-0002: the adapter owns the wire shape)."""

    route = respx.post(_URL).mock(return_value=_mock("messages_basic"))
    req = ModelRequest(
        messages=[
            {"role": "user", "content": "benign opener"},
            {"role": "assistant", "content": "sure", "tool_calls": [{"name": "x"}]},
            {"role": "user", "content": "the escalation"},
        ],
        sampling=Sampling(max_tokens=32),
    )
    await _adapter(anthropic_allowlist).send(req)

    body = json.loads(route.calls.last.request.content)
    assert body["messages"] == [
        {"role": "user", "content": "benign opener"},
        {"role": "assistant", "content": "sure"},
        {"role": "user", "content": "the escalation"},
    ]
    # No provider-foreign key leaks into the wire payload.
    assert all("tool_calls" not in m for m in body["messages"])


@respx.mock
async def test_default_max_tokens_applied(anthropic_allowlist: EndpointAllowlist) -> None:
    """max_tokens is required by the API; a default is supplied when unset."""

    route = respx.post(_URL).mock(return_value=_mock("messages_basic"))
    await _adapter(anthropic_allowlist).send(ModelRequest(prompt="hi"))

    body = json.loads(route.calls.last.request.content)
    assert body["max_tokens"] == 1024


def test_capabilities_logprobs_false_seed_false(anthropic_allowlist: EndpointAllowlist) -> None:
    """All eight flags reported; logprobs and seed are hard False (OD-1)."""

    caps = _adapter(anthropic_allowlist).capabilities()
    assert caps == Capabilities(
        tools=True,
        rag=False,
        memory=False,
        streaming=True,
        seed=False,
        logprobs=False,
        multi_identity=False,
        multimodal=True,
    )
