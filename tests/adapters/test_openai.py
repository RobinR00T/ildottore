"""OpenAIAdapter: cassette-driven send, golden logprobs, capabilities, wire shape."""

from __future__ import annotations

import httpx
import pytest
import respx

from ildottore.adapters import AdapterProductError, OpenAIAdapter, RetryConfig
from ildottore.policy import EndpointAllowlist
from ildottore.shared.models import Capabilities, ModelRequest, Sampling, TokenLogprob
from ildottore.shared.protocols import TargetAdapter

from .conftest import load_cassette, load_golden

_URL = "https://api.openai.com/v1/chat/completions"
_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)


def _adapter(allowlist: EndpointAllowlist, **kw: object) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="openai-test",
        base_url="https://api.openai.com",
        allowlist=allowlist,
        api_key="sk-fake-000000000000000000000000",
        model="gpt-4o-mini",
        retry=_FAST,
        **kw,  # type: ignore[arg-type]
    )


def _mock(name: str) -> httpx.Response:
    cassette = load_cassette("openai", name)
    return httpx.Response(cassette["status_code"], json=cassette["json"])


def test_satisfies_protocol(openai_allowlist: EndpointAllowlist) -> None:
    """OpenAIAdapter is a structural TargetAdapter (id/send/capabilities)."""

    assert isinstance(_adapter(openai_allowlist), TargetAdapter)


@respx.mock
async def test_logprobs_golden(openai_allowlist: EndpointAllowlist) -> None:
    """Cassette logprobs map exactly to the golden TokenLogprob list."""

    respx.post(_URL).mock(return_value=_mock("chat_with_logprobs"))
    resp = await _adapter(openai_allowlist).send(ModelRequest(prompt="hello"))

    expected = [
        TokenLogprob(token=g["token"], logprob=g["logprob"], top=[tuple(t) for t in g["top"]])
        for g in load_golden("openai_chat_with_logprobs")
    ]
    assert resp.logprobs == expected
    assert resp.text == "Hi there!"
    assert resp.finish_reason == "stop"


@respx.mock
async def test_no_logprobs_cassette_yields_none(openai_allowlist: EndpointAllowlist) -> None:
    """A response without a logprobs block yields ModelResponse.logprobs is None."""

    respx.post(_URL).mock(return_value=_mock("chat_no_logprobs"))
    resp = await _adapter(openai_allowlist).send(ModelRequest(prompt="hello"))

    assert resp.logprobs is None


@respx.mock
async def test_logprobs_disabled_by_config(openai_allowlist: EndpointAllowlist) -> None:
    """With logprobs disabled, mapping is skipped and logprobs stays None."""

    respx.post(_URL).mock(return_value=_mock("chat_with_logprobs"))
    adapter = _adapter(openai_allowlist, logprobs_enabled=False)
    resp = await adapter.send(ModelRequest(prompt="hello"))

    assert resp.logprobs is None


@respx.mock
async def test_tool_call_parsed(openai_allowlist: EndpointAllowlist) -> None:
    """A tool-call response captures tool_calls and empties text."""

    respx.post(_URL).mock(return_value=_mock("tool_call"))
    resp = await _adapter(openai_allowlist).send(ModelRequest(prompt="weather?"))

    assert resp.text == ""
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0]["function"]["name"] == "get_weather"
    assert resp.finish_reason == "tool_calls"


@respx.mock
async def test_malformed_no_choices_is_product_defect(
    openai_allowlist: EndpointAllowlist,
) -> None:
    """A 200 with no choices is a schema defect → AdapterProductError."""

    respx.post(_URL).mock(return_value=_mock("malformed_no_choices"))

    with pytest.raises(AdapterProductError):
        await _adapter(openai_allowlist).send(ModelRequest(prompt="x"))


@respx.mock
async def test_request_wire_shape(openai_allowlist: EndpointAllowlist) -> None:
    """System prompt, roles and pinned sampling params ride verbatim on the wire."""

    route = respx.post(_URL).mock(return_value=_mock("chat_no_logprobs"))
    req = ModelRequest(
        system_prompt="You are terse.",
        prompt="Say hi.",
        sampling=Sampling(temperature=0.0, top_p=0.9, seed=42, max_tokens=16),
    )
    await _adapter(openai_allowlist).send(req)

    sent = route.calls.last.request
    import json as _json

    body = _json.loads(sent.content)
    assert body["model"] == "gpt-4o-mini"
    assert body["messages"][0] == {"role": "system", "content": "You are terse."}
    assert body["messages"][1] == {"role": "user", "content": "Say hi."}
    assert body["temperature"] == 0.0
    assert body["top_p"] == 0.9
    assert body["seed"] == 42
    assert body["max_tokens"] == 16
    assert sent.headers["authorization"].startswith("Bearer ")


@respx.mock
async def test_seed_dropped_when_capability_off(openai_allowlist: EndpointAllowlist) -> None:
    """seed_enabled=False must not fabricate/forward a seed (contract §4)."""

    route = respx.post(_URL).mock(return_value=_mock("chat_no_logprobs"))
    adapter = _adapter(openai_allowlist, seed_enabled=False)
    await adapter.send(ModelRequest(prompt="hi", sampling=Sampling(seed=7)))

    import json as _json

    body = _json.loads(route.calls.last.request.content)
    assert "seed" not in body


@respx.mock
async def test_messages_passthrough(openai_allowlist: EndpointAllowlist) -> None:
    """Explicit messages ride verbatim (system prepended if provided)."""

    route = respx.post(_URL).mock(return_value=_mock("chat_no_logprobs"))
    req = ModelRequest(
        system_prompt="sys",
        messages=[{"role": "user", "content": "u1"}, {"role": "assistant", "content": "a1"}],
    )
    await _adapter(openai_allowlist).send(req)

    import json as _json

    body = _json.loads(route.calls.last.request.content)
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
    ]


def test_capabilities_all_eight_flags(openai_allowlist: EndpointAllowlist) -> None:
    """Capabilities reports all eight bool flags with the OpenAI defaults."""

    caps = _adapter(openai_allowlist).capabilities()
    assert caps == Capabilities(
        tools=True,
        rag=False,
        memory=False,
        streaming=True,
        seed=True,
        logprobs=True,
        multi_identity=False,
        multimodal=False,
    )


def test_multimodal_media_builds_image_url_content(openai_allowlist: EndpointAllowlist) -> None:
    """A single-turn request with media sends a text + image_url content array (data URL)."""

    adapter = _adapter(openai_allowlist, multimodal_enabled=True)
    req = ModelRequest(
        prompt="Describe this image.",
        media=[{"kind": "image", "format": "png", "render_text": "PWNED"}],
    )
    body, _ = adapter._build_request(req)
    content = body["messages"][-1]["content"]
    assert [part["type"] for part in content] == ["text", "image_url"]
    assert content[0]["text"] == "Describe this image."
    assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")
    assert adapter.capabilities().multimodal is True


def test_multimodal_absent_keeps_plain_string_content(openai_allowlist: EndpointAllowlist) -> None:
    """A text-only request is unchanged: content stays a plain string (backward compatible)."""

    body, _ = _adapter(openai_allowlist)._build_request(ModelRequest(prompt="hi"))
    assert body["messages"][-1]["content"] == "hi"
