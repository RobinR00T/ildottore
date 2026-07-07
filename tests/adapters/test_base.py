"""Base-adapter plumbing: allowlist gate, retry/error classification, logprobs.

Every httpx call is stubbed by respx; the allowlist-refusal tests assert respx
registered **zero** calls (the request never left the process — contract §7).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from ildottore.adapters import (
    AdapterEnvError,
    AdapterProductError,
    EndpointNotAllowed,
    OpenAIAdapter,
    RetryConfig,
    map_logprobs,
)
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import ModelRequest, TokenLogprob

_FAST_RETRY = RetryConfig(max_retries=2, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)


def _adapter(allowlist: EndpointAllowlist) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="openai-test",
        base_url="https://api.openai.com",
        allowlist=allowlist,
        api_key="sk-fake-key-value-not-real-000000000000",
        model="gpt-4o-mini",
        retry=_FAST_RETRY,
    )


# --- allowlist gate (contract §7) ------------------------------------------------


@pytest.mark.parametrize(
    ("host", "prefixes"),
    [
        ("evil.example.com", ["/v1"]),  # off-allowlist host
        ("api.openai.com", ["/admin"]),  # off-prefix path
    ],
)
@respx.mock
async def test_allowlist_refuses_before_any_call(host: str, prefixes: list[str]) -> None:
    """Off-host AND off-prefix each raise before any httpx traffic is issued."""

    route = respx.post(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
    adapter = _adapter(EndpointAllowlist([Endpoint(host=host, path_prefixes=prefixes)]))

    with pytest.raises(EndpointNotAllowed):
        await adapter.send(ModelRequest(prompt="hi"))

    assert route.call_count == 0  # zero egress on refusal


@respx.mock
async def test_allowed_endpoint_sends(openai_allowlist: EndpointAllowlist) -> None:
    """A URL under an allowed host+prefix issues exactly one call."""

    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={"id": "x", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
        )
    )
    adapter = _adapter(openai_allowlist)
    resp = await adapter.send(ModelRequest(prompt="hi"))

    assert route.call_count == 1
    assert resp.text == "ok"


# --- error classification (contract §7) ------------------------------------------


@respx.mock
async def test_retry_then_skip_on_429(openai_allowlist: EndpointAllowlist) -> None:
    """429 is env → retried up the budget then raised as AdapterEnvError."""

    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(429, json={"error": "rate_limited"})
    )
    adapter = _adapter(openai_allowlist)

    with pytest.raises(AdapterEnvError):
        await adapter.send(ModelRequest(prompt="hi"))

    assert route.call_count == _FAST_RETRY.max_retries + 1  # tried, retried, skipped


@respx.mock
async def test_retry_recovers_on_second_attempt(openai_allowlist: EndpointAllowlist) -> None:
    """A transient 503 followed by a 200 succeeds without raising."""

    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(
                200,
                json={"choices": [{"message": {"content": "recovered"}, "finish_reason": "stop"}]},
            ),
        ]
    )
    adapter = _adapter(openai_allowlist)
    resp = await adapter.send(ModelRequest(prompt="hi"))

    assert route.call_count == 2
    assert resp.text == "recovered"


@respx.mock
async def test_timeout_is_env_error(openai_allowlist: EndpointAllowlist) -> None:
    """A transport timeout is env → retried then AdapterEnvError."""

    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        side_effect=httpx.ConnectTimeout("timed out")
    )
    adapter = _adapter(openai_allowlist)

    with pytest.raises(AdapterEnvError):
        await adapter.send(ModelRequest(prompt="hi"))

    assert route.call_count == _FAST_RETRY.max_retries + 1


@respx.mock
async def test_non_retryable_4xx_is_product_defect(openai_allowlist: EndpointAllowlist) -> None:
    """A 400 is not retried and surfaces as a product defect (not a flake)."""

    route = respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(400, json={"error": "bad_request"})
    )
    adapter = _adapter(openai_allowlist)

    with pytest.raises(AdapterProductError):
        await adapter.send(ModelRequest(prompt="hi"))

    assert route.call_count == 1  # no retry on a non-transient status


@respx.mock
async def test_non_json_success_is_product_defect(openai_allowlist: EndpointAllowlist) -> None:
    """A 200 with a non-JSON body is a malformed response → product defect."""

    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, text="not json at all")
    )
    adapter = _adapter(openai_allowlist)

    with pytest.raises(AdapterProductError):
        await adapter.send(ModelRequest(prompt="hi"))


@respx.mock
async def test_json_array_success_is_product_defect(openai_allowlist: EndpointAllowlist) -> None:
    """A 200 whose JSON is an array (not an object) is a product defect."""

    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=[1, 2, 3])
    )
    adapter = _adapter(openai_allowlist)

    with pytest.raises(AdapterProductError):
        await adapter.send(ModelRequest(prompt="hi"))


# --- injected client reuse -------------------------------------------------------


@respx.mock
async def test_injected_client_is_not_closed(openai_allowlist: EndpointAllowlist) -> None:
    """A caller-provided client is reused and left open across sends."""

    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(
            200, json={"choices": [{"message": {"content": "a"}, "finish_reason": "stop"}]}
        )
    )
    async with httpx.AsyncClient() as client:
        adapter = _adapter(openai_allowlist)
        adapter.client = client
        await adapter.send(ModelRequest(prompt="hi"))
        assert not client.is_closed


# --- map_logprobs (ADR-0005) -----------------------------------------------------


def test_map_logprobs_none_stays_none() -> None:
    """Absent logprobs map to None (not []) — capability_unavailable path."""

    assert map_logprobs(None) is None


def test_map_logprobs_empty_list_stays_empty() -> None:
    """A present-but-empty list is preserved as []."""

    assert map_logprobs([]) == []


def test_map_logprobs_maps_top_list() -> None:
    """List-shaped top_logprobs become [(token, logprob), …]."""

    out = map_logprobs(
        [{"token": "a", "logprob": -0.1, "top_logprobs": [{"token": "a", "logprob": -0.1}]}]
    )
    assert out == [TokenLogprob(token="a", logprob=-0.1, top=[("a", -0.1)])]


def test_map_logprobs_maps_top_mapping() -> None:
    """Mapping-shaped top ({token: logprob}) is also accepted."""

    out = map_logprobs([{"token": "a", "logprob": -0.1, "top_logprobs": {"a": -0.1, "b": -2.0}}])
    assert out is not None
    assert out[0].top == [("a", -0.1), ("b", -2.0)]


def test_map_logprobs_missing_top_is_none() -> None:
    """No top_logprobs field → top stays None (no fabricated alternatives)."""

    out = map_logprobs([{"token": "a", "logprob": -0.1}])
    assert out == [TokenLogprob(token="a", logprob=-0.1, top=None)]


def test_map_logprobs_skips_broken_entry() -> None:
    """An entry missing token/logprob is skipped, not crashed on."""

    out = map_logprobs([{"logprob": -0.1}, {"token": "b", "logprob": -0.2}])
    assert out == [TokenLogprob(token="b", logprob=-0.2, top=None)]
