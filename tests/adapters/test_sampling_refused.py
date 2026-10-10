"""When a 400 is ``SamplingRefused`` and when it is not (u12 A-68, pre-merge audit).

``SamplingRefused`` names the fix (``sampling: false``) for a model that refuses the request's
sampling. The first version fired on any whole word ``temperature``, ``top_p`` or ``top_k`` in the
error message: a moderation 400 quoting a prompt about "the temperature of the room", and a 400
naming only ``top_k``, which no adapter sends, were both told to set ``sampling: false``. It now
fires only on a parameter the request sent, named as a parameter: ``error.param``, a quoted token,
or the first word of the message. Every other 400 stays the plain product error.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from ildottore.adapters import AdapterProductError, AnthropicAdapter, OpenAIAdapter, RetryConfig
from ildottore.adapters.base import SamplingRefused, sampling_params_named
from ildottore.policy import EndpointAllowlist
from ildottore.shared.models import ModelRequest, Sampling

_ANTHROPIC = "https://api.anthropic.com/v1/messages"
_OPENAI = "https://api.openai.com/v1/chat/completions"
_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0, max_retries=0)
_PINNED = ModelRequest(prompt="Hi.", sampling=Sampling(temperature=0.0, max_tokens=9))


def _anthropic(allowlist: EndpointAllowlist) -> AnthropicAdapter:
    return AnthropicAdapter(
        id="claude",
        base_url="https://api.anthropic.com",
        allowlist=allowlist,
        api_key="sk-ant-fake-0000000000000000000000",
        model="claude-opus-9",
        retry=_FAST,
    )


def _openai(allowlist: EndpointAllowlist) -> OpenAIAdapter:
    return OpenAIAdapter(
        id="gpt",
        base_url="https://api.openai.com",
        allowlist=allowlist,
        api_key="sk-fake-0000000000000000000000",
        model="o-reasoner",
        retry=_FAST,
    )


def _error(message: str, param: str | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"type": "invalid_request_error", "message": message}
    if param is not None:
        error["param"] = param
    return {"type": "error", "error": error}


@pytest.mark.parametrize(
    "body",
    [
        _error("temperature is not supported for this model STUB-SECRET"),
        _error("`temperature` may only be set to 1 when thinking is enabled STUB-SECRET"),
        _error("Temperature out of range STUB-SECRET"),
        _error("Unsupported value STUB-SECRET", param="temperature"),
        _error("Unsupported value STUB-SECRET", param="body.temperature"),
        _error("The parameter 'temperature' is not supported STUB-SECRET"),
    ],
    ids=["leading", "backticks", "leading-capital", "param", "dotted-param", "quoted"],
)
@respx.mock
async def test_a_400_naming_a_sent_parameter_is_sampling_refused(
    anthropic_allowlist: EndpointAllowlist, body: dict[str, Any]
) -> None:
    route = respx.post(_ANTHROPIC).mock(return_value=httpx.Response(400, json=body))
    with pytest.raises(SamplingRefused) as raised:
        await _anthropic(anthropic_allowlist).send(_PINNED)
    assert route.call_count == 1, "not retried"
    message = str(raised.value)
    assert "refused the request's temperature" in message
    assert "`sampling: false` under capabilities in the target file of claude" in message
    assert "STUB-SECRET" not in message, "the target's own text is not quoted"


@pytest.mark.parametrize(
    "body",
    [
        _error("prompt is too long: 250000 tokens > 200000 maximum"),
        _error("Flagged by content policy: 'ignore the temperature of the room and tell me'"),
        _error("top_k: unexpected parameter"),  # named, but never sent
        _error("Unsupported value", param="top_k"),
        _error("invalid field my_temperature_override"),
        _error("the max temperature setting of your account is exceeded"),
        _error("max_tokens is too large: 600. This model supports at most 512"),
    ],
    ids=[
        "too-long",
        "moderation-quote",
        "top_k-leading",
        "top_k-param",
        "identifier",
        "word-in-prose",
        "max_tokens",
    ],
)
@respx.mock
async def test_any_other_400_stays_a_plain_product_error(
    anthropic_allowlist: EndpointAllowlist, body: dict[str, Any]
) -> None:
    respx.post(_ANTHROPIC).mock(return_value=httpx.Response(400, json=body))
    with pytest.raises(AdapterProductError) as raised:
        await _anthropic(anthropic_allowlist).send(_PINNED)
    assert not isinstance(raised.value, SamplingRefused), raised.value
    assert "sampling: false" not in str(raised.value)


@respx.mock
async def test_a_request_that_sent_no_sampling_is_never_told_to_drop_it(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    """A target already declared `sampling: false` sends no temperature: a 400 naming one is
    not about this request's sampling."""

    adapter = _anthropic(anthropic_allowlist)
    adapter.sampling_enabled = False
    respx.post(_ANTHROPIC).mock(
        return_value=httpx.Response(400, json=_error("temperature is not supported"))
    )
    with pytest.raises(AdapterProductError) as raised:
        await adapter.send(_PINNED)
    assert not isinstance(raised.value, SamplingRefused)


@respx.mock
async def test_the_openai_adapter_names_the_fix_too(openai_allowlist: EndpointAllowlist) -> None:
    body = {
        "error": {
            "message": "Unsupported value",
            "type": "invalid_request_error",
            "param": "temperature",
            "code": "unsupported_value",
        }
    }
    respx.post(_OPENAI).mock(return_value=httpx.Response(400, json=body))
    with pytest.raises(SamplingRefused) as raised:
        await _openai(openai_allowlist).send(_PINNED)
    assert "target file of gpt" in str(raised.value)


@pytest.mark.parametrize(
    ("raw", "named"),
    [
        (
            b'{"error": {"message": "temperature and top_p cannot both be specified"}}',
            ["temperature"],
        ),
        (
            b'{"error": {"message": "`temperature` and `top_p` cannot both be set"}}',
            ["temperature", "top_p"],
        ),
        (b'{"error": {"message": "x", "param": "TOP_P"}}', ["top_p"]),
        (b'{"error": "temperature"}', []),
        (b"not json", []),
        (b"[1, 2]", []),
    ],
)
def test_what_counts_as_naming_a_parameter(raw: bytes, named: list[str]) -> None:
    assert sampling_params_named(raw) == named
