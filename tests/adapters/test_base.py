"""Base-adapter plumbing: allowlist gate, retry/error classification, logprobs.

Every httpx call is stubbed by respx; the allowlist-refusal tests assert respx
registered **zero** calls (the request never left the process - contract §7).
"""

from __future__ import annotations

import math

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
    """Absent logprobs map to None (not []) - capability_unavailable path."""

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


def _short(value: object) -> str:
    """A test id that stays short for a 400-digit integer."""

    text = repr(value)
    return text if len(text) <= 24 else f"{text[:6]}...{len(text)}-chars"


#: Figures no model produces, as ``json.loads`` hands them over (A-39).
_IMPOSSIBLE: list[object] = [
    10**400,
    -(10**400),
    [1],
    {},
    "abc",
    "-0.5",
    True,
    float("inf"),
    float("-inf"),
    float("nan"),
    0.5,
]


@pytest.mark.parametrize("figure", _IMPOSSIBLE, ids=_short)
def test_map_logprobs_does_not_read_a_block_with_an_impossible_token_figure(
    figure: object,
) -> None:
    """The whole block, not the entry: the readable rest alone would be scored as if it were
    the reply's, and a block of confident tokens with one impossible figure among them would
    read as "likely memorized"."""

    good = {"token": "a", "logprob": -0.01}
    assert map_logprobs([good, {"token": "b", "logprob": figure}, good]) is None


@pytest.mark.parametrize("figure", _IMPOSSIBLE, ids=_short)
def test_map_logprobs_drops_only_the_alternatives_of_a_token_with_an_impossible_one(
    figure: object,
) -> None:
    """No alternative is ever scored, so an impossible one costs its token the alternatives
    and nothing else: every token figure is still read (pre-commit audit F3, OD-24)."""

    kept = {"token": "c", "logprob": -0.2, "top_logprobs": [{"token": "c", "logprob": -0.2}]}
    as_list = [
        {
            "token": "a",
            "logprob": -0.1,
            "top_logprobs": [{"token": "a", "logprob": -0.1}, {"token": "b", "logprob": figure}],
        },
        kept,
    ]
    as_map = [{"token": "a", "logprob": -0.1, "top_logprobs": {"a": -0.1, "b": figure}}, kept]
    expected = [
        TokenLogprob(token="a", logprob=-0.1, top=None),
        TokenLogprob(token="c", logprob=-0.2, top=[("c", -0.2)]),
    ]

    assert map_logprobs(as_list) == expected
    assert map_logprobs(as_map) == expected


@pytest.mark.parametrize("figure", [0.5, float("nan"), 10**400], ids=_short)
def test_map_logprobs_reads_the_figure_of_an_entry_that_names_no_token(figure: object) -> None:
    """An entry with no token is skipped, but its figure is read first: skipped unread, a
    positive one beside four confident tokens let the rest be scored "likely memorized" (delta
    audit L2). An alternative that names no token costs its token the alternatives the same way."""

    good = {"token": "a", "logprob": -0.01}
    no_token = [good, good, good, good, {"token": None, "logprob": figure}]
    missing_token = [good, good, good, good, {"logprob": figure}]
    # Beside a readable alternative, or a skip-first reading would keep that one.
    alternative = [
        {
            "token": "a",
            "logprob": -0.01,
            "top_logprobs": [{"token": "a", "logprob": -0.01}, {"token": None, "logprob": figure}],
        },
        good,
    ]

    assert map_logprobs(no_token) is None
    assert map_logprobs(missing_token) is None
    assert map_logprobs(alternative) == [
        TokenLogprob(token="a", logprob=-0.01, top=None),
        TokenLogprob(token="a", logprob=-0.01, top=None),
    ]


def test_map_logprobs_skips_a_null_alternative_in_either_shape() -> None:
    """Absent is not impossible: a null alternative is skipped in the map shape as it always
    was in the list shape (the map shape raised ``TypeError`` on it), and alternatives that are
    all null are none at all in both shapes."""

    as_list = [{"token": "a", "logprob": -0.1, "top_logprobs": [{"token": "b", "logprob": None}]}]
    as_map = [{"token": "a", "logprob": -0.1, "top_logprobs": {"a": -0.1, "b": None}}]
    only_null = [{"token": "a", "logprob": -0.1, "top_logprobs": {"b": None}}]

    assert map_logprobs(as_list) == [TokenLogprob(token="a", logprob=-0.1, top=None)]
    assert map_logprobs(as_map) == [TokenLogprob(token="a", logprob=-0.1, top=[("a", -0.1)])]
    assert map_logprobs(only_null) == [TokenLogprob(token="a", logprob=-0.1, top=None)]


def test_map_logprobs_skips_a_null_token_figure_and_reads_the_rest() -> None:
    """Absent, not impossible: a token whose own figure is null is skipped as before, and the
    block is still read (only a figure no model produces voids it)."""

    out = map_logprobs([{"token": "a", "logprob": None}, {"token": "b", "logprob": -0.2}])
    assert out == [TokenLogprob(token="b", logprob=-0.2, top=None)]


@pytest.mark.parametrize("blob", [5, True, 0.5, "abc"], ids=repr)
def test_map_logprobs_reads_a_top_logprobs_that_is_no_list_or_map_as_no_alternatives(
    blob: object,
) -> None:
    """A number or a bool there raised ``TypeError`` when iterated; a string, iterated
    character by character, already read as no alternatives (kept as a control)."""

    out = map_logprobs([{"token": "a", "logprob": -0.1, "top_logprobs": blob}])
    assert out == [TokenLogprob(token="a", logprob=-0.1, top=None)]


def test_map_logprobs_keeps_every_figure_a_model_produces() -> None:
    """The other direction: certainty (``0``, an integer), OpenAI's ``-9999.0`` floor for an
    alternative it gives no chance, and a figure far below any real one are all kept."""

    out = map_logprobs(
        [
            {
                "token": "a",
                "logprob": 0,
                "top_logprobs": [{"token": "a", "logprob": 0}, {"token": "z", "logprob": -9999.0}],
            },
            {"token": "b", "logprob": -3, "top_logprobs": {"b": 0, "y": -1e300}},
            {"token": "c", "logprob": -0.0},
        ]
    )
    assert out == [
        TokenLogprob(token="a", logprob=0.0, top=[("a", 0.0), ("z", -9999.0)]),
        TokenLogprob(token="b", logprob=-3.0, top=[("b", 0.0), ("y", -1e300)]),
        TokenLogprob(token="c", logprob=-0.0, top=None),
    ]
    # ``-0.0 == 0.0``, so the sign is read apart: the figure is kept as sent.
    assert math.copysign(1.0, out[2].logprob) == -1.0
