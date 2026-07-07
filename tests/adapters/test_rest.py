"""RestAdapter: declarative template mapping, JSON-path extraction, capabilities."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ildottore.adapters import AdapterProductError, RestAdapter, RestTemplate, RetryConfig
from ildottore.adapters.rest import _get_path
from ildottore.policy import EndpointAllowlist
from ildottore.shared.models import Capabilities, ModelRequest
from ildottore.shared.protocols import TargetAdapter

from .conftest import load_cassette

_URL = "https://llm.example.com/generate"
_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)

_TEMPLATE = RestTemplate(
    path="/generate",
    prompt_field="input",
    system_field="system",
    text_path="output.answer",
    finish_path="meta.stop",
    id_path="request_id",
    usage_path="usage",
    static_body={"model": "long-tail-1"},
    static_headers={"x-tenant": "acme"},
)


def _adapter(allowlist: EndpointAllowlist, **kw: object) -> RestAdapter:
    return RestAdapter(
        id="rest-test",
        base_url="https://llm.example.com",
        allowlist=allowlist,
        api_key="tok-fake-000000000000000000",
        template=_TEMPLATE,
        retry=_FAST,
        **kw,  # type: ignore[arg-type]
    )


def _mock(name: str) -> httpx.Response:
    cassette = load_cassette("rest", name)
    return httpx.Response(cassette["status_code"], json=cassette["json"])


def test_satisfies_protocol(rest_allowlist: EndpointAllowlist) -> None:
    assert isinstance(_adapter(rest_allowlist), TargetAdapter)


@respx.mock
async def test_generic_ok(rest_allowlist: EndpointAllowlist) -> None:
    """Text/finish/id/usage are pulled from their configured JSON paths."""

    respx.post(_URL).mock(return_value=_mock("generic_ok"))
    resp = await _adapter(rest_allowlist).send(ModelRequest(prompt="hello"))

    assert resp.text == "Generic REST reply."
    assert resp.finish_reason == "complete"
    assert resp.raw_ids == {"id": "req-987"}
    assert resp.usage == {"tokens": 7}
    assert resp.logprobs is None  # long tail default (contract §5 step 4)


@respx.mock
async def test_missing_text_is_product_defect(rest_allowlist: EndpointAllowlist) -> None:
    """A response missing the text path is a schema defect → product error."""

    respx.post(_URL).mock(return_value=_mock("missing_text"))

    with pytest.raises(AdapterProductError):
        await _adapter(rest_allowlist).send(ModelRequest(prompt="x"))


@respx.mock
async def test_request_wire_shape(rest_allowlist: EndpointAllowlist) -> None:
    """Prompt/system land in the templated fields; static body+headers merged."""

    route = respx.post(_URL).mock(return_value=_mock("generic_ok"))
    req = ModelRequest(system_prompt="be brief", prompt="hi there")
    await _adapter(rest_allowlist).send(req)

    sent = route.calls.last.request
    body = json.loads(sent.content)
    assert body == {"model": "long-tail-1", "input": "hi there", "system": "be brief"}
    assert sent.headers["x-tenant"] == "acme"
    assert sent.headers["authorization"].startswith("Bearer ")


@respx.mock
async def test_prompt_falls_back_to_last_message(rest_allowlist: EndpointAllowlist) -> None:
    """With no explicit prompt, the last message's content is injected."""

    route = respx.post(_URL).mock(return_value=_mock("generic_ok"))
    req = ModelRequest(messages=[{"role": "user", "content": "from message"}])
    await _adapter(rest_allowlist).send(req)

    body = json.loads(route.calls.last.request.content)
    assert body["input"] == "from message"


def test_capabilities_conservative_defaults(rest_allowlist: EndpointAllowlist) -> None:
    """All eight flags default False for the long tail (contract §5 step 4)."""

    caps = _adapter(rest_allowlist).capabilities()
    assert caps == Capabilities()  # every flag False by default


def test_capabilities_config_overrides(rest_allowlist: EndpointAllowlist) -> None:
    """Config flips flags on for a capable REST target."""

    caps = _adapter(rest_allowlist, tools_enabled=True, streaming_enabled=True).capabilities()
    assert caps.tools is True
    assert caps.streaming is True


# --- JSON-path extractor edge cases ---------------------------------------------


def test_get_path_list_index() -> None:
    assert _get_path({"a": [{"b": 1}, {"b": 2}]}, "a.1.b") == 2


def test_get_path_negative_index() -> None:
    assert _get_path({"a": [10, 20, 30]}, "a.-1") == 30


def test_get_path_out_of_range_is_none() -> None:
    assert _get_path({"a": [1]}, "a.5") is None


def test_get_path_index_into_non_sequence_is_none() -> None:
    assert _get_path({"a": {"b": 1}}, "a.0") is None


def test_get_path_missing_key_is_none() -> None:
    assert _get_path({"a": 1}, "a.b.c") is None


def test_get_path_traverse_scalar_is_none() -> None:
    assert _get_path({"a": 1}, "a.b") is None
