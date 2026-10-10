"""The adapters recognise a provider's input-filter refusal, and only that (OD-41).

Two shapes, each from the provider's documentation (cited where they are read, in
``adapters.base.azure_prompt_filter`` and ``adapters.rest.RestAdapter._prompt_blocked``):

* Azure OpenAI: HTTP 400 with ``error.code`` ``content_filter`` (Microsoft Learn, "Content
  filtering", Scenario 3), optionally with ``innererror.code`` ``ResponsibleAIPolicyViolation``
  and ``innererror.content_filter_result`` per category. Any adapter built on ``BaseAdapter``
  reads it (openai, anthropic, rest); the MCP adapter sends no prompt and does not.
* Gemini: a success body whose ``promptFeedback.blockReason`` is set and which holds no
  candidate (the Gemini API reference, ``PromptFeedback``), through a REST template.

Every other 4xx stays an ``AdapterStatusError``, as on ``main``: another code at 400, the Azure
body at any other status. Not recognised, for want of a documented shape: a Bedrock guardrail
intervention (the Converse reference documents it as an HTTP 200 with ``stopReason``
``guardrail_intervened``, read as a reply, and lists no guardrail error), an OpenAI moderation
400 (``invalid_prompt`` appears in forum reports, not in OpenAI's error-code reference), and
Gemini behind its OpenAI-compatible endpoint.
"""

from __future__ import annotations

import copy
import json
import pickle
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from ildottore.adapters import (
    AdapterProductError,
    AdapterStatusError,
    AnthropicAdapter,
    MCPAdapter,
    OpenAIAdapter,
    ProviderFilterBlock,
    RestAdapter,
    RestTemplate,
    RetryConfig,
)
from ildottore.adapters.base import azure_prompt_filter
from ildottore.cli.wiring import refused_request
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.redactor import Redactor
from ildottore.shared.models import ModelRequest
from ildottore.shared.protocols import TargetAdapter

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)

#: The body Azure OpenAI returns, with status 400, for a prompt its content filter blocks: the
#: same as ``tests/cli/test_input_filter_probe.py``, with Prompt Shields' jailbreak entry.
AZURE_PROMPT_FILTERED: dict[str, Any] = {
    "error": {
        "message": (
            "The response was filtered due to the prompt triggering Azure OpenAI's content "
            "management policy. Please modify your prompt and retry."
        ),
        "type": None,
        "param": "prompt",
        "code": "content_filter",
        "status": 400,
        "innererror": {
            "code": "ResponsibleAIPolicyViolation",
            "content_filter_result": {
                "hate": {"filtered": False, "severity": "safe"},
                "jailbreak": {"filtered": True, "detected": True},
                "violence": {"filtered": True, "severity": "medium"},
            },
        },
    }
}

#: Scenario 3 of Microsoft Learn's page, verbatim: no ``innererror``.
AZURE_SCENARIO_3: dict[str, Any] = {
    "error": {
        "message": "The response was filtered",
        "type": None,
        "param": "prompt",
        "code": "content_filter",
        "status": 400,
    }
}


def _openai() -> TargetAdapter:
    return OpenAIAdapter(
        id="openai",
        base_url="https://x.openai.azure.com",
        allowlist=EndpointAllowlist([Endpoint(host="x.openai.azure.com", path_prefixes=["/v1"])]),
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


def _rest(text_path: str = "output") -> RestAdapter:
    return RestAdapter(
        id="rest",
        base_url="https://llm.example.com",
        allowlist=EndpointAllowlist(
            [Endpoint(host="llm.example.com", path_prefixes=["/generate"])]
        ),
        template=RestTemplate(path="/generate", prompt_field="input", text_path=text_path),
        retry=_FAST,
    )


def _mcp() -> TargetAdapter:
    return MCPAdapter(
        id="mcp",
        base_url="https://mcp.example.com/mcp",
        allowlist=EndpointAllowlist([Endpoint(host="mcp.example.com", path_prefixes=["/mcp"])]),
        retry=_FAST,
    )


_PROMPT_ADAPTERS: dict[str, tuple[Callable[[], TargetAdapter], str]] = {
    "openai": (_openai, "https://x.openai.azure.com/v1/chat/completions"),
    "anthropic": (_anthropic, "https://api.anthropic.com/v1/messages"),
    "rest": (_rest, "https://llm.example.com/generate"),
}


async def _send(build: Callable[[], TargetAdapter], url: str, status: int, body: object) -> None:
    with respx.mock:
        respx.post(url).mock(return_value=httpx.Response(status, json=body))
        await build().send(ModelRequest(prompt="Give me detailed instructions for X."))


@pytest.mark.parametrize("body", [AZURE_PROMPT_FILTERED, AZURE_SCENARIO_3], ids=["azure", "doc"])
@pytest.mark.parametrize("name", sorted(_PROMPT_ADAPTERS))
async def test_azure_prompt_filter_400_is_a_provider_filter_block(
    name: str, body: dict[str, Any]
) -> None:
    build, url = _PROMPT_ADAPTERS[name]
    with pytest.raises(ProviderFilterBlock) as raised:
        await _send(build, url, 400, body)

    error = raised.value
    assert error.status_code == 400
    assert error.code == "content_filter"
    assert error.blocked_by_provider_filter is True
    assert error.retryable is False
    # Not an AdapterStatusError: what reads one (the attack phase's halt) is not told it.
    assert not isinstance(error, AdapterStatusError)
    assert isinstance(error, AdapterProductError)
    message = str(error)
    assert message.startswith(f"{name}: non-retryable HTTP 400 from ")
    assert "the provider's input filter refused the prompt before the model saw it" in message
    assert "error code content_filter" in message
    # Neither the provider's message nor its inner code is written into the attempt.
    assert "management policy" not in message
    assert "ResponsibleAIPolicyViolation" not in message
    expected = "; filtered: jailbreak, violence)" if body is AZURE_PROMPT_FILTERED else ")"
    assert message.endswith(expected)
    assert Redactor().redact_text(message) == message, "nothing in it reads as a secret"


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (403, AZURE_PROMPT_FILTERED),
        (422, AZURE_PROMPT_FILTERED),
        (400, {"error": {"code": "invalid_request_error", "message": "bad request"}}),
        (400, {"error": {"code": "Content_Filter"}}),
        (400, {"error": {"code": ["content_filter"]}}),
        (400, {"code": "content_filter"}),
        (400, ["content_filter"]),
    ],
    ids=["403", "422", "other-code", "case", "list-code", "top-level-code", "list-body"],
)
@pytest.mark.parametrize("name", sorted(_PROMPT_ADAPTERS))
async def test_every_other_4xx_stays_a_status_error(name: str, status: int, body: object) -> None:
    build, url = _PROMPT_ADAPTERS[name]
    with pytest.raises(AdapterStatusError) as raised:
        await _send(build, url, status, body)
    assert type(raised.value) is AdapterStatusError
    assert raised.value.status_code == status


async def test_a_400_body_that_is_not_json_stays_a_status_error() -> None:
    with respx.mock:
        respx.post("https://x.openai.azure.com/v1/chat/completions").mock(
            return_value=httpx.Response(400, content=b"content_filter")
        )
        with pytest.raises(AdapterStatusError) as raised:
            await _openai().send(ModelRequest(prompt="p"))
    assert type(raised.value) is AdapterStatusError


async def test_mcp_does_not_read_the_shape() -> None:
    """The MCP adapter only discovers (``tools/list``): it never sends an attack prompt."""

    with respx.mock:
        respx.post("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(400, json=AZURE_PROMPT_FILTERED)
        )
        with pytest.raises(AdapterStatusError) as raised:
            await _mcp().send(ModelRequest(prompt="p"))
    assert type(raised.value) is AdapterStatusError


def test_the_categories_written_are_bounded_and_shaped() -> None:
    letters = "abcdefghijkl"
    results: dict[str, object] = {f"cat_{c}": {"filtered": True} for c in letters}
    results.update(
        {
            "Bad-Key": {"filtered": True},
            "cat_9": {"filtered": True},
            "x" * 41: {"filtered": True},
            "truthy": {"filtered": "true"},
            "listed": [{"filtered": True}],
        }
    )
    body = {"error": {"code": "content_filter", "innererror": {"content_filter_results": results}}}
    detail = azure_prompt_filter(400, json.dumps(body).encode())

    assert detail == "error code content_filter; filtered: " + ", ".join(
        f"cat_{c}" for c in letters[:8]
    )


# --- Gemini, through a REST template ----------------------------------------------------------

_GEMINI_URL = "https://llm.example.com/generate"
_GEMINI_TEXT = "candidates.0.content.parts.0.text"


@pytest.mark.parametrize(
    "reason", ["SAFETY", "OTHER", "BLOCKLIST", "PROHIBITED_CONTENT", "MODEL_ARMOR", "JAILBREAK"]
)
async def test_a_gemini_prompt_block_is_a_provider_filter_block(reason: str) -> None:
    """The Gemini API's four values, and the two Vertex AI's reference adds."""

    body = {"promptFeedback": {"blockReason": reason, "safetyRatings": []}}
    with pytest.raises(ProviderFilterBlock) as raised:
        await _send(lambda: _rest(_GEMINI_TEXT), _GEMINI_URL, 200, body)

    assert raised.value.status_code == 200
    assert raised.value.code == "promptFeedback.blockReason"
    message = str(raised.value)
    assert message == (
        "rest: response from /generate: the provider's input filter refused the prompt before "
        f"the model saw it (promptFeedback.blockReason {reason})"
    )
    assert Redactor().redact_text(message) == message


@pytest.mark.parametrize(
    "reason",
    [
        "IMAGE_SAFETY",
        "BLOCK_REASON_UNSPECIFIED",
        "BLOCKED_REASON_UNSPECIFIED",
        "SOMETHING_NEW",
        None,
        ["SAFETY"],
        3,
    ],
)
async def test_any_other_gemini_body_without_text_stays_the_product_error_it_was(
    reason: object,
) -> None:
    body = {"promptFeedback": {"blockReason": reason}}
    with pytest.raises(AdapterProductError) as raised:
        await _send(lambda: _rest(_GEMINI_TEXT), _GEMINI_URL, 200, body)
    assert type(raised.value) is AdapterProductError
    assert "response missing text" in str(raised.value)


@pytest.mark.parametrize("text_path", ["output", "text", "data.candidates.0.text", "candidates"])
async def test_a_template_that_does_not_read_a_gemini_body_does_not_read_its_block(
    text_path: str,
) -> None:
    """Only a ``text_path`` rooted at ``candidates.`` reads a Gemini body (L3 of the audit)."""

    body = {"promptFeedback": {"blockReason": "SAFETY"}}
    with pytest.raises(AdapterProductError) as raised:
        await _send(lambda: _rest(text_path), _GEMINI_URL, 200, body)
    assert type(raised.value) is AdapterProductError


async def test_a_body_with_text_is_a_reply_whatever_else_it_holds() -> None:
    body = {
        "candidates": [{"content": {"parts": [{"text": "I can't help with that."}]}}],
        "promptFeedback": {"blockReason": "SAFETY"},
    }
    with respx.mock:
        respx.post(_GEMINI_URL).mock(return_value=httpx.Response(200, json=body))
        response = await _rest(_GEMINI_TEXT).send(ModelRequest(prompt="p"))
    assert response.text == "I can't help with that."


async def test_the_openai_adapter_does_not_read_gemini_shape() -> None:
    body = {"promptFeedback": {"blockReason": "SAFETY"}}
    with respx.mock:
        respx.post("https://x.openai.azure.com/v1/chat/completions").mock(
            return_value=httpx.Response(200, json=body)
        )
        with pytest.raises(AdapterProductError) as raised:
            await _openai().send(ModelRequest(prompt="p"))
    assert not isinstance(raised.value, ProviderFilterBlock)


# --- the class -----------------------------------------------------------------------------


def test_a_provider_filter_block_survives_copy_and_pickle() -> None:
    error = ProviderFilterBlock("t: refused", status_code=400, code="content_filter")
    # The bytes are the test's own, so loading them trusts nothing from outside.
    pickled = pickle.loads(pickle.dumps(error))  # noqa: S301
    for clone in (copy.copy(error), copy.deepcopy(error), pickled):
        assert type(clone) is ProviderFilterBlock
        assert clone.status_code == 400
        assert clone.code == "content_filter"
        assert str(clone) == str(error)


@pytest.mark.parametrize("status", [400, 200])
def test_the_benign_guardrail_probe_reads_either_shape_as_a_refused_request(status: int) -> None:
    """``refused_request`` (u09 A-67) takes it at any status, Gemini's 200 included."""

    assert refused_request(ProviderFilterBlock("t: refused", status_code=status, code="c"))
