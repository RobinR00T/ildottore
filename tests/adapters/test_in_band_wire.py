"""The in-band setup's tools and tool turns in each provider's wire shape (OD-18)."""

from __future__ import annotations

import json

from ildottore.adapters.anthropic import AnthropicAdapter
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.policy import EndpointAllowlist
from ildottore.shared.models import ModelRequest

_NEUTRAL_TOOL = {"name": "lookup_ticket", "description": "d", "parameters": {"type": "object"}}
_HISTORY = [
    {"role": "user", "content": "look it up"},
    {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {"id": "a", "name": "lookup_ticket", "arguments": {"id": 1}},
            {"id": "b", "name": "lookup_ticket", "arguments": {"id": 2}},
        ],
    },
    {"role": "tool", "tool_call_id": "a", "name": "lookup_ticket", "content": "one"},
    {"role": "tool", "tool_call_id": "b", "name": "lookup_ticket", "content": "two"},
]


def test_openai_gets_functions_and_tool_messages(openai_allowlist: EndpointAllowlist) -> None:
    adapter = OpenAIAdapter(
        id="o", base_url="https://api.openai.com", allowlist=openai_allowlist, model="m"
    )
    body, _ = adapter._build_request(ModelRequest(messages=_HISTORY, tools=[_NEUTRAL_TOOL]))
    assert body["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "lookup_ticket",
                "description": "d",
                "parameters": {"type": "object"},
            },
        }
    ]
    call = body["messages"][1]["tool_calls"][0]
    assert call["type"] == "function" and json.loads(call["function"]["arguments"]) == {"id": 1}
    assert body["messages"][2] == {"role": "tool", "tool_call_id": "a", "content": "one"}


def test_anthropic_gets_tool_use_and_one_user_turn_of_results(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    adapter = AnthropicAdapter(
        id="a", base_url="https://api.anthropic.com", allowlist=anthropic_allowlist, model="m"
    )
    body, _ = adapter._build_request(ModelRequest(messages=_HISTORY, tools=[_NEUTRAL_TOOL]))
    assert body["tools"] == [
        {"name": "lookup_ticket", "description": "d", "input_schema": {"type": "object"}}
    ]
    assistant, results = body["messages"][1], body["messages"][2]
    assert [b["type"] for b in assistant["content"]] == ["tool_use", "tool_use"]
    assert assistant["content"][0]["input"] == {"id": 1}
    assert results["role"] == "user" and [b["tool_use_id"] for b in results["content"]] == [
        "a",
        "b",
    ]
    assert len(body["messages"]) == 3


def test_anthropic_drops_a_blank_text_before_a_tool_call(
    anthropic_allowlist: EndpointAllowlist,
) -> None:
    adapter = AnthropicAdapter(
        id="a", base_url="https://api.anthropic.com", allowlist=anthropic_allowlist, model="m"
    )
    history = [dict(_HISTORY[0]), {**_HISTORY[1], "content": "  \n"}, *_HISTORY[2:]]
    body, _ = adapter._build_request(ModelRequest(messages=history, tools=[_NEUTRAL_TOOL]))
    assert [b["type"] for b in body["messages"][1]["content"]] == ["tool_use", "tool_use"]
