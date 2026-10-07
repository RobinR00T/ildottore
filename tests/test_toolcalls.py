"""Tool calls read one way across provider shapes (``shared.toolcalls``, OD-18)."""

from __future__ import annotations

import pytest

from ildottore.shared.toolcalls import call_arguments, call_id, call_name

_OPENAI = {"id": "c1", "type": "function", "function": {"name": "f", "arguments": '{"a": 1}'}}
_ANTHROPIC = {"type": "tool_use", "id": "t1", "name": "f", "input": {"a": 1}}
_MOCK = {"name": "f", "args": {"a": 1}}


@pytest.mark.parametrize("call", [_OPENAI, _ANTHROPIC, _MOCK])
def test_every_shape_names_the_tool_and_its_arguments(call: dict[str, object]) -> None:
    assert call_name(call) == "f"
    assert call_arguments(call) == {"a": 1}


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ({"function": {"name": "f", "arguments": "not json"}}, {}),
        ({"function": {"name": "f", "arguments": "[1, 2]"}}, {}),
        ({"name": "f"}, {}),
        ({"function": {"name": 3}}, {}),
    ],
)
def test_arguments_that_are_not_an_object_read_as_none(
    call: dict[str, object], expected: dict[str, object]
) -> None:
    assert call_arguments(call) == expected


def test_a_call_without_a_name_or_an_id() -> None:
    assert call_name({"function": {"name": 3}}) == ""
    assert call_name({}) == ""
    assert call_id(_OPENAI, "fallback") == "c1"
    assert call_id(_MOCK, "fallback") == "fallback"
    assert call_id({"id": ""}, "fallback") == "fallback"
