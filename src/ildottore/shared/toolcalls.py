"""Tool calls in any provider's shape, read one way (``name``, ``id``).

A response carries its tool calls as the provider wrote them: OpenAI nests the name under
``function``, Anthropic's ``tool_use`` block and the mock's fixtures put it at the top. The
evaluators and the in-band tool loop (OD-18) must agree on which tool a call named, so both
read it here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

__all__ = ["call_arguments", "call_id", "call_name"]


def call_name(call: Mapping[str, object]) -> str:
    """The tool a call names: ``name``, or ``function.name``; ``""`` when neither is there."""

    name = call.get("name")
    if isinstance(name, str):
        return name
    fn = call.get("function")
    if isinstance(fn, Mapping):
        fn_name = fn.get("name")
        if isinstance(fn_name, str):
            return fn_name
    return ""


def call_id(call: Mapping[str, object], fallback: str) -> str:
    """The provider's id for a call, or ``fallback`` when it gave none (the mock's fixtures)."""

    value = call.get("id")
    return value if isinstance(value, str) and value else fallback


def call_arguments(call: Mapping[str, object]) -> dict[str, object]:
    """The arguments of a call as a mapping: ``arguments`` / ``input`` / ``args`` /
    ``parameters``, or ``function.arguments``, each either a mapping or OpenAI's JSON string.
    A string that is not a JSON object reads as ``{}``.
    """

    candidates = [call.get(key) for key in ("arguments", "input", "args", "parameters")]
    fn = call.get("function")
    if isinstance(fn, Mapping):
        candidates.append(fn.get("arguments"))
    for value in candidates:
        if isinstance(value, Mapping):
            return dict(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except ValueError:
                return {}
            return dict(parsed) if isinstance(parsed, dict) else {}
    return {}
