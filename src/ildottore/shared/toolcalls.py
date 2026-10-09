"""Tool calls in any provider's shape, read one way (``name``, ``id``).

A response carries its tool calls as the provider wrote them: OpenAI nests the name under
``function``, Anthropic's ``tool_use`` block and the mock's fixtures put it at the top. The
evaluators and the in-band tool loop (OD-18) must agree on which tool a call named, so both
read it here.
"""

from __future__ import annotations

from collections.abc import Mapping

from ildottore.shared.nesting import NestedTooDeeply, bounded_loads
from ildottore.shared.wellformed import well_formed_json

__all__ = ["call_arguments", "call_id", "call_name", "check_argument_nesting"]


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
    A string that is not a JSON object reads as ``{}``, and so does one nested deeper than
    :data:`~ildottore.shared.nesting.MAX_DEPTH`. A live reply carrying one never gets here:
    every adapter that reads tool calls refuses it (:func:`check_argument_nesting`: the base
    adapter's OpenAI and Anthropic replies, and a WebSocket target's frames when its block
    declares ``tool_calls_path``; the REST template and MCP discovery read none), so only a
    call from elsewhere (a fixture) can read as ``{}`` for its depth, where ``json.loads``
    raised ``RecursionError``.
    A lone surrogate escaped in that string reads as U+FFFD, as it does in the reply around
    it (A-47).
    """

    value = _raw_arguments(call)
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = well_formed_json(bounded_loads(value))
        except ValueError:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}
    return {}


def check_argument_nesting(call: Mapping[str, object]) -> None:
    """Raise :class:`~ildottore.shared.nesting.NestedTooDeeply` when the arguments
    :func:`call_arguments` would read are a JSON string nested too deeply.

    A string is the one part of a reply its own parse never opened; arguments that are a
    mapping were parsed, and measured, with the reply. A string that is not JSON passes: it
    reads as ``{}``, as before.
    """

    value = _raw_arguments(call)
    if not isinstance(value, str):
        return
    try:
        bounded_loads(value)
    except NestedTooDeeply:
        raise
    except ValueError:
        return


def _raw_arguments(call: Mapping[str, object]) -> object:
    """The first candidate that is a mapping or a string: the one :func:`call_arguments` reads."""

    candidates = [call.get(key) for key in ("arguments", "input", "args", "parameters")]
    fn = call.get("function")
    if isinstance(fn, Mapping):
        candidates.append(fn.get("arguments"))
    for value in candidates:
        if isinstance(value, Mapping | str):
            return value
    return None
