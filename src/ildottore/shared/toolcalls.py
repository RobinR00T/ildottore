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

__all__ = ["LongInteger", "call_arguments", "call_id", "call_name", "check_argument_nesting"]


class LongInteger(str):
    """An integer in a call's JSON-string arguments with more digits than ``int`` converts.

    ``json.loads`` converts every integer with ``int``, which refuses more digits than the
    interpreter's limit (``sys.get_int_max_str_digits``, 4300 by default; the limit bounds a
    conversion whose cost grows as the square of its length). Refused, the whole string read as
    no arguments, ``{}``, so one long number beside a smuggled key, a forbidden value or an
    injection made ``tool_call`` pass (L5 of the pre-merge audit of A-88, u06 A-89). Such an
    integer is kept as its digits, sign included, exactly as the text wrote them, and the rest of
    the arguments are read. The evaluators read it as they read a number: its text is its JSON
    spelling (``shared.tool_abuse.arg_value_text``), it is written unquoted in a map
    (``canonical_value_text``), and the patterns that read only strings (the injection markers,
    ``tool_sequence``'s ``step_arg_patterns``) skip it. Sent back to the target by the in-band
    tool loop, it is a JSON string: a ``str`` subclass serializes where an object of its own
    would raise in ``json.dumps``.
    """

    __slots__ = ()


def _integer(digits: str) -> int | LongInteger:
    """``int`` of a JSON integer's digits, or the digits kept when ``int`` refuses their length.

    The JSON grammar has already checked them, so the one ``ValueError`` left is the limit.
    """

    try:
        return int(digits)
    except ValueError:
        return LongInteger(digits)


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
    it (A-47). An integer in it with more digits than ``int`` converts reads as a
    :class:`LongInteger`, the rest of the object around it as written (A-89).
    """

    value = _raw_arguments(call)
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = well_formed_json(bounded_loads(value, parse_int=_integer))
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
        bounded_loads(value, parse_int=_integer)
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
