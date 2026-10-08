"""JSON a target or a model wrote, parsed with its nesting bounded (2026-10-07).

``json.loads`` raises ``RecursionError``, not a ``ValueError``, on a document nested past the
parser's stack (about 116,000 levels on Python 3.14, about 10,000 on 3.12, fewer on 3.11),
so every handler written for malformed JSON let it through, and one 400 KB reply of ``[``
aborted a whole campaign. A document the parser accepts can be as fatal later: pydantic refuses
to serialise a value more than 255 levels deep, and the redactor, ``repr`` and ``json.dumps``
overflow too, so a reply of 300 levels (about 600 bytes) aborted the campaign when its evidence
was written.

:func:`bounded_loads` measures a text's brackets before it is parsed (:func:`text_depth`), so the
parser never decides and the verdict does not depend on the Python version (a run of unclosed
``[`` was "not JSON" on 3.14 and a stack overflow on 3.12; pre-commit audit). Brackets that nest
deeper than :data:`MAX_DEPTH` and balance are refused as too deep, whether or not the rest is
valid JSON; brackets that do not balance are not JSON, and are refused as that without being
parsed. A provider's reply nests about 10 levels (an OpenAI reply with logprobs, 9), so the
limit leaves room for any real one and keeps everything downstream far from its own limits.
"""

from __future__ import annotations

import json
import re
from itertools import accumulate
from typing import Any

__all__ = ["MAX_DEPTH", "NestedTooDeeply", "bounded_loads", "text_depth"]

#: The deepest a JSON text may nest, counting objects and arrays (``{"a": [1]}`` is 2).
MAX_DEPTH = 100

#: A JSON string, or an unterminated one running to the end of the text (whose brackets are no
#: more structure than a terminated string's). Once it has seen a quote it cannot fail, so every
#: match is linear: one that failed on a lone backslash at the very end was retried from every
#: escaped quote, 38 s for 160 KB (delta audit). Possessive, or each escape keeps a backtracking
#: mark (241 MB for 4 MiB); ``DOTALL``, or a backslash before a newline fails it again.
_STRING = re.compile(r'"[^"\\]*+(?:\\.[^"\\]*+)*+(?:"|\\?\Z)', re.DOTALL)
_NOT_BRACKET = re.compile(r"[^\[\]{}]++")
_STEP = {"[": 1, "{": 1, "]": -1, "}": -1}


class NestedTooDeeply(ValueError):
    """A JSON text nested deeper than :data:`MAX_DEPTH`."""


def text_depth(text: str) -> int:
    """How deep the brackets of a JSON text nest, outside its strings, without parsing it.

    For valid JSON it is the depth of the parsed value (a scalar is 0), or more when a key
    written twice drops a deeper value. For a text that is not JSON it is what its brackets
    reach, which is at least as deep as a parser gets before it stops, so a refusal on it never
    lets the parser recurse past :data:`MAX_DEPTH`.
    """

    return _profile(text)[0]


def _profile(text: str) -> tuple[int, bool]:
    """The deepest the brackets outside strings reach, and whether as many close as open.

    Brackets that do not balance (left open, or closed more often than opened) cannot be JSON.
    """

    skeleton = _NOT_BRACKET.sub("", _STRING.sub("", text))
    deepest = max(0, max(accumulate(map(_STEP.__getitem__, skeleton)), default=0))
    opened = skeleton.count("[") + skeleton.count("{")
    return deepest, 2 * opened == len(skeleton)


def bounded_loads(text: str | bytes) -> Any:
    """``json.loads``, refusing a text nested deeper than :data:`MAX_DEPTH` before parsing it.

    Raises :class:`NestedTooDeeply` (a ``ValueError``) for the depth; a plain ``ValueError`` for
    brackets past the limit that do not balance; and what ``json.loads`` raises for anything else
    that is not JSON (``json.JSONDecodeError``, or ``UnicodeDecodeError`` for bytes that are not
    text: ``ValueError`` s too). Bytes are decoded as ``json.loads`` decodes them.
    """

    if isinstance(text, bytes | bytearray):
        text = text.decode(json.detect_encoding(text), "surrogatepass")
    # Fewer brackets than the limit cannot nest past it: most replies stop here.
    if text.count("[") + text.count("{") > MAX_DEPTH:
        deepest, balanced = _profile(text)
        if deepest > MAX_DEPTH and not balanced:
            # Not JSON whatever it holds, and parsing it would recurse: refused as what it is.
            # Refused as too deep, 101 unclosed `[` in a tool call's arguments failed the reply
            # where they read as no arguments before (delta audit).
            raise ValueError("not JSON: its brackets do not balance")
        if deepest > MAX_DEPTH:
            raise NestedTooDeeply(f"nested more than {MAX_DEPTH} levels deep")
    try:
        return json.loads(text)
    except RecursionError as exc:  # the measure above stops it first: kept as a backstop
        raise NestedTooDeeply(f"nested more than {MAX_DEPTH} levels deep") from exc
