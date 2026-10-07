"""Text a reply can carry and UTF-8 cannot: a lone surrogate, read as U+FFFD where it is parsed.

JSON lets a string escape any UTF-16 code unit, so a reply can hold half a character: the
escape for U+D800 with no low half after it, a low half alone, or the raw bytes ``ED A0 80``,
which ``json.loads`` decodes with ``surrogatepass``. Python keeps each as a code point that no
UTF-8 writer accepts, and every place a reply goes raised ``UnicodeEncodeError`` on it: the
evidence store's content hash, sqlite, httpx encoding the next request of a multi-turn spec, and
pydantic's JSON serializer. One such reply aborted the whole campaign, ``run`` with exit 3 and
"N of N specs never ran", ``run -sV`` with no report (2026-10-07, A-47).

A lone surrogate is replaced by U+FFFD, the replacement character, as WebIDL's ``USVString``
conversion and JavaScript's ``String.prototype.toWellFormed`` do. A high half followed by a low
half is the character the pair encodes (a CESU-8 body decodes that way), and every other
character is kept. The reply is still evaluated: refusing it instead would let a target turn
any failure into "not evaluated" by adding six characters. Which code unit stood there is not
kept (OD-28).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from itertools import chain
from typing import Any, Final

__all__ = ["REPLACEMENT", "well_formed_json", "well_formed_text"]

#: What a lone surrogate reads as.
REPLACEMENT: Final = chr(0xFFFD)

_SURROGATE: Final = re.compile(f"[{chr(0xD800)}-{chr(0xDFFF)}]")


def well_formed_text(text: str) -> str:
    """``text`` with each lone surrogate replaced by U+FFFD and each surrogate pair joined.

    UTF-16 with ``surrogatepass`` writes every code point as its code units, and decoding them
    back with ``replace`` is exactly the rule above, in C. A text with no surrogate is returned
    as it is.
    """

    if _SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def well_formed_json(value: Any) -> Any:
    """A parsed JSON value whose every string, key or value, is well formed.

    A value that holds no surrogate is returned as it is, the same object: copying every reply
    tripled the peak memory of a 4 MiB body of small containers (pre-commit audit). One that
    holds one is copied with each string made well formed. Both walks keep their own list
    instead of recursing, so a value nested past the interpreter's recursion limit
    (``json.loads`` builds some 116,000 levels on 3.14) costs a loop, not a ``RecursionError``.
    ``value`` is a tree as ``json.loads`` builds it: dicts, lists, strings and scalars, with no
    shared or cyclic containers.
    """

    if isinstance(value, str):
        return well_formed_text(value)
    if not isinstance(value, dict | list) or not _holds_surrogate(value):
        return value
    pending: list[tuple[Any, Any]] = []
    root = _child(value, pending)
    while pending:
        source, copy = pending.pop()
        if isinstance(source, dict):
            _fill(source, copy, pending)
        else:
            copy.extend(_child(item, pending) for item in source)
    return root


def _holds_surrogate(value: Any) -> bool:
    """Whether any string in ``value``, a key or a value, holds a surrogate.

    Depth first over iterators, so what it keeps grows with the nesting, not with the size.
    """

    end = object()
    stack: list[Iterator[Any]] = [iter((value,))]
    while stack:
        item = next(stack[-1], end)
        if item is end:
            stack.pop()
        elif isinstance(item, str):
            if _SURROGATE.search(item) is not None:
                return True
        elif isinstance(item, dict):
            stack.append(chain.from_iterable(item.items()))
        elif isinstance(item, list):
            stack.append(iter(item))
    return False


def _child(item: Any, pending: list[tuple[Any, Any]]) -> Any:
    """``item`` made well formed if it is a string, an empty copy queued if it is a container."""

    if isinstance(item, str):
        return well_formed_text(item)
    if isinstance(item, dict):
        copy: dict[Any, Any] = {}
        pending.append((item, copy))
        return copy
    if isinstance(item, list):
        items: list[Any] = []
        pending.append((item, items))
        return items
    return item


def _fill(source: dict[Any, Any], copy: dict[Any, Any], pending: list[tuple[Any, Any]]) -> None:
    """Copy ``source`` into ``copy``, renaming a key whose surrogates make it collide.

    Two keys can read the same once replaced (one half or another at the same place), and a
    plain copy would keep only the last value: a tool call's second argument, or a logprob
    alternative, gone from what the evaluators read. A key that is already well formed keeps
    its name; a replaced one that lands on a name in use takes the next ``, #n`` suffix, the
    form the evidence store gives two keys that mask to one.
    """

    kept = {key for key in source if not (isinstance(key, str) and _SURROGATE.search(key))}
    last: dict[str, int] = {}
    for key, item in source.items():
        name = key
        if key not in kept:
            name = base = well_formed_text(key)
            while name in kept or name in copy:
                last[base] = last.get(base, 1) + 1
                name = f"{base}, #{last[base]}"
        copy[name] = _child(item, pending)
