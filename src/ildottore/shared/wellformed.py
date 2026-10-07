"""Text a reply can carry and UTF-8 cannot: a lone surrogate, read as U+FFFD where it is parsed.

JSON lets a string escape any UTF-16 code unit, so a reply can hold half a character: the
escape for U+D800 with no low half after it, a low half alone, or the raw bytes ``ED A0 80``,
which ``json.loads`` decodes with ``surrogatepass``. Python keeps each as a code point that no
UTF-8 writer accepts, and every place a reply goes refused it: the evidence store's content
hash, sqlite and httpx encoding the next request of a multi-turn spec raise
``UnicodeEncodeError``, pydantic's JSON serializer ``PydanticSerializationError``. One such
reply aborted the whole campaign, ``run`` with exit 3 and "N of N specs never ran or did not
finish", ``run -sV`` with no report (2026-10-07, A-47).

A lone surrogate is replaced by U+FFFD, the replacement character, as WebIDL's ``USVString``
conversion and JavaScript's ``String.prototype.toWellFormed`` do. A high half followed by a low
half is the character the pair encodes (so a CESU-8 pair parsed from bytes joins), and every
other character is kept. The reply is still evaluated: refusing it instead would let a target
turn any failure into "not evaluated" by adding six characters. Which code unit stood there is
not kept (OD-28).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
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
    """``value`` with every string in it, a key or a value, made well formed, in place.

    ``value`` is a fresh parse, a tree as ``json.loads`` builds it (dicts, lists, strings and
    scalars, no shared or cyclic containers) that nothing else holds yet, as at every caller:
    its strings are replaced inside their lists and dicts, and a dict whose keys hold a
    surrogate is refilled with the keys renamed. So a reply costs no memory beyond the walk:
    copying every reply tripled the peak of a 4 MiB body of small containers, and copying only
    one that holds a surrogate gave a target 2.8 times the peak for three bytes (audits of
    A-47). The walk keeps one iterator per level instead of recursing, so its memory grows with
    the nesting, not the size, and a value nested past the interpreter's recursion limit
    (``json.loads`` builds some 116,000 levels on 3.14) costs a loop, not a
    ``RecursionError``. Returns ``value``, or the well formed text when it is a string.
    """

    if isinstance(value, str):
        return well_formed_text(value)
    stack: list[Iterator[tuple[Any, Any, Any]]] = []
    _enter(value, stack)
    while stack:
        entry = next(stack[-1], None)
        if entry is None:
            stack.pop()
            continue
        holder, slot, item = entry
        if isinstance(item, str):
            if _SURROGATE.search(item) is not None:
                holder[slot] = well_formed_text(item)
        else:
            _enter(item, stack)
    return value


def _enter(item: Any, stack: list[Iterator[tuple[Any, Any, Any]]]) -> None:
    """Queue the entries of a container (after renaming its keys); ignore a scalar.

    Assigning to a slot that already exists does not disturb the iterator over it: a dict's
    size does not change, and a list keeps its length.
    """

    if isinstance(item, dict):
        _rename_keys(item)
        stack.append((item, key, child) for key, child in item.items())
    elif isinstance(item, list):
        stack.append((item, index, child) for index, child in enumerate(item))


def _rename_keys(mapping: dict[Any, Any]) -> None:
    """Refill ``mapping`` in its order, a key that holds a surrogate made well formed.

    Two keys can read the same once replaced (one half or another at the same place), and a
    plain rename would keep only the last value: a tool call's second argument, or a logprob
    alternative, gone from what the evaluators read. A key that is already well formed keeps
    its name; a replaced one that lands on a name in use takes the next ``, #n`` suffix, the
    form the evidence store gives two keys that mask to one.
    """

    if not any(isinstance(key, str) and _SURROGATE.search(key) for key in mapping):
        return
    items = list(mapping.items())
    mapping.clear()
    kept = {key for key, _ in items if not (isinstance(key, str) and _SURROGATE.search(key))}
    last: dict[str, int] = {}
    for key, item in items:
        name = key
        if key not in kept:
            name = base = well_formed_text(key)
            while name in kept or name in mapping:
                last[base] = last.get(base, 1) + 1
                name = f"{base}, #{last[base]}"
        mapping[name] = item
