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
not kept. Deleting the half instead is what Unicode's security report advises against (UTR #36
rev. 15, 3.5 on deleting code points, 3.6.2 on ill-formed input): it would show the evaluators
text no consumer of the reply sees, a ``<scr`` and ``ipt>`` around a half read as ``<script>``
(OD-28, decided 2026-10-07).
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
    scalars, no shared or cyclic containers) that nothing else holds yet, as at every caller. A
    first walk only looks: a reply with no surrogate, the usual case, is returned as it is and
    costs that scan. Otherwise its strings are replaced inside their lists and dicts, and a dict
    whose keys hold a surrogate is refilled in its order with the keys renamed, one renamed key
    shared by every dict that has it, as ``json.loads`` shares a repeated key. Copying only a
    reply that held a surrogate (``95a7a24``) gave a target 2.8 times the peak memory of a
    4 MiB body for three bytes, and a generator per level of the fix (``dcefb7f``) made a reply
    nested 115,000 levels cost four times main's peak with no surrogate at all (audits of
    A-47). A clean reply now costs about main's peak memory, and
    most hostile shapes no more; the worst is one long string holding a surrogate, about three
    times the parse's peak, since it is held three times while it is replaced (the string, its
    UTF-16 bytes and the new one), as in any version. Both walks keep a plain
    iterator per level instead of recursing, so their own state grows with the nesting, and a
    value nested past the interpreter's recursion limit (``json.loads`` builds some 116,000
    levels on 3.14) costs a loop, not a ``RecursionError``. Returns ``value``, or the well
    formed text when it is a string.
    """

    if isinstance(value, str):
        return well_formed_text(value)
    if not _holds_surrogate(value):
        return value
    renamed: dict[str, str] = {}
    stack: list[tuple[Any, Iterator[tuple[Any, Any]]]] = []
    _enter(value, stack, renamed)
    while stack:
        holder, entries = stack[-1]
        entry = next(entries, None)
        if entry is None:
            stack.pop()
            continue
        slot, item = entry
        # Let go of the pair: an iterator reuses it only when nothing else holds it, and a pair
        # kept at every level held each replaced string while the levels below were fixed.
        entry = None
        if isinstance(item, str):
            if _SURROGATE.search(item) is not None:
                holder[slot] = well_formed_text(item)
        else:
            _enter(item, stack, renamed)
    return value


def _holds_surrogate(value: Any) -> bool:
    """Whether any string in ``value``, a key or a value, holds a surrogate.

    A dict's keys are read when it is reached and its values queued, so a level costs one
    plain iterator (a chain over its items cost a deep reply two thirds more than main's peak).
    """

    stack: list[Iterator[Any]] = [iter((value,))]
    while stack:
        item = next(stack[-1], _END)
        if item is _END:
            stack.pop()
        elif isinstance(item, str):
            if _SURROGATE.search(item) is not None:
                return True
        elif isinstance(item, dict):
            if any(isinstance(key, str) and _SURROGATE.search(key) for key in item):
                return True
            stack.append(iter(item.values()))
        elif isinstance(item, list):
            stack.append(iter(item))
    return False


#: The end of an iterator in :func:`_holds_surrogate`, where ``None`` is a value.
_END: Final = object()


def _enter(
    item: Any, stack: list[tuple[Any, Iterator[tuple[Any, Any]]]], renamed: dict[str, str]
) -> None:
    """Queue the entries of a container (after renaming its keys); ignore a scalar.

    Assigning to a slot that already exists does not disturb the iterator over it: a dict's
    size does not change, and a list keeps its length.
    """

    if isinstance(item, dict):
        _rename_keys(item, renamed)
        stack.append((item, iter(item.items())))
    elif isinstance(item, list):
        stack.append((item, enumerate(item)))


def _rename_keys(mapping: dict[Any, Any], renamed: dict[str, str]) -> None:
    """Refill ``mapping`` in its order, a key that holds a surrogate made well formed.

    Two keys can read the same once replaced (one half or another at the same place), and a
    plain rename would keep only the last value: a tool call's second argument, or a logprob
    alternative, gone from what the evaluators read. A key that is already well formed keeps
    its name; a replaced one that lands on a name in use takes the next ``, #n`` suffix, the
    form the evidence store gives two keys that mask to one. ``renamed`` holds each key's well
    formed text for the whole walk, and each suffixed name, so a key repeated in many dicts
    stays one string (rebuilding a suffixed name per dict, as ``11a5397`` did, cost 4.5 times
    the parse's peak).
    """

    if not any(isinstance(key, str) and _SURROGATE.search(key) for key in mapping):
        return
    last: dict[str, int] = {}
    # Every key is taken out and put back in its turn, so the order holds; a well formed key
    # not yet reached is still in ``mapping``, so a renamed key cannot take its name.
    for key in list(mapping):
        item = mapping.pop(key)
        name = key
        if isinstance(key, str) and _SURROGATE.search(key) is not None:
            base = renamed.get(key)
            if base is None:
                base = renamed[key] = well_formed_text(key)
            name = base
            while name in mapping:
                last[base] = last.get(base, 1) + 1
                name = f"{base}, #{last[base]}"
            if name is not base:  # a suffixed name, shared like the base (it holds no surrogate)
                name = renamed.setdefault(name, name)
        mapping[name] = item
