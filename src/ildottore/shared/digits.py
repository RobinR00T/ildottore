"""Numbers too long to write out, found before anything tries to write them.

Python refuses to turn an int of more than ``sys.get_int_max_str_digits()`` decimal digits into
text (4,300 by default, 640 at the lowest ``PYTHONINTMAXSTRDIGITS`` allows): ``str``, ``repr``,
an f-string and ``json.dumps`` raise ``ValueError``. YAML builds such an int from a short hex
literal (``0x`` and 4,000 ``f``), and whatever formatted it first failed: jsonschema's
``<value> is not of type 'string'`` made ``dottore lint`` a traceback with exit 1, and ``run``
and ``calibrate`` printed ``error: Exceeds the limit`` naming no file (pre-commit audit of
``fix/yaml-alias-expansion-cap``, 2026-10-07). The callers check where the value enters,
whatever the YAML loader caps: the limit can be lowered under the length of any literal cap,
and a value can come from JSON or be built in code. Clause A-40 (u02).
"""

from __future__ import annotations

import sys
from collections.abc import Iterator

__all__ = ["described", "path_text", "shown", "too_long", "too_long_paths"]


def too_long(value: object) -> bool:
    """Whether ``value`` is an int that ``str`` refuses under the current digit limit.

    The interpreter's own conversion decides, so nothing accepted here fails to print later;
    an int far past the limit is refused by its size before any digit is computed.
    """

    if not isinstance(value, int) or sys.get_int_max_str_digits() == 0:  # 0: no limit
        return False
    try:
        int.__repr__(value)
    except ValueError:
        return True
    return False


def described(verb: str = "write out") -> str:
    """What a message says instead of such a number, which it never quotes."""

    return f"a number too long to {verb} (over {sys.get_int_max_str_digits()} digits)"


def shown(value: object) -> str:
    """``repr(value)``, or what it holds when that is a number too long to write out."""

    try:
        return repr(value)
    except ValueError:
        return described() if isinstance(value, int) else f"a value holding {described()}"


def path_text(path: tuple[object, ...]) -> str:
    """``a/b/0/c`` for a path into a document, ``<root>`` for the document itself."""

    return "/".join(_part_text(part) for part in path) or "<root>"


def _part_text(part: object) -> str:
    try:
        return str(part)
    except ValueError:  # a key that is, or holds, a number too long to write out
        return "<number>" if isinstance(part, int) else "<value>"


def too_long_paths(data: object) -> Iterator[tuple[tuple[object, ...], bool]]:
    """Every place in ``data`` holding a number :func:`too_long` refuses.

    Yields ``(path, is_key)``: the path of the value, or, for a mapping key, of the mapping that
    holds it; in document order, a set's members in the set's own. Tuples and sets are entered
    too: YAML builds a list of tuples for ``!!omap`` and ``!!pairs`` and a set for ``!!set``,
    whose members are its keys, and a walk of mappings and lists alone let a number inside them
    through to the same traceback (pre-commit audit of A-40). Walked without recursion, each
    place holding only a link to its parent until a path is yielded; a container that YAML
    shares through an alias is entered once, and each number is converted once however often
    it is shared.
    """

    checked: dict[int, bool] = {}
    entered: set[int] = set()
    links: list[tuple[int, object]] = []  # (parent link, key or index); -1 is the document
    # (is_key, item, link to its path): a key is checked where it is written, before its value.
    stack: list[tuple[bool, object, int]] = [(False, data, -1)]
    while stack:
        is_key, item, link = stack.pop()
        if isinstance(item, dict | list | tuple | set | frozenset):
            if id(item) in entered:
                continue
            entered.add(id(item))
            children: list[tuple[bool, object, int]] = []
            if isinstance(item, dict):
                for key, value in item.items():
                    links.append((link, key))
                    children += [(True, key, link), (False, value, len(links) - 1)]
            elif is_key or isinstance(item, set | frozenset):
                children = [(True, member, link) for member in item]
            else:
                for index, value in enumerate(item):
                    links.append((link, index))
                    children.append((False, value, len(links) - 1))
            stack.extend(reversed(children))
        elif isinstance(item, int):
            if id(item) not in checked:
                checked[id(item)] = too_long(item)
            if checked[id(item)]:
                yield _path(links, link), is_key


def _path(links: list[tuple[int, object]], link: int) -> tuple[object, ...]:
    parts: list[object] = []
    while link >= 0:
        link, part = links[link]
        parts.append(part)
    return tuple(reversed(parts))
