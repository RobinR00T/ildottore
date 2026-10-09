"""Error text for the operator's own files that never quotes the values in them.

Scope, target and fleet files are where credentials get named, and sometimes pasted by
mistake. pydantic's message echoes the offending input (``input_value='<key>'``, truncated in
the middle, so the tail survived) and PyYAML's quotes a snippet of the line. The CLI's
redactor caught a pasted key only by its entropy, so these two helpers report where and why,
not the values (audits of the 2026-10-03 residuals). Two things still come through, because
they are the location or the reason itself: a mapping KEY the operator typed (it is part of
pydantic's field path) and an alias or tag name PyYAML could not resolve.

What does come through is cut at :data:`MAX_PROBLEM_CHARS`, and so is a value a refusal written
by hand names (:func:`quoted`): a 1 MB ``type:`` in a target file printed an ``error:`` line of
1,000,108 bytes, and an undefined alias of a million characters one of about 1,000,100
(pre-commit audit of the read cap, clause A-51).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sized
from typing import TYPE_CHECKING, cast

from pydantic import ValidationError

from ildottore.shared.digits import described

if TYPE_CHECKING:  # annotation only: `shared` imports pydantic and the stdlib at run time
    import yaml

__all__ = [
    "MAX_LISTED_PROBLEMS",
    "MAX_PROBLEM_CHARS",
    "cut",
    "listed",
    "quoted",
    "validation_problems",
    "yaml_problem",
]

#: Errors listed by default; the rest are counted, not listed. The spec loader's figure.
MAX_LISTED_PROBLEMS = 20
#: A field path, a reason or a quoted value longer than this is cut. The spec loader's figure for
#: a message.
MAX_PROBLEM_CHARS = 300


def validation_problems(exc: ValidationError, *, limit: int = MAX_LISTED_PROBLEMS) -> str:
    """``field.path: reason`` for the first ``limit`` errors, without the input value or a docs URL.

    The rest are counted, not listed, and a path or a reason past :data:`MAX_PROBLEM_CHARS` is
    cut. Listing every error, whole, made a 5.5 MB scope with 5,500 extra keys of 1,000
    characters print one ``error:`` line of 5,687,058 characters (pre-commit audit of the
    alias-expansion cap, 2026-10-07): a key the operator typed is part of the path.
    """

    errors = exc.errors(include_input=False, include_url=False)
    shown = errors[:limit]
    text = "; ".join(
        f"{cut('.'.join(str(part) for part in err['loc']) or '<root>')}: {cut(err['msg'])}"
        for err in shown
    )
    if len(shown) < len(errors):
        text += f"; and {len(errors) - len(shown)} more"
    return text


def cut(text: str) -> str:
    """``text``, or its first :data:`MAX_PROBLEM_CHARS` characters and its length.

    The length is written bare, as the spec loader writes it. For the ``repr`` of a text value
    (:func:`quoted`) it stays under 10,485,762, short of the nine digits the CLI's redactor masks
    as a phone number: ``repr`` writes at most ten characters (``\\U000e0001``) for a character
    the file spends a byte or more on, and the file is read up to 1 MiB.
    """

    if len(text) <= MAX_PROBLEM_CHARS:
        return text
    return f"{text[:MAX_PROBLEM_CHARS]}... ({len(text)} characters)"


def quoted(value: object) -> str:
    """``repr(value)`` as a refusal may quote it: its first :data:`MAX_PROBLEM_CHARS` characters.

    For the refusals written by hand that name a value of the operator's file (an invalid
    ``type``, a duplicated id, a label's spec id): they quoted it whole, bounded only by the
    1 MiB read, so a 1 MB ``type:`` printed an ``error:`` line of 1,000,108 bytes and a 500 KB
    duplicated target id one of 500,136 (clause A-51). A value whose ``repr`` is 300 characters
    or fewer is quoted exactly as before. A longer one is cut as :func:`cut` cuts it, and a list,
    mapping or set says how many items it holds instead: its ``repr`` is never built whole,
    because YAML aliases make it larger than its file (90 KB of a list of 20,000 aliases of one
    10 KB text is 200,080,000 characters of ``repr``, about 200 MB to build).
    """

    if type(value) not in _CONTAINERS:
        return cut(_repr(value))
    head = _repr_head(value, MAX_PROBLEM_CHARS + 1)
    if len(head) <= MAX_PROBLEM_CHARS:
        return head
    return f"{head[:MAX_PROBLEM_CHARS]}... ({len(cast('Sized', value))} items)"


def listed(
    texts: Iterable[str], *, show: Callable[[str], str] = cut, limit: int = MAX_LISTED_PROBLEMS
) -> str:
    """``a, b, c``: the first ``limit`` texts, each written by ``show``, and how many more.

    For a refusal that lists what the file declares: the ids a scope authorizes (each cut as
    :func:`cut` cuts it) and the credentials it declares for a target (each as an error may quote
    one). With the refusal's own quote cut, a scope id of a million characters still came back
    whole in the first when the scope named the target and refused its endpoint, and 3,000
    declared credentials printed 885,131 bytes in the second (clause A-51 and its audit).
    """

    items = list(texts)
    text = ", ".join(show(item) for item in items[:limit])
    if len(items) > limit:
        text += f", and {len(items) - limit} more"
    return text


_CONTAINERS = (list, tuple, dict, set, frozenset)


def _repr(item: object) -> str:
    """``repr(item)``, or what an integer is when Python will not write it out.

    A YAML integer in hex or in base 60 is built past the digits Python converts to text, and
    ``repr`` then raises (audit of A-51): the refusal that quoted it raised instead. It is
    described as ``shared.digits`` describes it (A-40); any other failure is raised.
    """

    try:
        return repr(item)
    except ValueError:
        if isinstance(item, int):
            return described()
        raise


def _repr_head(value: object, budget: int) -> str:
    """The first ``budget`` characters of ``repr(value)``, building no more of it than that.

    The containers YAML builds (a list, a mapping, a ``!!set``, the pairs of an ``!!omap``) are
    written as ``repr`` writes them, piece by piece, and the walk stops once ``budget``
    characters are out. Anything else is one ``repr``: a text holds no alias, so its ``repr`` is
    at most four times its share of the file.
    """

    parts: list[str] = []
    size = 0

    def out(text: str) -> bool:
        nonlocal size
        parts.append(text)
        size += len(text)
        return size < budget

    def items(opening: str, values: Iterable[object], closing: str, pairs: bool = False) -> bool:
        if not out(opening):
            return False
        for index, item in enumerate(values):
            if index and not out(", "):
                return False
            if pairs:
                key, entry = cast("tuple[object, object]", item)
                if not (walk(key) and out(": ") and walk(entry)):
                    return False
            elif not walk(item):
                return False
        return out(closing)

    def walk(item: object) -> bool:
        if type(item) is dict:
            return items("{", item.items(), "}", pairs=True)
        if type(item) is list:
            return items("[", item, "]")
        if type(item) is tuple:
            return items("(", item, ",)" if len(item) == 1 else ")")
        if type(item) in (set, frozenset) and item:
            opening, closing = ("{", "}") if type(item) is set else ("frozenset({", "})")
            return items(opening, cast("set[object]", item), closing)
        return out(_repr(item))

    walk(value)
    return "".join(parts)[:budget]


def yaml_problem(exc: yaml.YAMLError) -> str:
    """What PyYAML found wrong and where, without the snippet of the line it quotes.

    The position where PyYAML noticed the problem can be the line AFTER the typo (a missing
    space after a colon is reported on the next line), so the start of the entry it was reading
    is given too when PyYAML records it. A reader error (a control character) has a reason and a
    position instead. The problem is cut as :func:`cut` cuts it: it names an alias, a tag or a
    character it could not read, and "found undefined alias" with a name of a million
    characters printed about 1,000,100 bytes in ``run``, ``calibrate`` and ``lint`` (A-51).
    """

    problem = cut(
        str(getattr(exc, "problem", None) or getattr(exc, "reason", None) or "unreadable")
    )
    mark = getattr(exc, "problem_mark", None)
    where = ""
    if mark is not None:
        where = f" at line {mark.line + 1}, column {mark.column + 1}"
        context = getattr(exc, "context_mark", None)
        if context is not None and (context.line, context.column) != (mark.line, mark.column):
            where += f" (entry starting at line {context.line + 1}, column {context.column + 1})"
    elif isinstance(getattr(exc, "position", None), int):
        where = f" at character {exc.position + 1}"  # type: ignore[attr-defined]
    return f"{problem}{where}"
