"""Error text for the operator's own files that never quotes the values in them.

Scope, target and fleet files are where credentials get named, and sometimes pasted by
mistake. pydantic's message echoes the offending input (``input_value='<key>'``, truncated in
the middle, so the tail survived) and PyYAML's quotes a snippet of the line. The CLI's
redactor caught a pasted key only by its entropy, so these two helpers report where and why,
not the values (audits of the 2026-10-03 residuals). Two things still come through, because
they are the location or the reason itself: a mapping KEY the operator typed (it is part of
pydantic's field path) and an alias or tag name PyYAML could not resolve.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError

if TYPE_CHECKING:  # annotation only: `shared` imports pydantic and the stdlib at run time
    import yaml

__all__ = ["MAX_LISTED_PROBLEMS", "MAX_PROBLEM_CHARS", "validation_problems", "yaml_problem"]

#: Errors listed by default; the rest are counted, not listed. The spec loader's figure.
MAX_LISTED_PROBLEMS = 20
#: A field path or a reason longer than this is cut. The spec loader's figure for a message.
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
        f"{_cut('.'.join(str(part) for part in err['loc']) or '<root>')}: {_cut(err['msg'])}"
        for err in shown
    )
    if len(shown) < len(errors):
        text += f"; and {len(errors) - len(shown)} more"
    return text


def _cut(text: str) -> str:
    """``text``, or its first :data:`MAX_PROBLEM_CHARS` characters and its length."""

    if len(text) <= MAX_PROBLEM_CHARS:
        return text
    return f"{text[:MAX_PROBLEM_CHARS]}... ({len(text)} characters)"


def yaml_problem(exc: yaml.YAMLError) -> str:
    """What PyYAML found wrong and where, without the snippet of the line it quotes.

    The position where PyYAML noticed the problem can be the line AFTER the typo (a missing
    space after a colon is reported on the next line), so the start of the entry it was reading
    is given too when PyYAML records it. A reader error (a control character) has a reason and a
    position instead.
    """

    problem = getattr(exc, "problem", None) or getattr(exc, "reason", None) or "unreadable"
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
