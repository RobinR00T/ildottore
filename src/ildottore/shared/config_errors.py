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

__all__ = ["validation_problems", "yaml_problem"]


def validation_problems(exc: ValidationError, *, limit: int | None = None) -> str:
    """``field.path: reason`` for every error, without the input value or a docs URL.

    With ``limit``, only the first ``limit`` errors are listed and the rest counted.
    """

    errors = exc.errors(include_input=False, include_url=False)
    shown = errors if limit is None else errors[:limit]
    text = "; ".join(
        f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}" for err in shown
    )
    if len(shown) < len(errors):
        text += f"; and {len(errors) - len(shown)} more"
    return text


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
