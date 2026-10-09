"""Compiling the regular expressions a spec writes, one way for lint, a run and the evaluators.

A spec writes a regex in three places: the ``regex_absence`` and ``regex_presence`` patterns,
and ``tool_sequence``'s ``step_arg_patterns``. Lint, its offline fixture stubs, the pre-flight of
``dottore run`` and the evaluators all compile it through :func:`compile_spec_pattern`, with the
same flags and the same refusals (A-33). Two answers still depend on the caller: how deep groups
may nest (see :func:`compile_spec_pattern`), and whether a warning the engine gives is an error
(``-W error``).
"""

from __future__ import annotations

import re

__all__ = ["MAX_QUOTED_CHARS", "SpecPatternError", "compile_spec_pattern", "quote"]

#: What ``re.compile`` raises on a pattern it cannot compile. Not only ``re.error``: a repetition
#: past the engine's limit raises ``OverflowError`` (``a{4294967296}``), groups nested a few
#: hundred deep ``RecursionError``, two incompatible inline flags ``ValueError``
#: (``(?a)(?u)x``), and, when warnings are errors (``-W error``), a construct whose meaning may
#: change raises its ``FutureWarning`` (``[[a]``, a nested set). The evaluators caught only
#: ``re.error``, so the others aborted a whole ``dottore run``, and ``dottore lint`` crashed on
#: every one of them (2026-10-07).
_REFUSALS = (re.error, OverflowError, RecursionError, ValueError, Warning)

#: A quoted pattern, step name or reason keeps at most this many of its own characters.
MAX_QUOTED_CHARS = 120


class SpecPatternError(Exception):
    """A regex a spec writes that the engine cannot compile; the message says why."""

    def __init__(self, reason: str, pattern: str) -> None:
        super().__init__(reason)
        #: The pattern refused, so a caller that did not compile it can name it.
        self.pattern = pattern


def compile_spec_pattern(pattern: str) -> re.Pattern[str]:
    """``pattern`` compiled as every evaluator reads it: case-insensitive.

    Raises :class:`SpecPatternError` whatever the engine raised. The engine parses groups
    recursively, so how deep they may nest depends on how deep the caller's stack already is. On
    Python 3.14 (2026-10-07, ``python -m``; one or two more through ``dottore``): lint accepts 486
    nested groups and a run's pre-flight 487; an evaluator, a few frames deeper, decides on what
    the pre-flight compiled while ``re``'s cache (512 patterns) holds it, and accepts 481 when it
    compiles the pattern itself. So in a selection of more than 512 patterns, one nested 482 to
    487 deep lints clean, passes the pre-flight, and makes its evaluator abstain: the spec ends
    ``inconclusive`` with the reason in no report, where ``main`` aborted the run. Nothing real
    nests past a handful; a per-process cache of answers would close it and was not added.
    Compiling on a thread of its own made the answer one number, and was taken out again: the
    thread held up Ctrl-C and SIGTERM behind a slow compile, hung after ``fork``, queued every
    compile behind the slowest and lost the caller's warning filters (delta audit of A-33).
    """

    try:
        return re.compile(pattern, re.IGNORECASE)
    except _REFUSALS as exc:
        nested = isinstance(exc, RecursionError)
        reason = "its groups are nested too deeply to compile" if nested else str(exc)
        raise SpecPatternError(reason, pattern) from exc


def quote(text: str) -> str:
    """``text`` as ``ascii`` writes it, cut past :data:`MAX_QUOTED_CHARS` of its characters.

    ``ascii`` writes out every character a terminal acts on (a control, a format character, a
    line separator, a lone surrogate) and every other non-ASCII one, so a spec cannot rewrite
    the line that quotes it and the line encodes on any stream. A written-out character takes up
    to ten, so a quote is at most about 1,200 characters.
    """

    if len(text) <= MAX_QUOTED_CHARS:
        return ascii(text)
    return f"{text[:MAX_QUOTED_CHARS]!a}... ({len(text)} characters)"
