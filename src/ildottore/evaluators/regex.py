"""Regex evaluators: ``regex_absence`` and ``regex_presence`` (``docs/04 §1``).

Both are **deterministic** pre-filters (confidence ``1.0``): they never call a model.
Polarity is fixed (``docs/04 §0``):

* :class:`RegexAbsenceEvaluator` — ``fail`` if any forbidden pattern appears (e.g. a leaked
  system-prompt marker); ``pass`` when the output is clean.
* :class:`RegexPresenceEvaluator` — ``fail`` if a required "secure" marker is *absent*;
  ``pass`` when it is present.

Patterns come from the spec's :class:`~ildottore.shared.models.EvaluatorConfig.patterns`.
An empty / missing pattern list is **ambiguous** — the evaluator cannot decide — so it
returns ``inconclusive`` (confidence ``0.0``) rather than a fabricated pass (contract §4 KEEP).
A malformed regex is likewise ``inconclusive`` (a spec-authoring defect, surfaced not masked).
"""

from __future__ import annotations

import re

from ildottore.evaluators.base import BaseEvaluator
from ildottore.shared.enums import EvaluatorType
from ildottore.shared.models import EvalContext, Verdict

__all__ = ["RegexAbsenceEvaluator", "RegexPresenceEvaluator"]


def _compile(patterns: list[str]) -> tuple[list[re.Pattern[str]], str | None]:
    """Compile ``patterns``; return ``(compiled, error)`` — error non-None on bad regex."""
    compiled: list[re.Pattern[str]] = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat))
        except re.error as exc:
            return [], f"invalid regex {pat!r}: {exc}"
    return compiled, None


class RegexAbsenceEvaluator(BaseEvaluator):
    """``fail`` if a forbidden pattern appears in the response text."""

    type = EvaluatorType.REGEX_ABSENCE.value

    async def evaluate(self, ctx: EvalContext) -> Verdict:
        patterns = ctx.config.patterns or []
        if not patterns:
            return self._inconclusive("regex_absence requires at least one pattern")
        compiled, error = _compile(patterns)
        if error is not None:
            return self._inconclusive(error)
        text = ctx.response.text
        hits = [pat.pattern for pat in compiled if pat.search(text)]
        if hits:
            return self._fail(
                f"forbidden pattern(s) present: {', '.join(hits)}",
                matched=hits,
            )
        return self._pass("no forbidden pattern present")


class RegexPresenceEvaluator(BaseEvaluator):
    """``fail`` if a required secure marker is **absent** from the response text."""

    type = EvaluatorType.REGEX_PRESENCE.value

    async def evaluate(self, ctx: EvalContext) -> Verdict:
        patterns = ctx.config.patterns or []
        if not patterns:
            return self._inconclusive("regex_presence requires at least one pattern")
        compiled, error = _compile(patterns)
        if error is not None:
            return self._inconclusive(error)
        text = ctx.response.text
        missing = [pat.pattern for pat in compiled if not pat.search(text)]
        if missing:
            return self._fail(
                f"required secure marker(s) absent: {', '.join(missing)}",
                matched=missing,
            )
        return self._pass("all required secure markers present")
