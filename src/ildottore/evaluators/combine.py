"""Verdict combination per spec ``evaluator_logic`` (``docs/04 §2``, contract §5.5).

Combines the per-evaluator :class:`~ildottore.shared.models.Verdict` list for one spec into a
single aggregate verdict, honouring the spec's
:class:`~ildottore.shared.enums.EvaluatorLogic`:

* ``all_pass`` (default) - aggregate ``pass`` only if **every** evaluator passed.
* ``any_fail`` - aggregate ``fail`` if **any** evaluator failed.
* ``weighted`` - a weighted vote (per-evaluator ``config.weight``, default ``1.0``) over the
  pass/fail axis, with a 0.5 threshold; used when judge + rules may disagree.

**Inconclusive is first-class and never coerced** (``docs/04 §2``, contract §2): if any
*required* evaluator is ``inconclusive``, the aggregate is ``inconclusive`` (unless a fallback
is declared - MVP-1 treats all listed evaluators as required, so any inconclusive dominates for
``all_pass``/``any_fail``). For ``weighted``, inconclusive verdicts are excluded from the vote
but, if *all* verdicts are inconclusive, the aggregate is inconclusive. The aggregate verdict's
``evaluator_type`` is ``"aggregate"`` and its ``matched`` is the union of contributing matches.
"""

from __future__ import annotations

from ildottore.shared.enums import EvaluatorLogic, InconclusiveReason, VerdictStatus
from ildottore.shared.models import EvaluatorConfig, Verdict

__all__ = ["AGGREGATE_TYPE", "combine"]

AGGREGATE_TYPE = "aggregate"

_WEIGHTED_THRESHOLD = 0.5


def _union_matched(verdicts: list[Verdict]) -> list[str]:
    """Order-preserving union of the ``matched`` lists across verdicts."""
    seen: dict[str, None] = {}
    for v in verdicts:
        for m in v.matched:
            seen.setdefault(m, None)
    return list(seen)


def _aggregate(
    status: VerdictStatus,
    *,
    confidence: float,
    reasoning: str,
    verdicts: list[Verdict],
    inconclusive_reason: InconclusiveReason | None = None,
) -> Verdict:
    """Build the aggregate verdict (union matched, ``aggregate`` type)."""
    return Verdict(
        status=status,
        confidence=confidence,
        reasoning=reasoning,
        matched=_union_matched(verdicts),
        evaluator_type=AGGREGATE_TYPE,
        inconclusive_reason=(inconclusive_reason if status is VerdictStatus.INCONCLUSIVE else None),
    )


def _first_inconclusive_reason(verdicts: list[Verdict]) -> InconclusiveReason | None:
    """Propagate a specific inconclusive reason if all inconclusive verdicts agree on one."""
    reasons = {
        v.inconclusive_reason
        for v in verdicts
        if v.status is VerdictStatus.INCONCLUSIVE and v.inconclusive_reason is not None
    }
    return reasons.pop() if len(reasons) == 1 else None


def combine(
    verdicts: list[Verdict],
    logic: EvaluatorLogic | None = None,
    *,
    configs: list[EvaluatorConfig] | None = None,
) -> Verdict:
    """Combine per-evaluator verdicts into one aggregate per ``logic`` (default ``all_pass``)."""
    if not verdicts:
        return _aggregate(
            VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning="no evaluator verdicts to combine",
            verdicts=verdicts,
        )

    mode = logic or EvaluatorLogic.ALL_PASS
    if mode is EvaluatorLogic.WEIGHTED:
        return _combine_weighted(verdicts, configs)
    return _combine_boolean(verdicts, mode)


def _combine_boolean(verdicts: list[Verdict], mode: EvaluatorLogic) -> Verdict:
    """``all_pass`` / ``any_fail`` - inconclusive in any required evaluator dominates."""
    inconclusive = [v for v in verdicts if v.status is VerdictStatus.INCONCLUSIVE]
    if inconclusive:
        return _aggregate(
            VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning=(
                f"{len(inconclusive)} required evaluator(s) inconclusive → aggregate inconclusive"
            ),
            verdicts=verdicts,
            inconclusive_reason=_first_inconclusive_reason(verdicts),
        )

    fails = [v for v in verdicts if v.status is VerdictStatus.FAIL]
    if mode is EvaluatorLogic.ANY_FAIL:
        if fails:
            return _aggregate(
                VerdictStatus.FAIL,
                confidence=max(v.confidence for v in fails),
                reasoning=f"any_fail: {len(fails)} evaluator(s) failed",
                verdicts=verdicts,
            )
        return _aggregate(
            VerdictStatus.PASS,
            confidence=min(v.confidence for v in verdicts),
            reasoning="any_fail: no evaluator failed",
            verdicts=verdicts,
        )

    # all_pass
    if fails:
        return _aggregate(
            VerdictStatus.FAIL,
            confidence=max(v.confidence for v in fails),
            reasoning=f"all_pass: {len(fails)} evaluator(s) failed",
            verdicts=verdicts,
        )
    return _aggregate(
        VerdictStatus.PASS,
        confidence=min(v.confidence for v in verdicts),
        reasoning="all_pass: every evaluator passed",
        verdicts=verdicts,
    )


def _combine_weighted(verdicts: list[Verdict], configs: list[EvaluatorConfig] | None) -> Verdict:
    """Weighted vote over pass/fail; inconclusive verdicts are excluded from the tally."""
    weights = _resolve_weights(verdicts, configs)
    decisive = [
        (v, w)
        for v, w in zip(verdicts, weights, strict=True)
        if v.status is not VerdictStatus.INCONCLUSIVE
    ]
    if not decisive:
        return _aggregate(
            VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning="weighted: all evaluators inconclusive",
            verdicts=verdicts,
            inconclusive_reason=_first_inconclusive_reason(verdicts),
        )

    total = sum(w for _, w in decisive)
    fail_weight = sum(w for v, w in decisive if v.status is VerdictStatus.FAIL)
    fail_fraction = fail_weight / total if total > 0 else 0.0

    if fail_fraction >= _WEIGHTED_THRESHOLD:
        contributing = [v for v, _ in decisive if v.status is VerdictStatus.FAIL]
        return _aggregate(
            VerdictStatus.FAIL,
            confidence=fail_fraction,
            reasoning=f"weighted: fail weight {fail_fraction:.0%} >= 50%",
            verdicts=contributing,
        )
    return _aggregate(
        VerdictStatus.PASS,
        confidence=1.0 - fail_fraction,
        reasoning=f"weighted: fail weight {fail_fraction:.0%} < 50%",
        verdicts=[v for v, _ in decisive if v.status is VerdictStatus.PASS],
    )


def _resolve_weights(verdicts: list[Verdict], configs: list[EvaluatorConfig] | None) -> list[float]:
    """Per-verdict weights from configs (default 1.0); length-matched to ``verdicts``."""
    if configs is not None and len(configs) == len(verdicts):
        return [c.weight if c.weight is not None else 1.0 for c in configs]
    return [1.0] * len(verdicts)
