"""Verdict combination per spec ``evaluator_logic`` (``docs/04 §2``, contract §5.5).

Combines the per-evaluator :class:`~ildottore.shared.models.Verdict` list for one attempt into a
single aggregate verdict by the one rule every value of
:class:`~ildottore.shared.enums.EvaluatorLogic` names, ``deterministic_first``
(:func:`ildottore.shared.combination.combine_verdicts`; OD-19, decided 2026-10-11 under the
owner's delegation, ADR-0010, u06 A-73): a deterministic fail decides, else an inconclusive,
else a fail of ``semantic_judge`` alone, else pass; a judge that was consulted and abstained
without a reason is dropped. The runner and the lint fixture engine call the same function, so
the three cannot disagree.

Before, this module held a boolean combination (``all_pass``/``any_fail``, an ``inconclusive``
dominating even a deterministic fail) and a weighted vote (``weighted``, per-evaluator
``config.weight``), and nothing called either: the runner applied its own rule, and on a canary
leak beside an unconfigured judge the two disagreed. The vote let two passing judges outvote a
leak, the reason it is gone rather than wired (ADR-0010, option A). ``configs``, which carried
the weights, went with it.
"""

from __future__ import annotations

from ildottore.shared.combination import AGGREGATE_TYPE, combine_verdicts
from ildottore.shared.enums import EvaluatorLogic
from ildottore.shared.models import Verdict

__all__ = ["AGGREGATE_TYPE", "combine"]


def combine(verdicts: list[Verdict], logic: EvaluatorLogic | None = None) -> Verdict:
    """Combine one attempt's per-evaluator verdicts; ``logic`` is any value, all run one rule."""

    del logic  # every value of the field names the same rule (OD-19)
    return combine_verdicts(verdicts)
