"""A failing spec's control: what its verdict says about the fail (u08 A-106, ADR-0018).

``run --control`` sends a failing spec's ``attack.control`` once: the same ask without the
attack. Its verdict, read by the spec's own evaluators, says whether the fail follows from the
attack. The control is never a trial of the spec: it is stored under the mutation
:data:`~ildottore.shared.enums.CONTROL` and kept in ``Finding.control``, apart from the attempts
every reproducibility and confirmation reads.
"""

from __future__ import annotations

from collections.abc import Iterable

from ildottore.shared.combination import never_confirms
from ildottore.shared.enums import CONTROL, ControlOutcome, VerdictStatus
from ildottore.shared.models import Attempt, ControlCheck, Verdict
from ildottore.shared.resend import one_per_attempt_id

__all__ = ["control_check", "control_outcome", "split_control"]


def control_outcome(verdict: Verdict | None) -> ControlOutcome:
    """The outcome a control's verdict gives: a fail is not attributed, a pass is.

    A control the evaluators could not decide (no verdict, or ``inconclusive``) moves nothing,
    and neither does a fail that never confirms on its own (the judge alone reported it): such
    a fail demoted a confirmed finding on the judge's word, which is never enough to confirm one
    (OD-62).
    """

    if verdict is None or verdict.status is VerdictStatus.INCONCLUSIVE or never_confirms(verdict):
        return ControlOutcome.INCONCLUSIVE
    if verdict.status is VerdictStatus.FAIL:
        return ControlOutcome.NOT_ATTRIBUTED
    return ControlOutcome.ATTRIBUTED


def control_check(attempt: Attempt) -> ControlCheck:
    """The :class:`ControlCheck` a sent control's attempt stands for."""

    outcome = control_outcome(attempt.verdict)
    reason = None
    if outcome is ControlOutcome.INCONCLUSIVE:
        verdict = attempt.verdict
        if verdict is not None and never_confirms(verdict):
            reason = "the control's fail rests on the judge alone, which never decides on its own"
        else:
            why = verdict.reasoning if verdict is not None else None
            reason = why or attempt.error or "the control's reply was not judged"
    return ControlCheck(outcome=outcome, attempt=attempt, reason=reason)


def split_control(attempts: Iterable[Attempt]) -> tuple[list[Attempt], Attempt | None]:
    """A spec's stored attempts apart from its control, and the control's attempt if any.

    A control sent again (its first send ended in an environment error) leaves two artifacts
    under one id: the one that is its attempt is kept, as for any other id.
    """

    trials: list[Attempt] = []
    controls: list[Attempt] = []
    for attempt in attempts:
        (controls if attempt.mutation == CONTROL else trials).append(attempt)
    kept = one_per_attempt_id(controls)
    return trials, (kept[-1] if kept else None)
