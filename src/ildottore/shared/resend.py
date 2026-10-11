"""Which of an attempt id's artifacts is the attempt, when a resume sent it again (F11, u08 A-74).

A resume sends an attempt that ended in an environment error, whose reply could not be read, or
whose reply was stored without a verdict, again under the same id, so the evidence can hold the
failed try and its re-send. Both are history and stay cited; only one is the attempt that is
scored. The runner and the replay read it from here, so a report and ``dottore replay`` never
pick different copies: each had its own copy of the rule, and both kept whichever artifact came
first at a tie, the runner in the order the prior attempts were loaded, which is their file
names, their content hashes. So an unreadable re-send of an environment error could be dropped
and its spec published as a pass while the replay counted it (audit of the scoring, 2026-10-11,
HIGH 1).

The rule, in order:

1. an artifact answered and judged, then one with a verdict (an environment error's, a block's or
   an unreadable reply's inconclusive), then a bare reply: a verdict outranks a reply stored
   without one, whose re-send is the attempt whether it was judged or ended in an error;
2. at the same rank, one whose reason never lets its spec pass (:data:`NEVER_A_PASS`: a reply the
   adapter could not read, one the provider's filter cut or stopped on a side it did not report)
   over one whose reason does not, whichever was sent first. At that rank the other is an
   environment error or a block, which says nothing about the model's reply, and the reply that
   could not be read may be the one an attack changed: a resume that met a network failure must
   not turn it into a pass. A re-send the adapter reads outranks it under rule 1;
3. then the later send: the runner stamps :data:`SEND_NUMBER_KEY` on the request of every artifact
   it stores, ``1`` for an id's first send in the run and one more for each re-send, so the
   re-send is the attempt in the place of the try it replaces. An artifact stored before the
   stamp existed counts as sent before every stamped one;
4. otherwise the first, as before.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from ildottore.shared.amounts import is_count
from ildottore.shared.enums import InconclusiveReason
from ildottore.shared.models import Attempt, JsonDict
from ildottore.shared.provider_filter import CUT_REASONS, cut_by_output_filter, filter_side_unknown
from ildottore.shared.unreadable import unreadable_reply

__all__ = [
    "NEVER_A_PASS",
    "SEND_NUMBER_KEY",
    "never_a_pass",
    "one_per_attempt_id",
    "send_number",
    "with_send_number",
]

#: The ``request.metadata`` key under which every stored attempt says which send of its id it is:
#: ``1`` for the first in the run, ``n`` for the ``n``-th (a resume's re-send).
SEND_NUMBER_KEY: Final = "send_number"

#: The reasons an attempt keeps its spec from passing, however many others held (OD-42, OD-21).
NEVER_A_PASS: Final = CUT_REASONS | {InconclusiveReason.UNREADABLE_REPLY}


def send_number(attempt: Attempt) -> int | None:
    """Which send of its id this artifact is, or ``None`` when it was stored without the stamp."""

    value = (attempt.request.metadata or {}).get(SEND_NUMBER_KEY)
    return value if is_count(value) and value >= 1 else None


def with_send_number(attempt: Attempt, number: int) -> Attempt:
    """``attempt`` with :data:`SEND_NUMBER_KEY` set to ``number`` on its request."""

    metadata: JsonDict = {**(attempt.request.metadata or {}), SEND_NUMBER_KEY: number}
    return attempt.model_copy(
        update={"request": attempt.request.model_copy(update={"metadata": metadata})}
    )


def never_a_pass(attempt: Attempt) -> bool:
    """True when this attempt keeps its spec from passing: unreadable, cut, or side unknown.

    Read as every count reads it: from the verdict's reason, or, on an attempt stored without a
    verdict, from the error's mark or the reply's stop reason.
    """

    return (
        unreadable_reply(attempt) or cut_by_output_filter(attempt) or filter_side_unknown(attempt)
    )


def _rank(attempt: Attempt) -> tuple[bool, bool, bool, bool, int]:
    answered = attempt.response is not None
    judged = attempt.verdict is not None
    return (
        answered and judged,
        judged,
        answered,
        never_a_pass(attempt),
        send_number(attempt) or 0,
    )


def one_per_attempt_id(attempts: Iterable[Attempt]) -> list[Attempt]:
    """One artifact per attempt id, the one that is the attempt (the module's rule).

    The ids keep the order in which each first appears.
    """

    kept: dict[str, Attempt] = {}
    for attempt in attempts:
        current = kept.get(attempt.attempt_id)
        if current is None or _rank(attempt) > _rank(current):
            kept[attempt.attempt_id] = attempt
    return list(kept.values())
