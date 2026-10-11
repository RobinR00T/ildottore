"""A reply the adapter could not read, as an attempt records it (OD-21, u08 A-74).

A success reply that is not JSON, not a JSON object or not the provider's or the template's shape
is a ``ResponseMalformed`` (u04): the attempt has no reply to evaluate, and it is ``inconclusive:
unreadable_reply``. Such an attempt keeps its spec from passing, because the reply that broke may
be the one an attack changed (a wrapper whose JSON a quote in the model's output broke: pre-merge
audit of ``598f0858``, HIGH 1), and every report counts it apart.

Here, in ``shared``, because several peers read it: the runner records and scores it, the replay
and every report count it, the CLI's unreachable reason and its resume note name it. An attempt
is recognised by its verdict's reason, or, stored without a verdict, by the mark on its error;
never by the error's class name, which another adapter could spell differently.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from ildottore.shared.enums import InconclusiveReason
from ildottore.shared.models import Attempt

__all__ = [
    "UNREADABLE_MARK",
    "UNREADABLE_REPLY_KEY",
    "unreadable_attempt_ids",
    "unreadable_reply",
]

#: Appended to an unreadable attempt's ``error`` in place of the not-retryable mark: within a run
#: it is not sent again, and a resume sends it again (the target may have been fixed since).
UNREADABLE_MARK: Final = " [unreadable_reply]"

#: The ``request.metadata`` key under which the attempt keeps what came back for review: a bounded
#: excerpt of the body through the adapter's redactor, the body's size in bytes, and what the
#: adapter advises to check (``{"excerpt": str, "bytes": int, "advice": str}``).
UNREADABLE_REPLY_KEY: Final = "unreadable_reply"


def unreadable_reply(attempt: Attempt) -> bool:
    """True when this attempt's reply could not be read as the provider's.

    Read from the verdict's reason; the error's mark is read only when the attempt carries no
    verdict, since an error's tail can quote what a target sent and a verdict is the runner's own
    word (the rule ``shared.provider_filter.blocked_by_provider_filter`` follows).
    """

    verdict = attempt.verdict
    if verdict is not None:
        return verdict.inconclusive_reason is InconclusiveReason.UNREADABLE_REPLY
    return attempt.response is None and (attempt.error or "").endswith(UNREADABLE_MARK)


def unreadable_attempt_ids(attempts: Iterable[Attempt]) -> set[str]:
    """The ids of the attempts whose reply could not be read (one per id)."""

    return {attempt.attempt_id for attempt in attempts if unreadable_reply(attempt)}
