"""An attack prompt the provider's own input filter refused before the model saw it (OD-41).

Azure OpenAI's prompt filter answers such a prompt with HTTP 400 and the error code
``content_filter``, and Gemini's API with a body whose ``promptFeedback.blockReason`` is set and
that holds no candidate; the adapters raise ``ProviderFilterBlock`` on either (``adapters.base``,
``adapters.rest``, which cite the provider documentation). The attempt never reached the model,
so it is neither the model's refusal nor an exploit. The runner records it as ``inconclusive``
with the reason ``blocked_by_provider_filter`` (ADR-0011, u08 A-69) and the campaign goes on:
before OD-41 the first one stopped it (exit 3 after one request).

Here, in ``shared``, because four peers read it: the runner records and scores it, the replay
and every report count it, and a resume keeps it without sending it again.
"""

from __future__ import annotations

from collections.abc import Iterable

from ildottore.shared.enums import InconclusiveReason
from ildottore.shared.models import Attempt

__all__ = [
    "PROVIDER_FILTER_MARK",
    "blocked_attempt_ids",
    "blocked_by_provider_filter",
]

#: Appended to a blocked attempt's ``error``: the stored attempt says so without its verdict, so
#: a resume keeps it (a retry gets the same refusal) and a replay counts it.
PROVIDER_FILTER_MARK = " [blocked_by_provider_filter]"


def blocked_by_provider_filter(attempt: Attempt) -> bool:
    """True when the provider's input filter refused this attempt's prompt (no reply came back).

    Read from the verdict's reason, or from the error's mark when the attempt carries no verdict.
    """

    verdict = attempt.verdict
    if (
        verdict is not None
        and verdict.inconclusive_reason is InconclusiveReason.BLOCKED_BY_PROVIDER_FILTER
    ):
        return True
    return attempt.response is None and (attempt.error or "").endswith(PROVIDER_FILTER_MARK)


def blocked_attempt_ids(attempts: Iterable[Attempt]) -> set[str]:
    """The ids of the attempts the provider's input filter refused (one per id)."""

    return {attempt.attempt_id for attempt in attempts if blocked_by_provider_filter(attempt)}
