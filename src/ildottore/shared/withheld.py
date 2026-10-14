"""An attempt stored with the pieces of its reply withheld (u01 A-77, u08's half).

The evidence store refuses a write whose redacted payload is not a fixed point of the redactor,
and the runner then stores the attempt again with every piece of its reply's streams empty (its
logprob tokens and their alternatives, a transcript's content), its text, figures and verdict
kept, and ``request.metadata`` saying what was withheld and why. Here, in ``shared``, because the
runner writes the mark and every report and the terminal count it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from ildottore.shared.models import Attempt

__all__ = ["EVIDENCE_WITHHELD", "withheld_attempt_ids"]

#: The ``request.metadata`` key under which such an attempt says what was withheld and why.
EVIDENCE_WITHHELD: Final = "evidence_withheld"


def withheld_attempt_ids(attempts: Iterable[Attempt]) -> set[str]:
    """The ids of the attempts stored with the pieces of their reply withheld (one per id)."""

    return {
        attempt.attempt_id
        for attempt in attempts
        if EVIDENCE_WITHHELD in (attempt.request.metadata or {})
    }
