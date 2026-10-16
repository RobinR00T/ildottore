"""An identity sweep's crossing counts once in the reproducibility (u08 A-85, item 2).

The identity sweep sends a spec's attack once as each scope identity, before its attempts, and
``authz_leak`` reads those replies: one reply per identity, whatever the spec's ``--runs``. Every
attempt evaluated beside that sweep carries the same ``authz_leak`` verdict, so a crossing seen
in one reply of tenant A failed all of them, and the reproducibility, the successful-attack rate
``k / N`` over the attempts, read ``5 / 5`` (``1.0``, Critical) for one observation (pre-merge
audit of the scoring branch, #112, queued as pre-existing; measured through the CLI on
``7d01521f``: one sweep send per identity, ``reproducibility 1.0``, exit 2).

The runner numbers each sweep of a spec in the run (:func:`next_sweep`) and stamps the number on
``authz_leak``'s fail (:func:`stamped`, ``Verdict.identity_sweep``); the aggregate keeps it only
when no other evaluator would fail the attempt (``shared.combination``) and says so
(:func:`sweep_note`). Here, every attempt so marked counts as one success per sweep,
however many attempts carry it, and every other fail counts as before. The scorer
(``scoring.risk``) and the replay (``store.replay``) both count through :func:`count_successes`,
so a report and ``dottore replay`` cannot disagree. The verdicts themselves are kept: the
crossing is a confirmed leak (``docs/11 §4``), so the finding fails and stays confirmed, and only
how often it was shown changes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from ildottore.shared.enums import EvaluatorType, VerdictStatus
from ildottore.shared.models import Attempt, Verdict

__all__ = ["count_successes", "next_sweep", "review_note", "stamped", "sweep_note", "sweep_of"]


def sweep_of(attempt: Attempt) -> int | None:
    """The identity sweep whose crossing alone made ``attempt`` a fail, or ``None``."""

    return attempt.verdict.identity_sweep if attempt.verdict is not None else None


def count_successes(attempts: Iterable[Attempt], *, success: Callable[[Attempt], bool]) -> int:
    """How many of ``attempts`` are successful attacks, one sweep's crossing counted once.

    ``success`` is the reader's own test of an attempt (the scorer's: no error and a ``fail``
    verdict; the replay's: a ``fail`` verdict). Of the attempts it accepts, those whose fail is an
    identity sweep's alone count once per sweep, the rest once each.
    """

    own = 0
    sweeps: set[int] = set()
    for attempt in attempts:
        if not success(attempt):
            continue
        sweep = sweep_of(attempt)
        if sweep is None:
            own += 1
        else:
            sweeps.add(sweep)
    return own + len(sweeps)


def stamped(verdict: Verdict, sweep: int | None) -> Verdict:
    """``authz_leak``'s fail, stamped with the number of the identity sweep it read.

    ``authz_leak`` reads the sweep's replies, never the attempt's, so its fail is wholly the
    sweep's. Any other verdict, and any verdict with no sweep behind it, is returned as it is.
    """

    if (
        sweep is None
        or verdict.evaluator_type != EvaluatorType.AUTHZ_LEAK.value
        or verdict.status is not VerdictStatus.FAIL
    ):
        return verdict
    return verdict.model_copy(update={"identity_sweep": sweep})


def next_sweep(attempts: Sequence[Attempt]) -> int:
    """The number of a spec's next identity sweep: one more than any its stored fails carry, so a
    resume's new sweep counts as one more observation, never as one already counted."""

    return 1 + max(
        (a.verdict.identity_sweep or 0 for a in attempts if a.verdict is not None), default=0
    )


def sweep_note(verdict: Verdict) -> Verdict:
    """The aggregate, saying so when one identity sweep's crossing alone made it a fail.

    The reproducibility counts such a fail once per sweep, so without the note a report's
    ``k / N`` would read as a miscount of the attempts it lists as fails.
    """

    if verdict.identity_sweep is None:
        return verdict
    note = (
        f"the crossing of identity sweep {verdict.identity_sweep} alone made this a fail; the "
        "sweep sent one reply per identity, so the reproducibility counts it once, not once per "
        "attempt"
    )
    return verdict.model_copy(update={"reasoning": f"{verdict.reasoning}; {note}"})


def review_note(combined: Verdict, verdicts: list[Verdict]) -> Verdict:
    """The aggregate, quoting the ``authz_leak`` review behind it.

    Only the aggregate is stored, and "1 deterministic evaluator(s) reported exploited" did not
    say that the fail rests on a canary the request carries (``echo_only``), nor "1 evaluator(s)
    inconclusive" that two identities' replies share a line (both need review): the reviewer is
    told what to look at.
    """

    if combined.status is VerdictStatus.FAIL and combined.echo_only:
        wanted = VerdictStatus.FAIL
    elif combined.status is VerdictStatus.INCONCLUSIVE:
        wanted = VerdictStatus.INCONCLUSIVE
    else:
        return combined
    review = next(
        (
            v
            for v in verdicts
            if v.evaluator_type == EvaluatorType.AUTHZ_LEAK.value
            and v.status is wanted
            and (v.echo_only if wanted is VerdictStatus.FAIL else v.inconclusive_reason is None)
        ),
        None,
    )
    if review is None:
        return combined
    note = f"authz_leak: {review.reasoning}"
    return combined.model_copy(update={"reasoning": f"{combined.reasoning}; {note}"})
