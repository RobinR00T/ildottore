"""An identity sweep's crossing counts once in the reproducibility (u08 A-85, item 2).

The identity sweep sends a spec's attack once as each scope identity, before its attempts, and
``authz_leak`` reads those replies: one reply per identity, whatever the spec's ``--runs``. Every
attempt evaluated beside that sweep carries the same ``authz_leak`` verdict, so a crossing seen
in one reply of tenant A failed all of them, and the reproducibility, the successful-attack rate
``k / N`` over the attempts, read ``5 / 5`` (``1.0``, Critical) for one observation (pre-merge
audit of the scoring branch, #112, queued as pre-existing; measured through the CLI on
``7d01521f``: one sweep send per identity, ``reproducibility 1.0``, exit 2).

The runner numbers each sweep of a spec in the run and stamps the number on ``authz_leak``'s fail
(``Verdict.identity_sweep``); the aggregate keeps it only when no other evaluator would fail the
attempt (``shared.combination``). Here, every attempt so marked counts as one success per sweep,
however many attempts carry it, and every other fail counts as before. The scorer
(``scoring.risk``) and the replay (``store.replay``) both count through :func:`count_successes`,
so a report and ``dottore replay`` cannot disagree. The verdicts themselves are kept: the
crossing is a confirmed leak (``docs/11 §4``), so the finding fails and stays confirmed, and only
how often it was shown changes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from ildottore.shared.models import Attempt

__all__ = ["count_successes", "sweep_of"]


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
