"""N-run reproducibility: execute one (spec, variant) N times + aggregate (u08, §5.5).

Reproducibility is the product thesis (``docs/01 §5``, contract §2): a single lucky
success is a *low-reproducibility* finding, not a headline. :func:`reproduce` sends
one prepared request ``n`` times through :func:`~ildottore.core.execute.execute_attempt`
(pinned sampling, retry/timeout, per-send budget debit), pinning each send's
``mock_attempt`` index so a deterministic target (u03) walks a declared response
sequence in order. It returns the raw per-attempt list so a reader can recompute
``repro`` - nothing is summarized away.

:func:`repro_from_verdicts` computes ``repro = successful_attacks / N`` where a
"successful attack" is a ``fail`` verdict (polarity is fixed repo-wide: ``fail`` =
the target was exploited - ``docs/04 §0``). ``inconclusive`` attempts are counted in
the denominator ``N`` (they were run) but never as successes - an env-skipped attempt
is not evidence of resistance *or* exploitation.

Deterministic: same target + same seed + same N ⇒ identical attempts and identical
``repro`` (contract §7 determinism replay).
"""

from __future__ import annotations

import sys
from collections.abc import Awaitable, Callable, Iterable, Sequence

from ildottore.core.budgets import BudgetLedger
from ildottore.core.execute import (
    AttemptResult,
    BudgetExhaustedAfterReply,
    RetryPolicy,
    default_is_env_error,
    execute_attempt,
)
from ildottore.core.pacing import RateLimiter
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import ModelRequest, Sampling, Verdict
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "DEFAULT_N",
    "attempt_id_for",
    "planned_attempts_held",
    "repro_from_verdicts",
    "reproduce",
]

#: Default reproducibility runs (``docs/01 §5``, contract §9 - human-confirmable).
DEFAULT_N = 5

#: Request metadata key the deterministic mock (u03) reads to pin its sequence index.
_MOCK_ATTEMPT_KEY = "mock_attempt"


def attempt_id_for(spec_id: str, mutation: str, run_index: int) -> str:
    """A stable, human-readable attempt id (``<spec>::<mutation>#<n>``).

    Deterministic per ``(spec, mutation, run_index)`` so replays reference the same
    ids and the evidence store dedupes correctly (contract §7).
    """

    return f"{spec_id}::{mutation}#{run_index}"


def planned_attempts_held(
    stored: Iterable[str], spec_id: str, mutators: Sequence[str], runs: int
) -> int:
    """How many of a spec's planned attempts (each mutation, ``runs`` times) are in ``stored``.

    The same number as building every :func:`attempt_id_for` of the plan and intersecting, but
    counted by reading ``stored`` once, so the work follows what is stored, not ``runs``: a
    resume built that set for each started spec, and with the ``2**53`` a run store accepts it
    grew without end (A-59, OD-32). An id counts only in the exact form ``attempt_id_for``
    writes (an index without a leading zero, inside the plan), so no stored id passes for one,
    and an index wider than the plan's last one is passed over without being converted (past the
    interpreter's digit limit, that limit is the widest: ``attempt_id_for`` writes no longer one).
    """

    if runs <= 0:
        return 0
    # The widest index of the plan: a longer one is not planned, and is passed over before
    # ``int()``, which cost 4 s per check over 10,000 stored indexes of 4,300 digits (delta audit
    # of A-59). A run count the interpreter cannot write out has no such width to read.
    try:
        widest = len(str(runs - 1))
    except ValueError:
        widest = sys.get_int_max_str_digits()
    prefix = f"{spec_id}::"
    planned = set(mutators)
    held = 0
    for attempt_id in set(stored):
        if not attempt_id.startswith(prefix):
            continue
        mutation, sep, index = attempt_id[len(prefix) :].rpartition("#")
        if (
            sep
            and mutation in planned
            and index.isascii()
            and index.isdigit()
            and len(index) <= widest
            and index == str(int(index))
            and int(index) < runs
        ):
            held += 1
    return held


def _pin_attempt_index(request: ModelRequest, run_index: int) -> ModelRequest:
    """Return a copy of ``request`` with ``mock_attempt`` pinned to ``run_index``.

    Pinning makes the deterministic target a pure function of ``(scenario, index)``
    so N runs walk a declared response sequence in order and replays are byte-stable.
    A real over-the-wire adapter simply ignores the metadata key.
    """

    metadata = dict(request.metadata or {})
    metadata[_MOCK_ATTEMPT_KEY] = run_index
    return request.model_copy(update={"metadata": metadata})


async def reproduce(
    adapter: TargetAdapter,
    request: ModelRequest,
    *,
    spec_id: str,
    mutation: str,
    sampling: Sampling | None,
    ledger: BudgetLedger,
    n: int = DEFAULT_N,
    retry: RetryPolicy | None = None,
    timeout_s: float | None = None,
    is_env_error: Callable[[BaseException], bool] = default_is_env_error,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    now: Callable[[], float] | None = None,
    completed: set[str] | None = None,
    pacer: RateLimiter | None = None,
    into: list[AttemptResult] | None = None,
) -> list[AttemptResult]:
    """Execute ``request`` ``n`` times, returning the raw per-run results in order.

    Each run debits one *attempt* against the budget (adaptive/escalation attempts
    would count too) plus one *request* per send inside :func:`execute_attempt`. A
    :class:`~ildottore.core.budgets.BudgetExhausted` from either debit propagates so
    the runner records ``budget_exhausted`` with whatever ran so far.

    ``into`` (optional) is the caller's list, and each result is appended to it as it
    completes: a halt propagates as an exception, and the attempts the batch already had
    answered went with it, unstored, so the resume sent them again and paid for them twice.
    A reply whose own usage crossed the token ceiling is appended before the halt goes on.

    ``completed`` (optional) is a resume set: the attempt ids a prior run already answered
    (or that failed in a way a retry would repeat); a run whose id is in the set is
    **skipped** (not re-sent) so resume never duplicates a completed attempt (contract §7
    resume). An attempt that ended in another environment error is not in it and is sent
    again under its id (F11). Skipped runs are simply absent from the
    returned list - the caller merges them with the persisted attempts.
    """

    if n < 1:
        raise ValueError("n must be >= 1")
    results: list[AttemptResult] = into if into is not None else []
    for run_index in range(n):
        attempt_id = attempt_id_for(spec_id, mutation, run_index)
        if completed is not None and attempt_id in completed:
            continue
        ledger.debit_attempt()
        pinned = _pin_attempt_index(request, run_index)
        try:
            result = await execute_attempt(
                adapter,
                pinned,
                attempt_id=attempt_id,
                spec_id=spec_id,
                mutation=mutation,
                sampling=sampling,
                ledger=ledger,
                retry=retry,
                timeout_s=timeout_s,
                is_env_error=is_env_error,
                sleep=sleep,
                now=now,
                pacer=pacer,
            )
        except BudgetExhaustedAfterReply as halt:
            results.append(halt.result)
            raise
        results.append(result)
    return results


def repro_from_verdicts(verdicts: list[Verdict], n: int) -> float:
    """``repro = successful_attacks / N`` (`docs/01 §5`).

    A success is a ``fail`` verdict (target exploited). ``inconclusive`` counts in
    the denominator (the attempt was run) but never as a success. ``n`` is the
    intended run count, not ``len(verdicts)`` - an attempt that could not be
    evaluated still lowers reproducibility rather than being silently excluded.
    """

    if n < 1:
        raise ValueError("n must be >= 1")
    successes = sum(1 for v in verdicts if v.status is VerdictStatus.FAIL)
    return successes / n
