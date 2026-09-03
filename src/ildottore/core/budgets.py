"""Hard campaign budgets - the scanner cannot self-DoS (u08, contract §5.1).

A :class:`BudgetLedger` is the single source of truth for how much a campaign may
spend across four independent axes (``docs/08 §1``, contract §4 KEEP):

* **tokens** - provider token usage summed across attempts;
* **requests** - number of ``TargetAdapter.send`` calls;
* **wall-clock** - elapsed seconds since the ledger opened;
* **attempts** - mutated-attack executions, incl. adaptive/escalation retries.

Every ceiling is a **hard cap**: a debit that would cross it is refused *before*
the spend happens and the runner converts that refusal into a stop-&-escalate halt
with a partial ``TestRun`` marked ``budget_exhausted`` - never a silent truncation
(``AGENTS.md §2``, contract §2/§4). The ledger is a plain counter with a lock so a
bounded-concurrency scheduler can debit from several coroutines without a race;
``None`` on any axis means *unbounded* on that axis.

The clock is **injected** (``time_source``) so tests are deterministic and the wall
axis can be exercised without real sleeps (contract §7).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ildottore.shared.models import PlanBudgets

__all__ = [
    "BudgetExhausted",
    "BudgetLedger",
    "BudgetSnapshot",
]


class BudgetExhausted(RuntimeError):
    """A debit would breach a hard budget ceiling (stop-&-escalate signal).

    Carries the offending ``axis`` and the ceiling so the runner can record a
    precise ``budget_exhausted`` reason without re-deriving it.
    """

    def __init__(self, axis: str, limit: int | float, attempted: int | float) -> None:
        self.axis = axis
        self.limit = limit
        self.attempted = attempted
        super().__init__(
            f"budget exhausted on {axis!r}: attempted {attempted} would exceed limit {limit}"
        )


@dataclass(frozen=True)
class BudgetSnapshot:
    """An immutable read of the ledger's consumption (for evidence/telemetry)."""

    tokens: int
    requests: int
    attempts: int
    wall_s: float
    max_tokens: int | None
    max_requests: int | None
    max_attempts: int | None
    max_wall_s: int | None


class BudgetLedger:
    """Thread-safe, four-axis hard-budget accountant.

    Construct from explicit ceilings or from a plan's :class:`PlanBudgets`
    (:meth:`from_plan_budgets`). A ``None`` ceiling means that axis is unbounded.
    All debits are checked-then-applied under a single lock so concurrent
    coroutines/threads never over-spend past a ceiling (contract §4 KEEP: no
    self-DoS).
    """

    def __init__(
        self,
        *,
        max_tokens: int | None = None,
        max_requests: int | None = None,
        max_attempts: int | None = None,
        max_wall_s: int | None = None,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self._max_tokens = _validate_ceiling("max_tokens", max_tokens)
        self._max_requests = _validate_ceiling("max_requests", max_requests)
        self._max_attempts = _validate_ceiling("max_attempts", max_attempts)
        self._max_wall_s = _validate_ceiling("max_wall_s", max_wall_s)
        self._time = time_source if time_source is not None else time.monotonic
        self._lock = threading.Lock()
        self._tokens = 0
        self._requests = 0
        self._attempts = 0
        self._started = self._time()

    @classmethod
    def from_plan_budgets(
        cls,
        budgets: PlanBudgets,
        *,
        time_source: Callable[[], float] | None = None,
    ) -> BudgetLedger:
        """Build a ledger from a :class:`TestPlan`'s :class:`PlanBudgets`."""

        return cls(
            max_tokens=budgets.max_tokens,
            max_requests=budgets.max_requests,
            max_attempts=budgets.max_attempts,
            max_wall_s=budgets.max_wall_s,
            time_source=time_source,
        )

    # --- wall clock ----------------------------------------------------------

    def elapsed_s(self) -> float:
        """Seconds since the ledger opened (via the injected clock)."""

        return self._time() - self._started

    def check_wall(self) -> None:
        """Raise :class:`BudgetExhausted` if the wall-clock ceiling is crossed.

        Called at the top of each unit of work so a long campaign halts on time
        even between token/request debits.
        """

        if self._max_wall_s is None:
            return
        elapsed = self.elapsed_s()
        if elapsed > self._max_wall_s:
            raise BudgetExhausted("max_wall_s", self._max_wall_s, round(elapsed, 6))

    # --- discrete axes -------------------------------------------------------

    def debit_request(self, tokens: int = 0) -> None:
        """Account one request (and optional tokens) atomically; refuse on breach.

        Checked-then-applied under the lock: if *either* the request axis or the
        token axis would breach, **nothing** is committed and the spend never
        happens (contract §2 - no masked partial mid-attempt).
        """

        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        with self._lock:
            self._check_wall_locked()
            next_requests = self._requests + 1
            next_tokens = self._tokens + tokens
            if self._max_requests is not None and next_requests > self._max_requests:
                raise BudgetExhausted("max_requests", self._max_requests, next_requests)
            if self._max_tokens is not None and next_tokens > self._max_tokens:
                raise BudgetExhausted("max_tokens", self._max_tokens, next_tokens)
            self._requests = next_requests
            self._tokens = next_tokens

    def debit_attempt(self) -> None:
        """Account one mutated-attack attempt (adaptive retries count); refuse on breach."""

        with self._lock:
            self._check_wall_locked()
            next_attempts = self._attempts + 1
            if self._max_attempts is not None and next_attempts > self._max_attempts:
                raise BudgetExhausted("max_attempts", self._max_attempts, next_attempts)
            self._attempts = next_attempts

    def add_tokens(self, tokens: int) -> None:
        """Account tokens observed *after* a response (usage reconciliation); refuse on breach.

        Providers report actual token usage only in the response, which can exceed
        the caller's pre-debit estimate. Reconciling here keeps the token ceiling
        honest without letting a single response silently blow the budget.
        """

        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        with self._lock:
            next_tokens = self._tokens + tokens
            if self._max_tokens is not None and next_tokens > self._max_tokens:
                raise BudgetExhausted("max_tokens", self._max_tokens, next_tokens)
            self._tokens = next_tokens

    # --- read ----------------------------------------------------------------

    def snapshot(self) -> BudgetSnapshot:
        """A consistent read of all four axes (taken under the lock)."""

        with self._lock:
            return BudgetSnapshot(
                tokens=self._tokens,
                requests=self._requests,
                attempts=self._attempts,
                wall_s=round(self.elapsed_s(), 6),
                max_tokens=self._max_tokens,
                max_requests=self._max_requests,
                max_attempts=self._max_attempts,
                max_wall_s=self._max_wall_s,
            )

    def _check_wall_locked(self) -> None:
        if self._max_wall_s is None:
            return
        elapsed = self.elapsed_s()
        if elapsed > self._max_wall_s:
            raise BudgetExhausted("max_wall_s", self._max_wall_s, round(elapsed, 6))


def _validate_ceiling(axis: str, value: int | None) -> int | None:
    if value is not None and value < 0:
        raise ValueError(f"{axis} ceiling must be non-negative or None, got {value}")
    return value
