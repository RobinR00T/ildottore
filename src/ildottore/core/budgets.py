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

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal

from ildottore.shared.models import PlanBudgets

__all__ = [
    "DEFAULT_COMPLETION_TOKENS",
    "BudgetExhausted",
    "BudgetLedger",
    "BudgetSnapshot",
    "Spend",
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
            f"budget exhausted on {axis!r}: attempted {_figure(attempted, up=True)} "
            f"would exceed limit {_figure(limit, up=False)}"
        )

    @property
    def figures(self) -> str:
        """``limit X, attempted Y`` for a halt reason, both written by :func:`_figure`."""

        limit = _figure(self.limit, up=False)
        return f"limit {limit}, attempted {_figure(self.attempted, up=True)}"


#: From here on a count prints as a magnitude: no real spend gets near it, and its digits alone
#: would fill the line.
_MAGNITUDE_FROM = 10**18


def _figure(value: int | float, *, up: bool) -> str:
    """A budget figure as a halt message writes it, in a shape the redactor leaves alone.

    Every surface masks the halt reason (SEC-01), and written bare a figure of nine characters
    or more is a phone number to the redactor (a Luhn-valid one of 13 to 19 digits, a card), so
    the reason read ``attempted «REDACTED:phone»`` for the very figure that stopped the run: a
    stop on the default 1,800 s wall ceiling (``1800.123456``), a count past 99,999,999, an
    operator ceiling that high. Digit groups break the run both rules need; seconds keep three
    decimals, because ``800.123456`` after a group separator is a phone number again; and a
    count from ``_MAGNITUDE_FROM`` up is written as a magnitude.

    A figure that has to be shortened is rounded AWAY from the ceiling: ``up`` for the figure
    that crossed it, down for the ceiling itself. Rounded to the nearest, 1,800.0004 s against a
    1,800 s ceiling read ``attempted 1,800.000 would exceed limit 1,800``. The arithmetic is on
    exact integers, so neither a float's range nor the ``decimal`` context can move a digit.
    """

    if isinstance(value, float):
        if not math.isfinite(value):
            return str(value)
        numerator, denominator = value.as_integer_ratio()
        whole, millis = divmod(_divide(numerator * 1000, denominator, up=up), 1000)
        return f"{whole:,}.{millis:03d}"
    if value < _MAGNITUDE_FROM:
        return f"{value:,}"
    # `Decimal` of an int is exact whatever the context, and unlike `str` it takes more than
    # 4,300 digits.
    exponent = Decimal(value).adjusted()
    lead = _divide(value, 10 ** (exponent - 3), up=up)  # the four leading digits
    if lead == 10_000:  # 9.9995e+N rounded up is 1.000e+(N+1)
        lead, exponent = 1_000, exponent + 1
    return f"{lead // 1000}.{lead % 1000:03d}e+{exponent}"


def _divide(numerator: int, denominator: int, *, up: bool) -> int:
    """``numerator / denominator`` rounded up or down to an integer, exactly."""

    return -(-numerator // denominator) if up else numerator // denominator


@dataclass(frozen=True)
class Spend:
    """What a campaign consumed, on the axes a ceiling can bind.

    Persisted per run so a **resume** opens its ledger already holding the prior
    invocation's spend. Without it the hard budget was per invocation: a run halted at its
    500k-token ceiling, resumed, and spent another 500k under the same ceiling and the same
    run id, so "this scan will not cost more than X" was true of each command and false of
    the campaign the operator was actually paying for.
    """

    tokens: int = 0
    requests: int = 0
    attempts: int = 0
    wall_s: float = 0.0

    def plus(self, other: Spend) -> Spend:
        return Spend(
            tokens=self.tokens + other.tokens,
            requests=self.requests + other.requests,
            attempts=self.attempts + other.attempts,
            wall_s=self.wall_s + other.wall_s,
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


#: Output tokens reserved before a send whose spec declares no ``sampling.max_tokens``, and
#: priced by ``--estimate`` for the same requests: one figure for both, so the estimate and the
#: ceiling agree. It is an accounting figure, not a limit sent to the provider.
DEFAULT_COMPLETION_TOKENS = 512


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
        prior: Spend | None = None,
    ) -> None:
        self._max_tokens = _validate_ceiling("max_tokens", max_tokens)
        self._max_requests = _validate_ceiling("max_requests", max_requests)
        self._max_attempts = _validate_ceiling("max_attempts", max_attempts)
        self._max_wall_s = _validate_ceiling("max_wall_s", max_wall_s)
        self._time = time_source if time_source is not None else time.monotonic
        self._lock = threading.Lock()
        # A ledger opened for a RESUMED run starts at the prior invocation's spend, so every
        # ceiling binds the campaign rather than the command. `_prior_wall_s` is kept apart
        # from `_started` because elapsed time is derived from the clock, not accumulated.
        opening = prior if prior is not None else Spend()
        self._tokens = opening.tokens
        self._requests = opening.requests
        self._attempts = opening.attempts
        self._prior_wall_s = opening.wall_s
        self._started = self._time()

    @classmethod
    def from_plan_budgets(
        cls,
        budgets: PlanBudgets,
        *,
        time_source: Callable[[], float] | None = None,
        prior: Spend | None = None,
    ) -> BudgetLedger:
        """Build a ledger from a :class:`TestPlan`'s :class:`PlanBudgets`."""

        return cls(
            max_tokens=budgets.max_tokens,
            max_requests=budgets.max_requests,
            max_attempts=budgets.max_attempts,
            max_wall_s=budgets.max_wall_s,
            time_source=time_source,
            prior=prior,
        )

    # --- wall clock ----------------------------------------------------------

    def elapsed_s(self) -> float:
        """Seconds this CAMPAIGN has spent, prior invocations included.

        For a fresh run that is "since the ledger opened". For a resumed one it also
        carries the halted invocation's elapsed time, so ``max_wall_s`` bounds the campaign
        and not each command that continues it. The pause between them is not counted: only
        time the scanner was actually running.
        """

        return self._prior_wall_s + (self._time() - self._started)

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
        """Account tokens observed *after* a response (usage reconciliation); halt on breach.

        Providers report actual token usage only in the response, which can exceed the
        caller's pre-debit estimate. These tokens were already billed, so they are COMMITTED
        first and the breach is raised after: refusing to record them left the ledger, and the
        spend a ``--resume`` inherits, below what the provider charged (240 tokens consumed,
        60 recorded, and the resume granted 40 more; audit 2026-10-03, F7).
        """

        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        with self._lock:
            self._tokens += tokens
            if self._max_tokens is not None and self._tokens > self._max_tokens:
                raise BudgetExhausted("max_tokens", self._max_tokens, self._tokens)

    def token_ceiling(self) -> int | None:
        """The token ceiling, or ``None`` when there is none."""

        return self._max_tokens

    def remaining_tokens(self) -> int | None:
        """Tokens left under the ceiling, or ``None`` when there is no token ceiling."""

        with self._lock:
            if self._max_tokens is None:
                return None
            return max(0, self._max_tokens - self._tokens)

    def refund_tokens(self, tokens: int) -> None:
        """Release a pre-send token reservation for a send that produced no completion.

        A send that raised was never billed for its completion; keeping its reservation made a
        flaky endpoint exhaust the token ceiling with zero tokens consumed and persisted that
        phantom spend for the resume (audit 2026-10-03, F18). The request itself still counts.
        """

        if tokens < 0:
            raise ValueError("tokens must be non-negative")
        with self._lock:
            self._tokens = max(0, self._tokens - tokens)

    # --- read ----------------------------------------------------------------

    def spend(self) -> Spend:
        """This campaign's consumption so far, in the shape that is persisted."""

        snap = self.snapshot()
        return Spend(
            tokens=snap.tokens,
            requests=snap.requests,
            attempts=snap.attempts,
            wall_s=snap.wall_s,
        )

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
