"""Single-attempt execution: send + retry/backoff/rate-limit/timeout (u08, §5.4).

:func:`execute_attempt` performs **one** ``(spec, variant)`` send against a
:class:`~ildottore.shared.protocols.TargetAdapter` with:

* **pinned sampling** recorded on the :class:`Attempt` (temperature/top_p/seed) so
  the run is reproducible and a reader sees exactly how it was probed (``docs/01 §5``);
* **retry with bounded backoff** on *environment* errors (rate-limit / timeout /
  5xx) - an env failure is retried then, if it persists, surfaced as an
  ``inconclusive`` outcome, never a product ``fail`` (``AGENTS.md §2``, contract §4
  KEEP: env-vs-product);
* a **budget debit per request** through the injected :class:`BudgetLedger` so a
  retry storm cannot self-DoS (the debit happens before each send; a breach raises
  :class:`BudgetExhausted` straight to the runner).

Error **classification** is injected as a predicate (``is_env_error``) so ``core``
never imports the adapter concretes' exception types (contract §8). The default
predicate recognizes the adapters' structural marker (an ``is_env_error`` attribute
or the class-name convention) without importing them.

The clock/sleep is injected (``sleep``) so tests run without real delays and the
backoff schedule is deterministic (contract §7).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ildottore.core.budgets import BudgetLedger
from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, Sampling
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "AttemptResult",
    "RetryPolicy",
    "default_is_env_error",
    "execute_attempt",
]


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded exponential backoff for *environment* errors only (contract §4 KEEP).

    ``max_retries`` is the number of *extra* attempts after the first send. Backoff
    is ``base_delay_s * (multiplier ** retry_index)`` capped at ``max_delay_s`` -
    deterministic, no jitter (reproducible replays; a real deployment can inject a
    jittered ``sleep`` at the composition root).
    """

    max_retries: int = 3
    base_delay_s: float = 0.5
    multiplier: float = 2.0
    max_delay_s: float = 8.0

    def delay_for(self, retry_index: int) -> float:
        """Backoff delay before the ``retry_index``-th retry (0-based)."""

        delay = self.base_delay_s * (self.multiplier**retry_index)
        return min(delay, self.max_delay_s)


@dataclass
class AttemptResult:
    """The outcome of one send (`docs/01 §4.4`).

    ``attempt`` always carries the recorded sampling + mutation + request. On a
    successful send ``attempt.response`` is populated and ``env_error`` is ``None``;
    on an exhausted-retry env failure ``attempt.error`` holds the last error string
    and ``env_error`` is ``True`` - the runner maps that to
    ``inconclusive`` (never a product ``fail``).
    """

    attempt: Attempt
    env_error: bool = False
    retries: int = 0
    errors: list[str] = field(default_factory=list)


def default_is_env_error(exc: BaseException) -> bool:
    """Classify ``exc`` as an environment error (retry/skip) vs a product defect (fail).

    Structural, import-free recognition (contract §8): an exception is an env error
    when it exposes a truthy ``is_env_error`` attribute (the adapters' convention)
    **or** its class name matches the env-error / timeout / rate-limit family. A
    plain :class:`asyncio.TimeoutError` / :class:`TimeoutError` is always an env
    error. Anything else is treated as a product-side surprise and re-raised by the
    caller (not masked as a flake - ``AGENTS.md §2``).
    """

    marker = getattr(exc, "is_env_error", None)
    if isinstance(marker, bool):
        return marker
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return True
    # Suffix match, not substring: an *Error whose class name ends with a known env family is
    # an env error, but a product exception that merely CONTAINS such a word (e.g.
    # ``PromptTimeoutViolation``) is NOT masked as a flake (audit low). The adapters' own env
    # errors set the ``is_env_error`` marker above, so this is only a last-resort heuristic.
    name = type(exc).__name__.lower()
    return name.endswith(("enverror", "timeouterror", "ratelimiterror", "ratelimit"))


async def execute_attempt(
    adapter: TargetAdapter,
    request: ModelRequest,
    *,
    attempt_id: str,
    spec_id: str,
    mutation: str,
    sampling: Sampling | None,
    ledger: BudgetLedger,
    retry: RetryPolicy | None = None,
    timeout_s: float | None = None,
    is_env_error: Callable[[BaseException], bool] = default_is_env_error,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    now: Callable[[], float] | None = None,
) -> AttemptResult:
    """Send one request with retry/backoff/timeout, debiting the budget per send.

    Returns an :class:`AttemptResult`. Raises :class:`BudgetExhausted` (from the
    ledger) straight through - the runner converts that into a ``budget_exhausted``
    halt. A non-env exception propagates (a real product/harness defect must not be
    masked). Env errors are retried up to ``retry.max_retries`` then returned as an
    ``env_error`` result for the runner to record ``inconclusive``.
    """

    policy = retry if retry is not None else RetryPolicy()
    do_sleep = sleep if sleep is not None else asyncio.sleep
    clock = now if now is not None else asyncio.get_event_loop().time
    errors: list[str] = []

    # Reserve the request's own max_tokens BEFORE the send so the token ceiling is a
    # pre-spend cap (a breach raises before any provider spend), not a post-hoc tally that a
    # concurrent burst could overshoot (audit M12). The actual usage is reconciled after.
    reserved = sampling.max_tokens if sampling is not None and sampling.max_tokens else 0

    total_sends = policy.max_retries + 1
    for send_index in range(total_sends):
        # Budget is debited per *send* (retries count) so a storm can't self-DoS.
        ledger.debit_request(tokens=reserved)
        started = clock()
        try:
            response = await _send_with_timeout(adapter, request, timeout_s, do_sleep)
        except BaseException as exc:
            if not is_env_error(exc):
                raise
            errors.append(f"{type(exc).__name__}: {exc}")
            if send_index < policy.max_retries:
                await do_sleep(policy.delay_for(send_index))
                continue
            return AttemptResult(
                attempt=_attempt(
                    attempt_id,
                    spec_id,
                    mutation,
                    request,
                    sampling,
                    response=None,
                    error=errors[-1],
                    latency_ms=None,
                ),
                env_error=True,
                retries=send_index,
                errors=errors,
            )
        else:
            latency_ms = max(0.0, (clock() - started) * 1000.0)
            _reconcile_tokens(ledger, response, reserved)
            return AttemptResult(
                attempt=_attempt(
                    attempt_id,
                    spec_id,
                    mutation,
                    request,
                    sampling,
                    response=response,
                    error=None,
                    latency_ms=latency_ms,
                ),
                env_error=False,
                retries=send_index,
                errors=errors,
            )

    # Unreachable: the loop either returns or raises. Kept for type-completeness.
    raise AssertionError("execute_attempt loop exited without a result")  # pragma: no cover


async def _send_with_timeout(
    adapter: TargetAdapter,
    request: ModelRequest,
    timeout_s: float | None,
    do_sleep: Callable[[float], Awaitable[None]],
) -> ModelResponse:
    """Await ``adapter.send`` under an optional timeout (env error on expiry)."""

    if timeout_s is None:
        return await adapter.send(request)
    return await asyncio.wait_for(adapter.send(request), timeout=timeout_s)


def _reconcile_tokens(ledger: BudgetLedger, response: ModelResponse, reserved: int = 0) -> None:
    """Reconcile the pre-send ``reserved`` token estimate with the actual reported usage.

    ``reserved`` was already debited before the send (the pre-spend cap). Here we add only the
    OVERAGE (``actual - reserved``) when the provider reports using more than reserved, so the
    ledger never under-counts; a response that used fewer than reserved keeps the (conservative)
    reservation. A breach raises :class:`BudgetExhausted` from the ledger (surfaced to the runner).
    """

    usage = response.usage
    if not isinstance(usage, dict):
        return
    total = usage.get("total_tokens")
    if isinstance(total, int) and not isinstance(total, bool) and total > reserved:
        ledger.add_tokens(total - reserved)


def _attempt(
    attempt_id: str,
    spec_id: str,
    mutation: str,
    request: ModelRequest,
    sampling: Sampling | None,
    *,
    response: ModelResponse | None,
    error: str | None,
    latency_ms: float | None,
) -> Attempt:
    """Assemble the recorded :class:`Attempt` (sampling always captured)."""

    return Attempt(
        attempt_id=attempt_id,
        spec_id=spec_id,
        mutation=mutation,
        request=request,
        response=response,
        verdict=None,
        sampling=sampling,
        latency_ms=latency_ms,
        error=error,
    )
