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
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ildottore.core.budgets import DEFAULT_COMPLETION_TOKENS, BudgetExhausted, BudgetLedger
from ildottore.core.pacing import RateLimiter
from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, Sampling
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "NOT_RETRYABLE_MARK",
    "AttemptResult",
    "BudgetExhaustedAfterReply",
    "RetryPolicy",
    "default_is_env_error",
    "execute_attempt",
    "reserve_tokens",
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


class BudgetExhaustedAfterReply(BudgetExhausted):
    """A token ceiling crossed by the usage a reply reported, with that reply in hand.

    The provider billed those tokens, so the ledger records them and the campaign halts
    (``BudgetLedger.add_tokens``). The answered attempt rides on ``result`` so the caller can
    store it: it used to be dropped with the exception, and the resume sent it again and paid
    for it twice. Raised rather than returned, so a caller that does not look for it still halts.
    """

    def __init__(self, cause: BudgetExhausted, result: AttemptResult) -> None:
        super().__init__(cause.axis, cause.limit, cause.attempted)
        self.result = result


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
    pacer: RateLimiter | None = None,
) -> AttemptResult:
    """Send one request with retry/backoff/timeout, debiting the budget per send.

    Returns an :class:`AttemptResult`. Raises :class:`BudgetExhausted` (from the
    ledger) straight through - the runner converts that into a ``budget_exhausted``
    halt; when the ceiling is crossed by the usage of a reply already received, the
    exception is a :class:`BudgetExhaustedAfterReply` carrying the answered result, so
    the reply is stored rather than lost. A non-env exception propagates (a real
    product/harness defect must not be masked). Env errors are retried up to
    ``retry.max_retries`` then returned as an ``env_error`` result for the runner to record
    ``inconclusive``.
    """

    policy = retry if retry is not None else RetryPolicy()
    do_sleep = sleep if sleep is not None else asyncio.sleep
    clock = now if now is not None else asyncio.get_event_loop().time
    errors: list[str] = []

    # Reserve the request's tokens BEFORE the send so the token ceiling is a pre-spend cap (a
    # breach raises before any provider spend), not a post-hoc tally that a concurrent burst
    # could overshoot (audit M12). The actual usage is reconciled after.
    estimate = reserve_tokens(request, sampling)
    declared_cap = sampling is not None and bool(sampling.max_tokens)

    total_sends = policy.max_retries + 1
    for send_index in range(total_sends):
        # The authorized request rate is enforced per *send*, like the budget below, so a
        # retry storm cannot burst past it (u08 S8). Waiting happens before the debit: the
        # ledger records spend, the pacer decides when spending may happen.
        if pacer is not None:
            await pacer.acquire()
        # Budget is debited per *send* (retries count) so a storm can't self-DoS. A DEFAULT
        # estimate (no `max_tokens`) larger than the whole token ceiling is clamped to what is
        # left: it is a guess, not a limit the provider enforces, and unclamped it refused every
        # send under a ceiling below 513 tokens. Under any larger ceiling the full estimate is
        # reserved, so concurrent sends cannot all slip under it together.
        reserved = estimate
        if not declared_cap:
            ceiling = ledger.token_ceiling()
            remaining = ledger.remaining_tokens()
            if ceiling is not None and estimate > ceiling and remaining:
                reserved = remaining
        ledger.debit_request(tokens=reserved)
        started = clock()
        try:
            response = await _send_with_timeout(adapter, request, timeout_s, do_sleep)
        except BaseException as exc:
            if not is_env_error(exc):
                raise
            # No completion was billed for a send that failed: release its reservation (the
            # request still counts). Kept, it burned the token ceiling on a flaky endpoint.
            if reserved:
                ledger.refund_tokens(reserved)
            retryable = getattr(exc, "retryable", True) is not False
            # A failure that repeats identically is marked, so a resume does not send it again
            # either (it re-sends the other environment errors, F11).
            errors.append(
                f"{type(exc).__name__}: {exc}" + ("" if retryable else NOT_RETRYABLE_MARK)
            )
            # ``retryable = False`` (the adapters' convention, read structurally like
            # ``is_env_error``): a failure that repeats identically, such as a reply over the
            # size cap, is recorded once instead of being sent three more times.
            if send_index < policy.max_retries and retryable:
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
            answered = AttemptResult(
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
            try:
                _reconcile_tokens(ledger, response, reserved)
            except BudgetExhausted as exc:
                raise BudgetExhaustedAfterReply(exc, answered) from exc
            return answered

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


#: Appended to an attempt's error when the failure would repeat identically (``retryable =
#: False``, such as a reply over the size cap): a resume keeps that attempt instead of sending
#: it again.
NOT_RETRYABLE_MARK = " [not retryable]"


def reserve_tokens(request: ModelRequest, sampling: Sampling | None) -> int:
    """The tokens a send may consume, debited before it: input estimate plus output cap.

    Only the spec's ``max_tokens`` used to be reserved, and nothing at all for the 35 shipped
    specs that declare none, so four concurrent sends all passed the ceiling check before any
    reply came back: ``--budget-tokens 2500`` recorded 4000 (leftovers of the 2026-10-03 audit).
    The estimate is the one ``--estimate`` prints: input as text length / 4, output as
    ``max_tokens`` or :data:`DEFAULT_COMPLETION_TOKENS`. It bounds the spend only when the
    provider honours that output limit; a reply that uses more is still recorded in full.
    """

    texts = [request.system_prompt or "", request.prompt or ""]
    for message in request.messages or []:
        content = message.get("content")
        texts.append(content if isinstance(content, str) else "")
        if message.get("tool_calls"):  # threaded calls are input too (their arguments)
            texts.append(json.dumps(message["tool_calls"], sort_keys=True, default=str))
    if request.tools:  # in-band tool definitions (OD-18) are input too
        texts.append(json.dumps(request.tools, sort_keys=True))
    input_tokens = max(1, sum(len(text) for text in texts) // 4)
    output = sampling.max_tokens if sampling is not None and sampling.max_tokens else None
    return input_tokens + (output if output is not None else DEFAULT_COMPLETION_TOKENS)


def _reconcile_tokens(ledger: BudgetLedger, response: ModelResponse, reserved: int = 0) -> None:
    """True the pre-send ``reserved`` estimate up or down to the usage the provider reports.

    ``reserved`` was already debited before the send (the pre-spend cap). A reply that used
    more adds the overage, so the ledger never under-counts (a breach raises
    :class:`BudgetExhausted` after recording it); one that used less releases the rest, now
    that every send reserves a default estimate. Without a reported usage the reservation
    stands: the conservative figure is the only one there is.
    """

    total = _reported_total(response.usage)
    if total is None:
        return
    if total > reserved:
        ledger.add_tokens(total - reserved)
    elif total < reserved:
        ledger.refund_tokens(reserved - total)


def _reported_total(usage: object) -> int | None:
    """The total tokens a reply reports, in either provider's shape, or ``None``.

    OpenAI reports ``total_tokens``; Anthropic reports only ``input_tokens`` and
    ``output_tokens``, so its replies were never trued up (1034 tokens billed, the 513 reserved
    recorded; pre-commit audit of the leftovers). ``prompt_tokens`` + ``completion_tokens`` is
    the OpenAI shape without the total, and ``tokens`` a single-figure key of the mapping a
    REST template's ``usage_path`` points at (the adapter keeps only a mapping there; a REST
    target from ``target.yaml`` sets no ``usage_path`` and reports no usage).
    """

    if not isinstance(usage, dict):
        return None

    def count(key: str) -> int | None:
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None

    total = count("total_tokens")
    if total is None:
        total = count("tokens")  # a key of the mapping at a REST template's `usage_path`
    if total is not None:
        return total
    for first, second in (
        ("input_tokens", "output_tokens"),
        ("prompt_tokens", "completion_tokens"),
    ):
        a, b = count(first), count(second)
        if a is not None and b is not None:
            # Anthropic bills prompt-cache reads and writes as input too.
            cached = (count("cache_creation_input_tokens") or 0) + (
                count("cache_read_input_tokens") or 0
            )
            return a + b + cached
    return None


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
