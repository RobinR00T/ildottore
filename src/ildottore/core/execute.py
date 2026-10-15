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

A third class is neither (OD-41, u08 A-69): a prompt the provider's own input filter refused
before the model saw it (Azure OpenAI's HTTP 400 ``content_filter``, Gemini's prompt block),
which an adapter raises with a ``blocked_by_provider_filter`` marker set to ``True``. The attempt is
recorded as blocked, without a reply, and is not sent again (the same prompt is refused the same
way); the send stays debited, its token reservation is released as for an environment error (no
completion was produced), and the runner records it ``inconclusive: blocked_by_provider_filter``.
It used to propagate as a product error and stop the whole campaign at the first one.

A reply the provider's filter stopped (OD-42, u08 A-70) comes back as an HTTP 200, so it is read
here, after the send, with ``shared.provider_filter.filter_side``. A filter that refused the
prompt (a Bedrock guardrail trace that says so, Anthropic's ``refusal`` before any output) is the
block above, recorded the same way with the reply kept for the evidence. A filter that cut or
replaced what the model wrote, or one that does not say which it did, marks the result
``filter_cut`` with that side, and the runner never scores the reply as the model's answer.

A success reply the adapter cannot read (``ResponseMalformed``: not JSON, not an object, not the
provider's shape) is an environment failure that is not retried, so the attempt is inconclusive
(OD-21, decided 2026-10-11 under the owner's delegation, revisable). It carries a
``malformed_reply`` marker, read by :func:`is_unreadable_reply`, which the runner counts: a
campaign whose first :data:`UNREADABLE_REPLIES_TO_STOP` replies all are unreadable, with none it
could read, stops with :class:`UnreadableReplies` (u08 A-74), so a wrong endpoint is caught early.

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
from ildottore.shared.amounts import is_count
from ildottore.shared.error_text import error_text
from ildottore.shared.models import Attempt, JsonDict, ModelRequest, ModelResponse, Sampling
from ildottore.shared.protocols import TargetAdapter
from ildottore.shared.provider_filter import (
    INPUT_FILTER_REFUSED,
    INPUT_SIDE,
    PROVIDER_FILTER_MARK,
    describe_filter_stop,
    filter_side,
)
from ildottore.shared.unreadable import UNREADABLE_MARK, UNREADABLE_REPLY_KEY

__all__ = [
    "NOT_RETRYABLE_MARK",
    "UNREADABLE_REPLIES_TO_STOP",
    "UNREADABLE_STREAK_TO_STOP",
    "AttemptResult",
    "CeilingAtUnreadable",
    "ReplyOverBudget",
    "RetryPolicy",
    "UnreadableReplies",
    "default_is_env_error",
    "execute_attempt",
    "is_provider_filter_block",
    "is_unreadable_reply",
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
    ``inconclusive`` (never a product ``fail``). ``filter_blocked`` is ``True`` when the
    provider's input filter refused the prompt (OD-41): the error carries
    :data:`~ildottore.shared.provider_filter.PROVIDER_FILTER_MARK`, ``env_error`` is ``False``,
    and there is no response, unless the refusal came as a reply (OD-42), which is kept.

    ``filter_cut`` is the side (``output`` or ``unknown``) when the provider's filter stopped the
    reply after the prompt reached the model, or may have (OD-42, u08 A-70): the response is
    kept and is not the model's whole answer. ``cut_before_final`` is ``True`` when a conversation
    stopped at that reply before the one its spec scores (``core.conversation``).
    """

    attempt: Attempt
    env_error: bool = False
    filter_blocked: bool = False
    retries: int = 0
    errors: list[str] = field(default_factory=list)
    filter_cut: str | None = None
    cut_before_final: bool = False
    #: The target answered with a reply the adapter could not read (OD-21, u08 A-74): no
    #: response, ``env_error`` is ``True``, the error carries
    #: :data:`~ildottore.shared.unreadable.UNREADABLE_MARK`, and the runner records it
    #: ``inconclusive: unreadable_reply``, which keeps its spec from passing.
    unreadable: bool = False
    #: A conversation a later send's environment error or unreadable reply ended after the model
    #: had called a tool: its last reply with the whole trace so far (``core.conversation``),
    #: which the runner's trace evaluators read, since a call already made can fail the attempt
    #: (audit of the scoring, 2026-10-11, HIGH 2). Kept off ``attempt``, which still has no
    #: reply, so an attempt the trace does not fail is stored as before and a resume sends it
    #: again.
    trace_so_far: ModelResponse | None = None


class ReplyOverBudget(BudgetExhausted):
    """A token ceiling crossed by the usage a reply reported, with that reply in hand.

    The provider billed those tokens, so the ledger records them and the campaign halts
    (``BudgetLedger.add_tokens``). The answered attempt rides on ``result`` so the caller can
    store it: it used to be dropped with the exception, and the resume sent it again and paid
    for it twice. Raised rather than returned, so a caller that does not look for it still halts.
    Named so the redactor keeps the name: it masks ``BudgetExhaustedAfterReply`` as high
    entropy, so an error line that wrote the class would read ``«REDACTED:high_entropy:...»``
    (u01 A-63).
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


def is_provider_filter_block(exc: BaseException) -> bool:
    """True when ``exc`` says the provider's input filter refused the prompt (OD-41).

    Structural, as :func:`default_is_env_error` is: the adapters' ``ProviderFilterBlock`` sets
    ``blocked_by_provider_filter = True``. Only ``True`` counts, so a mock's attribute of
    another type is not read as one.
    """

    return getattr(exc, "blocked_by_provider_filter", None) is True


#: How many replies in a row the adapters could not read a campaign takes before it stops, while
#: it has read none (OD-21, u08 A-74). Five, as a circuit breaker's run of consecutive failures: a
#: wrong endpoint, provider or template answers every request alike and is caught for the price of
#: five requests instead of the battery's hundreds, while a hostile target has to garble every one
#: of the first five attacks to stop a scan.
UNREADABLE_REPLIES_TO_STOP = 5

#: The same run counted after the campaign has read a reply (u08 A-74): a target that breaks mid-
#: run (an expired session behind a proxy that serves a login page with a 200) answers every later
#: request alike, and sent the rest of the battery to be scored inconclusive (pre-merge audit of
#: 598f0858, MEDIUM 2: 355 requests, 353 unreadable, exit 0). Twenty, four times the first figure:
#: a proven endpoint earns more doubt, and an attack battery garbles in runs (a wrapper that
#: breaks on a quote breaks on every variant of a jailbreak that works). Each reply read resets
#: the run, so a garbled attack costs its attempt only.
UNREADABLE_STREAK_TO_STOP = 20


def is_unreadable_reply(exc: BaseException) -> bool:
    """True when ``exc`` is a success reply the adapter could not read (OD-21).

    Structural, as :func:`is_provider_filter_block` is: the adapters' ``ResponseMalformed`` sets
    ``malformed_reply = True``. Only ``True`` counts.
    """

    return getattr(exc, "malformed_reply", None) is True


class UnreadableReplies(Exception):
    """A run of replies the campaign could not read: it stops (u08 A-74).

    Raised by the runner's watch in place of the unreadable ``reply`` that ends the run (the
    fifth before any reply was read, or the twentieth in a row after). Not an environment error
    (``is_env_error = False``): it propagates out of :func:`execute_attempt` like a product
    error, carrying the ``result`` that reply makes, its reservation released, which
    ``reproduce`` and the conversation executor keep before the halt goes on, as they keep a
    :class:`ReplyOverBudget`'s (pre-merge audit of 598f0858, MEDIUM 1). The runner halts the
    campaign as ``aborted`` with this message as the reason. Named so the redactor keeps the name
    (u01 A-63).
    """

    is_env_error = False

    def __init__(self, message: str, *, reply: BaseException) -> None:
        super().__init__(message)
        self.reply = reply
        self.result: AttemptResult | None = None


class CeilingAtUnreadable(Exception):
    """A ceiling that refused the watch's benign check, with the unreadable reply that called for
    it (verification of da16f219, LOW 1).

    Raised by the runner's watch in place of that reply. :func:`execute_attempt` turns it into a
    :class:`ReplyOverBudget` carrying the reply's result, its reservation released, so the reply
    is stored before the ceiling halts the campaign: raised as the plain ceiling, it replaced the
    reply, which was never stored, and its tokens stayed reserved. Named so the redactor keeps the
    name (u01 A-63).
    """

    is_env_error = False

    def __init__(self, ceiling: BudgetExhausted, *, reply: BaseException) -> None:
        super().__init__(str(ceiling))
        self.ceiling = ceiling
        self.reply = reply


def _unreadable_result(
    reply: BaseException,
    *,
    attempt_id: str,
    spec_id: str,
    mutation: str,
    request: ModelRequest,
    sampling: Sampling | None,
    retries: int,
    errors: list[str],
) -> AttemptResult:
    """The attempt a reply the adapter could not read makes (OD-21, u08 A-74).

    No response; the error marked :data:`~ildottore.shared.unreadable.UNREADABLE_MARK` (a resume
    sends it again, since the target may have been fixed); and what the adapter kept of the body,
    its size and its advice, under ``request.metadata.unreadable_reply`` for review.
    """

    errors.append(f"{error_text(reply)}{UNREADABLE_MARK}")
    kept = {
        key: value
        for key, value in (
            ("excerpt", getattr(reply, "excerpt", None)),
            ("bytes", getattr(reply, "size", None)),
            ("advice", getattr(reply, "advice", None)),
        )
        if value is not None
    }
    recorded = request
    if kept:
        metadata: JsonDict = {**(request.metadata or {}), UNREADABLE_REPLY_KEY: kept}
        recorded = request.model_copy(update={"metadata": metadata})
    return AttemptResult(
        attempt=_attempt(
            attempt_id,
            spec_id,
            mutation,
            recorded,
            sampling,
            response=None,
            error=errors[-1],
            latency_ms=None,
        ),
        env_error=True,
        retries=retries,
        errors=errors,
        unreadable=True,
    )


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
    opens_attempt: bool = False,
) -> AttemptResult:
    """Send one request with retry/backoff/timeout, debiting the budget per send.

    ``opens_attempt``: this is the first request of an attack attempt, which its first send
    counts against the attempts axis in the same debit (a retry never counts again, u08 A-80).

    Returns an :class:`AttemptResult`. Raises :class:`BudgetExhausted` (from the
    ledger) straight through - the runner converts that into a ``budget_exhausted``
    halt; when the ceiling is crossed by the usage of a reply already received, the
    exception is a :class:`ReplyOverBudget` carrying the answered result, so
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
        ledger.debit_request(tokens=reserved, opens_attempt=opens_attempt)
        opens_attempt = False  # counted with the first send; a retry is the same attempt
        started = clock()
        try:
            response = await _send_with_timeout(adapter, request, timeout_s, do_sleep)
        except BaseException as exc:
            if is_provider_filter_block(exc):
                # Before the env question: it is not one, and before OD-41 it propagated as a
                # product error and stopped the campaign. Not retried: the same prompt is
                # refused the same way. The request stays debited; no completion was billed.
                if reserved:
                    ledger.refund_tokens(reserved)
                errors.append(f"{error_text(exc)}{PROVIDER_FILTER_MARK}")
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
                    filter_blocked=True,
                    retries=send_index,
                    errors=errors,
                )
            # A reply the adapter could not read (OD-21), and the one the campaign's watch stopped
            # it on, which travels on the stop (pre-merge audit of 598f0858, MEDIUM 1: it was
            # sent, debited and never stored, and its token reservation stayed spent).
            halt = exc if isinstance(exc, UnreadableReplies) else None
            refused = exc if isinstance(exc, CeilingAtUnreadable) else None
            reply = halt.reply if halt is not None else refused.reply if refused else exc
            if is_unreadable_reply(reply):
                if reserved:
                    ledger.refund_tokens(reserved)
                unreadable = _unreadable_result(
                    reply,
                    attempt_id=attempt_id,
                    spec_id=spec_id,
                    mutation=mutation,
                    request=request,
                    sampling=sampling,
                    retries=send_index,
                    errors=errors,
                )
                if refused is not None:  # the ceiling's halt, the reply in hand (as a reply's own)
                    raise ReplyOverBudget(refused.ceiling, unreadable) from exc
                if halt is None:
                    return unreadable
                halt.result = unreadable
                raise
            if not is_env_error(exc):
                raise
            # No completion was billed for a send that failed: release its reservation (the
            # request still counts). Kept, it burned the token ceiling on a flaky endpoint.
            if reserved:
                ledger.refund_tokens(reserved)
            retryable = getattr(exc, "retryable", True) is not False
            # A failure that repeats identically is marked, so a resume does not send it again
            # either (it re-sends the other environment errors, F11).
            errors.append(error_text(exc) + ("" if retryable else NOT_RETRYABLE_MARK))
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
            side = filter_side(response)
            error = None
            if side == INPUT_SIDE:
                # The provider's filter refused the prompt and said so in a reply (OD-42): the
                # block of OD-41, recorded with the same mark, the reply kept as evidence.
                target = getattr(adapter, "id", "target")
                error = (
                    f"{target}: {INPUT_FILTER_REFUSED} ({describe_filter_stop(response)})"
                    f"{PROVIDER_FILTER_MARK}"
                )
                errors.append(error)
            answered = AttemptResult(
                attempt=_attempt(
                    attempt_id,
                    spec_id,
                    mutation,
                    request,
                    sampling,
                    response=response,
                    error=error,
                    latency_ms=latency_ms,
                ),
                env_error=False,
                filter_blocked=side == INPUT_SIDE,
                retries=send_index,
                errors=errors,
                filter_cut=side if side is not None and side != INPUT_SIDE else None,
            )
            try:
                _reconcile_tokens(ledger, response, reserved)
            except BudgetExhausted as exc:
                raise ReplyOverBudget(exc, answered) from exc
            return answered

    # Unreachable: the loop either returns or raises. Kept for type-completeness.
    raise AssertionError("execute_attempt loop exited without a result")  # pragma: no cover


async def _send_with_timeout(
    adapter: TargetAdapter,
    request: ModelRequest,
    timeout_s: float | None,
    do_sleep: Callable[[float], Awaitable[None]],
) -> ModelResponse:
    """Await ``adapter.send`` under an optional timeout (env error on expiry).

    ``asyncio.timeout``, not ``asyncio.wait_for``: on Python 3.11 ``wait_for`` runs the send as a
    task of its own and, when its caller is cancelled just as that send completes, returns the
    reply and drops the cancellation (CPython gh-86296), so a spec a signal stopped at that
    instant went on sending (pre-merge audit of the A-60 fix). ``asyncio.timeout`` awaits the
    send in this task, where a cancellation always wins, and raises :class:`TimeoutError` on
    expiry, as ``wait_for`` did; from 3.12 ``wait_for`` is built on it.
    """

    if timeout_s is None:
        return await adapter.send(request)
    try:
        async with asyncio.timeout(timeout_s) as deadline:
            return await adapter.send(request)
    except TimeoutError as exc:
        # `asyncio.timeout` raises a TimeoutError with no message, which the attempt's error and
        # the run's reason then ended on: `TimeoutError: ` (u12 A-82, CLI audit L8).
        if deadline.expired():
            raise TimeoutError(
                f"no reply within the per-attempt timeout of {timeout_s:g} s"
            ) from exc
        raise


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
    stands: the conservative figure is the only one there is. A pair summed beside an
    unreadable prompt-cache figure is a floor: the reservation is trued up to it, never down
    (and a floor past ``2**53`` is no usage, like any sum past it).
    """

    reported = _reported_total(response.usage)
    if reported is None:
        return
    total, whole = reported
    if total > reserved:
        ledger.add_tokens(total - reserved)
    elif total < reserved and whole:
        ledger.refund_tokens(reserved - total)


def _reported_total(usage: object) -> tuple[int, bool] | None:
    """The total tokens a reply reports, in either provider's shape, and whether it is all of
    them; or ``None``.

    OpenAI reports ``total_tokens``; Anthropic reports only ``input_tokens`` and
    ``output_tokens``, so its replies were never trued up (1034 tokens billed, the 513 reserved
    recorded; pre-commit audit of the leftovers). ``prompt_tokens`` + ``completion_tokens`` is
    the OpenAI shape without the total, and ``tokens`` a single-figure key of the mapping a
    REST template's ``usage_path`` points at (the adapter keeps only a mapping there; a REST
    target from ``target.yaml`` sets no ``usage_path`` and reports no usage).

    A figure is read only when it is a JSON integer from 0 to ``2**53`` (:func:`is_count`). The
    reply is the target's, so its figures have no bound: a 400-digit one was trued into the
    ledger and the run exited 1 on ``OverflowError`` when its spend was persisted, with no
    report, and one past ``2**53`` was believed and halted the campaign on the token ceiling
    after one reply (2026-10-07). An unreadable figure is skipped like an absent one, so the
    next shape is read, and a sum past ``2**53`` is ``None``. A prompt-cache figure that is
    there and unreadable makes the sum of a pair a part, not the whole (``False``). Before, one
    that was not a non-negative integer was read as 0, which trued the reservation down past
    tokens the reply says it billed, and read as no usage (the first version of this fix) it
    kept the reservation below a larger pair.
    """

    if not isinstance(usage, dict):
        return None

    def count(key: str) -> int | None:
        value = usage.get(key)
        return value if is_count(value) else None

    total = count("total_tokens")
    if total is None:
        total = count("tokens")  # a key of the mapping at a REST template's `usage_path`
    if total is not None:
        return total, True
    # Anthropic bills prompt-cache reads and writes as input too. A null one is not reported.
    keys = ("cache_creation_input_tokens", "cache_read_input_tokens")
    cache = [usage[key] for key in keys if usage.get(key) is not None]
    for first, second in (
        ("input_tokens", "output_tokens"),
        ("prompt_tokens", "completion_tokens"),
    ):
        a, b = count(first), count(second)
        if a is not None and b is not None:
            read = [value for value in cache if is_count(value)]
            summed = a + b + sum(read)
            return (summed, len(read) == len(cache)) if is_count(summed) else None
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
