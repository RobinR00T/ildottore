"""Metering for sends the runner does not make itself: the ``--judge`` model.

Threat model S8 and clause A-11 say a declared ceiling binds every request the tool makes and
that every send obeys the authorized rate. The judge broke both: ``semantic_judge`` sends at
least two requests per evaluated attempt straight to its own adapter, with no ledger and no
pacer, so with ``--judge`` two thirds of the wire traffic sat outside both (audit 2026-10-03,
F6 / F-7: ``--budget-requests 5`` sent 15).

The judge adapter is built at the composition root, before the campaign's ledger exists, so it
is wrapped in a :class:`MeteredAdapter` that reads its ledger and pacer from a
:class:`SendMeter`. The runner binds the meter to its ledger and pacer for the length of
:meth:`~ildottore.core.runner.CampaignRunner.run`. The wrapper also owns the judge's retries,
each one metered, so a 429 storm cannot burst past the rate either (F10).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from ildottore.core.budgets import BudgetLedger
from ildottore.core.execute import RetryPolicy, default_is_env_error
from ildottore.core.pacing import RateLimiter
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse
from ildottore.shared.protocols import TargetAdapter

__all__ = ["MeteredAdapter", "SendMeter"]


class SendMeter:
    """The ledger and pacer of the campaign that is running now, for sends made outside it."""

    def __init__(self) -> None:
        self._ledger: BudgetLedger | None = None
        self._pacer: RateLimiter | None = None

    @contextmanager
    def bound(self, ledger: BudgetLedger, pacer: RateLimiter) -> Iterator[None]:
        """Meter every send through this meter against ``ledger`` and ``pacer`` for the block."""

        previous = (self._ledger, self._pacer)
        self._ledger, self._pacer = ledger, pacer
        try:
            yield
        finally:
            self._ledger, self._pacer = previous

    async def before_send(self) -> None:
        """Wait for the rate gate, then debit one request (raises ``BudgetExhausted``)."""

        if self._pacer is not None:
            await self._pacer.acquire()
        if self._ledger is not None:
            self._ledger.debit_request()


@dataclass
class MeteredAdapter:
    """A :class:`TargetAdapter` whose every wire send is paced and debited by a meter.

    Build the wrapped adapter with no retries of its own: this wrapper retries environment
    errors per ``retry``, metering each attempt, so no send is uncounted.
    """

    inner: TargetAdapter
    meter: SendMeter
    retry: RetryPolicy = field(default_factory=lambda: RetryPolicy(max_retries=2))
    is_env_error: Callable[[BaseException], bool] = default_is_env_error
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    id: str = field(init=False)

    def __post_init__(self) -> None:
        self.id = self.inner.id

    def capabilities(self) -> Capabilities:
        return self.inner.capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        for index in range(self.retry.max_retries + 1):
            await self.meter.before_send()
            try:
                return await self.inner.send(request)
            except Exception as exc:
                retryable = getattr(exc, "retryable", True) is not False
                if not self.is_env_error(exc) or not retryable or index == self.retry.max_retries:
                    raise
                await self.sleep(self.retry.delay_for(index))
        raise AssertionError("unreachable")  # pragma: no cover
