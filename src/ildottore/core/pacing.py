"""Request pacing - the ``--rate`` / ``-T`` ceiling, enforced (u08, S8).

``docs/02-threat-model.md`` S8 promises two halves: the scanner cannot outspend its budget
(:mod:`ildottore.core.budgets`) and it cannot outpace the rate the operator authorized. The
budget half was real; **the rate half did not exist**: ``--rate`` was parsed, resolved into a
:class:`~ildottore.cli.flags.Timing` and then dropped, so ``--rate 0.0001`` (one request every
ten thousand seconds) finished eighteen specs in two thirds of a second, and the rate column of
every ``-T`` template was decoration.

Two design points:

* **One gate for the whole campaign, not one per coroutine.** The scheduler runs specs under a
  bounded semaphore, so a per-task limiter would let each of ``concurrency`` tasks pace itself
  and multiply the real rate by ``concurrency``. A waiter reserves the next slot in a shared
  monotonic schedule under a lock, then sleeps outside it.
* **Retries count.** The ceiling is on *sends*, like the request budget, so a retry storm
  cannot burst past the authorized rate.

The clock and the sleep are injected, so the pacing is exercised in tests without real waits.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

__all__ = ["RateLimiter"]


class RateLimiter:
    """At most ``rate_rps`` sends per second across the whole campaign.

    ``rate_rps`` of ``None`` or ``<= 0`` means unpaced, and :meth:`acquire` is then a no-op:
    an offline mock campaign has no endpoint to be polite to, and pacing it would only slow
    CI down (the CLI says so out loud rather than accepting a flag it ignores).
    """

    def __init__(
        self,
        rate_rps: float | None,
        *,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._interval = 1.0 / rate_rps if rate_rps is not None and rate_rps > 0 else 0.0
        self._now = now
        self._sleep = sleep
        self._next_at: float | None = None
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        """Whether this limiter actually paces anything."""

        return self._interval > 0.0

    @property
    def interval_s(self) -> float:
        """Seconds between consecutive sends (``0.0`` when unpaced)."""

        return self._interval

    async def acquire(self) -> None:
        """Wait until the next send is due (no-op when unpaced)."""

        if self._interval <= 0.0:
            return
        clock = self._now if self._now is not None else asyncio.get_event_loop().time
        do_sleep = self._sleep if self._sleep is not None else asyncio.sleep
        async with self._lock:
            now = clock()
            # Reserve this send's slot before releasing the lock, so concurrent waiters
            # queue behind it instead of all computing the same "now" and firing together.
            start = now if self._next_at is None else max(now, self._next_at)
            self._next_at = start + self._interval
            delay = start - now
        if delay > 0.0:
            await do_sleep(delay)
