"""The rate ceiling (S8), which did not exist until 2026-09-21.

``--rate`` was parsed, resolved into a timing profile and dropped, so the rate half of the
threat model's S8 was decoration: ``--rate 0.0001`` (one request every ten thousand seconds)
finished eighteen specs in two thirds of a second. These tests drive the limiter with an
injected clock, so they assert the pacing arithmetic without waiting for it.
"""

from __future__ import annotations

import asyncio

import pytest

from ildottore.core.pacing import RateLimiter


class FakeClock:
    """A clock that only advances when something sleeps (so delays are observable)."""

    def __init__(self) -> None:
        self.t = 0.0
        self.slept: list[float] = []

    def now(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


def test_unpaced_limiter_never_sleeps() -> None:
    clock = FakeClock()
    limiter = RateLimiter(None, now=clock.now, sleep=clock.sleep)
    assert limiter.enabled is False
    asyncio.run(limiter.acquire())
    asyncio.run(limiter.acquire())
    assert clock.slept == []


@pytest.mark.parametrize("rate", [0.0, -1.0])
def test_a_non_positive_rate_is_unpaced(rate: float) -> None:
    assert RateLimiter(rate).enabled is False


def test_sends_are_spaced_by_the_interval() -> None:
    """Two requests per second means the second send waits half a second."""

    clock = FakeClock()
    limiter = RateLimiter(2.0, now=clock.now, sleep=clock.sleep)

    async def three() -> None:
        for _ in range(3):
            await limiter.acquire()

    asyncio.run(three())
    assert limiter.interval_s == pytest.approx(0.5)
    assert clock.slept == pytest.approx([0.5, 0.5])  # the first send goes immediately


def test_the_gate_is_shared_across_concurrent_waiters() -> None:
    """Concurrency must not multiply the rate.

    The scheduler runs specs under a bounded semaphore. A per-task limiter would let each of
    ``concurrency`` tasks pace itself, so the real rate would be ``rate x concurrency``: the
    reserved slot has to be shared, which is what this asserts.
    """

    clock = FakeClock()
    limiter = RateLimiter(1.0, now=clock.now, sleep=clock.sleep)

    async def four_at_once() -> None:
        await asyncio.gather(*(limiter.acquire() for _ in range(4)))

    asyncio.run(four_at_once())
    # Slots are reserved at t=0,1,2,3, so three of the four waiters wait and the campaign
    # clock ends at 3.0: four sends spread over three seconds at 1 req/s. With a per-task
    # limiter each waiter's first acquire would be due immediately and nothing would sleep,
    # which is the failure this pins.
    assert len(clock.slept) == 3
    assert clock.t == pytest.approx(3.0)
    assert sum(clock.slept) == pytest.approx(3.0)


def test_an_idle_gap_is_not_banked() -> None:
    """Waiting longer than the interval does not earn a burst of free sends."""

    clock = FakeClock()
    limiter = RateLimiter(1.0, now=clock.now, sleep=clock.sleep)
    asyncio.run(limiter.acquire())
    clock.t += 10.0  # idle
    asyncio.run(limiter.acquire())
    assert clock.slept == []  # due immediately, but only once
    asyncio.run(limiter.acquire())
    assert clock.slept == pytest.approx([1.0])


# --- the limiter is actually WIRED to the send path ---------------------------------


class _CountingPacer(RateLimiter):
    """A limiter that records how often it was consulted."""

    def __init__(self) -> None:
        super().__init__(1.0)
        self.acquired = 0

    async def acquire(self) -> None:
        self.acquired += 1


class _FlakyAdapter:
    """Fails with an env error once, then answers."""

    id = "flaky"

    def __init__(self) -> None:
        self.calls = 0

    async def send(self, request: object) -> object:
        from ildottore.shared.models import ModelResponse

        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("transient")
        return ModelResponse(text="ok")

    def capabilities(self) -> object:  # pragma: no cover - unused here
        from ildottore.shared.models import Capabilities

        return Capabilities()


def test_every_send_including_a_retry_passes_through_the_gate() -> None:
    """The ceiling is on sends, so a retry storm cannot burst past the authorized rate.

    Wired at ``execute_attempt``, the single funnel both the single-turn and the multi-turn
    paths go through, which is why one hook covers the whole engine.
    """

    from ildottore.core.budgets import BudgetLedger
    from ildottore.core.execute import RetryPolicy, execute_attempt
    from ildottore.shared.models import ModelRequest, PlanBudgets, Sampling

    pacer = _CountingPacer()
    adapter = _FlakyAdapter()

    async def go() -> None:
        await execute_attempt(
            adapter,  # type: ignore[arg-type]
            ModelRequest(prompt="hi", sampling=Sampling(temperature=0.0)),
            attempt_id="a1",
            spec_id="PI-DIRECT-001",
            mutation="identity",
            sampling=Sampling(temperature=0.0),
            ledger=BudgetLedger.from_plan_budgets(PlanBudgets(max_requests=10)),
            retry=RetryPolicy(max_retries=1),
            sleep=lambda _s: asyncio.sleep(0),
            now=lambda: 0.0,
            pacer=pacer,
        )

    asyncio.run(go())
    assert adapter.calls == 2  # one env failure, one success
    assert pacer.acquired == 2  # and BOTH were paced
