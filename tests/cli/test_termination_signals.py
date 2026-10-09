"""SIGTERM and SIGHUP stop a run as Ctrl-C would, even inside a callback (u12 A-60).

`execute_run` turned them into the KeyboardInterrupt Ctrl-C raises by installing
`signal.default_int_handler`, which raises wherever the main thread is. Inside a weakref
callback Python prints "Exception ignored" and drops it, so the run went on: in CI a SIGTERM
sent with a probe on the wire left the resume sending (41 requests served where 25 were
expected, `tests/cli/test_probe_pass_spend.py` on PRs #72 and #82). A Ctrl-C there was never lost:
inside `asyncio.run` it goes to asyncio's own handler, which cancels the run instead of raising.
SIGTERM and SIGHUP now do what Ctrl-C would do at that moment.

The signal is raised inside a real weakref callback, deterministically: `signal.raise_signal`
runs the Python handler before it returns, so the handler runs inside the callback.

SIGHUP is given a handler that does nothing for every test here (`sighup_handled`): under `nohup`
it is ignored, and an ignored SIGHUP stays ignored, so the SIGHUP cases failed under `nohup make
test` (pre-merge audit of #94).
"""

from __future__ import annotations

import asyncio
import gc
import logging
import signal
import weakref
from collections.abc import Iterator
from typing import Any

import pytest

from ildottore.cli.run import _termination_as_interrupt

pytestmark = pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")


class _Referent:
    pass


def _signal_inside_a_weakref_callback(signum: int) -> None:
    referent = _Referent()
    ref = weakref.ref(referent, lambda _ref: signal.raise_signal(signum))
    del referent  # the callback runs here; whatever it raises, Python only prints
    assert ref() is None


def _does_nothing(_signum: int, _frame: object) -> None:
    return None


@pytest.fixture(autouse=True)
def sighup_handled() -> Iterator[None]:
    """SIGHUP with a handler of its own, as a terminal leaves it, whatever the suite runs under.

    `_termination_as_interrupt` leaves an ignored SIGHUP ignored, which is what `nohup dottore
    run` needs, and `nohup` hands the suite SIGHUP ignored: the three SIGHUP cases then raised
    nothing and failed. This is the disposition the context manager replaces and puts back.
    """

    previous = signal.signal(signal.SIGHUP, _does_nothing)
    try:
        yield
    finally:
        signal.signal(signal.SIGHUP, previous)


@pytest.fixture
def ctrl_c() -> Iterator[None]:
    """Ctrl-C as an interactive shell leaves it; pytest a script starts with `&` has it ignored."""

    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


@pytest.mark.usefixtures("ctrl_c")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP", "SIGINT"])
def test_a_signal_inside_a_callback_stops_the_event_loop(name: str) -> None:
    """SIGINT is the control: it always stopped the loop. SIGTERM and SIGHUP were dropped."""

    finished: list[bool] = []

    async def campaign() -> None:
        _signal_inside_a_weakref_callback(getattr(signal, name))
        await asyncio.sleep(0.5)
        finished.append(True)

    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        asyncio.run(campaign())
    assert not finished, f"{name} inside a callback let the run finish"


@pytest.mark.parametrize("sigint", ["default", "ignored"])
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
def test_a_termination_signal_outside_a_loop_still_interrupts(name: str, sigint: str) -> None:
    """Outside an event loop, and when SIGINT is ignored (a job a script starts with `&`)."""

    previous = signal.signal(
        signal.SIGINT, signal.default_int_handler if sigint == "default" else signal.SIG_IGN
    )
    try:
        with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
            signal.raise_signal(getattr(signal, name))
    finally:
        signal.signal(signal.SIGINT, previous)


def test_a_termination_signal_in_a_loop_with_ctrl_c_ignored_still_interrupts() -> None:
    """With SIGINT ignored asyncio installs no handler of its own; SIGTERM must still stop it."""

    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    finished: list[bool] = []

    async def campaign() -> None:
        signal.raise_signal(signal.SIGTERM)
        await asyncio.sleep(0.5)
        finished.append(True)

    try:
        with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
            asyncio.run(campaign())
    finally:
        signal.signal(signal.SIGINT, previous)
    assert not finished


@pytest.mark.parametrize("sigint", ["default", "ignored"])
def test_with_ctrl_c_ignored_a_sigterm_in_an_asyncio_callback_waits_for_a_second(
    sigint: str,
) -> None:
    """What is left open (u12 A-60, the MANUAL): with Ctrl-C ignored a SIGTERM raises where the
    main thread is, and raised inside one of asyncio's own callbacks (here gather's, reading a
    result) it leaves the gather unfinished and the task awaiting it with nothing to wake it.
    `asyncio.run` cancels that task as it closes and then waits for it: ten turns of the closing
    loop later it is still cancelled and not done, and only the second signal ends the wait. With
    Ctrl-C at its default asyncio's handler cancels the run instead of raising, and the first
    signal is enough. If this fails because the first is enough with Ctrl-C ignored too, the docs
    that say to send the signal again are out of date.

    No clock decides it: the second signal is queued from inside the first's callback, so it runs
    on the loop `asyncio.run` drives as it closes, however slow the machine (a timer set before the
    first signal made 3 of 4 cases fail after a 0.25 s stall, pre-merge audit). With Ctrl-C at its
    default it is a timer 5 s on, which the closed loop never runs; it fails the test if it does.
    """

    signals: list[str] = []
    finished: list[bool] = []
    stuck: list[tuple[bool, int]] = []
    tasks: list[asyncio.Task[Any]] = []
    turns = 0

    def second() -> None:
        nonlocal turns
        if turns < 10:  # let the closing loop go round: nothing wakes the task
            turns += 1
            asyncio.get_running_loop().call_soon(second)
            return
        stuck.append((tasks[0].done(), tasks[0].cancelling()))
        signals.append("second")
        signal.raise_signal(signal.SIGTERM)

    class _SignalOnResult(asyncio.Future[None]):
        def result(self) -> None:
            if not signals:
                signals.append("first")
                loop = asyncio.get_running_loop()
                if sigint == "ignored":
                    loop.call_soon(second)  # behind the first, on the loop that closes the run
                else:
                    loop.call_later(5.0, second)  # a safety net: the first is enough here
                signal.raise_signal(signal.SIGTERM)
            return super().result()

    async def campaign() -> None:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        assert task is not None
        tasks.append(task)
        child = _SignalOnResult(loop=loop)
        loop.call_soon(child.set_result, None)
        await asyncio.gather(child)
        finished.append(True)

    previous = signal.signal(
        signal.SIGINT, signal.default_int_handler if sigint == "default" else signal.SIG_IGN
    )
    try:
        with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
            asyncio.run(campaign())
    finally:
        signal.signal(signal.SIGINT, previous)
    assert not finished
    if sigint == "default":
        assert signals == ["first"] and not stuck
        return
    assert signals == ["first", "second"]
    assert stuck == [(False, 1)]  # cancelled once as asyncio.run closed, and never woken
    # The stuck task is still pending: collect it here, with asyncio's "Task was destroyed but
    # it is pending!" muted, rather than in whichever test the collector next runs in.
    task_ref = weakref.ref(tasks.pop())
    logger = logging.getLogger("asyncio")
    muted = logger.disabled
    logger.disabled = True
    try:
        gc.collect()
    finally:
        logger.disabled = muted
    assert task_ref() is None
