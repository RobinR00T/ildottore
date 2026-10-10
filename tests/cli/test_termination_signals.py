"""SIGTERM and SIGHUP stop a run as Ctrl-C would, even inside a callback (u12 A-60).

`execute_run` turned them into the KeyboardInterrupt Ctrl-C raises by installing
`signal.default_int_handler`, which raises wherever the main thread is. Inside a weakref
callback Python prints "Exception ignored" and drops it, so the run went on: in CI a SIGTERM
sent with a probe on the wire left the resume sending (41 requests served where 25 were
expected, `tests/cli/test_probe_pass_spend.py` on PRs #72 and #82). A Ctrl-C there was never lost:
inside `asyncio.run` it goes to asyncio's own handler, which cancels the run instead of raising.
SIGTERM and SIGHUP then called whatever Ctrl-C handler was in place, which left one case: with
Ctrl-C ignored they still raised, and raised inside gather's callback they left the run waiting
for a second signal as it closed (pre-merge audit of #94). Every loop `dottore` runs is now one of
`interrupts.run_until_stopped`, where the first of them cancels the run's task whatever Ctrl-C's
disposition, and KeyboardInterrupt is raised once the loop is closed.

The signal is raised inside a real callback, deterministically: `signal.raise_signal` runs the
Python handler before it returns, so the handler runs inside the callback.

SIGHUP is given a handler that does nothing for every test here (`sighup_handled`): under `nohup`
it is ignored, and an ignored SIGHUP stays ignored, so the SIGHUP cases failed under `nohup make
test` (pre-merge audit of #94).
"""

from __future__ import annotations

import asyncio
import gc
import logging
import selectors
import signal
import threading
import weakref
from collections.abc import Callable, Coroutine, Iterator
from typing import Any

import pytest

from ildottore.cli.interrupts import run_until_stopped
from ildottore.cli.run import _termination_as_interrupt

pytestmark = pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX signals")

_Driver = Callable[[Coroutine[Any, Any, None]], None]


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


@pytest.fixture(params=["default", "ignored"])
def sigint(request: pytest.FixtureRequest) -> Iterator[str]:
    """Ctrl-C at its default, or ignored as for a job a script starts with `&`."""

    disposition = signal.default_int_handler if request.param == "default" else signal.SIG_IGN
    previous = signal.signal(signal.SIGINT, disposition)
    try:
        yield str(request.param)
    finally:
        signal.signal(signal.SIGINT, previous)


def _asyncio_run(main: Coroutine[Any, Any, None]) -> None:
    asyncio.run(main)


def _run_until_stopped(main: Coroutine[Any, Any, None]) -> None:
    run_until_stopped(main)


@pytest.mark.usefixtures("ctrl_c")
@pytest.mark.parametrize(
    "drive", [_run_until_stopped, _asyncio_run], ids=["run_until_stopped", "asyncio.run"]
)
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP", "SIGINT"])
def test_a_signal_inside_a_callback_stops_the_event_loop(name: str, drive: _Driver) -> None:
    """SIGINT is the control: it always stopped the loop. SIGTERM and SIGHUP were dropped.

    `asyncio.run` is the loop of a program that embeds `execute_run`'s pieces: there the signal
    still goes to the Ctrl-C handler in place, asyncio's own."""

    finished: list[bool] = []

    async def campaign() -> None:
        _signal_inside_a_weakref_callback(getattr(signal, name))
        await asyncio.sleep(0.5)
        finished.append(True)

    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        drive(campaign())
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


@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])
def test_a_termination_signal_in_a_loop_cancels_the_run(sigint: str, name: str) -> None:
    """With SIGINT ignored asyncio installs no handler of its own; the signal still stops the run,
    by cancelling it: the campaign sees CancelledError at its next await, not a KeyboardInterrupt
    raised wherever it was, and KeyboardInterrupt comes out once the loop is closed."""

    seen: list[str] = []

    async def campaign() -> None:
        try:
            signal.raise_signal(getattr(signal, name))
            await asyncio.sleep(0.5)
            seen.append("finished")
        except BaseException as exc:
            seen.append(type(exc).__name__)
            raise

    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        run_until_stopped(campaign())
    assert seen == ["CancelledError"]


def test_a_second_signal_raises_where_the_run_is(sigint: str) -> None:
    """The first cancels; a second, before the run has stopped, raises in place, as a second
    Ctrl-C does under `asyncio.run`: it is for a stop that does not end."""

    seen: list[str] = []

    async def campaign() -> None:
        try:
            signal.raise_signal(signal.SIGTERM)
            signal.raise_signal(signal.SIGTERM)
            await asyncio.sleep(0.5)
        except BaseException as exc:
            seen.append(type(exc).__name__)
            raise

    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        run_until_stopped(campaign())
    assert seen == ["KeyboardInterrupt"]


def test_one_signal_inside_an_asyncio_callback_is_enough(sigint: str) -> None:
    """A SIGTERM raised inside one of asyncio's own callbacks (gather's, reading a result).

    It used to raise there with Ctrl-C ignored, and gather's callback stopped before it woke
    the task awaiting it: `asyncio.run` cancelled that task as it closed and waited for it, and
    only a second signal ended the wait, the stuck part's spend written when Python collected
    the task (pre-merge audit of #94). Now the handler only cancels the task, gather's callback
    finishes, and the task unwinds inside the loop (here its `except`, in the runner the
    `finally` that writes the spend) before KeyboardInterrupt comes out, with Ctrl-C at its
    default or ignored alike.

    No clock decides it. The safety net is a callback queued from inside the first signal that
    goes round the loop: it stops once the task is done, and if ten turns later the task is
    still not done, nothing will wake it, so it records that and sends the second signal to end
    the test. It must never be needed.
    """

    signals: list[str] = []
    unwound: list[str] = []
    stuck: list[tuple[bool, int]] = []
    tasks: list[asyncio.Task[Any]] = []
    turns = 0

    def net() -> None:
        nonlocal turns
        if tasks[0].done():
            return
        if turns < 10:
            turns += 1
            asyncio.get_running_loop().call_soon(net)
            return
        stuck.append((tasks[0].done(), tasks[0].cancelling()))
        signals.append("second")
        signal.raise_signal(signal.SIGTERM)

    class _SignalOnResult(asyncio.Future[None]):
        def result(self) -> None:
            if not signals:
                signals.append("first")
                asyncio.get_running_loop().call_soon(net)
                signal.raise_signal(signal.SIGTERM)
            return super().result()

    async def campaign() -> None:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        assert task is not None
        tasks.append(task)
        child = _SignalOnResult(loop=loop)
        loop.call_soon(child.set_result, None)
        try:
            await asyncio.gather(child)
            unwound.append("finished")
        except BaseException as exc:
            unwound.append(type(exc).__name__)
            raise

    try:
        with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
            run_until_stopped(campaign())
        assert signals == ["first"] and not stuck, "a second signal was needed"
        assert unwound == ["CancelledError"]
        assert tasks[0].cancelled()
    finally:
        # Were the task stuck it would still be pending: collect it here, with asyncio's "Task
        # was destroyed but it is pending!" muted, rather than in whichever test runs next.
        if tasks and not tasks[0].done():
            tasks.clear()
            logger = logging.getLogger("asyncio")
            muted = logger.disabled
            logger.disabled = True
            try:
                gc.collect()
            finally:
                logger.disabled = muted


class _ClosingLoop(asyncio.SelectorEventLoop):
    """A loop that raises SIGTERM as it is closed, after its last turn."""

    closes = 0

    def close(self) -> None:
        super().close()
        _ClosingLoop.closes += 1
        if _ClosingLoop.closes == 1:
            signal.raise_signal(signal.SIGTERM)


@pytest.mark.parametrize("moment", ["after the task", "as the loop closes"])
def test_a_signal_as_the_last_loop_stops_is_not_lost(sigint: str, moment: str) -> None:
    """A SIGTERM that comes once the run's task is done, while the loop is still turning, or
    inside `loop.close()` after its last turn, where a callback queued on the loop never runs
    (why raising from a loop callback of our own was rejected): it is kept and raised once the
    loop is closed, so the campaign does not go on to its next step."""

    finished: list[bool] = []

    async def campaign() -> None:
        if moment == "after the task":
            # Queued now, it runs on the next turn, once this task has returned.
            asyncio.get_running_loop().call_soon(signal.raise_signal, signal.SIGTERM)
        finished.append(True)

    _ClosingLoop.closes = 0 if moment == "as the loop closes" else 1
    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        run_until_stopped(campaign(), loop_factory=_ClosingLoop)
    assert finished == [True]
    assert _ClosingLoop.closes == (1 if moment == "as the loop closes" else 2)


class _WatchedSelector(selectors.DefaultSelector):
    """Tells the test when the loop waits with nothing to do, and whether it was woken.

    A wait with no timeout polls, so a loop the handler never wakes is seen as such instead of
    blocking the test: once the handler has run (read before the poll), a poll that finds
    nothing ready means nothing will ever wake the loop. The poll's length decides nothing.
    """

    def __init__(self, waiting: threading.Event, handled: list[str]) -> None:
        super().__init__()
        self.waiting = waiting
        self.handled = handled
        self.unwoken = False

    def select(self, timeout: float | None = None) -> list[tuple[selectors.SelectorKey, int]]:
        if timeout is not None:
            return list(super().select(timeout))
        self.waiting.set()
        while True:
            handled = bool(self.handled)
            ready = list(super().select(0 if handled else 0.05))
            if ready:
                return ready
            if handled:
                self.unwoken = True
                raise KeyboardInterrupt  # the safety net: the test fails on `unwoken`


def test_a_signal_wakes_a_loop_that_is_waiting(sigint: str) -> None:
    """A SIGTERM that arrives while the loop waits in select() with nothing scheduled, as it
    does for a reply that has not come: the handler runs and returns, Python resumes the wait,
    and without a wake-up the cancellation would be seen only when something else woke it."""

    handled: list[str] = []
    waiting = threading.Event()
    selector = _WatchedSelector(waiting, handled)
    seen: list[str] = []

    def factory() -> asyncio.AbstractEventLoop:
        return asyncio.SelectorEventLoop(selector)

    async def campaign() -> None:
        try:
            await asyncio.get_running_loop().create_future()  # a reply that never comes
        except BaseException as exc:
            seen.append(type(exc).__name__)
            raise

    def send() -> None:
        assert waiting.wait(60), "the loop never waited"
        signal.pthread_kill(threading.main_thread().ident or 0, signal.SIGTERM)

    original = signal.getsignal(signal.SIGTERM)
    sender = threading.Thread(target=send)
    with _termination_as_interrupt():
        installed = signal.getsignal(signal.SIGTERM)
        assert callable(installed)

        def noted(signum: int, frame: Any) -> None:
            installed(signum, frame)
            handled.append("SIGTERM")

        signal.signal(signal.SIGTERM, noted)
        try:
            sender.start()
            with pytest.raises(KeyboardInterrupt):
                run_until_stopped(campaign(), loop_factory=factory)
        finally:
            signal.signal(signal.SIGTERM, installed)
            sender.join()
    assert signal.getsignal(signal.SIGTERM) is original
    assert not selector.unwoken, "the handler left the loop waiting"
    assert seen == ["CancelledError"]


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_a_signal_dropped_outside_a_loop_still_stops_the_next(sigint: str) -> None:
    """Outside a loop the signal raises where the main thread is, and Python drops what is
    raised inside a weakref callback. The campaign remembers it: its next loop does not start,
    so nothing is sent after it."""

    ran: list[bool] = []

    async def campaign() -> None:
        ran.append(True)

    with _termination_as_interrupt():
        _signal_inside_a_weakref_callback(signal.SIGTERM)  # dropped: Python only prints it
        with pytest.raises(KeyboardInterrupt):
            run_until_stopped(campaign())
    assert not ran
    run_until_stopped(campaign())  # a new campaign starts afresh
    assert ran == [True]


class _AsyncioLog(logging.Handler):
    """What asyncio logs during a test: a destroyed pending task, a never-retrieved exception."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage().splitlines()[0])


@pytest.fixture
def asyncio_log() -> Iterator[_AsyncioLog]:
    handler = _AsyncioLog()
    logger = logging.getLogger("asyncio")
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)


def _in_a_loop() -> str:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return "outside a loop"
    return "inside a loop"


@pytest.mark.usefixtures("ctrl_c")
def test_a_ctrl_c_in_the_campaigns_first_step_reaches_it(asyncio_log: _AsyncioLog) -> None:
    """The task used to be made before the loop started, so its first step ran before the
    coroutine `asyncio.Runner` runs had awaited it: a Ctrl-C there cancelled only that
    coroutine, the campaign was cancelled later, as the loop closed, and a second Ctrl-C during
    that stop left it pending, its `finally` (the runner's spend write) run when Python
    collected it, outside any loop (pre-merge audit). The second Ctrl-C is a callback queued
    during the stop, which awaits a future nothing sets: no clock decides it."""

    events: list[str] = []

    async def campaign() -> None:
        loop = asyncio.get_running_loop()
        try:
            signal.raise_signal(signal.SIGINT)  # in the first step, before any await
            await loop.create_future()
        except asyncio.CancelledError:
            events.append("cancelled")
            loop.call_soon(signal.raise_signal, signal.SIGINT)  # a second Ctrl-C, mid-stop
            await loop.create_future()  # a stop that takes a while
            raise
        finally:
            events.append(_in_a_loop())

    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        run_until_stopped(campaign())
    gc.collect()
    assert events == ["cancelled", "inside a loop"]
    assert asyncio_log.messages == []


def test_a_signal_before_the_task_exists_cancels_it_when_it_is_made(sigint: str) -> None:
    """Armed before the loop is made: a SIGTERM while `asyncio.Runner` makes it (here, from
    the loop factory) is noted, and the task is cancelled as it is made, before its first step,
    so the campaign never runs."""

    ran: list[bool] = []

    async def campaign() -> None:
        ran.append(True)

    def factory() -> asyncio.AbstractEventLoop:
        signal.raise_signal(signal.SIGTERM)
        return asyncio.SelectorEventLoop()

    with _termination_as_interrupt(), pytest.raises(KeyboardInterrupt):
        run_until_stopped(campaign(), loop_factory=factory)
    assert not ran


def test_a_cancellation_that_is_no_signal_stays_one() -> None:
    """A campaign cancelled by something other than a signal ends as under `asyncio.run`: with
    CancelledError, not KeyboardInterrupt."""

    async def campaign() -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await asyncio.sleep(0)

    with _termination_as_interrupt(), pytest.raises(asyncio.CancelledError):
        run_until_stopped(campaign())


def test_outside_the_main_thread_it_is_asyncio_run() -> None:
    results: list[int] = []

    async def campaign() -> int:
        return 7

    worker = threading.Thread(target=lambda: results.append(run_until_stopped(campaign())))
    worker.start()
    worker.join()
    assert results == [7]


def test_it_refuses_a_running_loop() -> None:
    async def campaign() -> None:
        return None

    async def inside() -> None:
        with pytest.raises(RuntimeError, match="running event loop"):
            run_until_stopped(campaign())

    asyncio.run(inside())
