"""Event loops that SIGTERM and SIGHUP stop as asyncio stops one on Ctrl-C (u12 A-60).

On the first Ctrl-C, ``asyncio.run`` cancels the task it runs and raises KeyboardInterrupt only
once that task is done, so nothing is raised inside the loop's own callbacks. It does so only
when Ctrl-C has Python's default handler as the loop starts. A SIGTERM or SIGHUP that raised
instead (with Ctrl-C ignored, as for a job a script starts with ``&``) could land in one of
asyncio's callbacks, and one landing in gather's left the task awaiting it with nothing to wake
it: the run stopped sending, then waited as it closed until a second signal, and the stuck
part's spend was written only when Python collected the task (pre-merge audit of #94).

:func:`run_until_stopped` runs a coroutine as ``asyncio.run`` does, as a task of its own, and
:func:`stop_running_loop`, which ``execute_run``'s SIGTERM and SIGHUP handler calls, does to that
task what asyncio does on Ctrl-C: the first signal cancels it and wakes the loop, and
KeyboardInterrupt is raised once the loop is closed. A signal that comes after the task is done,
while the loop closes, is kept and raised then too, never queued on a loop that may not run
again. A second signal raises in place, as a second Ctrl-C does.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

__all__ = ["run_until_stopped", "stop_running_loop", "terminations_watched"]

_T = TypeVar("_T")


class _Run:
    """One :func:`run_until_stopped`: its loop, the task it drives, and whether it was stopped."""

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.task: asyncio.Task[Any] | None = None
        self.stopped = False

    def drive(self, loop: asyncio.AbstractEventLoop, task: asyncio.Task[Any]) -> None:
        self.loop = loop
        self.task = task
        # A signal that came before the task existed is acted on here; one that came after the
        # line above cancelled it already, and a second cancel of a task not yet started is
        # the same single CancelledError.
        if self.stopped:
            task.cancel()

    def stop(self) -> None:
        """Called from the signal handler: in the main thread, between two of its bytecodes."""

        if self.stopped:
            raise KeyboardInterrupt  # a second signal: the stop is not ending, as asyncio does
        self.stopped = True
        loop, task = self.loop, self.task
        # Before the task exists, after it is done, or once the loop is closed, there is
        # nothing to cancel: run_until_stopped raises when the loop is closed.
        if loop is None or task is None or task.done() or loop.is_closed():
            return
        task.cancel()
        # The handler runs while the loop may be blocked in select(), which Python resumes
        # after a handler that does not raise: wake it so the cancellation is seen now.
        loop.call_soon_threadsafe(_wake)


def _wake() -> None:
    return None


#: The loop :func:`run_until_stopped` is driving in the main thread, if any.
_running: _Run | None = None
#: Whether a SIGTERM or SIGHUP arrived inside :func:`terminations_watched`; ``None`` outside it.
_received: bool | None = None


@contextmanager
def terminations_watched() -> Iterator[None]:
    """Remember, for one campaign, that a SIGTERM or SIGHUP arrived.

    Outside a loop the handler still raises where the main thread is, and Python drops what is
    raised inside a weakref callback or ``__del__``. Remembered, such a signal still stops the
    campaign before its next loop starts, so no request is sent after it.
    """

    global _received
    previous, _received = _received, False
    try:
        yield
    finally:
        _received = previous


def stop_running_loop() -> bool:
    """Note a SIGTERM or SIGHUP, and stop the loop :func:`run_until_stopped` drives.

    ``True`` when a loop took the signal (a second one raises KeyboardInterrupt here); ``False``
    when none is running, and the caller handles the signal itself.
    """

    global _received
    if _received is not None:
        _received = True
    running = _running
    if running is None:
        return False
    running.stop()
    return True


async def _drive(run: _Run, main: Coroutine[Any, Any, _T]) -> _T:
    """The coroutine ``asyncio.Runner`` runs: it makes ``main`` a task and awaits it at once.

    Made here and not before the loop starts, the task's first step runs only once this
    coroutine awaits it, so a Ctrl-C (asyncio cancels this coroutine) always reaches it. Made
    before, its first step ran first, a Ctrl-C there cancelled only this coroutine, and a second
    one during the stop left the task pending, its spend written when Python collected it
    (pre-merge audit of the A-60 fix).
    """

    loop = asyncio.get_running_loop()
    task = loop.create_task(main)
    run.drive(loop, task)
    return await task


def run_until_stopped(
    main: Coroutine[Any, Any, _T],
    *,
    loop_factory: Callable[[], asyncio.AbstractEventLoop] | None = None,
) -> _T:
    """``asyncio.run(main)``, which a SIGTERM or SIGHUP stops as Ctrl-C does (u12 A-60).

    ``asyncio.Runner`` runs a coroutine that makes ``main`` a task and awaits it at once
    (:func:`_drive`): Ctrl-C keeps asyncio's own handler, which cancels that coroutine and
    through it the task, from its first step on. Raises KeyboardInterrupt
    once the loop is closed when a signal stopped the run, whether the task ended cancelled or
    had already finished, and before anything runs when a signal arrived since the campaign
    started (:func:`terminations_watched`). Outside the main thread no signal reaches it, and it
    is ``asyncio.run``. ``loop_factory`` is ``asyncio.Runner``'s.
    """

    global _running
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        main.close()
        raise RuntimeError("run_until_stopped() cannot be called from a running event loop")
    if threading.current_thread() is not threading.main_thread():
        with asyncio.Runner(loop_factory=loop_factory) as runner:
            return runner.run(main)
    run = _Run()
    outer = _running
    try:
        _running = run
        # Read after arming: a signal before it, or one at this instant, is not lost.
        if _received:
            run.stopped = True
        else:
            with asyncio.Runner(loop_factory=loop_factory) as runner:
                try:
                    result = runner.run(_drive(run, main))
                except asyncio.CancelledError:
                    if not run.stopped:
                        raise
    finally:
        _running = outer
        task = run.task
        if task is None:
            main.close()  # never made a task: stopped before, or cancelled before it was
        elif task.done() and not task.cancelled():
            # Retrieved here: a KeyboardInterrupt raised inside it (a second signal) propagates
            # past the coroutine that awaits it, and asyncio would log it as never retrieved.
            task.exception()
    # Here, and not in a callback on the loop: one that came as the last loop stopped would be
    # queued on a loop that never runs again, and lost.
    if run.stopped:
        raise KeyboardInterrupt
    return result
