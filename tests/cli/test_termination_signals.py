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
"""

from __future__ import annotations

import asyncio
import signal
import weakref
from collections.abc import Iterator

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
