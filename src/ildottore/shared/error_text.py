"""An exception as one line of text, never an empty reason (u12 A-82, CLI audit L8).

``f"{type(exc).__name__}: {exc}"`` is how the engine records an attempt's error and how a
campaign that stopped says why. An exception built with no message (``TimeoutError()``, which
``asyncio.timeout`` raises; an ``httpx`` timeout with an empty one) left that line ending in
``TimeoutError: `` with nothing after it, and ``--timeout 1e-300`` ended a run so.
"""

from __future__ import annotations

__all__ = ["error_text"]


def error_text(exc: BaseException) -> str:
    """``"<Class>: <message>"``, or ``"<Class> (no detail given)"`` when the message is blank."""

    name = type(exc).__name__
    message = str(exc)
    return f"{name}: {message}" if message.strip() else f"{name} (no detail given)"
