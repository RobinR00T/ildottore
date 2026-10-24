"""The Il Dottore logo that ``dottore`` prints above its root help on an interactive terminal.

Two copies ship beside this module: ``banner.txt``, plain ASCII, and ``banner_ansi.txt``, the
same art with 24-bit ANSI colours (``38;2`` sequences). Stripped of its escape sequences the
colour copy is byte-identical to the plain one; ``tests/cli/test_banner.py`` holds that. Both
are read from the installed package (``package_path``), never from the checkout.

Shown only where a person is looking: :func:`show` says no off a terminal (a pipe, a file, a
script reading the help, the test runner) so what a script gets from ``dottore --help`` is what
it got before, and says plain on a terminal that has not declared 24-bit colour, since a
``38;2`` sequence on a 16-colour terminal prints as noise. The art is a caricature of the
author drawn as vector shapes and sampled to 56 columns, with the name under it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import cache
from typing import IO, Any

from ildottore.shared.package_data import package_path

__all__ = ["Env", "ansi", "env_for", "plain", "show", "write"]

#: The terminals that print a ``38;2`` sequence as the colour it names (no-color.org's
#: companion convention; ``COLORTERM`` is set by the terminal, not by the shell).
_TRUECOLOR = frozenset({"truecolor", "24bit"})


@dataclass(frozen=True)
class Env:
    """What :func:`show` reads from the process: the stream and three environment variables."""

    tty: bool
    """The stream the help goes to is a terminal."""
    no_color: str = ""
    """``NO_COLOR`` (no-color.org): present and not empty turns colour off."""
    term: str = ""
    """``TERM``: ``dumb`` turns colour off."""
    colorterm: str = ""
    """``COLORTERM``: colour only with ``truecolor`` or ``24bit``."""


def show(env: Env) -> tuple[bool, bool]:
    """Whether to print the logo, and whether in colour.

    Never off a terminal. Colour needs a terminal that declares 24-bit support, ``NO_COLOR``
    unset and ``TERM`` other than ``dumb``; anything else gets the plain copy.
    """

    if not env.tty:
        return False, False
    colour = env.no_color == "" and env.term != "dumb" and env.colorterm.lower() in _TRUECOLOR
    return True, colour


def env_for(stream: IO[Any] | None) -> Env:
    """The :class:`Env` of ``stream`` and the process environment.

    A stream with no ``isatty`` (a test runner's buffer), or one that is closed, is no terminal.
    """

    try:
        tty = bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError, OSError):
        tty = False
    return Env(
        tty=tty,
        no_color=os.environ.get("NO_COLOR", ""),
        term=os.environ.get("TERM", ""),
        colorterm=os.environ.get("COLORTERM", ""),
    )


@cache
def plain() -> str:
    """The logo as plain ASCII, every line newline-terminated."""

    return package_path("cli", "banner.txt").read_text(encoding="ascii")


@cache
def ansi() -> str:
    """The logo with its 24-bit colours, every line reset and newline-terminated."""

    return package_path("cli", "banner_ansi.txt").read_text(encoding="ascii")


def write(stream: IO[str], *, colour: bool) -> None:
    """Print the logo and a blank line to ``stream``, in colour or plain."""

    stream.write((ansi() if colour else plain()) + "\n")
