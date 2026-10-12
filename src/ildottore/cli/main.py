"""Entry-point module for the ``dottore`` / ``dott`` console scripts.

``pyproject.toml`` maps both ``[project.scripts]`` entries to ``ildottore.cli.main:main``
(contract §5.6). :func:`main` runs the assembled Typer :data:`app` from
:mod:`ildottore.cli.app` in click's non-standalone mode, so a usage error is printed by this
tool, through the redactor, and not by click: ``dottore run --runs "$KEY"`` printed
``Invalid value for '--runs': 'sk-ant-api03-...' is not a valid integer.`` with the key in
clear (CLI audit of 2026-10-11, M7; u12 A-82). :data:`app` is re-exported for the in-process
tests, for a caller embedding the command tree, and for a console script an older install
generated (``from ildottore.cli.main import app; sys.exit(app())``): calling it runs :func:`main`
too, so that script masks as well.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Sequence
from typing import NoReturn

import typer

from ildottore.cli.app import _masked, app
from ildottore.cli.exit_codes import ExitCode

__all__ = ["app", "main"]


def _click_classes(name: str) -> tuple[type[BaseException], ...]:
    """``name`` from click and from Typer's vendored copy of it, whichever are installed.

    Typer 0.26 raises from its own copy (``typer._click``), as ``app._usage_errors_exit_3``
    notes; catching only one of the two would let the other reach the terminal unmasked.
    """

    found: list[type[BaseException]] = []
    for module_name in ("click.exceptions", "typer._click.exceptions"):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        cls = getattr(module, name, None)
        if isinstance(cls, type) and issubclass(cls, BaseException) and cls not in found:
            found.append(cls)
    return tuple(found)


def _print_usage_error(exc: BaseException) -> None:
    """Click's usage block for ``exc``, its message through the redactor (u12 A-82).

    The usage line and the help hint are the command's own text; the message quotes what the
    operator typed (a value, an option name, a command name), so it goes through ``_masked``,
    the same mask and control-character rule as every other ``error:`` line of this tool.
    """

    ctx = getattr(exc, "ctx", None)
    if ctx is not None:
        print(ctx.get_usage(), file=sys.stderr)
        if ctx.command.get_help_option(ctx) is not None:
            print(f"Try '{ctx.command_path} {ctx.help_option_names[0]}' for help.", file=sys.stderr)
    print(f"error: {_masked(ValueError(_message(exc)))}", file=sys.stderr)


def _message(exc: BaseException) -> str:
    """A click exception's message, as click itself would print it."""

    format_message = getattr(exc, "format_message", None)
    return str(format_message()) if callable(format_message) else str(exc)


def main(argv: Sequence[str] | None = None, *, prog_name: str | None = None) -> NoReturn:
    """Run the ``dottore`` command tree and exit with its code.

    Non-standalone, so click hands its exceptions back here instead of printing them: a usage
    error (a bad value, an unknown option or command, an extra argument) is printed masked and
    exits 3 (``ExitCode.ERROR``, A-9); a bare ``dottore``, which prints the help, keeps its exit
    code; any other click error is printed masked with its own code; an abort exits 1, and
    Ctrl-C 130, as click's standalone mode does.
    """

    command = typer.main.get_command(app)
    try:
        code = command.main(
            args=list(argv) if argv is not None else None,
            prog_name=prog_name,
            standalone_mode=False,
        )
    except _click_classes("UsageError") as exc:
        # The help of a bare `dottore` (no_args_is_help) was printed when the error was built;
        # Typer prints nothing more for it either.
        if type(exc).__name__ != "NoArgsIsHelpError":
            _print_usage_error(exc)
        sys.exit(int(ExitCode.ERROR))
    except _click_classes("ClickException") as exc:
        print(f"error: {_masked(ValueError(_message(exc)))}", file=sys.stderr)
        sys.exit(int(getattr(exc, "exit_code", ExitCode.ERROR)))
    except _click_classes("Abort"):
        print("Aborted!", file=sys.stderr)
        sys.exit(1)
    # A command returns nothing or raises `typer.Exit(code)`, which non-standalone mode returns.
    sys.exit(code if isinstance(code, int) and not isinstance(code, bool) else 0)


if __name__ == "__main__":  # pragma: no cover
    main()
