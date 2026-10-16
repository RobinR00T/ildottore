"""Typer root - the ``dottore`` command surface (contract §1/§5).

The composition-root CLI. Every command is a thin wrapper that parses nmap-style
flags (``docs/09``) into the resolved option objects the ``run``/``fingerprint``/…
modules consume, then maps the outcome to a scriptable exit code (``exit_codes``).
No business logic lives here: commands wire and print (contract §2/§8).

Safety is not a flag you can turn off: ``run`` and ``fingerprint`` refuse to send a
single request without ``--scope``; ``--dry-run`` resolves and sends nothing. ``-A``
widens the battery, never the authorization gate (``docs/09 §5``).
"""

from __future__ import annotations

import contextlib
import errno
import json
import math
import os
import re
import sqlite3
import sys
import traceback
from collections.abc import Callable, Sequence
from functools import partial
from itertools import chain
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from typer.core import TyperGroup, TyperOption

from ildottore import __version__
from ildottore.adapters.base import AdapterError
from ildottore.cli import calibrate as calibrate_mod
from ildottore.cli import coverage as coverage_mod
from ildottore.cli import describe as describe_mod
from ildottore.cli import diff as diff_mod
from ildottore.cli import fingerprint as fingerprint_mod
from ildottore.cli import fleet as fleet_mod
from ildottore.cli import new_spec as new_spec_mod
from ildottore.cli import registry as registry_mod
from ildottore.cli import render_media as render_media_mod
from ildottore.cli import replay as replay_mod
from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.flags import DEFAULT_TEMPLATE
from ildottore.cli.lint import run_lint
from ildottore.cli.run import RunOptions, ScopeRequiredError
from ildottore.policy.errors import PolicyError
from ildottore.redactor import (
    CREDENTIAL_MASK,
    Redactor,
    holds_known_secret_part,
    known_secret_parts,
    log_safe_json,
    visible_controls,
)
from ildottore.reporting import report_schema
from ildottore.shared.judging_rules import JUDGING_RULES_VERSION
from ildottore.shared.schema_export import export_schemas
from ildottore.store.replay import TamperError

#: Where a command records how verbose it was asked to be, for the guard below (``ctx.meta`` is
#: shared by a command's context and its parents').
_VERBOSE_KEY = "ildottore.verbose"


def _typer_error(name: str) -> type[Exception]:
    """The error class ``name`` (``ClickException``, ``UsageError``) Typer raises and catches.

    Found from public Typer names, whatever module the copy of click Typer raises from lives in:
    the ancestry of ``typer.BadParameter``. Looked up in ``typer._click.exceptions`` by name, an
    ``Abort`` that moved to ``typer.exceptions`` in Typer 0.27 resolved to nothing and the guard
    quietly stopped mapping it (CI of #114). A class that cannot be found fails the import, so a
    future change of layout stops the CLI rather than changing its exit codes.
    """

    for cls in typer.BadParameter.__mro__:
        if cls.__name__ == name and issubclass(cls, Exception):
            return cls
    raise ImportError(f"typer.BadParameter derives from no {name}: an unknown Typer layout")


#: An exit asked for: let through with its code. `typer.Exit` is the class Typer catches.
_EXITS: tuple[type[BaseException], ...] = (typer.Exit,)
#: The library's errors (a usage error, a file it could not open): let through, as exit 3
#: (`_click_errors_exit_3` sets the class's code; `ClickException`'s default was 1).
_CLICK_ERRORS: tuple[type[BaseException], ...] = (_typer_error("ClickException"),)
#: The library's "Aborted!", exit 1 by default. `typer.Abort` is the class Typer catches.
_ABORTS: tuple[type[BaseException], ...] = (typer.Abort,)
_PASS_THROUGH: tuple[type[BaseException], ...] = (*_EXITS, *_CLICK_ERRORS)


def _installed_click_kind(exc: BaseException) -> str | None:
    """``"exit"``, ``"abort"`` or ``"error"`` for an exception of the separately installed click.

    Typer does not catch that copy's classes, so a plugin's ``click.ClickException`` exited 1
    with a traceback (round-2 audit of f51a7d07, LOW 2). Read from ``sys.modules``, so click is
    never imported for it, and ``None`` when it is not loaded or is the copy Typer raises from.
    """

    module = sys.modules.get("click.exceptions")
    if module is None or getattr(module, "ClickException", None) in _CLICK_ERRORS:
        return None  # not loaded, or it is the copy Typer raises from (a Typer that vendors none)
    for kind, name in (("exit", "Exit"), ("abort", "Abort"), ("error", "ClickException")):
        cls = getattr(module, name, None)
        if isinstance(cls, type) and isinstance(exc, cls):
            return kind
    return None


class OperationalErrorGroup(TyperGroup):
    """The root command group: an exception no command handled exits 3, never 1 (u12 A-9).

    Exit 1 means "findings below --fail-on", so a CI step that lets 1 through read a crash as an
    almost clean scan; that is how a locked run store, a bare sqlite3 error and every class a
    handler tuple forgot used to end. Here it is one line on stderr through the same masking as
    every other error, and its traceback (masked line by line) only under ``-v``. Ctrl-C is not
    an exception in this sense and keeps its 130.

    Built to be subclassed: it keeps no state, and a root group that does more (masking a usage
    error where it is raised) overrides ``main`` or ``invoke`` and calls ``super()``, which keeps
    this closure (``tests/cli/test_guard_subclass.py``).
    """

    def main(self, *args: Any, **kwargs: Any) -> Any:
        """The library's own handling around the root context, with its two exits 1 made 3.

        Help (``--help``, or no command at all) is printed while the root context is being made,
        before :meth:`invoke` and its guard: a broken pipe there, and an ``Aborted!`` raised
        there, were turned into exit 1 by the library itself.
        """

        try:
            return super().main(*args, **kwargs)
        except SystemExit as exc:
            context = exc.__context__
            if exc.code != 1 or context is None:
                raise
            if isinstance(context, OSError) and context.errno == errno.EPIPE:
                _say_broken_pipe()
            elif not isinstance(context, _ABORTS):
                raise
            raise SystemExit(int(ExitCode.ERROR)) from exc

    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except _PASS_THROUGH:
            raise
        except _ABORTS as exc:
            _echo_err("error: aborted")
            raise typer.Exit(int(ExitCode.ERROR)) from exc
        except SystemExit as exc:
            # A stray exit: rich's answer to a broken pipe is SystemExit(1) (pre-merge audit of
            # e6a1ab9b, MEDIUM 2 and LOW 5). 1 and 2 are the findings' codes here, and a text
            # code exits 1, so those are exit 3; 0 and a code from 3 up keep their meaning.
            if exc.code is None or (isinstance(exc.code, int) and exc.code not in (1, 2)):
                raise
            context = exc.__context__
            if isinstance(context, OSError) and context.errno == errno.EPIPE:
                _say_broken_pipe()
            else:
                _echo_err(
                    f"error: unexpected exit with status {exc.code!r} (an internal error, not a "
                    "scan result; rerun as `dottore -v ...` for the traceback)"
                )
            raise typer.Exit(int(ExitCode.ERROR)) from exc
        except Exception as exc:
            kind = _installed_click_kind(exc)
            if kind == "exit":
                # As a stray SystemExit: 1 and 2 are the findings' codes here.
                code = getattr(exc, "exit_code", 0)
                if code not in (1, 2):
                    raise typer.Exit(code) from exc
                _echo_err(
                    f"error: unexpected exit with status {code!r} (an internal error, not a "
                    "scan result; rerun as `dottore -v ...` for the traceback)"
                )
            elif kind == "abort":
                _echo_err("error: aborted")
            elif kind == "error":
                format_message = getattr(exc, "format_message", None)
                message = format_message() if callable(format_message) else str(exc)
                _echo_err(f"error: {_masked(RuntimeError(message))}")
            else:
                _report_unexpected(exc, verbose=int(ctx.meta.get(_VERBOSE_KEY, 0) or 0))
            raise typer.Exit(int(ExitCode.ERROR)) from exc


def _report_unexpected(exc: Exception, *, verbose: int) -> None:
    """Say on stderr what stopped the command, in one line (and its traceback under ``-v``)."""

    if isinstance(exc, OSError) and exc.errno == errno.EPIPE:
        _say_broken_pipe()
        return
    try:
        said = _masked(exc)
    except Exception:  # a message that cannot even be read: its class is what is left
        said = "<unprintable message>"
    _echo_err(
        f"error: unexpected {type(exc).__name__}: {said} (an internal error, not a scan "
        "result; rerun as `dottore -v ...` for the traceback)"
    )
    if verbose:
        for line in "".join(traceback.format_exception(exc)).splitlines():
            try:
                _echo_err(_masked(RuntimeError(line)))
            except Exception:
                _echo_err("<unprintable traceback line>")


#: What a command whose reader went away says, once, if stderr still has a reader.
_BROKEN_PIPE = "error: the output stream closed before the command finished (broken pipe)"


def _point_at_null(stream: Any) -> bool:
    """Point ``stream``'s file descriptor at the null device; False when it has none.

    The closed pipe is then never written again: the buffered text the next flush (the close
    callback below, the interpreter's own at exit) writes goes nowhere, so neither raises a
    second ``BrokenPipeError``, the one the command-line library turned into exit 1. What
    Python's documentation advises for a closed stdout (Note on SIGPIPE, ``signal`` module).
    """

    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return False
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null, descriptor)
    finally:
        os.close(null)
    return True


class _QuietStream:
    """A stream whose flush into a closed pipe is dropped; everything else is the stream's."""

    def __init__(self, wrapped: Any) -> None:
        self._wrapped = wrapped

    def flush(self) -> None:
        try:
            self._wrapped.flush()
        except OSError as exc:
            if exc.errno != errno.EPIPE:
                raise

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


def _say_broken_pipe() -> None:
    """Silence the closed stdout and say why on stderr (silenced too when it is closed as well)."""

    if not _point_at_null(sys.stdout):
        # A stream with no descriptor (a test runner's buffer): quiet it here, as the
        # command-line library's own wrapper does (no private module of it is imported for that).
        sys.stdout = _QuietStream(sys.stdout)
    try:
        typer.echo(_BROKEN_PIPE, err=True)
    except OSError:
        _point_at_null(sys.stderr)


def _echo_err(text: str) -> None:
    # stderr may be gone too: the exit code is then all that is left to say it.
    with contextlib.suppress(OSError):
        typer.echo(text, err=True)


def _counted() -> Any:
    """A counted flag's type (``-v``, ``-vv``), named so the help shows no value after it.

    The help printed ``-v, --verbose  INTEGER  [default: 0]``, as if it took a number (pre-merge
    audit of e6a1ab9b, LOW 8); the rich help leaves out a type named ``boolean``. The base is the
    type Typer gives a counted option itself, read off one, not imported from a private module.
    """

    base = type(TyperOption(param_decls=["-v"], count=True).type)
    counted = type("_Counted", (base,), {"name": "boolean", "__doc__": _counted.__doc__})
    return counted(min=0)


def _message(exc: BaseException) -> str:
    """A click exception's message, as click itself would print it."""

    format_message = getattr(exc, "format_message", None)
    return str(format_message()) if callable(format_message) else str(exc)


def _mask_in_place(exc: BaseException) -> None:
    """Make ``exc`` say its message through the CLI's mask, whoever prints it (u12 A-82).

    A usage error quotes what the operator typed (a value, an option or a command name), and
    click, Typer's standalone mode or a parent ``click.Group`` print it with
    ``format_message()``. The masked text replaces that method and ``message`` on the instance,
    so every printer shows it masked. A bare ``dottore``'s help (``NoArgsIsHelpError``) is left
    as it is: it holds no value.
    """

    if type(exc).__name__ == "NoArgsIsHelpError" or getattr(exc, "_dottore_masked", False):
        return
    shown = _masked(ValueError(_message(exc)))
    setattr(exc, "format_message", lambda: shown)  # noqa: B010 - an instance's method replaced
    setattr(exc, "message", shown)  # noqa: B010
    setattr(exc, "_dottore_masked", True)  # noqa: B010
    # The conversion error click raised it from (`invalid literal for int(): '<key>'`) is chained
    # to it: a group from the installed click does not catch Typer's copy's class and prints the
    # traceback, chain included (round-3 audit of A-82). Neither the cause nor the context goes.
    exc.__cause__ = None
    exc.__suppress_context__ = True


def _print_usage_error(exc: BaseException) -> None:
    """Click's usage block for ``exc``, its message through the redactor (u12 A-82).

    The usage line and the help hint are the command's own text; the message quotes what the
    operator typed, so it goes through the mask, as every other ``error:`` line of this tool.
    """

    _mask_in_place(exc)
    ctx = getattr(exc, "ctx", None)
    if ctx is not None:
        print(ctx.get_usage(), file=sys.stderr)
        if ctx.command.get_help_option(ctx) is not None:
            print(f"Try '{ctx.command_path} {ctx.help_option_names[0]}' for help.", file=sys.stderr)
    print(f"error: {_message(exc)}", file=sys.stderr)


#: A usage error: printed with the command's usage block, its message masked.
_USAGE_ERRORS: tuple[type[BaseException], ...] = (_typer_error("UsageError"),)


def run_masked(call: Callable[[], Any]) -> NoReturn:
    """Run ``call`` (the command tree in click's non-standalone mode) and exit with its code.

    A usage error (a bad value, an unknown option or command, an extra argument) is printed
    masked and exits 3 (``ExitCode.ERROR``, A-9); a bare ``dottore``, which prints the help,
    keeps its exit code. Any other error of the library (``FileError`` included) is printed
    masked and exits 3, and an abort says ``error: aborted`` and exits 3, as the root group's
    guard says one raised in a command (A-9's closure, u12 A-80). Ctrl-C keeps 130, which a
    command returns as its code. The classes are Typer's public ones (``_typer_error``).
    """

    try:
        code = call()
    except _USAGE_ERRORS as exc:
        # The help of a bare `dottore` (no_args_is_help) was printed when the error was built;
        # Typer prints nothing more for it either.
        if type(exc).__name__ != "NoArgsIsHelpError":
            _print_usage_error(exc)
        sys.exit(int(ExitCode.ERROR))
    except _CLICK_ERRORS as exc:
        _mask_in_place(exc)
        _echo_err(f"error: {_message(exc)}")
        sys.exit(int(ExitCode.ERROR))
    except _ABORTS:
        _echo_err("error: aborted")
        sys.exit(int(ExitCode.ERROR))
    # A command returns nothing or raises `typer.Exit(code)`, which non-standalone mode returns.
    sys.exit(code if isinstance(code, int) and not isinstance(code, bool) else 0)


class _MaskedGroup(OperationalErrorGroup):
    """The root command, whose usage errors go through the CLI's mask on every path (u12 A-82).

    Parsing the root's options (``make_context``) and resolving and parsing a sub-command
    (``invoke``) is where click raises a usage error, so both mask it in place before it leaves:
    a parent ``click.Group`` that holds this one, ``python -m typer``, and a caller that takes the
    command (``typer.main.get_command(app)()``) print it masked. Run standalone (``main``), as the
    console scripts, ``app()`` and a test runner do, it prints the plain usage block with an
    ``error:`` line (:func:`run_masked`). The console script used to point at the Typer app, and
    an install made then keeps calling it; with the masking only in ``cli.main.main``, three
    paths printed the key (pre-merge audits of A-82, MEDIUM 1 and round 2, LOW 1).

    It is the exit-code guard (:class:`OperationalErrorGroup`, u12 A-80) with the mask around it:
    each override calls ``super()``, so an unexpected exception still exits 3 in one masked line,
    and the library's own exits 1 around the root context (a broken pipe while printing help,
    ``Aborted!``) are still made 3.
    """

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: Any = None,
        **extra: Any,
    ) -> Any:
        try:
            return super().make_context(info_name, args, parent=parent, **extra)
        except _CLICK_ERRORS as exc:
            _mask_in_place(exc)
            raise

    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)  # the guard of OperationalErrorGroup runs inside
        except _CLICK_ERRORS as exc:
            _mask_in_place(exc)
            raise

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: Any,
    ) -> Any:
        parent_main = super().main

        def call() -> Any:
            return parent_main(
                args,
                prog_name,
                complete_var,
                standalone_mode=False,
                windows_expand_args=windows_expand_args,
                **extra,
            )

        if not standalone_mode:
            return call()
        run_masked(call)


app = typer.Typer(
    name="dottore",
    help="Il Dottore, nmap-for-AI: a spec-driven security scanner for LLMs and AI apps.",
    no_args_is_help=True,
    add_completion=False,
    cls=_MaskedGroup,
    # A traceback that reaches Typer's own hook (`app()` installs it) prints no locals: one of
    # them can be a resolved credential.
    pretty_exceptions_show_locals=False,
)

registry_app = typer.Typer(help="Inspect the attack-spec registry (read-only).")
schema_app = typer.Typer(help="Export the generated JSON schemas.")
app.add_typer(registry_app, name="registry")
app.add_typer(schema_app, name="schema")


# A usage error (an unknown option, a bad value) exits 3, the operational-error code. Click's
# default is 2, which in this tool means "findings at or above --fail-on", so a CI step with a
# typo in its flags reported a finding the scan never made (audit 2026-10-03, R17 / A-9). Any
# other error of the library (`ClickException`, `FileError`) exited 1, which means findings
# below --fail-on (pre-merge audit of e6a1ab9b, LOW 5). The classes set are those Typer raises
# and catches, whichever copy of click they come from.
def _click_errors_exit_3() -> None:
    # The classes Typer raises, found as the guard finds them (`_typer_error`), never through a
    # private module path; a separately installed click is not imported here, its exceptions are
    # mapped where one arrives (`_installed_click_kind`).
    for name in ("UsageError", "ClickException"):
        _typer_error(name).exit_code = int(ExitCode.ERROR)  # type: ignore[attr-defined]


_click_errors_exit_3()


def _version_callback(value: bool) -> None:
    if value:
        # The rules that judge a stored attempt, which a resume is bound to (u12 A-81): the
        # package version said 0.1.0 across five changes to them.
        typer.echo(f"dottore {__version__} (judging rules {JUDGING_RULES_VERSION})")
        raise typer.Exit(ExitCode.CLEAN)


def _streams_escape_what_they_cannot_encode(ctx: typer.Context) -> None:
    """Write a character the terminal's encoding lacks as its escape instead of failing.

    Control characters are written out as control pictures (``visible_controls``), which a
    cp1252 or ASCII stream cannot encode: `registry ls` exited 1 and printed nothing on such a
    stream when a spec's name held a newline (pre-commit audit of the control-characters
    block). stderr already does this by default; stdout raised. Each stream gets its own
    setting back when the command ends, for a caller that runs the app in its own process.
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        errors = getattr(stream, "errors", None)
        if reconfigure is not None and errors is not None:
            reconfigure(errors="backslashreplace")
            ctx.call_on_close(partial(_restore_stream, reconfigure, errors))


def _restore_stream(reconfigure: Any, errors: str) -> None:
    """Give a stream its error handler back; a reader that went away is exit 3 (u12 A-80).

    Reconfiguring flushes, and a command whose output was still buffered met the closed pipe
    here, after the command had returned: the command-line library turned that
    ``BrokenPipeError`` into exit 1, which here means findings below ``--fail-on``, and a live
    scan with findings piped into a closed reader sent its requests and exited 1 with nothing
    said (pre-merge audit of ``e6a1ab9b``, MEDIUM 2).
    """

    try:
        reconfigure(errors=errors)
    except OSError as exc:
        if exc.errno != errno.EPIPE:
            raise
        _say_broken_pipe()
        raise typer.Exit(int(ExitCode.ERROR)) from exc


@app.callback()
def _root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option(
            "-v",
            "--verbose",
            count=True,
            click_type=_counted(),
            show_default=False,
            help="Print the traceback of an internal error (exit 3), for any command. "
            "run -v also prints the resolved plan.",
        ),
    ] = 0,
) -> None:
    """Il Dottore root - see ``dottore <command> --help`` for each command."""

    ctx.meta[_VERBOSE_KEY] = verbose
    _streams_escape_what_they_cannot_encode(ctx)


def _spec_paths(spec: list[Path] | None) -> list[Path]:
    """``--spec-path`` as given, else the default the reading commands share (u12 A-80).

    A fallback to the battery beside the package is said on stderr: in a pack's own repository
    (``pack.yaml`` at its root, no ``specs/``) a command read the built-in battery without a
    word (pre-merge audit of e6a1ab9b, MEDIUM 3). ``lint`` does not fall back at all.
    """

    if spec:
        return list(spec)
    paths = wiring.default_spec_paths()
    if paths == [wiring.PACKAGED_SPEC_PATH]:
        _echo_err(
            "note: there is no specs/ directory here, so this reads the battery beside the "
            f"installed package: {visible_controls(str(wiring.PACKAGED_SPEC_PATH))} (pass "
            "--spec-path to read another)"
        )
    return paths


# --- run -------------------------------------------------------------------------


# An evidence file name (``<sha256>.json``) is the tool's own pointer, and the one thing a tamper
# refusal needs to show; the entropy rule would otherwise mask it.
_ARTIFACT_NAME = r"[0-9a-f]{64}\.json"
_SHA256 = re.compile(r"[0-9a-f]{64}")
# An absolute filesystem path in an error message (`/` not preceded by a word character, `:`,
# `/`, `]`, `@` or the `»` that closes a mask, so a URL's path is not one, after an IPv6 host,
# credentials or a masked host included).
_ABS_PATH = re.compile(r"(?<![\w:/\]@»\ue000])/[^\s'\"()\[\],;]+")
#: Longer tokens are not checked (PATH_MAX): each parent costs a filesystem lookup.
_MAX_PATH_LEN = 4096
# Where a WHOLE path can start (A-38): an absolute one as above, and not right after `+`, `=` or
# `-`, which the entropy rule joins into a token, with a name after the `/`; a relative one as
# a word, after a space, a quote, a bracket, a comma or a semicolon, not starting with `/` or `«`.
_WHOLE_ABS_START = re.compile(r"(?<![\w:/\]@»+=\ue000-])/(?=[^\s'\"()\[\],;/])")
_RELATIVE_WORD = re.compile(r"(?<![^\s'\"(\[,;`])[^\s'\"()\[\],;`/«][^\s'\"()\[\],;`]*")
# What the entropy rule could mask: a word without such a run is not worth a lookup.
_ENTROPY_RUN = re.compile(r"[A-Za-z0-9+/_=-]{16,}")
# A character the entropy rule joins into a token, `/` included. A whole path is never followed
# by one, and never starts right after one, so the rest of the message is read token by token
# exactly as without it.
_TOKEN_CHAR = re.compile(r"[A-Za-z0-9+/_=-]")
# Where one name ends for certain: a name holds no `/`, and an error line breaks at a newline.
_NAME_STOP = re.compile(r"[/\n\r\x00]")
#: No name is longer (NAME_MAX), so one start tries at most that many candidates, and prose
#: after a `/` cannot use up the lookups the other paths of the message need.
_MAX_NAME_LEN = 255
#: What the whole-path walk may cost one message: filesystem lookups, and checks (a lookup or a
#: cached answer). Past either it keeps nothing more, which costs readability only.
_MAX_LOOKUPS = 1024
_MAX_CHECKS = 65_536


class _Lookups:
    """The whole-path walk's filesystem checks for one message, each path once: a new lookup past
    ``_MAX_LOOKUPS``, and any check past ``_MAX_CHECKS``, answers False and sets ``spent``."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, bool], bool] = {}
        self._checks = 0
        self.spent = False

    def __call__(self, path: str, *, directory: bool) -> bool:
        self._checks += 1
        key = (path, directory)
        over = len(self._seen) >= _MAX_LOOKUPS or self._checks > _MAX_CHECKS
        if over and (key not in self._seen or self._checks > _MAX_CHECKS):
            self.spent = True
            return False
        if key not in self._seen:
            self._seen[key] = os.path.isdir(path) if directory else os.path.exists(path)
        return self._seen[key]


def _existing_prefixes(text: str) -> list[str]:
    """The part of each absolute path in ``text`` that exists on this machine.

    Kept readable: the redactor masked any high-entropy segment, so a macOS temp directory or a
    CI runner's workspace read `«REDACTED:high_entropy»` in "two formats would write the same
    file" and "is not a directory" errors. What exists on disk is the operator's own tree, not
    a value they typed; the rest of the path still goes through the redactor.
    """

    # Main's rule, main's calls, so main's answer on every Python version and main's cost or
    # less. `Path.exists` raises on 3.11 and 3.12 for a name too long or a directory that cannot
    # be read, and main kept nothing for that token: `os.path.exists` went on to the parent and
    # printed a key main masked (delta audit of A-38). No cap: stopped early it kept nothing
    # where main kept a directory, and the rest of the token, judged whole, printed a value main
    # masked (audit of the cap). No cache across tokens: holding every path asked took 1.3 GiB
    # for a 1 MiB message where main took 21 MiB (final audit). What it saves: a token written
    # again is not walked again, and the parents are built as they are reached.
    prefixes: list[str] = []
    walked: set[str] = set()
    for match in _ABS_PATH.finditer(text):
        token = match.group(0)
        if len(token) > _MAX_PATH_LEN or token in walked:
            continue
        walked.add(token)
        candidate = Path(token)
        for path in chain((candidate,), candidate.parents):
            shown = str(path)
            if shown == "/" or not token.startswith(shown):
                break
            try:
                exists = path.exists()
            except OSError:
                break
            if exists:
                prefixes.append(shown)
                break
    return prefixes


def _whole_path_end(text: str, start: int, limit: int, lookup: _Lookups) -> tuple[int, int]:
    """Where an existing path written whole from ``text[start]`` ends, and how far the walk read.

    The end is ``start`` when there is none. Directory by directory from its first name, so a
    directory holding a space or a bracket is read whole; the last name is the longest that
    exists and is followed by no character the entropy rule joins into a token, so
    `{path}: ...` and `{path}.` keep the path and the `:` or `.` is the message's.
    """

    head = start + 1 if text.startswith("/", start) else start
    while True:
        bound = min(limit, head + _MAX_NAME_LEN)
        stop = _NAME_STOP.search(text, head, bound)
        name_end = stop.start() if stop else bound
        if stop and text[name_end] == "/" and lookup(text[start:name_end], directory=True):
            head = name_end + 1
            continue
        for end in range(name_end, head, -1):
            if end < len(text) and _TOKEN_CHAR.match(text, end):
                continue
            if lookup(text[start:end], directory=False):
                return end, end
        return start, name_end


def _whole_path_spans(text: str, lookup: _Lookups) -> list[tuple[int, int]]:
    """Where ``text`` writes, whole, a path that exists on this machine (A-38).

    `_existing_prefixes` reads an absolute path up to the first space, quote or bracket and
    keeps the part of it that exists, so a report named after a commit SHA lost its name when
    the message wrote it before a colon, when it was relative, or when a directory on the way
    held a space or one of ``()[],;'"`` (audits of PR #61). A whole path starts and ends between
    characters the entropy rule does not join into a token, so keeping it changes how nothing
    else in the message is read: each attempt to keep more than that (the existing directories
    of a path that does not exist, the name an `OSError` quotes) printed a key that main masked
    (pre-commit, delta and pre-merge audits). A relative path is one word, from the working
    directory.
    """

    starts = [(m.start(), len(text)) for m in _WHOLE_ABS_START.finditer(text)]
    starts += [
        (m.start(), m.end()) for m in _RELATIVE_WORD.finditer(text) if _ENTROPY_RUN.search(m[0])
    ]
    spans: list[tuple[int, int]] = []
    read = 0
    for start, limit in sorted(starts):
        # Not from inside what a walk already read: `/./././...//` kept nothing and was walked
        # again from each of its `/`, at a cost that grew with the square of its length.
        if start < read:
            continue
        end, read = _whole_path_end(text, start, limit, lookup)
        if lookup.spent:
            break
        if end > start:
            spans.append((start, end))
    return spans


def _entropy_masked(entropy: Redactor, part: str) -> str:
    """``part`` through the entropy rule, the `/` in front of a masked name kept.

    The mask took the separator with it, so ``<dir>/<masked name>`` printed as
    ``<dir>«REDACTED...»``, a sibling of the directory rather than a file in it.
    """

    shown = entropy.redact_text(part)
    return "/" + shown if part.startswith("/") and not shown.startswith("/") else shown


#: The allowlist's own loopback hosts (``policy.allowlist``: plain http goes to these only), in a
#: URL's authority: kept readable, as they are no one's address (u12 A-82, CLI audit L8). The
#: IPv4 rule masked ``http://127.0.0.1:9/...`` in every allowlist refusal.
_LOOPBACK_IN_URL = re.compile(r"(?<=://)127\.0\.0\.1(?=[:/'\"\s)\]]|$)")
#: Stands in for a kept loopback host while the rules run: no rule reads a private-use character,
#: and the path rules above read a `/` after it as a URL's path, as after a mask's `»`.
_LOOPBACK_MARK = "\ue000"


def _os_error_text(exc: BaseException) -> str:
    """``str(exc)``, a file name too long to open described by its length (u12 A-82).

    ``[Errno 63] File name too long: '<5,000 digits>'`` printed the name, which the redactor
    then masked as a phone number: the length is what the operator needs.
    """

    if isinstance(exc, OSError) and exc.errno == errno.ENAMETOOLONG and exc.filename:
        # Neither "read" nor "write": the same error comes from `-t` and from `-oJ` (round-2
        # audit of A-82, LOW 5).
        return (
            f"[Errno {exc.errno}] {exc.strerror}: a name of {len(str(exc.filename)):,} characters"
        )
    return str(exc)


def _masked(exc: BaseException) -> str:
    """An error's text through the redactor before it reaches the terminal.

    Errors quote what the operator wrote, an endpoint URL with its password included: the
    scope refusal printed ``http://alice:<password>@host/...`` to stderr while reports, evidence
    and the run store all masked it (review of PR #32, SEC-02 left open on this path).

    They also quote what a third party wrote, a spec file name of a pack included, and printed
    its control characters raw: a file named ``x\\n::error ...`` made a line GitHub Actions
    reads as a workflow command (pre-merge audit of PR #49). A registered credential split by
    control characters is masked whole by the redactor (u01 A-32), and the control characters
    are written out last, after every mask (``visible_controls``).
    """

    # Every rule but the entropy fallback runs on the whole text first, labels and context
    # included; the entropy fallback, which cannot tell a sha256 or a random directory name from
    # a key, runs only on what is not kept below. Keeping a path raw skipped the email and
    # key-shape rules too (an existing `GoogleDrive-<email>` directory printed the address).
    # The late patterns (the key formats, the JWT and the UUID, u01 A-78) run last, on what the
    # entropy pass shows of each stretch it reads, as they run last in the redactor: run by
    # `plain`, before the entropy pass, a key glued to a word took less than the pass took of its
    # token (`x_<key>` printed `x_`); and neither redactor here has them, so each keeps as a
    # mask only the types it had (one written in the error, `«REDACTED:jwt:...»` in a labelled
    # value, is read as text by `entropy`, which then masks the value, as it did). What is kept
    # (a digest, an existing path) is kept from them too: run over the whole message, they
    # masked a UUID directory of an existing evidence root (pre-merge audit of A-78, L5).
    # Without the late patterns, `plain` masks the number rules' numbers inside a UUID as
    # before A-78, so the paths it leaves to keep are the ones it left before.
    plain = Redactor(entropy_threshold=math.inf, late=False)
    entropy = Redactor(patterns=[], late=False)
    late = Redactor(patterns=[], entropy_threshold=math.inf)
    # A bare digest stays readable only when the error itself carries it as one this tool
    # computed (`digests` on ScopeChecksumError and TamperError): the redactor cannot tell a
    # sha256 from a 64-hex key, so keeping every bare 64-hex printed a raw key pasted as an
    # `auth_ref` in clear (third audit of the residuals). The rest is redacted in context,
    # labels included. The sha256 filter also keeps a malformed value out of the pattern.
    carried = [
        d for d in getattr(exc, "digests", ()) if isinstance(d, str) and _SHA256.fullmatch(d)
    ]
    # A spec file a load refusal names (`spec_files` on SpecLoadError) is a relative path to an
    # entry under a spec root, a name whoever wrote the tree chose (the operator or a pack's
    # author), not a value of this run. It is kept only with no token character of the entropy
    # rule (`[\w+/=-]`) on either side: keeping the tail of a longer token would leave its head
    # on its own, short enough to pass the rule's length floor in clear.
    # A fleet refusal's parameter names (`kept_names` on FleetFileError) are kept the same way:
    # a name is not a secret, and `X-Amz-Credential` read as high entropy (u12 A-82).
    readable = [*getattr(exc, "spec_files", ()), *getattr(exc, "kept_names", ())]
    names = sorted(
        {re.escape(n) for n in readable if isinstance(n, str) and n},
        key=len,
        reverse=True,
    )
    # Every rule but the entropy fallback, URL passwords included, on the whole text, so a 64-hex
    # password is never kept as a digest. The URL rule ran on its own first, on the raw text, and
    # cut a registered credential holding an `@` or a `:` at it, so the redactor no longer found
    # it: `https://ops:P@ssw0rd!x@db.internal/v1` with `P@ssw0rd!x` registered printed
    # `ssw0rd!` (pre-merge audit of #96). The redactor's own URL rule runs after the registered
    # credentials are set aside.
    raw = _os_error_text(exc)
    parts = known_secret_parts()
    # The loopback host stands aside while the rules run, unless a registered credential holds
    # it (the rule below for a kept token), and comes back after the last of them.
    loopback = (
        "127.0.0.1"
        if _LOOPBACK_MARK not in raw and not holds_known_secret_part("127.0.0.1", parts)
        else None
    )
    if loopback is not None:
        raw = _LOOPBACK_IN_URL.sub(_LOOPBACK_MARK, raw)
    text = plain.redact_text(raw)
    paths = sorted({re.escape(p) for p in _existing_prefixes(text)}, key=len, reverse=True)
    keep = re.compile(
        r"(\b(?:"
        + "|".join([_ARTIFACT_NAME, *carried])
        + r")\b"
        + "".join(f"|{p}(?![^/\\s'\"()\\[\\],;])" for p in paths)
        + "".join(f"|(?<![\\w+/=-]){n}(?![\\w+/=-])" for n in names)
        + ")"
    )
    # A kept token holding 8 consecutive characters of a registered credential is masked:
    # `sk-<64 hex>` and `<64 hex>-v2` contain one (re-audit of the digest change), and so does
    # `<dir>/report-<part of the key>.json`, which the old test, "inside the key or holding it
    # whole", missed (delta audit of A-38). Outright, because the entropy rule passes an
    # id-shaped spec file name and a low-entropy hex run. Judged on its own when main's rule
    # kept it; a whole path holding one is not kept at all, so that stretch of the message is
    # read exactly as without A-38 (kept and judged whole, a long path diluted the part). What is
    # kept is decided where the pattern matched, in context: re-matching each piece of a split
    # on its own let a piece equal to a name pass with the token it was glued to before it
    # (pre-commit audit of the spec file names).
    held: dict[str, bool] = {}

    def holds_secret(kept: str) -> bool:
        if kept not in held:
            held[kept] = holds_known_secret_part(kept, parts)
        return held[kept]

    spans = [m.span() for m in keep.finditer(text)]
    whole = _whole_path_spans(text, _Lookups())
    spans += [s for s in whole if not holds_secret(text[s[0] : s[1]])]
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        # Overlapping spans only: two that touch are two parts, each judged on its own as main
        # judged them, or a digest glued to a long kept path was diluted below the threshold.
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    shown: list[str] = []
    done = 0
    for start, end in merged:
        kept = text[start:end]
        shown.append(late.redact_late(_entropy_masked(entropy, text[done:start])))
        shown.append(CREDENTIAL_MASK if holds_secret(kept) else kept)
        done = end
    shown.append(late.redact_late(_entropy_masked(entropy, text[done:])))
    joined = "".join(shown)
    if loopback is not None:
        joined = joined.replace(_LOOPBACK_MARK, loopback)
    return visible_controls(joined)


@app.command()
def run(
    ctx: typer.Context,
    target: Annotated[
        list[Path] | None,
        typer.Option("-t", "--target", help="Target file(s) (target.yaml). Repeatable."),
    ] = None,
    target_pos: Annotated[
        list[Path] | None,
        # A target.yaml, not a URL: the help promised "url/model-id/target.yaml" and only
        # ever accepted a file (a URL turned into "No such file or directory"). Declaring an
        # endpoint is the target file's job, because a URL alone cannot carry the provider,
        # the credential reference or the declared capabilities.
        typer.Argument(help="Target file(s) as positional args (target.yaml)."),
    ] = None,
    judge: Annotated[
        Path | None,
        typer.Option(
            "--judge",
            help="Judge model target.yaml (LLM-as-judge for semantic_judge on live scans).",
        ),
    ] = None,
    scope: Annotated[
        Path | None,
        typer.Option(
            "--scope",
            help="REQUIRED authorization record (scope.yaml).",
            # readable=False so an unreadable file surfaces as OUR operational error (exit 3)
            # instead of click's usage error (exit 2, which this tool uses for "findings at or
            # above --fail-on"): a CI step reading exit 2 as "vulnerabilities" would be wrong.
            readable=False,
        ),
    ] = None,
    suite: Annotated[
        str | None,
        typer.Option(
            "--suite",
            help="Suite id (the files in specs/suites/) or alias: owasp:llm, baseline, agentic.",
        ),
    ] = None,
    categories: Annotated[
        str | None,
        typer.Option("-p", "--categories", help="Comma-separated categories (pi,jailbreak,…)."),
    ] = None,
    spec_glob: Annotated[
        list[str] | None,
        typer.Option("--spec", help="Spec id or glob (e.g. 'PI-*'). Repeatable."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Exclude spec id/glob. Repeatable."),
    ] = None,
    top_tests: Annotated[
        int | None, typer.Option("--top-tests", help="Keep the N highest-signal specs.")
    ] = None,
    sn: Annotated[bool, typer.Option("-sn", help="Discovery only (no attacks).")] = False,
    sv: Annotated[bool, typer.Option("-sV", help="Fingerprint before attacking.")] = False,
    aggressive: Annotated[
        bool, typer.Option("-A", help="Aggressive: -sV + deep + adaptive.")
    ] = False,
    quick: Annotated[bool, typer.Option("--quick", help="T0 minimum battery.")] = False,
    deep: Annotated[
        bool,
        typer.Option(
            "--deep",
            help="Timing template T2 (slower) over the same battery; adaptive only with -sV.",
        ),
    ] = False,
    template: Annotated[
        int | None,
        typer.Option("-T", help="Timing template 0..5 (default 3; --quick/--deep imply one)."),
    ] = None,
    rate: Annotated[float | None, typer.Option("--rate", help="Max requests/sec.")] = None,
    budget_tokens: Annotated[
        int | None,
        typer.Option("--budget-tokens", help="Hard token ceiling (overrides the derived one)."),
    ] = None,
    budget_requests: Annotated[
        int | None,
        typer.Option("--budget-requests", help="Hard request ceiling (overrides the derived)."),
    ] = None,
    budget_wall: Annotated[
        int | None,
        typer.Option("--budget-wall", help="Hard wall-clock ceiling in seconds (overrides)."),
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", help="Max concurrent specs.")
    ] = None,
    timeout_s: Annotated[
        float | None, typer.Option("--timeout", help="Per-attempt timeout (s).")
    ] = None,
    runs: Annotated[
        int | None,
        typer.Option("--runs", help="Reproducibility runs (default 5)."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Resolve + validate; send nothing.")
    ] = False,
    estimate: Annotated[
        bool,
        typer.Option(
            "--estimate", help="Print a pre-run cost estimate (requests + tokens); no sends."
        ),
    ] = False,
    resume: Annotated[
        str | None,
        typer.Option(
            "--resume",
            help="Finish a halted run: its id. Answered and judged attempts are not re-sent; "
            "those that ended in an environment error (not one a retry would repeat), and "
            "replies the halt stored before they were judged, are sent again.",
        ),
    ] = None,
    resume_unverified: Annotated[
        bool,
        typer.Option(
            "--resume-unverified",
            help="Resume a run whose integrity record is missing (its ceiling then covers "
            "this invocation only).",
        ),
    ] = False,
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="CI gate band (info|low|medium|high|critical).")
    ] = "high",
    include_needs_review: Annotated[
        bool,
        typer.Option(
            "--include-needs-review",
            help="Also gate unconfirmed fails (not reproduced on every attempt of one variant, "
            "or with --runs 1 of the spec, or below the confidence threshold, or reported by "
            "the judge alone); SARIF then gives them their band's level. Undecided results "
            "never gate.",
        ),
    ] = False,
    compare: Annotated[bool, typer.Option("--compare", help="Model-comparison matrix.")] = False,
    hardened: Annotated[
        bool, typer.Option("--hardened", help="Replay hardened fixtures (clean-run smoke).")
    ] = False,
    o_json: Annotated[Path | None, typer.Option("-oJ", help="Write JSON report.")] = None,
    o_html: Annotated[Path | None, typer.Option("-oH", help="Write HTML report.")] = None,
    o_sarif: Annotated[Path | None, typer.Option("-oS", help="Write SARIF report.")] = None,
    o_junit: Annotated[Path | None, typer.Option("-oX", help="Write JUnit XML report.")] = None,
    o_all: Annotated[
        Path | None, typer.Option("-oA", help="Write all four formats to <prefix>.*")
    ] = None,
    evidence_root: Annotated[
        Path | None, typer.Option("--evidence-root", help="Evidence store root dir.")
    ] = None,
    run_db: Annotated[Path | None, typer.Option("--run-db", help="Run store SQLite path.")] = None,
    spec_path: Annotated[
        list[Path] | None,
        typer.Option(
            "--spec-path",
            help="Spec search path (default specs/ here, else the battery beside the package).",
        ),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour output.")] = False,
    quiet: Annotated[
        bool, typer.Option("-q", "--quiet", help="Suppress per-spec progress.")
    ] = False,
    verbose: Annotated[
        int,
        typer.Option(
            "-v",
            "--verbose",
            count=True,
            click_type=_counted(),
            show_default=False,
            help="Print the resolved plan, then run (-vv: the skipped and blocked ids too).",
        ),
    ] = 0,
) -> None:
    """Run a campaign against one or more targets."""

    ctx.meta[_VERBOSE_KEY] = max(verbose, int(ctx.meta.get(_VERBOSE_KEY, 0) or 0))
    targets = list(target or []) + list(target_pos or [])
    outputs: dict[str, Path] = {}
    if o_json is not None:
        outputs["json"] = o_json
    if o_html is not None:
        outputs["html"] = o_html
    if o_sarif is not None:
        outputs["sarif"] = o_sarif
    if o_junit is not None:
        outputs["junit"] = o_junit

    # Intensity flags change the battery / timing but never touch the scope gate.
    # ``-A`` is documented as "-sV + deep + adaptive", so it implies both of those here
    # rather than being a third, separate behaviour.
    #
    # An EXPLICIT -T always wins. `--quick`/`--deep` used to overwrite it in both directions
    # without a word: `-T0 --deep` quietly became T2 (0.5 to 2.0 req/s, concurrency 1 to 2),
    # and -T0 is exactly what an operator picks for a fragile production target. The implied
    # template is a default, so it applies only when the operator did not choose one.
    resolved_deep = deep or aggressive
    if template is not None:
        resolved_template = template
    elif quick:
        resolved_template = 0
    elif resolved_deep:
        resolved_template = 2
    else:
        resolved_template = DEFAULT_TEMPLATE

    opts = RunOptions(
        targets=targets,
        scope=scope,
        judge=judge,
        suite=suite,
        categories=[c.strip() for c in categories.split(",")] if categories else [],
        spec_globs=list(spec_glob or []),
        exclude_globs=list(exclude or []),
        top_tests=top_tests,
        template=resolved_template,
        discovery_only=sn,
        fingerprint_first=sv or aggressive,
        quick=quick,
        deep=resolved_deep,
        verbose=verbose,
        rate=rate,
        budget_tokens=budget_tokens,
        budget_requests=budget_requests,
        budget_wall_s=budget_wall,
        concurrency=concurrency,
        timeout_s=timeout_s,
        runs=runs if runs is not None else 5,
        runs_explicit=runs is not None,
        dry_run=dry_run,
        estimate=estimate,
        resume=resume,
        resume_unverified=resume_unverified,
        fail_on=fail_on,
        include_needs_review=include_needs_review,
        compare=compare,
        outputs=outputs,
        output_all_prefix=o_all,
        hardened=hardened,
        no_color=no_color,
        quiet=quiet,
        evidence_root=evidence_root,
        run_db=run_db,
    )

    if not targets:
        typer.echo("error: no target given (use -t/--target or a positional target)", err=True)
        raise typer.Exit(ExitCode.ERROR)

    try:
        outcome = run_mod.execute_run(opts, _spec_paths(spec_path), default_spec_path=not spec_path)
    except ScopeRequiredError as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except (PolicyError, AdapterError, TamperError, ValueError, OSError) as exc:
        # TamperError: a stored artifact whose content no longer hashes to its name, which
        # `--resume` can hit. It subclasses RuntimeError, so it escaped this handler and
        # surfaced as a traceback with exit 1: corrupted evidence read as an almost-clean
        # scan. Exactly the omission described just below, one class along.
        #
        # AdapterError (and its EndpointNotAllowed subclass) is an authorization/transport
        # failure, i.e. an operational error: exit 3. It derives from Exception, not from
        # ValueError, so it used to escape this handler entirely and surface as a traceback
        # with exit **1**, which in this tool means "findings below the threshold" - a CI
        # step treating 1 as "carry on" would read a refused endpoint as a clean-ish scan.
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except sqlite3.Error as exc:
        # The run store failed while the run used it (a lock held past the busy timeout, a full
        # disk): an operational error, named after the store (u10 A-80).
        _store_failed(opts.run_db or run_mod.DEFAULT_RUN_DB, exc)

    # The dry-run plan is printed by execute_run itself (it owns the resolved plan);
    # echoing a second, contentless line here just duplicated the header.
    raise typer.Exit(int(outcome.exit_code))


def _store_failed(run_db: Path, exc: sqlite3.Error) -> NoReturn:
    """Say which run store failed and exit 3 (a sqlite3 error that reached a command).

    A lock held past the wait names its store already, and is said as it is.
    """

    from ildottore.store.migrations import StoreLocked

    said = str(exc) if isinstance(exc, StoreLocked) else f"the run store at {run_db} failed: {exc}"
    typer.echo(f"error: {_masked(RuntimeError(said))}", err=True)
    raise typer.Exit(ExitCode.ERROR) from exc


# --- fleet -----------------------------------------------------------------------


@app.command()
def fleet(
    config: Annotated[
        Path, typer.Argument(help="fleet.yaml declaring every LLM/URL/MCP target to validate.")
    ],
    out: Annotated[
        Path, typer.Option("--out", help="Output dir for the generated scope + target files.")
    ] = Path(".dottore/fleet"),
    run_now: Annotated[
        bool, typer.Option("--run", help="Scan every expanded target immediately.")
    ] = False,
    judge: Annotated[
        Path | None,
        typer.Option(
            "--judge",
            help="Judge target.yaml; must match the fleet file's 'judge:' block, which is "
            "used on its own when this is omitted.",
        ),
    ] = None,
    runs: Annotated[int, typer.Option("--runs", help="Reproducibility runs (default 5).")] = 5,
    categories: Annotated[
        str | None, typer.Option("-p", "--categories", help="Comma-separated categories.")
    ] = None,
    o_json: Annotated[Path | None, typer.Option("-oJ", help="Write JSON report.")] = None,
    o_html: Annotated[Path | None, typer.Option("-oH", help="Write HTML report.")] = None,
    o_sarif: Annotated[Path | None, typer.Option("-oS", help="Write SARIF report.")] = None,
    o_junit: Annotated[Path | None, typer.Option("-oX", help="Write JUnit XML report.")] = None,
    o_all: Annotated[
        Path | None, typer.Option("-oA", help="Write all four formats to <prefix>.*")
    ] = None,
    evidence_root: Annotated[
        Path | None, typer.Option("--evidence-root", help="Evidence store root dir.")
    ] = None,
    run_db: Annotated[Path | None, typer.Option("--run-db", help="Run store SQLite path.")] = None,
    spec_path: Annotated[
        list[Path] | None,
        typer.Option(
            "--spec-path",
            help="Spec search path (default specs/ here, else the battery beside the package).",
        ),
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour output.")] = False,
) -> None:
    """Expand a fleet.yaml into an authorization scope + one target file per model.

    Declares the whole set of targets to validate in one place (hosted LLMs by API-key env
    reference, a local model, a raw URL, or an MCP server). Keys are never written, each
    entry references an env var. With --run it scans every expanded target right away.
    A judge is authorized only when the fleet file declares it in a 'judge:' block.

    --spec-path, --evidence-root, --run-db and -oJ/-oH/-oS/-oX/-oA mean what they mean to
    run; without --run they are carried into the printed 'dottore run' line.
    """

    try:
        cfg = fleet_mod.load_fleet(config)
        # The scope is built from the fleet file alone; a --judge file must match its `judge:`.
        judge_target = wiring.load_target(judge) if judge is not None else None
        materialized = fleet_mod.materialize_fleet(cfg, out, judge=judge_target)
    except (ValueError, OSError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(f"scope:   {materialized.scope_path}")
    for path in materialized.target_paths:
        typer.echo(f"target:  {path}")
    if materialized.judge_path is not None:
        typer.echo(f"judge:   {materialized.judge_path}")
    for target_id, reason in materialized.skipped:
        typer.echo(f"skipped: {target_id} ({reason})")
    judge_file = judge if judge is not None else materialized.judge_path

    asked = (("json", o_json), ("html", o_html), ("sarif", o_sarif), ("junit", o_junit))
    outputs = {fmt: path for fmt, path in asked if path is not None}
    if not run_now:
        joined = " ".join(f'"{p}"' for p in materialized.target_paths)
        # Carry the judge into the hint: the scope authorizes it, and an operator following a
        # hint that omits it drops the judge from the run. The run options too, for the same
        # reason (a hint without them writes the reports and the stores somewhere else).
        judge_arg = f' --judge "{judge_file}"' if judge_file is not None else ""
        flags = {"json": "-oJ", "html": "-oH", "sarif": "-oS", "junit": "-oX"}
        carried = [f'--spec-path "{p}"' for p in spec_path or []]
        carried += [f'--evidence-root "{evidence_root}"'] if evidence_root is not None else []
        carried += [f'--run-db "{run_db}"'] if run_db is not None else []
        carried += [f'{flags[fmt]} "{path}"' for fmt, path in outputs.items()]
        carried += [f'-oA "{o_all}"'] if o_all is not None else []
        tail = "".join(f" {arg}" for arg in carried)
        typer.echo(
            f'\nRun it:\n  dottore run {joined} --scope "{materialized.scope_path}"{judge_arg}'
            f"{tail}"
        )
        raise typer.Exit(ExitCode.CLEAN)

    opts = RunOptions(
        targets=list(materialized.target_paths),
        scope=materialized.scope_path,
        judge=judge_file,
        categories=[c.strip() for c in categories.split(",")] if categories else [],
        runs=runs,
        no_color=no_color,
        outputs=outputs,
        output_all_prefix=o_all,
        evidence_root=evidence_root,
        run_db=run_db,
        extra_inputs=[("the fleet file", config)],
    )
    try:
        # The same default spec path as `run` (u12 A-80): it was `specs/` in the working
        # directory with no option to change it, so `fleet --run` worked from the repository
        # root only ("path not found: specs").
        outcome = run_mod.execute_run(opts, _spec_paths(spec_path), default_spec_path=not spec_path)
    # AdapterError included for the same reason `run` includes it (see that handler): it
    # derives from Exception, so `fleet --run` used to turn an HTTP 401 or an off-allowlist
    # endpoint into a traceback and exit **1**, which in this tool means "findings below the
    # threshold". Identical condition, identical code path underneath, two exit codes.
    except (ScopeRequiredError, PolicyError, AdapterError, TamperError, ValueError, OSError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except sqlite3.Error as exc:
        _store_failed(opts.run_db or run_mod.DEFAULT_RUN_DB, exc)
    raise typer.Exit(int(outcome.exit_code))


# --- fingerprint -----------------------------------------------------------------


#: What pydantic's JSON leaves raw that a terminal acts on or cp1252 cannot encode: DEL and every
#: character outside ASCII (it escapes the C0 controls itself).
_JSON_NOT_ASCII = re.compile(r"[^\x00-\x7e]")


def _json_escape(match: re.Match[str]) -> str:
    units = match.group(0).encode("utf-16-be")
    return "".join(
        f"\\u{int.from_bytes(units[i : i + 2], 'big'):04x}" for i in range(0, len(units), 2)
    )


def _ascii_json(text: str) -> str:
    """pydantic's JSON with DEL and every character outside ASCII as a JSON escape.

    pydantic left a C1 control, DEL and U+2028 a target echoed raw, and on a cp1252 stdout the
    stream's own escapes (``\\x81``) are not JSON (delta audit of the control-characters
    block). ``json.dumps`` escaped them too, but wrote ``1e-07`` for pydantic's ``1e-7`` and
    ``NaN`` for its ``null`` (pre-merge audit): the numbers and the layout stay pydantic's.
    """

    return _JSON_NOT_ASCII.sub(_json_escape, text)


@app.command()
def fingerprint(
    target: Annotated[Path, typer.Argument(help="Target file (target.yaml).")],
    scope: Annotated[
        Path | None,
        typer.Option("--scope", help="REQUIRED authorization record.", readable=False),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Probe the deterministic mock instead of the live endpoint (no sends).",
        ),
    ] = False,
) -> None:
    """Fingerprint a target's model + guardrails (what run -sV does first).

    A target declaring a real endpoint is probed over the wire (scope-gated). Use
    --offline for the deterministic mock, which sends nothing and works in CI.
    """

    try:
        fp = fingerprint_mod.fingerprint_target(target, scope, offline=offline)
    except ScopeRequiredError as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except (PolicyError, AdapterError, ValueError, OSError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    # A probe whose reply came back refused is recorded in the fingerprint and said here, and
    # the command still prints what came back (OD-23); it used to exit 3 on one such reply. When
    # every probe was refused there is nothing to print, and a script must not read an empty
    # fingerprint as a result: exit 3 (delta audit).
    probes = run_mod.fingerprint_probe_count()
    empty = run_mod.every_probe_failed(fp, probes)
    warning = run_mod.probe_failure_warning(
        fp.target_id, fp, probes=probes, severity="error" if empty else "warning"
    )
    if warning is not None:
        typer.echo(warning, err=True)
    if empty:
        raise typer.Exit(ExitCode.ERROR)
    try:
        shown = _ascii_json(fp.model_dump_json(indent=2))
    except ValueError:  # a lone surrogate (a target id written `"t\ud800"`), not JSON to pydantic
        shown = json.dumps(fp.model_dump(mode="json"), indent=2)
    # A target id holding `##[error]` was a command to a CI runner reading the log (OD-20).
    typer.echo(log_safe_json(shown))
    raise typer.Exit(ExitCode.CLEAN)


# --- coverage (read-only, no target) ---------------------------------------------


@app.command()
def coverage(
    paths: Annotated[list[Path] | None, typer.Argument(help="Spec paths to measure.")] = None,
    framework: Annotated[
        str, typer.Option("--framework", help="all | owasp | atlas | iopc | aisvs.")
    ] = "all",
    suite: Annotated[
        str | None, typer.Option("--suite", help="Narrow to one suite (id or alias).")
    ] = None,
    gaps: Annotated[
        bool, typer.Option("--gaps/--no-gaps", help="List the codes NOT covered.")
    ] = True,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """What the battery TESTS, per framework, without running a scan.

    Reads the spec registry only: no target, no credential, nothing sent. Answers the
    question asked before a run (and before a purchase): "covered, of what?".
    """

    if framework not in coverage_mod.FRAMEWORK_KEYS:
        typer.echo(
            f"error: --framework must be one of {', '.join(coverage_mod.FRAMEWORK_KEYS)}",
            err=True,
        )
        raise typer.Exit(ExitCode.ERROR)
    try:
        result = coverage_mod.battery_coverage(
            _spec_paths(paths), suite=suite, default_spec_path=not paths
        )
    except (OSError, ValueError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    if as_json:
        typer.echo(coverage_mod.render_coverage_json(result, framework=framework, show_gaps=gaps))
    else:
        typer.echo(coverage_mod.render_coverage(result, framework=framework, show_gaps=gaps))
    raise typer.Exit(ExitCode.CLEAN)


# --- lint (mounted from u02) -----------------------------------------------------


@app.command()
def lint(
    paths: Annotated[list[Path] | None, typer.Argument(help="Spec paths to lint.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Schema + policy + fixtures-prove-detection lint of spec files, suites and packs."""

    # Strict: `specs/` here or the paths given, never the packaged battery. Linting that in a
    # pack's own repository printed "lint OK ... across 75 spec(s)" over a broken spec of the
    # pack, exit 0 (pre-merge audit of e6a1ab9b, MEDIUM 3). With no path and no `specs/` here
    # it is refused as the reading commands refuse a missing spec path (exit 3).
    if not paths and not Path("specs").is_dir():
        typer.echo(
            "error: spec path not found: specs. Pass the spec path to lint (dottore lint <dir>); "
            "with none, lint reads specs/ in the working directory and never the battery beside "
            "the installed package.",
            err=True,
        )
        raise typer.Exit(ExitCode.ERROR)
    search = list(paths) if paths else [Path("specs")]
    # A path the operator typed is echoed by the path findings, through the CLI's mask as every
    # other error line is: `lint <key>` printed the key (pre-merge audit of A-82, LOW a).
    code, output = run_lint(search, as_json=as_json, mask=lambda text: _masked(ValueError(text)))
    typer.echo(output)
    raise typer.Exit(code)


# --- registry --------------------------------------------------------------------


@registry_app.command("ls")
def registry_ls(
    category: Annotated[str | None, typer.Option("--category")] = None,
    owasp: Annotated[str | None, typer.Option("--owasp")] = None,
    tag: Annotated[str | None, typer.Option("--tag")] = None,
    suite: Annotated[str | None, typer.Option("--suite")] = None,
    spec_path: Annotated[list[Path] | None, typer.Option("--spec-path")] = None,
) -> None:
    """List registered specs (filterable by category/owasp/tag/suite)."""

    try:
        specs, unloaded = registry_mod.list_specs_and_unloaded(
            _spec_paths(spec_path),
            category=category,
            owasp=owasp,
            tag=tag,
            suite=suite,
            default_spec_path=not spec_path,
        )
    except ValueError as exc:  # an unknown suite, a spec path that holds nothing (A-82)
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    for row in registry_mod.render_spec_rows(specs):
        typer.echo(row)
    for note in registry_mod.unloaded_warnings(unloaded):
        typer.echo(note, err=True)


@app.command()
def describe(
    spec_id: Annotated[str, typer.Argument(help="Spec id to describe.")],
    spec_path: Annotated[list[Path] | None, typer.Option("--spec-path")] = None,
) -> None:
    """Show one spec's detail card."""

    try:
        spec = describe_mod.describe_spec(
            _spec_paths(spec_path), spec_id, default_spec_path=not spec_path
        )
    except ValueError as exc:  # a spec path that holds nothing (A-82)
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except describe_mod.DescribeError as exc:
        typer.echo(f"error: {_masked(ValueError(f'spec {spec_id!r} not found'))}", err=True)
        for note in registry_mod.unloaded_warnings(exc.unloaded):
            typer.echo(note, err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(describe_mod.render_describe(spec))


# --- render-media ----------------------------------------------------------------


@app.command("render-media")
def render_media(
    spec_id: Annotated[str, typer.Argument(help="Multimodal spec id (declares attack.media).")],
    out_dir: Annotated[Path, typer.Option("--out", help="Output directory.")] = Path(),
    spec_path: Annotated[list[Path] | None, typer.Option("--spec-path")] = None,
) -> None:
    """Render a multimodal spec's media carrier(s) to disk to inspect them (read-only, no target).

    Writes one file per attack.media part, named by its rendered type (.png for an image,
    .wav for audio), and prints each path, size and SHA-256 digest (the same
    chain-of-custody hash a run records). Sends nothing.
    """

    try:
        carriers = render_media_mod.render_spec_media(_spec_paths(spec_path), spec_id, out_dir)
    except render_media_mod.RenderMediaError as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(render_media_mod.render_carrier_report(carriers))


# --- new-spec --------------------------------------------------------------------


@app.command("new-spec")
def new_spec(
    spec_id: Annotated[str, typer.Option("--id", help="New spec id (e.g. PI-NEW-001).")],
    family: Annotated[str, typer.Option("--family", help="Spec family/tag.")],
    category: Annotated[str, typer.Option("--category", help="Category.")] = "prompt_injection",
    out_dir: Annotated[
        Path, typer.Option("--out", help="Output directory (default: current dir).")
    ] = Path(),
    stdout: Annotated[
        bool, typer.Option("--stdout", help="Print scaffold instead of writing.")
    ] = False,
) -> None:
    """Scaffold a new attack spec + empty fixtures."""

    try:
        if stdout:
            typer.echo(new_spec_mod.scaffold_spec(spec_id, family=family, category=category))
            return
        path = new_spec_mod.write_scaffold(out_dir, spec_id, family=family, category=category)
    except (ValueError, FileExistsError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(f"wrote {path}")


# --- replay ----------------------------------------------------------------------


@app.command()
def replay(
    run_id: Annotated[str, typer.Argument(help="Run id to replay from stored evidence.")],
    evidence_root: Annotated[
        Path, typer.Option("--evidence-root", help="Evidence store root dir.")
    ] = Path(".dottore/evidence"),
    run_db: Annotated[
        Path,
        typer.Option("--run-db", help="Run store; its findings are the evidence manifest."),
    ] = Path(".dottore/runs.sqlite"),
) -> None:
    """Re-read a run from stored evidence (reproducibility, no re-sending)."""

    from ildottore.store import TamperError

    try:
        with run_mod.lock_waits_noted():
            result, warning = replay_mod.replay_checked(evidence_root, run_id, run_db)
    except (OSError, ValueError, TamperError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except sqlite3.Error as exc:
        _store_failed(run_db, exc)
    if warning is not None:
        # It names the --run-db path; written out like an error (`_masked`).
        typer.echo(f"warning: {visible_controls(warning)}", err=True)
    typer.echo(replay_mod.render_replay(result))


# --- diff (baseline / drift) ------------------------------------------------------


@app.command()
def diff(
    baseline: Annotated[Path, typer.Argument(help="Baseline JSON run report (-oJ output).")],
    current: Annotated[Path, typer.Argument(help="Current JSON run report (-oJ output).")],
) -> None:
    """Compare a run against a stored baseline and surface regressions.

    Classifies each spec id as NEW-FAIL (regression), FIXED, UNVERIFIED, STILL-FAIL,
    UNCHANGED, ONLY-IN-BASELINE or ONLY-IN-CURRENT and exits nonzero when any regression is
    present, so it can gate CI like run.
    """

    try:
        # A truncated report is the input that silently breaks this gate: the specs that never
        # ran are absent, absence classifies as ONLY-IN-BASELINE, and ONLY-IN-BASELINE is not
        # a regression, so a scan that dropped a third of the battery diffs green. Refuse it.
        for label, path in (("baseline", baseline), ("current", current)):
            incomplete = diff_mod.incomplete_reason(path)
            if incomplete is not None:
                # Printed through `_masked` below, as calibrate prints it: the reason is the
                # report's and quotes a target's transport error, which printed a key in clear
                # here while calibrate masked it (audit of PR #61).
                raise ValueError(
                    f"the {label} report describes a run that did not complete "
                    f"({incomplete}). Its missing specs would diff as ONLY-IN-BASELINE, "
                    "which is not a regression, so the comparison would read clean. "
                    "Re-run that scan, or diff two complete reports."
                )
        report = diff_mod.diff_reports(baseline, current)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(diff_mod.render_diff(report))
    code = ExitCode.FINDINGS_AT_OR_ABOVE if report.has_regressions() else ExitCode.CLEAN
    raise typer.Exit(int(code))


@app.command()
def calibrate(
    report: Annotated[Path, typer.Argument(help="A JSON run report (-oJ output).")],
    labels: Annotated[Path, typer.Argument(help="Operator labels file (spec_id -> pass|fail).")],
) -> None:
    """Compare a run's findings against operator labels (human-in-the-loop).

    Reports agreement plus precision/recall (fail = positive). Read-only: it consumes operator
    verdicts to measure the scanner and its judge; it changes nothing and sends nothing.
    """

    try:
        # A halted run's report is missing the specs that never ran; calibrating it measures
        # the scanner on a battery it did not finish (audit R18).
        incomplete = diff_mod.incomplete_reason(report)
        if incomplete is not None:
            raise ValueError(
                f"the report describes a run that did not complete ({incomplete}); calibrate "
                "a complete run"
            )
        result = calibrate_mod.calibrate_reports(report, labels)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        typer.echo(f"error: {_masked(exc)}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(calibrate_mod.render_calibration(result))
    raise typer.Exit(ExitCode.CLEAN)


# --- schema export ---------------------------------------------------------------


@schema_app.command("export")
def schema_export(
    name: Annotated[
        str | None,
        typer.Option("--name", help="One schema (suite|pack|test-plan|attack-spec|report)."),
    ] = None,
) -> None:
    """Export the generated JSON schemas, and the JSON report's, to stdout."""

    # The report's schema is hand-authored and ships with the reporter (u11); it is printed
    # beside the generated ones, which it could not be (u12 A-82, CLI audit L5).
    schemas = {**export_schemas(), "report": report_schema()}
    if name is not None:
        if name not in schemas:
            refusal = f"unknown schema {name!r}; available: {', '.join(sorted(schemas))}"
            typer.echo(f"error: {_masked(ValueError(refusal))}", err=True)
            raise typer.Exit(ExitCode.ERROR)
        typer.echo(log_safe_json(json.dumps(schemas[name], indent=2, sort_keys=True)))
        return
    typer.echo(log_safe_json(json.dumps(schemas, indent=2, sort_keys=True)))
