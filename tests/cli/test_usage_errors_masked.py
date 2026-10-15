"""A usage error never prints the value the operator typed in clear (u12 A-82, CLI audit M7).

``dottore run --runs "$KEY"`` (a shell variable expanded into the wrong flag, a paste into the
wrong place) printed ``Invalid value for '--runs': 'sk-ant-api03-...' is not a valid
integer.`` on stderr, the key whole, and so did ``-T``, ``--rate``, the ``--budget-*`` flags and
``fleet --runs``: click printed the error itself, before any of this tool's masking ran. The
console scripts now run :func:`ildottore.cli.main.main`, which runs the command tree in click's
non-standalone mode and prints the usage block with its message through the CLI's redactor
(``_masked``), exit 3.

Every option of every command whose type refuses a key-shaped value is tried, found by walking
the command tree, so an option added later is covered without a list to keep in step.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from typing import Any

import pytest
import typer

from ildottore.cli.main import app, main

#: Shaped like an Anthropic key (the redactor masks it by shape), random enough to be no pattern.
KEY = "sk-ant-api03-Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aC-QwErTyUiOpAsDfGh"
#: Any run of it this long in the output is a leak.
FRAGMENTS = [KEY[i : i + 12] for i in range(0, len(KEY) - 12, 6)]


def _commands() -> Iterator[tuple[list[str], Any]]:
    """Every command of the tree with the words that reach it (``["registry", "ls"]``).

    Read by shape (a group has ``commands``): Typer 0.26 builds the tree from its own copy of
    click, so the classes of an installed ``click`` are not its classes.
    """

    def walk(path: list[str], command: Any) -> Iterator[tuple[list[str], Any]]:
        if hasattr(command, "commands"):
            for name, sub in sorted(command.commands.items()):
                yield from walk([*path, name], sub)
        else:
            yield path, command

    yield from walk([], typer.main.get_command(app))


def _refuses(param: Any) -> bool:
    try:
        param.type.convert(KEY, param, None)
    except Exception:  # click's BadParameter, from whichever copy
        return True
    return False


def _typed_options() -> list[tuple[list[str], str]]:
    """(command words, option) for each option that takes a value and refuses a key."""

    found = []
    for path, command in _commands():
        for param in command.params:
            if param.param_type_name != "option" or param.is_flag or param.count:
                continue
            if _refuses(param):
                found.append((path, max(param.opts, key=len)))
    return found


TYPED = _typed_options()


#: The two ways a console script calls the CLI: the one this version installs (``main()``), and
#: the one an older install generated and ``pip install -e`` keeps across a pull (``app()``).
#: And the click command a caller takes from the app (round-2 audit of A-82, LOW 1).
ENTRIES = {
    "main": lambda: main(),
    "app": lambda: app(),
    "command": lambda: typer.main.get_command(app)(),
}


def _invoke(
    argv: list[str], capsys: pytest.CaptureFixture[str], entry: str = "main"
) -> tuple[int, str, str]:
    """The CLI as a console script calls it: no arguments, the words in ``sys.argv``."""

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "argv", ["dottore", *argv])
        with pytest.raises(SystemExit) as exit_info:
            ENTRIES[entry]()
    out, err = capsys.readouterr()
    code = exit_info.value.code
    return (code if isinstance(code, int) else 1), out, err


def _assert_masked(code: int, out: str, err: str) -> None:
    assert code == 3, err
    assert "Traceback" not in out + err
    for fragment in FRAGMENTS:
        assert fragment not in out + err, err
    assert "«REDACTED" in err, err


def test_the_options_the_audit_named_are_among_those_tried() -> None:
    named = {(" ".join(path), option) for path, option in TYPED}
    for expected in [
        ("run", "--runs"),
        ("run", "-T"),
        ("run", "--rate"),
        ("run", "--budget-tokens"),
        ("run", "--budget-requests"),
        ("run", "--budget-wall"),
        ("run", "--timeout"),
        ("run", "--concurrency"),
        ("run", "--top-tests"),
        ("fleet", "--runs"),
    ]:
        assert expected in named, sorted(named)


@pytest.mark.parametrize("entry", sorted(ENTRIES))
@pytest.mark.parametrize(("path", "option"), TYPED, ids=[f"{' '.join(p)} {o}" for p, o in TYPED])
def test_a_key_given_to_a_typed_option_is_masked(
    path: list[str], option: str, entry: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _invoke([*path, option, KEY], capsys, entry)
    _assert_masked(code, out, err)
    # Still a usage error that says which option, and how to get help. The program's name is
    # left out: click takes it from the launcher (`python -m pytest` under some runners).
    assert f"'{option}'" in err or option in err, err
    first = err.splitlines()[0]
    assert first.startswith("Usage: ") and first.split("[OPTIONS]")[0].rstrip().endswith(
        " ".join(path)
    ), err
    assert any(line.startswith("error: ") for line in err.splitlines()), err


@pytest.mark.parametrize(
    "argv",
    [
        [KEY],  # as a command
        ["run", f"--{KEY}"],  # as an option
        ["lint", "--json", "x", f"--{KEY}"],
        ["registry", KEY],  # as a sub-command
        ["schema", "export", KEY],  # as an extra argument
        ["fleet", "f.yaml", "--runs"],  # an option missing its value (no key: still exit 3)
    ],
    ids=["command", "option", "lint-option", "subcommand", "extra-argument", "missing-value"],
)
@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_every_other_usage_error_goes_through_the_mask(
    argv: list[str], entry: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _invoke(argv, capsys, entry)
    assert code == 3, err
    assert "Traceback" not in out + err
    for fragment in FRAGMENTS:
        assert fragment not in out + err, err
    assert any(line.startswith("error: ") for line in err.splitlines()), err


def test_control_characters_in_a_usage_error_are_written_out(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The mask's last step (``visible_controls``) runs on a usage error too."""

    code, _, err = _invoke(["run", "--runs", "\x1b]0;pwned\x07X"], capsys)
    assert code == 3
    assert "\x1b" not in err and "\x07" not in err, err


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_what_is_not_an_error_keeps_its_exit_code(
    entry: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _invoke(["--version"], capsys, entry)
    assert code == 0 and out.startswith("dottore ")
    code, out, _ = _invoke(["run", "--help"], capsys, entry)
    assert code == 0 and "Usage" in out
    # A bare `dottore` prints the help and exits 3, as before (no_args_is_help).
    code, out, err = _invoke([], capsys, entry)
    assert code == 3 and "Usage" in out and "error:" not in err


def test_an_embedding_caller_still_gets_typers_own_call() -> None:
    """``app(..., standalone_mode=False)`` returns what the command returns, as Typer's call did,
    and a test runner still drives the command tree (it never calls ``app``)."""

    from typer.testing import CliRunner

    assert app(args=["--version"], standalone_mode=False) == 0
    assert CliRunner().invoke(app, ["--version"]).exit_code == 0


def test_the_console_scripts_point_at_main() -> None:
    """``pip install`` makes ``dottore`` and ``dott`` call :func:`main`, not the Typer app."""

    import tomllib
    from pathlib import Path

    project = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    assert project["scripts"] == {
        "dottore": "ildottore.cli.main:main",
        "dott": "ildottore.cli.main:main",
    }


@pytest.mark.parametrize(
    "launch",
    [
        ["-m", "ildottore.cli.main"],
        # The console script an older install generated, which `pip install -e` keeps across a
        # pull (pre-merge audit of A-82, MEDIUM 1).
        [
            "-c",
            "import sys; from ildottore.cli.main import app; sys.argv[0] = 'dottore'; "
            "sys.exit(app())",
        ],
        ["-c", "import sys; from ildottore.cli.main import main; sys.argv[0] = 'dottore'; main()"],
    ],
    ids=["module", "old-script", "new-script"],
)
def test_the_entry_point_masks_in_a_real_process(launch: list[str]) -> None:
    """The same in a process of its own, as each kind of installed script runs it."""

    result = subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, *launch, "run", "--runs", KEY],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    _assert_masked(result.returncode, result.stdout, result.stderr)


@pytest.mark.parametrize(
    ("raised", "expected_err"),
    [
        ("ClickException", "error: could not open "),
        ("FileError", "error: "),
        ("Abort", "error: aborted"),
    ],
)
def test_the_other_click_exceptions_exit_3_as_the_guard_closes_them(
    raised: str,
    expected_err: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A click error that is not a usage error is printed masked and exits 3, and an abort says
    `error: aborted` and exits 3: A-9's closure (u12 A-80), where click's standalone mode exited
    1, the code of findings below --fail-on. No command raises either before a command runs
    today. The classes are Typer's public ones: `typer._click.exceptions` lost `Abort` in Typer
    0.27, and `run_masked` let it escape uncaught there."""

    from ildottore.cli.app import _typer_error, run_masked

    def raising() -> None:
        if raised == "Abort":
            raise typer.Abort()
        click_exception = _typer_error("ClickException")
        if raised == "FileError":
            # Typer exports no FileError: it is the library's subclass of its ClickException.
            file_error = next(
                cls for cls in click_exception.__subclasses__() if cls.__name__ == "FileError"
            )
            raise file_error(f"/{KEY}", hint="no such file")
        raise click_exception(f"could not open {KEY}")

    with pytest.raises(SystemExit) as exit_info:
        run_masked(raising)
    out, err = capsys.readouterr()
    assert exit_info.value.code == 3
    assert expected_err in err
    for fragment in FRAGMENTS:
        assert fragment not in out + err, err


def test_a_parent_group_holding_the_command_prints_it_masked(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The root command masks a usage error where it raises it, so a group that holds it as a
    sub-command and prints the error itself shows it masked (round-2 audit of A-82, LOW 1)."""

    from typer.core import TyperGroup

    parent = TyperGroup(name="outer", commands={"dottore": typer.main.get_command(app)})
    with pytest.raises(SystemExit) as exit_info:
        parent.main(["dottore", "run", "--runs", KEY], prog_name="outer")
    out, err = capsys.readouterr()
    assert exit_info.value.code == 3
    for fragment in FRAGMENTS:
        assert fragment not in out + err, err
    assert "REDACTED" in err


def test_the_error_a_parent_group_catches_is_masked_already() -> None:
    """A caller that catches the exception itself (any click group that is not Typer's, or a
    script) reads the masked message too."""

    from ildottore.cli.app import _typer_error

    command = typer.main.get_command(app)
    with pytest.raises(_typer_error("UsageError")) as info:
        command.main(["run", "--runs", KEY], standalone_mode=False)
    for fragment in FRAGMENTS:
        assert fragment not in info.value.format_message() and fragment not in str(info.value)


def test_python_m_typer_prints_it_masked() -> None:
    """`python -m typer ildottore.cli.main run ...` loads the app into Typer's own CLI."""

    result = subprocess.run(  # noqa: S603 - this interpreter running Typer's CLI on this app
        [sys.executable, "-m", "typer", "ildottore.cli.main", "run", "run", "--runs", KEY],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**__import__("os").environ, "COLUMNS": "200"},
    )
    assert result.returncode != 0
    for fragment in FRAGMENTS:
        assert fragment not in result.stdout + result.stderr, result.stderr
    assert "REDACTED" in result.stdout + result.stderr, result.stderr


def test_a_group_of_the_installed_click_gets_the_masked_message_and_no_raw_cause() -> None:
    """A group from the installed `click` does not catch the exception of Typer's copy, so it
    prints a traceback: its last line is the masked message, and the conversion error click
    raised it from, which quotes the value, is not chained to it (round-3 audit of A-82). This is
    what embedding the command in a plain click group supports: a usage error says nothing of the
    value; the exit code and the traceback are that group's."""

    pytest.importorskip("click")
    code = (
        "import sys, click, typer\n"
        "from ildottore.cli.main import app\n"
        "parent = click.Group('outer')\n"
        "parent.add_command(typer.main.get_command(app), 'dottore')\n"
        "parent(sys.argv[1:])\n"
    )
    result = subprocess.run(  # noqa: S603 - this interpreter running the command in a group
        [sys.executable, "-c", code, "dottore", "run", "--runs", KEY],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    for fragment in FRAGMENTS:
        assert fragment not in result.stdout + result.stderr, result.stderr
    assert "During handling" not in result.stderr and "direct cause" not in result.stderr
    assert "REDACTED" in result.stderr.splitlines()[-1], result.stderr
