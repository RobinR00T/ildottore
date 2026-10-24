"""The logo above the root help: on a terminal only, in colour only where colour prints.

``dottore --help`` and a bare ``dottore`` print the Il Dottore logo (``cli/banner.txt``) above
the help when stdout is a terminal, in 24-bit colour (``cli/banner_ansi.txt``) when the terminal
declares it (``COLORTERM`` ``truecolor`` or ``24bit``) and neither ``NO_COLOR`` nor
``TERM=dumb`` says otherwise. Off a terminal, a script or a pipe reading the help gets exactly
what it got before, and a sub-command's help never carries it. The colour copy stripped of its
escape sequences is byte-identical to the plain one, so what a colour-blind diff of the two
would show is nothing.
"""

from __future__ import annotations

import io
import re
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from ildottore.cli import app as app_mod
from ildottore.cli import banner
from ildottore.cli.main import app

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CODE = re.compile(r"\x1b\[([0-9;]*)m")
_LOGO_LINE = "I l   D o t t o r e"


def _fake_env(env: banner.Env) -> Any:
    return lambda _stream: env


# --- the two copies ------------------------------------------------------------------------


def test_the_colour_copy_stripped_is_the_plain_copy() -> None:
    assert _ANSI.sub("", banner.ansi()) == banner.plain()


def test_the_plain_copy_is_ascii_art_that_fits_a_terminal() -> None:
    plain = banner.plain()
    assert plain.isascii()
    assert plain.endswith("\n") and not plain.endswith("\n\n")
    lines = plain.split("\n")[:-1]
    assert 20 <= len(lines) <= 40, len(lines)
    assert max(len(line) for line in lines) <= 80
    assert all(line == line.rstrip() for line in lines), "a trailing space"
    assert "\x1b" not in plain
    assert _LOGO_LINE in plain


def test_every_colour_line_ends_reset_and_uses_24_bit_colour_only() -> None:
    for line in banner.ansi().split("\n")[:-1]:
        codes = _CODE.findall(line)
        if not codes:
            assert line == "", line  # a blank row
            continue
        assert line.endswith("\x1b[0m"), line
        assert all(code.startswith("38;2;") for code in codes[:-1]), codes


# --- show() -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        (banner.Env(tty=False, colorterm="truecolor"), (False, False)),
        (banner.Env(tty=True), (True, False)),
        (banner.Env(tty=True, colorterm="truecolor"), (True, True)),
        (banner.Env(tty=True, colorterm="24bit"), (True, True)),
        (banner.Env(tty=True, colorterm="TrueColor"), (True, True)),
        (banner.Env(tty=True, colorterm="yes"), (True, False)),
        (banner.Env(tty=True, colorterm="truecolor", no_color="1"), (True, False)),
        (banner.Env(tty=True, colorterm="truecolor", no_color=" "), (True, False)),
        (banner.Env(tty=True, colorterm="truecolor", term="dumb"), (True, False)),
        (banner.Env(tty=True, colorterm="truecolor", term="xterm-256color"), (True, True)),
    ],
)
def test_show(env: banner.Env, expected: tuple[bool, bool]) -> None:
    assert banner.show(env) == expected


def test_env_for_reads_the_stream_and_the_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLORTERM", "truecolor")

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    assert banner.env_for(Tty()) == banner.Env(
        tty=True, no_color="1", term="xterm", colorterm="truecolor"
    )
    assert banner.env_for(io.StringIO()).tty is False
    assert banner.env_for(None).tty is False
    closed = io.StringIO()
    closed.close()
    assert banner.env_for(closed).tty is False  # isatty on a closed stream raises ValueError
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.delenv("COLORTERM")
    env = banner.env_for(io.StringIO())
    assert (env.no_color, env.colorterm) == ("", "")


def test_write_prints_the_copy_asked_for_and_a_blank_line() -> None:
    out = io.StringIO()
    banner.write(out, colour=False)
    assert out.getvalue() == banner.plain() + "\n"
    out = io.StringIO()
    banner.write(out, colour=True)
    assert out.getvalue() == banner.ansi() + "\n"


# --- the CLI --------------------------------------------------------------------------------


def test_off_a_terminal_the_help_carries_no_logo() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert _LOGO_LINE not in result.output
    assert result.output.lstrip().startswith("Usage: dottore")


def test_on_a_terminal_the_logo_comes_above_the_root_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "_banner_env_for", _fake_env(banner.Env(tty=True)))
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert result.output.startswith(banner.plain() + "\n")
    assert "\x1b" not in result.output
    assert "Usage: dottore" in result.output[len(banner.plain()) :]


def test_on_a_24_bit_terminal_the_logo_is_in_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        app_mod, "_banner_env_for", _fake_env(banner.Env(tty=True, colorterm="truecolor"))
    )
    result = runner.invoke(app, ["--help"], color=True)
    assert result.exit_code == 0
    assert result.output.startswith(banner.ansi() + "\n")


def test_a_bare_dottore_prints_the_logo_above_its_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "_banner_env_for", _fake_env(banner.Env(tty=True)))
    result = runner.invoke(app, [])
    assert result.output.startswith(banner.plain() + "\n")
    assert "Usage: dottore" in result.output
    assert result.output.count(_LOGO_LINE) == 1


def test_a_sub_command_help_never_carries_the_logo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        app_mod, "_banner_env_for", _fake_env(banner.Env(tty=True, colorterm="truecolor"))
    )
    for args in (["run", "--help"], ["registry", "--help"], ["registry", "ls", "--help"]):
        result = runner.invoke(app, args, color=True)
        assert result.exit_code == 0, args
        assert _LOGO_LINE not in result.output, args
        assert "%%%" not in result.output, args


def test_held_by_a_parent_group_the_root_help_carries_no_logo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A group that holds ``dottore`` as a sub-command prints that help as a sub-command's."""

    from typer.core import TyperGroup

    monkeypatch.setattr(
        app_mod, "_banner_env_for", _fake_env(banner.Env(tty=True, colorterm="truecolor"))
    )
    parent = TyperGroup(name="outer", commands={"dottore": typer.main.get_command(app)})
    with pytest.raises(SystemExit) as exit_info:
        parent.main(["dottore", "--help"], prog_name="outer")
    out, _ = capsys.readouterr()
    assert exit_info.value.code == 0
    assert _LOGO_LINE not in out
    assert "Usage: outer dottore" in out


def test_a_usage_error_carries_no_logo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_mod, "_banner_env_for", _fake_env(banner.Env(tty=True)))
    result = runner.invoke(app, ["--no-such-option"])
    assert result.exit_code == 3
    assert _LOGO_LINE not in result.output
