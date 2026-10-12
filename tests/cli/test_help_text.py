"""Every ``--help`` reads as user help, not as the source it is built from.

The help of a command is its docstring. Two of them showed internal text to the operator:
``lint`` said "(u02 command body)", a contract unit, and ``fingerprint`` printed reST's double
backticks around ``-sV`` (docs and contracts audit of 2026-10-12); ``fleet``, ``render-media``
and ``diff`` carried the same backticks. The commands are listed from the CLI itself, so a
command added later is checked too.
"""

from __future__ import annotations

import re

import pytest
import typer
from typer.testing import CliRunner

from ildottore.cli.main import app

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _command_paths() -> list[tuple[str, ...]]:
    """Every command path of the CLI, the root first, groups and their subcommands included."""

    root = typer.main.get_command(app)
    paths: list[tuple[str, ...]] = []

    def walk(command: object, path: tuple[str, ...]) -> None:
        paths.append(path)
        # A group has ``commands``; Typer's own click, not the click package, builds it.
        for name, sub in sorted(getattr(command, "commands", {}).items()):
            walk(sub, (*path, name))

    walk(root, ())
    return paths


_PATHS = _command_paths()


def _help(path: tuple[str, ...]) -> str:
    res = runner.invoke(app, [*path, "--help"], env={"COLUMNS": "200", "TERM": "dumb"})
    assert res.exit_code == 0, res.output
    return _ANSI.sub("", res.stdout)


def test_the_listing_reaches_every_command() -> None:
    names = {" ".join(p) for p in _PATHS}
    for expected in ("", "run", "fleet", "lint", "registry ls", "schema export", "diff"):
        assert expected in names


@pytest.mark.parametrize("path", _PATHS, ids=lambda p: " ".join(p) or "dottore")
def test_help_shows_no_internal_text(path: tuple[str, ...]) -> None:
    text = _help(path)
    assert "(u0" not in text
    assert "``" not in text
