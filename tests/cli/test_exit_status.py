"""An exit whose code is no exit status is an internal error, said masked, exit 3 (u12 A-83).

Exit 1 means "findings below --fail-on" and 0 a clean scan (A-9), so a code that is neither a
number the tool asks for nor nothing must not reach the process as one of them. On ``7d01521f``:

* ``typer.Exit("<text>")`` exited 0 with nothing said, through ``run_masked`` (A-82), which read
  any code that is not an integer as 0; before A-82 it exited 1 with the text in clear, as Python
  reads ``sys.exit("<text>")``. A bool exited 0, where Python reads ``True`` as 1, and a number
  past 255 reached ``sys.exit``, which POSIX cuts to its low 8 bits (256 is 0).
* ``SystemExit("<text>")`` raised in a command exited 3, but its line quoted the text unmasked
  (since #114, A-80): a registered credential and a key printed in clear.

Each case runs through the console entry point (``ildottore.cli.main:main``) in a process of its
own, with ``registry ls`` made to raise, and through the test runner, which calls the root
command's standalone ``main`` as ``app()`` does.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ildottore.cli import registry as registry_mod
from ildottore.cli.app import app
from ildottore.redactor import register_known_secret

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

REPO = Path(__file__).resolve().parents[2]
#: A credential the process registers, and a key it masks by its shape only.
REGISTERED = "Qm7vX2pL9kR4tN8w"
KEY = "sk-ant-api03-Z8xC2vB6nM1qW5eR9tY3uI7oP4aS0dF-GhJkLzXcVbNmQwEr"
TEXT = f"stopped with {REGISTERED} and {KEY}"
FRAGMENTS = [s[i : i + 8] for s in (REGISTERED, KEY) for i in range(0, len(s) - 8, 4)]

#: (what the command raises, as Python source, the exit code, whether the line is said)
CASES = {
    "typer-exit-text": ("typer.Exit(TEXT)", 3, True),
    "system-exit-text": ("SystemExit(TEXT)", 3, True),
    "typer-exit-true": ("typer.Exit(True)", 3, True),
    "typer-exit-false": ("typer.Exit(False)", 3, True),
    "typer-exit-256": ("typer.Exit(256)", 3, True),
    "typer-exit-negative": ("typer.Exit(-1)", 3, True),
    "system-exit-256": ("SystemExit(256)", 3, True),
    "system-exit-true": ("SystemExit(True)", 3, True),
    "typer-exit-none": ("typer.Exit(None)", 0, False),
    "typer-exit-0": ("typer.Exit(0)", 0, False),
    "typer-exit-1": ("typer.Exit(1)", 1, False),
    "typer-exit-2": ("typer.Exit(2)", 2, False),
    "typer-exit-130": ("typer.Exit(130)", 130, False),
    "system-exit-0": ("SystemExit(0)", 0, False),
    "system-exit-4": ("SystemExit(4)", 4, False),
}

_DRIVER = """
import sys
import typer
from ildottore.cli import registry as registry_mod
from ildottore.cli.main import main
from ildottore.redactor import register_known_secret
REGISTERED, KEY, raised, specs = sys.argv[1:5]
TEXT = f"stopped with {REGISTERED} and {KEY}"
register_known_secret(REGISTERED)
def boom(*args, **kwargs):
    raise eval(raised)
registry_mod.render_spec_rows = boom
main(["registry", "ls", "--spec-path", specs])
"""


def _assert_said(code: int, stderr: str, expected: int, said: bool) -> None:
    assert code == expected, stderr
    line = "error: unexpected exit with status "
    assert (line in stderr) is said, stderr
    for fragment in FRAGMENTS:
        assert fragment not in stderr, stderr


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_console_entry_point(case: str) -> None:
    raised, expected, said = CASES[case]
    result = subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-c", _DRIVER, REGISTERED, KEY, raised, str(REPO / "specs")],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    _assert_said(result.returncode, result.stderr, expected, said)
    if case.endswith("-text"):
        assert "«REDACTED:credential:" in result.stderr, result.stderr
        assert result.stderr.count("«REDACTED:") == 2, result.stderr


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_test_runner(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    raised, expected, said = CASES[case]
    register_known_secret(REGISTERED)
    namespace = {"typer": typer, "TEXT": TEXT}

    def boom(*args: object, **kwargs: object) -> object:
        raise eval(raised, namespace)  # noqa: S307 - the table above, not input

    monkeypatch.setattr(registry_mod, "render_spec_rows", boom)
    result = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(REPO / "specs")])
    _assert_said(result.exit_code, result.stderr, expected, said)


def test_a_status_whose_repr_fails_is_still_an_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Unprintable:
        def __repr__(self) -> str:
            raise RuntimeError("no")

    def boom(*args: object, **kwargs: object) -> object:
        raise typer.Exit(Unprintable())  # type: ignore[arg-type]

    monkeypatch.setattr(registry_mod, "render_spec_rows", boom)
    result = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(REPO / "specs")])
    assert result.exit_code == 3
    assert "unexpected exit with status <unprintable status>" in result.stderr
