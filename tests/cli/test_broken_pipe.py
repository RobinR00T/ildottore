"""A real broken pipe exits 3, never 1 (u12 A-80; pre-merge audit of `e6a1ab9b`, MEDIUM 2).

The guard caught the first `BrokenPipeError` and asked for exit 3, then the context's close
callback reconfigured stdout, flushing into the closed pipe again, and the command-line library
turned that second error into exit 1: `registry ls`, `lint`, `describe` and `coverage` piped into
a reader that had gone, and a live scan with findings, which sent its requests and exited 1 with
nothing said. Each command here writes into a pipe whose reader is closed before it starts.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ildottore.shared.package_data import BATTERY

from .conftest import make_spec, write_scope, write_spec_tree, write_target

REPO = Path(__file__).resolve().parents[2]

_ENTRY = (
    "import sys; sys.path[:0] = [sys.argv[1], sys.argv[2]]; sys.argv = ['dottore', *sys.argv[3:]]\n"
    "from ildottore.cli.main import app; app()"
)


def _into_a_closed_reader(cwd: Path, *argv: str) -> tuple[int, str]:
    env = {**os.environ, "MOCK_KEY": "x", "NO_COLOR": "1"}
    proc = subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-c", _ENTRY, str(REPO / "src"), str(REPO), *argv],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert proc.stdout is not None and proc.stderr is not None
    proc.stdout.close()  # the reader goes before the command writes anything
    err = proc.stderr.read().decode("utf-8", "replace")
    proc.stderr.close()
    return proc.wait(timeout=180), err


@pytest.mark.parametrize(
    "argv",
    [
        ["registry", "ls", "--spec-path", str(BATTERY)],
        ["lint", str(BATTERY)],
        ["describe", "PI-DIRECT-001", "--spec-path", str(BATTERY)],
        ["coverage", str(BATTERY)],
    ],
    ids=["registry-ls", "lint", "describe", "coverage"],
)
def test_a_read_only_command_into_a_closed_reader_exits_3(tmp_path: Path, argv: list[str]) -> None:
    code, err = _into_a_closed_reader(tmp_path, *argv)
    assert code == 3, err
    assert "error: the output stream closed before the command finished (broken pipe)" in err
    assert "Traceback" not in err
    assert "Exception ignored" not in err


@pytest.mark.parametrize("mode", ["--dry-run", "findings"])
def test_a_run_into_a_closed_reader_exits_3(tmp_path: Path, mode: str) -> None:
    """A scan with findings (exit 2 into a live reader) is not reported as 1 into a dead one."""

    target = write_target(tmp_path, mock_scenario="vulnerable")
    scope = write_scope(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    argv = ["run", str(target), "--scope", str(scope), "--spec-path", str(specs), "--runs", "1"]
    argv += ["--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.db")]
    argv += ["--dry-run", "-vv"] if mode == "--dry-run" else []
    code, err = _into_a_closed_reader(tmp_path, *argv)
    assert code == 3, err
    assert "broken pipe" in err
    assert "Exception ignored" not in err


@pytest.mark.parametrize(
    "argv", [["--help"], ["run", "--help"], []], ids=["help", "run-help", "none"]
)
def test_help_into_a_closed_reader_exits_3(tmp_path: Path, argv: list[str]) -> None:
    """Help is printed while the root context is being made, outside the guard, and the library
    answered its broken pipe with exit 1 (found re-running the audit's pipe checks)."""

    code, err = _into_a_closed_reader(tmp_path, *argv)
    assert code == 3, err
    assert "broken pipe" in err
    assert "Exception ignored" not in err
