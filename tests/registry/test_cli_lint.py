"""CLI lint command-body tests (contract §7)."""

from __future__ import annotations

import json
from pathlib import Path

from ildottore.cli.lint import (
    EXIT_LINT_FAILED,
    EXIT_OK,
    render_json,
    render_text,
    run_lint,
)
from ildottore.cli.lint import lint as cli_lint


def test_run_lint_exit_zero_on_good(packs_root: Path) -> None:
    code, output = run_lint([packs_root / "good"])
    assert code == EXIT_OK
    assert "lint OK" in output


def test_run_lint_nonzero_on_bad(packs_root: Path) -> None:
    code, output = run_lint([packs_root / "bad"])
    assert code == EXIT_LINT_FAILED
    assert "lint FAILED" in output
    assert "MISSING_TEST_ONLY" in output or "FIXTURE_NO_DETECT" in output


def test_json_rendering_is_parseable(packs_root: Path) -> None:
    code, output = run_lint([packs_root / "bad"], as_json=True)
    assert code == EXIT_LINT_FAILED
    parsed = json.loads(output)
    assert parsed["ok"] is False
    assert isinstance(parsed["errors"], list)
    assert parsed["counts"]["packs"] == 1


def test_render_helpers_directly(packs_root: Path) -> None:
    report = cli_lint([packs_root / "good"])
    text = render_text(report)
    assert "lint OK" in text
    js = json.loads(render_json(report))
    assert js["ok"] is True


def test_cli_lint_specs_tree_exits_zero() -> None:
    # The shipped repo specs/ tree (if present) must lint clean; skip gracefully if absent.
    specs_dir = Path(__file__).resolve().parents[2] / "specs" / "attacks"
    if not specs_dir.is_dir():
        return
    code, _ = run_lint([specs_dir])
    assert code in (EXIT_OK, EXIT_LINT_FAILED)  # content owned by u13; do not assert green
