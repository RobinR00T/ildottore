"""CLI-map golden (contract §7).

Every nmap↔dottore mapping (``docs/09 §1``) is parseable, and the ``docs/09 §3``
cheat-sheet invocations parse without error under ``--dry-run`` (they resolve + send
nothing). Also covers spec-selection precedence in :func:`run.select_specs`.
"""

from __future__ import annotations

import re
from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli.main import app
from ildottore.cli.run import CATEGORY_ALIASES, select_specs
from ildottore.shared.enums import Category

from .conftest import make_spec, write_scope, write_spec_tree, write_target

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _help_text(args: list[str]) -> str:
    """Rich/Typer help rendered wide + ANSI-stripped, so substring checks are independent of
    the runner's terminal width (CI has no TTY → rich wraps to 80 cols and truncates flags)."""
    res = runner.invoke(app, args, env={"COLUMNS": "200", "TERM": "dumb"})
    assert res.exit_code == 0
    return _ANSI.sub("", res.stdout)


def _dry(args: list[str]) -> int:
    return runner.invoke(app, args).exit_code


def test_root_help_lists_all_commands() -> None:
    out = _help_text(["--help"])
    for cmd in ("run", "fingerprint", "lint", "registry", "describe", "new-spec", "replay"):
        assert cmd in out


def test_version_flag() -> None:
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "dottore" in res.stdout


def test_run_help_exposes_nmap_style_flags() -> None:
    out = _help_text(["run", "--help"])
    for flag in ("-sV", "-A", "--quick", "--deep", "-T", "--suite", "--scope", "-oJ", "--fail-on"):
        assert flag in out


def test_cheatsheet_quick_scan_dry_run(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    code = _dry(
        [
            "run",
            "-t",
            str(target),
            "--quick",
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--dry-run",
        ]
    )
    assert code == 0


def test_cheatsheet_sv_suite_multiformat_dry_run(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    code = _dry(
        [
            "run",
            "-sV",
            "-p",
            "pi,leakage",
            "-T",
            "4",
            "--fail-on",
            "high",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--dry-run",
        ]
    )
    assert code == 0


def test_cheatsheet_aggressive_adaptive_budget_dry_run(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    code = _dry(
        [
            "run",
            "-A",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--dry-run",
        ]
    )
    assert code == 0


def test_category_aliases_cover_all_categories() -> None:
    # Every canonical Category is reachable via at least one -p token.
    reachable = set(CATEGORY_ALIASES.values())
    assert reachable == set(Category)


def test_select_specs_by_category() -> None:
    pi = make_spec("PI-1", category=Category.PROMPT_INJECTION)
    jb = make_spec("JB-1", category=Category.JAILBREAK)
    out = select_specs([pi, jb], categories=["pi"])
    assert [s.id for s in out] == ["PI-1"]


def test_select_specs_by_glob() -> None:
    pi = make_spec("PI-DIRECT-001")
    jb = make_spec("JB-ROLEPLAY-001", category=Category.JAILBREAK)
    out = select_specs([pi, jb], spec_globs=["PI-*"])
    assert [s.id for s in out] == ["PI-DIRECT-001"]


def test_select_specs_exclude_removes_matches() -> None:
    pi = make_spec("PI-DIRECT-001")
    jb = make_spec("JB-ROLEPLAY-001", category=Category.JAILBREAK)
    out = select_specs([pi, jb], exclude_globs=["JB-*"])
    assert [s.id for s in out] == ["PI-DIRECT-001"]


def test_select_specs_top_tests_keeps_highest_signal_in_order() -> None:
    low = make_spec("LOW-1", impact=1, exploitability=1)
    high = make_spec("HIGH-1", impact=4, exploitability=4)
    mid = make_spec("MID-1", impact=3, exploitability=2)
    out = select_specs([low, high, mid], top_tests=2)
    # Highest signal kept (HIGH, MID); original order preserved.
    assert [s.id for s in out] == ["HIGH-1", "MID-1"]


def test_select_specs_suite_seeds_base_set() -> None:
    a = make_spec("A-1")
    b = make_spec("B-1", category=Category.JAILBREAK)
    c = make_spec("C-1")
    out = select_specs([a, b, c], suite_specs=[a, b])
    assert {s.id for s in out} == {"A-1", "B-1"}
