"""CLI-map golden (contract §7).

Every nmap↔dottore mapping (``docs/09 §1``) is parseable, and the ``docs/09 §3``
cheat-sheet invocations parse without error under ``--dry-run`` (they resolve + send
nothing). Every long option the tool names to an operator is one it accepts. Also covers
spec-selection precedence in :func:`run.select_specs`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import typer
from typer.testing import CliRunner

from ildottore.cli.main import app
from ildottore.cli.run import CATEGORY_ALIASES, select_specs
from ildottore.shared.enums import Category

from .conftest import LONG_OPTION, make_spec, write_scope, write_spec_tree, write_target

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


def test_estimate_plan_counts_requests_and_tokens() -> None:
    """estimate_plan (docs/12 P2) counts requests = specs x runs x mutations x turns."""
    from ildottore.cli.run import estimate_plan

    specs = [make_spec("PI-DIRECT-001"), make_spec("PI-INDIRECT-RAG-001")]
    est = estimate_plan(specs, runs=5)
    assert est.specs == 2
    assert est.requests == 10  # 2 specs x 5 runs x 1 mutation (identity) x 1 turn
    assert est.input_tokens > 0 and est.output_tokens > 0
    assert est.by_category  # populated per category


def test_cli_estimate_prints_and_sends_nothing(tmp_path: Path) -> None:
    """`run --estimate` prints the estimate and makes zero sends (exit 0)."""
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(
        app,
        ["run", "-t", str(target), "--scope", str(scope), "--spec-path", str(specs), "--estimate"],
        env={"COLUMNS": "200", "TERM": "dumb"},
    )
    assert res.exit_code == 0
    assert "estimate:" in res.output and "requests" in res.output


def test_cheatsheet_quick_scan_dry_run(tmp_path: Path) -> None:
    """``--quick`` now SELECTS the T0 suite, so a spec tree without one is refused.

    It used to set the timing template and nothing else, which made this invocation pass
    against any spec tree at all - including this one, which registers no suites. The
    refusal names the registered suites, so a custom pack without a ``quick`` suite gets an
    actionable message instead of a silent full-battery run at T0 timing.
    """

    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(
        app,
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
        ],
    )
    assert res.exit_code == 3
    assert "is not registered" in res.output


def test_quick_narrows_the_battery_against_the_shipped_specs(tmp_path: Path) -> None:
    """``--quick`` selects fewer specs than the default battery (``docs/08 §2`` tier T0).

    Measured against the repo's own ``specs/`` tree, where the ``quick`` suite exists and was
    unselectable by the flag that documents it in six places.
    """

    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    base = ["run", "-t", str(target), "--scope", str(scope), "--spec-path", "specs", "--dry-run"]

    full = runner.invoke(app, base)
    quick = runner.invoke(app, [*base, "--quick"])
    assert full.exit_code == 0 and quick.exit_code == 0, (full.output, quick.output)

    def selected(output: str) -> int:
        match = re.search(r"(\d+) specs selected", output)
        assert match is not None, output
        return int(match.group(1))

    assert 0 < selected(quick.output) < selected(full.output)


def test_discovery_only_sends_nothing_and_says_so(tmp_path: Path) -> None:
    """``-sn`` is "discovery only, no attacks", and it used to send the whole battery.

    The flag was parsed by typer and never read (it was not even a field on ``RunOptions``),
    so an operator typing ``-sn`` against production got the full attack run. It now reports
    what is authorized and what the target declares, and returns.
    """

    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    res = runner.invoke(
        app,
        ["run", "-t", str(target), "-sn", "--scope", str(scope), "--spec-path", "specs"],
    )
    assert res.exit_code == 0
    assert "discovery (-sn): no attacks sent." in res.output
    assert "authorized by the scope" in res.output
    assert "would run" in res.output  # it SAYS what it did not do


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


# --- every long option the tool names is one it accepts (2026-10-07) ------------------

_REPO = Path(__file__).resolve().parents[2]


def _long_options_in(source: str) -> list[tuple[str, int, int]]:
    """Each long option a string literal of ``source`` names, docstrings aside, with the lines
    of the literal it is in (a literal concatenated over several lines is one constant).

    A docstring is a note to whoever reads the code: the planner's and the HTML reporter's name
    `--no-adaptive` and `--unsafe-render`, which are not built (`docs/10 §3`, OD-12). A command's
    docstring that an operator does read is its help text, which the test reads from the
    command tree instead.
    """

    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    return [
        (flag, node.lineno, node.end_lineno or node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
        for flag in LONG_OPTION.findall(node.value)
    ]


def test_the_option_scan_reads_messages_and_leaves_docstrings_out() -> None:
    """The instrument fires: a refusal like the one that shipped is caught, one line split over an
    f-string and a concatenation included and reported with the lines of the literal (on 3.12 and
    later, of its constant part), a wrong flag that runs on past a right one in letters, digits, `_`
    or `-` is read whole, and a docstring is not read."""

    source = (
        "def f(run_id, wall):\n"
        '    """A note naming --not-a-flag."""\n'
        "    raise ValueError(\n"
        '        f"run {run_id!r} spent {wall}s. Raise "\n'
        '        "--budget-wall-s for this campaign, or pass --dry-run. (not a--flag)"\n'
        '        " Not --budget-wall_s, --budget-wall-S or --budget-wall-; --budget-wall=60."\n'
        "    )\n"
    )

    found = _long_options_in(source)
    assert [flag for flag, _, _ in found] == [
        "--budget-wall-s",
        "--dry-run",
        "--budget-wall_s",
        "--budget-wall-S",
        "--budget-wall-",
        "--budget-wall",
    ]
    assert {(first, last) for _, first, last in found} == {(4, 6)}


def test_every_long_option_the_tool_names_is_one_it_accepts() -> None:
    """A flag the tool tells an operator to pass has to exist on some command.

    The resume refusal for a spent wall-clock ceiling said "Raise --budget-wall-s", and
    `dottore run` answers that with "No such option": the flag is `--budget-wall` (2026-10-07).
    Read here: every string literal under `src/ildottore` but the docstrings, and every help
    text the command tree renders. Long options only (`LONG_OPTION`: two dashes, then a lowercase
    ASCII letter, read up to the first character that is not a letter, a digit, `_` or `-`), since a
    short one is ambiguous in prose and in patterns (`-vv` is `-v` twice, `-rf` sits in a
    regex). Accepted: every option of every command and group, and the help option. A flag that
    belongs to another program (an example command line, a pattern) goes in a docstring or out
    of the literal.
    """

    accepted: set[str] = set()
    rendered: list[str] = []
    pending = [typer.main.get_command(app)]
    while pending:
        command = pending.pop()
        accepted.update(
            command.make_context("dottore", [], resilient_parsing=True).help_option_names
        )
        rendered += [text for text in (command.help, command.short_help, command.epilog) if text]
        for param in command.params:
            accepted.update((*param.opts, *param.secondary_opts))
            rendered += [param.help] if getattr(param, "help", None) else []
        pending += getattr(command, "commands", {}).values()

    named: dict[str, list[str]] = {}
    for path in sorted((_REPO / "src" / "ildottore").rglob("*.py")):
        for flag, first, last in _long_options_in(path.read_text(encoding="utf-8")):
            lines = f"{first}" if first == last else f"{first}-{last}"
            named.setdefault(flag, []).append(f"{path.relative_to(_REPO)}:{lines}")
    for text in rendered:
        for flag in LONG_OPTION.findall(text):
            named.setdefault(flag, []).append("a help text")

    assert len(named) > 20, f"the scan found almost nothing to check: {sorted(named)}"
    unknown = {flag: where for flag, where in named.items() if flag not in accepted}
    assert not unknown, f"no dottore command accepts these, yet the tool names them: {unknown}"
