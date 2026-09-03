"""``dottore lint`` command body (contract §5.5).

u12 wires this into the Typer app later; this module only provides the pure functions:

* :func:`lint` - load + lint search paths → :class:`~ildottore.registry.LintReport`.
* :func:`render_text` / :func:`render_json` - the two renderings (contract §6).
* :func:`run_lint` - the callable u12's command delegates to; returns a process exit code
  (0 = clean, 1 = any error-severity finding) and the rendered output string.

No side effects beyond reading the given paths (no exec, no network).
"""

from __future__ import annotations

import json
from pathlib import Path

from ildottore.registry import LintError, LintReport
from ildottore.registry import lint as _lint

EXIT_OK = 0
EXIT_LINT_FAILED = 1


def lint(paths: list[Path]) -> LintReport:
    """Load + lint the given search paths (contract §5.5 entry point)."""
    return _lint(paths)


def render_json(report: LintReport) -> str:
    """Machine-parseable rendering (contract §6)."""
    return json.dumps(report.model_dump_report(), indent=2, sort_keys=True)


def render_text(report: LintReport) -> str:
    """Human-readable rendering (contract §6)."""
    lines: list[str] = []
    c = report.counts
    for err in report.errors:
        lines.append(_fmt_line(err, "ERROR"))
    for warn in report.warnings:
        lines.append(_fmt_line(warn, "WARN"))
    status = "OK" if report.ok else "FAILED"
    lines.append(
        f"lint {status}: {len(report.errors)} error(s), {len(report.warnings)} warning(s) "
        f"across {c.specs} spec(s), {c.suites} suite(s), {c.packs} pack(s)"
    )
    return "\n".join(lines)


def _fmt_line(err: LintError, level: str) -> str:
    loc = err.spec_id or err.path or "-"
    return f"[{level}] {err.code} ({loc}): {err.message}"


def run_lint(paths: list[Path], *, as_json: bool = False) -> tuple[int, str]:
    """Lint ``paths`` and return ``(exit_code, rendered_output)``."""
    report = lint(paths)
    output = render_json(report) if as_json else render_text(report)
    exit_code = EXIT_OK if report.ok else EXIT_LINT_FAILED
    return exit_code, output
