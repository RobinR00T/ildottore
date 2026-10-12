"""``dottore lint`` command body (contract §5.5).

u12 wires this into the Typer app later; this module only provides the pure functions:

* :func:`lint` - load + lint search paths → :class:`~ildottore.registry.LintReport`.
* :func:`render_text` / :func:`render_json` - the two renderings (contract §6).
* :func:`run_lint` - the callable u12's command delegates to; returns a process exit code
  (0 = clean, 1 = any error-severity finding, 3 = a path that does not exist or yields nothing
  to lint, which wins over 1) and the rendered output string.

No side effects beyond reading the given paths (no exec, no network).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ildottore.redactor import log_safe_json, visible_controls
from ildottore.registry import PATH_CODES, LintCode, LintError, LintReport, Severity
from ildottore.registry import lint as _lint

EXIT_OK = 0
EXIT_LINT_FAILED = 1
#: A path that does not exist or yields nothing to lint (``PATH_NOT_FOUND``, ``NO_SPECS``): the
#: I/O code of every other command, and it wins over 1 (u12 A-82, CLI audit M9). ``lint
#: nonexistent`` exited 1, and a path holding no spec printed ``lint OK`` and exited 0.
EXIT_IO = 3


def lint(paths: list[Path]) -> LintReport:
    """Load + lint the given search paths (contract §5.5 entry point).

    The registered mutator names (built-ins plus installed plugins) are passed in so lint can
    refuse a mutation that names none of them; ``registry`` cannot import ``mutators`` itself.
    """
    from ildottore.mutators import build_default_registry

    # Loading plugins is new here, and a broken one used to crash lint with a traceback and
    # exit 1, the code for "your specs failed lint" (review of PR #32). It is reported instead.
    plugin_error: LintError | None = None
    try:
        registry = build_default_registry()
    except Exception as exc:
        registry = build_default_registry(discover=False)
        plugin_error = LintError(
            code=LintCode.MUTATOR_PLUGIN_ERROR,
            severity=Severity.WARNING,
            message=f"an installed mutator plugin could not be loaded ({exc}); linted with "
            "the built-in mutators only",
        )
    known = frozenset(registry.names())
    params = {
        name: frozenset(accepted)
        for name in known
        if (accepted := getattr(registry.get(name), "accepted_params", None)) is not None
    }
    report = _lint(paths, known_mutators=known, mutator_params=params)
    if plugin_error is None:
        return report
    return report.model_copy(update={"warnings": [plugin_error, *report.warnings]})


def render_json(report: LintReport) -> str:
    """Machine-parseable rendering (contract §6), with no CI log command in its bytes (OD-20)."""
    return log_safe_json(json.dumps(report.model_dump_report(), indent=2, sort_keys=True))


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


def _masked_paths(report: LintReport, mask: Callable[[str], str]) -> LintReport:
    """``report`` with the findings that quote a search path passed through ``mask``."""

    def masked(found: LintError) -> LintError:
        if found.code not in _PATH_FINDINGS:
            return found
        update: dict[str, object] = {"message": mask(found.message)}
        if found.path is not None:
            update["path"] = mask(found.path)
        return found.model_copy(update=update)

    return report.model_copy(
        update={
            "errors": [masked(e) for e in report.errors],
            "warnings": [masked(w) for w in report.warnings],
        }
    )


#: The findings whose text is a search path the operator typed.
_PATH_FINDINGS = PATH_CODES | {LintCode.FILES_NOT_READ}


def _fmt_line(err: LintError, level: str) -> str:
    # A pack's file names and values, written out: a file named `x\n::error ...` printed a
    # line GitHub Actions reads as a workflow command (pre-merge audit of PR #49).
    loc = visible_controls(err.spec_id or err.path or "-")
    return f"[{level}] {err.code} ({loc}): {visible_controls(err.message)}"


def run_lint(
    paths: list[Path], *, as_json: bool = False, mask: Callable[[str], str] | None = None
) -> tuple[int, str]:
    """Lint ``paths`` and return ``(exit_code, rendered_output)``.

    ``mask`` is applied to the findings that quote a search path as the operator typed it
    (``PATH_NOT_FOUND``, ``NO_SPECS``, ``FILES_NOT_READ``): the CLI passes its redactor, so a key
    given where a path belongs is not echoed (u12 A-82). The other findings quote a spec tree's
    contents, which lint reports as they are.
    """
    report = lint(paths)
    if mask is not None:
        report = _masked_paths(report, mask)
    output = render_json(report) if as_json else render_text(report)
    if any(e.code in PATH_CODES for e in report.errors):
        return EXIT_IO, output
    exit_code = EXIT_OK if report.ok else EXIT_LINT_FAILED
    return exit_code, output
