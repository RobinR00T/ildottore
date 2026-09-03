"""Terminal rendering: live per-spec progress + the summary table (contract §5.4/§6).

nmap-style output ergonomics (``docs/09 §4``): a live progress line per spec while a
run streams, then a category x severity-band x reproducibility summary table. All
strings are produced by **pure** functions (testable without a TTY); a thin
:class:`ProgressPrinter` wraps a :class:`rich.console.Console` for the interactive path
and honours ``--no-color``/``-q``.

Every value that reaches the terminal is already redacted upstream (findings carry no
raw secrets; the redactor is the choke point in the stores/reporters). This module
prints spec ids, statuses, bands and counts only - never a raw payload or response
(contract §6, ``AGENTS.md §2``).
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from ildottore.reporting.summary import build_run_summary
from ildottore.shared.enums import ScanBand
from ildottore.shared.models import AttackSpec, Finding

__all__ = [
    "ProgressPrinter",
    "coverage_lines",
    "progress_line",
    "summary_rows",
    "summary_table",
]

_BAND_ORDER = [
    ScanBand.CRITICAL.value,
    ScanBand.HIGH.value,
    ScanBand.MEDIUM.value,
    ScanBand.LOW.value,
    ScanBand.INFO.value,
]


def progress_line(index: int, total: int, spec_id: str, finding: Finding) -> str:
    """Format one nmap-style progress line for a completed spec.

    Example: ``Scanning target [ 34/60 specs ] PI-DIRECT-001 ... FAIL (high)``.
    """

    status = finding.status.value.upper()
    band = finding.risk.band.value
    return f"Scanning target [ {index}/{total} specs ] {spec_id} ... {status} ({band})"


@dataclass(frozen=True)
class _Row:
    category: str
    band: str
    count: int
    max_repro: float


def summary_rows(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> list[_Row]:
    """Aggregate findings into ``(category, band, count, max_repro)`` rows (sorted).

    Category comes from the originating spec's OWASP id (``unknown`` when the spec is
    absent from ``specs``). Rows are sorted by category then band severity so the
    table layout is deterministic (replay-stable, contract §7).
    """

    spec_map = specs or {}
    agg: dict[tuple[str, str], _Row] = {}
    for finding in findings:
        spec = spec_map.get(finding.spec_id)
        category = spec.owasp if spec is not None else "unknown"
        band = finding.risk.band.value
        key = (category, band)
        existing = agg.get(key)
        if existing is None:
            agg[key] = _Row(category, band, 1, finding.risk.reproducibility)
        else:
            agg[key] = _Row(
                category,
                band,
                existing.count + 1,
                max(existing.max_repro, finding.risk.reproducibility),
            )

    def _sort_key(row: _Row) -> tuple[str, int]:
        band_rank = _BAND_ORDER.index(row.band) if row.band in _BAND_ORDER else len(_BAND_ORDER)
        return (row.category, band_rank)

    return sorted(agg.values(), key=_sort_key)


def summary_table(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> Table:
    """Build the rich summary :class:`~rich.table.Table` (category x band x repro)."""

    table = Table(title="Il Dottore: scan summary")
    table.add_column("Category", style="cyan")
    table.add_column("Band")
    table.add_column("Count", justify="right")
    table.add_column("Max repro", justify="right")
    for row in summary_rows(findings, specs):
        table.add_row(
            row.category,
            f"[{_band_style(row.band)}]{row.band}[/]",
            str(row.count),
            f"{row.max_repro:.2f}",
        )
    return table


def coverage_lines(
    findings: list[Finding],
    specs: dict[str, AttackSpec] | None = None,
) -> list[str]:
    """Format the coverage block for the terminal summary (``docs/12`` P1).

    Reports the fraction of the OWASP LLM Top 10 and MITRE ATLAS tactic matrix the run
    exercised, plus specs run/pass/fail/inconclusive, so a green run over a narrow suite
    cannot read as broad assurance. Pure (no TTY); the caller routes it to the console.
    """

    cov = build_run_summary(findings, specs or {}).coverage
    return [
        (
            f"Coverage - OWASP LLM Top 10: {cov.owasp_exercised}/{cov.owasp_total} "
            f"({cov.owasp_pct * 100:.0f}%) · "
            f"MITRE ATLAS tactics: {cov.atlas_exercised}/{cov.atlas_total} "
            f"({cov.atlas_pct * 100:.0f}%)"
        ),
        (
            f"Specs run: {cov.specs_run} · pass {cov.specs_pass} · "
            f"fail {cov.specs_fail} · inconclusive {cov.specs_inconclusive}"
        ),
    ]


def _band_style(band: str) -> str:
    return {
        ScanBand.CRITICAL.value: "bold red",
        ScanBand.HIGH.value: "red",
        ScanBand.MEDIUM.value: "yellow",
        ScanBand.LOW.value: "green",
        ScanBand.INFO.value: "dim",
    }.get(band, "")


class ProgressPrinter:
    """Thin, TTY-aware wrapper over a :class:`rich.console.Console`.

    Honours ``no_color`` and ``quiet`` (``-q`` suppresses per-spec progress but keeps
    the final summary). Pure rendering lives in the module functions; this only routes
    the strings to the console so the commands stay declarative.
    """

    def __init__(self, *, no_color: bool = False, quiet: bool = False) -> None:
        self._console = Console(no_color=no_color, highlight=False)
        self._quiet = quiet

    @property
    def console(self) -> Console:
        return self._console

    def progress(self, index: int, total: int, spec_id: str, finding: Finding) -> None:
        """Print one progress line (suppressed under ``-q``)."""

        if self._quiet:
            return
        self._console.print(progress_line(index, total, spec_id, finding))

    def summary(self, findings: list[Finding], specs: dict[str, AttackSpec] | None = None) -> None:
        """Print the summary table + coverage block (always shown, even under ``-q``)."""

        self._console.print(summary_table(findings, specs))
        for line in coverage_lines(findings, specs):
            self._console.print(line)
