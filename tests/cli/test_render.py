"""Terminal rendering (contract §5.4/§6).

Pure rendering functions: a live per-spec progress line and a category x band x repro
summary. Output prints spec ids/statuses/bands/counts only — never a raw payload.
"""

from __future__ import annotations

from ildottore.cli.render import (
    ProgressPrinter,
    progress_line,
    summary_rows,
    summary_table,
)
from ildottore.shared.enums import Category, ScanBand

from .conftest import make_finding, make_spec


def test_progress_line_shape() -> None:
    finding = make_finding("PI-DIRECT-001", band=ScanBand.HIGH)
    line = progress_line(34, 60, "PI-DIRECT-001", finding)
    assert line == "Scanning target [ 34/60 specs ] PI-DIRECT-001 ... FAIL (high)"


def test_summary_rows_aggregate_by_category_and_band() -> None:
    specs = {
        "PI-DIRECT-001": make_spec("PI-DIRECT-001", owasp="LLM01"),
        "JB-ROLEPLAY-001": make_spec("JB-ROLEPLAY-001", category=Category.JAILBREAK, owasp="LLM01"),
    }
    findings = [
        make_finding("PI-DIRECT-001", band=ScanBand.HIGH),
        make_finding("JB-ROLEPLAY-001", band=ScanBand.HIGH),
    ]
    rows = summary_rows(findings, specs)
    assert len(rows) == 1  # same owasp+band collapses
    assert rows[0].category == "LLM01"
    assert rows[0].band == "high"
    assert rows[0].count == 2


def test_summary_rows_unknown_spec_labelled_unknown() -> None:
    findings = [make_finding("ORPHAN-1", band=ScanBand.LOW)]
    rows = summary_rows(findings, {})
    assert rows[0].category == "unknown"


def test_summary_rows_sorted_deterministically() -> None:
    specs = {
        "A-1": make_spec("A-1", owasp="LLM01"),
        "B-1": make_spec("B-1", owasp="LLM02"),
    }
    findings = [
        make_finding("B-1", band=ScanBand.LOW),
        make_finding("A-1", band=ScanBand.CRITICAL),
    ]
    rows = summary_rows(findings, specs)
    assert [r.category for r in rows] == ["LLM01", "LLM02"]


def test_summary_table_builds_rich_table() -> None:
    specs = {"PI-1": make_spec("PI-1", owasp="LLM01")}
    findings = [make_finding("PI-1", band=ScanBand.HIGH)]
    table = summary_table(findings, specs)
    assert table.row_count == 1
    assert table.title is not None


def test_progress_printer_quiet_suppresses_progress() -> None:
    printer = ProgressPrinter(quiet=True)
    with printer.console.capture() as cap:
        printer.progress(1, 2, "PI-1", make_finding("PI-1"))
    assert cap.get() == ""


def test_progress_printer_prints_when_not_quiet() -> None:
    printer = ProgressPrinter(no_color=True)
    with printer.console.capture() as cap:
        printer.progress(1, 2, "PI-1", make_finding("PI-1", band=ScanBand.HIGH))
    assert "PI-1" in cap.get()


def test_progress_printer_summary_always_prints() -> None:
    printer = ProgressPrinter(quiet=True, no_color=True)
    specs = {"PI-1": make_spec("PI-1", owasp="LLM01")}
    with printer.console.capture() as cap:
        printer.summary([make_finding("PI-1", band=ScanBand.HIGH)], specs)
    out = cap.get()
    assert "LLM01" in out
