"""Terminal rendering (contract §5.4/§6).

Pure rendering functions: a live per-spec progress line and a category x band x repro
summary. Output prints spec ids/statuses/bands/counts only - never a raw payload.
"""

from __future__ import annotations

from ildottore.cli.render import (
    ProgressPrinter,
    coverage_lines,
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


def test_coverage_lines_report_surface_and_disposition() -> None:
    specs = {"PI-1": make_spec("PI-1", owasp="LLM01")}
    lines = coverage_lines([make_finding("PI-1", band=ScanBand.HIGH)], specs)
    assert len(lines) == 4  # a spec that ran adds no warning lines
    # The edition/release travels with the figure: "LLM03 not covered" means the opposite
    # thing under the 2026 renumbering, and ATLAS renames tactics between releases.
    assert "OWASP LLM Top 10 (2025): 1/10 (10%)" in lines[0]
    assert "MITRE ATLAS tactics (2026.09): 1/16" in lines[0]
    # The IoPC axes get their own line: the impact axis is the one a non-technical reader
    # understands, so it must not be buried next to the technique counts.
    assert "IoPC techniques (" in lines[1]  # the axis names its taxonomy version
    assert "IoPC impacts:" in lines[1]
    # And the harm classes are spelled out, because a bare "IOPC-R012" tells nobody anything.
    assert lines[2].startswith("Harm classes tested:")
    # "run X of Y planned": the denominator is what the plan selected, not the length of
    # the finding list, which is how a truncated run used to report 100% of itself.
    assert "Specs run: 1 of 1 planned" in lines[3]
    assert "fail 1" in lines[3]


def test_coverage_lines_name_the_planned_denominator() -> None:
    """A run that produced 1 finding out of 3 planned specs says ``1 of 3``."""

    specs = {"PI-1": make_spec("PI-1", owasp="LLM01")}
    lines = coverage_lines([make_finding("PI-1", band=ScanBand.HIGH)], specs, planned_specs=3)
    assert "Specs run: 1 of 3 planned" in lines[3]


def test_progress_printer_summary_always_prints() -> None:
    printer = ProgressPrinter(quiet=True, no_color=True)
    specs = {"PI-1": make_spec("PI-1", owasp="LLM01")}
    with printer.console.capture() as cap:
        printer.summary([make_finding("PI-1", band=ScanBand.HIGH)], specs)
    out = cap.get()
    assert "LLM01" in out
    assert "Coverage - OWASP LLM Top 10 (2025):" in out


def test_coverage_lines_spell_out_the_harm_classes() -> None:
    """The impact axis must read as harm, not as opaque ids.

    Carrying the impact axis is only worth it if the line is readable without the taxonomy
    open, so the titles are rendered next to nothing: the codes themselves stay in the JSON.
    """

    from ildottore.shared.models import IoPC

    spec = make_spec("PI-1", owasp="LLM01")
    spec = spec.model_copy(update={"iopc": IoPC(impacts=["IOPC-R012", "IOPC-R031"])})
    lines = coverage_lines([make_finding("PI-1", band=ScanBand.HIGH)], {"PI-1": spec})
    harm = next(line for line in lines if line.startswith("Harm classes tested:"))
    assert "Fraud and social engineering content" in harm
    assert "System prompt leak" in harm
