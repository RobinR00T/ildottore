"""HTML reporter: autoescape, --unsafe-render gate, evidence inline+ref (contract §7; OD-12)."""

from __future__ import annotations

from ildottore.reporting.html_reporter import UNSAFE_RENDER_BANNER, HtmlReporter
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import TestRun
from tests.reporting.conftest import make_finding, make_run, make_spec


def _html(reporter: HtmlReporter, run: TestRun) -> str:
    return reporter.render(run, list(run.findings)).decode("utf-8")


def test_renders_without_error() -> None:
    run = make_run(findings=[make_finding()])
    html = _html(HtmlReporter(specs={"PI-DEMO-001": make_spec()}), run)
    assert "Il Dottore" in html
    assert "PI-DEMO-001" in html


def test_script_escaped_when_unsafe_off() -> None:
    run = make_run(findings=[make_finding(reasoning="<script>alert(1)</script>")])
    html = _html(HtmlReporter(), run)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_no_banner_by_default() -> None:
    run = make_run(findings=[make_finding()])
    html = _html(HtmlReporter(), run)
    assert UNSAFE_RENDER_BANNER not in html


def test_unsafe_render_emits_raw_and_banner() -> None:
    run = make_run(findings=[make_finding(reasoning="<b>bold</b>")])
    html = _html(HtmlReporter(unsafe_render=True), run)
    assert UNSAFE_RENDER_BANNER in html
    assert "<b>bold</b>" in html


def test_evidence_ref_rendered() -> None:
    run = make_run(findings=[make_finding(with_evidence=True)])
    html = _html(HtmlReporter(), run)
    assert "evidence://run-1/a1.json" in html
    assert "sha256:deadbeef" in html


def test_confirmed_and_needs_review_sections() -> None:
    findings = [
        make_finding("PI-DEMO-001", confirmed=True),
        make_finding("DL-DEMO-002", confirmed=False, status=VerdictStatus.INCONCLUSIVE),
    ]
    run = make_run(findings=findings)
    html = _html(HtmlReporter(), run)
    assert "Confirmed findings (1)" in html
    assert "Needs review (1)" in html


def test_model_comparison_table_multi_target() -> None:
    findings = [
        make_finding(target_id="t-a", band=ScanBand.CRITICAL),
        make_finding(target_id="t-b", band=ScanBand.LOW),
    ]
    run = make_run(findings=findings, targets=[])
    html = _html(HtmlReporter(specs={"PI-DEMO-001": make_spec()}), run)
    assert "Model comparison" in html
    assert "t-a" in html and "t-b" in html


def test_long_reasoning_is_excerpted() -> None:
    long_reason = "A" * 500
    run = make_run(findings=[make_finding(reasoning=long_reason)])
    html = _html(HtmlReporter(), run)
    assert "…" in html
    assert "A" * 500 not in html


def test_none_reasoning_omits_block() -> None:
    run = make_run(findings=[make_finding(reasoning=None)])
    html = _html(HtmlReporter(), run)
    assert 'class="reasoning"' not in html


def test_deterministic() -> None:
    run = make_run(findings=[make_finding()])
    reporter = HtmlReporter(specs={"PI-DEMO-001": make_spec()})
    assert reporter.render(run, list(run.findings)) == reporter.render(run, list(run.findings))
