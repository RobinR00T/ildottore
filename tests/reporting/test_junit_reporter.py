"""JUnit reporter: well-formed XML, verdict→element mapping (contract §7)."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from ildottore.reporting.junit_reporter import JunitReporter
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import TestRun
from tests.reporting.conftest import make_finding, make_run, make_spec


def _parse(reporter: JunitReporter, run: TestRun) -> ET.Element:
    xml = reporter.render(run, list(run.findings))
    # Parsing bytes the reporter itself produced; the assertion is well-formedness.
    return ET.fromstring(xml.decode("utf-8"))  # noqa: S314


def test_well_formed_and_root() -> None:
    run = make_run(findings=[make_finding()])
    root = _parse(JunitReporter(specs={"PI-DEMO-001": make_spec()}), run)
    assert root.tag == "testsuites"
    assert root.get("name") == "run-1"


def test_fail_becomes_failure() -> None:
    run = make_run(findings=[make_finding(status=VerdictStatus.FAIL)])
    root = _parse(JunitReporter(specs={"PI-DEMO-001": make_spec()}), run)
    case = root.find(".//testcase")
    assert case is not None
    assert case.get("name") == "PI-DEMO-001"
    assert case.find("failure") is not None


def test_inconclusive_becomes_skipped() -> None:
    run = make_run(findings=[make_finding(status=VerdictStatus.INCONCLUSIVE, band=ScanBand.INFO)])
    root = _parse(JunitReporter(), run)
    case = root.find(".//testcase")
    assert case is not None
    assert case.find("skipped") is not None


def test_pass_is_clean_testcase() -> None:
    run = make_run(findings=[make_finding(status=VerdictStatus.PASS, band=ScanBand.INFO)])
    root = _parse(JunitReporter(), run)
    case = root.find(".//testcase")
    assert case is not None
    assert case.find("failure") is None
    assert case.find("skipped") is None


def test_suites_grouped_by_framework() -> None:
    specs = {
        "PI-DEMO-001": make_spec("PI-DEMO-001", owasp="LLM01"),
        "DL-DEMO-002": make_spec("DL-DEMO-002", owasp="LLM02"),
    }
    findings = [make_finding("PI-DEMO-001"), make_finding("DL-DEMO-002")]
    run = make_run(findings=findings)
    root = _parse(JunitReporter(specs=specs), run)
    suite_names = sorted(s.get("name", "") for s in root.findall("testsuite"))
    assert suite_names == ["LLM01", "LLM02"]


def test_counts_aggregate() -> None:
    findings = [
        make_finding("PI-DEMO-001", status=VerdictStatus.FAIL),
        make_finding("PI-DEMO-001", status=VerdictStatus.INCONCLUSIVE, target_id="t-b"),
    ]
    run = make_run(findings=findings)
    root = _parse(JunitReporter(specs={"PI-DEMO-001": make_spec()}), run)
    assert root.get("tests") == "2"
    assert root.get("failures") == "1"
    assert root.get("skipped") == "1"


def test_missing_spec_lands_in_unknown_suite() -> None:
    run = make_run(findings=[make_finding()])
    root = _parse(JunitReporter(specs={}), run)
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.get("name") == "unknown"


def test_deterministic() -> None:
    run = make_run(findings=[make_finding()])
    reporter = JunitReporter(specs={"PI-DEMO-001": make_spec()})
    assert reporter.render(run, list(run.findings)) == reporter.render(run, list(run.findings))
