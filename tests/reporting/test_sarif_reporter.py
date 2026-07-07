"""SARIF 2.1.0 reporter: schema-valid, band→level, framework tags (contract §7)."""

from __future__ import annotations

import json
from typing import Any

import jsonschema
import pytest

from ildottore.reporting.sarif_reporter import (
    SarifReporter,
    band_to_level,
    load_sarif_schema,
)
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import TestRun
from tests.reporting.conftest import make_finding, make_run, make_spec


def _doc(reporter: SarifReporter, run: TestRun) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(reporter.render(run, list(run.findings)))
    return doc


def test_output_validates_against_sarif_schema() -> None:
    specs = {"PI-DEMO-001": make_spec()}
    run = make_run(findings=[make_finding()])
    doc = _doc(SarifReporter(specs=specs), run)
    jsonschema.validate(doc, load_sarif_schema())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Il Dottore"


@pytest.mark.parametrize(
    ("band", "level"),
    [
        (ScanBand.CRITICAL, "error"),
        (ScanBand.HIGH, "error"),
        (ScanBand.MEDIUM, "warning"),
        (ScanBand.LOW, "note"),
        (ScanBand.INFO, "note"),
    ],
)
def test_band_to_level(band: ScanBand, level: str) -> None:
    assert band_to_level(band) == level


def test_result_ruleid_is_spec_id_and_level_mapped() -> None:
    run = make_run(findings=[make_finding(band=ScanBand.MEDIUM)])
    doc = _doc(SarifReporter(specs={"PI-DEMO-001": make_spec()}), run)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "PI-DEMO-001"
    assert result["level"] == "warning"
    assert result["properties"]["band"] == "medium"
    assert result["properties"]["state"] == "confirmed"


def test_rule_carries_framework_tags() -> None:
    run = make_run(findings=[make_finding()])
    doc = _doc(SarifReporter(specs={"PI-DEMO-001": make_spec(owasp="LLM01", nist="MEASURE")}), run)
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "owasp:LLM01" in tags
    assert "atlas:AML.TA0000" in tags
    assert "nist:MEASURE" in tags


def test_rules_deduplicated_by_spec() -> None:
    findings = [
        make_finding("PI-DEMO-001", target_id="t-a"),
        make_finding("PI-DEMO-001", target_id="t-b"),
    ]
    run = make_run(findings=findings, targets=[])
    doc = _doc(SarifReporter(specs={"PI-DEMO-001": make_spec()}), run)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert doc["runs"][0]["results"][0]["ruleIndex"] == 0


def test_missing_spec_gets_unknown_tags_and_validates() -> None:
    run = make_run(findings=[make_finding()])
    doc = _doc(SarifReporter(specs={}), run)
    jsonschema.validate(doc, load_sarif_schema())
    tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "owasp:unknown" in tags


def test_kind_reflects_status() -> None:
    findings = [make_finding(status=VerdictStatus.PASS, band=ScanBand.INFO)]
    run = make_run(findings=findings)
    doc = _doc(SarifReporter(), run)
    assert doc["runs"][0]["results"][0]["kind"] == "pass"


def test_deterministic() -> None:
    run = make_run(findings=[make_finding()])
    reporter = SarifReporter(specs={"PI-DEMO-001": make_spec()})
    assert reporter.render(run, list(run.findings)) == reporter.render(run, list(run.findings))
