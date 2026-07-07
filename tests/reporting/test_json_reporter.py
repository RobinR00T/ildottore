"""JSON reporter: schema-valid, deterministic, lossless (contract §7)."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

import jsonschema

from ildottore.reporting.json_reporter import JsonReporter
from ildottore.shared.enums import ScanBand, VerdictStatus
from tests.reporting.conftest import make_finding, make_run, make_spec


def _report_schema() -> dict[str, Any]:
    text = (
        resources.files("ildottore.reporting.schemas")
        .joinpath("report-1.0.schema.json")
        .read_text(encoding="utf-8")
    )
    schema: dict[str, Any] = json.loads(text)
    return schema


def test_renders_valid_schema() -> None:
    specs = {"PI-DEMO-001": make_spec()}
    run = make_run(findings=[make_finding()])
    doc = json.loads(JsonReporter(specs=specs).render(run, list(run.findings)))
    jsonschema.validate(doc, _report_schema())
    assert doc["schema_version"] == "1.0"
    assert doc["run"]["run_id"] == "run-1"
    assert len(doc["findings"]) == 1


def test_deterministic_byte_identical() -> None:
    specs = {"PI-DEMO-001": make_spec()}
    run = make_run(findings=[make_finding()])
    reporter = JsonReporter(specs=specs)
    a = reporter.render(run, list(run.findings))
    b = reporter.render(run, list(run.findings))
    assert a == b


def test_summary_shape_in_output() -> None:
    specs = {"PI-DEMO-001": make_spec()}
    run = make_run(findings=[make_finding(confirmed=True)])
    doc = json.loads(JsonReporter(specs=specs).render(run, list(run.findings)))
    summary = doc["summary"]
    assert summary["confirmed_count"] == 1
    assert summary["by_band"] == {"critical": 1}
    assert set(summary["by_framework"]) == {"owasp", "atlas", "nist"}


def test_model_comparison_present_multi_target() -> None:
    specs = {"PI-DEMO-001": make_spec()}
    findings = [
        make_finding(target_id="t-a", band=ScanBand.CRITICAL),
        make_finding(target_id="t-b", band=ScanBand.LOW, status=VerdictStatus.PASS),
    ]
    run = make_run(findings=findings, targets=[])
    doc = json.loads(JsonReporter(specs=specs).render(run, findings))
    assert "model_comparison" in doc["summary"]
    jsonschema.validate(doc, _report_schema())


def test_no_model_comparison_single_target() -> None:
    run = make_run(findings=[make_finding()])
    doc = json.loads(JsonReporter().render(run, list(run.findings)))
    assert "model_comparison" not in doc["summary"]


def test_trailing_newline() -> None:
    run = make_run(findings=[make_finding()])
    out = JsonReporter().render(run, list(run.findings))
    assert out.endswith(b"\n")
