"""Every report prints the counts behind a reproducibility rate and their interval (u11 A-126)."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

import jsonschema

from ildottore.reporting.html_reporter import HtmlReporter
from ildottore.reporting.json_reporter import JsonReporter
from ildottore.reporting.sarif_reporter import SarifReporter
from ildottore.shared.enums import ScanBand
from ildottore.shared.models import Finding
from tests.reporting.conftest import make_finding, make_risk, make_run, make_spec

_SPECS = {"PI-DEMO-001": make_spec()}


def _counted() -> Finding:
    risk = make_risk(band=ScanBand.MEDIUM, reproducibility=0.2, risk=2.4)
    risk = risk.model_validate({**risk.model_dump(), "successes": 1, "trials": 5})
    return make_finding().model_copy(update={"risk": risk})


def _schema() -> dict[str, Any]:
    text = (
        resources.files("ildottore.reporting.schemas")
        .joinpath("report-1.0.schema.json")
        .read_text(encoding="utf-8")
    )
    schema: dict[str, Any] = json.loads(text)
    return schema


def test_json_carries_the_counts_and_validates() -> None:
    run = make_run(findings=[_counted()])
    doc = json.loads(JsonReporter(specs=_SPECS).render(run, list(run.findings)))
    jsonschema.validate(doc, _schema())
    risk = doc["findings"][0]["risk"]
    assert (risk["successes"], risk["trials"]) == (1, 5)


def test_sarif_carries_the_counts_and_the_interval() -> None:
    run = make_run(findings=[_counted()])
    doc = json.loads(SarifReporter(specs=_SPECS).render(run, list(run.findings)))
    props = doc["runs"][0]["results"][0]["properties"]
    assert (props["successes"], props["trials"]) == (1, 5)
    assert props["reproducibility_interval_95"] == [0.0362, 0.6245]


def test_sarif_leaves_an_uncounted_finding_as_it_was() -> None:
    run = make_run(findings=[make_finding()])
    doc = json.loads(SarifReporter(specs=_SPECS).render(run, list(run.findings)))
    props = doc["runs"][0]["results"][0]["properties"]
    assert not {"successes", "trials", "reproducibility_interval_95"} & props.keys()


def test_html_prints_the_counts_beside_the_rate() -> None:
    run = make_run(findings=[_counted()])
    html = HtmlReporter(specs=_SPECS).render(run, list(run.findings)).decode("utf-8")
    assert "reproducibility 0.20 (1/5, 95% CI 0.04 to 0.62)" in html


def test_html_prints_the_bare_rate_when_uncounted() -> None:
    run = make_run(findings=[make_finding()])
    html = HtmlReporter(specs=_SPECS).render(run, list(run.findings)).decode("utf-8")
    assert "reproducibility 1.00 ·" in html
