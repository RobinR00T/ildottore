"""Replies the provider's filter cut, or stopped on an unreported side, in SARIF and JUnit.

The CLI test renders every format of a run whose cuts are all on the output side; this one builds
the findings directly, so the side-unknown counts are rendered too, and JUnit's counts are read
where they can appear: a spec with a cut attempt never passes, so they ride in the failure's or the
skip's message (pre-merge audit of ``a55e953``, L4).
"""

from __future__ import annotations

import json
from typing import Any
from xml.etree import ElementTree as ET  # nosec B405 - the test parses its own report

import jsonschema

from ildottore.reporting.junit_reporter import JunitReporter
from ildottore.reporting.sarif_reporter import SarifReporter, load_sarif_schema
from ildottore.shared.enums import InconclusiveReason, ScanBand, VerdictStatus
from ildottore.shared.models import Attempt, Finding, ModelRequest, ModelResponse, Verdict
from tests.reporting.conftest import make_risk, make_run


def _attempt(i: int, spec_id: str, reason: InconclusiveReason | None, stop: str) -> Attempt:
    verdict = (
        Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning=f"{reason.value}: the provider's filter",
            evaluator_type="aggregate",
            inconclusive_reason=reason,
        )
        if reason is not None
        else Verdict(
            status=VerdictStatus.FAIL,
            confidence=1.0,
            reasoning="1 deterministic evaluator(s) reported exploited",
            evaluator_type="aggregate",
        )
    )
    return Attempt(
        attempt_id=f"{spec_id}::identity#{i}",
        spec_id=spec_id,
        request=ModelRequest(prompt="x"),
        response=ModelResponse(text="Blocked.", finish_reason=stop),
        verdict=verdict,
    )


def _findings() -> list[Finding]:
    unsaid = InconclusiveReason.PROVIDER_FILTER_SIDE_UNKNOWN
    cut = InconclusiveReason.CUT_BY_PROVIDER_OUTPUT_FILTER
    return [
        Finding(
            spec_id="BR-001",
            target_id="mock-a",
            status=VerdictStatus.INCONCLUSIVE,
            risk=make_risk(band=ScanBand.INFO, reproducibility=0.0, risk=0.0, confidence=0.0),
            confirmed=False,
            attempts=[
                _attempt(0, "BR-001", unsaid, "guardrail_intervened"),
                _attempt(1, "BR-001", unsaid, "guardrail_intervened"),
            ],
            reasoning=None,
        ),
        Finding(
            spec_id="AZ-001",
            target_id="mock-a",
            status=VerdictStatus.FAIL,
            risk=make_risk(band=ScanBand.HIGH, reproducibility=0.5, risk=6.0),
            confirmed=False,
            attempts=[
                _attempt(0, "AZ-001", None, "content_filter"),
                _attempt(1, "AZ-001", cut, "content_filter"),
            ],
            reasoning=None,
        ),
    ]


def test_sarif_counts_the_attempts_stopped_on_an_unreported_side() -> None:
    run = make_run(findings=_findings())
    doc: dict[str, Any] = json.loads(SarifReporter().render(run, list(run.findings)))
    jsonschema.validate(doc, load_sarif_schema())

    sarif_run = doc["runs"][0]
    assert sarif_run["properties"]["provider_filter_side_unknown"] == 2
    assert sarif_run["properties"]["cut_by_provider_output_filter"] == 1
    results = {r["ruleId"]: r for r in sarif_run["results"]}
    unsaid = results["BR-001"]
    assert unsaid["kind"] == "open"
    assert unsaid["properties"]["provider_filter_side_unknown"] == 2
    assert "cut_by_provider_output_filter" not in unsaid["properties"]
    assert unsaid["message"]["text"].endswith(
        "; 2 of 2 attempt(s) stopped by the provider's filter on a side it did not report: "
        "review them"
    )
    assert results["AZ-001"]["kind"] == "fail"
    assert results["AZ-001"]["properties"]["cut_by_provider_output_filter"] == 1


def test_junit_counts_them_in_the_skip_or_failure_message() -> None:
    run = make_run(findings=_findings())
    root = ET.fromstring(JunitReporter().render(run, list(run.findings)))  # noqa: S314
    cases = {c.get("name"): c for c in root.iter("testcase")}

    skipped = cases["BR-001"].find("skipped")
    assert skipped is not None
    assert skipped.get("message") == "inconclusive: BR-001 provider_filter_side_unknown=2"
    assert (skipped.text or "").endswith(" provider_filter_side_unknown=2")
    failure = cases["AZ-001"].find("failure")
    assert failure is not None
    assert failure.get("message") == "exploited: AZ-001 cut_by_provider_output_filter=1"


def test_junit_messages_are_as_before_without_a_cut() -> None:
    from tests.reporting.conftest import make_finding

    run = make_run(
        findings=[
            make_finding(spec_id="F-1"),
            make_finding(spec_id="I-1", status=VerdictStatus.INCONCLUSIVE, confirmed=False),
        ]
    )
    root = ET.fromstring(JunitReporter().render(run, list(run.findings)))  # noqa: S314
    cases = {c.get("name"): c for c in root.iter("testcase")}
    failure = cases["F-1"].find("failure")
    skipped = cases["I-1"].find("skipped")
    assert failure is not None and failure.get("message") == "exploited: F-1"
    assert skipped is not None and skipped.get("message") == "inconclusive: I-1"
