"""JUnit XML reporter (contract u11 §5 step 5, §6, §7).

Renders the pipeline pass/fail view CI systems consume. Findings are grouped into
``<testsuite>`` elements keyed by framework (the finding's OWASP LLM category, ``unknown``
when the spec is absent); each finding is one ``<testcase name=spec_id>``. Verdict polarity
is fixed repo-wide (``docs/04``): ``fail`` = exploited → ``<failure>``; ``inconclusive`` →
``<skipped>``; ``pass`` = secure → a clean testcase. Suite/counts attributes are derived so
the document parses as well-formed JUnit XML (contract §7).

Serialization is deterministic: suites are emitted in sorted framework order, testcases in
(masked) finding order, and the XML declaration + encoding are fixed (contract §4 KEEP).
Built with the stdlib ``xml.etree.ElementTree`` - the tool only ever serializes data it
produced itself, so no untrusted-XML parsing surface is introduced.
"""

from __future__ import annotations

from collections import OrderedDict
from xml.etree import ElementTree as ET

from ildottore.reporting.base import BaseReporter, register_reporter
from ildottore.reporting.masking import MaskingContext
from ildottore.reporting.summary import RunSummary
from ildottore.shared.enums import ReportFormat, VerdictStatus
from ildottore.shared.models import Finding

__all__ = ["JunitReporter"]

_UNKNOWN = "unknown"


class JunitReporter(BaseReporter):
    """Serializes the masked findings to well-formed JUnit XML bytes."""

    format = ReportFormat.JUNIT.value

    def _framework_of(self, finding: Finding) -> str:
        spec = self._specs.get(finding.spec_id)
        return spec.owasp if spec is not None else _UNKNOWN

    def _testcase(self, finding: Finding) -> ET.Element:
        case = ET.Element(
            "testcase",
            {
                "name": finding.spec_id,
                "classname": finding.target_id,
                "time": "0",
            },
        )
        detail = (
            f"band={finding.risk.band.value} risk={finding.risk.risk:g} "
            f"confidence={finding.risk.confidence:g} "
            f"state={'confirmed' if finding.confirmed else 'needs_review'}"
        )
        if finding.status is VerdictStatus.FAIL:
            failure = ET.SubElement(
                case,
                "failure",
                {"message": f"exploited: {finding.spec_id}", "type": finding.risk.band.value},
            )
            failure.text = (finding.reasoning or detail)[:4096]
        elif finding.status is VerdictStatus.INCONCLUSIVE:
            skipped = ET.SubElement(
                case, "skipped", {"message": f"inconclusive: {finding.spec_id}"}
            )
            skipped.text = (finding.reasoning or detail)[:4096]
        else:  # pass - secure
            system_out = ET.SubElement(case, "system-out")
            system_out.text = detail
        return case

    def _render(self, ctx: MaskingContext, summary: RunSummary) -> bytes:
        # Preserve finding order within each framework; suites sorted by name.
        by_framework: OrderedDict[str, list[Finding]] = OrderedDict()
        for finding in ctx.findings:
            by_framework.setdefault(self._framework_of(finding), []).append(finding)

        root = ET.Element("testsuites", {"name": ctx.run.run_id})
        total_tests = 0
        total_failures = 0
        total_skipped = 0

        for framework in sorted(by_framework):
            findings = by_framework[framework]
            failures = sum(1 for f in findings if f.status is VerdictStatus.FAIL)
            skipped = sum(1 for f in findings if f.status is VerdictStatus.INCONCLUSIVE)
            suite = ET.SubElement(
                root,
                "testsuite",
                {
                    "name": framework,
                    "tests": str(len(findings)),
                    "failures": str(failures),
                    "skipped": str(skipped),
                    "errors": "0",
                    "time": "0",
                },
            )
            for finding in findings:
                suite.append(self._testcase(finding))
            total_tests += len(findings)
            total_failures += failures
            total_skipped += skipped

        root.set("tests", str(total_tests))
        root.set("failures", str(total_failures))
        root.set("skipped", str(total_skipped))
        root.set("errors", "0")

        ET.indent(root, space="  ")
        body = ET.tostring(root, encoding="unicode")
        return ('<?xml version="1.0" encoding="UTF-8"?>\n' + body + "\n").encode("utf-8")


register_reporter(ReportFormat.JUNIT, JunitReporter)
