"""Golden-run snapshot + determinism gate (contract §7).

A frozen reference run must render byte-stable across two renders *and* match the committed
snapshot in ``fixtures/reports/`` (regression guard). Set ``UPDATE_REPORT_SNAPSHOTS=1`` to
regenerate after an intentional format change.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ildottore.reporting import get_reporter
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import AttackSpec, Finding, TestRun
from tests.reporting.conftest import make_finding, make_run, make_spec

_FIXTURES = Path(__file__).parent / "fixtures" / "reports"
_FORMATS = {"json": "json", "sarif": "sarif.json", "junit": "xml", "html": "html"}


def _golden_run() -> tuple[dict[str, AttackSpec], TestRun, list[Finding]]:
    specs = {
        "PI-DEMO-001": make_spec(),
        "DL-DEMO-002": make_spec("DL-DEMO-002", owasp="LLM02", nist="MAP"),
    }
    findings = [
        make_finding(
            "PI-DEMO-001",
            target_id="t-a",
            band=ScanBand.CRITICAL,
            status=VerdictStatus.FAIL,
            confirmed=True,
        ),
        make_finding(
            "DL-DEMO-002",
            target_id="t-b",
            band=ScanBand.MEDIUM,
            status=VerdictStatus.PASS,
            confirmed=False,
        ),
    ]
    run = make_run(run_id="golden-1", findings=findings, targets=[])
    return specs, run, findings


@pytest.mark.parametrize("fmt", list(_FORMATS))
def test_golden_snapshot_stable(fmt: str) -> None:
    specs, run, findings = _golden_run()
    reporter = get_reporter(fmt, specs=specs)
    first = reporter.render(run, findings)
    second = reporter.render(run, findings)
    assert first == second, f"{fmt}: non-deterministic render"

    path = _FIXTURES / f"golden.{_FORMATS[fmt]}"
    if os.environ.get("UPDATE_REPORT_SNAPSHOTS") == "1":
        path.write_bytes(first)
    assert path.read_bytes() == first, (
        f"{fmt}: snapshot drift — rerun with UPDATE_REPORT_SNAPSHOTS=1"
    )
