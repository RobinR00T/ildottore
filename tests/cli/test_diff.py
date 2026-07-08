"""``dottore diff`` — baseline/drift comparison (docs/12 P1).

Builds two synthetic JSON run reports (baseline / current) and asserts the drift
classification (NEW-FAIL regression / FIXED / STILL-FAIL / UNCHANGED) and the CLI exit
code that surfaces regressions to CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli import diff as diff_mod
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Finding

from .conftest import make_finding

runner = CliRunner()


def _write_report(path: Path, findings: list[Finding]) -> None:
    document = {
        "schema_version": "1.0",
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    path.write_text(json.dumps(document), encoding="utf-8")


def test_compare_runs_classifies_all_four_drifts() -> None:
    baseline = {
        "PI-A": make_finding(spec_id="PI-A", status=VerdictStatus.PASS),  # -> new_fail
        "PI-B": make_finding(spec_id="PI-B", status=VerdictStatus.FAIL),  # -> fixed
        "PI-C": make_finding(spec_id="PI-C", status=VerdictStatus.FAIL),  # -> still_fail
        "PI-D": make_finding(spec_id="PI-D", status=VerdictStatus.PASS),  # -> unchanged
    }
    current = {
        "PI-A": make_finding(spec_id="PI-A", status=VerdictStatus.FAIL),
        "PI-B": make_finding(spec_id="PI-B", status=VerdictStatus.PASS),
        "PI-C": make_finding(spec_id="PI-C", status=VerdictStatus.FAIL),
        "PI-D": make_finding(spec_id="PI-D", status=VerdictStatus.PASS),
    }

    report = diff_mod.compare_runs(baseline, current)
    by_spec = {e.spec_id: e.drift for e in report.entries}

    assert by_spec["PI-A"] is diff_mod.DriftClass.NEW_FAIL
    assert by_spec["PI-B"] is diff_mod.DriftClass.FIXED
    assert by_spec["PI-C"] is diff_mod.DriftClass.STILL_FAIL
    assert by_spec["PI-D"] is diff_mod.DriftClass.UNCHANGED

    assert [e.spec_id for e in report.regressions] == ["PI-A"]
    assert report.has_regressions() is True


def test_compare_runs_handles_specs_only_on_one_side() -> None:
    baseline = {"PI-OLD": make_finding(spec_id="PI-OLD", status=VerdictStatus.FAIL)}
    current = {"PI-NEW": make_finding(spec_id="PI-NEW", status=VerdictStatus.FAIL)}

    report = diff_mod.compare_runs(baseline, current)
    by_spec = {e.spec_id: e.drift for e in report.entries}

    assert by_spec["PI-OLD"] is diff_mod.DriftClass.ONLY_IN_BASELINE
    assert by_spec["PI-NEW"] is diff_mod.DriftClass.ONLY_IN_CURRENT
    # A spec appearing for the first time is not (by itself) a regression.
    assert report.has_regressions() is False


def test_diff_reports_loads_two_json_files_and_flags_regression(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _write_report(
        baseline_path,
        [
            make_finding(spec_id="PI-A", status=VerdictStatus.PASS),
            make_finding(spec_id="PI-B", status=VerdictStatus.FAIL),
        ],
    )
    _write_report(
        current_path,
        [
            make_finding(spec_id="PI-A", status=VerdictStatus.FAIL),
            make_finding(spec_id="PI-B", status=VerdictStatus.PASS),
        ],
    )

    report = diff_mod.diff_reports(baseline_path, current_path)
    by_spec = {e.spec_id: e.drift for e in report.entries}

    assert by_spec["PI-A"] is diff_mod.DriftClass.NEW_FAIL
    assert by_spec["PI-B"] is diff_mod.DriftClass.FIXED
    assert report.has_regressions() is True


def test_load_findings_accepts_bare_list(tmp_path: Path) -> None:
    path = tmp_path / "bare.json"
    findings = [make_finding(spec_id="PI-A", status=VerdictStatus.FAIL)]
    path.write_text(json.dumps([f.model_dump(mode="json") for f in findings]), encoding="utf-8")

    by_spec = diff_mod.load_findings(path)
    assert set(by_spec) == {"PI-A"}


def test_render_diff_lists_regressions() -> None:
    report = diff_mod.compare_runs(
        {"PI-A": make_finding(spec_id="PI-A", status=VerdictStatus.PASS)},
        {"PI-A": make_finding(spec_id="PI-A", status=VerdictStatus.FAIL)},
    )
    text = diff_mod.render_diff(report)
    assert "PI-A" in text
    assert "NEW-FAIL" in text
    assert "REGRESSIONS: PI-A" in text


def test_diff_cli_exits_zero_when_only_fixed(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _write_report(baseline_path, [make_finding(spec_id="PI-B", status=VerdictStatus.FAIL)])
    _write_report(current_path, [make_finding(spec_id="PI-B", status=VerdictStatus.PASS)])

    result = runner.invoke(app, ["diff", str(baseline_path), str(current_path)])

    assert result.exit_code == int(ExitCode.CLEAN)
    assert "FIXED" in result.stdout


def test_diff_cli_exits_nonzero_on_regression(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _write_report(baseline_path, [make_finding(spec_id="PI-A", status=VerdictStatus.PASS)])
    _write_report(current_path, [make_finding(spec_id="PI-A", status=VerdictStatus.FAIL)])

    result = runner.invoke(app, ["diff", str(baseline_path), str(current_path)])

    assert result.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE)
    assert "NEW-FAIL" in result.stdout
    assert "REGRESSIONS: PI-A" in result.stdout


def test_diff_cli_errors_on_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    other = tmp_path / "current.json"
    _write_report(other, [make_finding(spec_id="PI-A", status=VerdictStatus.PASS)])

    result = runner.invoke(app, ["diff", str(missing), str(other)])

    assert result.exit_code == int(ExitCode.ERROR)
