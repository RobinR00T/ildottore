"""CLI and reports: block 6 of the 2026-10-03 audit, one test per finding.

R3 (`--hardened` on a live target published a clean report about a model nobody contacted),
R4 (`diff` and `calibrate` merged targets, and fail to inconclusive read FIXED), R7 (SARIF kinds),
R9 (bad options accepted until after the campaign), R11 (two target files with one id), R17
(usage errors exited 2, the "findings" code), R18 (calibrate's arithmetic), and three lows: the
version string, the HTML document skeleton and `new-spec --id ../evil`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore import __version__
from ildottore.cli.app import app
from ildottore.cli.calibrate import calibrate, render_calibration
from ildottore.cli.diff import DriftClass, compare_runs
from ildottore.reporting import get_reporter
from ildottore.shared.enums import ReportFormat, ScanBand, VerdictStatus
from tests.reporting.conftest import make_finding, make_run

REPO = Path(__file__).resolve().parents[1]
LOCAL = ["-t", str(REPO / "examples" / "target.local.yaml")]
SCOPE = ["--scope", str(REPO / "examples" / "scope.local.yaml")]


def _invoke(*args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, list(args))


def _mock_workspace(tmp_path: Path) -> tuple[Path, Path]:
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return target, scope


# --- R3 -----------------------------------------------------------------------------------


def test_hardened_is_refused_on_a_live_target() -> None:
    result = _invoke("run", *LOCAL, *SCOPE, "--hardened", "--dry-run")
    assert result.exit_code == 3
    assert "--hardened replays the offline hardened fixtures" in result.output


def test_hardened_still_works_on_a_mock_target(tmp_path: Path) -> None:
    target, scope = _mock_workspace(tmp_path)
    result = _invoke(
        "run", "-t", str(target), "--scope", str(scope), "--hardened", "--quick", "--dry-run"
    )
    assert result.exit_code == 0, result.output


# --- R4 -----------------------------------------------------------------------------------


def _report(tmp_path: Path, name: str, findings: list) -> Path:  # type: ignore[type-arg]
    path = tmp_path / name
    path.write_bytes(get_reporter(ReportFormat.JSON).render(make_run(findings=findings), findings))
    return path


def test_a_report_with_two_targets_is_refused_by_diff(tmp_path: Path) -> None:
    """Indexing by spec id let a PASS on one target replace a FAIL on another."""

    mixed = _report(
        tmp_path,
        "mixed.json",
        [make_finding(target_id="a"), make_finding(target_id="b", status=VerdictStatus.PASS)],
    )
    single = _report(tmp_path, "single.json", [make_finding(target_id="a")])
    result = _invoke("diff", str(single), str(mixed))
    assert result.exit_code == 3
    assert "covers 2 targets" in result.output


def test_diff_refuses_two_different_targets(tmp_path: Path) -> None:
    base = _report(tmp_path, "a.json", [make_finding(target_id="a")])
    current = _report(tmp_path, "b.json", [make_finding(target_id="b")])
    result = _invoke("diff", str(base), str(current))
    assert result.exit_code == 3
    assert "compares one target with itself" in result.output


def test_a_fail_that_became_inconclusive_is_not_fixed() -> None:
    base = {"S-1": make_finding("S-1")}
    current = {"S-1": make_finding("S-1", status=VerdictStatus.INCONCLUSIVE, confirmed=False)}
    entry = compare_runs(base, current).entries[0]
    assert entry.drift is DriftClass.UNVERIFIED
    passed = {"S-1": make_finding("S-1", status=VerdictStatus.PASS, confirmed=False)}
    assert compare_runs(base, passed).entries[0].drift is DriftClass.FIXED


# --- R18 ----------------------------------------------------------------------------------


def test_calibration_agreement_is_an_exact_match_and_undefined_rates_say_so() -> None:
    findings = {
        "S-1": make_finding("S-1", status=VerdictStatus.INCONCLUSIVE, confirmed=False),
        "S-2": make_finding("S-2", status=VerdictStatus.PASS, confirmed=False),
    }
    report = calibrate(findings, {"S-1": VerdictStatus.PASS, "S-2": VerdictStatus.PASS})
    text = render_calibration(report)
    assert report.agreements == 1 and "agreement 50%" in text
    assert "precision n/a" in text and "recall n/a" in text


def test_calibration_percentages_are_floored() -> None:
    findings = {f"S-{i}": make_finding(f"S-{i}") for i in range(1, 251)}
    labels = dict.fromkeys(findings, VerdictStatus.FAIL)
    labels["S-1"] = VerdictStatus.PASS
    text = render_calibration(calibrate(findings, labels))
    assert "agreement 99%" in text  # 249/250 = 99.6%, which used to print 100%


def test_calibrate_refuses_a_halted_run(tmp_path: Path) -> None:
    report = _report(tmp_path, "r.json", [make_finding()])
    data = json.loads(report.read_text())
    data["summary"]["status"] = {"complete": False, "state": "budget_exhausted", "reason": "x"}
    report.write_text(json.dumps(data))
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DEMO-001: fail\n")
    result = _invoke("calibrate", str(report), str(labels))
    assert result.exit_code == 3
    assert "did not complete" in result.output


def test_diff_on_a_malformed_report_exits_3_not_a_traceback(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": [1, 2, 3]}')
    result = _invoke("diff", str(bad), str(bad))
    assert result.exit_code == 3


# --- R17 ----------------------------------------------------------------------------------


@pytest.mark.parametrize("args", [["run", "--no-such-flag"], ["run", "--runs", "many"]])
def test_a_usage_error_exits_3(args: list[str]) -> None:
    """Exit 2 is "findings at or above --fail-on"; a typo in a CI step reported a finding."""

    assert _invoke(*args).exit_code == 3


# --- R9 and R11 ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--fail-on", "bogus"], "invalid --fail-on"),
        (["--timeout", "0"], "--timeout must be greater than 0"),
        (["--concurrency", "0"], "--concurrency must be at least 1"),
        (["--top-tests", "0"], "--top-tests must be at least 1"),
        (["-oA", "/nonexistent-dir-for-dottore/report"], "is not a directory"),
    ],
)
def test_a_bad_option_is_refused_before_the_campaign(
    tmp_path: Path, extra: list[str], message: str
) -> None:
    target, scope = _mock_workspace(tmp_path)
    result = _invoke(
        "run",
        "-t",
        str(target),
        "--scope",
        str(scope),
        "--quick",
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
        *extra,
    )
    assert result.exit_code == 3
    assert message in result.output
    assert not (tmp_path / "ev").exists(), "nothing ran before the refusal"


def test_two_target_files_with_one_id_are_refused(tmp_path: Path) -> None:
    target, scope = _mock_workspace(tmp_path)
    twin = tmp_path / "twin.yaml"
    twin.write_text(target.read_text())
    result = _invoke("run", "-t", str(target), "-t", str(twin), "--scope", str(scope), "--dry-run")
    assert result.exit_code == 3
    assert "declare the id 'mock-target'" in result.output


# --- R7 -----------------------------------------------------------------------------------


def test_sarif_kinds_follow_the_standard() -> None:
    fail = make_finding("S-FAIL", band=ScanBand.HIGH)
    passed = make_finding("S-PASS", status=VerdictStatus.PASS, band=ScanBand.INFO)
    open_ = make_finding("S-OPEN", status=VerdictStatus.INCONCLUSIVE, confirmed=False)
    never = make_finding("S-NEVER", status=VerdictStatus.INCONCLUSIVE, confirmed=False)
    never = never.model_copy(update={"attempts": []})
    findings = [fail, passed, open_, never]
    doc = json.loads(get_reporter(ReportFormat.SARIF).render(make_run(findings=findings), findings))
    by_rule = {r["ruleId"]: (r["kind"], r["level"]) for r in doc["runs"][0]["results"]}
    assert by_rule["S-FAIL"] == ("fail", "error")
    assert by_rule["S-PASS"] == ("pass", "none")
    assert by_rule["S-OPEN"] == ("open", "none")
    assert by_rule["S-NEVER"] == ("notApplicable", "none")


# --- lows ---------------------------------------------------------------------------------


def test_the_version_is_the_package_version() -> None:
    assert _invoke("--version").output.strip() == f"dottore {__version__}"


def test_the_html_report_is_a_full_document_with_a_charset() -> None:
    html = get_reporter(ReportFormat.HTML).render(make_run(), []).decode()
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert '<meta charset="utf-8">' in html


def test_new_spec_refuses_an_id_that_would_escape_the_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _invoke(
        "new-spec", "--id", "../evil", "--family", "prompt_injection", "--out", str(out)
    )
    assert result.exit_code == 3
    assert not (tmp_path / "evil.yaml").exists()
