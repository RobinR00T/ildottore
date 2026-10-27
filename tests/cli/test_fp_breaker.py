"""The false-positive breaker end to end: ``calibrate --record``, ``run --fp-ledger`` (u08 A-105).

The rule itself (window, minimum, rate, a label recorded again) is in
``tests/shared/test_review_holds.py``.
"""

from __future__ import annotations

import json
import sqlite3
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import labels_ledger
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.resume import stored_review_holds
from ildottore.shared.review_holds import ReviewHold
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_scope, write_spec_tree, write_target

runner = CliRunner()
_SPECS = ("PI-DIRECT-001", "JB-ROLEPLAY-001")


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = write_spec_tree(tmp_path, [make_spec(spec_id) for spec_id in _SPECS])
    return scope, target, specs


def _run(tmp_path: Path, *extra: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope, target, specs = _tree(tmp_path)
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--runs",
            "1",
            "--evidence-root",
            str(tmp_path / "evidence"),
            "--run-db",
            str(tmp_path / "runs.db"),
            *extra,
        ],
    )


def _ledger(path: Path, spec_id: str, operators: list[str]) -> Path:
    lines = [
        json.dumps(
            {
                "run_id": f"run-{i:012x}",
                "spec_id": spec_id,
                "scanner": "fail",
                "operator": operator,
                "recorded_at": "2026-10-27T19:00:00Z",
            }
        )
        for i, operator in enumerate(operators)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _run_id(path: Path) -> str:
    return str(json.loads(path.read_text(encoding="utf-8"))["run"]["run_id"])


def _report(path: Path) -> dict[str, dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {f["spec_id"]: f for f in data["findings"]}


def test_a_held_spec_is_reported_as_needing_review(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "PI-DIRECT-001", ["pass"] * 4 + ["fail"] * 6)
    out = tmp_path / "report.json"
    result = _run(tmp_path, "--fp-ledger", str(ledger), "-oJ", str(out))
    # The other spec still fails, confirmed: the run still gates.
    assert result.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE), result.output
    assert (
        "review holds: PI-DIRECT-001, 4 of its last 10 labelled fails were false positives. "
        "A fail of each is reported as needing review."
    ) in result.output
    findings = _report(out)
    held, other = findings["PI-DIRECT-001"], findings["JB-ROLEPLAY-001"]
    assert held["status"] == "fail" and held["confirmed"] is False
    assert "held for review by the labels ledger: 4 of its last 10" in str(held["reasoning"])
    assert other["status"] == "fail" and other["confirmed"] is True
    assert "held for review" not in str(other["reasoning"])


def test_holding_every_fail_stops_the_gate_unless_review_is_included(tmp_path: Path) -> None:
    ledger = tmp_path / "labels.jsonl"
    text = "".join(
        _ledger(tmp_path / f"{spec_id}.jsonl", spec_id, ["pass"] * 5).read_text(encoding="utf-8")
        for spec_id in _SPECS
    )
    ledger.write_text(text, encoding="utf-8")
    held = _run(tmp_path, "--fp-ledger", str(ledger))
    # Both fails reported, neither gating: needs-review fails are not findings the gate counts.
    assert held.exit_code == int(ExitCode.CLEAN), held.output
    assert held.output.count("FAIL (critical, needs review)") == 2
    both = _run(tmp_path / "again", "--fp-ledger", str(ledger), "--include-needs-review")
    assert both.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE), both.output


def test_a_spec_held_but_not_selected_is_not_named(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "SAFETY-OTHER-001", ["pass"] * 5)
    result = _run(tmp_path, "--fp-ledger", str(ledger))
    assert result.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE), result.output
    assert "review holds" not in result.output


def test_a_ledger_it_cannot_read_stops_the_run_before_anything_is_sent(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "PI-DIRECT-001", ["pass"] * 5)
    ledger.write_text(ledger.read_text(encoding="utf-8") + "{not json\n", encoding="utf-8")
    out = tmp_path / "report.json"
    result = _run(tmp_path, "--fp-ledger", str(ledger), "-oJ", str(out))
    assert result.exit_code == int(ExitCode.ERROR)
    assert "line 6 is not JSON" in result.output and "refused whole" in result.output
    assert not out.exists()
    assert not (tmp_path / "evidence").exists() or not any((tmp_path / "evidence").rglob("*.json"))

    for bad, why in (
        ('{"run_id": "run-1", "spec_id": "PI-DIRECT-001", "scanner": "fail"}', "not a label"),
        (
            '{"run_id": "run-1", "spec_id": "PI-DIRECT-001", "scanner": "maybe", '
            '"operator": "pass", "recorded_at": "x"}',
            "scanner is not one of",
        ),
        (
            '{"run_id": "../x", "spec_id": "PI-DIRECT-001", "scanner": "fail", '
            '"operator": "pass", "recorded_at": "x"}',
            "run_id is not a run id",
        ),
        (
            '{"run_id": "run-1", "spec_id": "::error x", "scanner": "fail", '
            '"operator": "pass", "recorded_at": "x"}',
            "spec_id is not a spec id",
        ),
    ):
        ledger.write_text(bad + "\n", encoding="utf-8")
        refused = _run(tmp_path / why.replace(" ", "-"), "--fp-ledger", str(ledger))
        assert refused.exit_code == int(ExitCode.ERROR), bad
        assert why in refused.output, refused.output

    missing = _run(tmp_path / "missing", "--fp-ledger", str(tmp_path / "nowhere.jsonl"))
    assert missing.exit_code == int(ExitCode.ERROR)


def test_a_report_is_never_written_over_the_ledger(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "PI-DIRECT-001", ["pass"] * 5)
    before = ledger.read_bytes()
    result = _run(tmp_path, "--fp-ledger", str(ledger), "-oJ", str(ledger))
    assert result.exit_code == int(ExitCode.ERROR)
    assert "--fp-ledger" in result.output
    assert ledger.read_bytes() == before


def test_the_run_records_its_holds_and_a_resume_keeps_them(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "PI-DIRECT-001", ["pass"] * 5)
    out = tmp_path / "report.json"
    result = _run(tmp_path, "--fp-ledger", str(ledger), "-oJ", str(out))
    assert result.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE), result.output
    run_id = _run_id(out)
    db = tmp_path / "runs.db"
    with SqliteRunStore(db) as store:
        context = store.get_run_context(run_id)
    assert context is not None and context["review_holds"] == {"PI-DIRECT-001": [5, 5]}
    assert stored_review_holds(db, run_id) == {"PI-DIRECT-001": ReviewHold(5, 5)}
    assert stored_review_holds(tmp_path / "none.db", run_id) == {}

    refused = _run(tmp_path, "--resume", run_id, "--fp-ledger", str(ledger))
    assert refused.exit_code == int(ExitCode.ERROR)
    assert "--fp-ledger cannot be given with --resume" in refused.output


def test_a_run_without_a_ledger_records_no_holds(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = _run(tmp_path, "-oJ", str(out))
    assert result.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE), result.output
    with SqliteRunStore(tmp_path / "runs.db") as store:
        context = store.get_run_context(_run_id(out))
    assert context is not None and context["review_holds"] == {}


def test_calibrate_records_labels_and_five_false_alarms_hold_the_spec(tmp_path: Path) -> None:
    ledger = tmp_path / "labels.jsonl"
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: pass\nJB-ROLEPLAY-001: fail\n", encoding="utf-8")
    for i in range(5):
        out = tmp_path / f"report-{i}.json"
        assert _run(tmp_path / f"r{i}", "-oJ", str(out)).exit_code == 2
        recorded = runner.invoke(app, ["calibrate", str(out), str(labels), "--record", str(ledger)])
        assert recorded.exit_code == 0, recorded.output
        assert "DISAGREE PI-DIRECT-001: scanner=fail operator=pass" in recorded.output
        assert f"recorded: 2 label(s) appended to {ledger}" in recorded.output
    lines = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 10 and len({line["run_id"] for line in lines}) == 5
    assert {(line["spec_id"], line["scanner"], line["operator"]) for line in lines} == {
        ("PI-DIRECT-001", "fail", "pass"),
        ("JB-ROLEPLAY-001", "fail", "fail"),
    }
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600

    out = tmp_path / "held.json"
    result = _run(tmp_path / "held", "--fp-ledger", str(ledger), "-oJ", str(out))
    assert "PI-DIRECT-001, 5 of its last 5 labelled fails" in result.output
    assert _report(out)["PI-DIRECT-001"]["confirmed"] is False
    assert _report(out)["JB-ROLEPLAY-001"]["confirmed"] is True


def test_recording_the_same_report_again_counts_once(tmp_path: Path) -> None:
    ledger = tmp_path / "labels.jsonl"
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: pass\n", encoding="utf-8")
    out = tmp_path / "report.json"
    _run(tmp_path, "-oJ", str(out))
    for _ in range(5):
        runner.invoke(app, ["calibrate", str(out), str(labels), "--record", str(ledger)])
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 5
    result = _run(tmp_path / "again", "--fp-ledger", str(ledger))
    assert "review holds" not in result.output


def test_calibrate_record_refusals(tmp_path: Path) -> None:
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: pass\n", encoding="utf-8")
    out = tmp_path / "report.json"
    _run(tmp_path, "-oJ", str(out))
    report_before = out.read_bytes()
    for same in (out, labels):
        refused = runner.invoke(app, ["calibrate", str(out), str(labels), "--record", str(same)])
        assert refused.exit_code == int(ExitCode.ERROR)
        assert "--record names the report or the labels file" in refused.output
    assert out.read_bytes() == report_before

    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(json.loads(report_before)["findings"]), encoding="utf-8")
    ledger = tmp_path / "labels.jsonl"
    refused = runner.invoke(app, ["calibrate", str(bare), str(labels), "--record", str(ledger)])
    assert refused.exit_code == int(ExitCode.ERROR)
    assert "a bare list of findings cannot be recorded" in refused.output
    assert not ledger.exists()

    # Without --record nothing is written, as before.
    plain = runner.invoke(app, ["calibrate", str(bare), str(labels)])
    assert plain.exit_code == 0 and "recorded" not in plain.output


def test_a_record_past_the_cap_is_refused_before_it_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(labels_ledger, "MAX_FILE_BYTES", 200)
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: pass\nJB-ROLEPLAY-001: fail\n", encoding="utf-8")
    out = tmp_path / "report.json"
    _run(tmp_path, "-oJ", str(out))
    ledger = tmp_path / "labels.jsonl"
    ledger.write_text("", encoding="utf-8")
    refused = runner.invoke(app, ["calibrate", str(out), str(labels), "--record", str(ledger)])
    assert refused.exit_code == int(ExitCode.ERROR)
    assert "past the 200 bytes a run reads; start a new ledger" in refused.output
    assert ledger.read_text(encoding="utf-8") == ""


def test_the_ledger_is_never_written_through_a_symbolic_link(tmp_path: Path) -> None:
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: pass\n", encoding="utf-8")
    out = tmp_path / "report.json"
    _run(tmp_path, "-oJ", str(out))
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "labels.jsonl"
    link.symlink_to(elsewhere)
    refused = runner.invoke(app, ["calibrate", str(out), str(labels), "--record", str(link)])
    assert refused.exit_code == int(ExitCode.ERROR)
    assert elsewhere.read_text(encoding="utf-8") == "keep\n"


def test_dry_run_names_the_holds(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "PI-DIRECT-001", ["pass"] * 5)
    result = _run(tmp_path, "--fp-ledger", str(ledger), "--dry-run")
    assert result.exit_code == 0, result.output
    assert "review holds: PI-DIRECT-001, 5 of its last 5" in result.output


def test_a_resume_without_the_flag_holds_what_its_run_held(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "labels.jsonl", "PI-DIRECT-001", ["pass"] * 5)
    halted = _run(tmp_path, "--fp-ledger", str(ledger), "--budget-requests", "1")
    assert halted.exit_code == int(ExitCode.ERROR), halted.output
    conn = sqlite3.connect(tmp_path / "runs.db")
    try:
        ((run_id,),) = conn.execute("SELECT run_id FROM runs").fetchall()
    finally:
        conn.close()
    # The ledger changes after the run started: the resume holds what the run held.
    ledger.write_text("", encoding="utf-8")
    out = tmp_path / "resumed.json"
    resumed = _run(tmp_path, "--resume", run_id, "-oJ", str(out))
    assert resumed.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE), resumed.output
    assert "review holds: PI-DIRECT-001, 5 of its last 5" in resumed.output
    findings = _report(out)
    assert findings["PI-DIRECT-001"]["confirmed"] is False
    assert findings["JB-ROLEPLAY-001"]["confirmed"] is True
