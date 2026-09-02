"""HITL calibration (docs/12 P2): compare a run's findings against operator labels."""

from __future__ import annotations

from pathlib import Path

from ildottore.cli.calibrate import calibrate, calibrate_reports, load_labels, render_calibration
from ildottore.shared.enums import VerdictStatus

from .conftest import make_finding


def test_calibrate_precision_recall_and_agreement() -> None:
    findings = {
        "A": make_finding("A", status=VerdictStatus.FAIL),  # operator fail -> TP
        "B": make_finding("B", status=VerdictStatus.PASS),  # operator fail -> FN (missed)
        "C": make_finding("C", status=VerdictStatus.FAIL),  # operator pass -> FP (false alarm)
        "D": make_finding("D", status=VerdictStatus.PASS),  # operator pass -> TN
    }
    labels = {
        "A": VerdictStatus.FAIL,
        "B": VerdictStatus.FAIL,
        "C": VerdictStatus.PASS,
        "D": VerdictStatus.PASS,
    }
    r = calibrate(findings, labels)
    assert (r.tp, r.fp, r.fn, r.tn) == (1, 1, 1, 1)
    assert r.scored == 4
    assert r.agreement_rate == 0.5  # A + D agree
    assert r.precision == 0.5  # tp / (tp+fp)
    assert r.recall == 0.5  # tp / (tp+fn)
    assert {d[0] for d in r.disagreements} == {"B", "C"}


def test_calibrate_reports_uncovered_specs() -> None:
    findings = {"A": make_finding("A", status=VerdictStatus.FAIL)}
    labels = {"A": VerdictStatus.FAIL, "Z": VerdictStatus.FAIL}
    r = calibrate(findings, labels)
    assert r.only_in_labels == ["Z"]  # labelled but absent from the report
    assert r.only_in_report == []
    assert r.scored == 1


def test_load_labels_rejects_bad_verdict(tmp_path: Path) -> None:
    p = tmp_path / "labels.yaml"
    p.write_text("A: fail\nB: banana\n", encoding="utf-8")
    try:
        load_labels(p)
    except ValueError as exc:
        assert "invalid verdict" in str(exc)
    else:  # pragma: no cover - guard
        raise AssertionError("expected ValueError for an invalid label verdict")


def test_calibrate_reports_from_disk(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        '{"findings": ['
        '{"spec_id": "A", "target_id": "t", "status": "fail",'
        ' "risk": {"impact": 3, "exploitability": 3, "reproducibility": 1.0, "risk": 9.0,'
        ' "confidence": 0.9, "band": "high"}, "confirmed": true, "attempts": [], "evidence": [],'
        ' "reasoning": "x"}]}',
        encoding="utf-8",
    )
    labels = tmp_path / "labels.yaml"
    labels.write_text("A: fail\n", encoding="utf-8")
    r = calibrate_reports(report, labels)
    assert r.tp == 1 and r.scored == 1
    assert "agreement 100%" in render_calibration(r)
