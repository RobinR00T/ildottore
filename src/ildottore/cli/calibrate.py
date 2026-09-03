"""``dottore calibrate <report.json> <labels.yaml>``: human-in-the-loop calibration (docs/12 P2).

Compares a run's findings against an operator's ground-truth labels and reports how well the
scanner agreed: agreement rate plus precision/recall treating ``fail`` (exploited) as the
positive class. This is the bounded, read-only slice of the HITL loop: it consumes operator
verdicts to measure the scanner (and its judge), it changes nothing and sends nothing.

A labels file is a mapping ``spec_id -> pass|fail|inconclusive`` (YAML or JSON). Only specs
present in BOTH the report and the labels are scored; specs on one side only are reported as
uncovered (they cannot be compared, and never silently count as agreement).

Pure classification + thin I/O: ``calibrate`` is a dict-in/dataclass-out helper (contract §7),
and it reuses ``diff.load_findings`` for the report side. No scoring math (contract §8).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ildottore.cli.diff import load_findings
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Finding

__all__ = [
    "CalibrationReport",
    "calibrate",
    "calibrate_reports",
    "load_labels",
    "render_calibration",
]


def load_labels(path: Path) -> dict[str, VerdictStatus]:
    """Load an operator labels file (``spec_id -> pass|fail|inconclusive``, YAML or JSON)."""

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"labels file {path} must be a mapping of spec_id -> verdict")
    labels: dict[str, VerdictStatus] = {}
    for spec_id, verdict in raw.items():
        try:
            labels[str(spec_id)] = VerdictStatus(str(verdict).strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"labels file {path}: spec {spec_id!r} has invalid verdict {verdict!r}; "
                f"expected one of {', '.join(v.value for v in VerdictStatus)}"
            ) from exc
    return labels


@dataclass(frozen=True)
class CalibrationReport:
    """Agreement of the scanner's findings with operator labels (fail = positive class)."""

    tp: int  # scanner fail & label fail
    fp: int  # scanner fail & label not-fail (false alarm)
    fn: int  # scanner not-fail & label fail (missed)
    tn: int  # scanner not-fail & label not-fail
    scored: int  # specs present in both report and labels
    disagreements: list[tuple[str, VerdictStatus, VerdictStatus]] = field(default_factory=list)
    only_in_report: list[str] = field(default_factory=list)
    only_in_labels: list[str] = field(default_factory=list)

    @property
    def agreements(self) -> int:
        return self.tp + self.tn

    @property
    def agreement_rate(self) -> float:
        return self.agreements / self.scored if self.scored else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0


def calibrate(findings: dict[str, Finding], labels: dict[str, VerdictStatus]) -> CalibrationReport:
    """Pure compare of scanner findings vs operator labels (no I/O)."""

    tp = fp = fn = tn = 0
    disagreements: list[tuple[str, VerdictStatus, VerdictStatus]] = []
    both = sorted(set(findings) & set(labels))
    for spec_id in both:
        got = findings[spec_id].status
        want = labels[spec_id]
        got_fail = got is VerdictStatus.FAIL
        want_fail = want is VerdictStatus.FAIL
        if got_fail and want_fail:
            tp += 1
        elif got_fail and not want_fail:
            fp += 1
        elif not got_fail and want_fail:
            fn += 1
        else:
            tn += 1
        if got is not want:
            disagreements.append((spec_id, got, want))
    return CalibrationReport(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        scored=len(both),
        disagreements=disagreements,
        only_in_report=sorted(set(findings) - set(labels)),
        only_in_labels=sorted(set(labels) - set(findings)),
    )


def calibrate_reports(report_path: Path, labels_path: Path) -> CalibrationReport:
    """Load a JSON run report + a labels file from disk and calibrate."""

    return calibrate(load_findings(report_path), load_labels(labels_path))


def render_calibration(report: CalibrationReport) -> str:
    """Render a compact calibration summary (agreement + precision/recall + disagreements)."""

    lines = [
        f"calibration: {report.scored} spec(s) scored, "
        f"agreement {report.agreement_rate:.0%} ({report.agreements}/{report.scored})",
        f"  precision {report.precision:.0%}  recall {report.recall:.0%}  "
        f"(tp={report.tp} fp={report.fp} fn={report.fn} tn={report.tn}; fail = positive)",
    ]
    for spec_id, got, want in report.disagreements:
        lines.append(f"  DISAGREE {spec_id}: scanner={got.value} operator={want.value}")
    if report.only_in_labels:
        lines.append(f"  uncovered (labelled, not in report): {', '.join(report.only_in_labels)}")
    if report.only_in_report:
        lines.append(f"  unlabelled (in report, no label): {', '.join(report.only_in_report)}")
    return "\n".join(lines)
