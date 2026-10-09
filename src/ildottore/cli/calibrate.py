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

import math
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ildottore import safe_yaml
from ildottore.cli.diff import load_findings
from ildottore.redactor import visible_controls
from ildottore.shared.config_errors import quoted, yaml_problem
from ildottore.shared.digits import described, too_long
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.files import read_text_capped
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

    try:
        raw = safe_yaml.safe_load(read_text_capped(path))
    except yaml.YAMLError as exc:  # was a traceback and exit 1, "findings below the threshold"
        raise ValueError(f"labels file {path} is not valid YAML: {yaml_problem(exc)}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"labels file {path} must be a mapping of spec_id -> verdict")
    labels: dict[str, VerdictStatus] = {}
    for entry, (spec_id, verdict) in enumerate(raw.items(), start=1):
        if too_long(spec_id):
            # `str(spec_id)` raised in the `try` and the message below raised again: exit 3 with
            # `error: Exceeds the limit`, naming no file (A-40).
            raise ValueError(f"labels file {path}: the spec id of entry {entry} is {described()}")
        # Only a text can be a verdict, and it is checked before anything is turned into text:
        # `str()` of a list of aliases wrote hundreds of megabytes (audits of A-51).
        status = _verdict(verdict)
        if status is None:
            # The spec id is the location, quoted up to 300 characters (A-51); the value is not
            # quoted (the other loaders' rule).
            raise ValueError(
                f"labels file {path}: spec {quoted(spec_id)} has an invalid verdict; "
                f"expected one of {', '.join(v.value for v in VerdictStatus)}"
            )
        labels[str(spec_id)] = status
    return labels


def _verdict(value: object) -> VerdictStatus | None:
    """The verdict a label's value names, or ``None`` when it names none."""

    if not isinstance(value, str):
        return None
    try:
        return VerdictStatus(value.strip().lower())
    except ValueError:
        return None


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
        """Specs whose status matches the label EXACTLY.

        It was ``tp + tn``, so a scanner ``inconclusive`` against an operator ``pass`` counted as
        agreement and the summary read 100% beside DISAGREE lines (audit R18).
        """

        return self.scored - len(self.disagreements)

    @property
    def agreement_rate(self) -> float:
        return self.agreements / self.scored if self.scored else 0.0

    @property
    def precision(self) -> float | None:
        """``None`` when undefined (no scanner fail): printed as n/a, never as 0%."""

        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        """``None`` when undefined (no labelled fail): printed as n/a, never as 0%."""

        denom = self.tp + self.fn
        return self.tp / denom if denom else None


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


def _pct(rate: float | None) -> str:
    """A percentage floored, never rounded up (99.6% is not 100%), or ``n/a`` when undefined."""

    if rate is None:
        return "n/a"
    return f"{math.floor(rate * 100)}%"


def render_calibration(report: CalibrationReport) -> str:
    """Render a compact calibration summary (agreement + precision/recall + disagreements)."""

    lines = [
        f"calibration: {report.scored} spec(s) scored, "
        f"agreement {_pct(report.agreement_rate)} ({report.agreements}/{report.scored}, "
        "exact status match)",
        f"  precision {_pct(report.precision)}  recall {_pct(report.recall)}  "
        f"(tp={report.tp} fp={report.fp} fn={report.fn} tn={report.tn}; fail = positive)",
    ]
    # The report's spec ids are spec ids (`diff.load_findings`); a labels file's are any text.
    for spec_id, got, want in report.disagreements:
        lines.append(f"  DISAGREE {spec_id}: scanner={got.value} operator={want.value}")
    if report.only_in_labels:
        uncovered = visible_controls(", ".join(report.only_in_labels))
        lines.append(f"  uncovered (labelled, not in report): {uncovered}")
    if report.only_in_report:
        lines.append(f"  unlabelled (in report, no label): {', '.join(report.only_in_report)}")
    return "\n".join(lines)
