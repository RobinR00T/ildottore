"""``dottore diff <baseline> <current>`` — baseline/drift comparison (docs/12 P1).

Compares two JSON run reports (as written by ``-oJ``/``JsonReporter``, or a bare list of
findings) by spec id and classifies each spec as a **regression** (``NEW_FAIL`` — was not
failing, now fails), a **fix** (``FIXED`` — was failing, now not), a **persistent failure**
(``STILL_FAIL``) or ``UNCHANGED``. Specs present on only one side are reported too
(``ONLY_IN_BASELINE`` / ``ONLY_IN_CURRENT``) but never count as a regression on their own —
there is no prior data point to regress from.

Pure classification + thin I/O: this reads only ``Finding.spec_id``/``Finding.status`` and
never touches ``RiskScore`` math (contract §8 — scoring stays u07's). ``compare_runs`` is the
small pure helper (dict-in, dataclass-out, no I/O) so it is unit-testable without files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Finding

__all__ = [
    "DriftClass",
    "DriftEntry",
    "DriftReport",
    "compare_runs",
    "diff_reports",
    "load_findings",
    "render_diff",
]


class DriftClass(StrEnum):
    """Per-spec drift classification (docs/12 P1 "Baseline diff / drift")."""

    NEW_FAIL = "new_fail"  # regression: was not failing (or absent), now fails
    FIXED = "fixed"  # was failing, now not failing
    STILL_FAIL = "still_fail"  # failing in both
    UNCHANGED = "unchanged"  # not failing in both
    ONLY_IN_BASELINE = "only_in_baseline"  # spec dropped since baseline
    ONLY_IN_CURRENT = "only_in_current"  # spec added since baseline


#: Drift classes that trip the CI gate (``docs/12`` "regression report for CI").
REGRESSION_CLASSES = frozenset({DriftClass.NEW_FAIL})


@dataclass(frozen=True)
class DriftEntry:
    """One spec's baseline → current classification."""

    spec_id: str
    drift: DriftClass
    baseline_status: VerdictStatus | None
    current_status: VerdictStatus | None


@dataclass(frozen=True)
class DriftReport:
    """The full per-spec drift table for one baseline/current pair."""

    entries: list[DriftEntry]

    @property
    def regressions(self) -> list[DriftEntry]:
        """Entries that are regressions (contract: NEW_FAIL only)."""
        return [e for e in self.entries if e.drift in REGRESSION_CLASSES]

    def has_regressions(self) -> bool:
        return bool(self.regressions)


def load_findings(path: Path) -> dict[str, Finding]:
    """Load a JSON run report and index its findings by spec id.

    Accepts both the full report envelope written by ``JsonReporter``
    (``{"schema_version": ..., "findings": [...], ...}``) and a bare JSON list of findings,
    so hand-built fixtures/tests need not construct a full ``TestRun``. Later duplicates of
    the same ``spec_id`` win (last one in file order) — a report is expected to have at most
    one finding per spec, but this stays permissive rather than raising on odd input.
    """

    data = json.loads(path.read_text(encoding="utf-8"))
    raw_findings = data["findings"] if isinstance(data, dict) else data
    by_spec: dict[str, Finding] = {}
    for raw in raw_findings:
        finding = Finding.model_validate(raw)
        by_spec[finding.spec_id] = finding
    return by_spec


def _classify(baseline: Finding | None, current: Finding | None) -> DriftClass:
    if baseline is None and current is None:  # pragma: no cover — unreachable via compare_runs
        raise ValueError("_classify requires at least one side present")
    if baseline is None:
        return DriftClass.ONLY_IN_CURRENT
    if current is None:
        return DriftClass.ONLY_IN_BASELINE

    was_fail = baseline.status is VerdictStatus.FAIL
    is_fail = current.status is VerdictStatus.FAIL
    if was_fail and is_fail:
        return DriftClass.STILL_FAIL
    if was_fail and not is_fail:
        return DriftClass.FIXED
    if is_fail:  # not was_fail and is_fail
        return DriftClass.NEW_FAIL
    return DriftClass.UNCHANGED


def compare_runs(baseline: dict[str, Finding], current: dict[str, Finding]) -> DriftReport:
    """Pure compare: classify every spec id present in either side.

    No I/O, no scoring — a dict-in/dataclass-out helper so the classification logic is
    unit-testable without writing files (contract §7 determinism).
    """

    spec_ids = sorted(set(baseline) | set(current))
    entries = [
        DriftEntry(
            spec_id=spec_id,
            drift=_classify(baseline.get(spec_id), current.get(spec_id)),
            baseline_status=baseline[spec_id].status if spec_id in baseline else None,
            current_status=current[spec_id].status if spec_id in current else None,
        )
        for spec_id in spec_ids
    ]
    return DriftReport(entries=entries)


def diff_reports(baseline_path: Path, current_path: Path) -> DriftReport:
    """Load two JSON run reports from disk and compare them."""

    baseline = load_findings(baseline_path)
    current = load_findings(current_path)
    return compare_runs(baseline, current)


_LABELS: dict[DriftClass, str] = {
    DriftClass.NEW_FAIL: "NEW-FAIL",
    DriftClass.FIXED: "FIXED",
    DriftClass.STILL_FAIL: "STILL-FAIL",
    DriftClass.UNCHANGED: "UNCHANGED",
    DriftClass.ONLY_IN_BASELINE: "ONLY-IN-BASELINE",
    DriftClass.ONLY_IN_CURRENT: "ONLY-IN-CURRENT",
}


def render_diff(report: DriftReport) -> str:
    """Render a compact one-line-per-spec table + a regressions summary footer."""

    lines = [f"{'SPEC':<30}{'BASELINE':<14}{'CURRENT':<14}DRIFT"]
    for entry in report.entries:
        baseline_s = entry.baseline_status.value if entry.baseline_status is not None else "-"
        current_s = entry.current_status.value if entry.current_status is not None else "-"
        lines.append(f"{entry.spec_id:<30}{baseline_s:<14}{current_s:<14}{_LABELS[entry.drift]}")
    regressions = report.regressions
    fixed = sum(1 for e in report.entries if e.drift is DriftClass.FIXED)
    lines.append(f"specs: {len(report.entries)}  regressions: {len(regressions)}  fixed: {fixed}")
    if regressions:
        lines.append("REGRESSIONS: " + ", ".join(e.spec_id for e in regressions))
    return "\n".join(lines)
