"""``dottore diff <baseline> <current>`` - baseline/drift comparison (docs/12 P1).

Compares two JSON run reports (as written by ``-oJ``/``JsonReporter``, or a bare list of
findings) by spec id and classifies each spec as a **regression** (``NEW_FAIL`` - was not
failing, now fails), a **fix** (``FIXED`` - was failing, now not), a **persistent failure**
(``STILL_FAIL``) or ``UNCHANGED``. Specs present on only one side are reported too
(``ONLY_IN_BASELINE`` / ``ONLY_IN_CURRENT``) but never count as a regression on their own -
there is no prior data point to regress from.

Pure classification + thin I/O: this reads only ``Finding.spec_id``/``Finding.status`` and
never touches ``RiskScore`` math (contract §8 - scoring stays u07's). ``compare_runs`` is the
small pure helper (dict-in, dataclass-out, no I/O) so it is unit-testable without files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Finding

__all__ = [
    "DriftClass",
    "DriftEntry",
    "DriftReport",
    "compare_runs",
    "diff_reports",
    "incomplete_reason",
    "load_findings",
    "render_diff",
    "report_target",
]


class DriftClass(StrEnum):
    """Per-spec drift classification (docs/12 P1 "Baseline diff / drift")."""

    NEW_FAIL = "new_fail"  # regression: was not failing (or absent), now fails
    FIXED = "fixed"  # was failing, now passes
    # Was failing, now inconclusive or never sent: not demonstrated fixed. It used to read
    # FIXED, so a target that went unreachable "fixed" every exploit it had (audit R4).
    UNVERIFIED = "unverified"
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


def _read_report(path: Path) -> Any:
    """Parse a JSON report, with the file named in every way it can fail to read.

    ``json.loads`` raises ``RecursionError``, not a ``ValueError``, on a document nested past
    its stack (200,000 levels of ``[``): no handler caught it, and the traceback exited 1, which
    this tool uses for "findings below --fail-on", so a CI step read a malformed report as an
    almost clean result (pre-merge audit of #51). A decoding error did not say which of the
    two files it was about either.
    """

    # Absolute and never followed by a colon: the CLI keeps an existing absolute path readable,
    # and a relative path, or one with a colon after it, is not one, so a report named after a
    # commit SHA had its name masked as a high-entropy value (pre-commit and delta audits). Not
    # escaped here: an escaped name is no longer a path on disk, so the CLI masked it too; the
    # terminal escapes control characters for every message (#51).
    shown = path.absolute()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError(f"the report {shown} is nested too deeply to read as JSON") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"the report {shown} is not UTF-8 text (byte {exc.start})") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"the report {shown} is not valid JSON ({exc})") from exc


def incomplete_reason(path: Path) -> str | None:
    """Why this report describes a run that did not finish, or ``None`` when it did.

    ``diff`` is advertised as CI-gateable, and a truncated report is the input that breaks it:
    27 previously-failing specs simply vanish, which classifies as ``ONLY-IN-BASELINE``, which
    is not a regression, so the gate goes green. The report already states the truncation in
    ``summary.status``; this reads it instead of comparing counts and guessing.

    A report written before ``status`` existed (report-1.0 without the block) has no way to
    say, so it is treated as complete: silence there is age, not a claim.
    """

    data = _read_report(path)
    if not isinstance(data, dict):
        return None  # a bare findings list carries no run-level state
    status = (data.get("summary") or {}).get("status")
    if not isinstance(status, dict) or status.get("complete", True):
        return None
    # Text only: this tool writes both as text, and formatting a list nested 70,000 levels deep
    # overflowed the stack (a traceback and exit 1, pre-commit audit of the nesting fix).
    state = status.get("state")
    reason = status.get("reason")
    state = state if isinstance(state, str) and state else "incomplete"
    return f"{state}: {reason}" if isinstance(reason, str) and reason else state


def load_findings(path: Path) -> dict[str, Finding]:
    """Load a JSON run report and index its findings by spec id, for ONE target.

    Accepts both the full report envelope written by ``JsonReporter``
    (``{"schema_version": ..., "findings": [...], ...}``) and a bare JSON list of findings,
    so hand-built fixtures/tests need not construct a full ``TestRun``.

    A report that covers several targets is refused, and so is one with two findings for the
    same spec: indexing by spec id kept the last one in file order, so a multi-target report
    merged its targets and a FAIL on one could be replaced by a PASS on another (audit R4).
    Compare one target's report at a time.
    """

    data = _read_report(path)
    raw_findings = data["findings"] if isinstance(data, dict) else data
    if not isinstance(raw_findings, list):
        raise ValueError(f"{path}: expected a JSON run report or a list of findings")
    findings = [Finding.model_validate(raw) for raw in raw_findings]
    targets = sorted({f.target_id for f in findings})
    if len(targets) > 1:
        raise ValueError(
            f"{path} covers {len(targets)} targets ({', '.join(targets)}); compare one "
            "target's report at a time"
        )
    by_spec: dict[str, Finding] = {}
    for finding in findings:
        if finding.spec_id in by_spec:
            raise ValueError(
                f"{path} has more than one finding for {finding.spec_id}; compare one run's "
                "report at a time"
            )
        by_spec[finding.spec_id] = finding
    return by_spec


def report_target(findings: dict[str, Finding]) -> str | None:
    """The single target a loaded report is about (``None`` for an empty report)."""

    return next((f.target_id for f in findings.values()), None)


def _classify(baseline: Finding | None, current: Finding | None) -> DriftClass:
    if baseline is None and current is None:  # pragma: no cover - unreachable via compare_runs
        raise ValueError("_classify requires at least one side present")
    if baseline is None:
        return DriftClass.ONLY_IN_CURRENT
    if current is None:
        return DriftClass.ONLY_IN_BASELINE

    was_fail = baseline.status is VerdictStatus.FAIL
    is_fail = current.status is VerdictStatus.FAIL
    if was_fail and is_fail:
        return DriftClass.STILL_FAIL
    if was_fail and current.status is not VerdictStatus.PASS:
        return DriftClass.UNVERIFIED
    if was_fail and not is_fail:
        return DriftClass.FIXED
    if is_fail:  # not was_fail and is_fail
        return DriftClass.NEW_FAIL
    return DriftClass.UNCHANGED


def compare_runs(baseline: dict[str, Finding], current: dict[str, Finding]) -> DriftReport:
    """Pure compare: classify every spec id present in either side.

    No I/O, no scoring - a dict-in/dataclass-out helper so the classification logic is
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
    """Load two JSON run reports from disk and compare them (same target only)."""

    baseline = load_findings(baseline_path)
    current = load_findings(current_path)
    base_target, current_target = report_target(baseline), report_target(current)
    if base_target is not None and current_target is not None and base_target != current_target:
        raise ValueError(
            f"the baseline is about target {base_target!r} and the current report about "
            f"{current_target!r}; a drift report compares one target with itself"
        )
    return compare_runs(baseline, current)


_LABELS: dict[DriftClass, str] = {
    DriftClass.NEW_FAIL: "NEW-FAIL",
    DriftClass.FIXED: "FIXED",
    DriftClass.UNVERIFIED: "UNVERIFIED",
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
    unverified = [e.spec_id for e in report.entries if e.drift is DriftClass.UNVERIFIED]
    lines.append(
        f"specs: {len(report.entries)}  regressions: {len(regressions)}  fixed: {fixed}"
        + (f"  unverified: {len(unverified)}" if unverified else "")
    )
    if unverified:
        lines.append(
            "UNVERIFIED (failed in the baseline, not evaluated now, so not shown fixed): "
            + ", ".join(unverified)
        )
    if regressions:
        lines.append("REGRESSIONS: " + ", ".join(e.spec_id for e in regressions))
    return "\n".join(lines)
